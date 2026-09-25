"""Command-line entry point: argument parsing and the scan/audit commands."""
import argparse
import getpass
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich.text import Text
from rich import box as rich_box
from rich.markup import escape as rich_escape
from rich.prompt import Confirm

import warnings
# Silence third-party import noise (requests RequestsDependencyWarning + urllib3
# 'strict' FutureWarning) only; runs before narvy imports pull in requests.
warnings.filterwarnings("ignore", category=FutureWarning, module=r"urllib3(\..*)?")
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from requests.exceptions import RequestsDependencyWarning as _RequestsDependencyWarning
    warnings.filterwarnings("ignore", category=_RequestsDependencyWarning)
except Exception:
    # If the class ever moves, fall back to a module-scoped filter on requests.
    warnings.filterwarnings("ignore", module=r"requests(\..*)?")

from narvy import __version__
from narvy.reporter import generate_sarif_report, sarif_level, sarif_security_severity
from .decompiler import decompile_apk
from .rule_engine import load_rules_from_dir, run_rules_on_file
from . import auth, uploader, telemetry
from .third_party_filter import get_own_package_roots, resolve_file_scope, check_android_override
from .scope_config import load_scope_config
from . import semgrep_engine
from . import crypto_taint_lite
from . import native_hardening
from .doctor import run_doctor
from .ios import binary_analyzer as ios_binary_analyzer
from .ios import source_analyzer as ios_source_analyzer
from .ios.third_party_filter import IOS_VENDOR_DIR_NAMES
from .android import source_analyzer as android_source_analyzer
from .android import split_bundle
from .web import source_analyzer as web_source_analyzer
from .sca import android_deps as sca_android_deps
from .sca import ios_deps as sca_ios_deps
from .sca import web_deps as sca_web_deps
from .web.scanner import NucleiScanner
from .web.scan_blocklist import check_blocklist, ScanBlocked, REFUSAL_MESSAGE
from .web.ssrf_guard import validate_url as web_validate_url, SSRFBlocked
from .host.ssh_exec import HostConn, SSHExecError, _validate_conn
from .host.audit import audit_host
from .host.report import normalize_host_findings, severity_counts as host_severity_counts
# cloud/aws_scan.py and its boto3 dependency are imported lazily inside
# cmd_cloud_scan(): boto3 is an opt-in extra, not a dependency of the whole CLI.

# Human/progress/status UI goes to stderr so stdout carries only the machine
# payload (JSON/SARIF, or the results table via out_console).
console = Console(stderr=True)
out_console = Console()

# Check the real fd: rich says "terminal" whenever FORCE_COLOR is set, which
# would dump spinner frames into CI logs.
_STDERR_IS_TTY = sys.stderr.isatty()


def _progress_interval() -> float:
    """Seconds between non-TTY 'still running' lines (NARVY_PROGRESS_INTERVAL, default 30, 0 = off)."""
    raw = os.environ.get("NARVY_PROGRESS_INTERVAL", "").strip()
    try:
        return max(0.0, float(raw)) if raw else 30.0
    except ValueError:
        return 30.0


class _PlainProgress:
    """Plain-text progress for non-TTY output: one line per step plus a periodic 'still running'."""

    def __init__(self, out, interval=None):
        self._out = out
        self._last = {}
        self._current = ""
        self._interval = _progress_interval() if interval is None else interval
        self._started = time.monotonic()
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        self._started = time.monotonic()
        if self._interval > 0:
            self._thread = threading.Thread(target=self._heartbeat, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    def _heartbeat(self):
        while not self._stop.wait(self._interval):
            elapsed = int(time.monotonic() - self._started)
            step = self._current or "scan"
            self._out.print(
                f"[dim]... still running ({elapsed // 60}m{elapsed % 60:02d}s elapsed): "
                f"{rich_escape(step)}[/dim]"
            )

    def add_task(self, description, **kwargs):
        tid = len(self._last)
        self._last[tid] = None
        self._emit(tid, description)
        return tid

    def update(self, task_id, description=None, **kwargs):
        if description is not None:
            self._emit(task_id, description)

    def stop(self):
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=1)
            self._thread = None

    def _emit(self, tid, description):
        if self._last.get(tid) == description:
            return
        self._last[tid] = description
        try:
            self._current = Text.from_markup(description).plain.rstrip(". ")
        except Exception:
            self._current = str(description)
        self._out.print(description)


def scan_progress():
    """Rich spinner on a real TTY; plain, one-line-per-step status otherwise."""
    if _STDERR_IS_TTY:
        return Progress(console=console, disable=False)
    return _PlainProgress(console)


def _print_raw_tool_output(label, text):
    """Print a tool's captured raw output under a dim header (for --verbose/errors)."""
    text = (text or "").strip()
    if not text:
        return
    console.print(f"\n[dim]--- raw {label} output ---[/dim]")
    console.print(f"[dim]{rich_escape(text)}[/dim]")
    console.print("[dim]--- end raw output ---[/dim]\n")


WEB_MAX_RATE_LIMIT = 50

# getpass raises termios.error/EOFError under CI (non-TTY/closed stdin); termios is POSIX-only.
_GETPASS_ERRORS = [EOFError, KeyboardInterrupt, OSError]
try:  # pragma: no cover - platform dependent
    import termios as _termios
    _GETPASS_ERRORS.append(_termios.error)
except ImportError:  # pragma: no cover - Windows
    pass
_GETPASS_ERRORS = tuple(_GETPASS_ERRORS)

# Exit codes. The same contract for every command; listed in `narvy --help`.
EXIT_OK = 0
EXIT_FAIL_ON = 1        # --fail-on: a finding at or above the threshold
EXIT_COVERAGE = 2       # --fail-on: nothing breached, but a pass did not fully run
EXIT_BAD_TARGET = 3     # target missing, unsupported or refused, or invalid arguments
EXIT_ERROR = 4          # the scan, login, upload or report write failed

EXIT_CODES_HELP = (
    "exit codes:\n"
    "  0  scan completed (and nothing reached the --fail-on threshold)\n"
    "  1  --fail-on: at least one finding at or above the threshold\n"
    "  2  --fail-on: nothing reached the threshold, but part of the scan did not\n"
    "     run (for example a timed-out pass or an unreachable CVE database), so\n"
    "     the result cannot be certified clean\n"
    "  3  the target or arguments are not usable (path not found, unsupported\n"
    "     file type or project, refused URL, invalid option)\n"
    "  4  the scan, login, upload or report write failed\n"
    "  130  interrupted (Ctrl-C, SIGTERM)"
)


FAIL_ON_HELP = (
    "CI gate: exit 1 if any finding is at or above this severity ('any' = any "
    "finding). If nothing reaches it but part of the scan did not run, exit 2 "
    "instead of 0, because the result cannot be certified clean. Without "
    "--fail-on the exit code is 0 whatever is found."
)

# Public documentation (the repository README/SETUP guide).
DOCS_URL = "https://github.com/Narvy-Cyber/narvy-cli/blob/main/SETUP.md"


class _ArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error, which would collide with EXIT_COVERAGE."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_BAD_TARGET, f"{self.prog}: error: {message}\n")


# JADX takes -Xmx<size>; anything else leaks a raw JVM error, so gate it.
_MAX_MEM_RE = re.compile(r"^\d+[mMgGkK]?$")

_SEVERITY_LEVEL = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

_IOS_SOURCE_MARKER_EXTS = (".xcodeproj", ".xcworkspace")
_IOS_SOURCE_MARKER_FILES = ("Package.swift",)
# `.h` is deliberately absent: a header is just as likely C or C++, so it
# would select ios-source for any repo vendoring a C library.
_IOS_SOURCE_CODE_EXTS = (".swift", ".m", ".mm")
_IOS_DETECT_MAX_DEPTH = 6

_ANDROID_BINARY_EXTS = (".apk", ".aab")
_ANDROID_GRADLE_ROOT_FILES = ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")
_ANDROID_MANIFEST_FILENAME = "AndroidManifest.xml"

# Gradle is a general-purpose JVM build tool, so a Gradle file alone is not
# evidence of Android. Any one of the markers below is required instead.
_ANDROID_GRADLE_PLUGIN_IDS = (
    "com.android.application",
    "com.android.library",
    "com.android.dynamic-feature",
    "com.android.test",
    "com.android.asset-pack",
    "com.android.fused-library",
)
# Anchored so a bare "android" in a comment or a coordinate cannot match. The
# `android { }` block is the only marker left when AGP is wired via buildSrc.
_ANDROID_GRADLE_DSL_RE = re.compile(
    r"""apply\s+plugin\s*:\s*['"]android(-library)?['"]"""
    r"""|^\s*android\s*\{"""
    r"""|^\s*applicationId\s*[=(\s]""",
    re.MULTILINE,
)
_ANDROID_GRADLE_FILE_SUFFIXES = (".gradle", ".gradle.kts")
_ANDROID_MARKER_PROPERTY_FILES = ("gradle.properties",)
_ANDROID_MARKER_PROPERTIES = ("android.useAndroidX", "android.enableJetifier")
_ANDROID_VERSION_CATALOG_FILENAME = "libs.versions.toml"
_ANDROID_BUILD_FILE_SNIFF_BYTES = 512 * 1024
_ANDROID_DETECT_MAX_DEPTH = 6
_ANDROID_SKIP_DIR_NAMES = frozenset({
    "build", ".gradle", ".idea", ".git", "out", ".cxx", "node_modules",
    ".vscode", ".vs", "captures",
})


_WEB_SOURCE_MARKER_FILES = (
    "package.json", "requirements.txt", "setup.py", "pyproject.toml",
    "Pipfile", "composer.json", "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock", "Cargo.toml", "Cargo.lock",
    "packages.config", "Directory.Packages.props",
)
# Markers with no fixed filename: .NET manifests are named after their project.
_WEB_SOURCE_MARKER_SUFFIXES = (
    ".gemspec", ".csproj", ".fsproj", ".vbproj", ".sln", ".slnx",
)
# Fallback for projects with no manifest (e.g. plain .php files). Only reached
# after the iOS and Android checks fail.
_WEB_SOURCE_CODE_EXTS = (
    ".php", ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".go", ".rb", ".rs", ".java", ".cs", ".vb", ".fs",
)
# 6 to match the iOS/Android detectors: monorepos nest a service's manifest
# several levels deep (org/team/service/src), so a shallow cap missed them.
_WEB_SOURCE_DETECT_MAX_DEPTH = 6

# .NET manifests. A cross-platform .NET app (MAUI/Xamarin) ships a generated
# AndroidManifest.xml but is C# at heart, so it must not route to android-source.
_DOTNET_PROJECT_SUFFIXES = (".sln", ".slnx", ".csproj", ".fsproj", ".vbproj")


def _looks_like_web_source_dir(path: str) -> bool:
    """Only valid after the iOS-source and Android-source checks both returned False."""
    base_depth = path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _WEB_SOURCE_DETECT_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _ANDROID_SKIP_DIR_NAMES and not d.startswith(".")
                   and d not in ("node_modules", "vendor")]
        for f in files:
            if (f in _WEB_SOURCE_MARKER_FILES
                    or f.endswith(_WEB_SOURCE_MARKER_SUFFIXES)
                    or f.endswith(_WEB_SOURCE_CODE_EXTS)):
                return True
    return False


class UnsupportedScanTarget(Exception):
    """Target is neither a recognized binary format nor a recognized source project."""


def _looks_like_ios_source_dir(path: str) -> bool:
    base_depth = path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _IOS_DETECT_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in IOS_VENDOR_DIR_NAMES and d not in (".git", "node_modules")]
        for d in dirs:
            if d.endswith(_IOS_SOURCE_MARKER_EXTS):
                return True
        for f in files:
            if f in _IOS_SOURCE_MARKER_FILES or f.endswith(_IOS_SOURCE_CODE_EXTS):
                return True
    return False


def _has_ios_project_marker(path: str) -> bool:
    """Xcode project/workspace or Package.swift at the scan root (not nested)."""
    try:
        entries = os.listdir(path)
    except OSError:
        return False
    for e in entries:
        if e.endswith(_IOS_SOURCE_MARKER_EXTS) or e in _IOS_SOURCE_MARKER_FILES:
            return True
    return False


# Directories whose Xcode projects are samples, docs or fixtures rather than the
# product: a nested .xcodeproj under one of these is not an extra surface to scan.
_NON_PRODUCT_DIR_RE = re.compile(
    r"^(examples?|samples?|demos?|docs?|documentation|tests?|fixtures?|testdata|"
    r"benchmarks?|third[-_]?party|external|deps)$",
    re.IGNORECASE,
)
_NESTED_IOS_MAX_ROOTS = 5


def _nested_ios_project_roots(path: str) -> List[str]:
    """Dirs below the root holding an Xcode project or Package.swift, skipping vendor/sample/test trees."""
    roots: List[str] = []
    base_depth = path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _IOS_DETECT_MAX_DEPTH:
            dirs[:] = []
            continue
        if depth >= 1 and (
            any(d.endswith(_IOS_SOURCE_MARKER_EXTS) for d in dirs)
            or any(f in _IOS_SOURCE_MARKER_FILES for f in files)
        ):
            roots.append(root)
            dirs[:] = []
            if len(roots) >= _NESTED_IOS_MAX_ROOTS:
                break
            continue
        dirs[:] = sorted(
            d for d in dirs
            if d not in IOS_VENDOR_DIR_NAMES
            and d not in _ANDROID_SKIP_DIR_NAMES
            and d not in ("node_modules", "vendor")
            and not d.startswith(".")
            and not d.endswith(_IOS_SOURCE_MARKER_EXTS)
            and not _NON_PRODUCT_DIR_RE.match(d)
        )
    return roots


def _file_head_contains(path: str, needles, regex=None) -> bool:
    """True if the head of `path` contains any of `needles` or matches `regex`."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(_ANDROID_BUILD_FILE_SNIFF_BYTES)
    except OSError:
        return False
    for needle in needles:
        if needle in head:
            return True
    return bool(regex and regex.search(head))


def _has_android_gradle_marker(path: str) -> bool:
    """True if path holds an Android Gradle build (AGP plugin id, `android {}` DSL, or AndroidX property)."""
    base_depth = path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _ANDROID_DETECT_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _ANDROID_SKIP_DIR_NAMES and not d.startswith(".")]
        for f in files:
            if f.endswith(_ANDROID_GRADLE_FILE_SUFFIXES) or f == _ANDROID_VERSION_CATALOG_FILENAME:
                if _file_head_contains(os.path.join(root, f), _ANDROID_GRADLE_PLUGIN_IDS,
                                       _ANDROID_GRADLE_DSL_RE):
                    return True
            elif f in _ANDROID_MARKER_PROPERTY_FILES:
                if _file_head_contains(os.path.join(root, f), _ANDROID_MARKER_PROPERTIES):
                    return True
    return False


def _has_android_manifest(path: str) -> bool:
    """True if an AndroidManifest.xml exists anywhere in the (pruned) tree."""
    base_depth = path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _ANDROID_DETECT_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _ANDROID_SKIP_DIR_NAMES and not d.startswith(".")]
        if _ANDROID_MANIFEST_FILENAME in files:
            return True
    return False


def _has_dotnet_project_marker(path: str) -> bool:
    """True if a .NET solution/project file exists (.sln/.csproj/.fsproj/.vbproj)."""
    base_depth = path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _ANDROID_DETECT_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _ANDROID_SKIP_DIR_NAMES and not d.startswith(".")]
        for f in files:
            if f.endswith(_DOTNET_PROJECT_SUFFIXES):
                return True
    return False


def _looks_like_android_source_dir(path: str) -> bool:
    """True if path holds an AndroidManifest.xml or an Android Gradle marker."""
    return _has_android_manifest(path) or _has_android_gradle_marker(path)


def _has_android_marker_outside_android_dirs(path: str) -> bool:
    """True if an Android manifest or Gradle marker exists outside any `android/` dir."""
    base = path.rstrip(os.sep)
    base_depth = base.count(os.sep)

    def outside_android(root: str) -> bool:
        rel = os.path.relpath(root, path)
        segs = [] if rel == "." else rel.split(os.sep)
        return "android" not in segs

    for root, dirs, files in os.walk(path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _ANDROID_DETECT_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _ANDROID_SKIP_DIR_NAMES and not d.startswith(".")]
        if not outside_android(root):
            continue
        if _ANDROID_MANIFEST_FILENAME in files:
            return True
        for f in files:
            if f.endswith(_ANDROID_GRADLE_FILE_SUFFIXES) or f == _ANDROID_VERSION_CATALOG_FILENAME:
                if _file_head_contains(os.path.join(root, f), _ANDROID_GRADLE_PLUGIN_IDS,
                                       _ANDROID_GRADLE_DSL_RE):
                    return True
            elif f in _ANDROID_MARKER_PROPERTY_FILES:
                if _file_head_contains(os.path.join(root, f), _ANDROID_MARKER_PROPERTIES):
                    return True
    return False


def _is_hybrid_web_primary(path: str) -> bool:
    """React Native / Capacitor monorepo: JS/TS at the root, native code only under android/."""
    if not os.path.isfile(os.path.join(path, "package.json")):
        return False
    if not _has_code_outside(path, _JS_CODE_EXTS, _HYBRID_SKIP_DIRS):
        return False
    return not _has_android_marker_outside_android_dirs(path)


def _looks_like_jvm_non_android_dir(path: str) -> bool:
    """Only valid after _looks_like_android_source_dir and _looks_like_web_source_dir said no."""
    base_depth = path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _WEB_SOURCE_DETECT_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _ANDROID_SKIP_DIR_NAMES and not d.startswith(".")]
        for f in files:
            if f == "pom.xml" or f in _ANDROID_GRADLE_ROOT_FILES:
                return True
    return False


def _detect_scan_mode(target_path: str) -> str:
    """Detect scan mode (android / android-bundle / android-source / ios-binary / ios-source / web-source); mobile markers win over the web-source fallback."""
    if os.path.isdir(target_path):
        if _has_ios_project_marker(target_path):
            return "ios-source"
        # Android/web manifests beat a stray .m/.mm/.swift file (e.g. a Cgo bridge in a Go repo).
        if _looks_like_android_source_dir(target_path):
            # RN/Capacitor monorepo: native lives only in a nested android/ subdir
            # while the primary JS/TS surface sits at the root. Scan the JS/TS.
            if _is_hybrid_web_primary(target_path):
                return "web-source"
            # MAUI/Xamarin ships an AndroidManifest.xml but no Gradle build; it's C#,
            # so it goes to web-source.
            if _has_dotnet_project_marker(target_path) and not _has_android_gradle_marker(target_path):
                pass
            else:
                return "android-source"
        if _looks_like_web_source_dir(target_path):
            return "web-source"
        if _looks_like_jvm_non_android_dir(target_path):
            return "web-source"
        # Weak fallback: bare Swift/Obj-C source with no competing manifest.
        if _looks_like_ios_source_dir(target_path):
            return "ios-source"
        raise UnsupportedScanTarget(
            "This doesn't look like a supported scan target (not an .apk, not "
            "an .aab, not an .ipa, not an iOS Xcode/Swift project, not an "
            "Android Gradle project, not a web/backend project with a "
            "recognized manifest - package.json/requirements.txt/"
            "composer.json/go.mod/Gemfile/Cargo.toml/pom.xml/build.gradle/"
            "*.csproj/*.sln/etc)."
        )
    ext = os.path.splitext(target_path)[1].lower()
    if ext == ".ipa":
        return "ios-binary"
    if ext in _ANDROID_BINARY_EXTS:
        return "android"
    # .apkm / .xapk / .apks are ZIPs of sibling APKs, unreadable by jadx.
    if split_bundle.is_split_bundle(target_path):
        return "android-bundle"
    raise UnsupportedScanTarget(
        f"Unrecognized file type '{ext or os.path.basename(target_path)}'. "
        "Narvy CLI currently supports: .apk or .aab (Android), .apkm / "
        ".xapk / .apks (Android split-APK bundles), .ipa "
        "(iOS binary - unencrypted only), or a directory containing an "
        "Android Gradle project, an iOS Xcode/Swift project, or a web/"
        "backend project (source-mode scanning)."
    )


_JS_CODE_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_HYBRID_SKIP_DIRS = frozenset({
    "node_modules", ".git", "build", "dist", "out", ".gradle", "Pods",
    "android", "ios", "vendor", "__pycache__", ".dart_tool",
})


def _has_code_outside(target_path: str, exts, skip_dirs, max_depth: int = 4) -> bool:
    """True if a source file with one of `exts` exists outside `skip_dirs`."""
    base_depth = target_path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(target_path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        if any(f.endswith(exts) for f in files):
            return True
    return False


def _subdir_has(target_path: str, subdir: str, exts, names=(), max_depth: int = 4) -> bool:
    root_dir = os.path.join(target_path, subdir)
    if not os.path.isdir(root_dir):
        return False
    base_depth = root_dir.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(root_dir):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("build", "Pods")]
        for f in files:
            if f.endswith(exts) or f in names:
                return True
        for d in dirs:
            if d.endswith((".xcodeproj", ".xcworkspace")):
                return True
    return False


def _uncovered_surface_notes(target_path: str, scan_mode: str,
                             extra_ios_roots=()) -> List[str]:
    """Notes for code surfaces in a hybrid repo that the chosen scan mode does not cover."""
    if not os.path.isdir(target_path):
        return []
    notes: List[str] = []
    covers_js = scan_mode == "web-source"
    covers_android = scan_mode == "android-source"
    covers_ios = scan_mode in ("ios-source", "ios-binary") or bool(extra_ios_roots)

    # JS/TS primary code (RN / Capacitor): root package.json + JS outside native shells.
    if not covers_js and os.path.isfile(os.path.join(target_path, "package.json")) \
       and _has_code_outside(target_path, _JS_CODE_EXTS, _HYBRID_SKIP_DIRS):
        notes.append(
            "JavaScript/TypeScript code (a root package.json and .js/.ts files) is "
            "present but was NOT scanned - only the native shell was. Scan it with "
            "`narvy scan <dir>/src` (or the JS/TS subdirectory)."
        )
    # Dart / Flutter primary code.
    if scan_mode != "web-source" and os.path.isfile(os.path.join(target_path, "pubspec.yaml")) \
       and _subdir_has(target_path, "lib", (".dart",)):
        notes.append(
            "Dart/Flutter code (pubspec.yaml and lib/*.dart) is present but was NOT "
            "scanned - only the native shell was. Narvy has no Dart source analyzer; "
            "scan the native android/ and ios/ shells separately for now."
        )
    # An ios/ tree not covered by an Android/web scan. Fall back to a tree-wide
    # check for a hybrid whose native code is scattered (e.g. Expo modules/x/ios).
    if not covers_ios:
        if _subdir_has(target_path, "ios", (".swift", ".m", ".mm"), ("Info.plist",)):
            notes.append(
                "An ios/ project tree is present but was NOT scanned - this scan covered "
                "a different surface. Scan it with `narvy scan <dir>/ios`."
            )
        elif scan_mode == "web-source" and _looks_like_ios_source_dir(target_path):
            ios_dir = _first_dir_with(target_path, _IOS_SOURCE_CODE_EXTS)
            where = (f"`narvy scan {os.path.join(target_path, ios_dir)}`"
                     if ios_dir else "`narvy scan <path>` on its directory")
            notes.append(
                "Native iOS code (Swift/Obj-C files) is present in this repo without an "
                "Xcode project or Package.swift, so it was NOT scanned - only the "
                f"web/backend source surface was. Scan it with {where}."
            )
    # An android/ tree not covered by an iOS/web scan, with the same fallback.
    if not covers_android:
        if _subdir_has(target_path, "android", (".java", ".kt"),
                       ("AndroidManifest.xml", "build.gradle")):
            notes.append(
                "An android/ project tree is present but was NOT scanned - this scan "
                "covered a different surface. Scan it with `narvy scan <dir>/android`."
            )
        elif scan_mode == "web-source" and _looks_like_android_source_dir(target_path):
            notes.append(
                "Native Android code (AndroidManifest.xml / *.kt / *.java) is present "
                "in this repo but was NOT scanned - only the web/backend source surface was. Scan "
                "each native module or the android/ shell separately with `narvy scan <path>`."
            )
    # C/C++ has no analyzer in any scan mode (web, Android JNI, iOS). Without this
    # note a C/C++-heavy repo with one Python helper script reports "clean".
    if _has_code_outside(target_path, _C_CPP_CODE_EXTS, _C_SKIP_DIRS):
        notes.append(
            "C/C++ source files (.c/.cpp/.cc) are present but were NOT analyzed - "
            "Narvy has no C/C++ rules. Memory-safety and injection issues in that "
            "code are not covered by this scan; use a dedicated C/C++ analyzer for it."
        )
    return notes


def _first_dir_with(target_path: str, exts, max_depth: int = 6):
    """Shallowest dir holding a file with one of `exts`, skipping vendored dirs, or None."""
    base_depth = target_path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(target_path):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= max_depth:
            dirs[:] = []
            continue
        dirs[:] = sorted(d for d in dirs if d not in IOS_VENDOR_DIR_NAMES
                         and d not in ("node_modules", "vendor", "build", "dist", "out")
                         and not d.startswith("."))
        if any(f.endswith(exts) for f in files):
            rel = os.path.relpath(root, target_path)
            return None if rel == "." else rel
    return None


_C_CPP_CODE_EXTS = (".c", ".cc", ".cpp", ".cxx")
_C_SKIP_DIRS = frozenset({
    "node_modules", ".git", "build", "dist", "out", ".gradle", "Pods", "vendor",
    "__pycache__", ".dart_tool", "third_party", "third-party", "external", "deps",
})


def _positive_int(value):
    """argparse type for an integer >= 1."""
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"must be an integer >= 1, got {value!r}")
    if ivalue < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {ivalue}")
    return ivalue


def _absolute_url(url):
    """Server responses carry site-relative links ('/pricing'); a terminal needs a full URL."""
    url = str(url or "").strip()
    if url.startswith(("http://", "https://")):
        return url
    return uploader.API_BASE + "/" + url.lstrip("/")


def _scan_dashboard_url(data):
    """Direct link to one scan in the dashboard, from an ingest/analyze response."""
    if not isinstance(data, dict):
        return None
    for key in ("scan_url", "report_url"):
        if data.get(key):
            return _absolute_url(data[key])
    scan_id = data.get("scan_id")
    if scan_id:
        return f"{uploader.API_BASE}/analysis/s/{scan_id}"
    return None


def _print_upgrade_hint(status, data):
    """On a plan refusal (403) always show where to upgrade, as a full URL."""
    if status != 403:
        return
    url = None
    if isinstance(data, dict) and data.get("upgrade_url"):
        url = _absolute_url(data["upgrade_url"])
    if not url:
        url = f"{uploader.API_BASE}/pricing"
    msg = (data.get("message") or "") if isinstance(data, dict) else ""
    if url not in msg:
        console.print(f"[dim]Plans and upgrade: {url}[/dim]")


def _format_asset_limit_error(data):
    """Readable message for a 402 asset_limit_exceeded response, else None."""
    if not isinstance(data, dict) or data.get("error") != "asset_limit_exceeded":
        return None
    upgrade_url = _absolute_url(data.get("upgrade_url") or "/pricing")
    return (
        "You have reached your asset limit. Free a slot or upgrade at "
        f"{upgrade_url}."
    )


def _preflight_output_writable(out_file):
    """Error string if out_file can't be written, else None. Checked before the scan starts."""
    if os.path.isdir(out_file):
        return f"{out_file} is a directory"
    parent = os.path.dirname(os.path.abspath(out_file)) or "."
    if not os.path.isdir(parent):
        return f"the directory {parent} does not exist"
    if not os.access(parent, os.W_OK):
        return f"the directory {parent} is not writable"
    if os.path.exists(out_file) and not os.access(out_file, os.W_OK):
        return f"{out_file} already exists and is not writable"
    return None


def cmd_login(args):
    token = args.token
    if not token:
        # Piped stdin (echo TOKEN | narvy login) must work; only a real terminal gets the getpass prompt.
        try:
            stdin_is_tty = bool(sys.stdin) and sys.stdin.isatty()
        except (ValueError, OSError):
            stdin_is_tty = False
        if stdin_is_tty:
            try:
                token = getpass.getpass(
                    "Paste your Narvy API token (Account Settings > API Access): "
                )
            except _GETPASS_ERRORS:
                token = None
        else:
            try:
                token = sys.stdin.readline().strip()
            except (EOFError, OSError):
                token = None
    if not token:
        console.print(
            "[bold red]No token provided.[/bold red] Pass [bold]--token <TOKEN>[/bold] "
            "or run [bold]narvy login[/bold] interactively."
        )
        raise SystemExit(EXIT_BAD_TARGET)
    status, data = uploader.whoami(token)
    if status != 200:
        console.print(f"[bold red]Login failed:[/bold red] {data.get('error', status)}")
        raise SystemExit(EXIT_ERROR)
    auth.save_token(token, data["email"], data["plan"])
    console.print(f"[bold green]Logged in as {data['email']} ({data['plan']} plan).[/bold green]")


def cmd_logout(args):
    auth.logout()
    console.print("[bold green]Logged out.[/bold green]")


def cmd_scans(args):
    """List recent scans on the logged-in account."""
    creds = auth.load_credentials()
    if not creds:
        console.print("[bold red]Not logged in.[/bold red] Run `narvy login` first.")
        raise SystemExit(EXIT_ERROR)

    status, data = uploader.list_scans(creds["token"], limit=args.limit, status=args.status)
    if status == 404:
        console.print(
            "[bold red]Scan history isn't available from this server yet[/bold red] "
            "(HTTP 404 from /api/v1/scans - the endpoint isn't deployed). "
            "Your scans are still visible at "
            "[link=https://narvy.io]narvy.io[/link] under your dashboard "
            "in the meantime."
        )
        raise SystemExit(EXIT_ERROR)
    if status != 200:
        error_msg = data.get("error") or data.get("message") or data
        console.print(f"[bold red]Could not fetch scan history ({status}):[/bold red] {error_msg}")
        raise SystemExit(EXIT_ERROR)

    scans = data.get("scans", [])
    if args.format == "json":
        print(json.dumps(scans, indent=2))
        return

    if not scans:
        console.print(
            "[bold yellow]No scans found on your account yet.[/bold yellow] "
            "Run `narvy scan <path>` to scan locally. Submitting results here "
            "with `--upload` needs a paid plan (Starter and up)."
        )
        return

    table = Table(title=f"Recent scans ({creds['email']})")
    table.add_column("Scan ID", style="dim")
    table.add_column("App")
    table.add_column("Platform")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Submitted")
    for s in scans:
        scan_id = str(s.get("scan_id", "?"))
        status_val = str(s.get("status", "-"))
        status_style = {"done": "green", "failed": "red", "running": "yellow",
                        "queued": "dim", "scheduled": "dim", "pending_sast": "yellow"}.get(status_val, "white")
        table.add_row(
            scan_id[:8],
            rich_escape(str(s.get("app_name") or "-")),
            str(s.get("platform", "-")),
            str(s.get("analysis_type", "-")),
            f"[{status_style}]{status_val}[/{status_style}]",
            str(s.get("vulnerabilities_found", "-")),
            str(s.get("timestamp", "-")),
        )
    out_console.print(table)
    console.print(f"Full detail at [link=https://narvy.io]narvy.io[/link] under your dashboard.")


def _run_local_scan(apk_path, max_mem, override_config=None, force=False,
                    native_apk_path=None, extra_dex_inputs=None):
    """Android binary scan. Extra APKs go through the same jadx run."""
    if native_apk_path is None:
        native_apk_path = apk_path
    decompile_error = None
    sca_cov = None
    with scan_progress() as progress:
        task1 = progress.add_task("[green]Decompiling APK...", total=1)
        with tempfile.TemporaryDirectory() as temp_dir:
            ok, decompile_error = decompile_apk(apk_path, temp_dir, max_mem, force=force,
                                                extra_inputs=extra_dex_inputs)
            if not ok:
                progress.update(task1, completed=1, description="[red]Decompilation Failed.")
                progress.stop()
                # Progress owns the cursor: printing before stop() mangles this.
                console.print(f"\n[bold red]{decompile_error}[/bold red]\n")
                return None
            progress.update(task1, completed=1, description="[green]Decompilation Complete.")

            task2 = progress.add_task("[cyan]Analyzing files...", total=None)
            rules_path = os.path.join(os.path.dirname(__file__), 'rules', 'android')
            rules = load_rules_from_dir(rules_path)
            progress.update(task2, description=f"[cyan]Analyzing with {len(rules)} rules...")

            all_findings = []
            all_source_files = [os.path.join(root, file) for root, _, files in os.walk(temp_dir) for file in files if file.endswith(('.java', '.kt', '.xml'))]

            own_roots = get_own_package_roots(temp_dir)
            if own_roots:
                console.print(f"[dim]App package roots: {', '.join(sorted(own_roots))} (scoping analysis to this app's own code).[/dim]")
            else:
                console.print("[dim]Could not determine app package from manifest - falling back to known-SDK denylist.[/dim]")

            source_files = [f for f in all_source_files if resolve_file_scope(f, own_roots, override_config)]
            skipped = len(all_source_files) - len(source_files)
            if skipped:
                console.print(f"[dim]Skipped {skipped} third-party/framework files ({skipped * 100 // len(all_source_files)}%).[/dim]")
            if override_config:
                override_calls = [check_android_override(f, override_config) for f in all_source_files]
                forced_own = override_calls.count('own')
                forced_vendor = override_calls.count('vendor')
                if forced_own or forced_vendor:
                    console.print(
                        f"[dim].narvy-scope.yml overrides ({override_config.source_path}): "
                        f"{forced_own} file(s) forced first-party, "
                        f"{forced_vendor} file(s) forced third-party-excluded.[/dim]"
                    )

            progress.update(task2, total=len(source_files))
            for file_path in source_files:
                relative_path = os.path.relpath(file_path, temp_dir)
                findings_in_file = run_rules_on_file(file_path, rules)
                for finding in findings_in_file:
                    finding['file_path'] = relative_path
                    finding['engine'] = 'regex'
                all_findings.extend(findings_in_file)

                if file_path.endswith(('.java', '.kt')):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
                            taint_findings = crypto_taint_lite.check_file(fh.read())
                    except OSError:
                        taint_findings = []
                    for finding in taint_findings:
                        finding['file_path'] = relative_path
                    all_findings.extend(taint_findings)

                progress.update(task2, advance=1)
            progress.update(task2, description="[green]Analysis Complete.")

            # Semgrep takes a directory plus exclude globs, not a file list.
            if semgrep_engine.is_available():
                console.print("[dim]Running deep structural analysis (AST-aware, taint-tracking) - can take several minutes on larger apps, this is normal, don't interrupt.[/dim]")
                task3 = progress.add_task("[cyan]Deep structural analysis...", total=None)
                semgrep_findings = semgrep_engine.run_semgrep(temp_dir, own_roots=own_roots, override_config=override_config)
                if semgrep_findings:
                    all_findings.extend(semgrep_findings)
                _sg_note = semgrep_engine.degraded_coverage_note()
                if _sg_note:
                    progress.update(task3, completed=1, description="[yellow]Deep analysis INCOMPLETE (partial coverage).")
                    console.print(f"[bold yellow]{_sg_note}[/bold yellow]")
                else:
                    progress.update(task3, completed=1, description=f"[green]Deep analysis complete ({len(semgrep_findings or [])} findings).")
            else:
                console.print("[dim]semgrep not found - install with `pip install semgrep` for deeper structural detection. Continuing with regex rules only.[/dim]")

            # Runs against the raw zip at apk_path, not the decompiled temp_dir.
            console.print("[dim]Checking third-party dependencies against OSV.dev (SCA)...[/dim]")
            try:
                sca_findings, sca_rule_defs, sca_stats = sca_android_deps.scan(apk_path)
                all_findings.extend(sca_findings)
                rules.extend(sca_rule_defs)
                sca_cov = _sca_coverage(sca_stats)
                if not _sca_not_applicable(sca_stats, "apk"):
                    console.print(
                        f"[dim]SCA: checked {sca_stats['unique_dependencies_checked']} unique "
                        f"dependencies against OSV.dev, found {sca_stats['cves_found']} known "
                        f"CVE(s) across {sca_stats['vulnerable_dependencies']} dependency(ies).[/dim]"
                    )
                if sca_stats.get("dependencies_capped"):
                    _detected = sca_stats["unique_dependencies_detected"]
                    _checked = sca_stats["unique_dependencies_checked"]
                    console.print(
                        f"[bold yellow]SCA is INCOMPLETE: {_detected} unique "
                        f"dependencies were found but only {_checked} were queried "
                        f"({_detected - _checked} not checked) - the free OSV.dev API "
                        f"is rate-considerate-capped. Treat 0 CVEs on the remainder "
                        f"as UNKNOWN, not as clean.[/bold yellow]"
                    )
            except Exception as e:
                console.print(f"[dim]SCA dependency check failed (continuing without it): {e}[/dim]")

            console.print("[dim]Checking native library (.so) hardening flags (NX/PIE/RELRO/canary/RPATH)...[/dim]")
            try:
                nh_findings, nh_rule_defs, nh_stats = native_hardening.scan(native_apk_path)
                all_findings.extend(nh_findings)
                rules.extend(nh_rule_defs)
                if nh_stats["arch_analyzed"]:
                    console.print(
                        f"[dim]Native hardening: checked {nh_stats['libs_analyzed']} native "
                        f"librar{'y' if nh_stats['libs_analyzed'] == 1 else 'ies'} "
                        f"({nh_stats['own_libs_analyzed']} app-owned, "
                        f"{nh_stats['vendor_libs_analyzed']} known third-party/bundled) on "
                        f"{nh_stats['arch_analyzed']}, found {nh_stats['findings']} hardening "
                        f"gap(s).[/dim]"
                    )
                elif not nh_stats["lief_available"]:
                    console.print("[dim]Native hardening check skipped (lief not installed).[/dim]")
            except Exception as e:
                console.print(f"[dim]Native hardening check failed (continuing without it): {e}[/dim]")
    return all_findings, rules, {"sca_coverage": sca_cov}


_SCA_NOT_APPLICABLE = {
    "apk": ("SCA: not applicable to this app - no third-party library with a readable "
            "version was found in it (release builds usually strip that metadata), so "
            "no dependency CVE check could run. This is not a clean result."),
    "ipa": ("SCA: not applicable to this app - no embedded framework with a readable "
            "version was found, so no framework CVE check could run. This is not a "
            "clean result."),
    "source": ("SCA: not applicable here - no dependency manifest or lockfile with "
               "resolvable versions was found, so no dependency CVE check could run. "
               "This is not a clean result."),
}


def _sca_not_applicable(stats, kind):
    """Say SCA had nothing to check instead of printing '0 CVEs'. True if printed."""
    detected = stats.get("unique_dependencies_detected")
    if detected is None:
        detected = stats.get("total_dependencies_detected")
    if detected is None:
        detected = stats.get("unique_dependencies_checked", 0)
    if detected or stats.get("osv_unreachable"):
        return False
    console.print(f"[dim]{_SCA_NOT_APPLICABLE[kind]}[/dim]")
    return True


def _sca_coverage(stats):
    """SCA coverage flag for machine output: 'complete', or 'partial' when a rate limit truncated the dependency queries."""
    detected = stats.get("unique_dependencies_detected")
    if detected is None:
        detected = stats.get("total_dependencies_detected")
    checked = stats.get("unique_dependencies_checked", 0)
    if detected is None:
        detected = checked
    reasons = []
    if stats.get("dependencies_capped"):
        reasons.append("osv_dependency_cap")
    if stats.get("github_rate_limited"):
        reasons.append("github_advisory_rate_limit")
    # A manifest whose deps never reached OSV (e.g. Gemfile without a lock)
    # means 'partial', not 'complete'.
    unparsed = stats.get("unparsed_manifests") or []
    if unparsed:
        reasons.append("unparsed_manifest")
    # An OSV outage / cold cache means "0 CVEs" is UNKNOWN, not clean: degrade, don't pass.
    unreachable = bool(stats.get("osv_unreachable"))
    if unreachable:
        reasons.append("osv_unreachable")
    # Zero resolved deps is never 'complete': it usually means a manifest
    # format we don't parse yet.
    if not detected and not unreachable and not reasons:
        status = "none"
    else:
        status = "degraded" if unreachable else ("partial" if reasons else "complete")
    cov = {
        "status": status,
        "dependencies_detected": detected,
        "dependencies_checked": checked,
    }
    if status == "none":
        # Not a clean bill: there was nothing this pass could check.
        cov["applicable"] = False
        cov["note"] = "no dependency with a resolvable version was found; nothing was checked"
    if reasons:
        cov["degraded_reasons"] = reasons
    if unparsed:
        cov["unparsed_manifests"] = unparsed
    if stats.get("osv_dependencies_unresolved"):
        cov["dependencies_unresolved"] = stats["osv_dependencies_unresolved"]
    return cov


def _warn_github_advisory_truncated(stats):
    if not stats.get("github_rate_limited"):
        return
    console.print(
        f"[bold yellow]SCA is INCOMPLETE: the GitHub Advisory database was "
        f"rate-limited after {stats.get('github_queries_made', 0)} query(ies), so "
        f"the remaining dependencies were checked only against OSV.dev + the local "
        f"CVE DB. Set a GITHUB_TOKEN environment variable to raise the limit. Treat "
        f"0 CVEs on the un-queried remainder as UNKNOWN, not as clean.[/bold yellow]"
    )


def _run_ios_source_scan(source_dir):
    """None on hard failure, else (findings, rule_defs, meta)."""
    with scan_progress() as progress:
        task = progress.add_task("[cyan]Scanning Swift/Objective-C source...", total=None)
        result = ios_source_analyzer.analyze_source(source_dir)
        progress.update(task, completed=1, description="[green]Analysis Complete." if (isinstance(result, dict) and result.get("ok")) else "[red]Analysis failed.")

    if not result["ok"]:
        console.print(f"\n[bold red]{result['error']}[/bold red]\n")
        return None

    for note in result["notes"]:
        console.print(f"[dim]{rich_escape(note)}[/dim]")
    console.print(
        f"[dim]Scanned {result['swift_files_scanned']} Swift file(s) and "
        f"{result['objc_files_scanned']} Objective-C file(s); skipped "
        f"{result['skipped_third_party']} third-party/vendored file(s).[/dim]"
    )

    console.print("[dim]Checking Podfile.lock / Package.resolved dependencies for known CVEs (SCA)...[/dim]")
    sca_cov = None
    try:
        sca_findings, sca_rule_defs, sca_stats = sca_ios_deps.scan_source(source_dir)
        result["findings"].extend(sca_findings)
        result["rule_defs"].extend(sca_rule_defs)
        sca_cov = _sca_coverage(sca_stats)
        if not _sca_not_applicable(sca_stats, "source"):
            console.print(
                f"[dim]SCA: checked {sca_stats['unique_dependencies_checked']} unique "
                f"dependencies, found {sca_stats['cves_found']} known CVE(s) across "
                f"{sca_stats['vulnerable_dependencies']} dependency(ies).[/dim]"
            )
        _warn_github_advisory_truncated(sca_stats)
    except Exception as e:
        console.print(f"[dim]SCA dependency check failed (continuing without it): {e}[/dim]")

    return result["findings"], result["rule_defs"], {"sca_coverage": sca_cov}


def _run_android_source_scan(source_dir, override_config=None):
    """None on hard failure, else (findings, rule_defs). No decompile step."""
    with scan_progress() as progress:
        task = progress.add_task("[cyan]Scanning Android Gradle/Java/Kotlin source...", total=None)
        result = android_source_analyzer.analyze_source(source_dir, override_config=override_config)
        progress.update(task, completed=1, description="[green]Analysis Complete." if (isinstance(result, dict) and result.get("ok")) else "[red]Analysis failed.")

    if not result["ok"]:
        console.print(f"\n[bold red]{result['error']}[/bold red]\n")
        return None

    for note in result["notes"]:
        console.print(f"[dim]{rich_escape(note)}[/dim]")
    if result["own_roots"]:
        console.print(
            f"[dim]App package roots: {', '.join(result['own_roots'])} "
            f"(scoping analysis to this app's own code, across "
            f"{result['manifests_found']} module manifest(s) found).[/dim]"
        )
    console.print(
        f"[dim]Scanned {result['code_files_scanned']} Java/Kotlin file(s) and "
        f"{result['xml_files_scanned']} XML file(s); skipped "
        f"{result['skipped_third_party']} third-party/vendored file(s).[/dim]"
    )

    console.print(
        f"[dim]Checking {sca_web_deps.SUPPORTED_ECOSYSTEMS_LABEL} dependencies "
        f"(build.gradle/build.gradle.kts/Gemfile.lock/etc.) for known CVEs (SCA)...[/dim]"
    )
    sca_cov = None
    try:
        sca_findings, sca_rule_defs, sca_stats = sca_web_deps.scan(source_dir)
        result["findings"].extend(sca_findings)
        result["rule_defs"].extend(sca_rule_defs)
        sca_cov = _sca_coverage(sca_stats)
        if not _sca_not_applicable(sca_stats, "source"):
            console.print(
                f"[dim]SCA: checked {sca_stats['unique_dependencies_checked']} unique "
                f"dependencies against OSV.dev, found {sca_stats['cves_found']} known "
                f"CVE(s) across {sca_stats['vulnerable_dependencies']} dependency(ies).[/dim]"
            )
        if sca_stats.get("dependencies_capped"):
            skipped = sca_stats["unique_dependencies_detected"] - sca_stats["unique_dependencies_checked"]
            console.print(
                f"[bold yellow]SCA is INCOMPLETE: {sca_stats['unique_dependencies_detected']} "
                f"unique dependencies were found but only "
                f"{sca_stats['unique_dependencies_checked']} were queried "
                f"({skipped} not checked) - the free OSV.dev API is rate-"
                f"considerate-capped. Treat 0 CVEs on the remainder as "
                f"UNKNOWN, not as clean.[/bold yellow]"
            )
    except Exception as e:
        console.print(f"[dim]SCA dependency check failed (continuing without it): {e}[/dim]")

    return result["findings"], result["rule_defs"], {"sca_coverage": sca_cov}


def _run_web_source_scan(source_dir):
    """None on hard failure, else (findings, rule_defs)."""
    with scan_progress() as progress:
        task = progress.add_task(
            f"[cyan]Scanning web/backend source "
            f"({web_source_analyzer.SUPPORTED_LANGUAGES_LABEL})...",
            total=None,
        )
        result = web_source_analyzer.analyze_source(source_dir)
        progress.update(task, completed=1, description="[green]Analysis Complete." if (isinstance(result, dict) and result.get("ok")) else "[red]Analysis failed.")

    if not result["ok"]:
        console.print(f"\n[bold red]{result['error']}[/bold red]\n")
        return None

    for note in result["notes"]:
        console.print(f"[dim]{rich_escape(note)}[/dim]")
    if result["stacks_detected"]:
        console.print(
            f"[dim]Detected stack(s): {', '.join(result['stacks_detected'])} "
            f"({result['files_scanned']} source file(s) in scope).[/dim]"
        )

    console.print(
        f"[dim]Checking {sca_web_deps.SUPPORTED_ECOSYSTEMS_LABEL} dependencies "
        f"for known CVEs (SCA)...[/dim]"
    )
    sca_cov = None
    try:
        sca_findings, sca_rule_defs, sca_stats = sca_web_deps.scan(source_dir)
        result["findings"].extend(sca_findings)
        result["rule_defs"].extend(sca_rule_defs)
        sca_cov = _sca_coverage(sca_stats)
        if not _sca_not_applicable(sca_stats, "source"):
            console.print(
                f"[dim]SCA: checked {sca_stats['unique_dependencies_checked']} unique "
                f"dependencies against OSV.dev, found {sca_stats['cves_found']} known "
                f"CVE(s) across {sca_stats['vulnerable_dependencies']} dependency(ies).[/dim]"
            )
        if sca_stats.get("dependencies_capped"):
            skipped = sca_stats["unique_dependencies_detected"] - sca_stats["unique_dependencies_checked"]
            console.print(
                f"[yellow]SCA is INCOMPLETE: {sca_stats['unique_dependencies_detected']} "
                f"unique dependencies were found but only "
                f"{sca_stats['unique_dependencies_checked']} were queried "
                f"({skipped} not checked) - the free OSV.dev API is rate-"
                f"considerate-capped. Treat 0 CVEs on the remainder as "
                f"UNKNOWN, not as clean.[/yellow]"
            )
    except Exception as e:
        console.print(f"[dim]SCA dependency check failed (continuing without it): {e}[/dim]")

    return result["findings"], result["rule_defs"], {"sca_coverage": sca_cov}


def _run_ios_binary_scan(ipa_path, override_config=None):
    """(findings, rule_defs, meta) or None on hard failure. meta has {"encrypted": bool}."""
    with scan_progress() as progress:
        task = progress.add_task("[cyan]Extracting and analyzing Mach-O binary...", total=None)
        result = ios_binary_analyzer.analyze_ipa(ipa_path, override_config=override_config)
        progress.update(task, completed=1, description="[green]Analysis Complete." if (isinstance(result, dict) and result.get("ok")) else "[red]Analysis failed.")

    if not result["ok"]:
        console.print(f"\n[bold red]{result['error']}[/bold red]\n")
        return None

    if result.get("encrypted"):
        console.print(f"\n[bold yellow]{result['encrypted_message']}[/bold yellow]\n")
    for note in result["notes"]:
        console.print(f"[dim]{rich_escape(note)}[/dim]")

    # Embedded-framework SCA works even on a FairPlay-encrypted IPA.
    console.print("[dim]Checking embedded frameworks for known CVEs (SCA)...[/dim]")
    sca_cov = None
    try:
        sca_findings, sca_rule_defs, sca_stats = sca_ios_deps.scan_binary(ipa_path)
        result["findings"].extend(sca_findings)
        result["rule_defs"].extend(sca_rule_defs)
        sca_cov = _sca_coverage(sca_stats)
        if not _sca_not_applicable(sca_stats, "ipa"):
            console.print(
                f"[dim]SCA: checked {sca_stats['unique_dependencies_checked']} unique "
                f"embedded framework(s), found {sca_stats['cves_found']} known CVE(s) across "
                f"{sca_stats['vulnerable_dependencies']} framework(s).[/dim]"
            )
        _warn_github_advisory_truncated(sca_stats)
    except Exception as e:
        console.print(f"[dim]SCA dependency check failed (continuing without it): {e}[/dim]")

    return result["findings"], result["rule_defs"], {"encrypted": bool(result.get("encrypted")), "sca_coverage": sca_cov}


def _run_split_bundle_scan(bundle_path, max_mem, override_config=None, force=False):
    """Unpack a .apkm/.xapk/.apks and hand the members to _run_local_scan. None on hard failure, else (findings, rule_defs)."""
    tmp_dir = tempfile.mkdtemp(prefix="narvy-bundle-")
    try:
        try:
            bundle = split_bundle.extract_for_scan(bundle_path, tmp_dir)
        except split_bundle.SplitBundleError as e:
            console.print(f"\n[bold red]{e}[/bold red]\n")
            return None

        for style, text in split_bundle.summary_lines(bundle):
            # markup=False: rich would otherwise eat bracketed package names.
            console.print(text, style=style, markup=False)

        return _run_local_scan(
            bundle.base_apk_path,
            max_mem,
            override_config=override_config,
            force=force,
            native_apk_path=bundle.native_apk_path or bundle.base_apk_path,
            extra_dex_inputs=bundle.feature_apk_paths,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEV_STYLE = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue",
              "LOW": "cyan", "INFO": "dim"}
_CONF_STYLE = {"LOW": "dim", "MEDIUM": "white", "HIGH": "bold"}


def _finding_location_text(finding: Dict[str, Any]) -> str:
    """'File:Line', or 'File (symbol)' for binary findings without line info."""
    # file_path and location_symbol carry attacker-controlled text from the
    # scanned target: escape before rich parses it as markup.
    location_symbol = finding.get('location_symbol')
    file_path = rich_escape(str(finding.get('file_path', '')))
    if location_symbol:
        return f"{file_path} [dim]({rich_escape(str(location_symbol))})[/dim]"
    return f"{file_path}:{finding.get('line', '?')}"


def _details_text(value: Any) -> str:
    """Coerce `details` to a string (semgrep metadata can be a YAML list)."""
    if isinstance(value, list):
        return ", ".join(str(v).strip() for v in value if v)
    return str(value or "").strip()


def _render_finding_panel(finding: Dict[str, Any]) -> Panel:
    """One finding: location, description, recommendation and CWE/MASVS refs."""
    severity = str(finding.get('severity') or 'UNKNOWN').upper()
    sev_style = _SEV_STYLE.get(severity, "white")
    confidence = finding.get('confidence', 'MEDIUM')
    conf_style = _CONF_STYLE.get(confidence, "white")
    details = finding.get('details') or {}
    # description/recommendation embed raw content from the scanned target.
    description = rich_escape(_details_text(details.get('description')))
    recommendation = rich_escape(_details_text(details.get('recommendation')))
    cwe = rich_escape(_details_text(details.get('cwe')))
    masvs = rich_escape(_details_text(details.get('masvs')))

    lines = [
        f"[dim]Location:[/dim] {_finding_location_text(finding)}",
        f"[dim]Confidence:[/dim] [{conf_style}]{confidence}[/{conf_style}]",
    ]
    if description:
        lines.append("")
        lines.append(description)
    if recommendation and recommendation != description:
        lines.append("")
        lines.append(f"[bold]Recommendation:[/bold] {recommendation}")
    ref_bits = [b for b in (cwe, masvs) if b]
    if ref_bits:
        lines.append("")
        lines.append(f"[dim]{'  ·  '.join(ref_bits)}[/dim]")

    body = "\n".join(lines)
    rule_name = rich_escape(str(finding.get('name') or finding.get('rule_id') or 'Finding'))
    title = f"[{sev_style}]{severity}[/{sev_style}] {rule_name}"
    return Panel(body, title=title, title_align="left", border_style=sev_style,
                 box=rich_box.ROUNDED, padding=(0, 1))


def _print_findings_detail(console: Console, all_findings: List[Dict[str, Any]]) -> None:
    """Per-finding detail, grouped by severity, most severe first."""
    known_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    for severity in known_order:
        group = [f for f in all_findings if str(f.get('severity') or '').upper() == severity]
        if not group:
            continue
        sev_style = _SEV_STYLE.get(severity, "white")
        console.print(f"\n[bold {sev_style}]{severity} ({len(group)})[/bold {sev_style}]")
        for finding in group:
            console.print(_render_finding_panel(finding))
    leftover = [f for f in all_findings if str(f.get('severity') or '').upper() not in known_order]
    if leftover:
        console.print(f"\n[bold white]OTHER ({len(leftover)})[/bold white]")
        for finding in leftover:
            console.print(_render_finding_panel(finding))


def _ingest_platform_for_scan_mode(scan_mode: str) -> str:
    """Map a scan_mode onto the platform value the ingest endpoint expects."""
    if scan_mode.startswith("ios"):
        return "ios"
    if scan_mode.startswith("web"):
        return "web"
    return "android"


def _ingest_scan_mode_label(scan_mode: str) -> str:
    """Send 'android-binary' instead of 'android' so the server doesn't file it as source."""
    return "android-binary" if scan_mode == "android" else scan_mode


def _submit_results_ingest(all_findings, scan_mode, target_path):
    """POST results to /api/v1/ingest. Exits with EXIT_ERROR on any failure."""
    creds = auth.load_credentials()
    if not creds:
        console.print("[bold red]Not logged in.[/bold red] Run `narvy login` first, or drop --upload for a local-only scan.")
        raise SystemExit(EXIT_ERROR)

    platform = _ingest_platform_for_scan_mode(scan_mode)
    app_name = os.path.basename(os.path.normpath(target_path))
    app_name = re.sub(r"\.(zip|apk|aab|ipa|xapk|apkm|apks)$", "", app_name, flags=re.IGNORECASE) or app_name

    console.print(
        f"[cyan]Uploading {len(all_findings)} finding(s) to {creds['email']} "
        f"for server-side curation...[/cyan]"
    )
    try:
        status, data = uploader.ingest_results(
            creds["token"], app_name=app_name, platform=platform,
            scan_mode=_ingest_scan_mode_label(scan_mode), findings=all_findings,
        )
    except Exception as e:
        console.print(f"[bold red]Upload failed:[/bold red] {e}")
        raise SystemExit(EXIT_ERROR)

    if status not in (200, 201):
        asset_msg = _format_asset_limit_error(data) if status == 402 else None
        if asset_msg:
            console.print(f"[bold red]{asset_msg}[/bold red]")
            raise SystemExit(EXIT_ERROR)
        error_msg = data.get("error") or data if isinstance(data, dict) else data
        console.print(f"[bold red]Upload failed ({status}):[/bold red] {error_msg}")
        if isinstance(data, dict) and data.get("message"):
            console.print(f"[dim]{data['message']}[/dim]")
        _print_upgrade_hint(status, data)
        raise SystemExit(EXIT_ERROR)

    scan_id = data.get("scan_id")
    received = data.get("cli_findings_received", len(all_findings))
    normalized = data.get("normalized", "?")
    total_detected = data.get("total_detected", "?")
    actionable = data.get("actionable", "?")
    hidden = data.get("hidden", "?")
    dropped = data.get("dropped", 0)

    console.print(f"[bold green]Results uploaded.[/bold green] scan_id={scan_id}")
    console.print(
        f"[dim]CLI detected {received} -> Narvy cloud curated: {total_detected} distinct "
        f"after dedup, {actionable} actionable, {hidden} hidden by default view.[/dim]"
    )
    if dropped:
        console.print(
            f"[bold yellow]{dropped} finding(s) were DROPPED server-side during "
            f"normalization (unidentifiable/malformed) - they are NOT in the "
            f"dashboard. See the server response for details.[/bold yellow]"
        )
        for d in (data.get("dropped_details") or [])[:10]:
            console.print(f"  [yellow]- idx {d.get('index')}: {d.get('reason')}[/yellow]")
    scan_url = _scan_dashboard_url(data)
    if scan_url:
        console.print(f"View this scan: [link={scan_url}]{scan_url}[/link]")
    else:
        console.print("Track it at [link=https://narvy.io]narvy.io[/link] under your dashboard.")
    return data


def _submit_results_by_surface(all_findings, scan_mode, target_path, scan_meta=None):
    """Upload each scanned surface under its own platform (nested iOS goes up as iOS source)."""
    by_root: Dict[str, List[Dict[str, Any]]] = {}
    main: List[Dict[str, Any]] = []
    for f in all_findings:
        root = f.get("_surface_root")
        if root:
            g = {k: v for k, v in f.items() if k != "_surface_root"}
            fp = g.get("file_path") or ""
            prefix = root.rstrip(os.sep) + os.sep
            if fp.startswith(prefix):
                g["file_path"] = fp[len(prefix):]
            by_root.setdefault(root, []).append(g)
        else:
            main.append(f)
    for s in (scan_meta or {}).get("surfaces", [])[1:]:
        if s.get("mode") == "ios-source" and s.get("status") != "failed":
            by_root.setdefault(s["path"], [])
    _submit_results_ingest(main, scan_mode, target_path)
    for root, findings in by_root.items():
        console.print(f"[dim]iOS project in {rich_escape(root)}/:[/dim]")
        _submit_results_ingest(findings, "ios-source", os.path.join(target_path, root))


def _scan_to_json(all_findings, rules, scan_mode, target_path, encrypted, scan_meta=None):
    """Flat machine-readable JSON for `narvy scan --output json`."""
    by_sev: Dict[str, int] = {}
    out_findings: List[Dict[str, Any]] = []
    for f in all_findings:
        sev = str(f.get("severity", "") or "").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        details = f.get("details") if isinstance(f.get("details"), dict) else {}
        out_findings.append({
            "rule_id": f.get("rule_id"),
            "name": f.get("name"),
            "severity": sev,
            "confidence": f.get("confidence", "MEDIUM"),
            "file_path": f.get("file_path"),
            "line": f.get("line"),
            "location_symbol": f.get("location_symbol"),
            "engine": f.get("engine"),
            "description": details.get("description"),
            "recommendation": details.get("recommendation"),
            "cwe": details.get("cwe"),
            "masvs": details.get("masvs"),
        })
    summary = {
        "total_findings": len(all_findings),
        "by_severity": by_sev,
    }
    sca_cov = (scan_meta or {}).get("sca_coverage")
    if sca_cov is not None:
        summary["sca_coverage"] = sca_cov
    uncovered = (scan_meta or {}).get("uncovered_surfaces")
    if uncovered:
        summary["uncovered_surfaces"] = uncovered
    surfaces = (scan_meta or {}).get("surfaces")
    if surfaces:
        summary["surfaces"] = surfaces
    premium = (scan_meta or {}).get("premium_checks_not_run")
    if premium:
        summary["premium_checks_not_run"] = premium
    return {
        "tool": "Narvy CLI",
        "version": __version__,
        "scan_mode": scan_mode,
        "target": os.path.basename(target_path),
        "encrypted": bool(encrypted),
        "summary": summary,
        "findings": out_findings,
    }


def _scanned_modes_label(scan_mode, scan_meta):
    extra = [s["mode"] + " (" + s["path"] + ")" for s in (scan_meta or {}).get("surfaces", [])[1:]]
    return scan_mode + (" + " + ", ".join(extra) if extra else "")


def _scan_nested_ios_surfaces(target_path, ios_roots, all_findings, rules, scan_meta):
    """Scan nested iOS projects and merge their findings into the web-source results."""
    scan_meta = dict(scan_meta)
    surfaces = scan_meta.setdefault("surfaces", [{"mode": "web-source", "path": "."}])
    web_semgrep_run = dict(semgrep_engine.LAST_RUN)
    all_findings = list(all_findings)
    rules = list(rules)
    for ios_root in ios_roots:
        rel_root = os.path.relpath(ios_root, target_path)
        console.print(f"\n[cyan]iOS project found in {rich_escape(rel_root)}/ - scanning it too.[/cyan]")
        res = _run_ios_source_scan(ios_root)
        if res is None:
            surfaces.append({"mode": "ios-source", "path": rel_root, "status": "failed"})
            scan_meta.setdefault("uncovered_extra", []).append(
                f"The iOS project in {rel_root}/ could not be scanned (see the error above)."
            )
            continue
        ios_findings, ios_rules, ios_meta = res
        for f in ios_findings:
            fp = f.get("file_path")
            if fp and not os.path.isabs(fp):
                f["file_path"] = os.path.join(rel_root, fp)
            f["_surface_root"] = rel_root
        all_findings.extend(ios_findings)
        known = {r.get("id") for r in rules if isinstance(r, dict)}
        rules.extend(r for r in ios_rules if not (isinstance(r, dict) and r.get("id") in known))
        surfaces.append({"mode": "ios-source", "path": rel_root,
                         "findings": len(ios_findings),
                         "sca_coverage": (ios_meta or {}).get("sca_coverage")})
    # A degraded web pass must not be hidden by a clean iOS pass that ran after it.
    if web_semgrep_run.get("degraded") and not semgrep_engine.LAST_RUN.get("degraded"):
        semgrep_engine.LAST_RUN.update(web_semgrep_run)
    return all_findings, rules, scan_meta


def cmd_scan(args):
    target_path = args.apk_path
    if getattr(args, "upload_binary", False):
        args.upload = True
    if not os.path.exists(target_path):
        console.print(f"[bold red]Error:[/bold red] File not found at {target_path}")
        raise SystemExit(EXIT_BAD_TARGET)

    try:
        scan_mode = _detect_scan_mode(target_path)
    except UnsupportedScanTarget as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise SystemExit(EXIT_BAD_TARGET)
    telemetry.note(surface=telemetry.surface_for_scan_mode(scan_mode))
    if scan_mode in ("android", "ios-binary") and not zipfile.is_zipfile(target_path):
        console.print(f"[bold red]Error:[/bold red] {target_path} is not a valid zip archive, "
                      "so it can't be an APK, AAB or IPA. The file may be truncated or corrupt.")
        raise SystemExit(EXIT_BAD_TARGET)

    # Fail fast on bad input before the (possibly long) scan starts.
    # Check login first so --upload doesn't fail only after the scan.
    if args.upload or getattr(args, "upload_binary", False):
        if not auth.load_credentials():
            console.print("[bold red]Not logged in.[/bold red] Run `narvy login` first.")
            raise SystemExit(EXIT_ERROR)

    # --max-mem goes straight to JADX as -Xmx; validate before a bad value leaks a raw JVM error.
    if scan_mode in ("android", "android-bundle"):
        if not _MAX_MEM_RE.match(str(args.max_mem or "")):
            console.print(
                f"[bold red]Invalid --max-mem value '{args.max_mem}'.[/bold red] "
                "Expected a JADX heap size like '4g', '2048m' or '512k' "
                "(digits optionally followed by k/m/g)."
            )
            raise SystemExit(EXIT_BAD_TARGET)

    # Make sure the --file destination is writable before scanning.
    if args.output in ("sarif", "json") and args.file != "-":
        _default_out = "narvy-results.sarif" if args.output == "sarif" else "narvy-results.json"
        _preflight_out = args.file or _default_out
        _werr = _preflight_output_writable(_preflight_out)
        if _werr:
            console.print(f"[bold red]Cannot write {args.output.upper()} output to {_preflight_out}: {_werr}.[/bold red]")
            console.print("[dim]Check the parent directory exists and is writable, or pick a different --file path.[/dim]")
            raise SystemExit(EXIT_ERROR)

    # Android and iOS-binary paths only: iOS source mode classifies vendored
    # code by directory convention instead.
    override_config = load_scope_config(target_path)
    if override_config:
        console.print(f"[dim]Loaded scope overrides from {override_config.source_path}: "
                       f"{len(override_config.own)} 'own' pattern(s), "
                       f"{len(override_config.vendor)} 'vendor' pattern(s).[/dim]")

    if scan_mode == "ios-source":
        result = _run_ios_source_scan(target_path)
    elif scan_mode == "ios-binary":
        result = _run_ios_binary_scan(target_path, override_config=override_config)
    elif scan_mode == "android-source":
        result = _run_android_source_scan(target_path, override_config=override_config)
    elif scan_mode == "web-source":
        result = _run_web_source_scan(target_path)
    elif scan_mode == "android-bundle":
        result = _run_split_bundle_scan(target_path, args.max_mem,
                                        override_config=override_config,
                                        force=getattr(args, "force", False))
    else:
        result = _run_local_scan(target_path, args.max_mem,
                                 override_config=override_config,
                                 force=getattr(args, "force", False))

    if result is None:
        raise SystemExit(EXIT_ERROR)
    if len(result) == 3:
        all_findings, rules, scan_meta = result
    else:
        all_findings, rules = result
        scan_meta = {}
    encrypted_scan = bool(scan_meta.get("encrypted"))

    # A web repo can also carry a whole iOS app in a subdirectory (a server/ next
    # to an Xcode project). Scan that surface too instead of reporting it unscanned.
    extra_ios_roots = []
    if scan_mode == "web-source":
        extra_ios_roots = _nested_ios_project_roots(target_path)
    if extra_ios_roots:
        all_findings, rules, scan_meta = _scan_nested_ios_surfaces(
            target_path, extra_ios_roots, all_findings, rules, scan_meta)

    # Say so when a hybrid repo (RN/Flutter/Capacitor) has code this mode
    # didn't cover, instead of exiting 0 silently.
    uncovered_notes = _uncovered_surface_notes(target_path, scan_mode,
                                               extra_ios_roots=extra_ios_roots)
    uncovered_notes += scan_meta.get("uncovered_extra", [])

    premium_counts = {}
    if scan_mode == "web-source":
        try:
            premium_counts = web_source_analyzer.detect_premium_frameworks(target_path)
        except Exception:
            premium_counts = {}
        if premium_counts:
            scan_meta = dict(scan_meta)
            scan_meta["premium_checks_not_run"] = premium_counts
    if uncovered_notes:
        scan_meta = dict(scan_meta)
        scan_meta["uncovered_surfaces"] = uncovered_notes

    if args.output in ('sarif', 'json'):
        # Written to a file, never stdout: progress notes would interleave.
        if args.output == 'sarif':
            report = generate_sarif_report(
                all_findings, rules,
                encrypted=encrypted_scan,
                encrypted_artifact_uri=os.path.basename(target_path) if encrypted_scan else None,
            )
            out_file = args.file or "narvy-results.sarif"
            label = "SARIF report"
        else:
            report = _scan_to_json(all_findings, rules, scan_mode, target_path, encrypted_scan, scan_meta=scan_meta)
            out_file = args.file or "narvy-results.json"
            label = "JSON report"
        # `--file -` streams machine output to stdout (progress/notes go to stderr) so `... -f - | jq` works.
        if args.file == "-":
            sys.stdout.write(json.dumps(report, indent=2) + "\n")
            sys.stdout.flush()
        else:
            try:
                with open(out_file, 'w') as f:
                    json.dump(report, f, indent=2)
            except OSError as e:
                console.print(f"\n[bold red]Could not write {label} to {out_file}: {e}[/bold red]")
                console.print("[dim]Check the parent directory exists and is writable, or pick a different --file path.[/dim]")
                raise SystemExit(EXIT_ERROR)
            console.print(f"\n[bold green]{label} saved to {out_file}[/bold green]")
    else:
        console.print("\n[bold]--- Local Analysis Complete ---[/bold]")
        if not all_findings:
            if encrypted_scan:
                console.print(
                    "[bold yellow]No issues in the readable surface of this "
                    "FairPlay-encrypted binary (see the encryption notice above). This is not "
                    "a verdict on the app's own code, which is encrypted here: Narvy dynamic "
                    "analysis on the platform covers it for most apps.[/bold yellow]"
                )
            else:
                console.print("[bold green]No issues found based on the current rule set.[/bold green]")
        else:
            console.print(f"[bold red]Found {len(all_findings)} potential issues:[/bold red]")
            table = Table(title="Vulnerability Summary")
            table.add_column("Severity", justify="center", style="bold")
            table.add_column("Rule Name", style="cyan")
            table.add_column("File", style="magenta")
            table.add_column("Line", justify="right", style="dim")
            table.add_column("Confidence", justify="center", style="dim")
            for finding in sorted(all_findings, key=lambda x: _SEV_ORDER.get(x['severity'], 5)):
                sev_style = _SEV_STYLE.get(finding['severity'], "white")
                confidence = finding.get('confidence', 'MEDIUM')
                conf_style = _CONF_STYLE.get(confidence, "white")
                # A compiled binary has no line-number table, so `line` there is
                # a placeholder kept only for SARIF.
                line_cell = "-" if finding.get('location_symbol') else str(finding.get('line', '?'))
                table.add_row(
                    f"[{sev_style}]{finding['severity']}[/{sev_style}]",
                    rich_escape(str(finding['name'])), rich_escape(str(finding['file_path'])), line_cell,
                    f"[{conf_style}]{confidence}[/{conf_style}]",
                )
            out_console.print(table)
            console.print()
            console.rule("[bold]Finding Detail[/bold]")
            _print_findings_detail(console, all_findings)
            console.print()
            if scan_mode in ("android", "android-bundle", "android-source",
                             "ios-binary", "ios-source"):
                console.print(
                    "[dim]Tip: seeing your own code flagged as third-party, or a vendor SDK "
                    "flagged as yours? Add a .narvy-scope.yml to this repo to correct "
                    f"it - see the '.narvy-scope.yml' section of {DOCS_URL}[/dim]"
                )

    if uncovered_notes:
        console.print(
            "\n[bold yellow]COVERAGE NOTICE: this scan did not cover the whole "
            f"project.[/bold yellow] Scanned mode: [bold]{_scanned_modes_label(scan_mode, scan_meta)}[/bold]."
        )
        for note in uncovered_notes:
            console.print(f"[bold yellow]  - {note}[/bold yellow]")

    _premium_note = web_source_analyzer.premium_checks_note(premium_counts)
    if _premium_note:
        console.print(f"\n[dim]{rich_escape(_premium_note)}[/dim]")

    if args.upload and not getattr(args, "upload_binary", False):
        _submit_results_by_surface(all_findings, scan_mode, target_path, scan_meta)
    elif args.upload:
        # Legacy --upload-binary: POST the binary and let the server re-scan it.
        # upload_scan() opens the path in binary mode, so refuse a directory.
        if scan_mode in ("ios-source", "android-source", "web-source"):
            platform_label = {"ios-source": "iOS", "android-source": "Android", "web-source": "web/backend"}[scan_mode]
            console.print(f"[bold red]--upload-binary isn't supported for {platform_label} source-directory scans[/bold red] (the binary re-scan API expects a single .apk/.aab/.ipa file). Use plain [bold]--upload[/bold] instead - it submits this scan's RESULTS for server-side curation and DOES support source directories.")
            raise SystemExit(EXIT_BAD_TARGET)
        creds = auth.load_credentials()
        if not creds:
            console.print("[bold red]Not logged in.[/bold red] Run `narvy login` first, or drop --upload for a local-only scan.")
            raise SystemExit(EXIT_ERROR)
        # The server does its own base-module extraction, so the original
        # bundle is what gets sent. `.apks` is not in its allowlist.
        if scan_mode == "android-bundle" and target_path.lower().endswith(".apks"):
            console.print(
                "[bold red]--upload isn't supported for .apks bundles[/bold red] "
                "(the server accepts .apk, .aab, .apkm and .xapk). The local scan above "
                "already ran and its results are shown; to get a server-side scan too, "
                "extract the app module yourself (`unzip -j app.apks splits/base-master.apk`) "
                "and upload that .apk."
            )
            raise SystemExit(EXIT_BAD_TARGET)
        upload_platform = "android" if scan_mode in ("android", "android-bundle") else "ios"
        confirm_upload = getattr(args, "confirm_upload", False)
        console.print(f"\n[cyan]Uploading {os.path.basename(target_path)} to Narvy for the full server-side scan ({creds['email']}, {creds['plan']})...[/cyan]")
        status, data = uploader.upload_scan(
            target_path, creds["token"], platform=upload_platform, analysis_type="sast",
            confirm_warning=confirm_upload,
        )
        # 409 means the triage severity is 'warn', which a resubmit with
        # confirm_warning=true clears. One retry at most.
        if status == 409 and not confirm_upload and sys.stdin.isatty() and sys.stdout.isatty():
            triage = data.get('triage') or {}
            severity = triage.get('severity', '?')
            score = triage.get('score', '?')
            console.print(f"[bold yellow]Triage verdict:[/bold yellow] severity={severity} score={score}")
            findings = triage.get('findings') or []
            if findings:
                console.print("[bold yellow]Triage findings:[/bold yellow]")
                for finding in findings:
                    console.print(f"  - {finding}")
            try:
                proceed = Confirm.ask("Upload anyway?", default=False)
            except (EOFError, KeyboardInterrupt):
                proceed = False
            if proceed:
                status, data = uploader.upload_scan(
                    target_path, creds["token"], platform=upload_platform, analysis_type="sast",
                    confirm_warning=True,
                )
                confirm_upload = True
        if status not in (200, 202):
            asset_msg = _format_asset_limit_error(data) if status == 402 else None
            if asset_msg:
                console.print(f"[bold red]{asset_msg}[/bold red]")
                raise SystemExit(EXIT_ERROR)
            # The malware-triage gate returns a 'triage' dict alongside the
            # top-level error on 400 (refuse) and 409 (warn).
            error_msg = data.get('error') or data.get('warning') or data
            console.print(f"[bold red]Upload failed ({status}):[/bold red] {error_msg}")
            _print_upgrade_hint(status, data)
            triage = data.get('triage')
            if isinstance(triage, dict):
                severity = triage.get('severity', '?')
                score = triage.get('score', '?')
                console.print(f"[bold yellow]Triage verdict:[/bold yellow] severity={severity} score={score}")
                bundle_id = triage.get('bundle_id')
                if bundle_id:
                    console.print(
                        f"[dim]bundle_id={bundle_id} "
                        f"signing_identity={triage.get('signing_identity')}[/dim]"
                    )
                findings = triage.get('findings') or []
                if findings:
                    console.print("[bold yellow]Triage findings:[/bold yellow]")
                    for finding in findings:
                        console.print(f"  - {finding}")
            if status == 409 and not confirm_upload:
                console.print(
                    "[dim]This was a warning, not a hard refusal - skip the interactive "
                    "confirmation next time (CI/non-interactive use) with "
                    "[bold]--confirm-upload[/bold].[/dim]"
                )
            else:
                hint = data.get('hint')
                if hint:
                    console.print(f"[dim]{hint}[/dim]")
            raise SystemExit(EXIT_ERROR)
        scan_id = data.get('scan_id')
        console.print(f"[bold green]Server scan submitted.[/bold green] scan_id={scan_id}")
        scan_url = _scan_dashboard_url(data)
        if scan_url:
            console.print(f"Follow it here: [link={scan_url}]{scan_url}[/link]")
        else:
            console.print("Track it at [link=https://narvy.io]narvy.io[/link] under your dashboard.")

        # Informational only: the response carries no app id to sync overrides to.
        if override_config:
            console.print(
                "[dim]Local scope overrides in "
                f"{override_config.source_path} only apply to this local check. "
                "The server scan does not read this file; set the same own/vendor "
                "rules on the app's dashboard page if you want them there.[/dim]"
            )
    else:
        console.print("\n[bold yellow]Local scan only, not linked to your account.[/bold yellow]")
        scope = {"android": "the decompiled app", "ios-binary": "the compiled binary only"}.get(
            scan_mode, "the source checkout")
        console.print(f"Scanned {scope} with {len(rules)} local rules. One row per rule hit, no de-duplication.")
        console.print("To keep results in your Narvy dashboard (de-duplication, false-positive filtering, "
                      "history), run `narvy login` and add [bold]--upload[/bold].")

    # SCA that could not reach OSV.dev (outage / cold cache) reports 0 CVEs as UNKNOWN, not clean.
    sca_cov = scan_meta.get("sca_coverage")
    if isinstance(sca_cov, dict) and sca_cov.get("status") == "degraded":
        _unres = sca_cov.get("dependencies_unresolved", 0)
        console.print(
            f"[bold yellow]SCA is INCOMPLETE: the OSV.dev vulnerability database was "
            f"unreachable (network error / cold cache), so {_unres} dependency(ies) "
            f"could not be checked. Treat 0 CVEs on those as UNKNOWN, not as clean - "
            f"re-run with network access to OSV.dev.[/bold yellow]"
        )

    # Must stay last so failing the build never swallows the report/upload.
    # A coverage gap = a pass that couldn't read the target, where exit 0 would falsely claim clean.
    coverage_gaps = []
    if getattr(args, "fail_on", None):
        if isinstance(sca_cov, dict) and sca_cov.get("status") == "degraded":
            coverage_gaps.append(
                "The SCA dependency pass could not reach the OSV.dev vulnerability "
                f"database for {sca_cov.get('dependencies_unresolved', 0)} dependency(ies) "
                "(network error / cold cache), so their CVE status is UNKNOWN. Re-run "
                "with network access to OSV.dev."
            )
        if encrypted_scan:
            coverage_gaps.append(
                "This IPA is FairPlay-encrypted: this local run covered the cleartext "
                "surface only, not the app's own (encrypted) code. Narvy dynamic analysis "
                "on the platform covers that code for most apps."
            )
        if scan_mode in ("android", "android-bundle", "android-source",
                         "ios-source", "web-source"):
            if not semgrep_engine.is_available():
                coverage_gaps.append(
                    "The deep structural (Semgrep) pass did not run at all - semgrep is not "
                    "on PATH. Install it (`pip install semgrep`) for the code analysis this "
                    "scan mode relies on."
                )
            else:
                _gap_note = semgrep_engine.degraded_coverage_note()
                if _gap_note:
                    coverage_gaps.append(_gap_note)
    _exit_on_fail_on(all_findings, getattr(args, "fail_on", None),
                     coverage_gaps=coverage_gaps)


_UPLOAD_ALL_TARGET_EXTS = (".apk", ".aab", ".apkm", ".xapk", ".ipa")
# .apks is excluded from the walk entirely: the server does not accept it.
_UPLOAD_ALL_SKIP_DIR_NAMES = frozenset({
    ".git", ".gradle", ".idea", ".vscode", ".vs", "build", "out", ".cxx",
    "node_modules", "Pods", "Carthage", "DerivedData", ".build", "venv",
    ".venv", "__pycache__", ".narvy",
})


def _find_upload_targets(directory, recursive=True):
    """Sorted scan targets under `directory`, plus a count of .apks skipped."""
    targets = []
    apks_skipped = 0
    if recursive:
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in _UPLOAD_ALL_SKIP_DIR_NAMES
                      and not d.startswith(".")]
            for name in files:
                ext = os.path.splitext(name)[1].lower()
                if ext in _UPLOAD_ALL_TARGET_EXTS:
                    targets.append(os.path.join(root, name))
                elif ext == ".apks":
                    apks_skipped += 1
    else:
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in _UPLOAD_ALL_TARGET_EXTS:
                targets.append(full)
            elif ext == ".apks":
                apks_skipped += 1
    return sorted(targets), apks_skipped


def cmd_upload_all(args):
    directory = args.directory
    if not os.path.isdir(directory):
        console.print(f"[bold red]Error:[/bold red] {directory} is not a directory.")
        raise SystemExit(EXIT_BAD_TARGET)

    creds = auth.load_credentials()
    if not creds:
        console.print("[bold red]Not logged in.[/bold red] Run `narvy login` first, or drop `upload-all` for local-only scanning of each app individually.")
        raise SystemExit(EXIT_ERROR)

    targets, apks_skipped = _find_upload_targets(directory, recursive=not args.no_recursive)
    if apks_skipped:
        console.print(
            f"[dim]Skipped {apks_skipped} .apks bundle(s) - upload-all only submits "
            ".apk/.aab/.apkm/.xapk/.ipa (the server doesn't accept raw bundletool "
            ".apks). Extract the app module first (`unzip -j app.apks "
            "splits/base-master.apk`) to include it.[/dim]"
        )
    if not targets:
        console.print(
            f"[bold yellow]No .apk/.aab/.apkm/.xapk/.ipa found under {directory}"
            f"{'' if not args.no_recursive else ' (top level only, --no-recursive set)'}."
            "[/bold yellow]"
        )
        return

    console.print(
        f"[cyan]Found {len(targets)} target(s) under {directory}. "
        f"Scanning and uploading to {creds['email']} ({creds['plan']})...[/cyan]\n"
    )

    succeeded, failed = [], []
    for i, target in enumerate(targets, start=1):
        console.rule(f"[bold]{i}/{len(targets)}: {os.path.relpath(target, directory)}[/bold]")
        scan_args = argparse.Namespace(
            apk_path=target, max_mem=args.max_mem, force=args.force,
            upload=True, output="console", file="narvy-results.sarif",
            confirm_upload=getattr(args, "confirm_upload", False),
        )
        try:
            cmd_scan(scan_args)
        except SystemExit as e:
            if e.code not in (0, None):
                failed.append(target)
                continue
        succeeded.append(target)
        console.print()

    console.rule("[bold]upload-all summary[/bold]")
    console.print(f"[bold green]{len(succeeded)} succeeded[/bold green], "
                 f"[bold red]{len(failed)} failed[/bold red] out of {len(targets)}.")
    if failed:
        console.print("[bold red]Failed:[/bold red]")
        for f in failed:
            console.print(f"  - {os.path.relpath(f, directory)}")
        raise SystemExit(EXIT_ERROR)


def _reject_format_as_file(output_file):
    """Catch a swapped flag: -f/--file given a format name (e.g. `-f json`) instead of a path."""
    if output_file in ("text", "json", "sarif"):
        console.print(
            f"[bold red]ERROR:[/bold red] -f/--file expects a file path but got "
            f"'{output_file}', which is a format name. Use [bold]-o {output_file}[/bold] "
            f"to select the format, and -f/--file for the output path ('-' for stdout)."
        )
        raise SystemExit(EXIT_BAD_TARGET)
    if output_file and output_file != "-":
        err = _preflight_output_writable(output_file)
        if err:
            console.print(f"[bold red]Cannot write results to {output_file}: {err}.[/bold red]")
            raise SystemExit(EXIT_ERROR)


def _write_or_print(output_text, output_path):
    if output_path and output_path != "-":
        try:
            Path(output_path).write_text(output_text)
        except OSError as e:
            console.print(f"[bold red]Could not write results to {output_path}: {e}[/bold red]")
            console.print("[dim]Check the parent directory exists and is writable, or pick a different --output-file path.[/dim]")
            raise SystemExit(EXIT_ERROR)
        console.print(f"[bold green]Results written to {output_path}[/bold green]")
    else:
        print(output_text)


def _exit_on_fail_on(findings, fail_on, get_severity=lambda f: f.get("severity", "info"),
                     coverage_gaps=None):
    telemetry.note(findings=findings, get_severity=get_severity)
    if not fail_on:
        return
    threshold = _SEVERITY_LEVEL.get(fail_on, 0) if fail_on != "any" else 1
    # Severities arrive in mixed case across the scan paths, so normalise before
    # ranking. One the map cannot rank fails the gate closed.
    breaching = []
    unrankable = {}
    for f in findings:
        raw = get_severity(f)
        s = "" if raw is None else str(raw).strip().lower()
        level = _SEVERITY_LEVEL.get(s)
        if level is None:
            unrankable[s or "(empty)"] = unrankable.get(s or "(empty)", 0) + 1
        elif level >= threshold:
            breaching.append(f)
    if unrankable:
        detail = ", ".join(f"{n} x '{s}'" for s, n in sorted(unrankable.items()))
        console.print(
            f"\n[bold red]Failing this build: --fail-on {fail_on} was asked to gate on "
            f"{sum(unrankable.values())} finding(s) whose severity this CLI cannot rank "
            f"({detail}).[/bold red]"
        )
        console.print(
            "[dim]Known values are critical/high/medium/low/info. Rather than treat an "
            "unrecognised severity as harmless (which is what silently passes a build), "
            "the gate fails. Please report this output - it means a scanner path is "
            "emitting a severity the CLI has never seen.[/dim]"
        )
        raise SystemExit(EXIT_FAIL_ON)
    # Exit 2, not 1: the gate couldn't run, which is different from tripping.
    if coverage_gaps and not breaching:
        console.print(
            f"\n[bold red]Cannot pass this build: --fail-on {fail_on} found nothing at or "
            f"above that severity, but this scan did not have full coverage of the "
            f"target.[/bold red]"
        )
        for gap in coverage_gaps:
            console.print(f"[yellow]  - {gap}[/yellow]")
        console.print(
            "[dim]0 findings from a pass that did not run means UNKNOWN, not clean, so the "
            "gate has nothing to certify. Fix the gap above and re-run, or drop --fail-on "
            "if you want this scan as a log rather than a gate.[/dim]"
        )
        raise SystemExit(EXIT_COVERAGE)
    if not breaching:
        return
    counts = {}
    for f in breaching:
        s = str(get_severity(f)).strip().lower()
        counts[s] = counts.get(s, 0) + 1
    detail = ", ".join(f"{counts[s]} {s}"
                       for s in ("critical", "high", "medium", "low", "info")
                       if counts.get(s))
    console.print(f"\n[bold red]Failing this build: --fail-on {fail_on} "
                  f"and the scan found {detail}.[/bold red]")
    raise SystemExit(EXIT_FAIL_ON)


def _sarif_result(rule_id, message_text, uri, severity):
    """One SARIF result carrying level + security-severity, so consumers can rank it."""
    return {
        "ruleId": rule_id,
        "level": sarif_level(severity),
        "message": {"text": message_text},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri or ""}}}],
        "properties": {"security-severity": sarif_security_severity(severity)},
    }


def _distinct_rules_from_results(results):
    """SARIF rule descriptors for every ruleId in `results`, with the highest severity seen."""
    rules = []
    seen = {}
    for r in results:
        rid = r.get("ruleId")
        if not rid:
            continue
        ss = r.get("properties", {}).get("security-severity", "0.0")
        lvl = r.get("level", "warning")
        if rid not in seen:
            entry = {"id": rid,
                     "defaultConfiguration": {"level": lvl},
                     "properties": {"security-severity": ss}}
            seen[rid] = entry
            rules.append(entry)
        elif float(ss) > float(seen[rid]["properties"]["security-severity"]):
            seen[rid]["properties"]["security-severity"] = ss
            seen[rid]["defaultConfiguration"]["level"] = lvl
    return rules


def _web_to_sarif(findings):
    results = [_sarif_result(
        f.get("template_id", "web-finding"),
        f.get("title", f.get("description", "")),
        f.get("url", ""),
        f.get("severity"),
    ) for f in findings]
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Narvy Web Scanner CLI", "informationUri": "https://narvy.io",
                                "rules": _distinct_rules_from_results(results)}},
            "results": results,
        }],
    }


def cmd_web_scan(args):
    telemetry.note(surface="web")
    _reject_format_as_file(args.output_file)
    # nuclei treats a non-positive rate as no rate limiting at all.
    rate_limit = max(1, min(args.rate_limit, WEB_MAX_RATE_LIMIT))

    active = getattr(args, "active", False)
    mode_label = "active/dynamic" if active else "passive-only"

    if args.format == "text":
        console.print(f"\n[bold]Narvy Web Scanner[/bold] (free, local, {mode_label})")
        console.print(f"Target: {args.url}")
        console.print(f"Rate limit: {rate_limit} req/s (ceiling {WEB_MAX_RATE_LIMIT}, not overridable)")
        if active:
            console.print("[yellow]Active mode sends non-GET probes. Only scan targets you own or are authorized to test.[/yellow]")
        console.print("")

    try:
        check_blocklist(args.url)
    except ScanBlocked:
        console.print(f"[bold red]ERROR:[/bold red] {REFUSAL_MESSAGE}")
        raise SystemExit(EXIT_BAD_TARGET)
    try:
        web_validate_url(args.url)
    except SSRFBlocked as e:
        console.print(f"[bold red]ERROR:[/bold red] {e}")
        raise SystemExit(EXIT_BAD_TARGET)

    with scan_progress() as progress:
        scan_desc = "active web scan" if active else "passive web scan"
        task = progress.add_task(f"[cyan]Running {scan_desc} (can take several minutes)...", total=None)
        try:
            scanner = NucleiScanner()
        except Exception as e:
            progress.stop()
            console.print(f"\n[bold red]Could not obtain nuclei: {e}[/bold red]\n")
            raise SystemExit(EXIT_ERROR)
        result = scanner.scan(target=args.url, rate_limit=rate_limit, active=active)
        progress.update(task, completed=1, description="[green]Scan complete.")

    if not result.get("success"):
        console.print(f"[bold red]ERROR: scan failed - {result.get('error', 'unknown error')}[/bold red]")
        _print_raw_tool_output("nuclei", result.get("stderr"))
        raise SystemExit(EXIT_ERROR)

    # Nuclei's own stderr is captured, not streamed; show it only on request.
    if getattr(args, "verbose", False):
        _print_raw_tool_output("nuclei", result.get("stderr"))

    findings = result.get("findings", [])

    if args.format == "json":
        output = json.dumps(result, indent=2)
    elif args.format == "sarif":
        output = json.dumps(_web_to_sarif(findings), indent=2)
    else:
        lines = [
            "=" * 60, f"NARVY WEB SCAN RESULTS ({mode_label})", "=" * 60, "",
            f"Target: {args.url}",
        ]
        scanned_url = result.get("scanned_url")
        if scanned_url and scanned_url != args.url:
            lines.append(f"Scanned URL: {scanned_url} (resolved from the redirect chain)")
        if result.get("redirect_note"):
            lines.append(f"Redirect: {result['redirect_note']}")
        lines += [
            f"Total Findings: {len(findings)}", "",
        ]
        for f in findings:
            lines.append(f"[{f.get('severity', '?').upper()}] {f.get('title', '?')} - {f.get('url', '')}")
        if not findings:
            lines.append("No issues found with the passive-only template set.")
        lines.append("")
        if active:
            lines.append("This was an ACTIVE/dynamic scan: the full non-destructive Nuclei")
            lines.append("template set ran and sent non-GET detection probes (destructive tags")
            lines.append("dos/fuzzing/brute-force/intrusive excluded). Only run active scans on")
            lines.append("targets you own or are authorized to test.")
        else:
            lines.append("This was a passive-only scan (no injection payloads sent). Re-run with")
            lines.append("--active to send the full non-destructive dynamic template set. Only run")
            lines.append("active scans on targets you own or are authorized to test.")
        output = "\n".join(lines)

    _write_or_print(output, args.output_file)
    coverage_gaps = []
    if result.get("coverage_incomplete"):
        coverage_gaps.append(
            result.get("redirect_note")
            or "Only part of the target could be scanned (a redirect led to a host the "
               "SSRF policy would not follow), so these results are incomplete - 0 "
               "findings means UNKNOWN, not clean."
        )
    _exit_on_fail_on(findings, args.fail_on, coverage_gaps=coverage_gaps)


def _host_to_sarif(findings, coverage="unknown", audit_privilege="unknown"):
    results = [_sarif_result(
        f.get("rule_id") or "host-finding",
        f.get("title") or f.get("description", ""),
        f.get("location") or "lynis",
        f.get("severity"),
    ) for f in findings]
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Narvy Host Audit CLI", "informationUri": "https://narvy.io",
                                "rules": _distinct_rules_from_results(results)}},
            "properties": {"coverage": coverage, "auditPrivilege": audit_privilege},
            "results": results,
        }],
    }


def _split_host_port(host, port):
    """Split `host:port` (or `[ipv6]:port`); an inline port wins."""
    h = (host or "").strip()
    if h.startswith("["):
        end = h.find("]")
        if end != -1:
            addr, rest = h[1:end], h[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return addr, int(rest[1:])
            return addr, port
        return h, port
    if h.count(":") == 1:
        left, right = h.rsplit(":", 1)
        if left and right.isdigit():
            return left, int(right)
    return h, port


def cmd_host_audit(args):
    telemetry.note(surface="host")
    _reject_format_as_file(args.output_file)
    args.host, args.port = _split_host_port(args.host, args.port)
    try:
        _validate_conn(HostConn(hostname=args.host, user=args.user, port=args.port))
    except SSHExecError as e:
        console.print(f"[bold red]ERROR: {e}[/bold red]")
        raise SystemExit(EXIT_BAD_TARGET)
    if args.format == "text":
        console.print(f"\n[bold]Narvy Host Audit[/bold] - {args.user}@{args.host}:{args.port}")
        console.print("Runs locally, using your own SSH access (~/.ssh/config, ssh-agent, default identity files). "
                       "No credentials are sent to Narvy.\n")

    password = os.environ.get("NARVY_SSH_PASSWORD", "").strip()
    if not password and getattr(args, "ask_password", False):
        password = getpass.getpass(f"SSH password for {args.user}@{args.host}: ")
    if password:
        from .host.ssh_exec import capture_host_key
        host_key = capture_host_key(args.host, args.port)
        if not host_key:
            console.print(f"[bold red]ERROR: could not fetch the host key for {args.host}:{args.port} to pin it for password auth[/bold red]")
            raise SystemExit(EXIT_ERROR)
        conn = HostConn(
            hostname=args.host,
            user=args.user,
            port=args.port,
            password=password,
            known_host_key=host_key,
            use_ambient_identity=False,
        )
    else:
        conn = HostConn(
            hostname=args.host,
            user=args.user,
            port=args.port,
            use_ambient_identity=True,
        )

    start = time.time()
    with scan_progress() as progress:
        task = progress.add_task("[cyan]Running host audit over SSH (can take a few minutes)...", total=None)
        try:
            outcome = audit_host(conn, privilege=args.privilege)
        except SSHExecError as e:
            progress.stop()
            console.print(f"\n[bold red]ERROR: SSH connection failed - {e}[/bold red]\n")
            raise SystemExit(EXIT_ERROR)
        progress.update(task, completed=1, description="[green]Audit complete.")
    duration = time.time() - start

    if not outcome.ok:
        console.print(f"[bold red]ERROR: audit failed - {outcome.error}[/bold red]")
        raise SystemExit(EXIT_ERROR)

    # Lynis runs quietly over SSH and its report is parsed, not streamed; show the
    # raw report only on request.
    if getattr(args, "verbose", False):
        _print_raw_tool_output("lynis", outcome.raw)

    findings = normalize_host_findings(outcome.findings or [])
    counts = host_severity_counts(findings)

    meta = outcome.meta or {}
    audit_privilege = meta.get("audit_privilege", "unknown")
    coverage = meta.get("coverage", "unknown")
    scan_engine = meta.get(
        "scan_engine",
        "Narvy internal host checks + Lynis (GPL-3.0) hardening baseline")

    result = {
        "target": f"{args.user}@{args.host}:{args.port}",
        "duration_seconds": round(duration, 1),
        "scan_engine": scan_engine,
        "hardening_index": outcome.hardening_index,
        "severity_counts": counts,
        "total_findings": len(findings),
        "coverage": coverage,
        "audit_privilege": audit_privilege,
        "findings": findings,
    }

    if args.format == "json":
        output = json.dumps(result, indent=2)
    elif args.format == "sarif":
        output = json.dumps(_host_to_sarif(findings, coverage=coverage,
                                           audit_privilege=audit_privilege), indent=2)
    else:
        lines = [
            "=" * 60, "NARVY HOST AUDIT RESULTS", "=" * 60, "",
            f"Target: {result['target']}",
            f"Duration: {result['duration_seconds']}s",
            f"Scan engine: {result['scan_engine']}",
            f"Hardening Index: {result['hardening_index']}",
            f"Total Findings: {result['total_findings']}",
        ]
        if coverage == "partial":
            lines.append(
                "Coverage: PARTIAL (non-root audit; root-only CIS checks - deep "
                "file-permission and many hardening controls - were skipped. Run "
                "as root or with NOPASSWD sudo for full coverage.)")
        elif coverage == "full":
            lines.append(f"Coverage: FULL (privilege: {audit_privilege})")
        else:
            lines.append(f"Coverage: {coverage} (privilege: {audit_privilege})")
        lines += [
            "",
            "Severity Distribution:",
        ]
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            c = counts.get(sev, 0)
            if c:
                lines.append(f"  {sev.upper()}: {c}")
        lines.append("")
        for f in findings:
            lines.append(f"[{f.get('severity', '?').upper()}] {f.get('title', '?')}")
        output = "\n".join(lines)

    _write_or_print(output, args.output_file)
    coverage_gaps = []
    if coverage == "partial":
        coverage_gaps.append(
            f"This was a PARTIAL audit (privilege: {audit_privilege}) - the root-only "
            "CIS/deep hardening checks were skipped, so 0 findings at/above the "
            "threshold means UNKNOWN for those checks, not clean. Run as root or with "
            "NOPASSWD sudo for full coverage."
        )
    _exit_on_fail_on(findings, args.fail_on, coverage_gaps=coverage_gaps)


def _cloud_flatten(report):
    # 'passed_checks' is a list of dicts too and must be skipped by name.
    skip_keys = {"timestamp", "passed_checks"}
    findings = []
    for category, items in report.items():
        if category in skip_keys or not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append({
                "category": category,
                "severity": str(item.get("severity", "info")).lower(),
                "title": item.get("Issue") or item.get("issue") or item.get("Description")
                         or item.get("description") or f"{category} finding",
                "recommendation": item.get("Recommendation") or item.get("recommendation", ""),
                "resource": item.get("GroupId") or item.get("BucketName") or item.get("UserName")
                            or item.get("FunctionName") or item.get("Region") or "",
            })
    return findings


def _cloud_to_sarif(findings):
    results = [_sarif_result(
        f["category"],
        f["title"],
        f["resource"] or f["category"],
        f.get("severity"),
    ) for f in findings]
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Narvy Cloud Scanner CLI", "informationUri": "https://narvy.io",
                                "rules": _distinct_rules_from_results(results)}},
            "results": results,
        }],
    }


def cmd_cloud_scan(args):
    telemetry.note(surface="cloud")
    _reject_format_as_file(args.output_file)
    try:
        from .cloud.aws_scan import analyze_aws_security
    except ImportError:
        console.print(
            "[bold red]ERROR:[/bold red] the AWS cloud scanner needs boto3, which isn't "
            "installed (it's an opt-in extra to keep the base install light).\n"
            "Run: [bold]pip install narvy-cli\\[cloud][/bold] (or `pip install boto3` "
            "into the same environment)."
        )
        raise SystemExit(EXIT_ERROR)

    if args.format == "text":
        console.print(f"\n[bold]Narvy Cloud Scanner[/bold] (free, local, your own credentials)")
        console.print(f"Provider: {args.provider}" + (f" | Region: {args.region}" if args.region else " | All regions"))
        console.print("Using ambient credentials (aws configure / env vars / IAM role). Nothing is sent to Narvy.\n")

    with scan_progress() as progress:
        task = progress.add_task("[cyan]Scanning AWS account (can take a few minutes across all regions)...", total=None)
        try:
            # Empty dict: let boto3's own ambient credential chain resolve.
            report = analyze_aws_security({}, region=args.region)
        except Exception as e:
            progress.stop()
            console.print(f"\n[bold red]ERROR: scan failed - {e}[/bold red]")
            console.print("[dim]Check that AWS credentials are configured (aws configure / AWS_ACCESS_KEY_ID env var / IAM role).[/dim]")
            raise SystemExit(EXIT_ERROR)
        progress.update(task, completed=1, description="[green]Scan complete.")

    findings = _cloud_flatten(report)

    coverage = report.get("coverage") or {}
    coverage_partial = coverage.get("status") == "partial"
    coverage_gaps = []
    if coverage_partial:
        skipped = coverage.get("checks_skipped", 0)
        coverage_gaps.append(
            f"{skipped} AWS analyzer(s) could not complete (e.g. AccessDenied / "
            "throttling / a denied permission), so those services/regions were NOT "
            "assessed. 0 findings there means UNKNOWN, not clean. See coverage.errors "
            "in the JSON output and re-run with a role that can read them."
        )

    if args.format == "json":
        output = json.dumps(report, indent=2, default=str)
    elif args.format == "sarif":
        sarif = _cloud_to_sarif(findings)
        sarif["runs"][0]["properties"] = {"coverage": coverage}
        output = json.dumps(sarif, indent=2)
    else:
        lines = [
            "=" * 60, "NARVY CLOUD POSTURE RESULTS", "=" * 60, "",
            f"Provider: {args.provider}",
            f"Total Findings: {len(findings)}", "",
        ]
        by_sev = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            if by_sev.get(sev):
                lines.append(f"  {sev.upper()}: {by_sev[sev]}")
        lines.append("")
        if coverage_partial:
            lines.append(
                f"Coverage: PARTIAL - {coverage.get('checks_skipped', 0)} analyzer(s) "
                "could not complete (AccessDenied / throttling / denied permission). "
                "Those services/regions were NOT assessed; 0 findings there is UNKNOWN, "
                "not clean:")
            for err in coverage.get("errors", []):
                lines.append(f"  - {err}")
            lines.append("")
        for f in findings:
            lines.append(f"[{f['severity'].upper()}] ({f['category']}) {f['title']}")
        if not findings:
            lines.append("No issues found." if not coverage_partial
                         else "No issues found among the services that COULD be assessed (see coverage note above).")
        output = "\n".join(lines)

    _write_or_print(output, args.output_file)
    _exit_on_fail_on(findings, args.fail_on, coverage_gaps=coverage_gaps)


_CI_TEMPLATES = {
    "github": ("github.yml", os.path.join(".github", "workflows", "narvy.yml")),
    "gitlab": ("gitlab.yml", ".gitlab-ci.yml"),
    "bitbucket": ("bitbucket.yml", "bitbucket-pipelines.yml"),
}


def cmd_telemetry(args):
    action = args.action
    if action in ("on", "off"):
        if not telemetry.set_enabled(action == "on"):
            console.print(f"[bold red]Could not write {telemetry.CONFIG_PATH}.[/bold red]")
            raise SystemExit(EXIT_ERROR)
    st = telemetry.status()
    state = "on" if st["enabled"] else "off"
    console.print(f"Anonymous usage telemetry: [bold]{state}[/bold] ({st['reason']}).")
    if action == "status":
        console.print(f"[dim]{telemetry.NOTICE}[/dim]")
        console.print(f"[dim]Details: {DOCS_URL.replace('SETUP.md', 'README.md')}#telemetry[/dim]")


def cmd_init_ci(args):
    platform = getattr(args, "platform", None) or "github"
    template_name, rel_dest = _CI_TEMPLATES[platform]
    src = os.path.join(os.path.dirname(__file__), "ci_templates", template_name)
    try:
        template_text = Path(src).read_text(encoding="utf-8")
    except OSError as e:
        console.print(f"[bold red]Could not read the {platform} CI template: {e}[/bold red]")
        raise SystemExit(EXIT_ERROR)

    dest = Path(args.output_dir) / rel_dest

    # stat() can raise on an unreadable parent; exit clean, not with a traceback.
    try:
        _dest_exists = dest.exists()
    except OSError as e:
        console.print(f"[bold red]Cannot access {dest}: {e}[/bold red]")
        raise SystemExit(EXIT_ERROR)

    if _dest_exists:
        if args.force:
            pass
        elif sys.stdin.isatty() and sys.stdout.isatty():
            console.print(f"[bold yellow]{dest} already exists.[/bold yellow]")
            if platform in ("gitlab", "bitbucket"):
                console.print(
                    "[dim]This is usually your existing pipeline. Overwriting REPLACES it - "
                    "if you meant to add Narvy to an existing pipeline, decline and copy "
                    "the job/step from the template instead.[/dim]"
                )
            try:
                proceed = Confirm.ask("Overwrite it?", default=False)
            except (EOFError, KeyboardInterrupt):
                proceed = False
            if not proceed:
                console.print("[dim]Left the existing file untouched.[/dim]")
                raise SystemExit(EXIT_ERROR)
        else:
            console.print(
                f"[bold red]{dest} already exists.[/bold red] Refusing to overwrite it in a "
                "non-interactive shell. Re-run with [bold]--force[/bold] to replace it."
            )
            raise SystemExit(EXIT_ERROR)

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(template_text, encoding="utf-8")
    except OSError as e:
        console.print(f"[bold red]Could not write {dest}: {e}[/bold red]")
        console.print("[dim]Check the parent directory is writable, or pass a different --output-dir.[/dim]")
        raise SystemExit(EXIT_ERROR)

    console.print(f"[bold green]Wrote {platform} CI template to {dest}[/bold green]")
    console.print(
        "[dim]It installs the CLI from PyPI with [bold]pip install narvy-cli[/bold] "
        "and runs on every push and pull request.[/dim]"
    )
    console.print(
        "[dim]The template runs `narvy scan . --output sarif --file narvy-results.sarif "
        "--fail-on high`. Adjust --fail-on (critical/high/medium/low/any) to set how strict the "
        "build gate is, and commit the file to enable it.[/dim]"
    )


def cli():
    parser = _ArgumentParser(allow_abbrev=False, description=(
        "Narvy CLI - Static Analysis for Android APKs/AABs, iOS IPAs, "
        "Android/iOS source projects, and web/backend source projects "
        f"({web_source_analyzer.SUPPORTED_LANGUAGES_LABEL})"
    ), epilog=EXIT_CODES_HELP + "\n\nDocumentation: " + DOCS_URL,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--version", action="version",
        version=f"narvy {__version__}",
        help="Show the Narvy CLI version and exit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Shared -v/--verbose: surface the raw underlying tool output for debugging.
    verbose_parent = _ArgumentParser(add_help=False)
    verbose_parent.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show the raw tool output (nuclei / lynis) instead of the progress summary.")

    p_login = sub.add_parser("login", allow_abbrev=False, help="Link this machine to your Narvy account")
    p_login.add_argument("--token", help="API token (skips interactive prompt)")
    p_login.set_defaults(func=cmd_login)

    p_logout = sub.add_parser("logout", allow_abbrev=False, help="Remove the locally stored API token")
    p_logout.set_defaults(func=cmd_logout)

    p_scans = sub.add_parser("scans", allow_abbrev=False, help="List recent scans on your Narvy account (requires `narvy login`)")
    p_scans.add_argument("--limit", type=_positive_int, default=20, help="Max number of scans to show (default: 20, must be >= 1)")
    p_scans.add_argument("--status", choices=["queued", "running", "done", "failed", "pending_sast", "scheduled"],
                         help="Filter by scan status")
    p_scans.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")
    p_scans.set_defaults(func=cmd_scans)

    p_doctor = sub.add_parser("doctor", allow_abbrev=False, help="Check your Java/jadx/network/iOS-tooling setup before scanning")
    p_doctor.set_defaults(func=lambda args: run_doctor())

    p_scan = sub.add_parser(
        "scan", allow_abbrev=False,
        help="Scan an APK/AAB, an IPA, an Android/iOS source directory, or a web/backend source directory (runs locally; add --upload to send the results to your Narvy dashboard)",
        epilog=EXIT_CODES_HELP, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_scan.add_argument("apk_path", help=(f"What to scan: an .apk/.aab, an .apkm/.xapk/.apks bundle, an .ipa (unencrypted), or a source directory (Android Gradle, Xcode/Swift, or web/backend: "
        f"{web_source_analyzer.SUPPORTED_LANGUAGES_LABEL})."))
    p_scan.add_argument("--max-mem", default="4g", help="Max memory for jadx, e.g. '2g' or '4096m' (default: 4g). Android only.")
    p_scan.add_argument("--force", action="store_true",
                        help="Decompile anyway when the memory estimate says jadx will likely run out of memory.")
    p_scan.add_argument("--output", "-o", default="console", choices=["console", "sarif", "json"],
                        type=str.lower, help="Output format: console (default), sarif or json. sarif and json are written to --file.")
    p_scan.add_argument("--file", "-f", default=None, help="Output file for --output sarif/json (default: narvy-results.sarif or narvy-results.json). Ignored for console output.")
    p_scan.add_argument("--upload", action="store_true", help="Send the findings (never your code or binary) to your Narvy dashboard after the scan. Needs `narvy login` and a paid plan.")
    p_scan.add_argument("--upload-binary", action="store_true", help="Upload the binary itself (.apk/.aab/.ipa) for a server-side scan instead of the results. Implies --upload.")
    p_scan.add_argument("--confirm-upload", action="store_true",
                        help="Don't prompt when the server flags the file as suspicious (warn only, never a hard refuse). For CI.")
    p_scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"],
                        help=FAIL_ON_HELP + " Evaluated after --upload, so the results are still sent.")
    p_scan.set_defaults(func=cmd_scan)

    p_tel = sub.add_parser(
        "telemetry", allow_abbrev=False,
        help="Show or change anonymous usage telemetry (on by default; the README lists what is sent)",
    )
    p_tel.add_argument("action", choices=["status", "on", "off"], nargs="?", default="status",
                       help="status (default), on, or off. NARVY_TELEMETRY=0 or DO_NOT_TRACK=1 also turn it off.")
    p_tel.set_defaults(func=cmd_telemetry)

    p_initci = sub.add_parser(
        "init-ci", allow_abbrev=False,
        help="Write a CI pipeline template (GitHub Actions, GitLab CI or Bitbucket Pipelines)",
    )
    _ci_group = p_initci.add_mutually_exclusive_group()
    _ci_group.add_argument("--github", dest="platform", action="store_const", const="github",
                           help="GitHub Actions -> .github/workflows/narvy.yml (default)")
    _ci_group.add_argument("--gitlab", dest="platform", action="store_const", const="gitlab",
                           help="GitLab CI -> .gitlab-ci.yml")
    _ci_group.add_argument("--bitbucket", dest="platform", action="store_const", const="bitbucket",
                           help="Bitbucket Pipelines -> bitbucket-pipelines.yml")
    p_initci.add_argument("--output-dir", default=".",
                          help="Directory to write the template into (default: current directory)")
    p_initci.add_argument("--force", action="store_true",
                          help="Overwrite an existing file without asking (for non-interactive/CI use)")
    p_initci.set_defaults(func=cmd_init_ci, platform=None)

    p_upload_all = sub.add_parser(
        "upload-all", allow_abbrev=False,
        help="Upload every .apk/.aab/.apkm/.xapk/.ipa in a directory (needs `narvy login` and a paid plan)",
        description="Upload every .apk/.aab/.apkm/.xapk/.ipa found in a directory. Needs `narvy login` and a paid plan; local `narvy scan` is always free.",
    )
    p_upload_all.add_argument("directory", help="Directory to search for scan targets")
    p_upload_all.add_argument("--no-recursive", action="store_true",
                              help="Only look in the top-level directory, don't walk subdirectories")
    p_upload_all.add_argument("--max-mem", default="4g", help="Max memory for jadx on each Android target, e.g. '2g' or '4096m' (default: 4g).")
    p_upload_all.add_argument("--force", action="store_true",
                              help="Decompile anyway when the memory estimate says jadx will likely run out of memory.")
    p_upload_all.add_argument("--confirm-upload", action="store_true",
                              help="Don't prompt when the server flags a file as suspicious (warn only, never a hard refuse). For CI.")
    p_upload_all.set_defaults(func=cmd_upload_all)

    # allow_abbrev=False so `--activ` can't silently turn into `--active`.
    p_web = sub.add_parser("web-scan", allow_abbrev=False, parents=[verbose_parent], epilog=EXIT_CODES_HELP, formatter_class=argparse.RawDescriptionHelpFormatter, help="Scan a URL with nuclei. Passive by default; --active sends real probes.")
    p_web.add_argument("url", help="Target URL to scan")
    p_web.add_argument("--active", action="store_true",
                        help="Run the full active template set instead of passive GET-only checks. Only scan targets you are allowed to test. dos/fuzzing/brute-force/intrusive stay excluded.")
    p_web.add_argument("--rate-limit", type=int, default=WEB_MAX_RATE_LIMIT,
                        help=f"Requests per second (max {WEB_MAX_RATE_LIMIT}, enforced)")
    p_web.add_argument("--output", "-o", "--format", dest="format", choices=["text", "json", "sarif"],
                       default="text", type=str.lower,
                       help="Output format: text (default), json or sarif. Consistent with `scan`: -o = format.")
    p_web.add_argument("--file", "-f", "--output-file", dest="output_file", default=None,
                       help="Write output to this path ('-' = stdout, the default). Consistent with `scan`: -f = file.")
    p_web.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"], help=FAIL_ON_HELP)
    p_web.set_defaults(func=cmd_web_scan)

    p_host = sub.add_parser("host-audit", allow_abbrev=False, parents=[verbose_parent], epilog=EXIT_CODES_HELP, formatter_class=argparse.RawDescriptionHelpFormatter, help="Run a Lynis audit on a host over your own SSH access (no credentials sent to Narvy)")
    p_host.add_argument("host", help="Target hostname or IP")
    p_host.add_argument("--user", "-u", required=True, help="SSH username")
    p_host.add_argument("--port", "-p", type=int, default=22, help="SSH port (default: 22)")
    p_host.add_argument("--ask-password", action="store_true",
                        help="Use an SSH password instead of a key (prompted, or NARVY_SSH_PASSWORD). The host key is trusted on first use, so only do this on a network you trust.")
    p_host.add_argument("--privilege", choices=["auto", "root", "nopasswd_sudo", "none"],
                         default="auto", help="Privilege mode (default: auto-detect)")
    p_host.add_argument("--output", "-o", "--format", dest="format", choices=["text", "json", "sarif"],
                        default="text", type=str.lower,
                        help="Output format: text (default), json or sarif. Consistent with `scan`: -o = format.")
    p_host.add_argument("--file", "-f", "--output-file", dest="output_file", default=None,
                        help="Write output to this path ('-' = stdout, the default). Consistent with `scan`: -f = file.")
    p_host.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"], help=FAIL_ON_HELP)
    p_host.set_defaults(func=cmd_host_audit)

    p_cloud = sub.add_parser("cloud-scan", allow_abbrev=False, epilog=EXIT_CODES_HELP, formatter_class=argparse.RawDescriptionHelpFormatter, help="Cloud posture scan using your local AWS credentials (aws configure, env vars or IAM role)")
    p_cloud.add_argument("--provider", choices=["aws"], default="aws", help="Cloud provider (GCP/Azure not yet in the CLI)")
    p_cloud.add_argument("--region", help="Specific region to scan (default: all regions)")
    p_cloud.add_argument("--output", "-o", "--format", dest="format", choices=["text", "json", "sarif"],
                         default="text", type=str.lower,
                         help="Output format: text (default), json or sarif. Consistent with `scan`: -o = format.")
    p_cloud.add_argument("--file", "-f", "--output-file", dest="output_file", default=None,
                         help="Write output to this path ('-' = stdout, the default). Consistent with `scan`: -f = file.")
    p_cloud.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"], help=FAIL_ON_HELP)
    p_cloud.set_defaults(func=cmd_cloud_scan)

    args = parser.parse_args()
    # SIGTERM/SIGHUP (CI job cancel, docker stop, dropped SSH) take the Ctrl-C path so
    # child scanners (semgrep workers) are torn down instead of orphaned.
    from .proc import install_termination_handlers
    install_termination_handlers()
    command = getattr(args, "command", None)
    track = command in telemetry.COMMANDS
    if track:
        telemetry.maybe_show_notice()
    started = time.monotonic()
    exit_code, failure = EXIT_OK, None
    # Last-resort guard: turn any escaped exception into a clean one-line message, never a raw traceback.
    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("[yellow]Aborted.[/yellow]")
        exit_code = 130
        raise SystemExit(130)
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else (EXIT_OK if e.code is None else EXIT_ERROR)
        raise
    except Exception as e:
        failure = e
        exit_code = EXIT_ERROR
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        console.print("[dim]This looks like a bug. Please report it.[/dim]")
        raise SystemExit(EXIT_ERROR)
    finally:
        if track:
            telemetry.send(command, time.monotonic() - started, exit_code, failure)
            telemetry.flush()
