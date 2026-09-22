"""Web/backend source-repo SAST entry point for JS/TS, Python, PHP, Go, Ruby,
Rust, Java/Kotlin and C#/.NET, driving the bundled semgrep rule packs.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from narvy import semgrep_engine

_HERE = os.path.dirname(__file__)
_WEB_RULES_DIR = os.path.join(_HERE, "..", "rules", "web")
_WEB_LOCAL_RULES_DIR = os.path.join(_WEB_RULES_DIR, "local")
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))


def _find_pro_rules_root() -> Optional[str]:
    """Locate the optional extended rule tree via NARVY_PRO_RULES_DIR; None when unset."""
    env_dir = os.environ.get("NARVY_PRO_RULES_DIR", "").strip()
    if env_dir and os.path.isdir(os.path.join(env_dir, "web")):
        return env_dir
    return None


_PRO_RULES_ROOT = _find_pro_rules_root()
_PRO_WEB_RULES_DIR = (
    os.path.join(_PRO_RULES_ROOT, "web") if _PRO_RULES_ROOT else ""
)
_PRO_WEB_LOCAL_RULES_DIR = (
    os.path.join(_PRO_WEB_RULES_DIR, "local") if _PRO_RULES_ROOT else ""
)


def pro_rules_available() -> bool:
    return bool(_PRO_WEB_RULES_DIR) and os.path.isdir(_PRO_WEB_RULES_DIR)


# C#/.NET ships a base rule pack, so it is always a supported web-source language.
SUPPORTED_LANGUAGES_LABEL = (
    "JavaScript/TypeScript, Python, PHP, Go, Ruby, Rust, Java/Kotlin, C#/.NET"
)

_ALWAYS_ON_PACKS = ["secrets", "secrets_supplement"]

WEB_PACK_MAP: Dict[str, List[str]] = {
    # javascript.yml is tagged for both languages, so one pack covers both labels.
    "javascript": ["javascript"] + _ALWAYS_ON_PACKS,
    "typescript": ["javascript"] + _ALWAYS_ON_PACKS,
    "python": ["python"] + _ALWAYS_ON_PACKS,
    "php": ["php", "javascript"] + _ALWAYS_ON_PACKS,
    "go": ["go"] + _ALWAYS_ON_PACKS,
    "ruby": ["ruby"] + _ALWAYS_ON_PACKS,
    "rust": ["rust"] + _ALWAYS_ON_PACKS,
    "java": ["java", "kotlin"] + _ALWAYS_ON_PACKS,
    # C# has no <name>.yml: its rules live in a local pack wired through _LOCAL_PACK_DIRS.
    "csharp": list(_ALWAYS_ON_PACKS),
}

_LOW_COVERAGE_STACKS: Dict[str, str] = {
    "rust": (
        "Rust rule coverage is the thinnest of the supported stacks "
        "(12 rules): command injection, MD5/SHA-1, sqlx/diesel/rusqlite/"
        "postgres raw SQL, bincode deserialization, and axum/actix "
        "extractor-to-sink taint for path traversal and process spawning. "
        "TLS-verification-bypass and Trojan-Source bidi-character checks "
        "are NOT in the current pack. Memory safety (use-after-free, "
        "aliasing bugs in "
        "`unsafe`) is NOT covered by any static pattern here and needs "
        "Miri or a manual review; dependency CVEs come from this CLI's "
        "own SCA pass, not from these rules."
    ),
    "csharp": (
        "C#/.NET rule coverage is starter-level (10 rules): SQL injection "
        "via ADO.NET command-text concatenation, path traversal from "
        "HttpRequest input into System.IO file APIs, command injection from "
        "request input into Process.Start, XXE via XmlDocument's default "
        "resolver, BinaryFormatter and Json.NET TypeNameHandling "
        "deserialization, weak hashes (MD5/SHA-1), weak/legacy ciphers "
        "(DES/3DES/RC2), and two web.config/attribute checks (request "
        "validation disabled, debug compilation left on). NOT covered: "
        "Dapper/EF Core raw-SQL sinks, model-bound action-method parameters "
        "as a taint source (only Request.Query/Form/Headers/Cookies/"
        "RouteValues indexers are), Razor/Blazor template XSS, "
        "authorization-attribute analysis, TLS/certificate-validation "
        "settings, and connection-string secrets. Dependency CVEs come from "
        "this CLI's own NuGet SCA pass, not from these rules."
    ),
}

if not pro_rules_available():
    _LOW_COVERAGE_STACKS["rust"] = (
        "Rust rule coverage is the thinnest of the supported stacks "
        "(7 rules): command injection, MD5/SHA-1 as a password hash, sqlx "
        "raw SQL, and bincode deserialization. Memory safety "
        "(use-after-free, aliasing bugs in `unsafe`) is NOT covered by any "
        "static pattern here and needs Miri or a manual review; dependency "
        "CVEs come from this CLI's own SCA pass, not from these rules."
    )

_LOCAL_PACK_DIRS: Dict[str, Tuple[str, ...]] = {
    "javascript": ("typescript_narvy",),
    "typescript": ("typescript_narvy",),
    "php": (),
    "python": (),
    "go": (),
    "java": ("java_narvy",),
    "ruby": (),
    "rust": ("rust_narvy",),
    "csharp": ("csharp_narvy",),
}

# Recognized stacks with no dedicated rule pack (zero semgrep configs).
_UNPORTED_STACK_LABELS = {
    "dotnet": "C#/.NET backend (*.csproj / *.sln)",
}

_UNPORTED_STACK_PARTIAL_NOTE = {
    "dotnet": (
        "Its .cs files were still passed through the always-on cross-language "
        "packs, but those carry ZERO C#-tagged rules - only their "
        "language-agnostic hardcoded-secret patterns apply, which match any "
        "file type. Treat that as partial, best-effort coverage (secrets "
        "only), NOT a .NET security review: no ASP.NET Core framework rules, "
        "no C# injection or deserialization rules, no C# taint analysis."
    ),
}

_VENDOR_DIR_NAMES = frozenset({
    "node_modules", "vendor", "bower_components",
    ".venv", "venv", ".tox", "__pycache__",
    "Pods", "Carthage", "DerivedData",
    ".git", ".gradle", ".idea", ".vscode", ".vs",
    "build", "dist", "target", "out", ".next", ".nuxt", ".cache",
    "coverage", ".pytest_cache", "egg-info",
})

# Content-agnostic build-artifact basename globs. Minified/bundled output is
# machine-generated regardless of location, so these are excluded anywhere.
_BUILD_ARTIFACT_FILE_GLOBS = (
    "*.min.js", "*-min.js", "*.bundle.js", "*-bundle.js", "*.pack.js",
)

# Bundled third-party JS library basenames. A file literally named jquery.js /
# vue.js / d3.js can equally be an app's OWN source, so these are only excluded
# when the file sits UNDER a served-asset / vendored root (see _SERVED_ASSET_ROOT_DIRS).
_VENDOR_LIB_FILE_GLOBS = (
    "jquery.js", "jquery-*.js", "jquery.*.js",
    "vue.js", "vue.common*.js", "vue.runtime*.js", "vue.esm*.js",
    "angular.js", "react.js", "react-dom.js", "react.production*.js", "react.development*.js",
    "tinymce.js", "tinymce*.js", "tiny_mce*.js", "wp-tinymce*.js",
    "underscore.js", "underscore-*.js", "lodash.js",
    "leaflet.js", "leaflet-*.js", "leaflet.*.js",
    "d3.js", "d3.v*.js", "d3-*.js",
    "select2.js", "select2.*.js",
    "pdf.js", "pdf.worker*.js", "pdfjs*.js",
    "bootstrap.js", "bootstrap.bundle*.js",
    "cropper.js", "cropper-*.js",
    "raphael.js", "raphael-*.js", "raphael.*.js",
    "popper.js", "moment.js", "moment-*.js",
    "highlight.pack.js", "handlebars.js", "handlebars-*.js",
    "backbone.js", "knockout*.js", "modernizr*.js", "swfobject.js",
    "fabric.js", "Sortable.js", "clipboard.js",
)

# Directory names that are a vendored lib checkout ONLY under a served-asset root.
# A top-level dir named leaflet/ may be an app feature dir, so it is not excluded
# on the name alone.
_VENDOR_LIB_DIR_NAMES = ("tinymce", "select2", "leaflet", "pdfjs", "codemirror")

# Roots under which vendored/served third-party assets live. The lib-name globs
# and lib dir-names above only suppress matches nested under one of these.
_SERVED_ASSET_ROOT_DIRS = frozenset({
    "static", "assets", "public", "vendor", "node_modules",
    "wp-includes", "dist", "build",
})

_LANG_EXTS: Dict[str, Tuple[str, ...]] = {
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "python": (".py",),
    "php": (".php",),
    "go": (".go",),
    # Template extensions (.erb, .cshtml, .razor, .jsp) excluded: semgrep has no analyzer for them.
    "ruby": (".rb", ".rake", ".gemspec"),
    "rust": (".rs",),
    "java": (".java", ".kt", ".kts"),
    "csharp": (".cs",),
}

_DENSITY_THRESHOLD = {
    "javascript": 5, "typescript": 5, "python": 5, "php": 2, "go": 5,
    "ruby": 5, "rust": 5,
    "java": 5,
    "csharp": 5,
}

# Excluded from density counting so stray served assets do not promote an extra rule pack.
_SERVED_ASSET_DIR_NAMES = frozenset({"public", "static", "assets", "templates", "downloads"})

_MAX_DETECT_DEPTH = 8

# Kept intentionally shallow so a deeply-vendored package.json can't promote Node.
_NODE_APP_MAX_DEPTH = 2

# Go toolchain generated-code header convention (protoc-gen-go, codegen, mockgen, stringer).
_GENERATED_CODE_HEADER_RE = re.compile(
    r"^\s*(?://|#)\s*Code generated .* DO NOT EDIT\.\s*$", re.MULTILINE
)
_GENERATED_HEADER_SCAN_BYTES = 2000


# Rule ids that flag the SAME bug (hardcoded secret into a JWT sign/verify call);
# multiple hits on one (file,line) are one finding double-counted.
_JWT_ALIAS_RULE_IDS = frozenset({
    "js-jsonwebtoken-hardcoded-secret",
    "hardcoded-jwt-sign-secret",
})

_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# Markers of the hardcoded-secret family, the only category down-weighted in test paths.
_SECRET_RULE_MARKERS = (
    "secret", "hardcoded", "api-key", "apikey", "api_key",
    "token", "credential", "password", "private-key", "privatekey",
    "aws", "gcp", "google-", "stripe", "slack", "twilio",
    "entropy", "github", "gitlab",
)

# Path fragments and filename patterns that mark test / fixture / mock code.
_TEST_PATH_DIR_FRAGMENTS = (
    "/test/", "/tests/", "/__tests__/", "/spec/", "/specs/",
    "/mocks/", "/__mocks__/", "/fixtures/", "/fixture/", "/testdata/",
    "/e2e/", "/cypress/", "/testing/",
)
# Basename only; token must sit on a boundary so "latest.js"/"contest.js" are not tests.
_TEST_FILENAME_RE = re.compile(
    r"(?:^|[._-])(?:test|tests|spec|specs|mock|mocks|fixture|fixtures)(?:[._-]|$)"
    r"|^conftest\.py$",
    re.IGNORECASE,
)

LAST_RUN_JWT_DUPLICATES_DROPPED = 0
LAST_RUN_TEST_SECRETS_DOWNWEIGHTED = 0


def _is_secret_finding(finding: Dict[str, Any]) -> bool:
    rid = finding.get("rule_id", "").lower()
    return any(m in rid for m in _SECRET_RULE_MARKERS)


def _is_test_path(rel_path: str) -> bool:
    p = "/" + rel_path.replace("\\", "/").lstrip("/")
    if any(frag in p.lower() for frag in _TEST_PATH_DIR_FRAGMENTS):
        return True
    base = p.rsplit("/", 1)[-1]
    return bool(_TEST_FILENAME_RE.search(base))


def _collapse_jwt_aliases(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop the lower-severity alias when >1 JWT-secret rule hits one (file,line)."""
    global LAST_RUN_JWT_DUPLICATES_DROPPED
    # Index of alias-rule findings per (file,line).
    by_loc: Dict[Tuple[str, int], List[int]] = {}
    for idx, f in enumerate(findings):
        if f.get("rule_id") in _JWT_ALIAS_RULE_IDS:
            by_loc.setdefault((f.get("file_path"), f.get("line")), []).append(idx)

    drop: Set[int] = set()
    for _loc, idxs in by_loc.items():
        if len(idxs) < 2:
            continue
        # Keep the highest-severity finding; drop the rest of the alias group.
        keep = max(idxs, key=lambda i: _SEVERITY_RANK.get(findings[i].get("severity"), 0))
        for i in idxs:
            if i != keep:
                drop.add(i)
    LAST_RUN_JWT_DUPLICATES_DROPPED = len(drop)
    return [f for i, f in enumerate(findings) if i not in drop]


def _downweight_test_secrets(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Downgrade (never drop) hardcoded-secret findings in test/fixture paths to LOW and tag them."""
    global LAST_RUN_TEST_SECRETS_DOWNWEIGHTED
    n = 0
    for f in findings:
        if (
            _is_secret_finding(f)
            and f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
            and _is_test_path(f.get("file_path", ""))
        ):
            f["severity"] = "LOW"
            details = f.setdefault("details", {})
            note = (
                " [Narvy: this hit is in a test/fixture path, where a hardcoded "
                "secret is usually a fixture rather than a production credential, "
                "so severity is lowered - confirm it is not a real leaked secret.]"
            )
            if note.strip() not in (details.get("description") or ""):
                details["description"] = (details.get("description") or "") + note
            n += 1
    LAST_RUN_TEST_SECRETS_DOWNWEIGHTED = n
    return findings


LAST_RUN_TEST_FINDINGS_DOWNWEIGHTED = 0


def _downweight_test_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Lower (never drop) any remaining CRITICAL/HIGH/MEDIUM hit in a test/fixture path to LOW.

    Framework test suites and fixture apps (e.g. innerHTML/XSS demo fixtures)
    otherwise produce headline CRITICALs that are not shipped-app issues.
    """
    global LAST_RUN_TEST_FINDINGS_DOWNWEIGHTED
    note = (
        " [Narvy: this hit is in a test/fixture path, where such code is usually a "
        "fixture or test harness rather than shipped app code, so severity is "
        "lowered - confirm it is not a real production issue.]"
    )
    n = 0
    for f in findings:
        if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM") and _is_test_path(f.get("file_path", "")):
            f["severity"] = "LOW"
            details = f.setdefault("details", {})
            if isinstance(details, dict) and note.strip() not in (details.get("description") or ""):
                details["description"] = (details.get("description") or "") + note
            n += 1
    LAST_RUN_TEST_FINDINGS_DOWNWEIGHTED = n
    return findings


def _should_prune_dir(name: str) -> bool:
    return name in _VENDOR_DIR_NAMES or name.startswith(".")


def _find_marker(source_dir: str, filenames: Tuple[str, ...], max_depth: int = 1) -> bool:
    """True if any of `filenames` exists up to `max_depth` levels deep."""
    base_depth = source_dir.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(source_dir):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not _should_prune_dir(d)]
        if any(f in filenames for f in files):
            return True
    return False


def _find_marker_suffix(source_dir: str, suffixes: Tuple[str, ...], max_depth: int = 1) -> bool:
    base_depth = source_dir.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(source_dir):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not _should_prune_dir(d)]
        if any(f.endswith(suffixes) for f in files):
            return True
    return False


# Sphinx documentation trees carry doc-build .py (conf.py, a custom Pygments
# lexer, the theme) that must not promote a Python rule pack for a non-Python app.
_DOC_ROOT_NAME_RE = re.compile(
    r"^(?:docs?|documentation|user[_-]?guide.*|manual|website|site)$", re.IGNORECASE
)


def _sphinx_doc_roots(source_dir: str) -> Set[str]:
    """Directories to skip for STACK DETECTION only: subtrees that are Sphinx doc builds."""
    roots: Set[str] = set()
    for cur, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if not _should_prune_dir(d)]
        if "conf.py" not in files:
            continue
        try:
            with open(os.path.join(cur, "conf.py"), "r", encoding="utf-8", errors="ignore") as fh:
                head = fh.read(4000)
        except OSError:
            continue
        if "sphinx" not in head.lower():
            continue
        # Only exclude a subtree rooted at a doc-NAMED directory, never the scan
        # root itself, so a real Python project is never blanked out.
        root = None
        node = cur
        while node and node.startswith(source_dir) and node != source_dir:
            if _DOC_ROOT_NAME_RE.match(os.path.basename(node)):
                root = node
            node = os.path.dirname(node)
        if root is not None:
            roots.add(os.path.abspath(root))
    return roots


def _count_density(source_dir: str, exts: Tuple[str, ...]) -> int:
    doc_roots = _sphinx_doc_roots(source_dir)
    n = 0
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if not _should_prune_dir(d) and d not in _SERVED_ASSET_DIR_NAMES]
        if os.path.abspath(root) in doc_roots:
            dirs[:] = []
            continue
        for f in files:
            if f.endswith(exts):
                n += 1
    return n


def _has_real_node_app(source_dir: str, max_depth: int = _NODE_APP_MAX_DEPTH) -> bool:
    """package.json within `max_depth` levels carrying a real dependency key."""
    candidates: List[str] = []
    base_depth = source_dir.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(source_dir):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not _should_prune_dir(d)]
        if "package.json" in files:
            candidates.append(os.path.join(root, "package.json"))
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and any(
            k in data for k in ("dependencies", "devDependencies", "scripts")
        ):
            return True
    return False


def _has_source(source_dir: str, lang: str) -> bool:
    """True when the tree carries at least one real source file of `lang`.

    Presence of real source (not served assets or Sphinx doc tooling, which
    _count_density already skips) is enough to scan; a dependency manifest is
    treated as enrichment, not a precondition, so a lone app.js/app.py/etc. with
    no package.json is still scanned instead of being reported as "nothing to scan".
    """
    return _count_density(source_dir, _LANG_EXTS[lang]) >= 1


def detect_web_stacks(source_dir: str) -> Tuple[Set[str], Set[str]]:
    """Returns (ported_stacks, unported_stacks); either may be empty."""
    ported: Set[str] = set()
    unported: Set[str] = set()

    if (
        _find_marker(source_dir, ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile"))
        or _has_source(source_dir, "python")
    ):
        ported.add("python")

    if (
        os.path.isfile(os.path.join(source_dir, "composer.json"))
        or _has_source(source_dir, "php")
    ):
        ported.add("php")

    if (
        _has_real_node_app(source_dir)
        or _has_source(source_dir, "javascript")
        or _has_source(source_dir, "typescript")
    ):
        # Both labels resolve to the same pack; this only sets the label in notes.
        if _count_density(source_dir, _LANG_EXTS["typescript"]) > 0:
            ported.add("typescript")
        else:
            ported.add("javascript")

    if (
        _find_marker(source_dir, ("go.mod", "go.sum"))
        or _has_source(source_dir, "go")
    ):
        ported.add("go")

    if (
        _find_marker(source_dir, ("Gemfile", "Gemfile.lock"))
        or _find_marker_suffix(source_dir, (".gemspec",))
        or _has_source(source_dir, "ruby")
    ):
        ported.add("ruby")

    if (
        _find_marker(source_dir, ("Cargo.toml", "Cargo.lock"))
        or _has_source(source_dir, "rust")
    ):
        ported.add("rust")

    # Android projects are already excluded upstream, so a Gradle/Maven project here is JVM backend/library.
    if (
        _find_marker(source_dir, ("pom.xml", "build.gradle", "build.gradle.kts",
                                  "settings.gradle", "settings.gradle.kts"), max_depth=2)
        or _has_source(source_dir, "java")
    ):
        ported.add("java")

    # Depth 3: a .NET project file is typically src/<Project>/<Project>.csproj, not the root.
    if (
        _find_marker_suffix(source_dir, (".csproj", ".fsproj", ".vbproj", ".sln", ".slnx"), max_depth=3)
        or _find_marker(source_dir, ("packages.config", "Directory.Packages.props"), max_depth=3)
        or _has_source(source_dir, "csharp")
    ):
        ported.add("csharp")

    return ported, unported


def _pack_path(pack_name: str) -> Optional[str]:
    p = os.path.join(_WEB_RULES_DIR, f"{pack_name}.yml")
    return p if os.path.isfile(p) else None


def _pro_pack_path(pack_name: str) -> Optional[str]:
    if not _PRO_WEB_RULES_DIR:
        return None
    p = os.path.join(_PRO_WEB_RULES_DIR, f"{pack_name}_pro.yml")
    return p if os.path.isfile(p) else None


def _local_pack_path(local_dir_name: str) -> Optional[str]:
    """Base tree wins over the extended tree when both carry the name."""
    for parent in (_WEB_LOCAL_RULES_DIR, _PRO_WEB_LOCAL_RULES_DIR):
        if not parent:
            continue
        p = os.path.join(parent, local_dir_name)
        if os.path.isdir(p):
            return p
    return None


def _resolve_configs(ported_stacks: Set[str]) -> List[str]:
    """--config paths for the detected stacks: language packs then local packs."""
    wanted: List[str] = []
    seen: Set[str] = set()
    for stack in sorted(ported_stacks):
        for pack in WEB_PACK_MAP.get(stack, []):
            if pack not in seen:
                wanted.append(pack)
                seen.add(pack)

    configs: List[str] = []
    for pack in wanted:
        path = _pack_path(pack)
        if path:
            configs.append(path)
        pro_path = _pro_pack_path(pack)
        if pro_path:
            configs.append(pro_path)

    local_dirs_added: Set[str] = set()
    for stack in sorted(ported_stacks):
        for local_dir_name in _LOCAL_PACK_DIRS.get(stack, ()):
            if local_dir_name in local_dirs_added:
                continue
            local_path = _local_pack_path(local_dir_name)
            if local_path:
                configs.append(local_path)
                local_dirs_added.add(local_dir_name)

    return configs


def _load_rule_defs_from_yml(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return []
    defs = []
    for rule in (data or {}).get("rules", []):
        meta = rule.get("metadata", {}) or {}
        defs.append({
            "id": rule["id"],
            "name": rule.get("message", rule["id"])[:120],
            "severity": semgrep_engine.SEVERITY_MAP.get(rule.get("severity", "INFO"), "MEDIUM"),
            "details": {
                "cwe": meta.get("cwe", ""),
                "masvs": meta.get("masvs", ""),
                "description": rule.get("message", ""),
                "recommendation": rule.get("message", ""),
            },
        })
    return defs


def _load_all_rule_defs(configs: List[str]) -> List[Dict[str, Any]]:
    defs: List[Dict[str, Any]] = []
    for cfg in configs:
        if os.path.isdir(cfg):
            for fname in sorted(os.listdir(cfg)):
                if fname.endswith((".yml", ".yaml")):
                    defs.extend(_load_rule_defs_from_yml(os.path.join(cfg, fname)))
        else:
            defs.extend(_load_rule_defs_from_yml(cfg))
    return defs


def _rule_def_from_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback rule def for a rule that fired but was not in any loaded pack."""
    return {
        "id": finding["rule_id"],
        "name": finding["name"],
        "severity": finding["severity"],
        "details": dict(finding["details"]),
    }


def _is_generated_file(abs_path: str, _cache: Dict[str, bool] = {}) -> bool:
    if abs_path in _cache:
        return _cache[abs_path]
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(_GENERATED_HEADER_SCAN_BYTES)
    except OSError:
        _cache[abs_path] = False
        return False
    result = bool(_GENERATED_CODE_HEADER_RE.search(head))
    _cache[abs_path] = result
    return result


LAST_RUN_SKIPPED_GENERATED = 0
LAST_RUN_DUPLICATES_DROPPED = 0


def _scoped_vendor_lib_excludes(source_dir: str) -> List[str]:
    """Relative paths of vendored-lib files/dirs, but ONLY where a served-asset
    root (static/assets/public/...) is an ancestor. Named app source outside such
    a root (e.g. src/vue.js, a feature dir leaflet/) is left in scope."""
    import fnmatch
    excludes: List[str] = []
    for dirpath, dirnames, filenames in os.walk(source_dir):
        rel_dir = os.path.relpath(dirpath, source_dir)
        segs = [] if rel_dir == "." else rel_dir.split(os.sep)
        under_served = any(s in _SERVED_ASSET_ROOT_DIRS for s in segs)
        if under_served:
            hit = [d for d in dirnames if d in _VENDOR_LIB_DIR_NAMES]
            for d in hit:
                excludes.append(os.path.join(rel_dir, d) if rel_dir != "." else d)
            # Prune excluded lib dirs so we don't also enumerate their files.
            dirnames[:] = [d for d in dirnames if d not in hit]
        if not under_served:
            continue
        for fn in filenames:
            if any(fnmatch.fnmatch(fn, g) for g in _VENDOR_LIB_FILE_GLOBS):
                rel = os.path.join(rel_dir, fn) if rel_dir != "." else fn
                excludes.append(rel)
    return excludes


def _parse_semgrep_data(data: Dict[str, Any], source_dir: str,
                        seen_coords: Set[Tuple[str, str, int, int]],
                        seen_keys: Set[Tuple[str, str, int]]) -> Tuple[List[Dict[str, Any]], int, int]:
    """Turn semgrep JSON into finding dicts, deduping against the shared seen sets."""
    findings: List[Dict[str, Any]] = []
    skipped_generated = 0
    duplicates_dropped = 0
    for r in data.get("results", []):
        abs_path = r.get("path", "")
        coord = (
            r.get("check_id", ""),
            abs_path,
            r.get("start", {}).get("line", 0),
            r.get("start", {}).get("col", 0),
        )
        if coord in seen_coords:
            continue
        seen_coords.add(coord)
        if _is_generated_file(abs_path):
            skipped_generated += 1
            continue
        rel_path = os.path.relpath(abs_path, source_dir)
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        check_id = r.get("check_id", "semgrep-finding").rsplit(".", 1)[-1]
        line_no = r.get("start", {}).get("line", 1)
        key = (check_id, rel_path, line_no)
        if key in seen_keys:
            duplicates_dropped += 1
            continue
        seen_keys.add(key)
        findings.append({
            "rule_id": check_id,
            "file_path": rel_path,
            "name": extra.get("message", r.get("check_id", ""))[:120],
            "severity": semgrep_engine.SEVERITY_MAP.get(extra.get("severity", "INFO"), "MEDIUM"),
            "line": line_no,
            "details": {
                "cwe": meta.get("cwe", ""),
                "masvs": meta.get("masvs", ""),
                "description": extra.get("message", ""),
                "recommendation": extra.get("message", ""),
            },
            "engine": "semgrep",
        })
    return findings, skipped_generated, duplicates_dropped


# Cap on explicit test-path targets handed to the secret pass, to bound runtime.
_TEST_SECRET_PASS_MAX_FILES = 3000


def _collect_test_dir_files(source_dir: str) -> List[str]:
    """Files that live inside a literal test/ tests/ ... directory (which semgrep's
    default ignore drops), with a scannable extension, skipping vendored trees."""
    scannable: Tuple[str, ...] = tuple(
        ext for exts in _LANG_EXTS.values() for ext in exts
    )
    targets: List[str] = []
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in _VENDOR_DIR_NAMES]
        rel_root = os.path.relpath(root, source_dir)
        marker = "/" + rel_root.replace(os.sep, "/").lstrip("/") + "/"
        if not any(frag in marker.lower() for frag in _TEST_PATH_DIR_FRAGMENTS):
            continue
        for f in files:
            if f.endswith(scannable):
                targets.append(os.path.join(root, f))
                if len(targets) >= _TEST_SECRET_PASS_MAX_FILES:
                    return targets
    return targets


def _run_test_path_secret_pass(source_dir: str, configs: List[str], timeout: int,
                               seen_coords: Set[Tuple[str, str, int, int]],
                               seen_keys: Set[Tuple[str, str, int]]) -> List[Dict[str, Any]]:
    """Second, secret-only pass over files in literal test/ dirs. Semgrep's default
    ignore drops those dirs for every rule, hiding real leaked credentials there.
    Passing them as explicit targets bypasses that ignore; scoping to the secret
    packs keeps the blast radius off injection/XSS rules. Hits are down-ranked to
    LOW by the caller's test-path downweighting, never dropped. We run the full
    config set but keep ONLY secret-class hits, so injection/XSS rules stay
    ignored in test dirs (the hardcoded-credential rule lives in a language
    pack, not just the secrets pack)."""
    targets = _collect_test_dir_files(source_dir)
    if not targets:
        return []
    cmd = ["semgrep"]
    for cfg in configs:
        cmd += ["--config", cfg]
    cmd += targets
    cmd += ["--json", "--quiet", "--no-git-ignore", "--timeout", "60", "--no-rewrite-rule-ids"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return []
    if not proc.stdout:
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    findings, _skipped, _dupes = _parse_semgrep_data(data, source_dir, seen_coords, seen_keys)
    # Only secret-class hits belong here; injection/XSS rules stay ignored in tests.
    return [f for f in findings if _is_secret_finding(f)]


def _run_web_semgrep(source_dir: str, configs: List[str],
                      timeout: Optional[int] = None) -> Optional[List[Dict[str, Any]]]:
    global LAST_RUN_SKIPPED_GENERATED, LAST_RUN_DUPLICATES_DROPPED
    LAST_RUN_SKIPPED_GENERATED = 0
    LAST_RUN_DUPLICATES_DROPPED = 0
    if not configs:
        semgrep_engine._record_run("error", message="no rule packs resolved for detected stack(s)")
        return None
    if not semgrep_engine.is_available():
        semgrep_engine._record_run("unavailable")
        return None

    file_count = semgrep_engine.count_source_files(source_dir)
    if timeout is None:
        env_to = os.environ.get("NARVY_SEMGREP_TIMEOUT", "").strip()
        timeout = int(env_to) if env_to.isdigit() else semgrep_engine.compute_semgrep_timeout(source_dir)

    cmd = ["semgrep"]
    for cfg in configs:
        cmd += ["--config", cfg]
    cmd += [source_dir, "--json", "--quiet", "--no-git-ignore", "--timeout", "60"]
    # Otherwise semgrep prefixes each rule id with the install-dependent config path.
    cmd += ["--no-rewrite-rule-ids"]
    for vendor_dir in sorted(_VENDOR_DIR_NAMES):
        cmd += ["--exclude", vendor_dir]
    # Build artifacts are machine-generated anywhere, so excluded by broad glob.
    for build_glob in _BUILD_ARTIFACT_FILE_GLOBS:
        cmd += ["--exclude", build_glob]
    # Lib-name globs / lib dir-names only suppress matches under a served-asset
    # root; app code named like a lib (src/vue.js) stays in scope.
    for rel in _scoped_vendor_lib_excludes(source_dir):
        cmd += ["--exclude", rel]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        semgrep_engine._record_run("timeout", timeout_s=timeout, file_count=file_count)
        return []

    if not proc.stdout:
        if proc.returncode not in (0, 1):
            semgrep_engine._record_run("error", timeout_s=timeout, file_count=file_count,
                                        message=f"semgrep exited rc={proc.returncode}: {proc.stderr[:300]}")
        else:
            semgrep_engine._record_run("ok", timeout_s=timeout, file_count=file_count)
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        semgrep_engine._record_run("error", timeout_s=timeout, file_count=file_count,
                                    message="semgrep output was not valid JSON")
        return []

    semgrep_engine._record_run("ok", timeout_s=timeout, file_count=file_count)

    # Semgrep can emit one rule at one byte range several times (multiple binding sets);
    # a second key collapses the same rule delivered by two configs.
    seen_coords: Set[Tuple[str, str, int, int]] = set()
    seen_keys: Set[Tuple[str, str, int]] = set()
    findings, skipped_generated, duplicates_dropped = _parse_semgrep_data(
        data, source_dir, seen_coords, seen_keys)

    # Secret-only pass over literal test/ dirs that semgrep's default ignore hides.
    findings += _run_test_path_secret_pass(source_dir, configs, 60, seen_coords, seen_keys)
    LAST_RUN_SKIPPED_GENERATED = skipped_generated
    LAST_RUN_DUPLICATES_DROPPED = duplicates_dropped

    # Collapse overlapping JWT-secret rules, then down-weight secret hits in test paths.
    findings = _collapse_jwt_aliases(findings)
    findings = _downweight_test_secrets(findings)
    findings = _downweight_test_findings(findings)
    return findings


def _count_scanned_files(source_dir: str, ported_stacks: Set[str]) -> int:
    exts: Set[str] = set()
    for stack in ported_stacks:
        exts.update(_LANG_EXTS.get(stack, ()))
    if not exts:
        return 0
    return _count_density(source_dir, tuple(exts))


def analyze_source(source_dir: str) -> Dict[str, Any]:
    """Run web/backend source-mode SAST over source_dir, read-only."""
    empty_stats = {
        "stacks_detected": [], "stacks_unsupported": [], "files_scanned": 0,
    }
    if not source_dir or not os.path.isdir(source_dir):
        return {
            "ok": False, "error": f"Not a directory: {source_dir}",
            "findings": [], "rule_defs": [], "notes": [], **empty_stats,
        }

    notes: List[str] = []
    all_findings: List[Dict[str, Any]] = []

    ported_stacks, unported_stacks = detect_web_stacks(source_dir)

    if unported_stacks:
        labels = ", ".join(sorted(_UNPORTED_STACK_LABELS[s] for s in unported_stacks))
        detail = " ".join(
            _UNPORTED_STACK_PARTIAL_NOTE.get(s, "") for s in sorted(unported_stacks)
        ).strip() if ported_stacks else (
            "That part of the codebase was not scanned by this pass."
        )
        notes.append(
            f"Also detected {labels} in this repo - no DEDICATED rule pack has "
            f"been ported for that yet ({SUPPORTED_LANGUAGES_LABEL} are fully "
            f"covered). {detail}"
        )

    for stack in sorted(ported_stacks):
        if stack in _LOW_COVERAGE_STACKS:
            notes.append(f"LIMITED COVERAGE: {_LOW_COVERAGE_STACKS[stack]}")

    if not ported_stacks:
        notes.append(
            f"No supported web-source language ({SUPPORTED_LANGUAGES_LABEL}) "
            "was detected in this directory - nothing to scan with the "
            "current rule packs."
        )
        rule_defs = []
    else:
        configs = _resolve_configs(ported_stacks)
        rule_defs = _load_all_rule_defs(configs)

        if semgrep_engine.is_available():
            findings = _run_web_semgrep(source_dir, configs)
            if findings:
                all_findings.extend(findings)
                known_rule_ids = {d["id"] for d in rule_defs}
                for finding in findings:
                    rid = finding["rule_id"]
                    if rid not in known_rule_ids:
                        rule_defs.append(_rule_def_from_finding(finding))
                        known_rule_ids.add(rid)
            if LAST_RUN_SKIPPED_GENERATED:
                notes.append(
                    f"Skipped {LAST_RUN_SKIPPED_GENERATED} finding(s) inside "
                    "auto-generated code (files carrying a 'Code generated "
                    "... DO NOT EDIT.' header - e.g. protobuf/OpenAPI/mock "
                    "codegen output) - not actionable, not hand-written app "
                    "code."
                )
            sg_note = semgrep_engine.degraded_coverage_note()
            if sg_note:
                notes.append(sg_note)
        else:
            notes.append(
                "semgrep not found - install with `pip install semgrep` for "
                "web source-code analysis. No findings from this pass."
            )

    files_scanned = _count_scanned_files(source_dir, ported_stacks)

    return {
        "ok": True,
        "error": None,
        "findings": all_findings,
        "rule_defs": rule_defs,
        "stacks_detected": sorted(ported_stacks),
        "stacks_unsupported": sorted(unported_stacks),
        "files_scanned": files_scanned,
        "notes": notes,
    }
