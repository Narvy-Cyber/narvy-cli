"""Android source (Gradle/Java/Kotlin) SAST. Entry point: analyze_source()."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from narvy.rule_engine import load_rules_from_dir, run_rules_on_file
from narvy import semgrep_engine
from narvy import crypto_taint_lite
from narvy.scope_config import ScopeConfig
from narvy.third_party_filter import (
    GRADLE_SOURCE_MARKERS,
    extract_component_package_roots,
    parse_manifest_package_attr,
    resolve_file_scope,
)

_HERE = os.path.dirname(__file__)
ANDROID_RULES_DIR = os.path.join(_HERE, "..", "rules", "android")

_MANIFEST_FILENAME = "AndroidManifest.xml"
_GRADLE_BUILD_FILENAMES = ("build.gradle.kts", "build.gradle")
_SRC_CODE_EXTS = (".java", ".kt")

# Build output, tool caches and VCS dirs, pruned from every walk here.
_SKIP_DIR_NAMES = frozenset({
    "build", ".gradle", ".idea", ".git", "out", ".cxx", "node_modules",
    ".vscode", ".vs", "captures",
})

_NAMESPACE_RE = re.compile(r'\bnamespace\s*=?\s*["\']([\w.]+)["\']')
_APPLICATION_ID_RE = re.compile(r'\bapplicationId\s*=?\s*["\']([\w.]+)["\']')

# Name-based hardcoded-secret rules prone to preference-key / type-name echoes.
_SECRET_NAME_RULE_IDS = frozenset({
    "AND-S-001", "AND-S-002", "AND-S-010",
    "android-hardcoded-credential-java", "android-hardcoded-credential-kotlin",
})
_TYPE_DECL_RE = re.compile(r'\b(?:class|interface|object|enum)\b\s+[A-Za-z_]')
_QUOTED_RE = re.compile(r'"([^"\n]*)"')
_IDENT_VALUE_RE = re.compile(r'^[a-z][a-z0-9_]*$')
_LHS_NAME_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=\n]*)?=\s*"')
# Preference-key constant naming (KEY_.../PREF_...): its value is a settings-store
# key string, not a secret.
_PREFKEY_CONST_RE = re.compile(r'^(?:KEY|PREF|PREFS|PREFERENCE|SETTING|SETTINGS)_', re.IGNORECASE)

# Test / fixture locations where a headline CRITICAL/HIGH is usually a fixture.
_TEST_PATH_FRAGMENTS = (
    "/test/", "/tests/", "/androidtest/", "/__tests__/", "/spec/", "/specs/",
    "/fixtures/", "/fixture/", "/testdata/", "/mocks/", "/__mocks__/",
)
_TEST_FILE_RE = re.compile(
    r"(?:^|[._-])(?:test|tests|spec|specs|mock|mocks|fixture|fixtures)(?:[._-]|$)",
    re.IGNORECASE,
)


def _line_text(source_dir: str, rel_path: str, line: int) -> str:
    try:
        full = os.path.join(source_dir, rel_path)
        with open(full, "r", encoding="utf-8", errors="ignore") as fh:
            for i, text in enumerate(fh, start=1):
                if i == line:
                    return text
    except OSError:
        pass
    return ""


def _is_prefkey_echo_or_typename(line: str) -> bool:
    """A preference-key-name literal echoing its constant, or a class/type name - not a real secret."""
    if '"' not in line and _TYPE_DECL_RE.search(line):
        return True
    m = _QUOTED_RE.search(line)
    if not m:
        return False
    val = m.group(1)
    if not _IDENT_VALUE_RE.match(val):
        return False
    lhs = _LHS_NAME_RE.search(line)
    if not lhs:
        return False
    name = lhs.group(1)
    # The value just echoes the constant name, or it's a KEY_*/PREF_* settings key
    # (e.g. KEY_SECRET_TOKEN = "secret_token_pref").
    return val.lower() in name.lower() or bool(_PREFKEY_CONST_RE.match(name))


def _has_no_string_literal_rhs(line: str) -> bool:
    """True when a name-based secret match is assigned from a call or identifier, not a literal."""
    return not _QUOTED_RE.search(line)


def _drop_prefkey_echo_secrets(source_dir: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    kept = []
    for f in findings:
        if f.get("rule_id") in _SECRET_NAME_RULE_IDS:
            line = _line_text(source_dir, f.get("file_path", ""), f.get("line") or 0)
            if line and (_has_no_string_literal_rhs(line) or _is_prefkey_echo_or_typename(line)):
                continue
        kept.append(f)
    return kept


def _is_test_path(rel_path: str) -> bool:
    p = "/" + rel_path.replace("\\", "/").lstrip("/")
    if any(frag in p.lower() for frag in _TEST_PATH_FRAGMENTS):
        return True
    return bool(_TEST_FILE_RE.search(p.rsplit("/", 1)[-1]))


def _downrank_test_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Lower (never drop) CRITICAL/HIGH/MEDIUM findings in test/fixture paths to LOW and tag them."""
    note = (
        " [Narvy: this hit is in a test/fixture path, where such code is usually a "
        "fixture rather than shipped app code, so severity is lowered - confirm it "
        "is not a real production issue.]"
    )
    for f in findings:
        if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM") and _is_test_path(f.get("file_path", "")):
            f["severity"] = "LOW"
            details = f.setdefault("details", {})
            if isinstance(details, dict) and note.strip() not in (details.get("description") or ""):
                details["description"] = (details.get("description") or "") + note
    return findings

# A module may use either source-root name, or both.
_SRC_LEAF_DIRS = ("java", "kotlin")
_MAX_INFER_DEPTH = 12


def _should_prune_dir(name: str) -> bool:
    return name in _SKIP_DIR_NAMES or name.startswith(".")


def find_android_manifests(source_dir: str) -> List[str]:
    manifests = []
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if not _should_prune_dir(d)]
        if _MANIFEST_FILENAME in files:
            manifests.append(os.path.join(root, _MANIFEST_FILENAME))
    return manifests


def _module_dir_for_manifest(manifest_path: str) -> Optional[str]:
    """The module dir for a `<module>/src/<variant>/AndroidManifest.xml` path."""
    main_dir = os.path.dirname(manifest_path)
    src_dir = os.path.dirname(main_dir)
    if os.path.basename(src_dir) == "src":
        return os.path.dirname(src_dir)
    return None


def _read_gradle_namespace_and_app_id(module_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Read `namespace` and `applicationId` from a module's build.gradle(.kts) (regex; computed values yield None)."""
    namespace, app_id = None, None
    for fname in _GRADLE_BUILD_FILENAMES:
        fpath = os.path.join(module_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue
        if namespace is None:
            m = _NAMESPACE_RE.search(content)
            if m:
                namespace = m.group(1)
        if app_id is None:
            m = _APPLICATION_ID_RE.search(content)
            if m:
                app_id = m.group(1)
    return namespace, app_id


def _infer_root_packages_from_dir(main_dir: str) -> set:
    """Infer a module's top package from its source dir chain of single-child directories."""
    roots = set()
    for leaf in _SRC_LEAF_DIRS:
        src_root = os.path.join(main_dir, leaf)
        if not os.path.isdir(src_root):
            continue
        segments: List[str] = []
        current = src_root
        for _ in range(_MAX_INFER_DEPTH):
            try:
                entries = os.listdir(current)
            except OSError:
                break
            subdirs = [e for e in entries if not e.startswith(".")
                       and os.path.isdir(os.path.join(current, e))]
            has_files = any(not e.startswith(".") and os.path.isfile(os.path.join(current, e))
                             for e in entries)
            if has_files or len(subdirs) != 1:
                break
            segments.append(subdirs[0])
            current = os.path.join(current, subdirs[0])
        if segments:
            roots.add(".".join(segments))
    return roots


def get_own_package_roots_gradle(manifest_paths: List[str]) -> set:
    all_roots = set()
    for manifest_path in manifest_paths:
        main_dir = os.path.dirname(manifest_path)
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            content = ""

        module_dir = _module_dir_for_manifest(manifest_path)
        namespace, app_id = (None, None)
        if module_dir:
            namespace, app_id = _read_gradle_namespace_and_app_id(module_dir)
        manifest_pkg = parse_manifest_package_attr(content)
        dir_roots = _infer_root_packages_from_dir(main_dir)

        # Anchor for a component's relative android:name=".Foo".
        anchor = namespace or manifest_pkg or (sorted(dir_roots)[0] if dir_roots else None)

        module_roots = set(dir_roots)
        for candidate in (namespace, manifest_pkg, app_id):
            if candidate:
                module_roots.add(candidate)
        module_roots |= extract_component_package_roots(content, anchor)

        all_roots |= module_roots
    return all_roots


def _collect_source_files(source_dir: str) -> Tuple[List[str], List[str]]:
    code_files: List[str] = []
    xml_files: List[str] = []
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if not _should_prune_dir(d)]
        for fname in files:
            if fname.endswith(_SRC_CODE_EXTS):
                code_files.append(os.path.join(root, fname))
            elif fname.endswith(".xml"):
                xml_files.append(os.path.join(root, fname))
    return code_files, xml_files


# The '*' matches any source-set variant, not just 'main'.
_SEMGREP_INCLUDE_PREFIXES = ["src/*/java/", "src/*/kotlin/"]


def analyze_source(source_dir: str, override_config: Optional[ScopeConfig] = None) -> Dict[str, Any]:
    """Run Android source-mode SAST against a Gradle/Java/Kotlin checkout. Read-only."""
    empty_stats = {
        "manifests_found": 0, "own_roots": [], "code_files_scanned": 0,
        "xml_files_scanned": 0, "skipped_third_party": 0,
    }
    if not source_dir or not os.path.isdir(source_dir):
        return {
            "ok": False,
            "error": f"Not a directory: {source_dir}",
            "findings": [],
            "rule_defs": [],
            "notes": [],
            **empty_stats,
        }

    notes: List[str] = []
    all_findings: List[Dict[str, Any]] = []

    manifest_paths = sorted(find_android_manifests(source_dir))
    own_roots = get_own_package_roots_gradle(manifest_paths)

    if not manifest_paths:
        notes.append(
            "No AndroidManifest.xml found anywhere in this tree - this looked "
            "like an Android Gradle project (an Android Gradle plugin id / "
            "`android { }` block / AndroidX flag was found) but no module's "
            "own package could be confirmed. "
            "Falling back to the known-SDK denylist instead of an own-package "
            "allowlist, which is less precise (may include some third-party "
            "code, should not miss any of your own)."
        )
    elif not own_roots:
        notes.append(
            f"Found {len(manifest_paths)} AndroidManifest.xml file(s) but "
            "could not determine any module's own package (no `namespace` in "
            "build.gradle, no manifest package= attribute, no source files "
            "under src/main/java or src/main/kotlin). Falling back to the "
            "known-SDK denylist instead of an own-package allowlist."
        )

    code_files, xml_files = _collect_source_files(source_dir)
    all_source_files = code_files + xml_files

    source_files = [
        f for f in all_source_files
        if resolve_file_scope(f, own_roots, override_config, markers=GRADLE_SOURCE_MARKERS)
    ]
    skipped_third_party = len(all_source_files) - len(source_files)

    rules = load_rules_from_dir(ANDROID_RULES_DIR)
    code_files_scanned = 0
    xml_files_scanned = 0
    for file_path in source_files:
        rel_path = os.path.relpath(file_path, source_dir)
        findings_in_file = run_rules_on_file(file_path, rules)
        for finding in findings_in_file:
            finding["file_path"] = rel_path
            finding["engine"] = "regex"
        all_findings.extend(findings_in_file)

        if file_path.endswith(_SRC_CODE_EXTS):
            code_files_scanned += 1
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                    taint_findings = crypto_taint_lite.check_file(fh.read())
            except OSError:
                taint_findings = []
            for finding in taint_findings:
                finding["file_path"] = rel_path
            all_findings.extend(taint_findings)
        else:
            xml_files_scanned += 1

    semgrep_rule_defs: List[Dict[str, Any]] = []
    if semgrep_engine.is_available():
        semgrep_findings = semgrep_engine.run_semgrep(
            source_dir, own_roots=own_roots, override_config=override_config,
            include_path_prefixes=_SEMGREP_INCLUDE_PREFIXES,
        )
        if semgrep_findings:
            all_findings.extend(semgrep_findings)
        # A timed-out semgrep pass returns [], which must not read as clean.
        _sg_note = semgrep_engine.degraded_coverage_note()
        if _sg_note:
            notes.append(_sg_note)
        semgrep_rule_defs = semgrep_engine.load_rule_defs()
    else:
        notes.append(
            "semgrep not found - install with `pip install semgrep` for "
            "deeper structural detection. Regex rules still ran."
        )

    rule_defs = list(rules) + semgrep_rule_defs

    all_findings = _drop_prefkey_echo_secrets(source_dir, all_findings)
    all_findings = _downrank_test_findings(all_findings)

    return {
        "ok": True,
        "error": None,
        "findings": all_findings,
        "rule_defs": rule_defs,
        "manifests_found": len(manifest_paths),
        "own_roots": sorted(own_roots),
        "code_files_scanned": code_files_scanned,
        "xml_files_scanned": xml_files_scanned,
        "skipped_third_party": skipped_third_party,
        "notes": notes,
    }
