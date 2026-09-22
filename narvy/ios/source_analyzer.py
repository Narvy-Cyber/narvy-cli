"""iOS source-mode (Swift/ObjC) SAST entry point: ObjC regex pass, Swift Semgrep
pass, plist/entitlements pass. Public API: analyze_source()."""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import yaml

from narvy.rule_engine import load_rules_from_dir, run_rules_on_file
from narvy import semgrep_engine
from narvy import comment_filter
from narvy.ios.third_party_filter import is_ios_vendor_dir_path, IOS_VENDOR_DIR_NAMES
from narvy.ios import plist_checks
from narvy.ios import trust_all_context

_HERE = os.path.dirname(__file__)
OBJC_RULES_DIR = os.path.join(_HERE, "..", "rules", "ios", "objc")
SWIFT_SEMGREP_RULES_PATH = os.path.join(_HERE, "..", "rules", "ios_swift.yml")

_OBJC_EXTENSIONS = (".m", ".mm", ".h")
_SWIFT_EXTENSION = ".swift"

# Skips the npm tree a React Native project keeps beside its Xcode project.
_EXTRA_SKIP_DIR_NAMES = frozenset({"node_modules", ".git"})

# Suffix match: Xcode names test folders <TargetName>Tests / <TargetName>UITests.
_TEST_DIR_SUFFIXES = ("Tests", "UITests")

_SEMGREP_SEVERITY_MAP = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "INFO": "MEDIUM",
}


def _is_test_dir_name(name: str) -> bool:
    return name.endswith(_TEST_DIR_SUFFIXES)


def _is_extra_skip_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").split("/")
    return any(part in _EXTRA_SKIP_DIR_NAMES or _is_test_dir_name(part) for part in parts)


def _is_skipped_path(rel_path: str) -> bool:
    return is_ios_vendor_dir_path(rel_path) or _is_extra_skip_path(rel_path)


def _detect_react_native(source_dir: str) -> bool:
    """Structural signal that this is (at least partly) a React Native app."""
    if os.path.isdir(os.path.join(source_dir, "node_modules", "react-native")):
        return True
    for fname in ("Podfile", "Podfile.lock"):
        fpath = os.path.join(source_dir, fname)
        if os.path.isfile(fpath):
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            if "React-Core" in content or "react-native" in content.lower():
                return True
    return False


def _collect_source_files(source_dir: str) -> Tuple[List[str], List[str], int]:
    """Return (swift_files, objc_files, skipped_third_party_count)."""
    swift_files: List[str] = []
    objc_files: List[str] = []
    skipped = 0

    for root, _dirs, files in os.walk(source_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, source_dir)
            is_swift = fname.endswith(_SWIFT_EXTENSION)
            is_objc = fname.endswith(_OBJC_EXTENSIONS)
            if not (is_swift or is_objc):
                continue
            if _is_skipped_path(rel_path):
                skipped += 1
                continue
            if is_swift:
                swift_files.append(fpath)
            else:
                objc_files.append(fpath)

    return swift_files, objc_files, skipped


def _load_swift_semgrep_rule_defs() -> List[Dict[str, Any]]:
    """Synthesize a rule-def dict per rule id in ios_swift.yml, for SARIF."""
    try:
        with open(SWIFT_SEMGREP_RULES_PATH, "r") as f:
            data = yaml.safe_load(f)
    except OSError:
        return []

    defs = []
    for rule in (data or {}).get("rules", []):
        meta = rule.get("metadata", {}) or {}
        defs.append({
            "id": rule["id"],
            "name": rule.get("message", rule["id"])[:120],
            "severity": _SEMGREP_SEVERITY_MAP.get(rule.get("severity", "INFO"), "MEDIUM"),
            "details": {
                "cwe": meta.get("cwe", ""),
                "masvs": meta.get("masvs", ""),
                "description": rule.get("message", ""),
                "recommendation": rule.get("message", ""),
            },
        })
    return defs


def _run_swift_semgrep(source_dir: str,
                       timeout: Optional[int] = None) -> Optional[List[Dict[str, Any]]]:
    """Run Semgrep against ios_swift.yml over source_dir."""
    if not semgrep_engine.is_available():
        semgrep_engine._record_run('unavailable')
        return None

    file_count = semgrep_engine.count_source_files(source_dir)
    if timeout is None:
        timeout = semgrep_engine.compute_semgrep_timeout(source_dir)

    # --exclude args must be BARE names: a '/' anchors the pattern to the scan root.
    exclude_args: List[str] = []
    for name in sorted(IOS_VENDOR_DIR_NAMES | _EXTRA_SKIP_DIR_NAMES):
        exclude_args += ["--exclude", name]
    for suffix in _TEST_DIR_SUFFIXES:
        exclude_args += ["--exclude", f"*{suffix}"]

    cmd = (
        ["semgrep", "--config", SWIFT_SEMGREP_RULES_PATH, source_dir,
         "--include", "*.swift",
         "--json", "--quiet", "--no-git-ignore",
         "--timeout", "60"]
        + exclude_args
    )
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        semgrep_engine._record_run('timeout', timeout_s=timeout,
                                   file_count=file_count)
        return []

    if not proc.stdout:
        semgrep_engine._record_run('ok', timeout_s=timeout,
                                   file_count=file_count)
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        semgrep_engine._record_run(
            'error', timeout_s=timeout, file_count=file_count,
            message="semgrep output was not valid JSON")
        return []

    semgrep_engine._record_run('ok', timeout_s=timeout, file_count=file_count)

    # Per-file (content, comment-mask) cache: read each file at most once.
    file_cache: Dict[str, Tuple[str, Optional[List[bool]]]] = {}

    def _get_file(abs_path: str) -> Tuple[str, Optional[List[bool]]]:
        if abs_path not in file_cache:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                file_cache[abs_path] = ("", None)
                return file_cache[abs_path]
            mask = None
            if "//" in content or "/*" in content:
                mask = comment_filter.build_comment_mask(content)
            file_cache[abs_path] = (content, mask)
        return file_cache[abs_path]

    findings = []
    for r in data.get("results", []):
        abs_path = r.get("path", "")
        rel_path = os.path.relpath(abs_path, source_dir)
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        # Semgrep prefixes local-config ids with a dotted namespace; ours have no dots.
        check_id = r.get("check_id", "semgrep-finding").rsplit(".", 1)[-1]
        line_no = r.get("start", {}).get("line", 1)
        col_no = r.get("start", {}).get("col", 1)

        content, mask = _get_file(abs_path)

        # Drop regex-rule hits that sit inside a comment (AST rules never do).
        if mask is not None and comment_filter.line_col_in_comment(
            content, line_no, col_no, mask
        ):
            continue

        severity = _SEMGREP_SEVERITY_MAP.get(extra.get("severity", "INFO"), "MEDIUM")
        message = extra.get("message", "")

        # Downgrade trust-all-certs when guarded by a per-request opt-in flag.
        if check_id == "ios-swift-trust-all-certs" and content:
            flag = trust_all_context.opt_in_trust_flag(content, line_no)
            if flag:
                severity = "MEDIUM"
                message = (
                    message.rstrip()
                    + f" [Narvy: this path is reachable only when the opt-in "
                    f"flag `{flag}` is set (per-request, not unconditional), so "
                    f"severity is lowered - verify that flag is never enabled "
                    f"in production builds.]"
                )

        findings.append({
            "rule_id": check_id,
            "file_path": rel_path,
            "name": message[:120] if message else extra.get("message", r.get("check_id", ""))[:120],
            "severity": severity,
            "line": line_no,
            "details": {
                "cwe": meta.get("cwe", ""),
                "masvs": meta.get("masvs", ""),
                "description": message,
                "recommendation": message,
            },
            "engine": "semgrep",
        })
    return findings


def analyze_source(source_dir: str) -> Dict[str, Any]:
    """Scan a checked-out Swift/ObjC repo (read-only); returns the findings dict."""
    if not source_dir or not os.path.isdir(source_dir):
        return {
            "ok": False,
            "error": f"Not a directory: {source_dir}",
            "findings": [],
            "rule_defs": [],
            "swift_files_scanned": 0,
            "objc_files_scanned": 0,
            "skipped_third_party": 0,
            "notes": [],
        }

    notes: List[str] = []
    all_findings: List[Dict[str, Any]] = []

    objc_rules = load_rules_from_dir(OBJC_RULES_DIR)
    swift_semgrep_rule_defs = _load_swift_semgrep_rule_defs()

    swift_files, objc_files, skipped_third_party = _collect_source_files(source_dir)

    if _detect_react_native(source_dir):
        notes.append(
            "This looks like a React Native app (node_modules/react-native "
            "or a Podfile referencing React-Core was found). This scanner "
            "only covers the native Swift/Objective-C shell - the app's "
            "JS/TS business logic is out of scope and was not analyzed."
        )

    for file_path in objc_files:
        rel_path = os.path.relpath(file_path, source_dir)
        findings_in_file = run_rules_on_file(file_path, objc_rules)
        for finding in findings_in_file:
            finding["file_path"] = rel_path
            finding["engine"] = "regex"
        all_findings.extend(findings_in_file)

    if semgrep_engine.is_available():
        swift_findings = _run_swift_semgrep(source_dir)
        if swift_findings:
            all_findings.extend(swift_findings)
        _sg_note = semgrep_engine.degraded_coverage_note()
        if _sg_note:
            notes.append(_sg_note)
    else:
        notes.append(
            "semgrep not found - install with `pip install semgrep` for "
            "Swift analysis. ObjC regex rules still ran."
        )

    plist_findings, plist_notes, _plist_count = plist_checks.analyze_plist_and_entitlements(source_dir)
    all_findings.extend(plist_findings)
    notes.extend(plist_notes)

    rule_defs = list(objc_rules) + swift_semgrep_rule_defs + plist_checks.get_rule_defs()

    return {
        "ok": True,
        "error": None,
        "findings": all_findings,
        "rule_defs": rule_defs,
        "swift_files_scanned": len(swift_files),
        "objc_files_scanned": len(objc_files),
        "skipped_third_party": skipped_third_party,
        "notes": notes,
    }
