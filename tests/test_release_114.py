"""1.1.4: scan-root spelling (8.3 names, symlinks, VCS ancestors), name-only
secret severity, executed-vs-matched rule counts, grouped summary table."""
import ctypes
import json
import os
import shutil
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import pathnorm, semgrep_engine, secret_value_grade as svg  # noqa: E402
from narvy import main as narvy_main  # noqa: E402
from narvy.rule_engine import load_rules_from_dir, run_rules_on_file  # noqa: E402

HAS_SEMGREP = semgrep_engine.is_available()
ANDROID_RULES = os.path.join(os.path.dirname(narvy_main.__file__), "rules", "android")


def _jadx_tree(d, pkg="com/example/app"):
    src = os.path.join(d, "sources", *pkg.split("/"))
    os.makedirs(src, exist_ok=True)
    with open(os.path.join(src, "Web.java"), "w", encoding="utf-8") as f:
        f.write("package com.example.app;\n"
                "class Web { void f(android.webkit.WebSettings s) { s.setJavaScriptEnabled(true); } }\n")
    vendor = os.path.join(d, "sources", "okhttp3")
    os.makedirs(vendor, exist_ok=True)
    with open(os.path.join(vendor, "V.java"), "w", encoding="utf-8") as f:
        f.write("package okhttp3;\n"
                "class V { void f(android.webkit.WebSettings s) { s.setJavaScriptEnabled(true); } }\n")
    return d


@pytest.fixture(autouse=True)
def _reset():
    semgrep_engine._record_run('not_run')
    yield
    semgrep_engine._record_run('not_run')


# --- 1. one spelling of the scan root ------------------------------------

class _FakeGetLongPathNameW:
    """GetLongPathNameW with the Win32 size protocol, over a short->long map."""

    def __init__(self, mapping):
        self.mapping = mapping

    def __call__(self, path, buf, size):
        long_path = path
        for short, full in self.mapping.items():
            long_path = long_path.replace(short, full)
        if buf is None or size <= len(long_path):
            return len(long_path) + 1
        buf.value = long_path
        return len(long_path)


def test_long_path_name_expands_8dot3_components(monkeypatch):
    fake = SimpleNamespace(kernel32=SimpleNamespace(
        GetLongPathNameW=_FakeGetLongPathNameW({"RUNNER~1": "runneradmin"})))
    monkeypatch.setattr(pathnorm, "_IS_WINDOWS", True)
    monkeypatch.setattr(ctypes, "windll", fake, raising=False)
    short = r"C:\Users\RUNNER~1\AppData\Local\Temp\tmpab12"
    assert pathnorm._long_path_name(short) == r"C:\Users\runneradmin\AppData\Local\Temp\tmpab12"
    # No '~': nothing to expand, no Win32 call.
    assert pathnorm._long_path_name(r"C:\x\y") == r"C:\x\y"


def test_long_path_name_failure_keeps_the_path(monkeypatch):
    class _Zero:
        def __call__(self, *a):
            return 0
    broken = SimpleNamespace(kernel32=SimpleNamespace(GetLongPathNameW=_Zero()))
    monkeypatch.setattr(pathnorm, "_IS_WINDOWS", True)
    monkeypatch.setattr(ctypes, "windll", broken, raising=False)
    assert pathnorm._long_path_name(r"C:\Users\RUNNER~1\x") == r"C:\Users\RUNNER~1\x"


@pytest.mark.skipif(os.name == "nt", reason="alias simulated with a POSIX symlink")
def test_canonical_path_resolves_an_alias_to_the_long_name():
    with tempfile.TemporaryDirectory() as base:
        real = os.path.join(base, "runneradmin", "tmpab12")
        os.makedirs(real)
        os.symlink(os.path.join(base, "runneradmin"), os.path.join(base, "RUNNER~1"))
        alias = os.path.join(base, "RUNNER~1", "tmpab12")
        assert pathnorm.canonical_path(alias) == os.path.realpath(real)
        assert pathnorm.canonical_path(alias) == pathnorm.canonical_path(real)


@pytest.mark.skipif(not HAS_SEMGREP or os.name == "nt", reason="needs semgrep and POSIX symlinks")
def test_real_semgrep_through_an_aliased_root_below_a_vcs_folder():
    """1.1.3 reported 'matched none of the N app source files' here.

    Two ways the --include globs missed every file: the scan root is spelled
    through an alias (8.3 short name on Windows; a symlink here), and an
    ancestor folder holds .git, so semgrep's project root sits above the scan
    root and 'sources/...' no longer matches from there.
    """
    with tempfile.TemporaryDirectory() as base:
        os.makedirs(os.path.join(base, ".git"))
        real_parent = os.path.join(base, "runneradmin")
        _jadx_tree(os.path.join(real_parent, "tmpab12"))
        os.symlink(real_parent, os.path.join(base, "RUNNER~1"))
        for root in (os.path.join(base, "RUNNER~1", "tmpab12"),
                     os.path.join(real_parent, "tmpab12")):
            out = semgrep_engine.run_semgrep(root, own_roots={"com.example.app"}, timeout=300)
            assert semgrep_engine.LAST_RUN["status"] == "ok", semgrep_engine.LAST_RUN
            assert [f["file_path"].replace("\\", "/") for f in out
                    if f["rule_id"] == "android-webview-js-enabled"] == [
                "sources/com/example/app/Web.java"]


def test_include_globs_are_anchored_anywhere():
    captured = []

    def fake(cmd, **kw):
        captured.append(cmd)
        return mock.Mock(returncode=0, stdout=json.dumps(
            {"results": [], "errors": [], "paths": {"scanned": ["x"]}}), stderr="")
    with tempfile.TemporaryDirectory() as d, \
            mock.patch.object(semgrep_engine, "is_available", return_value=True), \
            mock.patch("narvy.semgrep_engine.run_tree", side_effect=fake):
        semgrep_engine.run_semgrep(_jadx_tree(d), own_roots={"com.example.app"})
    incs = [captured[0][i + 1] for i, a in enumerate(captured[0]) if a == "--include"]
    assert incs == ["**/sources/com/example/app/**"]


def test_unmatched_includes_fall_back_to_the_app_package_dirs():
    """Whatever made the globs miss, the app's own dirs are scanned as explicit roots."""
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        if len(calls) == 1:
            body = {"results": [], "errors": [], "paths": {"scanned": []}}
        else:
            target = [a for a in cmd if a.endswith(os.path.join("com", "example", "app"))][0]
            body = {"results": [{"check_id": "android-webview-js-enabled",
                                 "path": os.path.join(target, "Web.java"),
                                 "start": {"line": 2}, "extra": {"severity": "WARNING"}}],
                    "errors": [], "paths": {"scanned": [os.path.join(target, "Web.java")]}}
        return mock.Mock(returncode=0, stdout=json.dumps(body), stderr="")
    with tempfile.TemporaryDirectory() as d, \
            mock.patch.object(semgrep_engine, "is_available", return_value=True), \
            mock.patch("narvy.semgrep_engine.run_tree", side_effect=fake):
        root = _jadx_tree(d)
        out = semgrep_engine.run_semgrep(root, own_roots={"com.example.app"})
    assert len(calls) == 2
    assert "--include" not in calls[1]
    assert any(a.endswith(os.path.join("sources", "com", "example", "app")) for a in calls[1])
    assert not any(a.endswith("okhttp3") for a in calls[1])
    assert semgrep_engine.LAST_RUN["status"] == "ok"
    assert semgrep_engine.LAST_RUN_SCOPE["include_fallback"] is True
    assert [f["file_path"].replace("\\", "/") for f in out] == ["sources/com/example/app/Web.java"]


# --- 2. name-only secrets are not CRITICAL -------------------------------

@pytest.mark.parametrize("value,verdict", [
    # provider formats keep their severity
    ("AKIA" + "IOSFODNN7EXAMPLQ", svg.KEEP),
    ("AIza" + "SyD-abcdefghijklmnopqrstuvwxyz01234", svg.KEEP),
    ("sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", svg.KEEP),
    # key material of a real length
    ("This is the super secret key 123", svg.KEEP),        # 32 raw bytes, AES-256
    ("0123456789abcdef", svg.KEEP),                        # 16 raw bytes, AES-128
    ("9f86d081884c7d659a2feaa0c55ad015", svg.KEEP),        # 128-bit hex
    ("OviCwsFNWeoCSDKl3ZoD8j4BPnc1kCsfV+lOABCw", svg.KEEP),  # AWS secret shape
    # plainly not secrets
    ("password", svg.DROP), ("Password", svg.DROP), ("ProtectPassword", svg.DROP),
    ("access_token", svg.DROP), ("pref_key_token", svg.DROP),
    ("MAIN_CREDENTIAL", svg.DROP), ("ACTION_DATABASE_ASSIGN_PASSWORD_TASK", svg.DROP),
    ("com.example.app.KEY", svg.DROP), ("https://api.example.com/v1", svg.DROP),
    ("/data/local/tmp", svg.DROP), ("%s:%s", svg.DROP), ("", svg.DROP), ("changeme", svg.DROP),
    ("((?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{6,20})", svg.DROP),
    ("CREATE TABLE Key (Password TEXT PRIMARY KEY,pin TEXT )", svg.DROP),
    # name-only: capped
    ("Dinesh@123$", svg.CAP), ("feeder_secret_1234", svg.CAP), ("generator", svg.CAP),
    ("550e8400-e29b-41d4-a716-446655440000", svg.CAP),
])
def test_grade_value(value, verdict):
    assert svg.grade_value(value) == verdict


def _regex_findings(tmp, code, name="Keys.java"):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    return run_rules_on_file(path, load_rules_from_dir(ANDROID_RULES))


def test_secret_key_variable_rule_regraded_by_value():
    code = (
        "class Keys {\n"
        '  static final String PREF_KEY_THEME = "pref_key_theme_mode";\n'
        '  String secretKey = "Dinesh@123$abc";\n'
        '  String key = "This is the super secret key 123";\n'
        '  String aws_secret_access_key = "OviCwsFNWeoCSDKl3ZoD8j4BPnc1kCsfV+lOABCw";\n'
        '  String mapsApi = "AIza' 'SyD-abcdefghijklmnopqrstuvwxyz01234";\n'
        "}\n")
    with tempfile.TemporaryDirectory() as d:
        found = _regex_findings(d, code)
    s010 = {f["line"]: f for f in found if f["rule_id"] == "AND-S-010"}
    assert 2 not in s010                                  # pref key: dropped
    assert s010[3]["severity"] == "MEDIUM" and s010[3]["original_severity"] == "CRITICAL"
    assert s010[3]["value_evidence"] == "name_only" and s010[3]["confidence"] == "LOW"
    assert s010[4]["severity"] == "CRITICAL"              # AES-256 raw key: kept
    assert s010[5]["severity"] == "CRITICAL"              # AWS secret shape: kept
    # Provider-format rules themselves are untouched.
    assert any(f["rule_id"] == "AND-S-005" and f["severity"] == "HIGH" for f in found)


def test_hardcoded_password_rule_capped_not_dropped():
    with tempfile.TemporaryDirectory() as d:
        found = _regex_findings(d, 'class A { String password = "Dinesh@123$"; }\n')
    pw = [f for f in found if f["rule_id"] == "AND-S-002"]
    assert pw and all(f["severity"] == "MEDIUM" for f in pw)


def test_rule_details_are_not_mutated_across_findings():
    with tempfile.TemporaryDirectory() as d:
        rules = load_rules_from_dir(ANDROID_RULES)
        before = json.dumps([r["details"] for r in rules], sort_keys=True)
        path = os.path.join(d, "A.java")
        with open(path, "w", encoding="utf-8") as f:
            f.write('class A { String secretKey = "Dinesh@123$abc"; }\n')
        run_rules_on_file(path, rules)
        assert json.dumps([r["details"] for r in rules], sort_keys=True) == before


@pytest.mark.skipif(not HAS_SEMGREP, reason="semgrep not installed")
def test_semgrep_credential_rule_regraded_by_value():
    code = (
        "package com.example.app;\n"
        "class Cfg {\n"
        '  static final String KEY_ACCESS_TOKEN = "access_token";\n'
        '  static final String TAG_ASK_MAIN_CREDENTIAL = "TAG_ASK_MAIN_CREDENTIAL";\n'
        '  static final String ADMIN_PASSWORD = "Winter2024!x";\n'
        '  static final String AUTH_TOKEN = "' + "ghp_" + "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ" + '";\n'
        "}\n")
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "sources", "com", "example", "app")
        os.makedirs(src)
        with open(os.path.join(src, "Cfg.java"), "w", encoding="utf-8") as f:
            f.write(code)
        out = semgrep_engine.run_semgrep(d, own_roots={"com.example.app"}, timeout=300)
    cred = {f["line"]: f for f in out if f["rule_id"] == "android-hardcoded-credential-java"}
    assert 3 not in cred and 4 not in cred
    assert cred[5]["severity"] == "MEDIUM"
    assert cred[6]["severity"] == "CRITICAL"


def test_ios_binary_credential_string_regraded():
    from narvy.ios import binary_analyzer as ba
    findings = []
    ba._check_sensitive_strings(["password=hunter2hunter2x"], "App", findings)
    assert findings and findings[0]["severity"] == "MEDIUM"
    findings = []
    ba._check_sensitive_strings(["api_key=AKIA" "IOSFODNN7EXAMPLQ"], "App", findings)
    assert findings and findings[0]["severity"] == "HIGH"


# --- 3. rules executed vs rules matched ----------------------------------

def test_rules_sentence_separates_executed_from_matched():
    findings = [{"rule_id": "AND-CONF-001"}, {"rule_id": "AND-CONF-001"},
                {"rule_id": "android-webview-js-enabled"}, {"rule_id": "SCA-CVE-2020-7598"}]
    meta = {"rules_run": {"pattern": 28, "taint": 2, "structural": 18}}
    text = narvy_main._rules_sentence("the decompiled app", findings, meta)
    assert "with 48 local rules (28 pattern, 2 taint, 18 structural)" in text
    assert "2 of them produced findings" in text
    assert "matched 1 known advisory" in text
    stats = narvy_main._rule_stats(findings, meta)
    assert stats == {"executed": 48, "by_engine": meta["rules_run"], "matched": 2, "sca_matched": 1}


def test_structural_rules_not_counted_when_the_pass_did_not_run():
    text = narvy_main._rules_sentence("the decompiled app", [], {"rules_run": {"pattern": 28, "taint": 2}})
    assert "with 30 local rules" in text and "structural" not in text


# --- 4. grouped summary table --------------------------------------------

def test_group_findings_by_rule_and_file():
    fs = ([{"severity": "HIGH", "rule_id": "R1", "name": "n1", "file_path": "a", "line": i}
           for i in (5, 1, 9, 1)]
          + [{"severity": "HIGH", "rule_id": "R1", "name": "n1", "file_path": "b", "line": 3},
             {"severity": "CRITICAL", "rule_id": "R2", "name": "n2", "file_path": "a", "line": 7}])
    groups = narvy_main._group_findings(fs)
    assert [(g["finding"]["rule_id"], g["finding"]["file_path"], g["count"]) for g in groups] == [
        ("R2", "a", 1), ("R1", "a", 4), ("R1", "b", 1)]
    assert narvy_main._lines_cell(groups[1]["lines"]) == "1, 5, 9"
    assert narvy_main._lines_cell(list(range(1, 8))) == "1, 2, 3, 4 (+3)"


def test_no_group_flag_is_accepted():
    import subprocess
    root = os.path.join(os.path.dirname(__file__), "..")
    p = subprocess.run([sys.executable, "-m", "narvy", "scan", "--help"], cwd=root,
                       capture_output=True, text=True, env=dict(os.environ, NARVY_TELEMETRY="0"))
    assert p.returncode == 0 and "--no-group" in p.stdout
