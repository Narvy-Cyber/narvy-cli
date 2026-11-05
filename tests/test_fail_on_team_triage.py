"""--fail-on leaves out what the team dismissed in Narvy (1.3.2).

Prod QA: a package.json with only sequelize + mysql2, both marked false
positive on the platform; the ingest answered "0 actionable" and the CLI
still exited 1. With --upload, the gate now reads the ingest response's
``dismissed`` list (index in the submitted findings + status) and leaves
those findings out. Without upload, or when the server does not send the
field (older server), the gate stays local. A failed upload still exits 4.
"""
import argparse
import io

import pytest
from rich.console import Console

from narvy import main as cli_main
from narvy import repo_identity


def _f(rule, sev="HIGH", **extra):
    return {"rule_id": rule, "name": rule, "severity": sev, "file_path": "package.json",
            "line": 1, "details": {"description": "d"}, **extra}


@pytest.fixture
def env(monkeypatch, tmp_path):
    buf = io.StringIO()
    monkeypatch.setattr(cli_main, "console", Console(file=buf, width=240, no_color=True, highlight=False))
    monkeypatch.setattr(cli_main, "_detect_scan_mode", lambda p: "web-source")
    monkeypatch.setattr(cli_main, "load_scope_config", lambda p: None)
    monkeypatch.setattr(cli_main.semgrep_engine, "is_available", lambda: True)
    monkeypatch.setattr(cli_main.semgrep_engine, "degraded_coverage_note", lambda: None)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    target = tmp_path / "shop"
    target.mkdir()
    state = {"findings": [], "responses": [], "sent": []}

    monkeypatch.setattr(cli_main, "_run_web_source_scan",
                        lambda *a, **k: (state["findings"], [], {}))
    monkeypatch.setattr(cli_main, "_nested_ios_project_roots", lambda p: [])

    def fake_ingest(token, **kw):
        state["sent"].append(kw["findings"])
        return state["responses"].pop(0) if state["responses"] else (201, {"scan_id": "s"})
    monkeypatch.setattr(cli_main.uploader, "ingest_results", fake_ingest)

    def run(upload=True, fail_on="high"):
        args = argparse.Namespace(apk_path=str(target), max_mem="4g", force=False, upload=upload,
                                  upload_binary=False, app=None, output="console", file=None,
                                  fail_on=fail_on)
        try:
            cli_main.cmd_scan(args)
            return 0
        except SystemExit as e:
            return e.code
    state["run"] = run
    state["out"] = buf
    return state


def test_dismissed_findings_do_not_fail_the_build(env):
    env["findings"] = [_f("SCA-CVE-1"), _f("SCA-CVE-2")]
    env["responses"] = [(201, {"scan_id": "s", "actionable": 0, "dismissed": [
        {"index": 0, "status": "false_positive"}, {"index": 1, "status": "accepted_risk"}]})]
    assert env["run"]() == 0
    out = " ".join(env["out"].getvalue().split())
    assert "2 finding(s) excluded because your team dismissed them in Narvy" in out
    assert len(env["sent"][0]) == 2  # the upload itself sends everything


def test_one_dismissed_one_open_still_fails(env):
    env["findings"] = [_f("SCA-CVE-1"), _f("SCA-CVE-2")]
    env["responses"] = [(201, {"scan_id": "s", "dismissed": [{"index": 1, "status": "wont_fix"}]})]
    assert env["run"]() == cli_main.EXIT_FAIL_ON
    assert "1 finding(s) excluded" in " ".join(env["out"].getvalue().split())


def test_without_upload_the_gate_is_local(env):
    env["findings"] = [_f("SCA-CVE-1")]
    assert env["run"](upload=False) == cli_main.EXIT_FAIL_ON
    assert "excluded" not in env["out"].getvalue()


def test_older_server_without_the_field_keeps_the_local_gate(env):
    env["findings"] = [_f("SCA-CVE-1")]
    env["responses"] = [(201, {"scan_id": "s", "actionable": 0})]
    assert env["run"]() == cli_main.EXIT_FAIL_ON
    assert "excluded" not in env["out"].getvalue()


def test_empty_dismissed_list_changes_nothing(env):
    env["findings"] = [_f("SCA-CVE-1")]
    env["responses"] = [(201, {"scan_id": "s", "dismissed": []})]
    assert env["run"]() == cli_main.EXIT_FAIL_ON
    assert "excluded" not in env["out"].getvalue()


def test_failed_upload_exits_4_before_the_gate(env):
    env["findings"] = [_f("SCA-CVE-1")]
    env["responses"] = [(500, {"error": "boom"})]
    assert env["run"]() == cli_main.EXIT_ERROR


def test_no_line_without_fail_on(env):
    env["findings"] = [_f("SCA-CVE-1")]
    env["responses"] = [(201, {"scan_id": "s", "dismissed": [{"index": 0, "status": "false_positive"}]})]
    assert env["run"](fail_on=None) == 0
    assert "excluded" not in env["out"].getvalue()


@pytest.mark.parametrize("entry", [
    {"index": 5, "status": "false_positive"},      # out of range
    {"index": -1, "status": "false_positive"},
    {"index": "0", "status": "false_positive"},    # not an int
    {"index": True, "status": "false_positive"},
    {"index": 0, "status": "open"},                # not a dismissal
    {"index": 0},
    "0",
])
def test_unusable_entries_are_ignored(env, entry):
    env["findings"] = [_f("SCA-CVE-1")]
    env["responses"] = [(201, {"scan_id": "s", "dismissed": [entry]})]
    assert env["run"]() == cli_main.EXIT_FAIL_ON


def test_index_maps_to_the_finding_that_was_sent(env):
    # A low finding first: index 1 is the high one, dismissed -> passes.
    env["findings"] = [_f("R-LOW", sev="LOW"), _f("R-HIGH")]
    env["responses"] = [(201, {"scan_id": "s", "dismissed": [{"index": 1, "status": "false_positive"}]})]
    assert env["run"]() == 0


# ------------------------------------------------------- nested iOS surface

def test_nested_surface_indices_map_to_their_own_upload(monkeypatch):
    monkeypatch.setattr(cli_main, "console", Console(file=io.StringIO()))
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    web = _f("WEB-1")
    ios_a = _f("IOS-1", _surface_root="App", file_path="App/A.swift")
    ios_b = _f("IOS-2", _surface_root="App", file_path="App/B.swift")
    responses = [(201, {"scan_id": "s1", "dismissed": []}),
                 (201, {"scan_id": "s2", "dismissed": [{"index": 1, "status": "false_positive"}]})]
    monkeypatch.setattr(cli_main.uploader, "ingest_results", lambda token, **kw: responses.pop(0))
    meta = {"surfaces": [{"mode": "web-source", "path": "."}, {"mode": "ios-source", "path": "App"}]}
    got = cli_main._submit_results_by_surface([web, ios_a, ios_b], "web-source", "/x/repo", meta)
    assert got == [ios_b] and got[0] is ios_b


def test_one_surface_without_the_field_means_local_gate(monkeypatch):
    monkeypatch.setattr(cli_main, "console", Console(file=io.StringIO()))
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    responses = [(201, {"scan_id": "s1", "dismissed": [{"index": 0, "status": "false_positive"}]}),
                 (201, {"scan_id": "s2"})]
    monkeypatch.setattr(cli_main.uploader, "ingest_results", lambda token, **kw: responses.pop(0))
    meta = {"surfaces": [{"mode": "web-source", "path": "."}, {"mode": "ios-source", "path": "App"}]}
    got = cli_main._submit_results_by_surface(
        [_f("WEB-1"), _f("IOS-1", _surface_root="App")], "web-source", "/x/repo", meta)
    assert got is None
