"""1.1.1: own reports never rescanned, upload host shown, Flask cookie rules, unreadable files."""
import json
import os
import re
import subprocess
import sys

import pytest

from narvy import main as cli_main
from narvy import own_reports, semgrep_engine, uploader
from narvy.web import ssrf_guard


def _write(root, rel, text="x"):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def _run_cli(*argv, env_extra=None):
    env = dict(os.environ, NARVY_TELEMETRY="0", **(env_extra or {}))
    return subprocess.run([sys.executable, "-c", "from narvy.main import cli; cli()", *argv],
                          capture_output=True, text=True, env=env, timeout=600)


def _text(r):
    """stdout+stderr without colour codes, on one line."""
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr).split())


@pytest.fixture(autouse=True)
def _fresh_own_reports():
    own_reports._cache.clear()
    own_reports.SKIPPED.clear()
    own_reports.set_output_path(None)
    yield
    own_reports.set_output_path(None)


# ------------------------------------------------------------ own reports

def test_narvy_sarif_and_json_are_recognized_by_content(tmp_path):
    sarif = _write(str(tmp_path), "renamed.txt", json.dumps(
        {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Narvy CLI"}}, "results": []}]}))
    web = _write(str(tmp_path), "w.json", json.dumps({"tool": "Narvy Web Scanner CLI", "findings": []}))
    scan = _write(str(tmp_path), "s.json", json.dumps({"tool": "Narvy CLI", "findings": []}))
    assert own_reports.is_own_report(sarif)
    assert own_reports.is_own_report(web)
    assert own_reports.is_own_report(scan)


def test_other_json_and_sarif_are_still_scanned(tmp_path):
    other = _write(str(tmp_path), "semgrep.sarif", json.dumps(
        {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}}}]}))
    mixed = _write(str(tmp_path), "mixed.sarif", json.dumps(
        {"runs": [{"tool": {"driver": {"name": "Narvy CLI"}}}, {"tool": {"driver": {"name": "x"}}}]}))
    pkg = _write(str(tmp_path), "package.json", '{"name": "Narvy"}')
    broken = _write(str(tmp_path), "narvy.sarif", '{"runs": [{"tool": {"driver": {"name": "Narvy')
    odd = _write(str(tmp_path), "odd.sarif", '{"runs": [{"tool": "Narvy CLI"}, 3, null]}')
    for p in (other, mixed, pkg, broken, odd):
        assert not own_reports.is_own_report(p), p


def test_output_target_is_excluded_whatever_it_holds(tmp_path):
    target = _write(str(tmp_path), "out.txt", "npm_authToken = 'abc'")
    assert not own_reports.is_own_report(target)
    own_reports._cache.clear()
    own_reports.set_output_path(target)
    assert own_reports.is_own_report(target)


def test_drop_own_reports_keeps_project_findings(tmp_path):
    root = str(tmp_path)
    _write(root, "narvy.sarif", json.dumps({"runs": [{"tool": {"driver": {"name": "Narvy CLI"}}}]}))
    _write(root, "src/app.js", "x")
    kept = own_reports.drop_own_reports(
        [{"file_path": "narvy.sarif"}, {"file_path": "src/app.js"}, {"file_path": ""}], root)
    assert [f["file_path"] for f in kept] == ["src/app.js", ""]
    assert own_reports.SKIPPED == {"narvy.sarif"}


@pytest.mark.skipif(not semgrep_engine.is_available(), reason="semgrep not installed")
@pytest.mark.parametrize("fmt,name", [("sarif", "narvy.sarif"), ("json", "report.json")])
def test_second_run_does_not_scan_the_first_report(tmp_path, fmt, name):
    root = str(tmp_path)
    _write(root, "package.json", '{"name": "demo", "dependencies": {}}')
    _write(root, "index.js", "const x = require('child_process');\nx.exec(process.argv[2]);\n")
    first = _run_cli("scan", root, "--output", fmt, "--file", os.path.join(root, name))
    assert first.returncode == 0, first.stderr[-2000:]
    report_one = json.load(open(os.path.join(root, name)))
    # Rule text quoted in a report looks like a secret; a copy elsewhere is found by content.
    report_one["note"] = "//registry.npmjs.org/:_authToken=" + "ab12" * 6
    _write(root, "old/" + name, json.dumps(report_one, indent=2))
    second = _run_cli("scan", root, "--output", fmt, "--file", os.path.join(root, name))
    assert second.returncode == 0, second.stderr[-2000:]
    data = json.load(open(os.path.join(root, name)))
    if fmt == "sarif":
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in data["runs"][0]["results"]]
    else:
        uris = [f["file_path"] for f in data["findings"]]
    assert not any(u.endswith(name) for u in uris), uris
    assert re.search(r"Ignored Narvy report file\(s\) from an earlier run: (\S+, )*old/" + re.escape(name),
                     _text(second)), _text(second)[-600:]


# ------------------------------------------------------------ upload host

def test_upload_line_names_the_server_when_token_comes_from_env(monkeypatch):
    monkeypatch.setattr(uploader, "API_BASE", "https://narvy.io")
    assert cli_main._server_and_account({"token": "t", "email": "", "plan": ""}) == "narvy.io"
    assert cli_main._server_and_account({"email": "a@b.c", "plan": "starter"}) == "narvy.io (a@b.c, starter)"
    monkeypatch.setattr(uploader, "API_BASE", "http://127.0.0.1:9")
    assert cli_main._server_and_account({}) == "127.0.0.1:9"
    assert "127.0.0.1:9" in cli_main._upload_failed_label(401)


def test_upload_failure_prints_the_host(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", '{"name": "demo"}')
    _write(root, "index.js", "console.log(1)\n")
    r = _run_cli("scan", root, "--upload",
                 env_extra={"NARVY_TOKEN": "bogus", "NARVY_URL": "http://127.0.0.1:9"})
    assert r.returncode == cli_main.EXIT_ERROR
    assert "to 127.0.0.1:9 for server-side curation" in _text(r)
    assert "Upload to 127.0.0.1:9 failed" in _text(r)


# ------------------------------------------------------------ flask cookie rules

@pytest.mark.skipif(not semgrep_engine.is_available(), reason="semgrep not installed")
def test_flask_cookie_rules_fire_only_in_flask_code(tmp_path):
    rules = os.path.join(os.path.dirname(cli_main.__file__), "rules", "web", "python.yml")
    _write(str(tmp_path), "app.py",
           "from flask import Flask, make_response\n"
           "app = Flask(__name__)\n"
           "def a():\n    r = make_response('x')\n    r.set_cookie('sid', 'v')\n    return r\n"
           "def b():\n    r = make_response('x')\n    r.set_cookie('sid', 'v', httponly=True, secure=True)\n"
           "    return r\n")
    _write(str(tmp_path), "other.py", "def c(r):\n    r.set_cookie('sid', 'v')\n")
    out = subprocess.run([semgrep_engine.semgrep_bin(), "--config", rules, "--json", "--quiet",
                          "--metrics=off", str(tmp_path)],
                         capture_output=True, text=True, timeout=300)
    hits = {(r["check_id"].rsplit(".", 1)[-1], os.path.basename(r["path"]), r["start"]["line"])
            for r in json.loads(out.stdout)["results"] if "set-cookie" in r["check_id"]}
    assert hits == {("flask-set-cookie-missing-httponly", "app.py", 5),
                    ("flask-set-cookie-missing-secure", "app.py", 5)}


# ------------------------------------------------------------ unreadable files

@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads everything")
def test_unreadable_files_are_counted_not_silently_skipped(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", '{"name": "demo"}')
    _write(root, "index.js", "console.log(1)\n")
    locked = _write(root, "src/key.js", "const k = 'x';\n")
    _write(root, "node_modules/m/locked.js", "x")
    os.chmod(locked, 0)
    os.chmod(os.path.join(root, "node_modules/m/locked.js"), 0)
    try:
        assert cli_main._unreadable_paths(root) == [os.path.join("src", "key.js")]
        r = _run_cli("scan", root, "--format", "json", "--file", "-", "-v")
        assert r.returncode == 0, r.stderr[-2000:]
        assert json.loads(r.stdout)["summary"]["unreadable_paths"] == ["src/key.js"]
        assert "could not be read" in _text(r) and "- src/key.js" in _text(r)
    finally:
        os.chmod(locked, 0o644)
        os.chmod(os.path.join(root, "node_modules/m/locked.js"), 0o644)


# ------------------------------------------------------------ web-scan refusal

def test_localhost_refusal_says_what_it_is():
    with pytest.raises(ssrf_guard.SSRFBlocked, match="loopback"):
        ssrf_guard.validate_url("http://localhost:8080/")
    r = _run_cli("web-scan", "http://localhost:8080")
    assert r.returncode == cli_main.EXIT_BAD_TARGET
    assert "publicly reachable" in _text(r)
