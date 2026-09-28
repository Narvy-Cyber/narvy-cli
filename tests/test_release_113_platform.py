"""1.1.3: the APK structural pass never reports a failed run as clean; platform CI harness."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import semgrep_engine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), '..')


def _jadx_tree(d, pkg="com/example/app"):
    src = os.path.join(d, "sources", *pkg.split("/"))
    os.makedirs(src, exist_ok=True)
    with open(os.path.join(src, "Web.java"), "w", encoding="utf-8") as f:
        f.write("package com.example.app;\n"
                "class Web { void f(android.webkit.WebSettings s) { s.setJavaScriptEnabled(true); } }\n")
    return d


def _proc(rc, stdout="", stderr=""):
    return mock.Mock(returncode=rc, stdout=stdout, stderr=stderr)


@pytest.fixture(autouse=True)
def _reset():
    semgrep_engine._record_run('not_run')
    yield
    semgrep_engine._record_run('not_run')


def _run_with(side_effect, d):
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return side_effect(len(calls))
    with mock.patch.object(semgrep_engine, "is_available", return_value=True), \
         mock.patch.object(semgrep_engine, "semgrep_jobs", return_value=4), \
         mock.patch("narvy.semgrep_engine.run_tree", side_effect=fake):
        out = semgrep_engine.run_semgrep(d, own_roots={"com.example.app"})
    return out, calls


def test_fatal_json_error_is_not_a_clean_pass():
    """rc=2 with a JSON body and no results was recorded as 'ok' with 0 findings."""
    body = json.dumps({"results": [], "errors": [{"type": "Fatal error", "message": "core crashed"}]})
    with tempfile.TemporaryDirectory() as d:
        out, calls = _run_with(lambda n: _proc(2, body), _jadx_tree(d))
    assert out == []
    assert semgrep_engine.LAST_RUN["status"] == "error"
    assert "core crashed" in semgrep_engine.LAST_RUN["message"]
    assert semgrep_engine.degraded_coverage_note() is not None
    # retried once with a single worker before giving up
    assert len(calls) == 2
    assert calls[0][calls[0].index("--jobs") + 1] == "4"
    assert calls[1][calls[1].index("--jobs") + 1] == "1"


def test_single_worker_retry_recovers_the_findings():
    ok = json.dumps({"results": [{"check_id": "android-webview-js-enabled",
                                  "path": "x/sources/com/example/app/Web.java",
                                  "start": {"line": 2}, "extra": {"severity": "WARNING"}}],
                     "errors": [], "paths": {"scanned": ["x"]}})
    with tempfile.TemporaryDirectory() as d:
        out, calls = _run_with(lambda n: _proc(3221225477 if n == 1 else 0, "" if n == 1 else ok),
                               _jadx_tree(d))
    assert [f["rule_id"] for f in out] == ["android-webview-js-enabled"]
    assert semgrep_engine.LAST_RUN["status"] == "ok"
    assert len(calls) == 2


def test_include_globs_matching_nothing_is_reported():
    body = json.dumps({"results": [], "errors": [], "paths": {"scanned": []}})
    with tempfile.TemporaryDirectory() as d:
        out, _ = _run_with(lambda n: _proc(0, body), _jadx_tree(d))
    assert out == []
    assert semgrep_engine.LAST_RUN["status"] == "error"
    assert "matched none of the 1 app source files" in semgrep_engine.LAST_RUN["message"]


def test_nothing_to_scan_is_still_a_clean_pass():
    body = json.dumps({"results": [], "errors": [], "paths": {"scanned": []}})
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "resources"))
        out, calls = _run_with(lambda n: _proc(0, body), d)
    assert out == [] and len(calls) == 1
    assert semgrep_engine.LAST_RUN["status"] == "ok"


def test_rule_ids_do_not_depend_on_the_install_path():
    body = json.dumps({"results": [], "errors": []})
    with tempfile.TemporaryDirectory() as d:
        _, calls = _run_with(lambda n: _proc(0, body), _jadx_tree(d))
    assert "--no-rewrite-rule-ids" in calls[0]


@pytest.mark.skipif(shutil.which("semgrep") is None and not semgrep_engine.is_available(),
                    reason="semgrep not installed")
def test_real_semgrep_on_a_jadx_tree_under_a_path_with_spaces():
    with tempfile.TemporaryDirectory(prefix="narvy ci ") as base:
        d = _jadx_tree(os.path.join(base, "out dir"))
        out = semgrep_engine.run_semgrep(d, own_roots={"com.example.app"}, timeout=300)
    assert semgrep_engine.LAST_RUN["status"] == "ok", semgrep_engine.LAST_RUN
    assert "android-webview-js-enabled" in {f["rule_id"] for f in out}
    assert all(f["file_path"].replace("\\", "/").startswith("sources/") for f in out)


def _harness():
    spec = importlib.util.spec_from_file_location(
        "platform_check", os.path.join(ROOT, "tools", "ci", "platform_check.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_harness_takes_the_launcher_dir_off_path(monkeypatch):
    """Runners already have the user Scripts dir on PATH; the harness removes it."""
    h = _harness()
    with tempfile.TemporaryDirectory() as d:
        user_bin = os.path.join(d, "user bin")
        other = os.path.join(d, "other")
        os.makedirs(user_bin)
        os.makedirs(other)
        name = "narvy.exe" if os.name == "nt" else "narvy"
        with open(os.path.join(user_bin, name), "w") as f:
            f.write("")
        monkeypatch.setenv("PATH", os.pathsep.join([other, user_bin]))
        dropped = h.strip_launcher_dirs_from_path()
        assert dropped == [user_bin]
        assert os.environ["PATH"] == other


def test_harness_still_asserts_the_precondition():
    src = open(os.path.join(ROOT, "tools", "ci", "platform_check.py"), encoding="utf-8").read()
    assert 'shutil.which("narvy") is None' in src
    assert "NARVY_CI_ON_PATH" not in src
