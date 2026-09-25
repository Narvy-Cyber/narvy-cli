"""`narvy scans` and `narvy upload-all`."""
from __future__ import annotations

import argparse
import io
import json
import os
import sys

import pytest
from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy import main as cli_main  # noqa: E402


def _capture_console(monkeypatch):
    buf = io.StringIO()
    cap = Console(file=buf, width=240, force_terminal=False,
                  no_color=True, highlight=False)
    # console (stderr, status/progress) and out_console (stdout, results tables)
    # are two objects since the stderr/stdout split; capture both into one buffer.
    monkeypatch.setattr(cli_main, "console", cap)
    monkeypatch.setattr(cli_main, "out_console", cap, raising=False)
    return buf


class _FakeResponse:
    def __init__(self, status_code, json_body=None, raise_on_json=False):
        self.status_code = status_code
        self._json_body = json_body
        self._raise_on_json = raise_on_json

    def json(self):
        if self._raise_on_json:
            raise ValueError("no JSON object could be decoded")
        return self._json_body


def test_list_scans_builds_expected_request(monkeypatch):
    """GET /api/v1/scans with the token, paging and status filter."""
    captured = {}

    def fake_get(url, headers=None, params=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["params"] = params
        captured["timeout"] = timeout
        return _FakeResponse(200, {"scans": [], "total": 0})

    monkeypatch.setattr(cli_main.uploader.requests, "get", fake_get)
    status, data = cli_main.uploader.list_scans("tok123", limit=5, status="done")
    assert status == 200
    assert data == {"scans": [], "total": 0}
    assert captured["url"] == f"{cli_main.uploader.API_BASE}/api/v1/scans"
    assert captured["headers"] == {"X-API-Token": "tok123"}
    assert captured["params"] == {"limit": 5, "offset": 0, "status": "done"}


def test_list_scans_non_json_body_does_not_crash(monkeypatch):
    """An HTML error body doesn't crash list_scans()."""
    def fake_get(url, headers=None, params=None, timeout=None):
        return _FakeResponse(404, raise_on_json=True)

    monkeypatch.setattr(cli_main.uploader.requests, "get", fake_get)
    status, data = cli_main.uploader.list_scans("tok123")
    assert status == 404
    assert "error" in data


def _scans_args(limit=20, status=None, fmt="text"):
    return argparse.Namespace(limit=limit, status=status, format=fmt)


def test_cmd_scans_requires_login(monkeypatch):
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: None)
    with pytest.raises(SystemExit) as exc:
        cli_main.cmd_scans(_scans_args())
    assert exc.value.code == cli_main.EXIT_ERROR
    assert "Not logged in" in buf.getvalue()


def test_cmd_scans_reports_404_honestly(monkeypatch):
    """A missing endpoint must not crash and must not claim success."""
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "community"})
    monkeypatch.setattr(cli_main.uploader, "list_scans",
                        lambda token, limit=20, status=None: (404, {"error": "not found"}))
    with pytest.raises(SystemExit) as exc:
        cli_main.cmd_scans(_scans_args())
    assert exc.value.code == cli_main.EXIT_ERROR
    out = buf.getvalue()
    assert "isn't available" in out or "not available" in out
    assert "404" in out


def test_cmd_scans_renders_table_on_success(monkeypatch):
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "pro"})
    scans = [
        {"scan_id": "abcdef12-3456-7890", "app_name": "MyApp", "platform": "android",
         "analysis_type": "sast", "status": "done", "vulnerabilities_found": 7,
         "timestamp": "2020-01-01T10:00:00Z"},
    ]
    monkeypatch.setattr(cli_main.uploader, "list_scans",
                        lambda token, limit=20, status=None: (200, {"scans": scans, "total": 1}))
    cli_main.cmd_scans(_scans_args())
    out = buf.getvalue()
    assert "MyApp" in out
    assert "android" in out
    assert "abcdef12" in out


def test_cmd_scans_empty_list_is_friendly_not_an_error(monkeypatch):
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "community"})
    monkeypatch.setattr(cli_main.uploader, "list_scans",
                        lambda token, limit=20, status=None: (200, {"scans": [], "total": 0}))
    cli_main.cmd_scans(_scans_args())  # must not raise
    assert "No scans found" in buf.getvalue()


def test_cmd_scans_json_format_prints_raw_json(monkeypatch, capsys):
    monkeypatch.setattr(cli_main, "console",
                        Console(file=io.StringIO(), width=240, force_terminal=False, no_color=True))
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "community"})
    scans = [{"scan_id": "x", "app_name": "A", "platform": "ios", "analysis_type": "sast",
              "status": "done", "vulnerabilities_found": 0, "timestamp": "2020-01-01T00:00:00Z"}]
    monkeypatch.setattr(cli_main.uploader, "list_scans",
                        lambda token, limit=20, status=None: (200, {"scans": scans, "total": 1}))
    cli_main.cmd_scans(_scans_args(fmt="json"))
    printed = capsys.readouterr().out
    parsed = json.loads(printed)
    assert parsed == scans


def test_find_upload_targets_recursive_and_skip_dirs(tmp_path):
    (tmp_path / "appA.apk").write_bytes(b"x")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "appB.ipa").write_bytes(b"x")
    (nested / "bundle.apks").write_bytes(b"x")
    skip_dir = tmp_path / "build" / "should_be_skipped"
    skip_dir.mkdir(parents=True)
    (skip_dir / "hidden.apk").write_bytes(b"x")

    targets, apks_skipped = cli_main._find_upload_targets(str(tmp_path), recursive=True)
    names = sorted(os.path.relpath(t, str(tmp_path)) for t in targets)
    assert names == [os.path.join("nested", "appB.ipa"), "appA.apk"] or \
        names == ["appA.apk", os.path.join("nested", "appB.ipa")]
    assert os.path.join("build", "should_be_skipped", "hidden.apk") not in [
        os.path.relpath(t, str(tmp_path)) for t in targets
    ]
    assert apks_skipped == 1


def test_find_upload_targets_non_recursive(tmp_path):
    (tmp_path / "appA.apk").write_bytes(b"x")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "appB.apk").write_bytes(b"x")

    targets, _ = cli_main._find_upload_targets(str(tmp_path), recursive=False)
    assert [os.path.basename(t) for t in targets] == ["appA.apk"]


def _upload_all_args(directory, no_recursive=False):
    return argparse.Namespace(directory=directory, no_recursive=no_recursive,
                              max_mem="4g", force=False)


def test_cmd_upload_all_requires_login_before_scanning_anything(tmp_path, monkeypatch):
    (tmp_path / "app.apk").write_bytes(b"x")
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: None)
    called = []
    monkeypatch.setattr(cli_main, "cmd_scan", lambda args: called.append(args))

    with pytest.raises(SystemExit) as exc:
        cli_main.cmd_upload_all(_upload_all_args(str(tmp_path)))
    assert exc.value.code == cli_main.EXIT_ERROR
    assert "Not logged in" in buf.getvalue()
    assert called == []  # zero scans attempted: fail fast, no wasted work


def test_cmd_upload_all_rejects_non_directory(tmp_path, monkeypatch):
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "community"})
    missing = str(tmp_path / "does-not-exist")
    with pytest.raises(SystemExit):
        cli_main.cmd_upload_all(_upload_all_args(missing))
    assert "is not a directory" in buf.getvalue()


def test_cmd_upload_all_empty_directory_is_not_an_error(tmp_path, monkeypatch):
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "community"})
    cli_main.cmd_upload_all(_upload_all_args(str(tmp_path)))  # must not raise
    assert "No .apk" in buf.getvalue()


def test_cmd_upload_all_one_failure_does_not_abort_the_batch(tmp_path, monkeypatch):
    """One failed upload doesn't stop the batch."""
    (tmp_path / "good.apk").write_bytes(b"x")
    (tmp_path / "bad.apk").write_bytes(b"x")
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "community"})

    calls = []

    def fake_cmd_scan(args):
        calls.append(args.apk_path)
        if os.path.basename(args.apk_path) == "bad.apk":
            raise SystemExit(1)
        # good.apk: cmd_scan returns normally (no exception) on success.

    monkeypatch.setattr(cli_main, "cmd_scan", fake_cmd_scan)

    with pytest.raises(SystemExit) as exc:
        cli_main.cmd_upload_all(_upload_all_args(str(tmp_path)))
    # both targets attempted, in spite of one failing
    assert len(calls) == 2
    # overall exit code is EXIT_ERROR because at least one target failed
    assert exc.value.code == cli_main.EXIT_ERROR
    out = buf.getvalue()
    assert "1 succeeded" in out
    assert "1 failed" in out
    assert "bad.apk" in out


def test_cmd_upload_all_all_succeed_no_system_exit(tmp_path, monkeypatch):
    (tmp_path / "a.apk").write_bytes(b"x")
    (tmp_path / "b.apk").write_bytes(b"x")
    buf = _capture_console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "community"})
    monkeypatch.setattr(cli_main, "cmd_scan", lambda args: None)  # every target succeeds

    cli_main.cmd_upload_all(_upload_all_args(str(tmp_path)))  # must not raise
    assert "2 succeeded" in buf.getvalue()
    assert "0 failed" in buf.getvalue()


def test_cmd_upload_all_passes_through_max_mem_and_force(tmp_path, monkeypatch):
    (tmp_path / "a.apk").write_bytes(b"x")
    monkeypatch.setattr(cli_main, "console",
                        Console(file=io.StringIO(), width=240, force_terminal=False, no_color=True))
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.com", "plan": "community"})
    seen = {}

    def fake_cmd_scan(args):
        seen["max_mem"] = args.max_mem
        seen["force"] = args.force
        seen["upload"] = args.upload

    monkeypatch.setattr(cli_main, "cmd_scan", fake_cmd_scan)
    args = _upload_all_args(str(tmp_path))
    args.max_mem = "8g"
    args.force = True
    cli_main.cmd_upload_all(args)
    assert seen == {"max_mem": "8g", "force": True, "upload": True}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
