"""Telemetry: what is sent, how to turn it off, and that it never breaks a scan."""
import json
import os
import sys
import uuid

import pytest

from narvy import telemetry, main as cli_main

ALLOWED_KEYS = {
    "schema", "install_id", "cli_version", "python_version", "os", "ci", "command",
    "surface", "duration_bucket", "findings", "exit_code", "error_class",
}


@pytest.fixture
def tel_home(tmp_path, monkeypatch):
    monkeypatch.delenv("NARVY_TELEMETRY", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    for v in telemetry._CI_ENV_VARS:
        monkeypatch.delenv(v, raising=False)
    cfg_dir = tmp_path / ".narvy"
    monkeypatch.setattr(telemetry, "CONFIG_DIR", str(cfg_dir))
    monkeypatch.setattr(telemetry, "CONFIG_PATH", str(cfg_dir / "config.json"))
    telemetry._context.clear()
    sent = []
    monkeypatch.setattr(telemetry, "_post", lambda ev: sent.append(ev))
    return sent


def _findings():
    return [
        {"severity": "CRITICAL", "file_path": "/home/alice/secret-project/app.py",
         "name": "SQL injection in customer_invoices", "rule_id": "x"},
        {"severity": "high", "file_path": "src/billing.php", "name": "XSS"},
        {"severity": "low", "file_path": "a", "name": "b"},
    ]


def test_event_has_only_the_documented_fields_and_no_content(tel_home):
    telemetry.note(surface="source", findings=_findings())
    ev = telemetry.build_event("scan", 42.0, 1)
    assert set(ev) == ALLOWED_KEYS
    assert set(ev["findings"]) == {"critical", "high", "medium", "low", "info"}
    assert ev["findings"]["critical"] == "1-5" and ev["findings"]["medium"] == "0"
    assert ev["duration_bucket"] == "10s-1m"
    assert ev["surface"] == "source" and ev["command"] == "scan" and ev["exit_code"] == 1
    assert uuid.UUID(ev["install_id"]).version == 4
    blob = json.dumps(ev)
    for leaked in ("alice", "secret-project", "app.py", "billing", "customer_invoices",
                   "SQL", os.path.expanduser("~")):
        assert leaked not in blob


def test_install_id_is_random_and_stable(tel_home):
    a = telemetry.install_id()
    assert a == telemetry.install_id()
    assert uuid.UUID(a).version == 4


def test_error_class_is_a_name_only(tel_home):
    ev = telemetry.build_event("scan", 1, 4, ValueError("/home/alice/x.apk is broken"))
    assert ev["error_class"] == "ValueError"
    assert "alice" not in json.dumps(ev)


@pytest.mark.parametrize("var,val", [("NARVY_TELEMETRY", "0"), ("NARVY_TELEMETRY", "off"),
                                     ("DO_NOT_TRACK", "1"), ("DO_NOT_TRACK", "true")])
def test_env_opt_out(tel_home, monkeypatch, var, val):
    monkeypatch.setenv(var, val)
    assert not telemetry.is_enabled()
    telemetry.send("scan", 1, 0)
    telemetry.flush()
    assert tel_home == []


def test_command_off_is_persisted(tel_home):
    assert telemetry.is_enabled()
    assert telemetry.set_enabled(False)
    assert not telemetry.is_enabled()
    with open(telemetry.CONFIG_PATH) as f:
        assert json.load(f)["telemetry"] is False
    telemetry.send("scan", 1, 0)
    assert tel_home == []
    telemetry.set_enabled(True)
    assert telemetry.is_enabled()


def test_ci_is_reported_not_disabled(tel_home, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert telemetry.is_enabled()
    assert telemetry.build_event("scan", 1, 0)["ci"] is True


def test_notice_is_printed_once(tel_home, capsys):
    telemetry.maybe_show_notice()
    telemetry.maybe_show_notice()
    err = capsys.readouterr().err
    assert err.count("anonymous usage statistics") == 1
    assert "narvy telemetry off" in err and "DO_NOT_TRACK=1" in err


def test_no_notice_when_disabled(tel_home, monkeypatch, capsys):
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    telemetry.maybe_show_notice()
    assert capsys.readouterr().err == ""


def test_send_failure_never_raises(tel_home, monkeypatch):
    def boom(ev):
        raise RuntimeError("network down")
    monkeypatch.setattr(telemetry, "_post", boom)
    telemetry.send("scan", 1, 0)
    telemetry.flush()


def test_real_post_swallows_errors_and_uses_short_timeout(monkeypatch):
    import requests
    seen = {}

    def fake_post(url, json=None, timeout=None):
        seen["timeout"] = timeout
        raise requests.exceptions.ConnectionError("nope")
    monkeypatch.setattr(requests, "post", fake_post)
    telemetry._post({"x": 1})
    assert seen["timeout"] <= 1.0


def test_unknown_command_is_not_sent(tel_home):
    assert telemetry.build_event("telemetry", 1, 0) is None


def test_cli_sends_one_event_with_exit_code_for_bad_target(tel_home, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", ["narvy", "scan", str(tmp_path / "missing.apk")])
    with pytest.raises(SystemExit) as exc:
        cli_main.cli()
    telemetry.flush()
    assert exc.value.code == cli_main.EXIT_BAD_TARGET
    assert len(tel_home) == 1
    ev = tel_home[0]
    assert ev["command"] == "scan" and ev["exit_code"] == cli_main.EXIT_BAD_TARGET
    assert "missing.apk" not in json.dumps(ev)


def test_telemetry_command_status_and_off(tel_home, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["narvy", "telemetry", "off"])
    cli_main.cli()
    assert not telemetry.is_enabled()
    monkeypatch.setattr(sys, "argv", ["narvy", "telemetry"])
    cli_main.cli()
    assert "off" in capsys.readouterr().err
    assert tel_home == []  # the telemetry command itself is never reported
