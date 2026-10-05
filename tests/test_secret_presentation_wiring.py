"""Honest secret wording + masking in every CLI output (parity with the hosted engine).

Fake secrets are built by concatenation so secret scanners never flag this file.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import logging
import os
import sys

import pytest
from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy import main as cli_main  # noqa: E402
from narvy import secret_output  # noqa: E402
from narvy import secret_presentation as sp  # noqa: E402
from narvy.reporter import generate_sarif_report  # noqa: E402

AWS_ID = "AKIA" + "Z7QJ4XKW2LMN5RTB"
STRIPE_SK = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dcXyZ"
AIZA_CLIENT = "AIza" + "SyD4kX9mQ2vB7nR1tL8pW3cF6hJ0gK5sZ2e"
AIZA_SERVER = "AIza" + "SyB8nM3qR6vT1xW4yZ7aC0dF2gH5jK9lP3m"
PEM_BODY = "MIIEowIBAAKCAQEA7Qz" + "Xp3VbN8kL2mR5tY9wC1dF4gH6jK0lP3sA7eU2iO5qT8xZ"
CFG_PW = "Hunter" + "2Bravo" + "Xq77"
RAWS = [AWS_ID, STRIPE_SK, AIZA_CLIENT, AIZA_SERVER, PEM_BODY, CFG_PW]

SAAS_MAIN = os.path.join(os.environ.get("NARVY_HOSTED_ENGINE_DIR", os.path.join(os.path.expanduser("~"), "titanshield")),
                         "src", "sast_shared", "secret_presentation.py")


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def test_module_is_byte_identical_to_the_hosted_engine_copy():
    saas = SAAS_MAIN if os.path.isfile(SAAS_MAIN) else None
    if saas is None:
        pytest.skip("hosted engine checkout not present on this machine")
    cli = os.path.join(os.path.dirname(sp.__file__), "secret_presentation.py")
    assert _sha(cli) == _sha(saas), f"narvy/secret_presentation.py drifted from {saas}"


# ---------------------------------------------------------------------------
# Fixture: files on disk + findings in the exact shape the CLI engines produce
# ---------------------------------------------------------------------------

def _write_fixture(root):
    files = {
        "server/config.js": ("module.exports = {\n"
                             f"  awsAccessKeyId: '{AWS_ID}',\n"
                             "  region: 'eu-west-3',\n"
                             f"  stripeSecretKey: '{STRIPE_SK}',\n"
                             "};\n"),
        "web/src/firebase.js": ("const firebaseConfig = {\n"
                                f"  apiKey: \"{AIZA_CLIENT}\",\n"
                                "};\n"),
        "backend/settings.py": f"GOOGLE_MAPS_API_KEY = \"{AIZA_SERVER}\"\n",
        "deploy/key.pem": ("-----BEGIN RSA " + "PRIVATE KEY-----\n" + PEM_BODY + "\n"
                           "-----END RSA " + "PRIVATE KEY-----\n"),
        "config.py": f"password = \"{CFG_PW}\"\n",
        "app.py": "import os\n",
    }
    for rel, txt in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt)


# One shared details dict per rule, as rule_engine / semgrep packs share it.
_RULE_DETAILS = {
    "aws-access-key-id": {"description": "AWS Access Key ID detected (AKIA/ASIA 16-char format).",
                          "recommendation": "Rotate the key.", "cwe": "CWE-798", "masvs": ""},
    "stripe-secret-key": {"description": "Stripe live secret key detected (sk_live_...).",
                          "recommendation": "Roll the key.", "cwe": "CWE-798", "masvs": ""},
    "google-api-key": {"description": "Google API Key detected (AIza...).",
                       "recommendation": "Restrict the key.", "cwe": "CWE-798", "masvs": ""},
    "detected-private-key": {"description": "A PEM-encoded private key block was found in source.",
                             "recommendation": "Remove it.", "cwe": "CWE-321", "masvs": ""},
    "hardcoded-credential-assignment": {
        "description": "A variable named like a credential is assigned a plain string.",
        "recommendation": "Use an environment variable.", "cwe": "CWE-798", "masvs": ""},
    "sql-injection": {"description": "User input reaches a SQL query.",
                      "recommendation": "Use parameters.", "cwe": "CWE-89", "masvs": ""},
}


def _f(rule_id, path, line, sev):
    return {"rule_id": rule_id, "file_path": path, "name": _RULE_DETAILS[rule_id]["description"][:120],
            "severity": sev, "line": line, "details": _RULE_DETAILS[rule_id], "engine": "semgrep"}


def _findings():
    return [
        _f("aws-access-key-id", "server/config.js", 2, "CRITICAL"),
        _f("stripe-secret-key", "server/config.js", 4, "CRITICAL"),
        _f("google-api-key", "web/src/firebase.js", 2, "CRITICAL"),
        _f("google-api-key", "backend/settings.py", 1, "CRITICAL"),
        _f("detected-private-key", "deploy/key.pem", 1, "CRITICAL"),
        _f("hardcoded-credential-assignment", "config.py", 1, "HIGH"),
        _f("sql-injection", "app.py", 1, "HIGH"),
    ]


def _assert_no_raw(text):
    leaked = [r[:4] + "..." for r in RAWS if r in text]
    assert not leaked, f"raw secret value(s) in output: {leaked}"


def _by(findings, rule_id, path):
    return next(f for f in findings if f["rule_id"] == rule_id and f["file_path"] == path)


# ---------------------------------------------------------------------------
# present_cli_findings itself
# ---------------------------------------------------------------------------

def test_present_rewords_masks_and_demotes_public_client_key(tmp_path):
    _write_fixture(tmp_path)
    shared_before = copy.deepcopy(_RULE_DETAILS)
    fs = _findings()
    secret_output.present_cli_findings(fs, str(tmp_path))

    aws = _by(fs, "aws-access-key-id", "server/config.js")
    assert aws["name"] == "Potential secret: AWS access key ID (format match, not tested)"
    assert aws["secret_confidence"] == "likely" and aws["secret_tested"] is False
    assert aws["severity"] == "CRITICAL"
    assert "AKIA••••••••5RTB" in aws["details"]["description"]

    stripe = _by(fs, "stripe-secret-key", "server/config.js")
    assert stripe["name"] == "Potential secret: Stripe live secret key (format match, not tested)"

    client = _by(fs, "google-api-key", "web/src/firebase.js")
    assert client["severity"] == "INFO" and client["original_severity"] == "CRITICAL"
    assert client["secret_public_by_design"] is True
    assert client["name"].startswith("Public client key: Google API key")

    server = _by(fs, "google-api-key", "backend/settings.py")
    assert server["severity"] == "CRITICAL" and not server.get("secret_public_by_design")

    pem = _by(fs, "detected-private-key", "deploy/key.pem")
    assert pem["name"] == "Potential secret: private key (format match, not tested)"

    pw = _by(fs, "hardcoded-credential-assignment", "config.py")
    assert pw["name"].endswith("(pattern match, not tested)")
    assert pw["secret_confidence"] == "potential" and pw["severity"] == "HIGH"

    sqli = _by(fs, "sql-injection", "app.py")
    assert "secret_presentation" not in sqli and "description" not in sqli  # untouched
    assert sqli["name"] == "User input reaches a SQL query."

    for f in fs:
        assert "line_content" not in f  # the transient source line never leaves
    _assert_no_raw(json.dumps(fs))
    assert _RULE_DETAILS == shared_before, "shared rule details were mutated"


def test_fingerprint_basis_matches_what_the_server_hashed_before_masking(tmp_path):
    _write_fixture(tmp_path)
    fs = _findings()
    clear = copy.deepcopy(fs)
    secret_output.present_cli_findings(fs, str(tmp_path))
    for before, after in zip(clear, fs):
        if not after.get("secret_presentation"):
            continue
        # cli_ingest.normalize_finding lifts details.description; the CLI ships no snippet.
        server_view = dict(before, description=before["details"]["description"])
        assert after["fingerprint_mask_basis"] == sp.fingerprint_basis_of(server_view)
        assert after["fingerprint_mask_basis"]["sink"] is None


def test_presentation_is_idempotent(tmp_path):
    _write_fixture(tmp_path)
    fs = _findings()
    secret_output.present_cli_findings(fs, str(tmp_path))
    snap = json.dumps(fs, sort_keys=True)
    secret_output.present_cli_findings(fs, str(tmp_path))
    assert json.dumps(fs, sort_keys=True) == snap


def test_android_binary_context_makes_google_key_a_public_client_key(tmp_path):
    """In an APK every string ships to the device: same call as the hosted engine."""
    src = tmp_path / "sources" / "com" / "x"
    src.mkdir(parents=True)
    (src / "Config.java").write_text(f'String K = "{AIZA_SERVER}";\n')
    f = _f("google-api-key", str(src / "Config.java"), 1, "CRITICAL")
    secret_output.present_cli_findings([f], str(tmp_path / "app.apk"), "android")
    assert f["severity"] == "INFO" and f["secret_public_by_design"] is True
    _assert_no_raw(json.dumps(f))


def test_name_only_severity_grading_is_kept(tmp_path):
    """secret_value_grade decided HIGH/MEDIUM before; presentation must not change it."""
    _write_fixture(tmp_path)
    f = _f("hardcoded-credential-assignment", "config.py", 1, "MEDIUM")
    f["details"] = dict(f["details"], severity_basis="variable name only")
    secret_output.present_cli_findings([f], str(tmp_path))
    assert f["severity"] == "MEDIUM"
    assert f["details"]["severity_basis"] == "variable name only"


def test_masks_even_when_wording_fails(monkeypatch):
    def boom(_f):
        raise RuntimeError("x")
    monkeypatch.setattr(sp, "present_finding", boom)
    f = {"rule_id": "x", "file_path": "a.js", "line": 1, "name": "n",
         "details": {"description": "token " + STRIPE_SK}}
    secret_output.present_cli_findings([f])
    _assert_no_raw(json.dumps(f))


# ---------------------------------------------------------------------------
# Through cmd_scan: terminal, JSON, SARIF, upload payload
# ---------------------------------------------------------------------------

def _capture_console(monkeypatch):
    buf = io.StringIO()
    cap = Console(file=buf, width=400, force_terminal=False, no_color=True, highlight=False)
    monkeypatch.setattr(cli_main, "console", cap)
    monkeypatch.setattr(cli_main, "out_console", cap, raising=False)
    return buf


def _scan_args(target, output="console", file=None, upload=False):
    return argparse.Namespace(apk_path=str(target), max_mem="4g", force=False, output=output,
                              verbose=False, file=file, upload=upload, upload_binary=False,
                              confirm_upload=False, fail_on=None)


@pytest.fixture
def fake_web_scan(tmp_path, monkeypatch):
    _write_fixture(tmp_path)
    monkeypatch.setattr(cli_main, "_detect_scan_mode", lambda p: "web-source")
    monkeypatch.setattr(cli_main, "_run_web_source_scan",
                        lambda p: (_findings(), [], {}))
    monkeypatch.setattr(cli_main, "_nested_ios_project_roots", lambda p: [])
    monkeypatch.setattr(cli_main, "_uncovered_surface_notes", lambda *a, **k: [])
    monkeypatch.setattr(cli_main.web_source_analyzer, "detect_premium_frameworks", lambda p: {})
    return tmp_path


def test_terminal_output_is_honest_and_masked(fake_web_scan, monkeypatch):
    buf = _capture_console(monkeypatch)
    cli_main.cmd_scan(_scan_args(fake_web_scan))
    out = buf.getvalue()
    _assert_no_raw(out)
    assert "Potential secret: Stripe live secret key (format match, not tested)" in out
    assert "Public client key: Google API key (not a secret, check its restrictions)" in out
    assert "AKIA••••••••5RTB" in out
    assert "Narvy did not test this value" in out
    assert "anyone who can read the source code can read it too" in out  # web-source context


def test_json_report_is_masked_and_carries_secret_fields(fake_web_scan, monkeypatch, tmp_path):
    _capture_console(monkeypatch)
    out = tmp_path / "r.json"
    cli_main.cmd_scan(_scan_args(fake_web_scan, output="json", file=str(out)))
    text = out.read_text()
    _assert_no_raw(text)
    data = json.loads(text)
    fs = data["findings"]
    aws = _by(fs, "aws-access-key-id", "server/config.js")
    assert aws["secret_confidence"] == "likely" and aws["secret_tested"] is False
    assert aws["title_fr"].startswith("Secret potentiel")
    client = _by(fs, "google-api-key", "web/src/firebase.js")
    assert client["severity"] == "INFO" and client["secret_public_by_design"] is True
    assert data["summary"]["by_severity"].get("INFO") == 1
    assert "secret_sha256" not in text and "fingerprint_mask_basis" not in text


def test_sarif_report_message_is_the_honest_title(fake_web_scan, monkeypatch, tmp_path):
    _capture_console(monkeypatch)
    out = tmp_path / "r.sarif"
    cli_main.cmd_scan(_scan_args(fake_web_scan, output="sarif", file=str(out)))
    text = out.read_text()
    _assert_no_raw(text)
    results = json.loads(text)["runs"][0]["results"]
    stripe = next(r for r in results if r["ruleId"] == "stripe-secret-key")
    assert stripe["message"]["text"] == "Potential secret: Stripe live secret key (format match, not tested)"
    assert stripe["properties"]["secret_tested"] is False
    assert stripe["properties"]["secret_confidence"] == "likely"
    client = next(r for r in results if r["ruleId"] == "google-api-key"
                  and r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "web/src/firebase.js")
    assert client["level"] == "note" and client["properties"]["severity"] == "INFO"
    sqli = next(r for r in results if r["ruleId"] == "sql-injection")
    assert sqli["message"]["text"] == "User input reaches a SQL query."
    assert "secret_tested" not in sqli["properties"]


def test_upload_payload_is_masked_and_keeps_fingerprint_basis(fake_web_scan, monkeypatch):
    _capture_console(monkeypatch)
    sent = {}

    def fake_ingest(token, app_name, platform, scan_mode, findings, version=None):
        sent["body"] = json.dumps({"findings": findings})
        return 201, {"scan_id": "s1"}

    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t"})
    monkeypatch.setattr(cli_main.uploader, "ingest_results", fake_ingest)
    cli_main.cmd_scan(_scan_args(fake_web_scan, upload=True))
    body = sent["body"]
    _assert_no_raw(body)
    fs = json.loads(body)["findings"]
    for f in fs:
        if f["rule_id"] != "sql-injection":
            assert f["secret_presentation"] == sp.PRESENTATION_VERSION
            assert f["fingerprint_mask_basis"]["scheme"] == "mask-v1"
    assert _by(fs, "google-api-key", "web/src/firebase.js")["severity"] == "INFO"


def test_sarif_generator_untouched_for_non_secret_findings():
    f = {"rule_id": "r", "file_path": "a", "line": 3, "severity": "HIGH",
         "details": {"description": "d"}}
    res = generate_sarif_report([f], [])["runs"][0]["results"][0]
    assert res["message"]["text"] == "d" and "secret_tested" not in res["properties"]


# ---------------------------------------------------------------------------
# web-scan and logs
# ---------------------------------------------------------------------------

def test_web_scan_findings_masked_and_client_key_public():
    f = {"source": "nuclei", "template_id": "google-api-key-exposure", "title": "Exposed Google API key",
         "description": "", "severity": "high", "url": "https://example.com/app.js",
         "evidence": [AIZA_CLIENT], "response_raw": "var k='" + AIZA_CLIENT + "';"}
    s = {"source": "nuclei", "template_id": "stripe-secret-exposure", "title": "Exposed Stripe secret key",
         "severity": "high", "url": "https://example.com/x.js", "evidence": [STRIPE_SK]}
    secret_output.present_web_findings([f, s])
    _assert_no_raw(json.dumps([f, s]))
    assert f["severity"] == "info" and f["secret_public_by_design"] is True
    assert s["title"] == "Potential secret: Stripe live secret key (format match, not tested)"
    sarif = cli_main._web_to_sarif([f, s])
    assert sarif["runs"][0]["results"][1]["properties"]["secret_tested"] is False


def test_cli_startup_installs_log_masking(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["narvy", "--version"])
    with pytest.raises(SystemExit):
        cli_main.cli(prog="narvy")
    rec = logging.getLogRecordFactory()("t", logging.INFO, __file__, 1,
                                        "key=%s", (STRIPE_SK,), None)
    assert STRIPE_SK not in rec.getMessage()
    assert "sk_l••••••••cXyZ" in rec.getMessage()


def test_raw_tool_output_is_masked(monkeypatch):
    buf = _capture_console(monkeypatch)
    cli_main._print_raw_tool_output("nuclei", "found " + STRIPE_SK)
    _assert_no_raw(buf.getvalue())
