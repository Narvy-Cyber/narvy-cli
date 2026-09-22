"""Tests for the FairPlay-encryption disclosure wording, the coverage caveat in
console and SARIF output, and the scope-override tip gate.
"""

import argparse
import io
import json
import os
import sys

import pytest
from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy import main as cli_main  # noqa: E402
from narvy.reporter import generate_sarif_report  # noqa: E402


def _run_cmd_scan(monkeypatch, tmp_path, scan_mode, scan_result, output="console"):
    """Drive cmd_scan() with the analysis engines stubbed out and return
    everything it printed."""
    target = tmp_path / {"android": "app.apk", "android-bundle": "app.apkm",
                         "ios-binary": "App.ipa", "android-source": "src",
                         "ios-source": "iossrc"}[scan_mode]
    if scan_mode in ("android-source", "ios-source"):
        target.mkdir()
    else:
        target.write_bytes(b"stub")

    buf = io.StringIO()
    monkeypatch.setattr(cli_main, "console",
                        Console(file=buf, width=240, force_terminal=False,
                                no_color=True, highlight=False))
    monkeypatch.setattr(cli_main, "_detect_scan_mode", lambda p: scan_mode)
    monkeypatch.setattr(cli_main, "load_scope_config", lambda p: None)
    for fn in ("_run_local_scan", "_run_split_bundle_scan", "_run_ios_binary_scan",
               "_run_android_source_scan", "_run_ios_source_scan"):
        monkeypatch.setattr(cli_main, fn, lambda *a, **k: scan_result)

    args = argparse.Namespace(
        apk_path=str(target), max_mem="4g", force=False, upload=False,
        output=output, file=str(tmp_path / "out.sarif"),
    )
    cli_main.cmd_scan(args)
    return buf.getvalue()


def _finding(rule_id="IOS-BIN-CRYPTO-001", severity="MEDIUM"):
    return {
        "rule_id": rule_id, "name": rule_id, "file_path": "App", "line": 1,
        "severity": severity, "confidence": "MEDIUM",
        "details": {"description": "d", "recommendation": "r",
                    "cwe": "CWE-327", "masvs": "MSTG-CRYPTO-4"},
    }


def _rule(rule_id="IOS-BIN-CRYPTO-001"):
    return {
        "id": rule_id, "name": rule_id, "severity": "MEDIUM", "confidence": "MEDIUM",
        "masvs": "MSTG-CRYPTO-4",
        "details": {"description": "d", "recommendation": "r",
                    "cwe": "CWE-327", "masvs": "MSTG-CRYPTO-4"},
    }


def _disclosure_text():
    """The literal encrypted_message built by analyze_ipa, read from source so
    this test needs no IPA."""
    import re
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "narvy", "ios", "binary_analyzer.py")).read()
    m = re.search(r'result\["encrypted_message"\] = \((.*?)\n\s*\)\n', src, re.S)
    assert m, "encrypted_message assignment not found; did the disclosure move?"
    return " ".join(re.findall(r'"([^"]*)"', m.group(1)))


def test_disclosure_does_not_claim_upload_decrypts():
    """`--upload` must not be sold as a FairPlay bypass. Only device dynamic
    analysis is described as running the app decrypted, never --upload itself."""
    import re
    text = _disclosure_text()
    assert "--upload" in text, "the --upload mention is a real value-add, keep it"
    lowered = text.lower()
    assert not re.search(r"--upload[^.]*decrypt", lowered), (
        f"--upload must not be sold as decrypting FairPlay; got: {text}"
    )
    assert "for a full scan of this app" not in lowered, (
        "'--upload for a full scan' is an overclaim: no scan is full on an "
        "encrypted binary"
    )


def test_disclosure_still_sells_what_upload_actually_adds():
    """--upload does apply more analysis to the cleartext surface, and that
    must not be over-corrected away."""
    text = _disclosure_text().lower()
    assert "masvs" in text and "cleartext" in text, (
        "the value of --upload (more analysis of the cleartext surface, MASVS "
        "mapping, ML triage) should still be stated"
    )


def test_fairplay_decryptor_is_not_referenced_by_this_cli():
    """Nothing in this CLI decrypts FairPlay, and nothing should claim to."""
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "narvy")
    hits = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if not f.endswith(".py"):
                continue
            p = os.path.join(dirpath, f)
            body = open(p, encoding="utf-8", errors="replace").read()
            if "decrypt_ipa" in body or "FairPlayDecryptor" in body:
                hits.append(p)
    assert hits == [], f"CLI must not reference a FairPlay decryptor: {hits}"


def test_encrypted_zero_finding_scan_does_not_print_confident_all_clear(monkeypatch, tmp_path):
    """Encrypted, and the code/string rules find nothing because they cannot
    read the code."""
    out = _run_cmd_scan(monkeypatch, tmp_path, "ios-binary",
                        ([], [_rule()], {"encrypted": True}))
    assert "No issues found based on the current rule set." not in out, (
        "an encrypted binary must never get the confident all-clear line"
    )
    assert "FairPlay-encrypted" in out
    assert "dynamic analysis on the platform" in out


def test_unencrypted_zero_finding_scan_keeps_the_confident_message(monkeypatch, tmp_path):
    """A readable binary with zero findings is legitimately a clean result."""
    out = _run_cmd_scan(monkeypatch, tmp_path, "ios-binary",
                        ([], [_rule()], {"encrypted": False}))
    assert "No issues found based on the current rule set." in out
    assert "clean bill of health" not in out


def test_android_zero_finding_scan_unaffected(monkeypatch, tmp_path):
    """The 2-tuple contract of every non-iOS-binary scan path is untouched by
    the meta-dict addition."""
    out = _run_cmd_scan(monkeypatch, tmp_path, "android", ([], [_rule()]))
    assert "No issues found based on the current rule set." in out


def test_ios_binary_scan_returns_the_encrypted_flag():
    """The flag has to actually leave _run_ios_binary_scan, so a refactor that
    drops the third element fails here."""
    import narvy.main as m
    analyzed = {
        "ok": True, "error": None, "encrypted": True,
        "encrypted_message": "msg", "findings": [], "rule_defs": [_rule()],
        "icdump_used": False, "notes": [],
    }
    orig_analyze = m.ios_binary_analyzer.analyze_ipa
    orig_sca = m.sca_ios_deps.scan_binary
    orig_console = m.console
    try:
        m.ios_binary_analyzer.analyze_ipa = lambda p, override_config=None: analyzed
        m.sca_ios_deps.scan_binary = lambda p: ([], [], {
            "unique_dependencies_checked": 0, "cves_found": 0,
            "vulnerable_dependencies": 0})
        m.console = Console(file=io.StringIO(), width=240, no_color=True)
        result = m._run_ios_binary_scan("/nonexistent/App.ipa")
    finally:
        m.ios_binary_analyzer.analyze_ipa = orig_analyze
        m.sca_ios_deps.scan_binary = orig_sca
        m.console = orig_console
    assert len(result) == 3, "encrypted flag was dropped again"
    assert result[2]["encrypted"] is True


def test_sarif_unencrypted_output_is_unchanged():
    """Nothing is added for a normal scan."""
    report = generate_sarif_report([_finding()], [_rule()])
    run = report["runs"][0]
    assert "invocations" not in run
    assert [r["ruleId"] for r in run["results"]] == ["IOS-BIN-CRYPTO-001"]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["IOS-BIN-CRYPTO-001"]


def test_sarif_encrypted_emits_visible_result_and_notification():
    """Both channels: a `result` (visible as a code-scanning annotation) and an
    invocation-level toolExecutionNotification."""
    report = generate_sarif_report([], [_rule()], encrypted=True,
                                   encrypted_artifact_uri="Sample.ipa")
    run = report["runs"][0]

    notes = [r for r in run["results"] if r["ruleId"] == "IOS-FAIRPLAY-ENCRYPTED"]
    assert len(notes) == 1
    note = notes[0]
    assert note["level"] == "note"
    assert "FairPlay-encrypted" in note["message"]["text"]
    assert "not 'clean'" in note["message"]["text"]
    assert (note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "Sample.ipa")

    # ruleId must resolve against the driver's rule list, or GitHub renders
    # the alert with no name/description.
    assert "IOS-FAIRPLAY-ENCRYPTED" in [r["id"] for r in run["tool"]["driver"]["rules"]]

    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is True
    tn = inv["toolExecutionNotifications"][0]
    assert tn["level"] == "note"
    assert "FairPlay-encrypted" in tn["message"]["text"]


def test_sarif_encrypted_without_artifact_uri_omits_locations():
    """SARIF allows a result with no locations, but not an empty or null
    location object."""
    report = generate_sarif_report([], [_rule()], encrypted=True)
    note = [r for r in report["runs"][0]["results"]
            if r["ruleId"] == "IOS-FAIRPLAY-ENCRYPTED"][0]
    assert "locations" not in note


@pytest.mark.parametrize("encrypted", [False, True])
def test_sarif_validates_against_the_real_sarif_210_schema(encrypted):
    """GitHub's ingester rejects a whole SARIF upload on a schema violation, so
    a botched addition here would take the entire report down."""
    jsonschema = pytest.importorskip("jsonschema")
    # Vendored from OASIS so this is a hard guarantee in CI, not a
    # network-dependent skip.
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "fixtures", "sarif-schema-2.1.0.json")
    schema = json.load(open(schema_path))
    report = generate_sarif_report([_finding()], [_rule()], encrypted=encrypted,
                                   encrypted_artifact_uri="Sample.ipa" if encrypted else None)
    jsonschema.validate(instance=report, schema=schema)


def test_cmd_scan_threads_encrypted_into_sarif(monkeypatch, tmp_path):
    """The encrypted flag and the SARIF caveat wired together through cmd_scan."""
    _run_cmd_scan(monkeypatch, tmp_path, "ios-binary",
                  ([], [_rule()], {"encrypted": True}), output="sarif")
    report = json.load(open(tmp_path / "out.sarif"))
    run = report["runs"][0]
    assert "IOS-FAIRPLAY-ENCRYPTED" in [r["ruleId"] for r in run["results"]]
    assert (run["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"] == "App.ipa")
    assert run["invocations"][0]["toolExecutionNotifications"]


def test_no_dead_docs_url_anywhere_in_the_cli():
    """There is no /docs tree on the site, so no printed URL may point at one."""
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "narvy")
    hits = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if not f.endswith(".py"):
                continue
            p = os.path.join(dirpath, f)
            body = open(p, encoding="utf-8", errors="replace").read()
            for i, line in enumerate(body.splitlines(), 1):
                if "narvy.io/docs" in line and not line.lstrip().startswith("#"):
                    hits.append(f"{p}:{i}")
    assert hits == [], f"dead narvy.io/docs link(s): {hits}"


def test_detect_scan_mode_returns_bare_android_for_a_plain_apk(tmp_path):
    """"android-binary" is a value this function never returns."""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"stub")
    assert cli_main._detect_scan_mode(str(apk)) == "android"
    aab = tmp_path / "app.aab"
    aab.write_bytes(b"stub")
    assert cli_main._detect_scan_mode(str(aab)) == "android"


@pytest.mark.parametrize("scan_mode", ["android", "android-bundle", "android-source",
                                       "ios-binary", "ios-source"])
def test_scope_override_tip_fires_for_every_mobile_scan_mode(monkeypatch, tmp_path, scan_mode):
    """Parametrized over the actual return values of _detect_scan_mode()."""
    out = _run_cmd_scan(monkeypatch, tmp_path, scan_mode, ([_finding()], [_rule()]))
    assert ".narvy-scope.yml" in out, (
        f"scope-override tip did not fire for scan_mode={scan_mode!r}"
    )


def test_scope_override_tip_gate_matches_real_scan_modes():
    """Every string in the gate tuple must be a value _detect_scan_mode() can
    return; a dead string there is invisible at runtime."""
    import re
    src = open(cli_main.__file__, encoding="utf-8").read()
    m = re.search(r"if scan_mode in \(([^)]*)\):\n\s*(?:#[^\n]*\n\s*)*console\.print\(\s*\n?\s*\"\[dim\]Tip: seeing your own code",
                  src)
    if m is None:
        m = re.search(r"if scan_mode in \(([^)]*)\):(?:(?!\n    [a-z]).)*?narvy-scope\.yml",
                      src, re.S)
    assert m, "scope-override tip gate not found; did it move?"
    gated = set(re.findall(r'"([^"]+)"', m.group(1)))
    real = {"android", "android-bundle", "android-source", "ios-binary",
            "ios-source", "web-source"}
    assert gated <= real, f"gate contains string(s) _detect_scan_mode never returns: {gated - real}"
    assert "android" in gated, "the plain-.apk mode must be gated in"
