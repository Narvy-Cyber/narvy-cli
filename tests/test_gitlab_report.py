"""--output gitlab: GitLab SAST report (artifacts:reports:sast).

GitLab's merge request security widget and pipeline Security tab read a
report declared under artifacts:reports:sast that validates against GitLab's
security report schema; a SARIF kept as a plain artifact is never read. The
output is validated against the OFFICIAL schema files (security-report-schemas,
dist/sast-report-format.json, tags v15.2.1 and v15.2.4, copied unmodified under
tests/fixtures/gitlab_security_report_schemas/).
"""

import argparse
import io
import json
import os
import sys
import zipfile

import pytest
import yaml
from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy import main as cli_main  # noqa: E402
from narvy.gitlab_report import SCHEMA_VERSION, gitlab_sast_from_cli_sarif  # noqa: E402
from narvy.reporter import generate_sarif_report  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(HERE, "fixtures", "gitlab_security_report_schemas")


def _validate(report):
    jsonschema = pytest.importorskip("jsonschema")
    names = sorted(n for n in os.listdir(SCHEMA_DIR) if n.startswith("sast-report-format-"))
    assert names, "official schema fixtures missing"
    for n in names:
        schema = json.load(open(os.path.join(SCHEMA_DIR, n)))
        jsonschema.Draft7Validator(schema).validate(report)


def _finding(rule_id, severity, file_path="sources/com/example/A.java", line=12, cwe="CWE-327"):
    return {
        "rule_id": rule_id, "name": rule_id, "file_path": file_path, "line": line,
        "severity": severity, "confidence": "HIGH",
        "details": {"description": f"{rule_id} description", "recommendation": "fix it",
                    "cwe": cwe, "masvs": "MASVS-CRYPTO-1"},
    }


def _rule(rule_id, severity, cwe="CWE-327"):
    return {
        "id": rule_id, "name": rule_id, "severity": severity, "confidence": "HIGH",
        "masvs": "MASVS-CRYPTO-1",
        "details": {"description": f"{rule_id} description", "recommendation": "fix it",
                    "cwe": cwe, "masvs": "MASVS-CRYPTO-1"},
    }


def _sarif(encrypted=False):
    findings = [_finding("R-CRIT", "CRITICAL"), _finding("R-HIGH", "HIGH", line=3, cwe="CWE-312"),
                _finding("R-MED", "MEDIUM"), _finding("R-LOW", "LOW"), _finding("R-INFO", "INFO")]
    rules = [_rule("R-CRIT", "CRITICAL"), _rule("R-HIGH", "HIGH", cwe="CWE-312"),
             _rule("R-MED", "MEDIUM"), _rule("R-LOW", "LOW"), _rule("R-INFO", "INFO")]
    return generate_sarif_report(findings, rules, encrypted=encrypted,
                                 encrypted_artifact_uri="App.ipa" if encrypted else None)


def test_report_validates_and_maps_every_finding():
    report = gitlab_sast_from_cli_sarif(_sarif(), version="1.2.2", started=1760000000.0,
                                        ended=1760000060.0, default_file="app.apk")
    _validate(report)
    assert report["version"] == SCHEMA_VERSION
    assert report["scan"]["type"] == "sast"
    assert report["scan"]["analyzer"]["version"] == "1.2.2"
    sev = {v["identifiers"][0]["value"]: v["severity"] for v in report["vulnerabilities"]}
    assert sev == {"R-CRIT": "Critical", "R-HIGH": "High", "R-MED": "Medium",
                   "R-LOW": "Low", "R-INFO": "Info"}
    high = [v for v in report["vulnerabilities"] if v["identifiers"][0]["value"] == "R-HIGH"][0]
    assert high["location"] == {"file": "sources/com/example/A.java", "start_line": 3, "end_line": 3}
    assert any(i["type"] == "cwe" and i["value"] == "312" for i in high["identifiers"])


def test_vulnerability_name_is_the_rule_title_not_its_description():
    rule = _rule("AND-CONF-001", "HIGH")
    rule["name"] = "Application is Debuggable"
    sarif = generate_sarif_report([_finding("AND-CONF-001", "HIGH")], [rule])
    report = gitlab_sast_from_cli_sarif(sarif, version="1.2.2", started=1760000000.0,
                                        ended=1760000001.0)
    _validate(report)
    assert report["vulnerabilities"][0]["name"] == "Application is Debuggable"


def test_fairplay_coverage_note_is_a_scan_message_not_a_vulnerability():
    report = gitlab_sast_from_cli_sarif(_sarif(encrypted=True), version="1.2.2",
                                        started=1760000000.0, ended=1760000001.0)
    _validate(report)
    assert len(report["vulnerabilities"]) == 5
    assert all(v["identifiers"][0]["value"] != "IOS-FAIRPLAY-ENCRYPTED"
               for v in report["vulnerabilities"])
    assert report["scan"]["messages"][0]["level"] == "warn"
    assert "FairPlay" in report["scan"]["messages"][0]["value"]


def test_empty_scan_is_a_valid_report():
    report = gitlab_sast_from_cli_sarif(generate_sarif_report([], []), version="1.2.2",
                                        started=1760000000.0, ended=1760000000.0)
    _validate(report)
    assert report["vulnerabilities"] == []


def test_cmd_scan_output_gitlab_writes_the_report(monkeypatch, tmp_path):
    """--output gitlab through cmd_scan (engines stubbed): default file name,
    schema-valid, and a finding without a source line attached to the APK."""
    target = tmp_path / "app.apk"
    with zipfile.ZipFile(target, "w") as z:
        z.writestr("stub", "stub")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_main, "console", Console(file=io.StringIO(), width=240, no_color=True))
    monkeypatch.setattr(cli_main, "_detect_scan_mode", lambda p: "android")
    monkeypatch.setattr(cli_main, "load_scope_config", lambda p: None)
    result = ([_finding("R-HIGH", "HIGH")], [_rule("R-HIGH", "HIGH")])
    monkeypatch.setattr(cli_main, "_run_local_scan", lambda *a, **k: result)
    args = argparse.Namespace(apk_path=str(target), max_mem="4g", force=False, upload=False,
                              output="gitlab", file=None, fail_on=None)
    cli_main.cmd_scan(args)
    report = json.load(open(tmp_path / "gl-sast-report.json"))
    _validate(report)
    assert [v["severity"] for v in report["vulnerabilities"]] == ["High"]


def test_output_choice_and_format_as_file_guard():
    parser_src = open(cli_main.__file__, encoding="utf-8").read()
    assert 'choices=["console", "sarif", "json", "gitlab"]' in parser_src
    with pytest.raises(SystemExit):
        cli_main._reject_format_as_file("gitlab")


def test_gitlab_template_declares_reports_sast_and_gates_in_a_second_job():
    path = os.path.join(os.path.dirname(cli_main.__file__), "ci_templates", "gitlab.yml")
    d = yaml.safe_load(open(path, encoding="utf-8"))
    job = d["narvy_sast"]
    assert job["artifacts"]["reports"]["sast"] == "gl-sast-report.json"
    script = " ".join(job["script"])
    assert "--output gitlab --file gl-sast-report.json" in script
    # GitLab ingests a security report only from a job that succeeds: the scan
    # job records the --fail-on exit code instead of failing...
    assert "--fail-on high || echo $? > narvy-exit-code" in script
    # ...and the gate job fails the pipeline with it.
    gate = d["narvy_gate"]
    assert gate["needs"] == [{"job": "narvy_sast", "artifacts": True}]
    assert 'exit "$(cat narvy-exit-code)"' in " ".join(gate["script"])
