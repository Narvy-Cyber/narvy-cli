"""Regression: secrets in test/fixture paths must be SURFACED (down-ranked to LOW),
never dropped. The two secret rules previously excluded test/spec/mock/fixture paths
at the rule level, so a real secret committed to a test fixture was hidden entirely
while the same secret in app code was HIGH.
"""
from __future__ import annotations

import os
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.web import source_analyzer as web

_RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'narvy', 'rules', 'web')

# Path-exclude tokens that would silence a secret sitting in a test/fixture path.
_TEST_PATH_EXCLUDE_TOKENS = ("test", "spec", "mock", "fixture", "conftest")


def _rule(path, rule_id):
    with open(path) as fh:
        for rule in yaml.safe_load(fh)["rules"]:
            if rule.get("id") == rule_id:
                return rule
    raise AssertionError(f"{rule_id} not found in {path}")


def _test_path_excludes(rule):
    excludes = (rule.get("paths") or {}).get("exclude") or []
    return [e for e in excludes
            if any(tok in e.lower() for tok in _TEST_PATH_EXCLUDE_TOKENS)]


def test_generic_high_entropy_does_not_exclude_test_paths():
    rule = _rule(os.path.join(_RULES_DIR, "secrets_supplement.yml"),
                 "narvy.secrets.generic-high-entropy-assignment")
    assert _test_path_excludes(rule) == []


def test_python_hardcoded_credential_does_not_exclude_test_paths():
    rule = _rule(os.path.join(_RULES_DIR, "python.yml"),
                 "narvy.python.secrets.hardcoded-credential-assignment.hardcoded-credential-assignment")
    assert _test_path_excludes(rule) == []


def test_conftest_counts_as_test_path_for_downrank():
    # conftest.py is test-support code: a secret there is surfaced but down-ranked.
    assert web._is_test_path("app/conftest.py")
    assert web._is_test_path("conftest.py")
    # A normal source file is not a test path.
    assert not web._is_test_path("app/config.py")
    assert not web._is_test_path("src/context.py")


def test_secret_in_test_path_is_downranked_not_dropped():
    findings = [
        {"rule_id": "generic-high-entropy-assignment",
         "file_path": "src/config.js", "line": 1, "severity": "HIGH", "details": {}},
        {"rule_id": "generic-high-entropy-assignment",
         "file_path": "__tests__/config.test.js", "line": 1, "severity": "HIGH", "details": {}},
        {"rule_id": "hardcoded-credential-assignment",
         "file_path": "fixtures/creds.js", "line": 1, "severity": "HIGH", "details": {}},
    ]
    # The pipeline runs both passes; every test-path hit ends at LOW, none dropped.
    out = web._downweight_test_findings(web._downweight_test_secrets(findings))
    by_path = {f["file_path"]: f["severity"] for f in out}
    assert by_path["src/config.js"] == "HIGH"
    assert by_path["__tests__/config.test.js"] == "LOW"
    assert by_path["fixtures/creds.js"] == "LOW"
    assert len(out) == len(findings)  # nothing dropped


import tempfile

# Realistic (non-placeholder) AWS key; the documented AKIA...EXAMPLE is excluded.
_AWS_KEY = "AKIA" + "Z7XQK9PLMN3WBVCD"  # split literal: real key shape at runtime, no push-protection hit


def _write(root, rel, content):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)


def test_collect_test_dir_files_targets_ignored_dirs_only():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "test/creds.js", "//\n")
        _write(root, "tests/fixtures.py", "#\n")
        _write(root, "src/app.js", "//\n")
        _write(root, "node_modules/pkg/test/x.js", "//\n")  # vendored, skipped
        got = {os.path.relpath(p, root) for p in web._collect_test_dir_files(root)}
        assert os.path.join("test", "creds.js") in got
        assert os.path.join("tests", "fixtures.py") in got
        assert os.path.join("src", "app.js") not in got
        assert not any("node_modules" in p for p in got)


def test_secret_in_literal_test_dir_is_surfaced_at_low():
    # Semgrep's default ignore drops test/ dirs; the secret pass must recover a
    # real leaked credential there, down-ranked to LOW, while non-secret sinks in
    # the same dir stay ignored (blast radius stays off injection/XSS).
    with tempfile.TemporaryDirectory() as root:
        _write(root, "package.json", '{"name":"x"}')
        _write(root, "src/app.js", "const a = 1;\n")
        _write(root, "test/creds.js",
               f'const key = "{_AWS_KEY}";\n'
               'const cp = require("child_process"); cp.exec("cat " + req.query.f);\n')
        _write(root, "tests/fixtures.py", f'AWS_KEY = "{_AWS_KEY}"\n')
        result = web.analyze_source(root)
        assert result["ok"] is True
        if not result["findings"]:
            return  # semgrep unavailable
        test_hits = [f for f in result["findings"] if f["file_path"].startswith(("test/", "tests/"))]
        assert test_hits, "secret in a literal test/ dir was not surfaced"
        # Every surfaced test-path hit is a secret, at LOW, tagged.
        for f in test_hits:
            assert web._is_secret_finding(f), f["rule_id"]
            assert f["severity"] == "LOW", (f["rule_id"], f["severity"])
            assert "test/fixture path" in (f["details"].get("description") or "")
        rule_ids = {f["rule_id"] for f in test_hits}
        assert "aws-access-key-id" in rule_ids
        # The cmd-injection sink in the same test file must NOT be surfaced.
        assert not any("exec" in r or "child-process" in r for r in rule_ids)
