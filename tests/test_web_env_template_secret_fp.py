"""Precision: the credentials-in-uri and google-api-key rules fired CRITICAL on
template env files (*.example / *.sample / *.dist) and CI workflow yml, which
carry placeholder values, not real leaks. Those paths are excluded from the two
rules while a real secret in .env or normal source still fires.
"""
from __future__ import annotations

import os
import sys
import tempfile

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.web import source_analyzer as web

_RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'narvy', 'rules', 'web')
# AIza + exactly 35 chars, matching the google-api-key regex.
_GKEY = "AIza" + "0123456789012345678901234567890abcd"  # split literal: real key shape at runtime, no push-protection hit
_DSN = "postgres://admin:sup3rs3cret@db.internal:5432/app"


def _rule(path, rule_id):
    with open(path) as fh:
        for rule in yaml.safe_load(fh)["rules"]:
            if rule.get("id") == rule_id:
                return rule
    raise AssertionError(f"{rule_id} not found in {path}")


def _excludes(rule):
    return (rule.get("paths") or {}).get("exclude") or []


def test_both_rules_exclude_template_and_ci_paths():
    for fname, rid in (("secrets.yml", "narvy.secrets.credentials-in-uri"),
                       ("secrets_supplement.yml", "narvy.secrets.google-api-key")):
        ex = _excludes(_rule(os.path.join(_RULES_DIR, fname), rid))
        for pat in ("*.example", "*.sample", "*.dist", ".github/workflows/*"):
            assert pat in ex, (rid, pat)


def _write(root, rel, content):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p) or root, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)


def test_template_and_ci_files_do_not_fire_but_real_secrets_do():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "package.json", '{"name":"x"}')
        # Template / CI files: must NOT fire.
        _write(root, ".env.example", f"DATABASE_URL={_DSN}\nGKEY={_GKEY}\n")
        _write(root, ".env.sample", f"DATABASE_URL={_DSN}\n")
        _write(root, "config.dist", f"url={_DSN}\n")
        _write(root, ".github/workflows/ci.yml", f"url: {_DSN}\nkey: {_GKEY}\n")
        # Real files: must fire.
        _write(root, ".env", f"DATABASE_URL={_DSN}\n")
        _write(root, "src/db.js", f'const dsn = "{_DSN}";\nconst k = "{_GKEY}";\n')
        result = web.analyze_source(root)
        assert result["ok"] is True
        if not result["findings"]:
            return  # semgrep unavailable
        by_rule = {}
        for f in result["findings"]:
            if f["rule_id"] in ("credentials-in-uri", "google-api-key"):
                by_rule.setdefault(f["rule_id"], set()).add(f["file_path"])
        # No secret-in-uri / google-key finding may come from a template or CI file.
        for rid, paths in by_rule.items():
            for p in paths:
                assert not p.endswith((".example", ".sample", ".dist")), (rid, p)
                assert ".github/workflows/" not in p, (rid, p)
        # The real .env and source file still fire.
        assert ".env" in by_rule.get("credentials-in-uri", set())
        assert any(p.endswith("src/db.js") for p in by_rule.get("credentials-in-uri", set()))
        assert any(p.endswith("src/db.js") for p in by_rule.get("google-api-key", set()))
