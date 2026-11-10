"""Rule precision fixes synced from the platform rule set (November 2026)."""
import json
import os
import subprocess
import textwrap

import pytest

from narvy import semgrep_engine

RULES = os.path.join(os.path.dirname(semgrep_engine.__file__), "rules")

pytestmark = pytest.mark.skipif(not semgrep_engine.is_available(), reason="semgrep not installed")


def _hits(pack, filename, code, tmp_path):
    src = tmp_path / filename
    src.write_text(textwrap.dedent(code))
    p = subprocess.run([semgrep_engine.semgrep_bin(), "--metrics=off", "--quiet", "--json", "--jobs", "1",
                        "--no-git-ignore", "--config", os.path.join(RULES, pack), str(src)],
                       capture_output=True, text=True, timeout=300)
    out = json.loads(p.stdout)
    assert not out["errors"], out["errors"]
    return sorted((r["check_id"].rsplit(".", 1)[-1], r["start"]["line"]) for r in out["results"])


def _lines(hits, rule):
    return [line for r, line in hits if r == rule]


# --- secrets: a PUBKEY name is a public key, not a secret ---------------------

def test_high_entropy_exempts_pubkey_names(tmp_path):
    hits = _hits("web/secrets_supplement.yml", "AppConfig.kt", """\
        object AppConfig {
            const val RELAY_PUBKEY = "5fc48ac4765ff81e9c51014b9d2f2c91621370f4c6b5452a9c06456e4cccaeb1"
            val serverPublicKey = "q9Xv2LmT8sKp4RwZ7nYb3HcJ6dFg1AeU5oIiWxQz"
            val nodePub_Key = "q9Xv2LmT8sKp4RwZ7nYb3HcJ6dFg1AeU5oIiWxQz"
            val SIGNING_SECRET_KEY = "q9Xv2LmT8sKp4RwZ7nYb3HcJ6dFg1AeU5oIiWxQz"
        }
        """, tmp_path)
    assert _lines(hits, "generic-high-entropy-assignment") == [5]
