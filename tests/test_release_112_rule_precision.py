"""1.1.2: community rule precision fixes synced from the platform rule set."""
import json
import os
import subprocess
import textwrap

import pytest

from narvy.web import source_analyzer as sa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "narvy", "rules", "web")
SEMGREP = os.path.join(ROOT, "venv", "bin", "semgrep")


def _hits(pack, filename, code, tmp_path):
    if not os.path.exists(SEMGREP):
        pytest.skip("semgrep not installed in the CLI venv")
    src = tmp_path / filename
    src.write_text(textwrap.dedent(code))
    p = subprocess.run([SEMGREP, "--metrics=off", "--quiet", "--json", "--config",
                        os.path.join(RULES, pack + ".yml"), str(src)],
                       capture_output=True, text=True, timeout=300)
    out = json.loads(p.stdout)
    return sorted((r["check_id"].rsplit(".", 1)[-1], r["start"]["line"]) for r in out["results"])


def test_php_ssrf_needs_attacker_controlled_start(tmp_path):
    hits = _hits("php", "a.php", """\
        <?php
        $page = file_get_contents($_GET['url']);
        $id = $_GET['id'];
        $src = file_get_contents(APP_ROOT . "modules/{$id}/source/{$_GET['lvl']}.php");
        """, tmp_path)
    assert ("tainted-url-file-get-contents", 2) in hits
    assert ("tainted-url-file-get-contents", 4) not in hits
    assert ("tainted-file-read-path", 4) in hits


def test_php_open_redirect_header_case_insensitive(tmp_path):
    hits = _hits("php", "r.php", """\
        <?php
        header("location: " . $_GET['redirect']);
        """, tmp_path)
    assert [h for h in hits if h[0] == "open-redirect-header-location"] == [("open-redirect-header-location", 2)]


def test_js_cleartext_only_when_url_reaches_network(tmp_path):
    hits = _hits("javascript", "c.js", """\
        fetch("http://cdn.acme.io/data.json");
        text = text.replace('http://htmledit.squarefree.com', x);
        var linkUrl = 'http://...';
        """, tmp_path)
    ct = [h for h in hits if h[0] == "cleartext-http-literal"]
    assert ct == [("cleartext-http-literal", 1)]


def test_view_hint_lowers_informational_rule(tmp_path):
    f = {"severity": "HIGH", "details": {"description": "x"}}
    sa._apply_view_hint(f, {"default_view": "hidden", "hidden_reason": "why"}, "")
    assert f["severity"] == "LOW" and "why" in f["details"]["description"]

    src = tmp_path / "server.go"
    src.write_text("srv.ListenAndServe()\nsrv.ListenAndServeTLS(c, k)\n")
    g = {"severity": "HIGH", "details": {}}
    sa._apply_view_hint(g, {"hidden_if_file_matches": "ListenAndServeTLS",
                            "hidden_if_file_reason": "tls elsewhere"}, str(src))
    assert g["severity"] == "LOW"
    src.write_text("srv.ListenAndServe()\n")
    h = {"severity": "HIGH", "details": {}}
    sa._apply_view_hint(h, {"hidden_if_file_matches": "ListenAndServeTLS"}, str(src))
    assert h["severity"] == "HIGH"
