"""A lone source file with NO dependency manifest must still be scanned.

Stack detection used to require a manifest OR a >=5-file density floor, so a
single vulnerable app.js/app.py/app.php/main.go with no package.json/etc. was
reported as "nothing to scan" while real vulns sat there. Detection now keys off
source-file EXTENSIONS (manifest is enrichment only). Docs/config/asset-only
trees stay honestly rejected.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.web import source_analyzer as w


def _write(root, rel, content=""):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)


def test_lone_source_file_no_manifest_is_detected():
    cases = {
        "app.js": "javascript",
        "app.py": "python",
        "app.php": "<?php\n",
        "main.go": "go",
        "lib.rb": "ruby",
        "main.rs": "rust",
    }
    lang_of = {"app.js": "javascript", "app.py": "python", "app.php": "php",
               "main.go": "go", "lib.rb": "ruby", "main.rs": "rust"}
    for fname, expected in lang_of.items():
        with tempfile.TemporaryDirectory() as root:
            _write(root, fname, cases[fname] if fname == "app.php" else "x = 1\n")
            ported, _ = w.detect_web_stacks(root)
            assert expected in ported, f"{fname} -> {ported}"


def test_manifest_is_enrichment_not_required():
    # Same lone file, with and without a manifest, both detect the stack.
    with tempfile.TemporaryDirectory() as root:
        _write(root, "app.js", "const x = 1;\n")
        assert "javascript" in w.detect_web_stacks(root)[0]
        _write(root, "package.json", '{"name":"x","dependencies":{"express":"4.0.0"}}')
        assert "javascript" in w.detect_web_stacks(root)[0]


def test_docs_and_config_only_dirs_still_rejected():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "README.md", "# docs\n")
        _write(root, "config.yaml", "a: 1\n")
        _write(root, "notes.txt", "hello\n")
        ported, _ = w.detect_web_stacks(root)
        assert ported == set()
