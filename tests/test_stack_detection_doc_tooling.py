"""Stack detection must not be promoted by Sphinx documentation-build .py files
(conf.py, a custom lexer, the theme) sitting inside a doc tree of a non-Python
project - while a real Python project that merely ships Sphinx docs still counts.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.web import source_analyzer as w

_SPHINX_CONF = "import sphinx\nproject = 'x'\nextensions = ['sphinx.ext.autodoc']\n"


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def test_php_project_with_sphinx_docs_is_not_python():
    with tempfile.TemporaryDirectory() as root:
        # A PHP app with plenty of .php.
        for i in range(6):
            _write(os.path.join(root, "system", f"File{i}.php"), "<?php\n")
        # A Sphinx user-guide tree whose only .py are doc tooling.
        _write(os.path.join(root, "user_guide_src", "source", "conf.py"), _SPHINX_CONF)
        _write(os.path.join(root, "user_guide_src", "cilexer", "setup.py"), "from setuptools import setup\n")
        _write(os.path.join(root, "user_guide_src", "cilexer", "cilexer.py"), "x = 1\n")
        _write(os.path.join(root, "user_guide_src", "themes", "t.py"), "y = 2\n")
        _write(os.path.join(root, "user_guide_src", "extra.py"), "z = 3\n")

        ported, _ = w.detect_web_stacks(root)
        assert "php" in ported
        assert "python" not in ported
        assert os.path.join(root, "user_guide_src") in {p for p in w._sphinx_doc_roots(root)}


def test_real_python_project_with_docs_still_detected():
    with tempfile.TemporaryDirectory() as root:
        # A genuine Python app whose code is NOT under a doc dir.
        for i in range(6):
            _write(os.path.join(root, "app", f"mod{i}.py"), "x = 1\n")
        # Plus a Sphinx docs/ tree.
        _write(os.path.join(root, "docs", "conf.py"), _SPHINX_CONF)

        ported, _ = w.detect_web_stacks(root)
        assert "python" in ported


def test_conf_py_at_root_does_not_blank_out_python():
    with tempfile.TemporaryDirectory() as root:
        for i in range(6):
            _write(os.path.join(root, f"mod{i}.py"), "x = 1\n")
        _write(os.path.join(root, "conf.py"), _SPHINX_CONF)  # not under a doc-named dir
        ported, _ = w.detect_web_stacks(root)
        assert "python" in ported
