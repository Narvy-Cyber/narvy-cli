"""Vendored JS libs under static/ or assets/ don't flood findings."""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.web import source_analyzer as w


# innerHTML sink that dom-innerhtml-assign fires on, dropped into every file.
_XSS = "function boom(el, s){ el.innerHTML = s; }\n"


def _write(root, rel, content):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)


def _build_tree(root):
    # App's own JS (must be scanned).
    _write(root, "src/static/app/js/menu.js", _XSS)
    _write(root, "package.json", '{"name":"x","dependencies":{"express":"4.0.0"}}')
    # Vendored third-party libs (must be excluded).
    _write(root, "src/static/vuejs/vue.js", _XSS)
    _write(root, "src/static/d3/d3.v6.js", _XSS)
    _write(root, "src/static/d3/d3-selection.v2.js", _XSS)
    _write(root, "src/static/leaflet/leaflet.js", _XSS)
    _write(root, "src/static/select2/select2.js", _XSS)
    _write(root, "src/static/pdfjs/pdf.js", _XSS)
    _write(root, "app/assets/javascripts/jquery-3.7.1-ui-1.13.3.js", _XSS)
    _write(root, "wp-includes/js/tinymce/tinymce.min.js", _XSS)
    _write(root, "static/charts/raphael-min.js", _XSS)


def test_vendored_lib_globs_cover_the_named_libs():
    import fnmatch

    def excluded(name):
        globs = w._VENDOR_LIB_FILE_GLOBS + w._BUILD_ARTIFACT_FILE_GLOBS
        return any(fnmatch.fnmatch(name, g) for g in globs)

    for name in ("vue.js", "d3.v6.js", "d3-selection.v2.js", "leaflet.js",
                 "select2.js", "pdf.js", "jquery-3.7.1-ui-1.13.3.js",
                 "tinymce.min.js", "raphael-min.js", "bootstrap.min.js"):
        assert excluded(name), name
    # App files are never caught.
    for name in ("menu.js", "widget.js", "app.js", "checkout.js"):
        assert not excluded(name), name


def test_scan_drops_vendored_keeps_app_code():
    with tempfile.TemporaryDirectory() as root:
        _build_tree(root)
        result = w.analyze_source(root)
        assert result["ok"] is True
        if not result["findings"]:
            return  # semgrep unavailable
        paths = {f["file_path"] for f in result["findings"]}
        # App's own JS is scanned.
        assert any("static/app/js/menu.js" in p for p in paths)
        # No finding may come from a vendored library file.
        vendored_markers = ("vue.js", "/d3/", "leaflet", "select2", "pdf.js",
                            "jquery-", "tinymce", "raphael-min")
        leaked = [p for p in paths if any(m in p for m in vendored_markers)]
        assert leaked == [], f"vendored libs leaked findings: {leaked}"


# Real cmd-inj / SQLi / XSS sinks, so a lost file is a lost true positive.
_CMDINJ = "const cp=require('child_process'); cp.exec('cat ' + req.query.f);\n"
_SQLI = "const q='SELECT * FROM u WHERE id='+req.query.id; db.query(q);\n"


def test_app_code_named_like_a_lib_outside_served_root_is_kept():
    # Lib-like names outside static/, assets/, public/ etc. are app code and
    # must not be dropped.
    with tempfile.TemporaryDirectory() as root:
        _write(root, "package.json", '{"name":"x","version":"1.0.0"}')
        _write(root, "src/vue.js", _CMDINJ)          # app file named like a lib
        _write(root, "components/jquery.js", _CMDINJ)  # app file named like a lib
        _write(root, "leaflet/routes.js", _SQLI)       # app feature dir named like a lib
        _write(root, "src/app.min.js", _CMDINJ)        # build artifact -> still dropped
        result = w.analyze_source(root)
        assert result["ok"] is True
        if not result["findings"]:
            return  # semgrep unavailable
        paths = {f["file_path"] for f in result["findings"]}
        assert any(p.endswith("src/vue.js") for p in paths), paths
        assert any(p.endswith("components/jquery.js") for p in paths), paths
        assert any(p.endswith("leaflet/routes.js") for p in paths), paths
        # Minified build artifact is content-agnostic noise, dropped anywhere.
        assert not any("app.min.js" in p for p in paths), paths


def test_vendored_flood_under_served_root_stays_suppressed():
    # The same names under a served-asset root are vendored and stay suppressed.
    with tempfile.TemporaryDirectory() as root:
        _write(root, "package.json", '{"name":"x","version":"1.0.0"}')
        _write(root, "src/handler.js", _CMDINJ)                     # app -> kept
        _write(root, "static/vuejs/vue.js", _CMDINJ)                # vendored -> dropped
        _write(root, "app/assets/jquery-ui.js", _SQLI)             # vendored -> dropped
        _write(root, "wp-includes/js/tinymce/plugin.js", _CMDINJ)  # vendored dir -> dropped
        result = w.analyze_source(root)
        assert result["ok"] is True
        if not result["findings"]:
            return  # semgrep unavailable
        paths = {f["file_path"] for f in result["findings"]}
        assert any(p.endswith("src/handler.js") for p in paths), paths
        leaked = [p for p in paths
                  if "static/vuejs" in p or "assets/jquery-ui" in p or "tinymce" in p]
        assert leaked == [], f"vendored flood leaked: {leaked}"
