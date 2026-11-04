"""`narvy scan app.apk|app.ipa --upload` sends the binary's package id.

The server (cli_ingest.ingest_package_id) joins the CLI result to the App a
web upload of the same binary created. Only `package_id` is new in the body,
only for binary scans, and only a dotted id: source scans send nothing new.
"""
import io
import os
import plistlib
import zipfile

import pytest
from rich.console import Console

from narvy import main as cli_main
from narvy import repo_identity, uploader
from narvy.ios import binary_analyzer

_MANIFEST = ('<?xml version="1.0" encoding="utf-8"?>\n'
             '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
             'android:versionCode="7" package="com.acme.shop">\n'
             '<application android:name=".App"/></manifest>\n')


def _quiet(monkeypatch):
    monkeypatch.setattr(cli_main, "console", Console(file=io.StringIO(), width=200, no_color=True))


def _stub_android_engines(monkeypatch, manifest_rel):
    def fake_decompile(apk_path, out_dir, max_mem, force=False, extra_inputs=None, notify=None):
        p = os.path.join(out_dir, manifest_rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(_MANIFEST)
        return True, None
    monkeypatch.setattr(cli_main, "decompile_apk", fake_decompile)
    monkeypatch.setattr(cli_main.semgrep_engine, "is_available", lambda: False)
    monkeypatch.setattr(cli_main.sca_android_deps, "scan",
                        lambda p: ([], [], {"unique_dependencies_checked": 0, "cves_found": 0,
                                            "vulnerable_dependencies": 0}))
    monkeypatch.setattr(cli_main.native_hardening, "scan",
                        lambda p: ([], [], {"arch_analyzed": None, "lief_available": False}))


# ------------------------------------------------------------ extraction

@pytest.mark.parametrize("manifest_rel", [
    "resources/AndroidManifest.xml",                       # .apk
    "resources/base/manifest/AndroidManifest.xml",         # .aab
])
def test_android_scan_meta_carries_the_manifest_package(monkeypatch, tmp_path, manifest_rel):
    _quiet(monkeypatch)
    _stub_android_engines(monkeypatch, manifest_rel)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    _, _, meta = cli_main._run_local_scan(str(apk), "auto")
    assert meta["package_id"] == "com.acme.shop"


def _ipa(path, plist):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/Shop.app/Info.plist", plistlib.dumps(plist))


def test_ipa_bundle_id_read_from_info_plist(tmp_path):
    if not binary_analyzer.LIEF_AVAILABLE:
        pytest.skip("lief not installed")
    ipa = tmp_path / "Shop.ipa"
    # No executable in the archive: analysis stops, the bundle id was already read.
    _ipa(ipa, {"CFBundleIdentifier": "com.acme.shop.ios", "CFBundleExecutable": "Shop"})
    result = binary_analyzer.analyze_ipa(str(ipa))
    assert result["bundle_id"] == "com.acme.shop.ios"


def test_ios_binary_scan_meta_carries_the_bundle_id(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(cli_main.ios_binary_analyzer, "analyze_ipa", lambda p, override_config=None: {
        "ok": True, "error": None, "encrypted": False, "encrypted_message": None,
        "findings": [], "rule_defs": [], "icdump_used": False, "notes": [],
        "bundle_id": "com.acme.shop.ios"})
    monkeypatch.setattr(cli_main.sca_ios_deps, "scan_binary", lambda p: ([], [], {
        "unique_dependencies_checked": 0, "cves_found": 0, "vulnerable_dependencies": 0}))
    _, _, meta = cli_main._run_ios_binary_scan("/nonexistent/Shop.ipa")
    assert meta["package_id"] == "com.acme.shop.ios"


# ------------------------------------------------------------ what is sent

def _capture_ingest(monkeypatch):
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    calls = []

    def fake_ingest(token, **kw):
        calls.append(kw)
        return 201, {"scan_id": "s"}
    monkeypatch.setattr(cli_main.uploader, "ingest_results", fake_ingest)
    return calls


@pytest.mark.parametrize("scan_mode,target,pkg", [
    ("android", "app.apk", "com.acme.shop"),
    ("android-bundle", "app.apkm", "com.acme.shop"),
    ("ios-binary", "Shop.ipa", "com.acme.shop.ios"),
])
def test_binary_upload_sends_package_id(monkeypatch, tmp_path, scan_mode, target, pkg):
    _quiet(monkeypatch)
    calls = _capture_ingest(monkeypatch)
    cli_main._submit_results_by_surface([], scan_mode, str(tmp_path / target), {"package_id": pkg})
    assert calls[-1]["package_id"] == pkg


@pytest.mark.parametrize("scan_mode", ["android-source", "ios-source", "web-source"])
def test_source_upload_sends_no_package_id(monkeypatch, tmp_path, scan_mode):
    _quiet(monkeypatch)
    calls = _capture_ingest(monkeypatch)
    cli_main._submit_results_by_surface([], scan_mode, str(tmp_path), {"package_id": "com.acme.shop"})
    assert calls[-1]["package_id"] is None


@pytest.mark.parametrize("raw", [None, "", "Unknown", "shop", " ", "../etc/passwd", "a b.c", 42,
                                 "x" * 201 + ".y"])
def test_unusable_package_id_is_not_sent(monkeypatch, tmp_path, raw):
    _quiet(monkeypatch)
    calls = _capture_ingest(monkeypatch)
    cli_main._submit_results_by_surface([], "android", str(tmp_path / "app.apk"), {"package_id": raw})
    assert calls[-1]["package_id"] is None


def test_body_adds_only_package_id(monkeypatch):
    seen = []

    class R:
        status_code = 201

        def json(self):
            return {"scan_id": "s"}

    monkeypatch.setattr(uploader.requests, "post",
                        lambda url, headers=None, json=None, timeout=None: seen.append(json) or R())
    uploader.ingest_results("t", "app", "android", "android-binary", [])
    uploader.ingest_results("t", "app", "android", "android-binary", [], package_id="com.acme.shop")
    assert "package_id" not in seen[0]
    assert set(seen[1]) - set(seen[0]) == {"package_id"}
    assert seen[1]["package_id"] == "com.acme.shop"
