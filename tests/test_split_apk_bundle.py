"""Split-APK bundles (.apkm/.xapk/.apks): detection, extraction, limits and wiring."""

import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy.android import split_bundle  # noqa: E402
from narvy.main import _detect_scan_mode, UnsupportedScanTarget  # noqa: E402


def _apk_bytes(*, dex=0, so=(), arsc=False, manifest=True, extra=()):
    """Minimal APK zip with the member names the checks look for."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if manifest:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64)
        for i in range(dex):
            name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
            zf.writestr(name, b"dex\n035\x00" + b"\x00" * 128)
        for lib in so:
            zf.writestr(lib, b"\x7fELF" + b"\x00" * 256)
        if arsc:
            zf.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 64)
        for name, data in extra:
            zf.writestr(name, data)
    return buf.getvalue()


def _bundle(path, members, metadata=None):
    """Write a bundle ZIP. `members` is a list of (name, bytes)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
        for name, text in (metadata or {}).items():
            zf.writestr(name, text)
    return path


def make_apkm(path):
    """base.apk with dex and no .so, config splits, info.json."""
    return _bundle(
        path,
        [
            ("base.apk", _apk_bytes(dex=3, arsc=True,
                                    extra=[("META-INF/androidx.core_core.version", b"1.13.1")])),
            ("split_config.arm64_v8a.apk", _apk_bytes(so=["lib/arm64-v8a/libfoo.so",
                                                          "lib/arm64-v8a/libbar.so"])),
            ("split_config.armeabi_v7a.apk", _apk_bytes(so=["lib/armeabi-v7a/libfoo.so"])),
            ("split_config.xxhdpi.apk", _apk_bytes(arsc=True)),
            ("split_config.ldpi.apk", _apk_bytes(arsc=True)),
        ],
        {"info.json": '{"pname": "com.example.sampleapp", "app_name": "Sample App"}',
         "icon.png": "\x89PNG"},
    )


def make_xapk(path):
    """Package-named base, config splits, dex feature modules and a feature ABI split."""
    return _bundle(
        path,
        [
            ("com.example.app.apk", _apk_bytes(dex=2, arsc=True)),
            ("config.armeabi_v7a.apk", _apk_bytes(so=["lib/armeabi-v7a/libapp.so"])),
            ("config.en.apk", _apk_bytes(arsc=True)),
            ("config.hdpi.apk", _apk_bytes(arsc=True)),
            ("FeatureAlpha.apk", _apk_bytes(dex=1)),
            ("FeatureBeta.apk", _apk_bytes(dex=1)),
            ("FeatureBeta.config.armeabi_v7a.apk", _apk_bytes(so=["lib/armeabi-v7a/libbeta.so"])),
            ("FeatureStub.apk", _apk_bytes()),  # manifest-only stub, no dex
        ],
        {"manifest.json": '{"package_name": "com.example.app", "name": "Example"}'},
    )


@pytest.mark.parametrize("ext", [".apkm", ".xapk", ".apks", ".APKM", ".XAPK"])
def test_detect_scan_mode_recognizes_bundles(tmp_path, ext):
    target = tmp_path / f"app{ext}"
    target.write_bytes(b"PK\x03\x04")  # detection is extension-based, like .apk/.ipa
    assert _detect_scan_mode(str(target)) == "android-bundle"


def test_detect_scan_mode_still_rejects_other_archives(tmp_path):
    """Random zips are still not Android targets."""
    for ext in (".zip", ".aar", ".jar", ".txt"):
        target = tmp_path / f"thing{ext}"
        target.write_bytes(b"PK\x03\x04")
        with pytest.raises(UnsupportedScanTarget):
            _detect_scan_mode(str(target))


def test_plain_apk_and_aab_unchanged(tmp_path):
    for ext in (".apk", ".aab"):
        target = tmp_path / f"app{ext}"
        target.write_bytes(b"PK\x03\x04")
        assert _detect_scan_mode(str(target)) == "android"


def test_is_split_bundle():
    assert split_bundle.is_split_bundle("/x/y.apkm")
    assert split_bundle.is_split_bundle("/x/y.XAPK")
    assert not split_bundle.is_split_bundle("/x/y.apk")
    assert not split_bundle.is_split_bundle("/x/y.aab")


@pytest.mark.parametrize("name,kind,token,owner", [
    ("base.apk", "base", None, None),
    ("config.arm64_v8a.apk", "abi", "arm64_v8a", None),
    ("split_config.armeabi_v7a.apk", "abi", "armeabi_v7a", None),
    ("config.xxxhdpi.apk", "density", "xxxhdpi", None),
    ("split_config.tvdpi.apk", "density", "tvdpi", None),
    ("config.en.apk", "language", "en", None),
    ("config.zh.apk", "language", "zh", None),
    # feature-owned config split
    ("FeatureBeta.config.armeabi_v7a.apk", "abi", "armeabi_v7a", "FeatureBeta"),
    ("FeatureGamma.config.armeabi_v7a.apk", "abi", "armeabi_v7a", "FeatureGamma"),
    # bundletool .apks split naming
    ("base-arm64_v8a.apk", "abi", "arm64_v8a", None),
    ("base-xxhdpi.apk", "density", "xxhdpi", None),
    ("base-en.apk", "language", "en", None),
    # bundletool emits one master split per device variant: both are the app
    # module, and "master_2" must never be filed as a language token
    ("base-master.apk", "base", None, None),
    ("base-master_2.apk", "base", None, None),
    # dynamic feature modules: no name convention, resolved by peeking
    ("FeatureAlpha.apk", "unknown", None, None),
    ("FeatureStub.apk", "unknown", None, None),
])
def test_classify_by_name(name, kind, token, owner):
    assert split_bundle._classify_by_name(name) == (kind, token, owner)


def test_apkm_extracts_app_module_and_abi_split(tmp_path):
    bundle_path = make_apkm(str(tmp_path / "sample.apkm"))
    out = tmp_path / "out"
    eb = split_bundle.extract_for_scan(bundle_path, str(out))

    assert eb.bundle_format == "apkm"
    assert eb.package_name == "com.example.sampleapp"
    assert eb.base_member == "base.apk"
    assert os.path.isfile(eb.base_apk_path)
    with zipfile.ZipFile(eb.base_apk_path) as zf:
        assert "classes.dex" in zf.namelist()

    # base.apk has no .so, so the ABI split must be pulled out too or native
    # hardening reports nothing.
    assert eb.native_source == "abi-split"
    assert eb.native_abi == "arm64-v8a"          # _ARCH_PREFERENCE order, not zip order
    assert os.path.isfile(eb.native_apk_path)
    with zipfile.ZipFile(eb.native_apk_path) as zf:
        assert "lib/arm64-v8a/libfoo.so" in zf.namelist()

    assert eb.split_count == 4
    assert eb.dex_bearing_splits == []


def test_abi_preference_is_deterministic_not_zip_order(tmp_path):
    """arm64-v8a wins regardless of member order."""
    bundle_path = _bundle(
        str(tmp_path / "b.apkm"),
        [
            ("split_config.armeabi_v7a.apk", _apk_bytes(so=["lib/armeabi-v7a/libx.so"])),
            ("split_config.x86_64.apk", _apk_bytes(so=["lib/x86_64/libx.so"])),
            ("split_config.arm64_v8a.apk", _apk_bytes(so=["lib/arm64-v8a/libx.so"])),
            ("base.apk", _apk_bytes(dex=1, arsc=True)),
        ],
    )
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    assert eb.native_abi == "arm64-v8a"


def test_base_module_that_ships_its_own_so_needs_no_abi_split(tmp_path):
    """No ABI split when the base already ships .so files."""
    bundle_path = _bundle(
        str(tmp_path / "native_in_base.xapk"),
        [
            ("com.example.app.apk", _apk_bytes(dex=2, arsc=True, so=["lib/arm64-v8a/libapp.so"])),
            ("config.xxxhdpi.apk", _apk_bytes(arsc=True)),
        ],
        {"manifest.json": '{"package_name": "com.example.app"}'},
    )
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    assert eb.native_source == "base"
    assert eb.native_apk_path is None


def test_xapk_base_named_after_package(tmp_path):
    """Base named <package>.apk, taken from manifest.json."""
    bundle_path = make_xapk(str(tmp_path / "app.xapk"))
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    assert eb.bundle_format == "xapk"
    assert eb.package_name == "com.example.app"
    assert eb.base_member == "com.example.app.apk"


def test_dex_bearing_feature_modules_are_extracted_for_decompilation(tmp_path):
    """Feature modules carry app code and go to the same jadx run."""
    bundle_path = make_xapk(str(tmp_path / "app.xapk"))
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))

    assert set(eb.dex_bearing_splits) == {"FeatureAlpha.apk", "FeatureBeta.apk"}
    assert len(eb.feature_apk_paths) == 2
    for p in eb.feature_apk_paths:
        assert os.path.isfile(p)
        with zipfile.ZipFile(p) as zf:
            assert "classes.dex" in zf.namelist()
    # the manifest-only stub carries no code and must NOT be added as a
    # decompile input
    assert "FeatureStub.apk" not in eb.dex_bearing_splits
    assert eb.skipped_feature_splits == []


def test_feature_owned_abi_split_is_not_mistaken_for_the_apps(tmp_path):
    """A feature module's ABI split is not picked for the app."""
    bundle_path = make_xapk(str(tmp_path / "app.xapk"))
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    assert os.path.basename(eb.native_apk_path) == "config.armeabi_v7a.apk"
    owners = {m.owner for m in eb.members if m.owner}
    assert owners == {"FeatureBeta"}


def test_extracted_feature_names_cannot_collide_with_base(tmp_path):
    """Extracted feature names can't overwrite the base or ABI split."""
    bundle_path = _bundle(
        str(tmp_path / "evil.xapk"),
        [
            ("com.example.app.apk", _apk_bytes(dex=2, arsc=True)),
            ("config.arm64_v8a.apk", _apk_bytes(so=["lib/arm64-v8a/libx.so"])),
            ("some/dir/base.apk", _apk_bytes(dex=1)),
        ],
        {"manifest.json": '{"package_name": "com.example.app"}'},
    )
    out = tmp_path / "out"
    eb = split_bundle.extract_for_scan(bundle_path, str(out))
    assert eb.base_member == "com.example.app.apk"
    with zipfile.ZipFile(eb.base_apk_path) as zf:
        assert "classes2.dex" in zf.namelist()   # still the 2-dex app module
    for p in eb.feature_apk_paths:
        assert os.path.basename(p).startswith("feature_")


def _make_apks(path):
    return _bundle(
        path,
        [
            ("splits/base-master.apk", _apk_bytes(dex=3, arsc=True)),
            # same code, packaged for a different device variant
            ("splits/base-master_2.apk", _apk_bytes(dex=3, arsc=True)),
            ("splits/base-arm64_v8a.apk", _apk_bytes(so=["lib/arm64-v8a/libnative-lib.so"])),
            ("splits/base-armeabi_v7a.apk", _apk_bytes(so=["lib/armeabi-v7a/libnative-lib.so"])),
            ("splits/base-xxhdpi.apk", _apk_bytes(arsc=True)),
            ("splits/base-en.apk", _apk_bytes(arsc=True)),
        ],
        {"toc.pb": "\x00binary-protobuf"},
    )


def test_apks_picks_one_master_split_and_the_abi_split(tmp_path):
    eb = split_bundle.extract_for_scan(_make_apks(str(tmp_path / "app.apks")),
                                       str(tmp_path / "out"))
    assert eb.bundle_format == "apks"
    assert eb.base_member == "splits/base-master.apk"
    assert eb.native_abi == "arm64-v8a"
    variants = [m.name for m in eb.members if m.kind == "variant"]
    assert variants == ["splits/base-master_2.apk"]


def test_apks_master_choice_is_stable_across_member_order(tmp_path):
    """The master APK choice doesn't depend on zip order."""
    forward = _bundle(str(tmp_path / "a.apks"), [
        ("splits/base-master.apk", _apk_bytes(dex=1, arsc=True)),
        ("splits/base-master_2.apk", _apk_bytes(dex=1, arsc=True)),
    ])
    reverse = _bundle(str(tmp_path / "b.apks"), [
        ("splits/base-master_2.apk", _apk_bytes(dex=1, arsc=True)),
        ("splits/base-master.apk", _apk_bytes(dex=1, arsc=True)),
    ])
    a = split_bundle.extract_for_scan(forward, str(tmp_path / "outa"))
    b = split_bundle.extract_for_scan(reverse, str(tmp_path / "outb"))
    assert a.base_member == b.base_member == "splits/base-master.apk"


def test_apks_summary_calls_the_extra_master_a_device_variant(tmp_path):
    eb = split_bundle.extract_for_scan(_make_apks(str(tmp_path / "app.apks")),
                                       str(tmp_path / "out"))
    text = " ".join(t for _s, t in split_bundle.summary_lines(eb))
    assert "device-variant" in text
    assert "same code, scanned once" in text
    # it must NOT be mis-filed as a language split
    assert "75 language" not in text


def test_config_split_is_never_chosen_as_the_base(tmp_path):
    """A config split is never picked as the base."""
    bundle_path = _bundle(
        str(tmp_path / "weird.apkm"),
        [
            # deliberately first in zip order AND biggest
            ("config.arm64_v8a.apk", _apk_bytes(so=[f"lib/arm64-v8a/lib{i}.so" for i in range(40)])),
            ("theapp.apk", _apk_bytes(dex=1, arsc=True)),
        ],
    )
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    assert eb.base_member == "theapp.apk"


def test_bundle_with_no_app_module_refuses_instead_of_scanning_a_split(tmp_path):
    """No dex anywhere: refuse instead of scanning a split."""
    bundle_path = _bundle(
        str(tmp_path / "nodex.apkm"),
        [
            ("split_config.arm64_v8a.apk", _apk_bytes(so=["lib/arm64-v8a/libx.so"])),
            ("split_config.xxhdpi.apk", _apk_bytes(arsc=True)),
        ],
    )
    with pytest.raises(split_bundle.SplitBundleError) as exc:
        split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    assert "base.apk" in str(exc.value)


def test_bundle_with_no_apk_members_at_all(tmp_path):
    bundle_path = _bundle(str(tmp_path / "empty.xapk"), [], {"manifest.json": "{}"})
    with pytest.raises(split_bundle.SplitBundleError) as exc:
        split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    assert "no .apk files" in str(exc.value)


def test_not_a_zip(tmp_path):
    p = tmp_path / "junk.apkm"
    p.write_bytes(b"this is not a zip file at all")
    with pytest.raises(split_bundle.SplitBundleError) as exc:
        split_bundle.extract_for_scan(str(p), str(tmp_path / "out"))
    assert "not a valid ZIP" in str(exc.value)


# A bundle is attacker-supplied input.

def test_path_traversal_member_is_refused(tmp_path):
    p = tmp_path / "evil.apkm"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("base.apk", _apk_bytes(dex=1))
        zf.writestr("../../../../etc/cron.d/pwn", b"* * * * * root sh")
    with pytest.raises(split_bundle.SplitBundleError) as exc:
        split_bundle.extract_for_scan(str(p), str(tmp_path / "out"))
    assert "path-traversal" in str(exc.value)


def test_zip_bomb_ratio_is_refused(tmp_path):
    p = tmp_path / "bomb.apkm"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("base.apk", _apk_bytes(dex=1))
        zf.writestr("payload.bin", b"\x00" * (80 * 1024 * 1024))  # ~80000:1
    with pytest.raises(split_bundle.SplitBundleError) as exc:
        split_bundle.extract_for_scan(str(p), str(tmp_path / "out"))
    assert "zip bomb" in str(exc.value)


def test_nothing_is_written_outside_dest_dir(tmp_path):
    """Member paths are replaced by basenames we choose, never used as-is."""
    bundle_path = _bundle(
        str(tmp_path / "nested.apks"),
        [
            ("splits/base-master.apk", _apk_bytes(dex=1, arsc=True)),
            ("splits/base-arm64_v8a.apk", _apk_bytes(so=["lib/arm64-v8a/libx.so"])),
        ],
    )
    out = tmp_path / "out"
    eb = split_bundle.extract_for_scan(bundle_path, str(out))
    assert eb.base_member == "splits/base-master.apk"
    produced = []
    for root, _dirs, files in os.walk(out):
        produced.extend(os.path.join(root, f) for f in files)
    assert all(os.path.dirname(p) == str(out) for p in produced), produced


def test_summary_states_what_was_and_was_not_scanned(tmp_path):
    bundle_path = make_apkm(str(tmp_path / "sample.apkm"))
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    text = " ".join(t for _s, t in split_bundle.summary_lines(eb))
    assert ".apkm split-APK bundle" in text
    assert "com.example.sampleapp" in text
    assert "base.apk" in text
    assert "arm64-v8a" in text
    assert "not separately analysed" in text


def test_summary_names_the_feature_modules_that_were_scanned(tmp_path):
    bundle_path = make_xapk(str(tmp_path / "app.xapk"))
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    text = " ".join(t for _s, t in split_bundle.summary_lines(eb))
    assert "FeatureAlpha.apk" in text
    assert "FeatureBeta.apk" in text
    assert "decompiled together with the app module" in text


def test_oversized_feature_module_is_reported_as_incomplete(tmp_path, monkeypatch):
    """An oversized feature module is reported as INCOMPLETE."""
    monkeypatch.setattr(split_bundle, "_MAX_FEATURE_INPUT_BYTES", 1)
    bundle_path = make_xapk(str(tmp_path / "app.xapk"))
    eb = split_bundle.extract_for_scan(bundle_path, str(tmp_path / "out"))
    assert set(eb.skipped_feature_splits) == {"FeatureAlpha.apk", "FeatureBeta.apk"}
    assert eb.feature_apk_paths == []
    styles_text = split_bundle.summary_lines(eb)
    incomplete = [t for s, t in styles_text if "INCOMPLETE" in t]
    assert incomplete and "UNSCANNED" in incomplete[0]
    assert any(s == "bold yellow" for s, _t in styles_text)


def test_bundle_scan_delegates_to_the_same_local_scan(tmp_path, monkeypatch):
    """Bundles go through the same _run_local_scan as a plain APK."""
    from narvy import main as cli_main

    bundle_path = make_xapk(str(tmp_path / "app.xapk"))
    captured = {}

    def fake_run_local_scan(apk_path, max_mem, override_config=None, force=False,
                            native_apk_path=None, extra_dex_inputs=None):
        captured["apk_path"] = apk_path
        captured["native_apk_path"] = native_apk_path
        captured["extra_dex_inputs"] = list(extra_dex_inputs or [])
        captured["max_mem"] = max_mem
        # everything must still exist at call time (temp dir not yet cleaned)
        captured["all_exist"] = (
            os.path.isfile(apk_path)
            and os.path.isfile(native_apk_path)
            and all(os.path.isfile(p) for p in captured["extra_dex_inputs"])
        )
        return ([], [])

    monkeypatch.setattr(cli_main, "_run_local_scan", fake_run_local_scan)
    result = cli_main._run_split_bundle_scan(bundle_path, "4g")

    assert result == ([], [])
    assert captured["max_mem"] == "4g"
    assert os.path.basename(captured["apk_path"]) == "base.apk"
    assert os.path.basename(captured["native_apk_path"]) == "config.armeabi_v7a.apk"
    assert len(captured["extra_dex_inputs"]) == 2
    assert captured["all_exist"]


def test_bundle_temp_dir_is_cleaned_up(tmp_path, monkeypatch):
    from narvy import main as cli_main

    bundle_path = make_xapk(str(tmp_path / "app.xapk"))
    seen = {}

    def fake_run_local_scan(apk_path, max_mem, **kwargs):
        seen["dir"] = os.path.dirname(apk_path)
        return ([], [])

    monkeypatch.setattr(cli_main, "_run_local_scan", fake_run_local_scan)
    cli_main._run_split_bundle_scan(bundle_path, "4g")
    assert not os.path.exists(seen["dir"])


def test_bad_bundle_returns_none_not_traceback(tmp_path, monkeypatch):
    """Hard-failure convention: return None after printing, never raise."""
    from narvy import main as cli_main

    p = tmp_path / "junk.apkm"
    p.write_bytes(b"not a zip")
    assert cli_main._run_split_bundle_scan(str(p), "4g") is None


def test_decompile_apk_passes_extra_inputs_to_jadx(monkeypatch, tmp_path):
    """Extra inputs are passed to jadx."""
    from narvy import decompiler

    apk = tmp_path / "base.apk"
    apk.write_bytes(_apk_bytes(dex=1))
    feat = tmp_path / "feature_alpha.apk"
    feat.write_bytes(_apk_bytes(dex=1))

    monkeypatch.setattr(decompiler, "resolve_jadx_binary", lambda: "/fake/jadx")
    monkeypatch.setattr(decompiler, "resolve_java_home", lambda: None)
    monkeypatch.setattr(decompiler, "check_memory_preflight",
                        lambda *a, **k: type("V", (), {"should_block": False, "message": ""})())

    captured = {}

    class _Done:
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _Done()

    monkeypatch.setattr(decompiler.subprocess, "run", fake_run)

    ok, err = decompiler.decompile_apk(str(apk), str(tmp_path / "out"), "4g",
                                       extra_inputs=[str(feat)])
    assert ok, err
    assert captured["cmd"][-2:] == [str(apk), str(feat)]


def test_decompile_apk_without_extra_inputs_is_byte_for_byte_unchanged(monkeypatch, tmp_path):
    from narvy import decompiler

    apk = tmp_path / "base.apk"
    apk.write_bytes(_apk_bytes(dex=1))

    monkeypatch.setattr(decompiler, "resolve_jadx_binary", lambda: "/fake/jadx")
    monkeypatch.setattr(decompiler, "resolve_java_home", lambda: None)
    monkeypatch.setattr(decompiler, "check_memory_preflight",
                        lambda *a, **k: type("V", (), {"should_block": False, "message": ""})())
    captured = {}

    class _Done:
        stdout = ""
        stderr = ""

    monkeypatch.setattr(decompiler.subprocess, "run",
                        lambda cmd, **kw: (captured.__setitem__("cmd", cmd), _Done())[1])

    out_dir = str(tmp_path / "out")
    ok, err = decompiler.decompile_apk(str(apk), out_dir, "4g")
    assert ok, err
    assert captured["cmd"] == ["/fake/jadx", "--output-dir", out_dir,
                               "--show-bad-code", str(apk)]
