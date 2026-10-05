"""Positive and negative synthetic cases for every Google Play check, on APK,
AAB and split-APK containers."""
import datetime as dt

import pytest

import builders as B
from builders import E

FAIL, PASS, ND, NA = "fail", "pass", "not_determined", "not_applicable"
ARM64 = "lib/arm64-v8a/libfoo.so"


def comp(tag, name, exported=None, filt=True, **extra):
    attrs = {"android:name": name}
    if exported is not None:
        attrs["android:exported"] = exported
    attrs.update(extra)
    children = [E("intent-filter", {}, [E("action", {"android:name": "com.example.ACTION"})])] if filt else []
    return E(tag, attrs, children)


# --------------------------------------------------------------- target SDK
@pytest.mark.parametrize("target,status", [(36, PASS), (37, PASS), (35, FAIL), (28, FAIL)])
def test_target_sdk_phone(run, target, status):
    res, _ = run(B.apk(B.manifest(target=target)))
    r = res["PLAY-TARGET-SDK"]
    assert r.status == status
    if status == FAIL:
        assert r.severity == "blocker" and "36" in r.message["en"] and "2026-11-01" in r.message["en"]


def test_target_sdk_before_2026_deadline(run):
    res, _ = run(B.apk(B.manifest(target=35)), as_of=dt.date(2026, 8, 30))
    assert res["PLAY-TARGET-SDK"].status == PASS


def test_target_sdk_no_extension_mention_after_extension_date(run):
    res, _ = run(B.apk(B.manifest(target=35)), as_of=dt.date(2026, 11, 2))
    assert res["PLAY-TARGET-SDK"].status == FAIL and "extension" not in res["PLAY-TARGET-SDK"].message["en"]


@pytest.mark.parametrize("feature,target,status", [
    ("android.hardware.type.watch", 35, PASS), ("android.hardware.type.watch", 34, FAIL),
    ("android.software.leanback", 34, PASS), ("android.software.leanback", 33, FAIL),
    ("android.hardware.type.automotive", 35, PASS),
])
def test_target_sdk_form_factors(run, feature, target, status):
    res, _ = run(B.apk(B.manifest(target=target, features=[(feature, None)])))
    assert res["PLAY-TARGET-SDK"].status == status


def test_target_sdk_leanback_not_required_is_phone_rule(run):
    res, _ = run(B.apk(B.manifest(target=35, features=[("android.software.leanback", False)])))
    assert res["PLAY-TARGET-SDK"].status == FAIL


def test_target_sdk_missing_defaults_to_min(run):
    res, _ = run(B.apk(B.manifest(target=None, min_sdk=21)))
    r = res["PLAY-TARGET-SDK"]
    assert r.status == FAIL and "21" in r.message["en"]


def test_target_sdk_on_aab(run):
    res, _ = run(B.aab(B.manifest(target=34)), ".aab")
    assert res["PLAY-TARGET-SDK"].status == FAIL
    res, _ = run(B.aab(B.manifest(target=36)), ".aab")
    assert res["PLAY-TARGET-SDK"].status == PASS


# --------------------------------------------------------------- 16 KB ELF
def test_16kb_aligned_passes(run):
    res, _ = run(B.apk(B.manifest(), files={ARM64: B.elf64([0x4000, 0x4000]), "lib/x86_64/libfoo.so": B.elf64([0x10000])}))
    assert res["PLAY-16KB-ELF"].status == PASS


def test_16kb_misaligned_warns_before_enforcement(run):
    res, _ = run(B.apk(B.manifest(), files={ARM64: B.elf64([0x4000, 0x1000])}))
    r = res["PLAY-16KB-ELF"]
    assert r.status == FAIL and r.severity == "warning"
    assert r.evidence[0].path == ARM64 and "4096" in r.evidence[0].value


def test_16kb_misaligned_blocks_after_enforcement(run):
    res, _ = run(B.apk(B.manifest(target=36), files={ARM64: B.elf64([0x1000])}), as_of=dt.date(2027, 2, 1))
    assert res["PLAY-16KB-ELF"].status == FAIL and res["PLAY-16KB-ELF"].severity == "blocker"


def test_16kb_32bit_abis_ignored(run):
    res, _ = run(B.apk(B.manifest(), files={"lib/armeabi-v7a/libfoo.so": B.elf32([0x1000])}))
    assert res["PLAY-16KB-ELF"].status == PASS


def test_16kb_non_elf_skipped(run):
    res, _ = run(B.apk(B.manifest(), files={ARM64: b"\x7fKOM" + b"\x00" * 100}))
    r = res["PLAY-16KB-ELF"]
    assert r.status == PASS and any("not an ELF" in e.value for e in r.evidence)


def test_16kb_truncated_elf_not_determined(run):
    res, _ = run(B.apk(B.manifest(), files={ARM64: B.elf64([0x4000])[:70]}))
    assert res["PLAY-16KB-ELF"].status == ND


def test_16kb_on_aab_and_split_set(run):
    res, _ = run(B.aab(B.manifest(), files={"base/lib/arm64-v8a/libfoo.so": B.elf64([0x1000])}), ".aab")
    assert res["PLAY-16KB-ELF"].status == FAIL
    base = B.apk(B.manifest())
    split = B.apk(E("manifest", {"package": "com.example.app", "split": "config.arm64_v8a"}, [E("application")]),
                  files={ARM64: B.elf64([0x1000])})
    res, rep = run(B.split_set({"base.apk": base, "split_config.arm64_v8a.apk": split}), ".xapk")
    assert rep.container == "apks"
    assert res["PLAY-16KB-ELF"].status == FAIL
    assert res["PLAY-16KB-ELF"].evidence[0].path.startswith("split_config.arm64_v8a.apk!")


# --------------------------------------------------------------- 16 KB zip alignment
def test_zipalign_misaligned_uncompressed(run):
    data = B.apk(B.manifest(app_attrs={"android:extractNativeLibs": False}), files={ARM64: B.elf64([0x4000])},
                 stored=[ARM64], align_stored=16384, misalign=True)
    res, _ = run(data)
    assert res["PLAY-16KB-ZIPALIGN"].status == FAIL


def test_zipalign_aligned_uncompressed(run):
    data = B.apk(B.manifest(app_attrs={"android:extractNativeLibs": False}), files={ARM64: B.elf64([0x4000])},
                 stored=[ARM64], align_stored=16384)
    res, _ = run(data)
    assert res["PLAY-16KB-ZIPALIGN"].status == PASS


def test_zipalign_not_applicable_when_extracted(run):
    data = B.apk(B.manifest(), files={ARM64: B.elf64([0x4000])}, stored=[ARM64], align_stored=16384, misalign=True)
    res, _ = run(data)
    assert res["PLAY-16KB-ZIPALIGN"].status == NA


def test_zipalign_not_applicable_for_aab(run):
    res, _ = run(B.aab(B.manifest()), ".aab")
    assert res["PLAY-16KB-ZIPALIGN"].status == NA


# --------------------------------------------------------------- exported
def test_exported_missing_fails(run):
    man = B.manifest(target=31, app_children=[comp("activity", ".A", exported=True), comp("receiver", ".R")])
    res, _ = run(B.apk(man))
    r = res["PLAY-EXPORTED"]
    assert r.status == FAIL and r.severity == "blocker" and len(r.evidence) == 1 and ".R" in r.evidence[0].value


def test_exported_present_passes(run):
    man = B.manifest(target=34, app_children=[comp("activity", ".A", exported=True), comp("service", ".S", exported=False),
                                              comp("receiver", ".R", exported=False), comp("provider", ".P")])
    res, _ = run(B.apk(man))
    assert res["PLAY-EXPORTED"].status == PASS


def test_exported_without_filter_is_fine(run):
    man = B.manifest(target=34, app_children=[comp("service", ".S", filt=False)])
    res, _ = run(B.apk(man))
    assert res["PLAY-EXPORTED"].status == NA


def test_exported_rule_not_applicable_below_31(run):
    man = B.manifest(target=30, app_children=[comp("activity", ".A")])
    res, _ = run(B.apk(man))
    assert res["PLAY-EXPORTED"].status == NA


def test_exported_on_aab(run):
    man = B.manifest(target=33, app_children=[comp("activity", ".A")])
    res, _ = run(B.aab(man), ".aab")
    assert res["PLAY-EXPORTED"].status == FAIL


def test_exported_name_without_resource_id_is_ignored(run):
    """Android reads framework attributes by resource id; a bare 'exported' attribute is not android:exported."""
    a = E("activity", {"android:name": ".A", "exported": "true"},
          [E("intent-filter", {}, [E("action", {"android:name": "x"})])])
    res, _ = run(B.apk(B.manifest(target=31, app_children=[a])))
    assert res["PLAY-EXPORTED"].status == FAIL


# --------------------------------------------------------------- foreground services
FGS = "android.permission.FOREGROUND_SERVICE"


def svc(name, types=None):
    attrs = {"android:name": name}
    if types:
        mask = 0
        for t in types:
            mask |= B.FGS[t]
        attrs["android:foregroundServiceType"] = ("hex", mask)
    return E("service", attrs)


def test_fgs_type_missing(run):
    res, _ = run(B.apk(B.manifest(target=34, perms=[FGS], app_children=[svc(".S")])))
    assert res["PLAY-FGS-TYPE"].status == FAIL and res["PLAY-FGS-TYPE"].severity == "info"
    assert res["PLAY-FGS-DECLARATION"].status == NA


def test_fgs_type_present_with_permissions(run):
    man = B.manifest(target=34, perms=[FGS, "android.permission.FOREGROUND_SERVICE_LOCATION",
                                       "android.permission.FOREGROUND_SERVICE_DATA_SYNC"],
                     app_children=[svc(".S", ["location", "dataSync"]), svc(".T", ["shortService"])])
    res, _ = run(B.apk(man))
    assert res["PLAY-FGS-TYPE"].status == PASS
    assert res["PLAY-FGS-PERMISSION"].status == PASS
    d = res["PLAY-FGS-DECLARATION"]
    assert d.status == FAIL and "location" in d.message["en"] and "shortService" in d.message["en"]


def test_fgs_type_permission_missing(run):
    man = B.manifest(target=35, perms=[FGS], app_children=[svc(".S", ["camera"])])
    res, _ = run(B.apk(man))
    r = res["PLAY-FGS-PERMISSION"]
    assert r.status == FAIL and "FOREGROUND_SERVICE_CAMERA" in r.evidence[0].detail


def test_fgs_rules_not_applicable_below_34(run):
    res, _ = run(B.apk(B.manifest(target=33, perms=[FGS], app_children=[svc(".S")])))
    assert {res[k].status for k in ("PLAY-FGS-TYPE", "PLAY-FGS-PERMISSION", "PLAY-FGS-DECLARATION")} == {NA}


def test_fgs_without_permission_not_applicable(run):
    res, _ = run(B.apk(B.manifest(target=34, app_children=[svc(".S")])))
    assert res["PLAY-FGS-TYPE"].status == NA


def test_fgs_on_aab(run):
    man = B.manifest(target=34, perms=[FGS], app_children=[svc(".S", ["mediaPlayback"])])
    res, _ = run(B.aab(man), ".aab")
    assert res["PLAY-FGS-TYPE"].status == PASS
    assert res["PLAY-FGS-PERMISSION"].status == FAIL


# --------------------------------------------------------------- permission declarations
@pytest.mark.parametrize("perm,group", [
    ("android.permission.QUERY_ALL_PACKAGES", "Package visibility"),
    ("android.permission.MANAGE_EXTERNAL_STORAGE", "All files access"),
    ("android.permission.ACCESS_BACKGROUND_LOCATION", "Background location"),
    ("android.permission.READ_SMS", "SMS"),
    ("android.permission.READ_CALL_LOG", "Call Log"),
    ("android.permission.REQUEST_INSTALL_PACKAGES", "Request install packages"),
    ("android.permission.USE_EXACT_ALARM", "Exact alarm"),
    ("android.permission.READ_MEDIA_IMAGES", "Photo and video"),
    ("android.permission.health.READ_STEPS", "Health Connect"),
])
def test_permission_declaration_needed(run, perm, group):
    res, _ = run(B.apk(B.manifest(perms=[perm])))
    r = res["PLAY-PERMISSION-DECLARATION"]
    assert r.status == FAIL and r.severity == "warning" and group in r.message["en"]
    assert "Play Console" in r.message["en"] and r.evidence[0].value == perm


def test_permission_declaration_full_screen_intent_only_target_34(run):
    res, _ = run(B.apk(B.manifest(target=33, perms=["android.permission.USE_FULL_SCREEN_INTENT"])))
    assert res["PLAY-PERMISSION-DECLARATION"].status == PASS
    res, _ = run(B.apk(B.manifest(target=34, perms=["android.permission.USE_FULL_SCREEN_INTENT"])))
    assert res["PLAY-PERMISSION-DECLARATION"].status == FAIL


def test_permission_declaration_accessibility_service(run):
    s = E("service", {"android:name": ".A11y", "android:permission": "android.permission.BIND_ACCESSIBILITY_SERVICE"})
    res, _ = run(B.apk(B.manifest(app_children=[s])))
    assert res["PLAY-PERMISSION-DECLARATION"].status == FAIL


def test_permission_declaration_clean(run):
    res, _ = run(B.apk(B.manifest(perms=["android.permission.INTERNET", "android.permission.CAMERA",
                                         "android.permission.ACCESS_FINE_LOCATION"])))
    assert res["PLAY-PERMISSION-DECLARATION"].status == PASS


# --------------------------------------------------------------- debuggable
def test_debuggable_true_blocks(run):
    res, _ = run(B.apk(B.manifest(app_attrs={"android:debuggable": True})))
    assert res["PLAY-DEBUGGABLE"].status == FAIL and res["PLAY-DEBUGGABLE"].severity == "blocker"


@pytest.mark.parametrize("attrs", [{}, {"android:debuggable": False}])
def test_debuggable_false_or_absent(run, attrs):
    res, _ = run(B.apk(B.manifest(app_attrs=attrs)))
    assert res["PLAY-DEBUGGABLE"].status == PASS


def test_debuggable_through_resource_reference(run):
    man = B.manifest(app_attrs={"android:debuggable": ("ref", 0x7F020000)})
    res, _ = run(B.apk(man, files={"resources.arsc": B.arsc({0x7F020000: ("bool", True)})}))
    assert res["PLAY-DEBUGGABLE"].status == FAIL
    res, _ = run(B.apk(man))  # dangling reference
    assert res["PLAY-DEBUGGABLE"].status == ND


def test_debuggable_on_aab(run):
    res, _ = run(B.aab(B.manifest(app_attrs={"android:debuggable": True})), ".aab")
    assert res["PLAY-DEBUGGABLE"].status == FAIL


# --------------------------------------------------------------- cleartext
def test_cleartext_explicit_true(run):
    res, _ = run(B.apk(B.manifest(app_attrs={"android:usesCleartextTraffic": True})))
    assert res["PLAY-CLEARTEXT"].status == FAIL and res["PLAY-CLEARTEXT"].severity == "warning"


def test_cleartext_default_by_target(run):
    res, _ = run(B.apk(B.manifest(target=27)))
    assert res["PLAY-CLEARTEXT"].status == FAIL
    res, _ = run(B.apk(B.manifest(target=28)))
    assert res["PLAY-CLEARTEXT"].status == PASS


NSC_ID = 0x7F010000


def nsc_apk(root):
    man = B.manifest(app_attrs={"android:networkSecurityConfig": ("ref", NSC_ID), "android:usesCleartextTraffic": False})
    return B.apk(man, files={"resources.arsc": B.arsc({NSC_ID: ("file", "res/xml/nsc.xml")}), "res/xml/nsc.xml": B.axml(root)})


def test_cleartext_nsc_base_config_true(run):
    res, _ = run(nsc_apk(E("network-security-config", {}, [E("base-config", {"cleartextTrafficPermitted": True})])))
    r = res["PLAY-CLEARTEXT"]
    assert r.status == FAIL and r.severity == "warning" and r.evidence[0].path == "res/xml/nsc.xml"


def test_cleartext_nsc_domain_only(run):
    root = E("network-security-config", {}, [
        E("domain-config", {"cleartextTrafficPermitted": True}, [E("domain", {"includeSubdomains": True}, text="example.com")])])
    res, _ = run(nsc_apk(root))
    r = res["PLAY-CLEARTEXT"]
    assert r.status == FAIL and r.severity == "info" and r.evidence[0].value == "example.com"


def test_cleartext_nsc_strict(run):
    res, _ = run(nsc_apk(E("network-security-config", {}, [E("base-config", {"cleartextTrafficPermitted": False})])))
    assert res["PLAY-CLEARTEXT"].status == PASS


def test_cleartext_nsc_on_aab(run):
    man = B.manifest(app_attrs={"android:networkSecurityConfig": ("ref", NSC_ID)})
    data = B.aab(man, resources={NSC_ID: ("file", "res/xml/nsc.xml")},
                 xml_files={"res/xml/nsc.xml": E("network-security-config", {}, [E("base-config", {"cleartextTrafficPermitted": True})])})
    res, _ = run(data, ".aab")
    assert res["PLAY-CLEARTEXT"].status == FAIL


def test_cleartext_nsc_unresolvable_is_not_determined(run):
    man = B.manifest(app_attrs={"android:networkSecurityConfig": ("ref", NSC_ID)})
    res, _ = run(B.apk(man))
    assert res["PLAY-CLEARTEXT"].status == ND


def test_cleartext_null_nsc_falls_back_to_manifest(run):
    man = B.manifest(app_attrs={"android:networkSecurityConfig": ("ref", 0)})
    res, _ = run(B.apk(man))
    assert res["PLAY-CLEARTEXT"].status == PASS


# --------------------------------------------------------------- robustness
@pytest.mark.parametrize("payload", [b"", b"not a zip", b"PK\x03\x04garbage"])
def test_garbage_input_is_an_input_error(tmp_path, payload):
    from narvy.store_check.analyze import InputError, analyze
    p = tmp_path / "x.apk"
    p.write_bytes(payload)
    with pytest.raises(InputError):
        analyze(str(p))


def test_corrupt_manifest_is_an_input_error(tmp_path):
    import io
    import zipfile

    from narvy.store_check.analyze import InputError, analyze
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\xff" * 40)
    p = tmp_path / "x.apk"
    p.write_bytes(buf.getvalue())
    with pytest.raises(InputError):
        analyze(str(p))


def test_target_sdk_legacy_television_feature(run):
    res, _ = run(B.apk(B.manifest(target=34, features=[("android.hardware.type.television", None)])))
    assert res["PLAY-TARGET-SDK"].status == PASS
    res, _ = run(B.apk(B.manifest(target=34, features=[("android.hardware.type.television", False)])))
    assert res["PLAY-TARGET-SDK"].status == FAIL
