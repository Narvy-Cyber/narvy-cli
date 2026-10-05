"""Positive and negative synthetic cases for every App Store check."""
import datetime as dt
import plistlib

import pytest

import builders as B

FAIL, PASS, ND, NA = "fail", "pass", "not_determined", "not_applicable"
TS = "NSPrivacyAccessedAPICategoryFileTimestamp"
BOOT = "NSPrivacyAccessedAPICategorySystemBootTime"
DISK = "NSPrivacyAccessedAPICategoryDiskSpace"
UD = "NSPrivacyAccessedAPICategoryUserDefaults"
KB = "NSPrivacyAccessedAPICategoryActiveKeyboards"


def ipa_run(run, **kw):
    return run(B.ipa(**kw), ".ipa")


# --------------------------------------------------------------- SDK version
@pytest.mark.parametrize("sdk_name,plat,xcode,macho_sdk,status", [
    ("iphoneos26.0", "26.0", "2600", (26, 0), PASS),
    ("iphoneos18.2", "18.2", "1620", (18, 2), FAIL),
    ("iphoneos26.0", "26.0", "2600", (18, 0), ND),  # Info.plist and binary disagree
])
def test_sdk_version(run, sdk_name, plat, xcode, macho_sdk, status):
    res, _ = ipa_run(run, info={"DTSDKName": sdk_name, "DTPlatformVersion": plat, "DTXcode": xcode},
                     executable=B.macho(sdk=macho_sdk))
    r = res["APPSTORE-SDK-VERSION"]
    assert r.status == status
    if status == FAIL:
        assert r.severity == "blocker" and "26" in r.message["en"]


def test_sdk_version_uses_binary_when_plist_keys_missing(run):
    res, _ = ipa_run(run, info={"DTSDKName": None, "DTPlatformVersion": None, "DTXcode": None},
                     executable=B.macho(sdk=(17, 0)))
    assert res["APPSTORE-SDK-VERSION"].status == FAIL


def test_sdk_version_before_2026_requirement(run):
    res, _ = ipa_run(run, info={"DTSDKName": "iphoneos18.2", "DTPlatformVersion": "18.2", "DTXcode": "1620"},
                     executable=B.macho(sdk=(18, 2)))
    assert res["APPSTORE-SDK-VERSION"].status == FAIL
    res, _ = run(B.ipa(info={"DTSDKName": "iphoneos18.2", "DTPlatformVersion": "18.2", "DTXcode": "1620"},
                       executable=B.macho(sdk=(18, 2))), ".ipa", as_of=dt.date(2026, 4, 27))
    assert res["APPSTORE-SDK-VERSION"].status == PASS


# --------------------------------------------------------------- minimum OS
@pytest.mark.parametrize("mos,status", [("12.4", FAIL), ("13.0", PASS), ("17.0", PASS)])
def test_min_os(run, mos, status):
    res, _ = ipa_run(run, info={"MinimumOSVersion": mos})
    assert res["APPSTORE-MIN-OS"].status == status


def test_min_os_not_enforced_before_2026_09_09(run):
    res, _ = run(B.ipa(info={"MinimumOSVersion": "12.0"}), ".ipa", as_of=dt.date(2026, 9, 8))
    assert res["APPSTORE-MIN-OS"].status == NA


# --------------------------------------------------------------- required reason APIs
def test_rr_undeclared_in_app_binary(run):
    res, _ = ipa_run(run, executable=B.macho(imports=["_stat", "_mach_absolute_time"]))
    r = res["APPSTORE-REQUIRED-REASON-API"]
    assert r.status == FAIL and r.severity == "warning"
    vals = " ".join(e.value for e in r.evidence)
    assert TS in vals and BOOT in vals


def test_rr_declared_in_app_manifest(run):
    res, _ = ipa_run(run, executable=B.macho(imports=["_stat", "_mach_absolute_time", "_OBJC_CLASS_$_NSUserDefaults"]),
                     files={"PrivacyInfo.xcprivacy": B.privacy_manifest({TS: ["C617.1"], BOOT: ["35F9.1"], UD: ["CA92.1"]})})
    assert res["APPSTORE-REQUIRED-REASON-API"].status == PASS


def test_rr_static_sdk_resource_bundle_manifest_covers_app_binary(run):
    res, _ = ipa_run(run, executable=B.macho(imports=["_statfs"]),
                     files={"Foo_Privacy.bundle/PrivacyInfo.xcprivacy": B.privacy_manifest({DISK: ["E174.1"]})})
    assert res["APPSTORE-REQUIRED-REASON-API"].status == PASS


def test_rr_framework_needs_its_own_manifest(run):
    """Apple: the bundle that includes the executable or dynamic library needs the manifest."""
    files = B.framework("Kit", B.macho(imports=["_OBJC_CLASS_$_NSUserDefaults"]))
    files["PrivacyInfo.xcprivacy"] = B.privacy_manifest({UD: ["CA92.1"]})
    res, _ = ipa_run(run, files=files)
    r = res["APPSTORE-REQUIRED-REASON-API"]
    assert r.status == FAIL and r.evidence[0].path.endswith("Frameworks/Kit.framework/Kit")
    files = B.framework("Kit", B.macho(imports=["_OBJC_CLASS_$_NSUserDefaults"]), B.privacy_manifest({UD: ["C56D.1"]}))
    res, _ = ipa_run(run, files=files)
    assert res["APPSTORE-REQUIRED-REASON-API"].status == PASS


def test_rr_getattrlist_accepts_either_category(run):
    exe = B.macho(imports=["_getattrlist"])
    res, _ = ipa_run(run, executable=exe)
    assert res["APPSTORE-REQUIRED-REASON-API"].status == FAIL
    res, _ = ipa_run(run, executable=exe, files={"PrivacyInfo.xcprivacy": B.privacy_manifest({DISK: ["85F4.1"]})})
    assert res["APPSTORE-REQUIRED-REASON-API"].status == PASS


def test_rr_defined_symbol_is_not_an_api_use(run):
    """An app defining its own `_stat` does not call the system API."""
    res, _ = ipa_run(run, executable=B.macho(defined=["_stat"], imports=["_objc_msgSend"]))
    assert res["APPSTORE-REQUIRED-REASON-API"].status == PASS


def test_rr_selector_only_is_not_determined(run):
    res, _ = ipa_run(run, executable=B.macho(selectors=["systemUptime", "viewDidLoad"]))
    r = res["APPSTORE-REQUIRED-REASON-API"]
    assert r.status == ND and "ProcessInfo.systemUptime" in r.evidence[0].detail


def test_rr_selector_declared_passes(run):
    res, _ = ipa_run(run, executable=B.macho(selectors=["activeInputModes"]),
                     files={"PrivacyInfo.xcprivacy": B.privacy_manifest({KB: ["54BD.1"]})})
    assert res["APPSTORE-REQUIRED-REASON-API"].status == PASS


def test_rr_selectors_in_encrypted_binary_are_unreadable(run):
    res, _ = ipa_run(run, executable=B.macho(selectors=["systemUptime"], encrypted=True))
    r = res["APPSTORE-REQUIRED-REASON-API"]
    assert r.status == PASS  # no proven use, and the note says selectors were unreadable
    assert any("encrypted" in e.detail for e in r.evidence)


def test_rr_no_api_no_manifest(run):
    res, _ = ipa_run(run, executable=B.macho(imports=["_objc_msgSend", "_open"]))
    assert res["APPSTORE-REQUIRED-REASON-API"].status == PASS


# --------------------------------------------------------------- privacy manifest validity
def test_pm_absent_is_info(run):
    res, _ = ipa_run(run)
    r = res["APPSTORE-PRIVACY-MANIFEST"]
    assert r.status == FAIL and r.severity == "info"


def test_pm_valid(run):
    res, _ = ipa_run(run, files={"PrivacyInfo.xcprivacy": B.privacy_manifest({UD: ["CA92.1"]})})
    assert res["APPSTORE-PRIVACY-MANIFEST"].status == PASS


@pytest.mark.parametrize("content", [
    b"not a plist",
    B.privacy_manifest({"NSPrivacyAccessedAPICategoryMadeUp": ["CA92.1"]}),
    B.privacy_manifest({UD: ["35F9.1"]}),  # boot-time reason used for user defaults
    B.privacy_manifest({UD: []}),
])
def test_pm_invalid(run, content):
    res, _ = ipa_run(run, files={"PrivacyInfo.xcprivacy": content})
    r = res["APPSTORE-PRIVACY-MANIFEST"]
    assert r.status == FAIL and r.severity == "warning"


# --------------------------------------------------------------- listed SDKs
def test_listed_sdk_without_manifest(run):
    res, _ = ipa_run(run, files=B.framework("Alamofire", B.macho()))
    r = res["APPSTORE-THIRD-PARTY-SDK"]
    assert r.status == FAIL and r.severity == "warning" and "Alamofire.framework" in r.evidence[0].path


def test_listed_sdk_with_manifest(run):
    res, _ = ipa_run(run, files=B.framework("Alamofire", B.macho(), B.privacy_manifest({})))
    assert res["APPSTORE-THIRD-PARTY-SDK"].status == PASS


def test_listed_sdk_with_nested_resource_bundle_manifest(run):
    files = B.framework("SDWebImage", B.macho())
    files["Frameworks/SDWebImage.framework/SDWebImage.bundle/PrivacyInfo.xcprivacy"] = B.privacy_manifest({})
    res, _ = ipa_run(run, files=files)
    assert res["APPSTORE-THIRD-PARTY-SDK"].status == PASS


def test_unlisted_framework_ignored(run):
    res, _ = ipa_run(run, files=B.framework("MyOwnKit", B.macho()))
    assert res["APPSTORE-THIRD-PARTY-SDK"].status == NA


def test_listed_sdk_name_is_case_sensitive(run):
    res, _ = ipa_run(run, files=B.framework("alamofire", B.macho()))
    assert res["APPSTORE-THIRD-PARTY-SDK"].status == NA


# --------------------------------------------------------------- ATS
def test_ats_arbitrary_loads(run):
    res, _ = ipa_run(run, info={"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}})
    assert res["APPSTORE-ATS"].status == FAIL and res["APPSTORE-ATS"].severity == "warning"


def test_ats_arbitrary_loads_ignored_with_web_content_key(run):
    res, _ = ipa_run(run, info={"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True,
                                                           "NSAllowsArbitraryLoadsInWebContent": True}})
    assert res["APPSTORE-ATS"].status == FAIL and res["APPSTORE-ATS"].severity == "info"


def test_ats_exception_domain(run):
    res, _ = ipa_run(run, info={"NSAppTransportSecurity": {"NSExceptionDomains": {
        "example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}}}})
    r = res["APPSTORE-ATS"]
    assert r.status == FAIL and r.severity == "info" and "example.com" in r.evidence[0].value


@pytest.mark.parametrize("ats", [None, {}, {"NSAllowsArbitraryLoads": False}])
def test_ats_ok(run, ats):
    info = {} if ats is None else {"NSAppTransportSecurity": ats}
    res, _ = ipa_run(run, info=info)
    assert res["APPSTORE-ATS"].status == PASS


def test_ats_in_extension(run):
    ext_info = plistlib.dumps({"CFBundleExecutable": "Ext", "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}})
    res, _ = ipa_run(run, files={"PlugIns/Ext.appex/Info.plist": ext_info, "PlugIns/Ext.appex/Ext": B.macho()})
    assert res["APPSTORE-ATS"].status == FAIL and "Ext.appex" in res["APPSTORE-ATS"].evidence[0].path


# --------------------------------------------------------------- purpose strings
def test_purpose_string_empty(run):
    res, _ = ipa_run(run, info={"NSCameraUsageDescription": "  "}, executable=B.macho(entitlements={}))
    r = res["APPSTORE-PURPOSE-STRINGS"]
    assert r.status == FAIL and "NSCameraUsageDescription" in r.evidence[0].value


def test_purpose_string_empty_but_localized_is_not_determined(run):
    res, _ = ipa_run(run, info={"NSCameraUsageDescription": ""}, executable=B.macho(entitlements={}),
                     files={"en.lproj/InfoPlist.strings": b'"NSCameraUsageDescription" = "Scan documents";'})
    assert res["APPSTORE-PURPOSE-STRINGS"].status == ND


@pytest.mark.parametrize("ent,keys,status", [
    ({"com.apple.developer.healthkit": True}, {}, FAIL),
    ({"com.apple.developer.healthkit": True}, {"NSHealthShareUsageDescription": "Read steps"}, PASS),
    ({"com.apple.developer.homekit": True}, {}, FAIL),
    ({"com.apple.developer.nfc.readersession.formats": ["TAG"]}, {}, FAIL),
    ({"com.apple.developer.nfc.readersession.formats": ["TAG"]}, {"NFCReaderUsageDescription": "Read tags"}, PASS),
    ({"com.apple.developer.siri": True}, {}, PASS),  # Siri intents do not need NSSiriUsageDescription
])
def test_purpose_strings_from_entitlements(run, ent, keys, status):
    res, _ = ipa_run(run, info=keys, executable=B.macho(entitlements=ent))
    assert res["APPSTORE-PURPOSE-STRINGS"].status == status


def test_purpose_strings_unsigned_binary_not_determined(run):
    res, _ = ipa_run(run, executable=B.macho())
    assert res["APPSTORE-PURPOSE-STRINGS"].status == ND


# --------------------------------------------------------------- structure
def test_ipa_without_app_is_input_error(tmp_path):
    import io
    import zipfile

    from narvy.store_check.analyze import InputError, analyze
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Payload/A.app/Info.plist", b"garbage")
    p = tmp_path / "x.ipa"
    p.write_bytes(buf.getvalue())
    with pytest.raises(InputError):
        analyze(str(p))


def test_non_macho_executable_is_not_determined(run):
    res, _ = ipa_run(run, executable=b"#!/bin/sh\necho hi\n" * 10)
    assert res["APPSTORE-REQUIRED-REASON-API"].status == ND
