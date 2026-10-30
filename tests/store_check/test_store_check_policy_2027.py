"""Google Play policy changes effective 2027-01-27 (contacts, precise location,
geofencing in foreground services, READ_CALL_LOG for phone-call verification)
and the VpnService declaration. Positive and negative synthetic cases, before
and after the date, on APK and AAB."""
import datetime as dt

import pytest

import builders as B
from builders import E

FAIL, PASS, ND, NA = "fail", "pass", "not_determined", "not_applicable"
BEFORE = dt.date(2026, 10, 9)
AFTER = dt.date(2027, 1, 27)
CONTACTS = "android.permission.READ_CONTACTS"
FINE = "android.permission.ACCESS_FINE_LOCATION"
COARSE = "android.permission.ACCESS_COARSE_LOCATION"
FGS = "android.permission.FOREGROUND_SERVICE"
CALL_LOG = "android.permission.READ_CALL_LOG"
NEW_IDS = ("PLAY-CONTACTS-PERMISSION", "PLAY-PRECISE-LOCATION", "PLAY-FGS-GEOFENCING", "PLAY-CALL-LOG-VERIFICATION")


def fine(flags=None):
    a = {"android:name": FINE}
    if flags is not None:
        a["android:usesPermissionFlags"] = ("hex", flags)
    return E("uses-permission", a)


def loc_service(types=B.FGS["location"]):
    return E("service", {"android:name": ".TrackService", "android:foregroundServiceType": ("hex", types),
                         "android:exported": False})


def _no_dash(r):
    for d in (r.title, r.message, r.requirement):
        for lang in ("en", "fr"):
            assert "—" not in d[lang] and "–" not in d[lang]


# --------------------------------------------------------------- contacts
@pytest.mark.parametrize("as_of,prefix_en,prefix_fr", [
    (BEFORE, "Required from 2027-01-27: ", "Exigé à partir du 2027-01-27 : "),
    (AFTER, "Play Console declaration needed", "Déclaration Play Console exigée"),
])
def test_contacts_target_37_fails_as_warning_with_dated_title(run, as_of, prefix_en, prefix_fr):
    res, _ = run(B.apk(B.manifest(target=37, perms=[CONTACTS])), as_of=as_of)
    r = res["PLAY-CONTACTS-PERMISSION"]
    assert (r.status, r.severity) == (FAIL, "warning")
    assert r.title["en"].startswith(prefix_en) and r.title["fr"].startswith(prefix_fr)
    assert "target API 37" in r.title["en"] and "Contact Picker" in r.message["en"]
    assert r.evidence[0].value == CONTACTS
    _no_dash(r)


def test_contacts_never_a_blocker_after_the_date(run):
    _res, rep = run(B.apk(B.manifest(target=37, perms=[CONTACTS])), as_of=dt.date(2027, 6, 1))
    assert rep.counts()["blocker"] == 0


@pytest.mark.parametrize("perms,target,status", [
    ([], 37, NA), ([CONTACTS], 36, NA), (["android.permission.WRITE_CONTACTS"], 37, NA), ([CONTACTS], 38, FAIL),
])
def test_contacts_negative_cases(run, perms, target, status):
    res, _ = run(B.apk(B.manifest(target=target, perms=perms)), as_of=AFTER)
    assert res["PLAY-CONTACTS-PERMISSION"].status == status


def test_contacts_on_aab(run):
    res, _ = run(B.aab(B.manifest(target=37, perms=[CONTACTS])), suffix=".aab", as_of=AFTER)
    assert res["PLAY-CONTACTS-PERMISSION"].status == FAIL


def test_contacts_target_unresolved_not_determined(run):
    m = B.manifest(target=None, perms=[CONTACTS])
    m.children[0].attrs["android:targetSdkVersion"] = ("ref", 0x7f0b0001)
    res, _ = run(B.apk(m), as_of=AFTER)
    assert res["PLAY-CONTACTS-PERMISSION"].status == ND


# --------------------------------------------------------------- precise location
@pytest.mark.parametrize("as_of,prefix", [(BEFORE, "Required from 2027-01-27: "), (AFTER, "Play Console declaration needed")])
def test_fine_location_without_flag_needs_declaration(run, as_of, prefix):
    res, _ = run(B.apk(B.manifest(target=37, extra=[fine()])), as_of=as_of)
    r = res["PLAY-PRECISE-LOCATION"]
    assert (r.status, r.severity) == (FAIL, "warning") and r.title["en"].startswith(prefix)
    assert "onlyForLocationButton" in r.message["en"] and "one-time" in r.message["en"]
    _no_dash(r)


def test_fine_location_below_37_still_needs_declaration_button_rule_later(run):
    res, _ = run(B.apk(B.manifest(target=35, perms=[FINE])), as_of=AFTER)
    r = res["PLAY-PRECISE-LOCATION"]
    assert r.status == FAIL and "once the app targets API 37" in r.message["en"]


def test_fine_location_with_only_for_location_button_passes(run):
    res, _ = run(B.apk(B.manifest(target=37, extra=[fine(0x20000)])), as_of=AFTER)
    r = res["PLAY-PRECISE-LOCATION"]
    assert r.status == PASS and "0x20000" in r.evidence[0].detail


def test_fine_location_with_other_flag_fails(run):
    res, _ = run(B.apk(B.manifest(target=37, extra=[fine(0x10000)])), as_of=AFTER)
    assert res["PLAY-PRECISE-LOCATION"].status == FAIL


def test_fine_location_flag_on_aab(run):
    res, _ = run(B.aab(B.manifest(target=37, extra=[fine(0x20000)])), suffix=".aab", as_of=AFTER)
    assert res["PLAY-PRECISE-LOCATION"].status == PASS


def test_coarse_only_not_applicable(run):
    res, _ = run(B.apk(B.manifest(target=37, perms=[COARSE])), as_of=AFTER)
    assert res["PLAY-PRECISE-LOCATION"].status == NA


# --------------------------------------------------------------- geofencing in FGS
@pytest.mark.parametrize("as_of,prefix", [(BEFORE, "Required from 2027-01-27: "), (AFTER, "Geofencing in a foreground service not allowed")])
def test_location_fgs_not_determined(run, as_of, prefix):
    m = B.manifest(target=35, perms=[FGS, "android.permission.FOREGROUND_SERVICE_LOCATION", FINE],
                   app_children=[loc_service()])
    res, _ = run(B.apk(m), as_of=as_of)
    r = res["PLAY-FGS-GEOFENCING"]
    assert (r.status, r.severity) == (ND, "warning") and r.title["en"].startswith(prefix)
    assert "Geofence API" in r.message["en"] and ".TrackService" in r.evidence[0].value
    _no_dash(r)


def test_location_fgs_mixed_types(run):
    m = B.manifest(target=35, perms=[FGS], app_children=[loc_service(B.FGS["location"] | B.FGS["dataSync"])])
    res, _ = run(B.apk(m), as_of=AFTER)
    assert res["PLAY-FGS-GEOFENCING"].status == ND


def test_non_location_fgs_not_applicable(run):
    m = B.manifest(target=35, perms=[FGS, FINE], app_children=[loc_service(B.FGS["mediaPlayback"])])
    res, _ = run(B.apk(m), as_of=AFTER)
    assert res["PLAY-FGS-GEOFENCING"].status == NA


def test_old_target_with_fgs_and_location_not_determined(run):
    res, _ = run(B.apk(B.manifest(target=28, perms=[FGS, COARSE])), as_of=AFTER)
    r = res["PLAY-FGS-GEOFENCING"]
    assert r.status == ND and "< 29" in r.message["en"]


def test_target_29_without_location_type_not_applicable(run):
    res, _ = run(B.apk(B.manifest(target=29, perms=[FGS, COARSE])), as_of=AFTER)
    assert res["PLAY-FGS-GEOFENCING"].status == NA


# --------------------------------------------------------------- READ_CALL_LOG verification
@pytest.mark.parametrize("as_of,prefix", [(BEFORE, "Required from 2027-01-27: "), (AFTER, "READ_CALL_LOG not allowed")])
def test_read_call_log_not_determined(run, as_of, prefix):
    res, _ = run(B.apk(B.manifest(target=36, perms=[CALL_LOG])), as_of=as_of)
    r = res["PLAY-CALL-LOG-VERIFICATION"]
    assert (r.status, r.severity) == (ND, "warning") and r.title["en"].startswith(prefix)
    assert "SMS Retriever" in r.message["en"] and "Digital Credentials" in r.message["en"]
    _no_dash(r)


def test_write_call_log_only_not_applicable(run):
    res, _ = run(B.apk(B.manifest(target=36, perms=["android.permission.WRITE_CALL_LOG"])), as_of=AFTER)
    assert res["PLAY-CALL-LOG-VERIFICATION"].status == NA


# --------------------------------------------------------------- no permission at all
def test_plain_app_has_no_new_finding(run):
    res, rep = run(B.apk(B.manifest(target=36)), as_of=AFTER)
    assert all(res[c].status == NA for c in NEW_IDS)
    assert rep.counts()["blocker"] == 0


def test_ios_has_no_new_rule(run):
    res, _ = run(B.ipa(), suffix=".ipa", as_of=AFTER)
    assert res
    assert not set(res) & set(NEW_IDS)


# --------------------------------------------------------------- VpnService declaration
def vpn_service(perm=True, action=True):
    attrs = {"android:name": ".TunnelService", "android:exported": False}
    if perm:
        attrs["android:permission"] = "android.permission.BIND_VPN_SERVICE"
    kids = [E("intent-filter", {}, [E("action", {"android:name": "android.net.VpnService"})])] if action else []
    return E("service", attrs, kids)


@pytest.mark.parametrize("perm,action", [(True, True), (True, False), (False, True)])
def test_vpn_service_needs_declaration(run, perm, action):
    res, _ = run(B.apk(B.manifest(target=36, app_children=[vpn_service(perm, action)])))
    r = res["PLAY-PERMISSION-DECLARATION"]
    assert (r.status, r.severity) == (FAIL, "warning")
    assert "VpnService" in r.title["en"] and "VpnService" in r.title["fr"]
    assert "https://support.google.com/googleplay/android-developer/answer/12564964" in r.extra_doc_urls
    assert ".TunnelService" in r.evidence[0].value


def test_vpn_service_on_aab(run):
    res, _ = run(B.aab(B.manifest(target=36, app_children=[vpn_service()])), suffix=".aab")
    assert res["PLAY-PERMISSION-DECLARATION"].status == FAIL


def test_ordinary_service_is_not_vpn(run):
    s = E("service", {"android:name": ".Sync", "android:exported": False},
          [E("intent-filter", {}, [E("action", {"android:name": "com.example.SYNC"})])])
    res, _ = run(B.apk(B.manifest(target=36, app_children=[s])))
    assert res["PLAY-PERMISSION-DECLARATION"].status == PASS
