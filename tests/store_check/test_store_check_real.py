"""Regression test on real binaries (skipped unless NARVY_STORE_CHECK_CORPUS
points to a directory that holds them).

Every expected blocker below was verified independently on 2026-10-04:
targetSdkVersion and android:debuggable with `aapt dump badging/xmltree`,
16 KB ELF alignment with `llvm-readelf -lW`, iOS SDK / minimum OS with plistlib
and `llvm-objdump --macho --private-headers`, required-reason imports with
`llvm-nm -u` (identical on all 255 Mach-O files of the IPA corpus).
"""
import datetime as dt
import os

import pytest

from narvy.store_check.analyze import analyze

T = os.path.join(os.environ.get("NARVY_STORE_CHECK_CORPUS", "/nonexistent"), "")
AS_OF = dt.date(2026, 10, 4)

# file -> {check_id: (status, severity or None)}
EXPECTED = {
    "InsecureBankv2.apk": {"PLAY-TARGET-SDK": ("fail", "blocker"), "PLAY-DEBUGGABLE": ("fail", "blocker"),
                           "PLAY-PERMISSION-DECLARATION": ("fail", "warning"), "PLAY-CLEARTEXT": ("fail", "warning")},
    "sieve.apk": {"PLAY-TARGET-SDK": ("fail", "blocker"), "PLAY-DEBUGGABLE": ("fail", "blocker")},
    "com.termux.apk": {"PLAY-TARGET-SDK": ("fail", "blocker"), "PLAY-16KB-ELF": ("fail", "warning"),
                       "PLAY-DEBUGGABLE": ("pass", None), "PLAY-EXPORTED": ("not_applicable", None)},
    "bitwarden.apk": {"PLAY-16KB-ELF": ("fail", "warning")},
    "signal.apk": {"PLAY-16KB-ELF": ("pass", None), "PLAY-DEBUGGABLE": ("pass", None)},
    "org.wikipedia.apk": {"PLAY-TARGET-SDK": ("pass", None), "PLAY-EXPORTED": ("pass", None),
                          "PLAY-DEBUGGABLE": ("pass", None)},
    "com.whatsapp.xapk": {"PLAY-TARGET-SDK": ("fail", "blocker"), "PLAY-16KB-ELF": ("pass", None),
                          "PLAY-16KB-ZIPALIGN": ("pass", None), "PLAY-CLEARTEXT": ("fail", "warning")},
    "aabs/fcc.aab": {"PLAY-TARGET-SDK": ("fail", "blocker"), "PLAY-16KB-ZIPALIGN": ("not_applicable", None),
                     "PLAY-CLEARTEXT": ("pass", None)},
    "DVIA-v2.ipa": {"APPSTORE-SDK-VERSION": ("fail", "blocker"), "APPSTORE-MIN-OS": ("fail", "blocker"),
                    "APPSTORE-REQUIRED-REASON-API": ("fail", "warning"), "APPSTORE-ATS": ("fail", "warning"),
                    "APPSTORE-THIRD-PARTY-SDK": ("fail", "warning")},
    "iGoat-Swift.ipa": {"APPSTORE-SDK-VERSION": ("fail", "blocker"), "APPSTORE-MIN-OS": ("fail", "blocker")},
    "org.videolan.vlc-ios_650377962_3.7.1.ipa": {"APPSTORE-SDK-VERSION": ("fail", "blocker"),
                                                  "APPSTORE-MIN-OS": ("fail", "blocker"),
                                                  "APPSTORE-PURPOSE-STRINGS": ("pass", None)},
    "com.shazam.Shazam_284993459_26.5.0.ipa": {"APPSTORE-SDK-VERSION": ("pass", None), "APPSTORE-MIN-OS": ("pass", None),
                                               "APPSTORE-ATS": ("pass", None)},
    "com.brave.ios.browser_1052879175_1.87.ipa": {"APPSTORE-SDK-VERSION": ("pass", None),
                                                  "APPSTORE-THIRD-PARTY-SDK": ("fail", "warning"),
                                                  "APPSTORE-PURPOSE-STRINGS": ("pass", None)},
}


@pytest.mark.real
@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_real_binary(name):
    path = T + name
    if not os.path.exists(path):
        pytest.skip("real binary not present")
    rep = analyze(path, as_of=AS_OF)
    by = {r.check_id: r for r in rep.results}
    for cid, (status, sev) in EXPECTED[name].items():
        assert by[cid].status == status, (cid, by[cid].message["en"])
        if sev:
            assert by[cid].severity == sev, cid


@pytest.mark.real
def test_no_blocker_on_current_store_builds():
    """IPAs downloaded from the App Store in 2026 and built with the iOS 26 SDK
    were accepted by App Store Connect: none of our checks may call them blocked."""
    names = ["ch.protonmail.protonmail_979659905_7.8.0.ipa", "com.audible.iphone_379693831_4.65.2.ipa",
             "com.brave.ios.browser_1052879175_1.87.ipa", "com.shazam.Shazam_284993459_26.5.0.ipa",
             "com.wearezeta.zclient.ios_930944768_4.15.1.ipa", "org.mozilla.ios.Firefox_989804926_148.3.ipa"]
    present = [n for n in names if os.path.exists(T + n)]
    if not present:
        pytest.skip("real binaries not present")
    for n in present:
        rep = analyze(T + n, as_of=AS_OF)
        blockers = [r.check_id for r in rep.results if r.status == "fail" and r.severity == "blocker"]
        assert blockers == [], (n, blockers)
