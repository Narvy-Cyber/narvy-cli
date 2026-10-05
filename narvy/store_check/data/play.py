"""Google Play requirements, transcribed from Google's official pages.

Every value below was read on 2026-10-04 from the URL next to it. When Google
publishes a new deadline, update this file and its test; nothing is fetched at
analysis time.
"""
from __future__ import annotations

import datetime as _dt

RETRIEVED = "2026-10-04"

# --- Target API level -------------------------------------------------------
# https://developer.android.com/google/play/requirements/target-sdk
# (page "Last updated 2026-10-01 UTC"):
#   "Starting August 31, 2026: New apps and app updates must target Android 16
#    (API level 36) or higher to be submitted to Google Play; except for Wear OS
#    and Android Automotive OS apps, which must target Android 15 (API level 35)
#    or higher, and Android TV and Android XR apps, which must target Android 14
#    (API level 34) or higher."
#   "If you need more time to update your app, you'll be able to request an
#    extension to November 1, 2026."
# The 2025 row is the previous requirement, kept so that an --as-of date before
# 2026-08-31 still evaluates correctly. Source: Play Console Help answer 11926878
# ("Starting August 31 2025, new apps and app updates must target Android 15
# (API level 35) or higher ...; except for Wear OS, Android Automotive OS, and
# Android TV apps, which must target Android 14 (API level 34) or higher";
# extension to November 1, 2025).
TARGET_SDK_URL = "https://developer.android.com/google/play/requirements/target-sdk"
TARGET_SDK_TIMELINE = [
    # (effective date, {form factor: minimum targetSdk}, extension date or None)
    (_dt.date(2025, 8, 31), {"phone": 35, "wear": 34, "automotive": 34, "tv": 34}, _dt.date(2025, 11, 1)),
    (_dt.date(2026, 8, 31), {"phone": 36, "wear": 35, "automotive": 35, "tv": 34}, _dt.date(2026, 11, 1)),
]

# --- 16 KB page size ---------------------------------------------------------
# https://developer.android.com/guide/practices/page-sizes
#   "all apps targeting Android 15 (API level 35) and higher must support 16 KB
#    memory page sizes on 64-bit devices on Google Play. Starting February 1,
#    2027, if your app updates don't support 16 KB memory page sizes, you won't
#    be able to release these updates."
#   ELF check: LOAD segments must show "align 2**14" or more (arm64-v8a, x86_64).
#   Zip check: uncompressed shared libraries must be 16 KB aligned in the APK
#   ("zipalign -c -P 16").
PAGE_SIZE_URL = "https://developer.android.com/guide/practices/page-sizes"
PAGE_SIZE_ENFORCED = _dt.date(2027, 2, 1)
PAGE_SIZE_TARGET_SDK = 35
PAGE_SIZE_ABIS = ("arm64-v8a", "x86_64")
PAGE_SIZE_ALIGN = 1 << 14

# --- Android 12 exported components ------------------------------------------
# https://developer.android.com/about/versions/12/behavior-changes-12#exported
#   "If your app targets Android 12 or higher and contains activities, services,
#    or broadcast receivers that use intent filters, you must explicitly declare
#    the android:exported attribute ... your app can't be installed on a device
#    that runs Android 12 or higher."
EXPORTED_URL = "https://developer.android.com/about/versions/12/behavior-changes-12#exported"

# --- Foreground service types (Android 14) -----------------------------------
# https://developer.android.com/develop/background-work/services/fgs/service-types
# https://developer.android.com/about/versions/14/changes/fgs-types-required
# https://support.google.com/googleplay/android-developer/answer/13392821
# Flag values from AOSP core/res/res/values/attrs_manifest.xml (attr
# foregroundServiceType), permission names from the service-types page.
FGS_URL = "https://developer.android.com/about/versions/14/changes/fgs-types-required"
FGS_TYPES_URL = "https://developer.android.com/develop/background-work/services/fgs/service-types"
FGS_PLAY_URL = "https://support.google.com/googleplay/android-developer/answer/13392821"
FGS_FLAGS = {
    0x01: "dataSync",
    0x02: "mediaPlayback",
    0x04: "phoneCall",
    0x08: "location",
    0x10: "connectedDevice",
    0x20: "mediaProjection",
    0x40: "camera",
    0x80: "microphone",
    0x100: "health",
    0x200: "remoteMessaging",
    0x400: "systemExempted",
    0x800: "shortService",
    0x1000: "fileManagement",
    0x2000: "mediaProcessing",
    0x40000000: "specialUse",
}
FGS_PERMISSION = {
    "camera": "android.permission.FOREGROUND_SERVICE_CAMERA",
    "connectedDevice": "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
    "dataSync": "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    "health": "android.permission.FOREGROUND_SERVICE_HEALTH",
    "location": "android.permission.FOREGROUND_SERVICE_LOCATION",
    "mediaPlayback": "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK",
    "mediaProcessing": "android.permission.FOREGROUND_SERVICE_MEDIA_PROCESSING",
    "mediaProjection": "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
    "microphone": "android.permission.FOREGROUND_SERVICE_MICROPHONE",
    "phoneCall": "android.permission.FOREGROUND_SERVICE_PHONE_CALL",
    "remoteMessaging": "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING",
    "specialUse": "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
    "systemExempted": "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED",
    # shortService: no type-specific permission (only FOREGROUND_SERVICE).
}

# --- Permissions that need a Play Console declaration -------------------------
# https://support.google.com/googleplay/android-developer/answer/16558241
#   (Permissions and APIs that Access Sensitive Information) and the topic
# https://support.google.com/googleplay/android-developer/topic/12798286
PERMISSIONS_POLICY_URL = "https://support.google.com/googleplay/android-developer/answer/16558241"
DECLARATION_FORM_URL = "https://support.google.com/googleplay/android-developer/answer/9214102"
_SMS_CALLLOG_URL = "https://support.google.com/googleplay/android-developer/answer/10208820"
_BG_LOC_URL = "https://support.google.com/googleplay/android-developer/answer/9799150"
_ALL_FILES_URL = "https://support.google.com/googleplay/android-developer/answer/10467955"
_QAP_URL = "https://support.google.com/googleplay/android-developer/answer/10158779"
_RIP_URL = "https://support.google.com/googleplay/android-developer/answer/12085295"
_FSI_URL = "https://support.google.com/googleplay/android-developer/answer/13392821"
_A11Y_URL = "https://support.google.com/googleplay/android-developer/answer/10964491"

DECLARED_PERMISSIONS = {
    # permission: (group label, policy URL, extra condition key or None)
    "android.permission.READ_SMS": ("SMS", _SMS_CALLLOG_URL, None),
    "android.permission.SEND_SMS": ("SMS", _SMS_CALLLOG_URL, None),
    "android.permission.WRITE_SMS": ("SMS", _SMS_CALLLOG_URL, None),
    "android.permission.RECEIVE_SMS": ("SMS", _SMS_CALLLOG_URL, None),
    "android.permission.RECEIVE_WAP_PUSH": ("SMS", _SMS_CALLLOG_URL, None),
    "android.permission.RECEIVE_MMS": ("SMS", _SMS_CALLLOG_URL, None),
    "android.permission.READ_CALL_LOG": ("Call Log", _SMS_CALLLOG_URL, None),
    "android.permission.WRITE_CALL_LOG": ("Call Log", _SMS_CALLLOG_URL, None),
    "android.permission.PROCESS_OUTGOING_CALLS": ("Call Log", _SMS_CALLLOG_URL, None),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("Background location", _BG_LOC_URL, None),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("All files access", _ALL_FILES_URL, None),
    "android.permission.QUERY_ALL_PACKAGES": ("Package visibility", _QAP_URL, None),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Request install packages", _RIP_URL, None),
    "android.permission.USE_FULL_SCREEN_INTENT": ("Full-screen intent", _FSI_URL, "target34"),
    "android.permission.USE_EXACT_ALARM": ("Exact alarm", PERMISSIONS_POLICY_URL, None),
    "android.permission.READ_MEDIA_IMAGES": ("Photo and video", PERMISSIONS_POLICY_URL, None),
    "android.permission.READ_MEDIA_VIDEO": ("Photo and video", PERMISSIONS_POLICY_URL, None),
}
HEALTH_PERMISSION_PREFIX = "android.permission.health."
HEALTH_URL = PERMISSIONS_POLICY_URL
ACCESSIBILITY_BIND = "android.permission.BIND_ACCESSIBILITY_SERVICE"
ACCESSIBILITY_URL = _A11Y_URL

# --- Debuggable --------------------------------------------------------------
# https://developer.android.com/studio/publish/preparing#publishing-configure
#   (remove android:debuggable before release); Play Console rejects uploads of
#   debuggable APKs/bundles ("You uploaded a debuggable APK or Android App Bundle").
DEBUGGABLE_URL = "https://developer.android.com/studio/publish/preparing#publishing-configure"

# --- Cleartext traffic ---------------------------------------------------------
# https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic
#   default "true" for targetSdk <= 27, "false" for >= 28; ignored on Android 7.0+
#   when a network security config is present.
# https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted
CLEARTEXT_URL = "https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted"
CLEARTEXT_MANIFEST_URL = "https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic"


def target_requirement(as_of: _dt.date, form_factor: str):
    """Return (min_target, effective_date, extension_date) in force on as_of, or None."""
    current = None
    for eff, mins, ext in TARGET_SDK_TIMELINE:
        if as_of >= eff:
            current = (mins[form_factor], eff, ext)
    return current
