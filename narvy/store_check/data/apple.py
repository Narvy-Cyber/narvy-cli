"""Apple App Store requirements, transcribed from Apple's official pages.

Every value below was read on 2026-10-04 from the URL next to it.
"""
from __future__ import annotations

import datetime as _dt

RETRIEVED = "2026-10-04"

# --- SDK / Xcode minimum for uploads -----------------------------------------
# https://developer.apple.com/news/upcoming-requirements/
#   "Apps uploaded to App Store Connect must be built with Xcode 26 or later
#    using an SDK for iOS 26, iPadOS 26, tvOS 26, visionOS 26, or watchOS 26."
#    (effective April 28, 2026)
#   "Apps uploaded to App Store Connect must be built with Xcode 15 for iOS 17
#    ... starting April 29, 2024." (still listed on the same page)
#   Xcode 16 / iOS 18 SDK from April 24, 2025: Apple news item of that period,
#   no longer listed on the page; referenced in Apple Developer Forums thread
#   https://developer.apple.com/forums/thread/780321. Only used for --as-of
#   dates before 2026-04-28.
SDK_REQ_URL = "https://developer.apple.com/news/upcoming-requirements/"
SDK_TIMELINE = [
    # (effective date, minimum SDK major, minimum Xcode major)
    (_dt.date(2024, 4, 29), 17, 15),
    (_dt.date(2025, 4, 24), 18, 16),
    (_dt.date(2026, 4, 28), 26, 26),
]


# Same page, read 2026-10-04:
#   "iOS and iPadOS minimum system requirements. Since September 9, 2026. iOS and
#    iPadOS apps uploaded to App Store Connect must target iOS 13 or later."
MIN_OS_URL = SDK_REQ_URL
MIN_OS_TIMELINE = [
    (_dt.date(2026, 9, 9), 13),
]


def min_os_requirement(as_of: _dt.date):
    cur = None
    for eff, v in MIN_OS_TIMELINE:
        if as_of >= eff:
            cur = (v, eff)
    return cur


def sdk_requirement(as_of: _dt.date):
    cur = None
    for eff, sdk, xcode in SDK_TIMELINE:
        if as_of >= eff:
            cur = (sdk, xcode, eff)
    return cur


# --- Required reason APIs ----------------------------------------------------
# https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api
#   "Starting May 1, 2024, apps that don't describe their use of required reason
#    API in their privacy manifest file aren't accepted by App Store Connect."
#   "For each executable or dynamic library in an app that uses a required reason
#    API, the bundle that includes the executable or dynamic library needs to
#    include a privacy manifest file that reports the API."
# Category keys, API list and reason codes:
# https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype
REQUIRED_REASON_URL = "https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api"
API_TYPE_URL = ("https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/"
                "nsprivacyaccessedapitypes/nsprivacyaccessedapitype")
PRIVACY_MANIFEST_URL = "https://developer.apple.com/documentation/bundleresources/privacy-manifest-files"
REQUIRED_REASON_ENFORCED = _dt.date(2024, 5, 1)

CAT_FILE_TIMESTAMP = "NSPrivacyAccessedAPICategoryFileTimestamp"
CAT_BOOT_TIME = "NSPrivacyAccessedAPICategorySystemBootTime"
CAT_DISK_SPACE = "NSPrivacyAccessedAPICategoryDiskSpace"
CAT_ACTIVE_KEYBOARDS = "NSPrivacyAccessedAPICategoryActiveKeyboards"
CAT_USER_DEFAULTS = "NSPrivacyAccessedAPICategoryUserDefaults"

REASONS = {
    CAT_FILE_TIMESTAMP: {"DDA9.1", "C617.1", "3B52.1", "0A2A.1"},
    CAT_BOOT_TIME: {"35F9.1", "8FFB.1", "3D61.1"},
    CAT_DISK_SPACE: {"85F4.1", "E174.1", "7D9E.1", "B728.1"},
    CAT_ACTIVE_KEYBOARDS: {"3EC4.1", "54BD.1"},
    CAT_USER_DEFAULTS: {"CA92.1", "1C8F.1", "C56D.1", "AC6B.1"},
}

# Binary-level names of the APIs Apple lists. Imported symbols (Mach-O
# undefined symbols / chained-fixup imports) are exact evidence: the binary
# links against that API.
#   Apple API (as listed)                 -> symbol in the binary
#   FileAttributeKey.creationDate         -> _NSFileCreationDate
#   FileAttributeKey.modificationDate     -> _NSFileModificationDate
#   URLResourceKey.contentModificationDateKey -> _NSURLContentModificationDateKey
#   URLResourceKey.creationDateKey        -> _NSURLCreationDateKey
#   FileAttributeKey.systemFreeSize       -> _NSFileSystemFreeSize
#   FileAttributeKey.systemSize           -> _NSFileSystemSize
#   URLResourceKey.volume*CapacityKey     -> _NSURLVolume*CapacityKey
#   UserDefaults                          -> _OBJC_CLASS_$_NSUserDefaults
#   C functions                           -> leading underscore
# getattrlist / fgetattrlist / getattrlistat are listed by Apple under BOTH
# FileTimestamp and DiskSpace: a reference alone cannot tell which, so they are
# handled as "either category".
SYMBOLS = {
    "_NSFileCreationDate": (CAT_FILE_TIMESTAMP,),
    "_NSFileModificationDate": (CAT_FILE_TIMESTAMP,),
    "_NSURLContentModificationDateKey": (CAT_FILE_TIMESTAMP,),
    "_NSURLCreationDateKey": (CAT_FILE_TIMESTAMP,),
    "_getattrlistbulk": (CAT_FILE_TIMESTAMP,),
    "_stat": (CAT_FILE_TIMESTAMP,),
    "_fstat": (CAT_FILE_TIMESTAMP,),
    "_fstatat": (CAT_FILE_TIMESTAMP,),
    "_lstat": (CAT_FILE_TIMESTAMP,),
    "_getattrlist": (CAT_FILE_TIMESTAMP, CAT_DISK_SPACE),
    "_fgetattrlist": (CAT_FILE_TIMESTAMP, CAT_DISK_SPACE),
    "_getattrlistat": (CAT_FILE_TIMESTAMP, CAT_DISK_SPACE),
    "_mach_absolute_time": (CAT_BOOT_TIME,),
    "_NSURLVolumeAvailableCapacityKey": (CAT_DISK_SPACE,),
    "_NSURLVolumeAvailableCapacityForImportantUsageKey": (CAT_DISK_SPACE,),
    "_NSURLVolumeAvailableCapacityForOpportunisticUsageKey": (CAT_DISK_SPACE,),
    "_NSURLVolumeTotalCapacityKey": (CAT_DISK_SPACE,),
    "_NSFileSystemFreeSize": (CAT_DISK_SPACE,),
    "_NSFileSystemSize": (CAT_DISK_SPACE,),
    "_statfs": (CAT_DISK_SPACE,),
    "_statvfs": (CAT_DISK_SPACE,),
    "_fstatfs": (CAT_DISK_SPACE,),
    "_fstatvfs": (CAT_DISK_SPACE,),
    "_OBJC_CLASS_$_NSUserDefaults": (CAT_USER_DEFAULTS,),
}

# Objective-C/Swift properties Apple lists that are reached through a message
# send. A selector reference proves the binary sends that message, but not to
# which class (the app may define its own method with the same name), so this
# evidence alone never produces a "fail": at most "not determined".
SELECTORS = {
    "systemUptime": (CAT_BOOT_TIME, "ProcessInfo.systemUptime"),
    "activeInputModes": (CAT_ACTIVE_KEYBOARDS, "UITextInputMode.activeInputModes"),
    "fileModificationDate": (CAT_FILE_TIMESTAMP, "UIDocument.fileModificationDate"),
}

# --- Third-party SDKs that must ship a privacy manifest and signature ----------
# https://developer.apple.com/support/third-party-SDK-requirements/
#   "You must include the privacy manifest for any SDK listed below when you
#    submit new apps in App Store Connect that include those SDKs, or when you
#    submit an app update that adds one of the listed SDKs as part of the
#    update. Signatures are also required in these cases where the listed SDKs
#    are used as binary dependencies."
SDK_LIST_URL = "https://developer.apple.com/support/third-party-SDK-requirements/"
LISTED_SDKS = (
    "Abseil", "AFNetworking", "Alamofire", "AppAuth", "BoringSSL", "openssl_grpc", "Capacitor",
    "Charts", "connectivity_plus", "Cordova", "device_info_plus", "DKImagePickerController",
    "DKPhotoGallery", "FBAEMKit", "FBLPromises", "FBSDKCoreKit", "FBSDKCoreKit_Basics",
    "FBSDKLoginKit", "FBSDKShareKit", "file_picker", "FirebaseABTesting", "FirebaseAuth",
    "FirebaseCore", "FirebaseCoreDiagnostics", "FirebaseCoreExtension", "FirebaseCoreInternal",
    "FirebaseCrashlytics", "FirebaseDynamicLinks", "FirebaseFirestore", "FirebaseInstallations",
    "FirebaseMessaging", "FirebaseRemoteConfig", "Flutter", "flutter_inappwebview",
    "flutter_local_notifications", "fluttertoast", "FMDB", "geolocator_apple",
    "GoogleDataTransport", "GoogleSignIn", "GoogleToolboxForMac", "GoogleUtilities", "grpcpp",
    "GTMAppAuth", "GTMSessionFetcher", "hermes", "image_picker_ios", "IQKeyboardManager",
    "IQKeyboardManagerSwift", "Kingfisher", "leveldb", "Lottie", "MBProgressHUD", "nanopb",
    "OneSignal", "OneSignalCore", "OneSignalExtension", "OneSignalOutcomes", "OpenSSL",
    "OrderedSet", "package_info", "package_info_plus", "path_provider", "path_provider_ios",
    "Promises", "Protobuf", "Reachability", "RealmSwift", "RxCocoa", "RxRelay", "RxSwift",
    "SDWebImage", "share_plus", "shared_preferences_ios", "SnapKit", "sqflite", "Starscream",
    "SVProgressHUD", "SwiftyGif", "SwiftyJSON", "Toast", "UnityFramework", "url_launcher",
    "url_launcher_ios", "video_player_avfoundation", "wakelock", "webview_flutter_wkwebview",
)

# --- App Transport Security --------------------------------------------------
# https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads
#   Setting it to YES disables ATS for all domains; App Review requires a
#   justification. On iOS 10+ it is ignored when NSAllowsArbitraryLoadsForMedia,
#   NSAllowsArbitraryLoadsInWebContent or NSAllowsLocalNetworking is present.
ATS_URL = ("https://developer.apple.com/documentation/bundleresources/information-property-list/"
           "nsapptransportsecurity/nsallowsarbitraryloads")
ATS_OVERRIDE_KEYS = ("NSAllowsArbitraryLoadsForMedia", "NSAllowsArbitraryLoadsInWebContent",
                     "NSAllowsLocalNetworking")

# --- Purpose strings ---------------------------------------------------------
# https://developer.apple.com/documentation/uikit/requesting-access-to-protected-resources
# https://developer.apple.com/app-store/review/guidelines/#data-collection-and-storage (5.1.1)
USAGE_URL = "https://developer.apple.com/documentation/uikit/requesting-access-to-protected-resources"
# Entitlement -> Info.plist keys, at least one of which must be present.
#   HealthKit: https://developer.apple.com/documentation/healthkit/setting-up-healthkit
#   HomeKit:   https://developer.apple.com/documentation/bundleresources/information-property-list/nshomekitusagedescription
#   NFC:       https://developer.apple.com/documentation/bundleresources/information-property-list/nfcreaderusagedescription
# Deliberately NOT included: com.apple.developer.siri -> NSSiriUsageDescription.
# The Siri entitlement is also used for intents/shortcuts that never request Siri
# authorization; Audible 4.65.2, Brave 1.87 and VLC 3.7.1 are on the App Store
# with the entitlement and no NSSiriUsageDescription (verified on their IPAs).
ENTITLEMENT_USAGE_KEYS = {
    "com.apple.developer.healthkit": (("NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription"),
                                      "https://developer.apple.com/documentation/healthkit/setting-up-healthkit"),
    "com.apple.developer.homekit": (("NSHomeKitUsageDescription",),
                                    "https://developer.apple.com/documentation/bundleresources/information-property-list/nshomekitusagedescription"),
    "com.apple.developer.nfc.readersession.formats": (("NFCReaderUsageDescription",),
                                                      "https://developer.apple.com/documentation/bundleresources/information-property-list/nfcreaderusagedescription"),
}
