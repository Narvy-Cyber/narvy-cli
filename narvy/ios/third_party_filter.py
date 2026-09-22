"""Third-party scoping for iOS: vendor-directory filtering in source mode, and a
three-tier classification of embedded frameworks (first-party/vendor/unconfirmed)."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional, Set, Tuple

from ..scope_config import ScopeConfig, entry_matches, segment_prefix_match

# Matched as exact path segments, never substrings (so "VendoredAssets" is safe).
IOS_VENDOR_DIR_NAMES = frozenset({
    "Pods",
    "Carthage",
    ".swiftpm",
    "Vendor",
    "Vendored",
    "DerivedData",
    ".build",
    "ModuleCache.noindex",
})

# Matched with `startswith`: every entry must be specific enough that no
# first-party framework name can begin with it.
IOS_THIRD_PARTY_FRAMEWORK_PREFIXES = (
    "SwiftUI", "Combine", "Foundation", "UIKit", "CoreFoundation",
    "SwiftProtobuf",
    "Firebase", "FBLPromises", "GoogleUtilities", "GoogleDataTransport",
    "GoogleAppMeasurement", "GTMSessionFetcher", "GTMAppAuth", "GoogleSignIn",
    "GoogleMaps", "GoogleMobileAds", "GoogleToolboxForMac", "nanopb",
    "FBSDKCoreKit", "FBSDKLoginKit", "FBSDKShareKit", "FBSDKGamingServicesKit",
    "FBAEMKit",
    "Alamofire", "AFNetworking", "AlamofireImage",
    "RxSwift", "RxCocoa", "RxRelay", "ReactiveSwift", "ReactiveCocoa",
    "Combine",
    "Realm", "RealmSwift", "SQLite",
    "SDWebImage", "SDWebImageWebPCoder", "Kingfisher", "libwebp",
    "Crashlytics", "Fabric", "Sentry", "Bugsnag", "Mixpanel", "Amplitude",
    "Segment", "AppsFlyerLib", "Adjust", "Branch", "OneSignal",
    "Stripe", "StripeCore", "StripeUICore", "StripePaymentsUI", "Braintree",
    "PayPal",
    "Swinject", "SnapKit", "Then", "SwiftyJSON", "KeychainAccess", "Alamofire",
    "PromiseKit", "Moya", "Result",
    "React", "hermes", "Flutter", "flutter", "Cordova",
    "WebRTC", "GoogleWebRTC",
    "OneSignal", "PushKit",
    "Lottie",
    "Parse", "Bolts",
    "Flurry",
    "HockeySDK", "BITHockeyKit", "Crashlytics",
    "UrbanAirship", "MoPub", "Chartboost", "Vungle", "IronSource", "AppLovin",
    "Tune", "Kochava", "Localytics", "Optimizely", "Appboy", "BrazeKit", "Braze",
    # IQKeyboardManager ships as SPM sub-module frameworks sharing this prefix.
    "IQ",
    "MBProgressHUD", "Masonry", "ReachabilitySwift", "Reachability",
    "TTTAttributedLabel", "MJRefresh", "YYModel", "YYCache", "YYImage",
    "TalsecRuntime", "Talsec", "FreeRasp",
    "GoogleCast",
    "SCSDKCoreKit",
    "SpotifyLogin",
    "TwilioVoice",
    "SSZipArchive",
)


# Reverse-DNS roots take two segments when the leading one is a generic TLD.
_GENERIC_TLD_SEGMENTS = {"com", "org", "io", "net", "edu", "gov", "co"}


def _bundle_id_root(bundle_id: str) -> str:
    segments = [s for s in bundle_id.split(".") if s]
    if not segments:
        return ""
    if segments[0].lower() in _GENERIC_TLD_SEGMENTS and len(segments) >= 2:
        return ".".join(segments[:2]).lower()
    return segments[0].lower()


def bundle_ids_share_reverse_dns_root(bundle_id_a: Optional[str],
                                       bundle_id_b: Optional[str]) -> bool:
    if not bundle_id_a or not bundle_id_b:
        return False
    root_a, root_b = _bundle_id_root(bundle_id_a), _bundle_id_root(bundle_id_b)
    return bool(root_a) and root_a == root_b


# Case-insensitive, checked before the first-party root check. Never "org.cocoapods."
# (stamped on first-party pods too); vendors need their SDK sub-namespace.
IOS_THIRD_PARTY_BUNDLE_ID_PREFIXES = (
    "com.lynxsft.",
    "com.facebook.sdk.",
    "io.sentry.",
    "io.realm.",
    "com.onesignal.",
    "com.braze.",
    "com.bolts.",
    "com.adjust.sdk.",
    "com.applovin.",
    "kingfisher.",
    "com.airbnb.lottie.",
    "com.giphy.",
    "com.google.ads.",
    "com.google.cast",
    "com.fourthline.",
    "authada.",
    "com.plaid.",
    "com.snapchat.",
    "com.spotify.sdk.",
    "com.twilio.",
    "com.ziparchive.",
    "com.sardine.",
    "com.prove.sdk.",
    "com.riskified.",
)
_IOS_THIRD_PARTY_BUNDLE_ID_PREFIXES_LOWER = tuple(
    p.lower() for p in IOS_THIRD_PARTY_BUNDLE_ID_PREFIXES)


def is_ios_vendor_dir_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").split("/")
    return any(part in IOS_VENDOR_DIR_NAMES for part in parts)


_PODFILE_LOCK_POD_RE = re.compile(r'^\s*-\s*([A-Za-z0-9_./+-]+?)(?:\s*\(|\s*$)', re.MULTILINE)

# CocoaPods indents installed pods with exactly 2 spaces, constraints with 4+.
_PODFILE_LOCK_TOP_POD_RE = re.compile(r'^  - ([A-Za-z0-9_./+-]+?)(?:\s+\(([^)]+)\))?:?\s*$')


def _read_podfile_lock_pods_section(repo_root: str) -> Optional[str]:
    lock_path = os.path.join(repo_root, "Podfile.lock")
    if not os.path.isfile(lock_path):
        return None
    try:
        with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return None
    m = re.search(r'^PODS:\s*\n(.*?)(?:\n[A-Z]+:|\Z)', content, re.DOTALL | re.MULTILINE)
    return m.group(1) if m else None


def get_vendored_pod_names(repo_root: str) -> Set[str]:
    section = _read_podfile_lock_pods_section(repo_root)
    if section is None:
        return set()
    pods = set()
    for line in section.splitlines():
        pm = _PODFILE_LOCK_POD_RE.match(line)
        if pm:
            pods.add(pm.group(1).split("/", 1)[0])
    return pods


def get_vendored_pods_with_versions(repo_root: str) -> Dict[str, str]:
    """Top-level pod name to locked installed version, empty if unparseable."""
    section = _read_podfile_lock_pods_section(repo_root)
    if section is None:
        return {}
    pods: Dict[str, str] = {}
    for line in section.splitlines():
        pm = _PODFILE_LOCK_TOP_POD_RE.match(line)
        if not pm:
            continue
        name = pm.group(1).split("/", 1)[0]
        version = pm.group(2)
        if name and version and name not in pods:
            pods[name] = version
    return pods


def get_own_bundle_id(plist: Dict[str, Any]) -> Optional[str]:
    bid = plist.get("CFBundleIdentifier")
    return bid if isinstance(bid, str) and bid else None


def is_third_party_framework_name(name: str) -> bool:
    return any(name == p or name.startswith(p) for p in IOS_THIRD_PARTY_FRAMEWORK_PREFIXES)


TIER_FIRST_PARTY = "first_party"
TIER_THIRD_PARTY = "third_party"
TIER_UNCONFIRMED = "unconfirmed"


def classify_ios_framework(framework_name: str,
                            framework_bundle_id: Optional[str],
                            app_bundle_id: Optional[str]) -> Tuple[str, str]:
    """(tier, reason) for one embedded framework, reason safe to show to a user."""
    # Vendor check first: a bare dylib has no bundle id and would fall to first-party.
    bundle_id_lower = framework_bundle_id.lower() if framework_bundle_id else None

    bundle_hit = bundle_id_lower is not None and any(
        bundle_id_lower.startswith(p) for p in _IOS_THIRD_PARTY_BUNDLE_ID_PREFIXES_LOWER)
    name_hit = is_third_party_framework_name(framework_name)
    if bundle_hit or name_hit:
        signals = []
        if bundle_hit:
            signals.append(f"bundle id {framework_bundle_id!r} matches curated vendor list")
        if name_hit:
            signals.append("framework name matches curated vendor name list")
        return TIER_THIRD_PARTY, "confirmed external vendor SDK (" + "; ".join(signals) + ")"

    if framework_bundle_id is None:
        return TIER_FIRST_PARTY, (
            "no separate bundle id could be read (statically linked framework or "
            "unreadable/absent Info.plist) - cannot isolate as third-party, scanning "
            "as the app's own code rather than risking a false exclusion")

    if bundle_ids_share_reverse_dns_root(framework_bundle_id, app_bundle_id):
        return TIER_FIRST_PARTY, (
            f"bundle id {framework_bundle_id!r} shares its reverse-DNS root with the "
            f"app's own bundle id {app_bundle_id!r}")

    return TIER_UNCONFIRMED, (
        f"bundle id {framework_bundle_id!r} does not share a reverse-DNS root with the "
        f"app's own bundle id {app_bundle_id!r}, and is not on the curated third-party "
        f"vendor list")


def check_ios_override(framework_name: str,
                        framework_bundle_id: Optional[str],
                        config: Optional[ScopeConfig]) -> Optional[str]:
    """'own', 'vendor' or None from a user-declared .narvy-scope.yml ('own' wins)."""
    if not config:
        return None
    name_lower = framework_name.lower()
    bid_lower = framework_bundle_id.lower() if framework_bundle_id else None

    def _hits(patterns) -> bool:
        for entry in patterns:
            if entry_matches(entry, name_lower):
                return True
            if bid_lower and segment_prefix_match(entry, bid_lower):
                return True
        return False

    if _hits(config.own):
        return "own"
    if _hits(config.vendor):
        return "vendor"
    return None
