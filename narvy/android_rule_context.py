"""Context gates for the Android regex rules: look at the call site or manifest element around a match."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

# PendingIntent flags; jadx emits these as decimals (67108864 / 33554432).
_FLAG_IMMUTABLE = 0x04000000
_FLAG_MUTABLE = 0x02000000

# Runaway guard on how far past the match to look for the closing paren or tag.
_MAX_CALL_SPAN = 4000
_MAX_ELEMENT_SPAN = 20000

_LAUNCHER_CATEGORIES = (
    "android.intent.category.LAUNCHER",
    "android.intent.category.LEANBACK_LAUNCHER",
)


def _balanced_span(content: str, open_index: int, limit: int,
                   opener: str = "(", closer: str = ")") -> Optional[str]:
    """Text between `open_index` and its matching closer, or None if unclosed."""
    depth = 1
    i = open_index
    end = min(len(content), open_index + limit)
    while i < end:
        ch = content[i]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return content[open_index:i]
        i += 1
    return None


def _split_top_level_args(args: str):
    parts, depth, cur = [], 0, ""
    for ch in args:
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        cur += ch
    parts.append(cur)
    return [p.strip() for p in parts]


def _pending_intent_gate(content: str, match: "re.Match",
                         finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """AND-CONF-009: read the flags argument the rule is named after."""
    args = _balanced_span(content, match.end(), _MAX_CALL_SPAN)
    if args is None:
        return finding
    parts = _split_top_level_args(args)
    # flags is the 4th arg of PendingIntent.getActivity(...), last as fallback.
    candidates = []
    if len(parts) >= 4:
        candidates.append(parts[3])
    if parts:
        candidates.append(parts[-1])

    for flag_arg in candidates:
        if not flag_arg:
            continue
        if re.fullmatch(r"-?\d+", flag_arg):
            value = int(flag_arg)
            if value & _FLAG_IMMUTABLE:
                return None
            if value & _FLAG_MUTABLE:
                return _mark_explicit_mutable(finding)
            return finding
        if "FLAG_IMMUTABLE" in flag_arg:
            return None
        if "FLAG_MUTABLE" in flag_arg:
            return _mark_explicit_mutable(finding)
    return finding


def _mark_explicit_mutable(finding: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(finding)
    out["details"] = dict(finding.get("details") or {})
    out["name"] = "PendingIntent Explicitly Created as Mutable"
    out["details"]["description"] = (
        "This PendingIntent is created with FLAG_MUTABLE, so whoever holds it can "
        "fill in the unset parts of the wrapped Intent and have it sent with this "
        "app's identity and permissions. That is sometimes deliberate and necessary "
        "(inline notification replies, Wear OS complications, Slice/Bubble metadata), "
        "but it is the mutability that makes PendingIntent hijacking possible, so the "
        "wrapped Intent must have an explicit component or package set."
    )
    out["details"]["recommendation"] = (
        "Confirm the mutability is required. If it is, make the wrapped Intent "
        "explicit (setComponent/setPackage/setClass) so it cannot be redirected. If "
        "it is not, switch to FLAG_IMMUTABLE."
    )
    return out


def _component_element(content: str, start: int) -> str:
    """The full manifest element starting at `start`, self-closing or not."""
    tag_match = re.match(r"<([\w.\-]+)", content[start:])
    if not tag_match:
        return content[start:start + _MAX_ELEMENT_SPAN]
    tag = tag_match.group(1)
    window = content[start:start + _MAX_ELEMENT_SPAN]
    close = window.find(f"</{tag}>")
    self_close = window.find("/>")
    next_open = window.find("<", 1)
    if self_close != -1 and (next_open == -1 or self_close < next_open):
        return window[:self_close + 2]
    if close != -1:
        return window[:close + len(tag) + 3]
    return window


def _exported_component_gate(content: str, match: "re.Match",
                             finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """AND-CONF-004: a LAUNCHER entry point must be exported."""
    element = _component_element(content, match.start())
    if any(cat in element for cat in _LAUNCHER_CATEGORIES):
        return None
    return finding


# Firebase resource keys are identifiers, not secrets, per Google
# (firebase.google.com/docs/projects/api-keys): graded MEDIUM, not dropped.
_FIREBASE_KEY_RESOURCE_NAMES = (
    "google_api_key", "google_crash_reporting_api_key", "google_app_id",
    "google_maps_key", "com.google.android.geo.api_key",
    "com.google.android.maps.v2.api_key",
)


def _google_api_key_gate(content: str, match: "re.Match",
                         finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    path = (finding.get("file_path") or "").replace("\\", "/").lower()
    line_start = content.rfind("\n", 0, match.start()) + 1
    line_end = content.find("\n", match.end())
    line = content[line_start:line_end if line_end != -1 else len(content)]

    in_google_services = path.endswith("google-services.json")
    named_firebase = any(n in line for n in _FIREBASE_KEY_RESOURCE_NAMES)
    if not (in_google_services or named_firebase):
        return finding

    out = dict(finding)
    out["severity"] = "MEDIUM"
    out["details"] = dict(finding.get("details") or {})
    out["details"]["description"] = (
        "A Google API key generated by the Google Services plugin (google-services.json "
        "-> res/values/strings.xml) is embedded in the app. Google documents this key as "
        "an IDENTIFIER rather than a secret - authorization for Firebase services comes "
        "from Security Rules, IAM and App Check, not from key secrecy - so its mere "
        "presence in the APK is expected and is not by itself an exposure. It is reported "
        "at Medium rather than dropped because the one thing that does make it dangerous "
        "cannot be seen from the binary: if the key is not restricted to this app's "
        "package name and signing-certificate SHA-1, and not restricted to the specific "
        "APIs it needs, anyone can lift it out of the APK and burn quota or billing "
        "against your project (Maps/Places), or reach an unrestricted Identity Toolkit "
        "endpoint."
    )
    out["details"]["recommendation"] = (
        "Open Google Cloud Console -> APIs & Services -> Credentials and confirm this key "
        "has (1) an Android application restriction listing this package name plus the "
        "release signing certificate SHA-1, and (2) an API restriction limiting it to only "
        "the APIs the app actually calls. If both are in place, this is working as "
        "designed and can be accepted. Enable Firebase App Check for the backend services."
    )
    return out


RULE_GATES = {
    "AND-CONF-009": _pending_intent_gate,
    "AND-CONF-004": _exported_component_gate,
    "AND-S-005": _google_api_key_gate,
}


def apply_gate(rule_id: str, content: str, match: "re.Match",
               finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the finding (possibly re-graded) or None to drop it. Never raises."""
    gate = RULE_GATES.get(rule_id)
    if gate is None:
        return finding
    try:
        return gate(content, match, finding)
    except Exception:
        return finding
