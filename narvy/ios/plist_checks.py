"""Info.plist and entitlements checks: ATS, URL schemes and Universal Links."""
from __future__ import annotations

import glob
import os
import plistlib
from typing import Any, Dict, List, Optional, Tuple

from .third_party_filter import is_ios_vendor_dir_path

_SYSTEM_URL_SCHEMES = {
    "http", "https", "mailto", "tel", "sms", "facetime", "facetime-audio",
    "itms-apps", "itms-appss",
}

_WEAK_TLS_VERSIONS = {"TLSv1.0", "TLSv1.1"}


def _rule_def(rule_id: str, name: str, severity: str, cwe: str, masvs: str,
              description: str, recommendation: str) -> Dict[str, Any]:
    return {
        "id": rule_id,
        "name": name,
        "severity": severity,
        "details": {
            "cwe": cwe,
            "masvs": masvs,
            "description": description,
            "recommendation": recommendation,
        },
    }


_RULE_DEFS: Dict[str, Dict[str, Any]] = {
    d["id"]: d for d in [
        _rule_def(
            "IOS-PLIST-ATS-001", "ATS Allows Arbitrary Loads (HTTP Everywhere)",
            "HIGH", "CWE-319", "MSTG-NETWORK-1",
            "NSAllowsArbitraryLoads is true in NSAppTransportSecurity, disabling App Transport Security app-wide. The app can connect over insecure HTTP and with weak/legacy TLS settings to any host.",
            "Remove NSAllowsArbitraryLoads (or set it to false) and use NSExceptionDomains for the specific hosts that genuinely need an exception, with the narrowest exception flags possible.",
        ),
        _rule_def(
            "IOS-PLIST-ATS-002", "ATS Allows Arbitrary Loads in Web Content",
            "MEDIUM", "CWE-319", "MSTG-NETWORK-1",
            "NSAllowsArbitraryLoadsInWebContent is true, letting WKWebView/UIWebView load insecure HTTP sub-resources even though top-level ATS is otherwise enforced. Enables mixed-content attacks against content rendered in the app's own WebViews.",
            "Set NSAllowsArbitraryLoadsInWebContent to false unless the app must render arbitrary third-party web content that cannot be upgraded to HTTPS.",
        ),
        _rule_def(
            "IOS-PLIST-ATS-003", "ATS Exception Domain Allows Insecure HTTP",
            "MEDIUM", "CWE-319", "MSTG-NETWORK-1",
            "An NSExceptionDomains entry sets NSExceptionAllowsInsecureHTTPLoads to true for a specific domain, permitting cleartext HTTP traffic to that host.",
            "Use HTTPS for this domain and remove the exception. If the domain genuinely cannot support TLS, treat all traffic to it as untrusted/interceptable.",
        ),
        _rule_def(
            "IOS-PLIST-ATS-004", "ATS Exception Domain Allows Weak TLS Version",
            "HIGH", "CWE-326", "MSTG-NETWORK-2",
            "An NSExceptionDomains entry sets NSExceptionMinimumTLSVersion to TLSv1.0 or TLSv1.1, both deprecated and vulnerable to known protocol-level attacks (e.g. POODLE, BEAST).",
            "Set NSExceptionMinimumTLSVersion to TLSv1.2 or higher, or remove the exception entirely if the server supports modern TLS.",
        ),
        _rule_def(
            "IOS-PLIST-URL-001", "Custom URL Scheme Declared",
            "LOW", "CWE-284", "MSTG-PLATFORM-3",
            "The app registers one or more custom (non-system) URL schemes via CFBundleURLTypes. Any other installed app can invoke these schemes, making the handler part of the app's attack surface (deep link hijacking / spoofed invocation) - this is an attack-surface note, not by itself a proven vulnerability. See the app's URL/deep-link handler source for whether incoming URLs are validated.",
            "Validate the source of incoming URLs where possible (options[.sourceApplication] on iOS <9, or treat all incoming custom-scheme URLs as untrusted input). Prefer Universal Links for anything security-sensitive.",
        ),
        _rule_def(
            "IOS-PLIST-URL-002", "Custom URL Schemes Without Universal Links",
            "MEDIUM", "CWE-284", "MSTG-PLATFORM-3",
            "The app declares custom URL scheme(s) via CFBundleURLTypes but its entitlements do not declare a corresponding applinks: Universal Link domain. Universal Links are strictly more secure for deep linking (they require the destination domain to serve a signed apple-app-site-association file, so only the verified domain owner can trigger them - unlike a custom scheme, which any app can register).",
            "Implement Universal Links (com.apple.developer.associated-domains with an applinks: entry) for any deep-link flow that carries sensitive actions (login, payment, account changes), and treat the custom scheme as a legacy/best-effort fallback only.",
        ),
        _rule_def(
            "IOS-PLIST-URL-003", "Wildcard Universal Link Domain",
            "MEDIUM", "CWE-284", "MSTG-PLATFORM-3",
            "An applinks: entry in com.apple.developer.associated-domains uses a wildcard domain (*.example.com). Any subdomain - including ones the app owner does not control or has forgotten about - can trigger Universal Link handling in the app.",
            "Use specific, fully-qualified domains instead of a wildcard. If a wildcard is genuinely required, validate the host explicitly in the Universal Link handler before acting on it.",
        ),
    ]
}


def get_rule_defs() -> List[Dict[str, Any]]:
    """All rule definitions this module can emit, for SARIF."""
    return list(_RULE_DEFS.values())


def _find_own_info_plists(source_dir: str) -> List[str]:
    """Info.plist files under source_dir, excluding vendored and build trees."""
    results = []
    for path in glob.iglob(os.path.join(source_dir, "**", "Info.plist"), recursive=True):
        rel = os.path.relpath(path, source_dir)
        if is_ios_vendor_dir_path(rel):
            continue
        results.append(path)
    return results


def _find_entitlements_for(info_plist_path: str, source_dir: str,
                            _all_entitlements_cache: List[str]) -> Optional[str]:
    """Best-effort entitlements file for an Info.plist (same directory first), or None."""
    same_dir = os.path.dirname(info_plist_path)
    local_matches = glob.glob(os.path.join(same_dir, "*.entitlements"))
    if local_matches:
        return local_matches[0]
    return _all_entitlements_cache[0] if _all_entitlements_cache else None


def _all_entitlements(source_dir: str) -> List[str]:
    results = []
    for path in glob.iglob(os.path.join(source_dir, "**", "*.entitlements"), recursive=True):
        rel = os.path.relpath(path, source_dir)
        if is_ios_vendor_dir_path(rel):
            continue
        results.append(path)
    return results


def _load_plist(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


def _check_ats(ats: Dict[str, Any], rel_path: str) -> List[Dict[str, Any]]:
    findings = []
    if not ats:
        # No ATS block means the iOS default (strict, HTTPS-only) applies.
        return findings

    if ats.get("NSAllowsArbitraryLoads"):
        findings.append(_make_finding("IOS-PLIST-ATS-001", rel_path, 1))

    if ats.get("NSAllowsArbitraryLoadsInWebContent"):
        findings.append(_make_finding("IOS-PLIST-ATS-002", rel_path, 1))

    exception_domains = ats.get("NSExceptionDomains", {}) or {}
    if isinstance(exception_domains, dict):
        for domain, config in exception_domains.items():
            if not isinstance(config, dict):
                continue
            if config.get("NSExceptionAllowsInsecureHTTPLoads"):
                findings.append(_make_finding(
                    "IOS-PLIST-ATS-003", rel_path, 1,
                    extra_desc=f' Domain: "{domain}".'))
            if config.get("NSExceptionMinimumTLSVersion") in _WEAK_TLS_VERSIONS:
                tls = config.get("NSExceptionMinimumTLSVersion")
                findings.append(_make_finding(
                    "IOS-PLIST-ATS-004", rel_path, 1,
                    extra_desc=f' Domain: "{domain}", version: {tls}.'))
    return findings


def _declared_url_schemes(plist_content: Dict[str, Any]) -> List[str]:
    schemes = []
    for url_type in (plist_content.get("CFBundleURLTypes") or []):
        if not isinstance(url_type, dict):
            continue
        for scheme in (url_type.get("CFBundleURLSchemes") or []):
            if isinstance(scheme, str) and scheme.strip():
                schemes.append(scheme.strip())
    return schemes


def _check_url_schemes_and_universal_links(
        plist_content: Dict[str, Any], rel_plist_path: str,
        entitlements: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    schemes = _declared_url_schemes(plist_content)
    custom_schemes = [s for s in schemes if s.lower() not in _SYSTEM_URL_SCHEMES]
    if not custom_schemes:
        return findings

    findings.append(_make_finding(
        "IOS-PLIST-URL-001", rel_plist_path, 1,
        extra_desc=f' Declared scheme(s): {", ".join(custom_schemes)}.'))

    if entitlements is None:
        # Universal Links live in entitlements only; without one they can't be ruled out.
        return findings

    domains = entitlements.get("com.apple.developer.associated-domains", []) or []
    applinks_domains = [
        d[len("applinks:"):] for d in domains
        if isinstance(d, str) and d.startswith("applinks:")
    ]
    if not applinks_domains:
        findings.append(_make_finding(
            "IOS-PLIST-URL-002", rel_plist_path, 1,
            extra_desc=f' Declared scheme(s): {", ".join(custom_schemes)}.'))

    for domain in applinks_domains:
        if domain.startswith("*."):
            findings.append(_make_finding(
                "IOS-PLIST-URL-003", rel_plist_path, 1,
                extra_desc=f' Domain: "{domain}".'))

    return findings


def _make_finding(rule_id: str, file_path: str, line: int,
                   extra_desc: str = "") -> Dict[str, Any]:
    rule = _RULE_DEFS[rule_id]
    details = dict(rule["details"])
    if extra_desc:
        details["description"] = details["description"] + extra_desc
    return {
        "rule_id": rule_id,
        "file_path": file_path,
        "name": rule["name"],
        "severity": rule["severity"],
        "line": line,
        "engine": "plist",
        "details": details,
    }


def analyze_plist_and_entitlements(source_dir: str) -> Tuple[List[Dict[str, Any]], List[str], int]:
    """Scan every non-vendored Info.plist. Returns (findings, notes, count)."""
    findings: List[Dict[str, Any]] = []
    notes: List[str] = []

    info_plists = _find_own_info_plists(source_dir)
    if not info_plists:
        return findings, notes, 0

    entitlements_files = _all_entitlements(source_dir)
    if not entitlements_files:
        notes.append(
            "No *.entitlements file found in the repo - Universal Links "
            "checks were skipped for all Info.plist targets (cannot prove "
            "Universal Links are absent without the real entitlements)."
        )

    for plist_path in info_plists:
        rel_plist = os.path.relpath(plist_path, source_dir)
        plist_content = _load_plist(plist_path)
        if plist_content is None:
            continue

        findings.extend(_check_ats(plist_content.get("NSAppTransportSecurity", {}) or {}, rel_plist))

        entitlements_path = _find_entitlements_for(plist_path, source_dir, entitlements_files)
        entitlements = _load_plist(entitlements_path) if entitlements_path else None
        findings.extend(_check_url_schemes_and_universal_links(plist_content, rel_plist, entitlements))

    return findings, notes, len(info_plists)
