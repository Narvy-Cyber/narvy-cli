"""iOS dependency CVEs from Podfile.lock, Package.resolved and embedded frameworks."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import plistlib
import re
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from .osv_client import OSVClient, get_default_client
from ..ios.third_party_filter import (
    get_vendored_pods_with_versions,
    IOS_THIRD_PARTY_FRAMEWORK_PREFIXES,
    is_third_party_framework_name,
)

logger = logging.getLogger(__name__)


# Zero-network fallback. Every entry must be a real published CVE or GHSA id.
KNOWN_VULNERABLE_IOS_LIBS: Dict[str, List[Dict[str, Any]]] = {
    "AFNetworking": [
        {
            "less_than": "2.6.0",
            "cve": "CVE-2016-4817",
            "severity": "HIGH",
            "title": "AFNetworking SSL certificate validation bypass",
            "description": "AFNetworking before 2.6.0 does not properly validate SSL/TLS "
                            "certificates in certain configurations, allowing man-in-the-middle "
                            "attacks against the app's network traffic.",
            "fixed_version": "2.6.0",
            "cwe": "CWE-295",
        },
    ],
    "Alamofire": [
        {
            "less_than": "4.7.2",
            "cve": "CVE-2018-1000814",
            "severity": "HIGH",
            "title": "Alamofire certificate-pinning bypass",
            "description": "Alamofire before 4.7.2 contains a certificate-pinning bypass that "
                            "can allow a man-in-the-middle attacker to intercept TLS traffic "
                            "the app believed was pinned.",
            "fixed_version": "4.7.2",
            "cwe": "CWE-295",
        },
    ],
    "SDWebImage": [
        {
            "less_than": "5.0.0",
            "cve": "CVE-2019-10752",
            "severity": "HIGH",
            "title": "SDWebImage out-of-bounds read via crafted image",
            "description": "SDWebImage before 5.0.0 is vulnerable to an out-of-bounds read "
                            "when decoding a maliciously crafted image, which can crash the "
                            "app (denial of service) and, depending on memory layout, "
                            "potentially leak adjacent memory contents.",
            "fixed_version": "5.0.0",
            "cwe": "CWE-125",
        },
    ],
}

_GH_API_URL = "https://api.github.com/advisories"
_GH_CACHE_DIR = Path.home() / ".narvy" / "github_advisory_cache"
_GH_CACHE_TTL_SECONDS = 24 * 3600

# GitHub's unauthenticated quota is per-IP, so cap advisory queries per scan.
_GH_MAX_QUERIES_PER_SCAN = 25
_GH_MIN_REMAINING_BUDGET = 5


class _GitHubAdvisoryBudget:
    """Tracks GitHub's unauthenticated rate-limit budget for one scan."""

    def __init__(self):
        self.queries_made = 0
        self.remaining: Optional[int] = None
        self.exhausted = False

    def can_query(self) -> bool:
        if self.exhausted:
            return False
        if self.queries_made >= _GH_MAX_QUERIES_PER_SCAN:
            return False
        if self.remaining is not None and self.remaining <= _GH_MIN_REMAINING_BUDGET:
            return False
        return True

    def record_response(self, resp: requests.Response):
        self.queries_made += 1
        remaining_hdr = resp.headers.get("X-RateLimit-Remaining")
        if remaining_hdr is not None:
            try:
                self.remaining = int(remaining_hdr)
            except ValueError:
                pass
        if resp.status_code == 403 and (self.remaining == 0 or "rate limit" in resp.text.lower()):
            self.exhausted = True
            logger.warning(
                "[SCA] GitHub Advisory API rate limit hit (60/hr unauthenticated) - "
                "stopping further GitHub queries for this scan, continuing with OSV "
                "+ local curated DB only."
            )


def _gh_cache_path(key: str) -> Path:
    _GH_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return _GH_CACHE_DIR / f"{hashlib.md5(key.encode()).hexdigest()}.json"


def _gh_cache_get(key: str) -> Optional[List[Dict[str, Any]]]:
    path = _gh_cache_path(key)
    if not path.exists():
        return None
    try:
        if (time.time() - path.stat().st_mtime) > _GH_CACHE_TTL_SECONDS:
            return None
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _gh_cache_put(key: str, data: List[Dict[str, Any]]):
    try:
        with open(_gh_cache_path(key), "w") as f:
            json.dump(data, f)
    except OSError:
        pass


def _query_github_advisories_swift(library_name: str, budget: _GitHubAdvisoryBudget) -> List[Dict[str, Any]]:
    """Cache-first, budget-gated GitHub Advisory lookup for the Swift ecosystem."""
    cache_key = f"swift:{library_name.lower()}"
    cached = _gh_cache_get(cache_key)
    if cached is not None:
        return cached

    if not budget.can_query():
        return []

    try:
        resp = requests.get(
            _GH_API_URL,
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
            params={"ecosystem": "swift", "affects": library_name, "per_page": 50},
            timeout=15,
        )
        budget.record_response(resp)
        if resp.status_code == 200:
            advisories = resp.json() or []
            _gh_cache_put(cache_key, advisories)
            return advisories
        elif resp.status_code == 404:
            _gh_cache_put(cache_key, [])
            return []
        else:
            logger.debug(f"[SCA] GitHub Advisory API returned {resp.status_code} for {library_name}")
            return []
    except requests.exceptions.RequestException as e:
        logger.debug(f"[SCA] GitHub Advisory query failed for {library_name}: {e}")
        return []


def _cvss_from_vector(vector: str) -> float:
    if not vector or "CVSS:3" not in vector:
        return 0.0
    metrics = {}
    for part in vector.replace('CVSS:3.1/', '').replace('CVSS:3.0/', '').split('/'):
        if ':' in part:
            k, v = part.split(':', 1)
            metrics[k] = v
    av = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}.get(metrics.get('AV', ''), 0.85)
    ac = {'L': 0.77, 'H': 0.44}.get(metrics.get('AC', ''), 0.77)
    scope_changed = metrics.get('S', 'U') == 'C'
    pr_map = {'N': 0.85, 'L': 0.68, 'H': 0.50} if scope_changed else {'N': 0.85, 'L': 0.62, 'H': 0.27}
    pr = pr_map.get(metrics.get('PR', ''), 0.85)
    ui = {'N': 0.85, 'R': 0.62}.get(metrics.get('UI', ''), 0.85)
    c = {'H': 0.56, 'L': 0.22, 'N': 0.0}.get(metrics.get('C', ''), 0.0)
    i = {'H': 0.56, 'L': 0.22, 'N': 0.0}.get(metrics.get('I', ''), 0.0)
    a = {'H': 0.56, 'L': 0.22, 'N': 0.0}.get(metrics.get('A', ''), 0.0)
    exploitability = 8.22 * av * ac * pr * ui
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0:
        return 0.0
    impact = (7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)) if scope_changed else (6.42 * iss)
    if impact <= 0:
        return 0.0
    if scope_changed:
        return min(math.ceil(min(1.08 * (impact + exploitability), 10.0) * 10) / 10, 10.0)
    return min(math.ceil(min(impact + exploitability, 10.0) * 10) / 10, 10.0)


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    if score > 0:
        return 'LOW'
    return 'MEDIUM'


def _parse_github_advisory(advisory: Dict[str, Any], dep_name: str, dep_version: str) -> Optional[Dict[str, Any]]:
    """One GitHub advisory in OSVFinding.to_dict() shape, or None if it doesn't name this package."""
    matched = False
    fixed_version = None
    for vuln in advisory.get('vulnerabilities', []) or []:
        pkg = vuln.get('package', {}) or {}
        if pkg.get('ecosystem', '').lower() != 'swift':
            continue
        if pkg.get('name', '').lower() != dep_name.lower():
            continue
        matched = True
        fpv = vuln.get('first_patched_version') or {}
        if fpv.get('identifier'):
            fixed_version = fpv['identifier']
    if not matched:
        return None

    cve_id = advisory.get('cve_id') or advisory.get('ghsa_id') or 'UNKNOWN'
    cvss = advisory.get('cvss') or {}
    vector = cvss.get('vector_string', '')
    score = _cvss_from_vector(vector) if vector else 0.0
    severity = _score_to_severity(score) if score > 0 else (advisory.get('severity') or 'medium').upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        severity = "MEDIUM"

    cwes = advisory.get('cwes') or []
    cwe = cwes[0].get('cwe_id', 'CWE-1104') if cwes else 'CWE-1104'

    return {
        "cve": cve_id,
        "osv_id": advisory.get('ghsa_id', ''),
        "severity": severity,
        "cvss_score": score,
        "summary": advisory.get('summary', '') or '',
        "details": (advisory.get('description') or '')[:500],
        "fixed_version": fixed_version,
        "references": [r for r in (advisory.get('references') or []) if isinstance(r, str)][:5],
        "cwe": cwe,
        "source": "GitHub Advisory Database",
    }


# Pod name to OSV "SwiftURL" package name (bare `github.com/<owner>/<repo>`) for
# Podfile.lock projects with no source URL. A wrong entry queries the wrong repo.
_POD_NAME_TO_GITHUB_REPO: Dict[str, str] = {
    "AFNetworking": "github.com/AFNetworking/AFNetworking",
    "Alamofire": "github.com/Alamofire/Alamofire",
    "SDWebImage": "github.com/SDWebImage/SDWebImage",
    "Realm": "github.com/realm/realm-swift",
    "RealmSwift": "github.com/realm/realm-swift",
    "Kingfisher": "github.com/onevcat/Kingfisher",
    "SnapKit": "github.com/SnapKit/SnapKit",
    "SwiftyJSON": "github.com/SwiftyJSON/SwiftyJSON",
    "Firebase": "github.com/firebase/firebase-ios-sdk",
    "RxSwift": "github.com/ReactiveX/RxSwift",
    "RxCocoa": "github.com/ReactiveX/RxSwift",
    "Moya": "github.com/Moya/Moya",
    "PromiseKit": "github.com/mxcl/PromiseKit",
    "CryptoSwift": "github.com/krzyzanowskim/CryptoSwift",
    "KeychainSwift": "github.com/evgenyneu/keychain-swift",
    "Sparkle": "github.com/sparkle-project/Sparkle",
    "ZIPFoundation": "github.com/weichsel/ZIPFoundation",
    "lottie-ios": "github.com/airbnb/lottie-ios",
    "SwiftLint": "github.com/realm/SwiftLint",
    "Starscream": "github.com/daltoniam/Starscream",
}


def _normalize_repo_url_to_swifturl_name(url: str) -> Optional[str]:
    """An HTTPS or SSH repo URL as OSV's SwiftURL package-name format."""
    if not url:
        return None
    u = url.strip()
    u = re.sub(r'^(https?://|ssh://)', '', u)
    u = re.sub(r'^git@', '', u)
    if re.match(r'^[^/]+:[^/]', u):
        u = u.replace(':', '/', 1)
    u = u.rstrip('/')
    if u.endswith('.git'):
        u = u[:-4]
    return u or None


@dataclass(frozen=True)
class _IOSDep:
    name: str
    version: str
    source: str
    osv_package_name: Optional[str] = None


def extract_source_dependencies(source_dir: str) -> List[_IOSDep]:
    """Podfile.lock + Package.resolved, for the `ios-source` scan mode."""
    deps: List[_IOSDep] = []

    pods = get_vendored_pods_with_versions(source_dir)
    for name, version in pods.items():
        osv_name = _POD_NAME_TO_GITHUB_REPO.get(name)
        deps.append(_IOSDep(name=name, version=version, source="podfile.lock", osv_package_name=osv_name))

    for resolved_path in _find_package_resolved_files(source_dir):
        deps.extend(_parse_package_resolved(resolved_path))

    return deps


_PKG_RESOLVED_MAX_DEPTH = 8
_VENDOR_DIR_SKIP = {"Pods", "Carthage", "DerivedData", ".build", "ModuleCache.noindex", ".git", "node_modules"}


def _find_package_resolved_files(source_dir: str) -> List[str]:
    found = []
    base_depth = source_dir.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(source_dir):
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _PKG_RESOLVED_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _VENDOR_DIR_SKIP]
        if "Package.resolved" in files:
            found.append(os.path.join(root, "Package.resolved"))
    return found


def _parse_package_resolved(path: str) -> List[_IOSDep]:
    """Dependencies from a Package.resolved, in either SwiftPM lockfile schema."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.debug(f"[SCA] Could not parse {path}: {e}")
        return deps

    pins = data.get("pins")
    if pins is None:
        pins = (data.get("object") or {}).get("pins", [])

    for pin in pins or []:
        name = pin.get("identity") or pin.get("package")
        state = pin.get("state") or {}
        version = state.get("version")
        location = pin.get("location") or pin.get("repositoryURL") or ""
        if name and version:
            osv_name = _normalize_repo_url_to_swifturl_name(location) or _POD_NAME_TO_GITHUB_REPO.get(name)
            deps.append(_IOSDep(name=name, version=version, source="package.resolved", osv_package_name=osv_name))
    return deps


def extract_binary_dependencies(ipa_path: str) -> List[_IOSDep]:
    """Embedded Frameworks/*/Info.plist, scoped to known third-party SDK names."""
    deps: List[_IOSDep] = []
    try:
        with zipfile.ZipFile(ipa_path, "r") as ipa:
            framework_plists = [
                n for n in ipa.namelist()
                if "Frameworks/" in n and n.endswith("/Info.plist")
            ]
            for plist_path in framework_plists:
                parts = plist_path.split("/")
                framework_folder = next((p for p in parts if p.endswith(".framework")), None)
                if not framework_folder:
                    continue
                framework_name = framework_folder[: -len(".framework")]
                if not is_third_party_framework_name(framework_name):
                    continue
                try:
                    plist_dict = plistlib.loads(ipa.read(plist_path))
                except Exception:
                    continue
                version = (plist_dict.get("CFBundleShortVersionString")
                           or plist_dict.get("CFBundleVersion"))
                if not version:
                    continue
                osv_name = _POD_NAME_TO_GITHUB_REPO.get(framework_name)
                deps.append(_IOSDep(name=framework_name, version=str(version),
                                     source="framework", osv_package_name=osv_name))
    except (zipfile.BadZipFile, OSError) as e:
        logger.error(f"[SCA] Error reading {ipa_path}: {e}")
    return deps


def _severity_style_default(sev: str) -> str:
    sev = (sev or "MEDIUM").upper()
    return sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"


def _finding_from_cve(dep: _IOSDep, cve_dict: Dict[str, Any], source_label: str) -> Dict[str, Any]:
    cve_id = cve_dict.get("cve") or cve_dict.get("osv_id") or "UNKNOWN"
    severity = _severity_style_default(cve_dict.get("severity", "MEDIUM"))
    fixed_version = cve_dict.get("fixed_version")
    summary = cve_dict.get("summary") or (cve_dict.get("details") or "")[:400] or "No summary available."

    description = (
        f"{dep.name}@{dep.version} is affected by {cve_id} "
        f"(detected via {dep.source}, matched by {source_label}). {summary}"
    )
    recommendation = (
        f"Update {dep.name} to version {fixed_version} or later."
        if fixed_version
        else f"No fixed version is listed for {dep.name} yet. Check the framework's "
             f"release notes / consider an alternative library."
    )

    rule_id = f"SCA-{cve_id}"
    return {
        "rule_id": rule_id,
        "file_path": dep.name,
        "name": f"{cve_id}: {dep.name}@{dep.version} (vulnerable dependency)",
        "severity": severity,
        "details": {
            "description": description,
            "recommendation": recommendation,
            "cwe": cve_dict.get("cwe", "CWE-1104"),
            "masvs": "MSTG-CODE-5",
        },
        "line": 1,
        "engine": "sca",
        "sca": {
            "package": dep.name,
            "version": dep.version,
            "detected_via": dep.source,
            "fixed_version": fixed_version,
            "references": cve_dict.get("references", []),
            "ecosystem": "SwiftURL" if dep.osv_package_name else "swift",
            "cve_source": source_label,
        },
    }


def _rule_def_from_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": finding["rule_id"],
        "name": finding["name"],
        "severity": finding["severity"],
        "masvs": finding["details"]["masvs"],
        "details": dict(finding["details"]),
    }


def _check_local_curated_db(dep: _IOSDep) -> List[Dict[str, Any]]:
    entries = KNOWN_VULNERABLE_IOS_LIBS.get(dep.name)
    if not entries:
        return []
    hits = []
    raw_parts = re.findall(r'\d+', dep.version)[:3]
    if not raw_parts:
        return []
    try:
        dep_parts = [int(x) for x in raw_parts]
    except ValueError:
        return []
    while len(dep_parts) < 3:
        dep_parts.append(0)
    for entry in entries:
        target = [int(x) for x in re.findall(r'\d+', entry["less_than"])[:3]]
        while len(target) < 3:
            target.append(0)
        if dep_parts < target:
            hits.append({
                "cve": entry["cve"],
                "severity": entry["severity"],
                "summary": entry["title"],
                "details": entry["description"],
                "fixed_version": entry["fixed_version"],
                "cwe": entry["cwe"],
                "references": [],
            })
    return hits


def _check_all_sources(
    dep: _IOSDep,
    osv_client: OSVClient,
    gh_budget: _GitHubAdvisoryBudget,
    use_github: bool,
) -> List[Tuple[Dict[str, Any], str]]:
    """(cve_dict, source_label) pairs deduplicated by CVE id across all sources."""
    if not dep.version or dep.version.lower() == "unknown":
        return []

    seen_cves: set = set()
    results: List[Tuple[Dict[str, Any], str]] = []

    # OSV first: no rate ceiling. Needs a SwiftURL repo path, not a library name.
    if dep.osv_package_name:
        for f in osv_client.query_dict(dep.osv_package_name, dep.version, ecosystem="SwiftURL"):
            cve_id = f.get("cve") or f.get("osv_id")
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                results.append((f, "OSV.dev"))

    for f in _check_local_curated_db(dep):
        cve_id = f.get("cve")
        if cve_id and cve_id not in seen_cves:
            seen_cves.add(cve_id)
            results.append((f, "curated local DB"))

    if use_github:
        advisories = _query_github_advisories_swift(dep.name, gh_budget)
        for adv in advisories:
            f = _parse_github_advisory(adv, dep.name, dep.version)
            if not f:
                continue
            cve_id = f.get("cve")
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                results.append((f, "GitHub Advisory Database"))

    return results


def _scan_deps(deps: List[_IOSDep], osv_client: Optional[OSVClient] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    client = osv_client or get_default_client()
    gh_budget = _GitHubAdvisoryBudget()

    seen_keys: set = set()
    unique_deps: List[_IOSDep] = []
    for d in deps:
        key = (d.name, d.version)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_deps.append(d)

    findings: List[Dict[str, Any]] = []
    rule_defs: List[Dict[str, Any]] = []
    vulnerable_names: set = set()
    gh_used_for = 0

    unresolved_before = getattr(client, "query_failures_no_cache", 0)

    for dep in unique_deps:
        use_github = gh_used_for < _GH_MAX_QUERIES_PER_SCAN
        cve_hits = _check_all_sources(dep, client, gh_budget, use_github)
        if use_github:
            gh_used_for += 1
        for cve_dict, source_label in cve_hits:
            finding = _finding_from_cve(dep, cve_dict, source_label)
            findings.append(finding)
            rule_defs.append(_rule_def_from_finding(finding))
            vulnerable_names.add(dep.name)

    stats = {
        "total_dependencies_detected": len(deps),
        "unique_dependencies_checked": len(unique_deps),
        "cves_found": len(findings),
        "vulnerable_dependencies": len(vulnerable_names),
        "github_queries_made": gh_budget.queries_made,
        "github_rate_limited": gh_budget.exhausted,
    }
    unresolved = getattr(client, "query_failures_no_cache", 0) - unresolved_before
    stats["osv_dependencies_unresolved"] = unresolved
    stats["osv_unreachable"] = unresolved > 0
    return findings, rule_defs, stats


def scan_source(source_dir: str, osv_client: Optional[OSVClient] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Entry point for `ios-source` scan mode."""
    deps = extract_source_dependencies(source_dir)
    return _scan_deps(deps, osv_client)


def scan_binary(ipa_path: str, osv_client: Optional[OSVClient] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Entry point for `ios-binary` scan mode."""
    deps = extract_binary_dependencies(ipa_path)
    return _scan_deps(deps, osv_client)
