"""Android SCA: find dependencies in an APK/AAB and look up CVEs on OSV."""

from __future__ import annotations

import json
import logging
import re
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple

from .osv_client import OSVClient, get_default_client

logger = logging.getLogger(__name__)

# Maven coordinates (group:artifact:version) found as .dex string constants.
_MAVEN_COORD_PATTERN = re.compile(r'([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([0-9][a-zA-Z0-9_.-]*)')

# Lower number = more authoritative, wins dedup.
_SOURCE_PRIORITY = {
    "pom.properties": 0,
    "version-string": 1,
    "version-file": 2,
    "gradle-metadata": 3,
    "dex-strings": 4,
}

# Hard backstop so one scan can never turn into thousands of HTTP calls.
_MAX_DETAIL_QUERIES = 400


@dataclass(frozen=True)
class _Dep:
    group_id: str
    artifact_id: str
    version: str
    source: str

    @property
    def maven_name(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


def _extract_from_version_files(zf: zipfile.ZipFile) -> List[_Dep]:
    deps = []
    GROUP_MAPPINGS = {
        'kotlinx_coroutines': 'org.jetbrains.kotlinx',
        'kotlinx.coroutines': 'org.jetbrains.kotlinx',
        'kotlin': 'org.jetbrains.kotlin',
    }
    for name in zf.namelist():
        if not (name.startswith('META-INF/') and name.endswith('.version')):
            continue
        try:
            filename = name.replace('META-INF/', '').replace('.version', '')
            if '_' in filename:
                parts = filename.rsplit('_', 1)
                group_id = parts[0]
                artifact_id = parts[1] if len(parts) > 1 else filename
            else:
                group_id = filename
                artifact_id = filename.split('.')[-1]

            version = zf.read(name).decode('utf-8', errors='ignore').strip()
            if not version or len(version) > 20 or 'task' in version.lower() or ':' in version:
                continue
            if len(group_id) <= 3 or len(artifact_id) <= 2:
                continue

            for prefix, mapped_group in GROUP_MAPPINGS.items():
                if group_id.startswith(prefix):
                    if 'kotlinx' in group_id.lower():
                        artifact_id = f'kotlinx-coroutines-{artifact_id}'
                    group_id = mapped_group
                    break

            if version and group_id and artifact_id:
                deps.append(_Dep(group_id, artifact_id, version, 'version-file'))
        except Exception as e:
            logger.debug(f"[SCA] Error reading {name}: {e}")
    return deps


def _extract_from_pom_properties(zf: zipfile.ZipFile) -> List[_Dep]:
    deps = []
    for name in zf.namelist():
        if 'pom.properties' not in name:
            continue
        try:
            content = zf.read(name).decode('utf-8', errors='ignore')
            group_id = artifact_id = version = None
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('groupId='):
                    group_id = line.split('=', 1)[1].strip()
                elif line.startswith('artifactId='):
                    artifact_id = line.split('=', 1)[1].strip()
                elif line.startswith('version='):
                    version = line.split('=', 1)[1].strip()
            if group_id and artifact_id and version:
                deps.append(_Dep(group_id, artifact_id, version, 'pom.properties'))
        except Exception as e:
            logger.debug(f"[SCA] Error reading {name}: {e}")
    return deps


def _extract_from_gradle_metadata(zf: zipfile.ZipFile) -> List[_Dep]:
    deps = []
    for name in zf.namelist():
        if not (name.endswith('.module') or 'gradle-metadata' in name.lower()):
            continue
        try:
            content = zf.read(name).decode('utf-8', errors='ignore')
            data = json.loads(content)
            component = data.get('component', {})
            group = component.get('group')
            module = component.get('module')
            version = component.get('version')
            if group and module and version:
                deps.append(_Dep(group, module, version, 'gradle-metadata'))
        except Exception as e:
            logger.debug(f"[SCA] Error parsing {name}: {e}")
    return deps


def _is_valid_dependency(group_id: str, artifact_id: str) -> bool:
    """Drop noisy coordinates; a group id with no dot is usually an obfuscated class name."""
    invalid_patterns = (
        'example', 'test', 'sample', 'demo', 'mock',
        'android.support', 'androidx.', 'com.android.',
        'kotlin.', 'kotlinx.',
    )
    full_name = f"{group_id}.{artifact_id}".lower()
    if any(p in full_name for p in invalid_patterns):
        return False
    if '.' not in group_id:
        return False
    return True


def _extract_dex_strings(dex_data: bytes) -> List[str]:
    strings = []
    current = []
    for byte in dex_data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= 10:
                strings.append(''.join(current))
            current = []
    if len(current) >= 10:
        strings.append(''.join(current))
    return strings


def _extract_from_dex_packages(zf: zipfile.ZipFile) -> List[_Dep]:
    deps = []
    for name in zf.namelist():
        if not name.endswith('.dex'):
            continue
        try:
            dex_data = zf.read(name)
            strings = _extract_dex_strings(dex_data)
            for s in strings:
                for group, artifact, version in _MAVEN_COORD_PATTERN.findall(s):
                    if _is_valid_dependency(group, artifact):
                        deps.append(_Dep(group, artifact, version, 'dex-strings'))
        except Exception as e:
            logger.debug(f"[SCA] Error reading DEX {name}: {e}")
    return deps


# Recovers a version from a runtime string constant on R8-shrunk builds that
# strip pom.properties and carry no literal Maven coordinate. Kept narrow.
_VERSION_STRING_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex, group:artifact, description)
    (r'okhttp/(\d+\.\d+\.\d+)', 'com.squareup.okhttp3:okhttp', 'OkHttp User-Agent literal'),
    (r'Retrofit/(\d+\.\d+\.\d+)', 'com.squareup.retrofit2:retrofit', 'Retrofit User-Agent literal'),
]


def _extract_from_version_strings(zf: zipfile.ZipFile) -> List[_Dep]:
    deps = []
    compiled = [(re.compile(p, re.IGNORECASE), coord, desc) for p, coord, desc in _VERSION_STRING_PATTERNS]
    found_coords: Set[str] = set()
    for name in zf.namelist():
        if not name.endswith('.dex'):
            continue
        try:
            dex_data = zf.read(name)
            strings = _extract_dex_strings(dex_data)
            for s in strings:
                if len(s) > 200:
                    continue
                for pattern, coord, desc in compiled:
                    if coord in found_coords:
                        continue
                    m = pattern.search(s)
                    if m:
                        group_id, artifact_id = coord.split(':', 1)
                        deps.append(_Dep(group_id, artifact_id, m.group(1), 'version-string'))
                        found_coords.add(coord)
                        logger.debug(f"[SCA] Found {coord} version {m.group(1)} via {desc}")
        except Exception as e:
            logger.debug(f"[SCA] Error reading DEX {name} for version strings: {e}")
    return deps


def extract_dependencies(apk_path: str) -> List[_Dep]:
    all_deps: List[_Dep] = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            all_deps.extend(_extract_from_version_files(zf))
            all_deps.extend(_extract_from_pom_properties(zf))
            all_deps.extend(_extract_from_gradle_metadata(zf))
            all_deps.extend(_extract_from_version_strings(zf))
            all_deps.extend(_extract_from_dex_packages(zf))
    except zipfile.BadZipFile:
        logger.error(f"[SCA] Invalid APK/AAB file: {apk_path}")
    except Exception as e:
        logger.error(f"[SCA] Error extracting dependencies from {apk_path}: {e}")
    return all_deps


def _dedupe_by_coordinate(deps: List[_Dep]) -> List[_Dep]:
    best: Dict[Tuple[str, str], _Dep] = {}
    for dep in deps:
        key = (dep.group_id, dep.artifact_id)
        current = best.get(key)
        if current is None or _SOURCE_PRIORITY.get(dep.source, 9) < _SOURCE_PRIORITY.get(current.source, 9):
            best[key] = dep
    return list(best.values())


def _severity_style_default(sev: str) -> str:
    return sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"


def _finding_from_osv(dep: _Dep, osv_finding_dict: Dict[str, Any]) -> Dict[str, Any]:
    cve_id = osv_finding_dict.get("cve") or osv_finding_dict.get("osv_id") or "UNKNOWN"
    severity = _severity_style_default(osv_finding_dict.get("severity", "MEDIUM"))
    fixed_version = osv_finding_dict.get("fixed_version")
    summary = osv_finding_dict.get("summary") or osv_finding_dict.get("details", "")[:400] or "No summary available."

    description = (
        f"{dep.maven_name}@{dep.version} is affected by {cve_id} "
        f"(detected via {dep.source}). {summary}"
    )
    recommendation = (
        f"Update {dep.maven_name} to version {fixed_version} or later."
        if fixed_version
        else f"No fixed version is listed by OSV yet for {dep.maven_name}. "
             f"Check {dep.group_id}:{dep.artifact_id}'s release notes / consider an alternative library."
    )

    rule_id = f"SCA-{cve_id}"
    return {
        "rule_id": rule_id,
        "file_path": dep.maven_name,
        "name": f"{cve_id}: {dep.artifact_id}@{dep.version} (vulnerable dependency)",
        "severity": severity,
        "details": {
            "description": description,
            "recommendation": recommendation,
            "cwe": osv_finding_dict.get("cwe", "CWE-1104"),
            "masvs": "MSTG-CODE-5",
        },
        # SARIF startLine requires an int; a dependency finding has no source line.
        "line": 1,
        "engine": "sca",
        "sca": {
            "package": dep.maven_name,
            "version": dep.version,
            "detected_via": dep.source,
            "fixed_version": fixed_version,
            "references": osv_finding_dict.get("references", []),
            "ecosystem": "Maven",
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


def scan(apk_path: str, osv_client: OSVClient = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Scan an APK/AAB for vulnerable third-party dependencies: (findings, rule_defs, stats)."""
    client = osv_client or get_default_client()

    all_deps = extract_dependencies(apk_path)
    deduped = _dedupe_by_coordinate(all_deps)

    # "_detected" is the pre-cap count; "_checked" is what was actually queried.
    stats: Dict[str, Any] = {
        "total_dependencies_detected": len(all_deps),
        "unique_dependencies_detected": len(deduped),
        "unique_dependencies_checked": len(deduped),
        "dependencies_capped": False,
        "cves_found": 0,
        "vulnerable_dependencies": 0,
    }

    if not deduped:
        return [], [], stats

    if len(deduped) > _MAX_DETAIL_QUERIES:
        logger.warning(
            f"[SCA] {len(deduped)} unique dependencies detected - capping OSV "
            f"queries at {_MAX_DETAIL_QUERIES} to stay considerate of the free "
            f"public API."
        )
        stats["dependencies_capped"] = True
        deduped = deduped[:_MAX_DETAIL_QUERIES]
        stats["unique_dependencies_checked"] = len(deduped)

    # Batch existence pre-filter: spend a full detail query only on packages with a vuln.
    pkg_version_pairs = [(d.maven_name, d.version) for d in deduped]
    has_vuln = client.has_any_vuln_batch(pkg_version_pairs, ecosystem="Maven")

    findings: List[Dict[str, Any]] = []
    rule_defs: List[Dict[str, Any]] = []
    vulnerable_coords: Set[str] = set()

    unresolved_before = getattr(client, "query_failures_no_cache", 0)

    for dep in deduped:
        if not dep.version or dep.version == "unknown":
            continue
        key = (dep.maven_name, dep.version)
        if not has_vuln.get(key, False):
            continue

        osv_findings = client.query_dict(dep.maven_name, dep.version, ecosystem="Maven")
        for osv_finding in osv_findings:
            finding = _finding_from_osv(dep, osv_finding)
            findings.append(finding)
            rule_defs.append(_rule_def_from_finding(finding))
            stats["cves_found"] += 1
            vulnerable_coords.add(dep.maven_name)

    stats["vulnerable_dependencies"] = len(vulnerable_coords)
    unresolved = getattr(client, "query_failures_no_cache", 0) - unresolved_before
    stats["osv_dependencies_unresolved"] = unresolved
    stats["osv_unreachable"] = unresolved > 0
    return findings, rule_defs, stats
