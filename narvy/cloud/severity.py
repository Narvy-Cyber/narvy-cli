"""The severity of a cloud finding (decisions 2026-11-02 and 2026-11-03).

One rule for every cloud surface (results page tiles and list, /cloud scan
list, bridged report, PDF / JSON / SARIF exports, tracker counts): a finding
states the severity of its check in the rule table (src/cloud/rule_severity,
keyed by stable rule id, exact-title aliases for old reports), else the
severity its report gives it. A finding neither gives is "undetermined"; no
surface guesses one from its text or its service.

The cloud results page reads ``cloud_findings(report)`` and counts that list,
so its tiles count exactly the findings it lists.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple

SEVERITIES = ("critical", "high", "medium", "low", "info")
UNDETERMINED = "undetermined"
# Title-case form the unified finding schema uses ("Critical", ...).
UNDETERMINED_TITLE = "Undetermined"

_ALIASES = {
    "informational": "info", "information": "info",
    # The Azure analyzer writes French levels (src/cloud/azure/azure_analyzer).
    "critique": "critical", "eleve": "high", "élevé": "high",
    "moyen": "medium", "faible": "low",
}

# Report keys that are metadata / appendix, never finding lists.
NON_FINDING_KEYS = frozenset({
    'summary', 'severity_summary', 'total_findings', 'passed_checks',
    'passing_checks', 'general_recommendations', '_general_recommendations',
    'timestamp', 'error', 'metadata', 'scan_info', 'denied_apis',
    'scan_incomplete', 'scan_incomplete_reason',
    # GCP: the denied API URLs below the incomplete threshold (strings).
    'permission_warnings', 'permission_warning_message',
})


def _stated_severity(item: Dict[str, Any]) -> Optional[str]:
    raw = str(item.get("severity") or item.get("Severity") or "").strip().lower()
    raw = _ALIASES.get(raw, raw)
    return raw if raw in SEVERITIES else None


def report_severity(item: Any, category: Any = None) -> str:
    """Lowercase severity of ``item`` (a raw report item of ``category``):
    the rule table's for its check (src/cloud/rule_severity.resolve_severity),
    else the one its report gives, else "undetermined"."""
    if not isinstance(item, dict):
        return UNDETERMINED
    from .rule_severity import resolve_severity, rule_id_for
    sev = resolve_severity(_stated_severity(item), rule_id_for(item, category))
    return sev if sev in SEVERITIES else UNDETERMINED


def report_severity_title(item: Any, category: Any = None) -> str:
    """Same rule, title-case ("High", "Undetermined") for the unified schema."""
    return report_severity(item, category).capitalize()


def iter_finding_lists(report: Any) -> Iterator[Tuple[str, List[Any]]]:
    """(category key, non-empty item list) for every finding list of a raw
    cloud report: top-level lists and one level of nesting
    (GCP ``vulnerabilities -> service -> [...]``), metadata keys skipped."""
    if not isinstance(report, dict):
        return
    for category, items in report.items():
        if category in NON_FINDING_KEYS:
            continue
        if isinstance(items, list):
            if items:
                yield category, items
        elif isinstance(items, dict):
            for sub_cat, sub_items in items.items():
                if sub_cat in NON_FINDING_KEYS:
                    continue
                if isinstance(sub_items, list) and sub_items:
                    yield f"{category} / {sub_cat}", sub_items


def normalize_cloud_finding(cat: str, item: Any) -> Dict[str, Any]:
    """One raw report item in the shape the cloud results template reads."""
    if not isinstance(item, dict):
        return {'severity': UNDETERMINED, 'title': str(item), 'service': cat}
    resource = (item.get('UserName') or item.get('GroupName') or item.get('GroupId')
                or item.get('FunctionName') or item.get('BucketName')
                or item.get('DBInstanceIdentifier') or item.get('TableName')
                or item.get('resource') or item.get('resource_id')
                or item.get('Name') or item.get('Id') or item.get('Arn'))
    rec = (item.get('Recommendation') or item.get('recommendation')
           or item.get('description') or item.get('issue') or '')
    region = item.get('Region') or item.get('region') or item.get('resource_region')
    label = str(cat).replace('_', ' ').title()
    title = (f"{label}: {resource}" if resource
             else (str(rec)[:70] if rec else f"{label} finding"))
    from .rule_severity import rule_id_for
    return {'severity': report_severity(item, cat), 'cloud_rule_id': rule_id_for(item, cat),
            'title': title, 'description': rec,
            'resource': resource, 'region': region, 'service': cat,
            'recommendation': rec}


def cloud_findings_by_category(report: Any) -> Dict[str, List[Dict[str, Any]]]:
    """{category: [normalized finding, ...]} in report order."""
    return {cat: [normalize_cloud_finding(cat, it) for it in items]
            for cat, items in iter_finding_lists(report)}


def cloud_findings(report: Any) -> List[Dict[str, Any]]:
    """The flat list of findings the cloud results page lists."""
    out: List[Dict[str, Any]] = []
    for norm in cloud_findings_by_category(report).values():
        out.extend(norm)
    return out


def severity_counts(findings: Any) -> Dict[str, int]:
    """{critical, high, medium, low, info, undetermined, total} of EXACTLY
    the given normalized findings."""
    counts = {s: 0 for s in SEVERITIES + (UNDETERMINED,)}
    n = 0
    for f in findings or []:
        sev = (f.get('severity') if isinstance(f, dict) else None) or UNDETERMINED
        sev = str(sev).lower()
        counts[sev if sev in counts else UNDETERMINED] += 1
        n += 1
    counts['total'] = n
    return counts


def report_counts(report: Any) -> Dict[str, int]:
    """Severity counts of the list a report's results page shows."""
    return severity_counts(cloud_findings(report))
