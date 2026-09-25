"""Normalize host-audit findings into the CLI's own flat finding schema."""

from __future__ import annotations

from typing import Any, Dict, List

from .lynis_parser import ENGINE_NAME

_SEV_MAP = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info",
}

_OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
_OWASP_OUTDATED = "A06:2021 - Vulnerable and Outdated Components"


def _owasp_for(finding) -> str:
    if (finding.get("category") or "") == "Packages & Patching":
        return _OWASP_OUTDATED
    return _OWASP_MISCONFIG


def normalize_host_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for i, f in enumerate(findings, start=1):
        sev = _SEV_MAP.get(str(f.get("severity", "")).lower(), "Low")
        desc = f.get("description") or f.get("title") or ""
        details = f.get("details")
        cis = f.get("cis")
        extra = []
        if details:
            extra.append(f"Details: {details}")
        if cis:
            extra.append(f"Control: {cis}")
        full_desc = desc + (("\n\n" + "\n".join(extra)) if extra else "")

        category = f.get("category") or "Host Hardening"
        title = f.get("title") or f.get("test_id") or "Host finding"
        test_id = f.get("test_id") or ""
        out.append({
            "id": i,
            "title": title,
            "type": category,
            "rule_id": f.get("control_id") or test_id,
            "code_snippet": f.get("discriminator") or f"{f.get('control_id') or test_id}: {title}",
            "severity": sev,
            "category": category,
            "description": full_desc,
            "location": f.get("location") or "",
            "cwe": f.get("cwe") or "",
            "cis": cis or "",
            "owasp": _owasp_for(f),
            "remediation": f.get("remediation") or "",
            "reference": f.get("reference") or "",
            "engine": f.get("engine") or ENGINE_NAME,
            "confidence": f.get("confidence") or "HIGH",
            "surface": "infrastructure",
        })
    return out


def severity_counts(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulns:
        s = v.get("severity", "Low")
        if s in counts:
            counts[s] += 1
    return counts
