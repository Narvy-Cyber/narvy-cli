"""SARIF 2.1.0 -> GitLab SAST security report (gl-sast-report.json).

GitLab's merge request security widget, pipeline Security tab and
vulnerability report ingest a job artifact declared under
``artifacts:reports:sast`` that conforms to GitLab's security report schema
(https://gitlab.com/gitlab-org/security-products/security-report-schemas,
dist/sast-report-format.json). A SARIF file kept as a plain artifact is never
read. GitLab 19.2+ (Ultimate) also has ``artifacts:reports:sarif``, but it
drops every result without a physical location, which is most binary
(APK / IPA) findings, and it fails the whole scan above 50 % dropped. This
converter keeps every shown finding and works on every GitLab version that
reads schema 15.x.

Pure function, no dependency. The SaaS carries the same converter
(src/core/gitlab_sast_report.py); keep the two identical.

Mapping:
  severity     properties.severity (our label), else security-severity score
               (rule or result), else SARIF level. A result we ship at level
               "note" (hardening, to review) is capped at Low.
  identifiers  primary = ruleId, then one "cwe" identifier per CWE.
  location     physicalLocation uri / startLine / endLine. A result with no
               location gets ``default_file`` (the scanned artifact); no line
               gives start_line 1, no end line gives end_line = start_line.
  suppressed   results (hidden by the default view) are not exported.
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

SCHEMA_VERSION = "15.2.1"

_LABEL = {
    "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "MODERATE": "Medium",
    "LOW": "Low", "INFO": "Info", "INFORMATIONAL": "Info", "INFORMATION": "Info",
}
_LEVEL = {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}
_RANK = {"Unknown": 0, "Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
_CWE_RE = re.compile(r"cwe[-_/ :]*(\d+)", re.IGNORECASE)


def _ts(value: Optional[datetime]) -> str:
    if not isinstance(value, datetime):
        value = datetime.now(timezone.utc)
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.strftime("%Y-%m-%dT%H:%M:%S")


def _score_label(score: Any) -> Optional[str]:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    if s >= 0.1:
        return "Low"
    return "Info"


def _severity(result: Dict[str, Any], rule: Dict[str, Any]) -> str:
    props = result.get("properties") or {}
    rprops = rule.get("properties") or {}
    sev = _LABEL.get(str(props.get("severity") or "").strip().upper())
    if not sev:
        sev = (_score_label(props.get("security-severity"))
               or _score_label(rprops.get("security-severity")))
    if not sev:
        level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
        sev = _LEVEL.get(str(level or "").lower(), "Unknown")
    if result.get("level") == "note" and _RANK[sev] > _RANK["Low"]:
        sev = "Low"
    return sev


def _text(obj: Any) -> str:
    if isinstance(obj, dict):
        t = obj.get("text") or obj.get("markdown")
        return t if isinstance(t, str) else ""
    return obj if isinstance(obj, str) else ""


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _cwes(result: Dict[str, Any], rule: Dict[str, Any]) -> List[str]:
    found: List[str] = []
    props = result.get("properties") or {}
    rprops = rule.get("properties") or {}
    cands: Iterable[Any] = (_as_list(props.get("cwe")) + _as_list(rprops.get("cwe"))
                            + _as_list(rprops.get("tags")) + _as_list(props.get("tags"))
                            + [_text(rule.get("help"))])
    for c in cands:
        s = str(c)
        nums = _CWE_RE.findall(s) or ([s] if s.isdigit() else [])
        for num in nums:
            if num not in found:
                found.append(num)
    return found


def _location(result: Dict[str, Any], default_file: Optional[str]) -> Dict[str, Any]:
    loc: Dict[str, Any] = {}
    phys = None
    for l in result.get("locations") or []:
        if isinstance(l, dict) and isinstance(l.get("physicalLocation"), dict):
            phys = l["physicalLocation"]
            break
    uri = ""
    if phys:
        uri = str((phys.get("artifactLocation") or {}).get("uri") or "")
        if uri.startswith("file://"):
            uri = uri[len("file://"):]
        while uri.startswith("./"):
            uri = uri[2:]
        region = phys.get("region") or {}
        start = region.get("startLine")
        if isinstance(start, int) and not isinstance(start, bool) and start >= 1:
            loc["start_line"] = start
            end = region.get("endLine")
            if isinstance(end, int) and not isinstance(end, bool) and end >= start:
                loc["end_line"] = end
    if uri:
        loc["file"] = uri
    elif default_file:
        loc["file"] = default_file
    # GitLab's location fingerprint combines file, start_line and end_line
    # ("these attributes are mandatory", docs/development/integrations/
    # secure.md). A finding with no line (manifest, binary) gets line 1.
    loc.setdefault("start_line", 1)
    loc.setdefault("end_line", loc["start_line"])
    return loc


def _suppressed(result: Dict[str, Any]) -> bool:
    for s in result.get("suppressions") or []:
        if isinstance(s, dict) and s.get("status", "accepted") == "accepted":
            return True
    return False


def sarif_to_gitlab_sast(sarif: Dict[str, Any], *, analyzer_id: str, analyzer_name: str,
                         analyzer_version: str, vendor: str, analyzer_url: Optional[str] = None,
                         default_file: Optional[str] = None,
                         start_time: Optional[datetime] = None,
                         end_time: Optional[datetime] = None,
                         note_rule_ids: Iterable[str] = ()) -> Dict[str, Any]:
    """GitLab SAST report (schema SCHEMA_VERSION) for a SARIF 2.1.0 log.

    ``note_rule_ids``: rules that report scan coverage, not a vulnerability
    (e.g. an encrypted binary); their results become scan messages."""
    vulns: List[Dict[str, Any]] = []
    messages: List[Dict[str, str]] = []
    note_ids = set(note_rule_ids or ())
    seen_ids = set()
    hidden = 0
    for run in (sarif or {}).get("runs") or []:
        if not isinstance(run, dict):
            continue
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict) and r.get("id")}
        for idx, result in enumerate(run.get("results") or []):
            if not isinstance(result, dict):
                continue
            if _suppressed(result):
                hidden += 1
                continue
            rule_id = result.get("ruleId")
            rule: Dict[str, Any] = by_id.get(rule_id) or {}
            if not rule and isinstance(result.get("ruleIndex"), int) and 0 <= result["ruleIndex"] < len(rules):
                rule = rules[result["ruleIndex"]] if isinstance(rules[result["ruleIndex"]], dict) else {}
                rule_id = rule_id or rule.get("id")
            rule_id = str(rule_id or "unknown-rule")
            message = _text(result.get("message"))
            if rule_id in note_ids:
                if message:
                    messages.append({"level": "warn", "value": message[:4096]})
                continue
            # rule.name is the title when it reads as one (the CLI's); else an
            # identifier, and shortDescription carries the title (the SaaS's).
            title = rule.get("name") if isinstance(rule.get("name"), str) else ""
            short = ((title.strip() if " " in title.strip() else "")
                     or _text(rule.get("shortDescription")) or title or message or rule_id)
            full = _text(rule.get("fullDescription"))
            description = message
            if full and full != message:
                description = f"{message}\n\n{full}" if message else full

            identifiers = [{
                "type": f"{analyzer_id}_rule_id",
                "name": f"{analyzer_name} {rule_id}"[:255],
                "value": rule_id,
            }]
            for num in _cwes(result, rule):
                identifiers.append({
                    "type": "cwe", "name": f"CWE-{num}", "value": num,
                    "url": f"https://cwe.mitre.org/data/definitions/{num}.html",
                })

            location = _location(result, default_file)
            fp = ""
            for key in ("fingerprints", "partialFingerprints"):
                vals = result.get(key)
                if isinstance(vals, dict) and vals:
                    fp = str(sorted(vals.items())[0][1])
                    break
            seed = "|".join([analyzer_id, rule_id, location.get("file", ""),
                             str(location.get("start_line", "")), fp or str(idx)])
            vid = str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
            n = 0
            while vid in seen_ids:
                n += 1
                vid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{seed}|{n}"))
            seen_ids.add(vid)

            vuln: Dict[str, Any] = {
                "id": vid,
                "name": str(short)[:255],
                "description": description[:1048576],
                "severity": _severity(result, rule),
                "identifiers": identifiers,
                "location": location,
            }
            help_uri = rule.get("helpUri")
            if isinstance(help_uri, str) and help_uri.startswith(("http://", "https://")):
                vuln["links"] = [{"url": help_uri}]
            vulns.append(vuln)

    tool = {"id": analyzer_id, "name": analyzer_name, "version": analyzer_version or "unknown",
            "vendor": {"name": vendor}}
    analyzer = dict(tool)
    if analyzer_url and analyzer_url.startswith(("http://", "https://")):
        analyzer["url"] = analyzer_url
        tool["url"] = analyzer_url
    scan: Dict[str, Any] = {
        "analyzer": analyzer,
        "scanner": tool,
        "type": "sast",
        "start_time": _ts(start_time),
        "end_time": _ts(end_time or start_time),
        "status": "success",
    }
    if hidden:
        messages.append({"level": "info",
                         "value": f"{hidden} result(s) hidden by the default view are not exported."})
    if messages:
        scan["messages"] = messages
    return {"version": SCHEMA_VERSION, "scan": scan, "vulnerabilities": vulns}


# Rules that report scan coverage, not a vulnerability.
_COVERAGE_RULE_IDS = ("IOS-FAIRPLAY-ENCRYPTED",)


def gitlab_sast_from_cli_sarif(sarif: Dict[str, Any], *, version: str, started: float,
                               ended: float, default_file: Optional[str] = None) -> Dict[str, Any]:
    """GitLab SAST report for the SARIF `narvy scan` builds (``--output gitlab``)."""
    return sarif_to_gitlab_sast(
        sarif, analyzer_id="narvy", analyzer_name="Narvy", analyzer_version=version,
        vendor="Narvy", analyzer_url="https://narvy.io", default_file=default_file,
        start_time=datetime.fromtimestamp(started, timezone.utc),
        end_time=datetime.fromtimestamp(ended, timezone.utc),
        note_rule_ids=_COVERAGE_RULE_IDS)
