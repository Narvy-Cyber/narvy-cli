"""Parse a Lynis `lynis-report.dat` into Narvy host-audit findings.

The `.dat` is a flat key=value file; repeated keys use a `key[]=` suffix.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .host_knowledge import lookup

ENGINE_NAME = "Lynis (GPL-3.0), orchestrated by Narvy"

# Canonical upstream reference for a Lynis control id.
LYNIS_REF_BASE = "https://cisofy.com/lynis/controls/"

_WARNING_DOWNGRADE = {
    "KRNL-5830": "low",
}

# "LYNIS" is Lynis's own outdated-version notice, not a host control.
_SKIP_TEST_IDS = {"LYNIS"}

_TESTID_GROUP_CATEGORY = {
    "ACCT": "Accounting & Auditing",
    "AUTH": "Authentication",
    "BANN": "Banners & Policy",
    "BOOT": "Boot & Services",
    "CONT": "Containers",
    "CRYP": "Cryptography",
    "DBS": "Databases",
    "DEB": "Package Management",
    "FILE": "Filesystem",
    "FINT": "File Integrity",
    "FIRE": "Firewall",
    "HRDN": "Hardening",
    "HTTP": "Web Server",
    "INSE": "Insecure Services",
    "KRNL": "Kernel",
    "LOGG": "Logging",
    "MACF": "Mandatory Access Control",
    "MAIL": "Mail",
    "MALW": "Malware Protection",
    "NAME": "DNS & Naming",
    "NETW": "Network",
    "PHP": "PHP",
    "PKGS": "Packages & Patching",
    "PRNT": "Printing",
    "SCHD": "Scheduled Tasks",
    "SHLL": "Shell",
    "SQD": "Squid Proxy",
    "SSH": "SSH",
    "STRG": "Storage",
    "TIME": "Time Sync",
    "TOOL": "Security Tooling",
    "USB": "USB Devices",
    "VIRT": "Virtualization",
}


def _category_for(test_id: str) -> str:
    group = (test_id or "").split("-", 1)[0].upper()
    return _TESTID_GROUP_CATEGORY.get(group, "Host Hardening")

# TEST-ID -> (CWE, CIS control label). Unmapped ids still produce a finding.
_TESTID_MAP = {
    "DBS-1820": ("CWE-306", "CIS 5.x Database Authentication"),
    "PKGS-7392": ("CWE-1104", "CIS 1.9 Patch Management"),
    "SSH-7408": ("CWE-16", "CIS 5.2 SSH Server Configuration"),
    "AUTH-9328": ("CWE-521", "CIS 5.4 Password Policy"),
    "FIRE-4513": ("CWE-1327", "CIS 3.5 Firewall Configuration"),
    "BOOT-5122": ("CWE-284", "CIS 1.4 Bootloader Password"),
    "KRNL-5820": ("CWE-284", "CIS 1.5 Kernel Hardening"),
}

_SENSITIVE_LISTEN = {
    "mongod": "MongoDB", "mysqld": "MySQL", "postgres": "PostgreSQL",
    "redis-server": "Redis", "memcached": "Memcached",
    "elasticsearch": "Elasticsearch", "mongos": "MongoDB",
}

# Loopback / link-local / RFC1918 = not exposed. 0.0.0.0 and :: (all interfaces) are handled separately.
_PRIVATE_ADDR_RE = re.compile(
    r"^(127\.|::1$|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:)"
)
_ALL_INTERFACES = {"0.0.0.0", "::", "*", "[::]"}


def parse_lynis_report(dat_text: str,
                       absent_modules: Optional[set] = None) -> Dict[str, Any]:
    """Return {meta, findings, hardening_index} from the raw report text."""
    meta: Dict[str, str] = {}
    warnings: List[str] = []
    suggestions: List[str] = []
    listens: List[str] = []

    for raw in dat_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        if key == "warning[]":
            warnings.append(val)
        elif key == "suggestion[]":
            suggestions.append(val)
        elif key == "network_listen[]":
            listens.append(val)
        elif key in ("hardening_index", "lynis_version", "os_fullname",
                     "hostname", "os_version"):
            meta.setdefault(key, val)

    exposed_services = _exposed_service_names(listens)

    findings: List[Dict[str, Any]] = []
    for w in warnings:
        findings.append(_finding_from_pipe(w, kind="warning",
                                           exposed_services=exposed_services))
    for s in suggestions:
        findings.append(_finding_from_pipe(s, kind="suggestion",
                                           exposed_services=exposed_services))
    findings.extend(_exposure_findings(listens))

    # The EOL-OS control's text matches no _variant_of() pattern; attach the distro from meta.
    os_evidence = meta.get("os_fullname") or meta.get("os_version") or ""
    if os_evidence:
        for f in findings:
            if f and f.get("control_id") == "NARVY-HOST-OS-001":
                f["title"] = f"{f['title']} ({os_evidence})"
                f["discriminator"] = f"{f['control_id']}:{os_evidence}"
                f["description"] = f"{f['description']}\n\nDetected: {os_evidence}"

    seen = set()
    clean: List[Dict[str, Any]] = []
    for f in findings:
        if not f:
            continue
        # Drop findings about kernel modules the host confirmed it lacks.
        variant = (f.get("_variant") or "").strip()
        if variant and variant in (absent_modules or set()):
            continue
        k = f.get("discriminator") or (f.get("test_id"), f.get("title"))
        if k in seen:
            continue
        seen.add(k)
        clean.append(f)

    try:
        hi = int(meta.get("hardening_index", "")) if meta.get("hardening_index") else None
    except ValueError:
        hi = None

    return {"meta": meta, "hardening_index": hi, "findings": clean}


# TEST-ID -> the service token to look for in the listener list.
_EXPOSURE_SENSITIVE_CONTROLS = {
    "DBS-1820": "mongod",
}


def _exposed_service_names(listens: List[str]) -> set:
    """Service names bound to a routable / all-interfaces address."""
    exposed = set()
    for l in listens:
        parts = l.split("|")
        if len(parts) < 4:
            continue
        addr, service = parts[2].strip(), parts[3].strip().lower()
        host = _host_of(addr)
        if host in _ALL_INTERFACES or not _PRIVATE_ADDR_RE.match(host):
            exposed.add(service)
    return exposed


def _adjust_for_exposure(test_id: str, severity: str,
                         exposed_services: set) -> tuple:
    """Downgrade a 'no authentication' finding when the service is loopback-only."""
    svc = _EXPOSURE_SENSITIVE_CONTROLS.get(test_id)
    if not svc or severity != "high":
        return severity, ""
    if any(svc in s for s in exposed_services):
        return severity, ""
    return "medium", (
        "\n\nScope: this service is currently bound to loopback only, so it is "
        "not reachable from the network. Severity is reduced accordingly. It "
        "still matters: any local account, or a compromise of any application "
        "on this host, reaches the data with no further authentication."
    )


def _variant_of(text: str) -> str:
    """Pull the distinguishing token from a sibling suggestion so siblings don't collapse into one row."""
    m = re.search(r"'([^']{1,40})'", text)
    if m:
        return m.group(1)
    m = re.search(r"(/[a-z][a-z0-9_/.-]{1,30})", text)
    if m:
        return m.group(1)
    m = re.search(r"\b(minimum|maximum)\b", text, re.I)
    if m:
        return m.group(1).lower()
    return ""


def _finding_from_pipe(val: str, *, kind: str,
                       exposed_services: Optional[set] = None) -> Optional[Dict[str, Any]]:
    # TESTID|description|details|solution| -- split capped at 4 so a stray '|' in solution doesn't shift fields.
    if val.endswith("|"):
        val = val[:-1]
    parts = val.split("|", 3)
    test_id = parts[0].strip() if parts else ""
    if not test_id or test_id.upper() in _SKIP_TEST_IDS:
        return None
    desc = parts[1].strip() if len(parts) > 1 else ""
    details = _clean(parts[2]) if len(parts) > 2 else ""
    solution_advice, solution_url = _parse_solution(parts[3] if len(parts) > 3 else "")
    reference = solution_url or _lynis_ref(test_id)

    # Prefer the curated KB entry; fall back to raw fields when absent.
    kb = lookup(test_id)
    raw_title = desc or test_id

    if kb:
        variant = _variant_of(f"{desc} {details}")
        title = f"{kb.title} ({variant})" if variant else kb.title
        description = kb.description
        if variant:
            description = f"{description}\n\nAffected: {variant}"
        severity, scope_note = _adjust_for_exposure(
            test_id, kb.severity, exposed_services or set())
        if scope_note:
            description = description + scope_note
        return {
            "engine": ENGINE_NAME,
            "test_id": test_id,
            "control_id": kb.control_id,
            "title": title,
            "severity": severity,
            "category": _category_for(test_id),
            "description": description,
            "details": "",
            "remediation": kb.remediation,
            "cwe": kb.cwe or None,
            "cis": kb.cis or None,
            "location": kb.location or "",
            "reference": reference,
            "discriminator": f"{kb.control_id}:{variant}" if variant else kb.control_id,
            "_variant": variant,
        }

    sev = _WARNING_DOWNGRADE.get(test_id, "medium") if kind == "warning" else "low"
    cwe, cis = _TESTID_MAP.get(test_id, (None, None))
    # Generic control-id group from the test-id prefix.
    group = test_id.split("-", 1)[0].upper()
    generic_id = f"NARVY-HOST-GEN-{group}"
    return {
        "engine": ENGINE_NAME,
        "test_id": test_id,
        "control_id": generic_id,
        "title": raw_title,
        "severity": sev,
        "category": _category_for(test_id),
        "description": desc,
        "details": details,
        "remediation": solution_advice or (
            "Review this control against your hardening baseline and apply your "
            "platform's recommended configuration."
        ),
        "cwe": cwe,
        "cis": cis,
        "location": "",
        "reference": reference,
        "discriminator": f"{generic_id}:{raw_title[:60]}",
    }


def _exposure_findings(listens: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for l in listens:
        # source|proto|address:port|service|
        parts = l.split("|")
        if len(parts) < 4:
            continue
        proto, addr, service = parts[1].strip(), parts[2].strip(), parts[3].strip()
        host = _host_of(addr)
        if host not in _ALL_INTERFACES and _PRIVATE_ADDR_RE.match(host):
            continue
        svc_key = next((k for k in _SENSITIVE_LISTEN if k in service.lower()), None)
        if not svc_key:
            continue
        name = _SENSITIVE_LISTEN[svc_key]
        out.append({
            "engine": ENGINE_NAME,
            "test_id": "NETW-EXPOSURE",
            "control_id": "NARVY-HOST-NETW-900",
            "discriminator": f"NARVY-HOST-NETW-900:{addr}",
            "title": f"{name} listening on a routable address ({addr})",
            "severity": "medium",
            "category": "network-exposure",
            "description": (
                f"{name} ({service}) is bound to {addr}/{proto}, reachable "
                f"beyond localhost. Confirm authentication and firewall rules."
            ),
            "details": l,
            "remediation": (
                "Bind the service to 127.0.0.1 or a private interface, require "
                "authentication, and restrict access with a host firewall."
            ),
            "cwe": "CWE-668",
            "cis": "CIS 3.x Network Configuration",
            "location": f"listen:{addr}",
        })
    return out


def _host_of(addr: str) -> str:
    """Extract the host part of a listen address, IPv6-safe."""
    a = addr.strip()
    if a.startswith("["):
        return a[: a.find("]") + 1] if "]" in a else a
    if a.count(":") > 1:
        return a
    host = a.rsplit(":", 1)[0] if ":" in a else a
    return host.split("%", 1)[0]


def _clean(s: str) -> str:
    s = (s or "").strip()
    s = s.rstrip("|").strip()
    # Fields are directive-tokened: `text:` is advice, `url:` a link. Strip the prefix, keep the value.
    low = s.lower()
    if low.startswith("text:"):
        s = s[5:].strip()
    elif low.startswith("url:"):
        s = s[4:].strip()
    return "" if s in ("-", "") else s


def _parse_solution(raw: str) -> tuple:
    """Split a Lynis solution field (directive-tokened `text:`/`url:`) into (advice, reference url)."""
    s = (raw or "").strip().rstrip("|").strip()
    if not s or s == "-":
        return "", ""
    low = s.lower()
    if low.startswith("url:"):
        return "", s[4:].strip()
    if low.startswith("text:"):
        return s[5:].strip(), ""
    return s, ""


def _lynis_ref(test_id: str) -> str:
    """Canonical upstream reference URL for a Lynis control id."""
    tid = (test_id or "").strip()
    if not tid:
        return ""
    return f"{LYNIS_REF_BASE}{tid}/"
