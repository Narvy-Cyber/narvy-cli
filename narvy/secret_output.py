"""CLI wiring of narvy/secret_presentation.py (honest secret wording + masking).

narvy/secret_presentation.py is a byte-identical copy of the hosted engine's
module, so the CLI and the dashboard word and mask a secret the same way.
This file only adapts the CLI finding shape to it:

* CLI findings keep description/cwe/recommendation in a nested ``details``
  dict. The hosted ingest (cli_ingest.normalize_finding) lifts them to the top
  level before fingerprinting, so the same lift happens here first: the
  classifier then sees what the server sees, and ``fingerprint_mask_basis`` is
  taken from exactly the inputs the server's fingerprint used before masking
  existed (no fixed/new churn on the dashboard).
* CLI findings carry no snippet. To recognise the provider format (and so
  word "format match" vs "pattern match", and spot public client keys) the
  matched line is read from disk into a transient ``line_content`` key, used
  by the classifier and removed again. It never reaches any output.
* Terminal, JSON and SARIF read ``details``; the honest, masked wording is
  copied back there. Severity stays upper-case (the CLI convention).

Runs once per scan, after every severity decision (secret_value_grade) and
before any output or upload.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional

from . import secret_presentation as sp

__all__ = ["present_cli_finding", "present_cli_findings", "present_web_findings",
           "json_secret_fields", "sarif_secret_properties", "sp"]

_PEM_BEGIN = "PRIVATE KEY-----"
_PEM_MAX_LINES = 120

# Fields of a presented finding the local JSON report carries.
JSON_SECRET_FIELDS = (
    "title", "title_fr", "description_fr", "remediation", "remediation_fr",
    "severity_rationale", "severity_rationale_fr", "secret_confidence", "secret_tested",
    "secret_public_by_design", "secret_kind", "secret_match_basis", "original_severity",
)


def _lift(f: Dict[str, Any], key: str, value: Any, added: List[str]) -> None:
    if value in (None, "", [], {}):
        return
    if f.get(key) in (None, "", [], {}):
        f[key] = value
        added.append(key)


def _resolve(file_path: str, root: Optional[str]) -> Optional[str]:
    if not file_path:
        return None
    if os.path.isabs(file_path):
        return file_path if os.path.isfile(file_path) else None
    if root:
        base = root if os.path.isdir(root) else os.path.dirname(root)
        p = os.path.join(base, file_path)
        if os.path.isfile(p):
            return p
    return None


def _matched_text(f: Dict[str, Any], root: Optional[str],
                  cache: Dict[str, Optional[List[str]]]) -> Optional[str]:
    """The finding's source line (a whole PEM block when the line opens one)."""
    try:
        line_no = int(f.get("line") or 0)
    except (TypeError, ValueError):
        return None
    path = _resolve(str(f.get("file_path") or ""), root)
    if not path or line_no <= 0:
        return None
    if path not in cache:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                cache[path] = fh.read().splitlines()
        except OSError:
            cache[path] = None
    lines = cache[path]
    if not lines or line_no > len(lines):
        return None
    text = lines[line_no - 1]
    if _PEM_BEGIN in text and "BEGIN" in text:
        block = [text]
        for nxt in lines[line_no:line_no + _PEM_MAX_LINES]:
            block.append(nxt)
            if "END" in nxt and _PEM_BEGIN in nxt:
                break
        text = "\n".join(block)
    return text


# CLI scan mode -> the {platform, scan_mode} the hosted engine files the upload
# under (cli_ingest: binary vs source), so the wording ("app package" vs
# "source code") and the client-context call match the dashboard's.
_SCAN_CONTEXT = {
    "android": {"platform": "android", "scan_mode": "binary"},
    "android-bundle": {"platform": "android", "scan_mode": "binary"},
    "ios-binary": {"platform": "ios", "scan_mode": "binary"},
    "android-source": {"platform": "android", "scan_mode": "source"},
    "ios-source": {"platform": "ios", "scan_mode": "source"},
    "web-source": {"platform": "web", "scan_mode": "source"},
}


def scan_context(scan_mode: Optional[str]) -> Optional[Dict[str, str]]:
    return _SCAN_CONTEXT.get(str(scan_mode or ""))


def _present(f: Dict[str, Any], context: Optional[Dict[str, Any]]) -> bool:
    return sp.present_finding(f, context) if context else sp.present_finding(f)


def present_cli_finding(f: Dict[str, Any], root: Optional[str] = None,
                        cache: Optional[Dict[str, Optional[List[str]]]] = None,
                        context: Optional[Dict[str, Any]] = None) -> bool:
    """Reword + mask one CLI finding in place. Returns True when it changed."""
    if not isinstance(f, dict):
        return False
    cache = {} if cache is None else cache
    details = f.get("details")
    if isinstance(details, dict):
        # Rule definitions share one details dict across all their findings
        # (and with the SARIF rule descriptors): never write into it.
        details = dict(details)
        f["details"] = details
    added: List[str] = []
    if isinstance(details, dict):
        _lift(f, "description", details.get("description"), added)
        _lift(f, "cwe", details.get("cwe"), added)
    elif isinstance(details, str):
        _lift(f, "description", details, added)

    transient = False
    view = dict(f, **{k: v for k, v in (context or {}).items() if not f.get(k)})
    if sp.is_secret_finding(view) and not f.get("secret_presentation"):
        b = f.get("fingerprint_mask_basis")
        if not (isinstance(b, dict) and b.get("scheme") == sp.MASK_BASIS_SCHEME):
            # Taken before line_content exists: the server never saw that line.
            f["fingerprint_mask_basis"] = sp.fingerprint_basis_of(f)
        if "line_content" not in f:
            text = _matched_text(f, root, cache)
            if text:
                f["line_content"] = text
                transient = True
    try:
        changed = _present(f, context)
    finally:
        if transient:
            f.pop("line_content", None)

    if not changed and not f.get("secret_presentation"):
        for k in added:  # nothing to present: leave the finding as it was
            f.pop(k, None)
        return False

    if isinstance(f.get("severity"), str):
        f["severity"] = f["severity"].upper()
    if isinstance(f.get("original_severity"), str):
        f["original_severity"] = f["original_severity"].upper()
    details = f.get("details")  # present_finding may have replaced it (masked copy)
    if isinstance(details, dict) and f.get("secret_presentation"):
        details["description"] = f.get("description") or details.get("description")
        if isinstance(f.get("remediation"), str):
            details["recommendation"] = f["remediation"]
    return True


def present_cli_findings(findings: Iterable[Dict[str, Any]], root: Optional[str] = None,
                         scan_mode: Optional[str] = None) -> int:
    """present_cli_finding over a scan's final findings. Never raises."""
    cache: Dict[str, Optional[List[str]]] = {}
    context = scan_context(scan_mode)
    n = 0
    for f in findings or []:
        try:
            if present_cli_finding(f, root, cache, context):
                n += 1
        except Exception:  # noqa: BLE001 - a presentation error must never lose a finding
            try:
                _mask_only(f)
            except Exception:  # noqa: BLE001
                pass
    return n


def _mask_only(f: Dict[str, Any]) -> None:
    """Fallback when wording failed: at least never show a format-matched value."""
    for k, v in list(f.items()):
        if isinstance(v, str) and k not in ("file_path", "rule_id", "severity"):
            f[k] = sp.mask_text(v)
        elif isinstance(v, dict):
            f[k] = {kk: sp.mask_text(vv) if isinstance(vv, str) else vv for kk, vv in v.items()}


def present_web_findings(findings: Iterable[Dict[str, Any]]) -> int:
    """web-scan findings: everything nuclei sees was served to browsers, so a
    public-by-design key there is client context (same as the hosted web scanner)."""
    n = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        try:
            f.setdefault("secret_client_context", True)
            if sp.present_finding(f):
                n += 1
        except Exception:  # noqa: BLE001
            try:
                _mask_only(f)
            except Exception:  # noqa: BLE001
                pass
    return n


def json_secret_fields(f: Dict[str, Any]) -> Dict[str, Any]:
    """Extra keys for the local JSON report (never secret_sha256 or basis internals)."""
    if not f.get("secret_presentation"):
        return {}
    return {k: f[k] for k in JSON_SECRET_FIELDS if k in f}


def sarif_secret_properties(f: Dict[str, Any]) -> Dict[str, Any]:
    if not f.get("secret_presentation"):
        return {}
    out: Dict[str, Any] = {"secret_tested": False}
    for k in ("secret_confidence", "secret_public_by_design", "secret_kind",
              "secret_match_basis", "original_severity"):
        if f.get(k) not in (None, ""):
            out[k] = f[k]
    return out
