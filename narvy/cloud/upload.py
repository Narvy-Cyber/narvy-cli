"""The body `narvy cloud-scan --upload` sends: findings and scan metadata only.

Built from an allow-list of finding fields, never from the raw provider report,
and checked before it leaves the machine: a body that carries a credential
value from this process's environment, an AWS access key id or a private key
is refused, not sent.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

# Fields of a normalized finding (narvy.cloud.normalize) that are uploaded.
FINDING_FIELDS = (
    "id", "title", "type", "rule_id", "cloud_rule_id", "severity", "category",
    "description", "file", "location", "line", "cwe", "cis", "owasp",
    "remediation", "engine", "confidence", "surface", "discriminator",
)

# Environment variables that hold credential material for the AWS and Google
# credential chains. Their VALUES must never appear in an upload.
CREDENTIAL_ENV_VARS = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
)

_KEY_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}"),
)


class CredentialInPayload(RuntimeError):
    """The upload body carries credential material: it is not sent."""


def _clean_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k in FINDING_FIELDS:
        v = f.get(k)
        if v is None or isinstance(v, (int, float)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


def coverage_summary(coverage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Status and count only: the error strings stay local (they name ARNs and APIs)."""
    cov = coverage or {}
    return {
        "status": "partial" if cov.get("status") == "partial" else "complete",
        "checks_skipped": int(cov.get("checks_skipped") or 0),
    }


def build_body(provider: str, account_id: str, findings: List[Dict[str, Any]],
               coverage: Optional[Dict[str, Any]] = None,
               scan_seconds: Optional[float] = None,
               checks_passed: Optional[int] = None) -> Dict[str, Any]:
    label = {"aws": "AWS", "gcp": "GCP"}.get(provider, provider.upper())
    body = {
        "app_name": f"{label} {account_id}".strip(),
        "platform": "cloud",
        "scan_mode": "cloud",
        "version": account_id or provider,
        "findings": [_clean_finding(f) for f in findings if isinstance(f, dict)],
        "scan_seconds": round(float(scan_seconds), 1) if scan_seconds is not None else None,
        "cloud": {
            "provider": provider,
            "account_id": account_id,
            "coverage": coverage_summary(coverage),
            "checks_passed": int(checks_passed or 0),
        },
    }
    assert_no_credentials(body)
    return body


def assert_no_credentials(body: Dict[str, Any], environ=None) -> None:
    """Raise CredentialInPayload when ``body`` carries credential material."""
    text = json.dumps(body, default=str)
    env = os.environ if environ is None else environ
    for name in CREDENTIAL_ENV_VARS:
        value = (env.get(name) or "").strip()
        if len(value) >= 8 and value in text:
            raise CredentialInPayload(f"the upload would contain the value of {name}; nothing was sent")
    for pat in _KEY_PATTERNS:
        if pat.search(text):
            raise CredentialInPayload("the upload would contain credential material; nothing was sent")
