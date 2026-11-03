"""The body `narvy cloud-scan --upload` sends: findings and scan metadata only.

Built from an allow-list of finding fields, never from the raw provider report,
and checked before it leaves the machine. The upload is refused, not sent,
when any text in it carries:

- a value of a credential environment variable (AWS, Google);
- a secret of the credentials the scan actually used: the AWS key id, secret
  and session token the boto3 chain resolved (profile, SSO, env, role), the
  Google access token and refresh token (ADC);
- a credential shape: AWS key id (AKIA/ASIA/...), private key block, Google
  OAuth access token (ya29.), Google OAuth client secret (GOCSPX-), Google
  refresh token (1//).

Every string of the body is checked as it is, nested values included, so a
secret that JSON would escape is still found.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional

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
    re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|AGPA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}"),
    re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{10,}"),
    re.compile(r"(?<![0-9A-Za-z/])1//[0-9A-Za-z_\-]{20,}"),
)

_MIN_SECRET_LEN = 8


class CredentialInPayload(RuntimeError):
    """The upload body carries credential material: it is not sent."""


def _as_text(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, (dict, list, tuple)):
        return json.dumps(v, ensure_ascii=False, default=str, sort_keys=True)
    return str(v)


def _clean_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _as_text(f.get(k)) for k in FINDING_FIELDS}


def coverage_summary(coverage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Status and count only: the error strings stay local (they name ARNs and APIs)."""
    cov = coverage or {}
    try:
        skipped = max(0, int(cov.get("checks_skipped") or 0))
    except (TypeError, ValueError):
        skipped = 0
    return {
        "status": "partial" if cov.get("status") == "partial" else "complete",
        "checks_skipped": skipped,
    }


def provider_secrets(provider: str, environ=None) -> List[str]:
    """The secret values of the credentials this process uses for ``provider``:
    resolved through the same chains the scan used, kept in memory only to
    check the upload against them."""
    out: List[str] = []
    if provider == "aws":
        try:
            import boto3
            creds = boto3.Session().get_credentials()
            if creds is not None:
                fz = creds.get_frozen_credentials()
                out += [fz.access_key, fz.secret_key, fz.token]
        except Exception:  # noqa: BLE001 - no resolvable credentials: nothing to add
            pass
    if provider == "gcp":
        try:
            from . import gcp_scan
            out += google_secrets(gcp_scan.last_credentials)
        except Exception:  # noqa: BLE001
            pass
    return [s for s in out if isinstance(s, str) and len(s.strip()) >= _MIN_SECRET_LEN]


def google_secrets(credentials: Any) -> List[str]:
    if credentials is None:
        return []
    vals = []
    for attr in ("token", "refresh_token", "_refresh_token", "client_secret", "_client_secret",
                 "_private_key_id"):
        v = getattr(credentials, attr, None)
        if isinstance(v, str):
            vals.append(v)
    return vals


def build_body(provider: str, account_id: str, findings: List[Dict[str, Any]],
               coverage: Optional[Dict[str, Any]] = None,
               scan_seconds: Optional[float] = None,
               checks_passed: Optional[int] = None,
               secrets: Optional[Iterable[str]] = None) -> Dict[str, Any]:
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
    assert_no_credentials(body, secrets=secrets)
    return body


def _strings(v: Any) -> Iterator[str]:
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield str(k)
            yield from _strings(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _strings(x)


def assert_no_credentials(body: Dict[str, Any], environ=None,
                          secrets: Optional[Iterable[str]] = None) -> None:
    """Raise CredentialInPayload when ``body`` carries credential material."""
    env = os.environ if environ is None else environ
    named = []
    for name in CREDENTIAL_ENV_VARS:
        value = (env.get(name) or "").strip()
        if len(value) >= _MIN_SECRET_LEN:
            named.append((name, value))
    for value in secrets or []:
        if isinstance(value, str) and len(value.strip()) >= _MIN_SECRET_LEN:
            named.append(("the scan's own credentials", value.strip()))
    for text in _strings(body):
        for name, value in named:
            if value in text:
                raise CredentialInPayload(f"the upload would contain a value of {name}; nothing was sent")
        for pat in _KEY_PATTERNS:
            if pat.search(text):
                raise CredentialInPayload("the upload would contain credential material; nothing was sent")
