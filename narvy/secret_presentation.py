"""Honest wording and masking of secret findings (2026-10-04).

Narvy never tests a secret: no login, no API call, no revocation check. A
secret finding only says "this value has the shape of a credential". This
module is the one place that turns any detector's secret finding into what
the customer sees:

* wording: "Potential secret: <kind> (format match, not tested)" for a value
  that matches a provider's published format, "(pattern match, not tested)"
  for a name / entropy detection. EN and FR are stamped on the finding
  (``title`` / ``title_fr``, ``description`` / ``description_fr``,
  ``remediation`` / ``remediation_fr``, ``severity_rationale`` /
  ``severity_rationale_fr``). Severity is never changed for a secret.
* confidence: ``secret_confidence`` is "likely" only when a deterministic
  validator exists for the value (provider structure or checksum, PEM
  structure), "potential" otherwise. Never "confirmed". ``confidence`` is set
  to the same word only when the finding has none.
* public-by-design keys (Stripe / Supabase publishable keys, Mapbox public
  tokens, Supabase anon JWTs, Google AIza keys in client code) are not
  secrets: they become Info "Public client key ... check its restrictions".
* masking: every secret value is replaced by ``abcd\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022wxyz`` (first 4
  and last 4 characters, values shorter than 20 characters fully masked) in
  every text field of the finding. File and line stay visible. A
  ``secret_sha256`` of the first raw value is kept for dedup.
* fingerprint stability: before any text field that feeds the vulnerability
  fingerprint (code snippet / sink / description) is changed, the hashes the
  fingerprint would have used are stamped in ``fingerprint_mask_basis``.
  website/vulnerability_fingerprint.py reads them, so a masked finding keeps
  the fingerprint it had when it was stored in clear (no migration).

Pure stdlib, no project import: the CLI ships a byte-identical copy
(narvy/secret_presentation.py). Idempotent: running it twice is a no-op.
Nothing here logs or returns a raw secret value.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import re
import zlib
from typing import Any, Dict, Iterable, List, Optional, Tuple

PRESENTATION_VERSION = 1
MASK_BASIS_SCHEME = "mask-v1"
# Bullets, not asterisks: "********" is Markdown emphasis and vanished from
# rendered descriptions (the PDF showed "AIzad9Fg", which reads as a short key).
MASK_FILL = "\u2022" * 8
_MIN_PARTIAL_LEN = 20  # below this the value is fully masked (at least 12 chars hidden)

# ---------------------------------------------------------------------------
# Masking primitives
# ---------------------------------------------------------------------------


def mask_value(value: Any) -> str:
    """First 4 + last 4 characters, the rest replaced by a fixed-width fill
    (the length is not revealed). Values shorter than 20 characters are fully
    masked, so at most 8 of at least 20 characters are ever shown."""
    v = str(value or "")
    if len(v) < _MIN_PARTIAL_LEN:
        return MASK_FILL
    return v[:4] + MASK_FILL + v[-4:]


def secret_sha256(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", "surrogatepass")).hexdigest()


def _is_masked(value: str) -> bool:
    return MASK_FILL in value or "***" in value


# Provider formats: (provider, regex, strength). Specific prefixes first.
# Prefixes that GitHub push protection / gitleaks match are split so this
# file itself does not trip a secret scanner.
_TOKEN_FORMATS: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("github_fine_grained_pat", re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"), "structure"),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"), "checksum"),
    ("stripe_secret_key", re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{24,247}"), "structure"),
    ("stripe_test_key", re.compile(r"(?:sk|rk)_test_[0-9A-Za-z]{24,247}"), "structure"),
    ("stripe_publishable_key", re.compile(r"pk_(?:live|test)_[0-9A-Za-z]{24,247}"), "structure"),
    ("aws_access_key_id", re.compile(r"(?:AKIA|ASIA)[A-Z2-7]{16}"), "structure"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}"), "structure"),
    ("slack_token", re.compile(r"xox[bpase]-(?:\d{6,15}-){1,3}[A-Za-z0-9]{24,64}"), "structure"),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "structure"),
    ("google_oauth_secret", re.compile(r"GOCSPX-[0-9A-Za-z_\-]{28}"), "structure"),
    ("sendgrid_api_key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), "structure"),
    ("gitlab_pat", re.compile(r"glpat-[A-Za-z0-9_\-]{20}"), "structure"),
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{36}"), "structure"),
    ("openai_api_key", re.compile(r"sk-(?:proj-|svcacct-|admin-)[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "structure"),
    ("anthropic_api_key", re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}"), "structure"),
    ("twilio_api_key", re.compile(r"SK[0-9a-f]{32}"), "structure"),
    ("square_token", re.compile(r"sq0(?:atp|csp)-[0-9A-Za-z_\-]{22,43}"), "structure"),
    ("telegram_bot_token", re.compile(r"\d{8,10}:AA[0-9A-Za-z_\-]{33}"), "structure"),
    ("mailchimp_api_key", re.compile(r"[0-9a-f]{32}-us\d{1,2}"), "structure"),
    ("mapbox_public_token", re.compile(r"pk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"), "structure"),
    ("mapbox_secret_token", re.compile(r"sk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"), "structure"),
    ("supabase_publishable_key", re.compile(r"sb_publishable_[A-Za-z0-9_\-]{20,}"), "structure"),
    ("supabase_secret_key", re.compile(r"sb_secret_[A-Za-z0-9_\-]{20,}"), "structure"),
]
# Formats that may run into a following word character (variable-length).
_OPEN_END = {"stripe_secret_key", "stripe_test_key", "stripe_publishable_key", "openai_api_key",
             "anthropic_api_key", "square_token", "supabase_publishable_key", "supabase_secret_key",
             "mapbox_public_token", "mapbox_secret_token"}
_PUBLIC_PROVIDERS = {"stripe_publishable_key", "supabase_publishable_key", "mapbox_public_token"}

_PEM_RE = re.compile(
    r"(-----BEGIN (?P<label>(?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----)"
    r"(?P<body>.*?)(-----END (?P=label)-----)", re.DOTALL)
_PEM_HEADER_ONLY_RE = re.compile(
    r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)"
    r"((?:\\n|\\r|\s)*)([A-Za-z0-9+/=\\\s]{16,})")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
_URI_CRED_RE = re.compile(
    r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|ftp|sftp|smtps?|https?|jdbc:[a-z]+)://"
    r"[^\s:@/'\"`]+:)([^\s@/'\"`]{3,})(@)")
_BEARER_RE = re.compile(r"(?i)(\b(?:bearer|basic)\s+)([A-Za-z0-9_\-\.=+/]{20,})")
_CRED_NAME = (r"(?:pass(?:word|wd|phrase)?|pwd|secret(?:_?key)?|api[_\-]?key|apikey|access[_\-]?key|"
              r"auth[_\-]?token|token|private[_\-]?key|client[_\-]?secret|credentials?|"
              r"encryption[_\-]?key|crypto[_\-]?key|signing[_\-]?key|jwt[_\-]?secret|key)")
_ASSIGN_RE = re.compile(
    r"(?i)(?P<name>[A-Za-z0-9_\-.]*" + _CRED_NAME + r"[A-Za-z0-9_\-]*)[\"']?\s*(?:=|:|=>|,|\()\s*"
    r"(?:@|[a-z]\s*)?[\"'`](?P<v>[^\"'`\n]{4,512})[\"'`]")
_XML_VALUE_RE = re.compile(
    r"(?i)<(?:string|item)[^>]*name=\"[^\"]*" + _CRED_NAME + r"[^\"]*\"[^>]*>(?P<v>[^<]{4,512})</")
_DESC_VALUE_RE = re.compile(
    r"(?i)\b(?:key|secret|token|password|passwd|value|credential|found|match(?:ed)?)\s*[:=]\s*"
    r"[\"'`]?(?P<v>[^\s\"'`,;]{6,512})")
_QUOTED_RE = re.compile(r"[\"'`]([^\"'`\n]{8,512})[\"'`]")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _github_checksum_ok(token: str) -> bool:
    m = re.fullmatch(r"gh[pousr]_([A-Za-z0-9]{30})([A-Za-z0-9]{6})", token or "")
    if not m:
        return False
    n = zlib.crc32(m.group(1).encode()) & 0xFFFFFFFF
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = _B62[r] + out
    return out.rjust(6, "0") == m.group(2)


def find_provider_tokens(text: str) -> List[Tuple[str, str, str]]:
    """[(provider, token, strength)] in `text`, non-overlapping."""
    out: List[Tuple[str, str, str]] = []
    taken: List[Tuple[int, int]] = []
    text = text or ""
    for provider, rx, strength in _TOKEN_FORMATS:
        for m in rx.finditer(text):
            s, e = m.span()
            if provider != "slack_webhook" and s > 0 and (text[s - 1].isalnum() or text[s - 1] == "_"):
                continue
            if provider not in _OPEN_END and e < len(text) and (text[e].isalnum() or text[e] == "_"):
                continue
            if any(not (e <= a or s >= b) for a, b in taken):
                continue
            taken.append((s, e))
            out.append((provider, m.group(0), strength))
    return out


def _jwt_role(token: str) -> Optional[str]:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part.encode()).decode("utf-8", "ignore"))
        role = payload.get("role") if isinstance(payload, dict) else None
        return str(role) if role else None
    except Exception:  # noqa: BLE001
        return None


# Cheap prefilter: a text containing none of these cannot hold a token
# mask_text() would change. Plain substring tests (C speed): one big regex
# alternation cost ~65 us per 2 KB finding. '@' stands for the
# user:password@host URI form, checked precisely afterwards.
_QUICK_LITERALS = (
    "AKIA", "ASIA", "AIza", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "_live_",
    "_test_", "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xoxe-", "hooks.slack", "GOCSPX-", "SG.",
    "glpat-", "npm_", "sk-proj-", "sk-svcacct-", "sk-admin-", "sk-ant-", "T3BlbkFJ", "sq0",
    ":AA", "k.eyJ", "sb_publishable_", "sb_secret_", "PRIVATE KEY", "eyJ",
    "Bearer ", "bearer ", "BEARER ", "Basic ", "basic ", "BASIC ",
)
_QUICK_REGEXES = (re.compile(r"SK[0-9a-f]{32}"), re.compile(r"[0-9a-f]{32}-us[0-9]"))


class _QuickRe:
    """Drop-in for the former regex prefilter (.search(text) -> truthy)."""

    @staticmethod
    def search(text: str) -> bool:
        if any(t in text for t in _QUICK_LITERALS):
            return True
        if "://" in text and "@" in text:  # user:password@host
            return True
        if ("SK" in text or "-us" in text) and any(rx.search(text) for rx in _QUICK_REGEXES):
            return True
        return False


_QUICK_RE = _QuickRe()


def mask_text(text: str, raw_values: Iterable[str] = ()) -> str:
    """Mask every known raw value and every provider-format / PEM / JWT /
    URI-password / bearer token in `text`. Idempotent."""
    if not text or not isinstance(text, str):
        return text
    raw_values = [r for r in raw_values if r]
    if not raw_values and not _QUICK_RE.search(text):
        return text
    out = text
    for raw in sorted({r for r in raw_values if r and len(r) >= 4}, key=len, reverse=True):
        if raw in out:
            out = out.replace(raw, mask_value(raw))
    out = _PEM_RE.sub(lambda m: f"{m.group(1)}[private key material masked]{m.group(4)}", out)
    out = _PEM_HEADER_ONLY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[private key material masked]", out)
    for _provider, token, _s in find_provider_tokens(out):
        out = out.replace(token, mask_value(token))
    out = _JWT_RE.sub(lambda m: mask_value(m.group(0)), out)
    out = _URI_CRED_RE.sub(lambda m: m.group(1) + MASK_FILL + m.group(3)
                           if not _is_masked(m.group(2)) else m.group(0), out)
    out = _BEARER_RE.sub(lambda m: m.group(1) + mask_value(m.group(2))
                         if not _is_masked(m.group(2)) else m.group(0), out)
    return out


# ---------------------------------------------------------------------------
# Is this a secret finding?
# ---------------------------------------------------------------------------

_SECRET_ID_RE = re.compile(
    r"(?i)(?:^|[._\-/])secrets?[._\-/]|hard[-_ ]?coded[-_ ]?(?:secret|api[-_ ]?key|password|passwd|credential|"
    r"token|key|crypto|encryption|private|jwt|symmetric|aes|session)|generic[-_]high[-_]entropy|"
    r"credentials?[-_]in[-_]uri|detected[-_]private[-_]key|private[-_]key[-_](?:file|encrypted|block)|"
    r"pgp[-_]private[-_]key|aws[-_](?:secret|access)[-_]key|enhanced_auth_aws_key|"
    r"api[-_]?key[-_](?:exposed|leak|found)|exposed[-_](?:secret|api[-_]?key|credential|token)|"
    r"leaked[-_](?:secret|key|credential|token)|^and-s-0(?:09|10)$|^secret$|^hardcoded_credentials?$|"
    r"use_of_hard-coded_(?:credentials|cryptographic_key|password)|bcrypt[-_]hash[-_]hardcoded|"
    r"container_secret|cred_hardcoded")
_SECRET_TITLE_RE = re.compile(
    r"(?i)\b(?:hard-?coded|embedded|exposed|leaked|plaintext)\b[^.\n]{0,40}\b(?:secrets?|api[\s_-]?keys?|passwords?|"
    r"credentials?|tokens?|private keys?|access keys?|encryption keys?|crypto(?:graphic)? keys?|"
    r"jwt(?: sign(?:ing)?)? secrets?|symmetric (?:encryption )?keys?|secret keys?)\b|"
    r"^(?:potential )?(?:api key|secret|private key|access key|token) (?:found|detected)|"
    r"\b(?:api key|secret|token|private key|access key id?)\b[^.\n]{0,20}\b(?:found|detected) "
    r"(?:in|hardcoded)|^generic high entropy assignment$|^credentials embedded in url$|^potential secret")
_SECRET_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-547"}
# Same CWE family, different problem: these are NOT a secret value in code.
_NOT_SECRET_RE = re.compile(
    r"(?i)^\.?env file|\bfile (?:in|committed to) (?:the )?repositor|\blog(?:s|ged|ging)?\b|logcat|password[- ]?hash|hash(?:ing|ed)? (?:of|for) password|"
    r"md5|sha-?1|login\.defs|sudo|\bssh\b|grub|bootloader|pam_|world-readable|permissions? on|"
    r"plaintext (?:password )?storage|stored in (?:plain|clear)|sharedpreferences|keystore usage|"
    r"password (?:field|policy|strength|age|reset)|autocomplete|input type|keyboard cache|"
    r"secure ?text ?entry|clipboard|backup")


def _s(v: Any) -> str:
    return v if isinstance(v, str) else ("" if v is None else str(v))


def _ids_of(f: Dict[str, Any]) -> List[str]:
    out = []
    for k in ("rule_id", "check_id", "type", "vulnerability_type", "vuln_type", "vuln_id", "id",
              "template_id", "template-id", "category"):
        v = f.get(k)
        if isinstance(v, str) and v:
            out.append(v)
    return out


def _cwes_of(f: Dict[str, Any]) -> List[str]:
    vals: List[str] = []
    for k in ("cwe", "cwe_id", "cwe_ids", "cwes"):
        v = f.get(k)
        if isinstance(v, (list, tuple)):
            vals.extend(_s(x) for x in v)
        elif v:
            vals.append(_s(v))
    out = []
    for v in vals:
        for m in re.finditer(r"(?i)CWE[-_ ]?(\d+)", v):
            out.append("CWE-" + m.group(1))
        if v.strip().isdigit():
            out.append("CWE-" + v.strip())
    return out


def is_secret_finding(f: Any) -> bool:
    """A finding whose subject is a secret value present in the artifact."""
    if not isinstance(f, dict):
        return False
    if f.get("secret_presentation") or f.get("secret_public_by_design"):
        return True
    if str(f.get("platform") or "").lower() == "host" or str(f.get("scan_mode") or "") == "ssh":
        return False
    title = _s(f.get("title") or f.get("name"))
    ids = _ids_of(f)
    if any(_NOT_SECRET_RE.search(x) for x in [title] + ids):
        return False
    if any(_SECRET_ID_RE.search(x) for x in ids):
        return True
    if title and _SECRET_TITLE_RE.search(title):
        return True
    cwes = set(_cwes_of(f))
    if cwes & _SECRET_CWES and not re.search(r"(?i)\b(?:url|https?|cleartext|ssl|tls|certificate)\b", title):
        return True
    ev = f.get("evidence")
    if isinstance(ev, dict) and ev.get("kind") == "secret":
        return True
    return False


# ---------------------------------------------------------------------------
# Raw values of one finding
# ---------------------------------------------------------------------------

# Keys whose value IS the secret.
_VALUE_KEYS = ("secret_value", "matched_value", "matched_secret", "raw_value", "raw_secret",
               "secret", "Secret", "match", "Match", "matched", "matched_string", "key_value",
               "extracted_value", "secret_match", "value", "token", "literal", "string_value")
# Keys whose text is shown to the customer and may carry the value.
_TEXT_KEYS = ("code_snippet", "snippet", "code", "vulnerable_code", "sink", "evidence",
              "evidence_text", "context", "line_content", "matched_line", "details", "detail",
              "proof", "message", "description", "title", "name", "extra", "matcher_name",
              "extracted_results", "extracted-results", "data", "value_preview", "raw",
              "remediation", "recommendation", "impact", "summary", "ai_explanation",
              "explanation", "customer_summary", "triage_reason", "reason", "notes", "Match",
              "match", "lines", "content", "request", "response", "curl_command", "location")
# Identity keys never rewritten (fingerprint / grouping / navigation).
_IDENTITY_KEYS = {"file", "file_path", "path", "filename", "rule_id", "check_id", "id", "vuln_id",
                  "type", "vulnerability_type", "vuln_type", "cwe", "cwe_id", "owasp", "masvs",
                  "masvs_id", "fingerprint", "secret_sha256", "fingerprint_mask_basis",
                  "fingerprint_basis", "line", "line_number", "start_line", "end_line", "severity",
                  "category", "platform", "component", "activity", "service", "class", "class_name",
                  "function", "function_name", "method", "url", "endpoint", "parameter", "param",
                  "template_id", "template-id", "host", "package", "package_name", "scan_id",
                  "secret_client_context", "secret_presentation", "secret_kind",
                  "secret_match_basis", "secret_confidence"}


def _strings(v: Any) -> Iterable[str]:
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            if k not in _IDENTITY_KEYS or k == "location":
                yield from _strings(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _strings(x)


def _strip_trunc(v: str) -> str:
    """Analyzers truncate long values with '...' / an ellipsis: the raw value
    is what precedes it."""
    v = v.strip()
    for tail in ("...", "\u2026"):
        if v.endswith(tail) and len(v) > len(tail) + 3:
            v = v[: -len(tail)]
    return v


def _plausible_value(v: str) -> bool:
    v = v.strip()
    if len(v) < 4 or _is_masked(v):
        return False
    if re.fullmatch(r"(?i)(?:true|false|null|none|nil|undefined|string|password|secret|token|"
                    r"api_?key|key|value|\$\{?\w+\}?|%[sd@])", v):
        return False
    return True


def _raw_values(f: Dict[str, Any]) -> List[str]:
    vals: List[str] = []
    for k in _VALUE_KEYS:
        v = f.get(k)
        if isinstance(v, str) and _plausible_value(v) and len(v) >= 6:
            vals.append(v.strip())
        elif isinstance(v, list):
            vals.extend(x.strip() for x in v if isinstance(x, str) and _plausible_value(x) and len(x) >= 6)
    for k in ("metadata", "extra"):
        sub = f.get(k)
        if isinstance(sub, dict):
            for kk in ("secret", "secret_value", "matched_value", "match"):
                v = sub.get(kk)
                if isinstance(v, str) and _plausible_value(v) and len(v) >= 6:
                    vals.append(v.strip())
    blob_parts = []
    for k in _TEXT_KEYS:
        if k in f:
            blob_parts.extend(_strings(f.get(k)))
    blob = "\n".join(blob_parts)
    for _p, tok, _s2 in find_provider_tokens(blob):
        vals.append(tok)
    for m in _ASSIGN_RE.finditer(blob):
        v = m.group("v")
        if _plausible_value(v) and not v.lower().startswith(("http://", "https://")):
            vals.append(v)
    for m in _URI_CRED_RE.finditer(blob):
        if _plausible_value(m.group(2)):
            vals.append(m.group(2))
    for m in _XML_VALUE_RE.finditer(blob):
        if _plausible_value(m.group("v")):
            vals.append(m.group("v"))
    desc = _s(f.get("description")) + "\n" + _s(f.get("title"))
    for m in _DESC_VALUE_RE.finditer(desc):
        v = m.group("v").rstrip(".…")
        if v.endswith("..."):
            v = v[:-3]
        if _plausible_value(v) and (_entropy(v) >= 3.0 or any(c.isdigit() for c in v)) and "/" not in v[:1]:
            vals.append(v)
    # Quoted literal in the description ("... appears to be hardcoded: \"...\"").
    for m in _QUOTED_RE.finditer(_s(f.get("description"))):
        v = m.group(1).rstrip(".…")
        if _plausible_value(v):
            vals.append(v)
    # A secret finding whose snippet has a single quoted literal: that literal.
    if not vals:
        lits = [m.group(1) for m in _QUOTED_RE.finditer(blob)
                if _plausible_value(m.group(1)) and " " not in m.group(1).strip()
                and not m.group(1).lower().startswith(("http://", "https://"))]
        vals.extend(lits[:3])
    seen, out = set(), []
    for v in (_strip_trunc(x) for x in vals):
        if v not in seen and _plausible_value(v):
            seen.add(v)
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# Fingerprint basis (mirror of website/vulnerability_fingerprint.py)
# ---------------------------------------------------------------------------

_GENERIC_COMPONENTS = frozenset({
    'activity', 'activities', 'service', 'services', 'receiver', 'receivers',
    'broadcast_receiver', 'broadcast_receivers', 'provider', 'providers',
    'content_provider', 'content_providers', 'application', 'manifest',
    'component', 'components',
})


def _fp_normalize(value: str) -> str:
    if not value:
        return ''
    return re.sub(r'\s+', '_', value.lower().strip())


def _fp_sink(f: Dict[str, Any]) -> Optional[str]:
    """Exactly vulnerability_fingerprint._extract_sink_pattern (+ the
    generic-component manifest context fallback of generate_sast_fingerprint)."""
    ev = f.get('evidence')
    for c in (f.get('code_snippet'), f.get('sink'), f.get('vulnerable_code'),
              ev.get('code') if isinstance(ev, dict) and 'kind' not in ev else None):
        if c and len(str(c)) > 10:
            return re.sub(r'\s+', ' ', str(c).strip())[:200]
    comp = f.get('component')
    loc = f.get('location')
    if not comp and isinstance(loc, dict):
        comp = loc.get('component')
    if comp and _fp_normalize(str(comp)) in _GENERIC_COMPONENTS:
        if isinstance(loc, dict) and loc.get('line') is not None:
            ctx = str(loc.get('context') or '').strip()
            if len(ctx) > 10:
                return re.sub(r'\s+', ' ', ctx)[:200]
    return None


def fingerprint_basis_of(f: Dict[str, Any]) -> Dict[str, Any]:
    sink = _fp_sink(f)
    desc = f.get('description')
    return {
        "scheme": MASK_BASIS_SCHEME,
        "sink": hashlib.md5(sink.encode()).hexdigest()[:8] if sink else None,
        "desc": (hashlib.sha256(_fp_normalize(str(desc)).encode()).hexdigest()[:16]
                 if desc else None),
    }


def _stamp_basis(f: Dict[str, Any]) -> None:
    b = f.get("fingerprint_mask_basis")
    if isinstance(b, dict) and b.get("scheme") == MASK_BASIS_SCHEME:
        return  # first (clear-text) basis wins
    f["fingerprint_mask_basis"] = fingerprint_basis_of(f)


# ---------------------------------------------------------------------------
# Wording (EN + FR). Zero em-dash in either language.
# ---------------------------------------------------------------------------

_PROVIDER_LABELS = {
    "github_fine_grained_pat": ("GitHub fine-grained access token", "jeton d'accès GitHub à granularité fine"),
    "github_token": ("GitHub token", "jeton GitHub"),
    "stripe_secret_key": ("Stripe live secret key", "clé secrète Stripe de production"),
    "stripe_test_key": ("Stripe test-mode secret key", "clé secrète Stripe de test"),
    "stripe_publishable_key": ("Stripe publishable key", "clé publiable Stripe"),
    "aws_access_key_id": ("AWS access key ID", "identifiant de clé d'accès AWS"),
    "slack_webhook": ("Slack webhook URL", "URL de webhook Slack"),
    "slack_token": ("Slack token", "jeton Slack"),
    "google_api_key": ("Google API key", "clé d'API Google"),
    "google_oauth_secret": ("Google OAuth client secret", "secret client OAuth Google"),
    "sendgrid_api_key": ("SendGrid API key", "clé d'API SendGrid"),
    "gitlab_pat": ("GitLab access token", "jeton d'accès GitLab"),
    "npm_token": ("npm access token", "jeton d'accès npm"),
    "openai_api_key": ("OpenAI API key", "clé d'API OpenAI"),
    "anthropic_api_key": ("Anthropic API key", "clé d'API Anthropic"),
    "twilio_api_key": ("Twilio API key", "clé d'API Twilio"),
    "square_token": ("Square token", "jeton Square"),
    "telegram_bot_token": ("Telegram bot token", "jeton de bot Telegram"),
    "mailchimp_api_key": ("Mailchimp API key", "clé d'API Mailchimp"),
    "mapbox_public_token": ("Mapbox public token", "jeton public Mapbox"),
    "mapbox_secret_token": ("Mapbox secret token", "jeton secret Mapbox"),
    "supabase_publishable_key": ("Supabase publishable key", "clé publiable Supabase"),
    "supabase_secret_key": ("Supabase secret key", "clé secrète Supabase"),
    "supabase_anon_key": ("Supabase anon key", "clé anon Supabase"),
    "private_key": ("private key", "clé privée"),
    "jwt": ("JSON Web Token", "jeton JWT"),
}
_KIND_LABELS = {
    "password": ("hardcoded password", "mot de passe codé en dur"),
    "crypto_key": ("hardcoded encryption key", "clé de chiffrement codée en dur"),
    "jwt_secret": ("hardcoded token signing secret", "secret de signature de jetons codé en dur"),
    "uri_credentials": ("credentials in a URL", "identifiants dans une URL"),
    "password_hash": ("hardcoded password hash", "empreinte de mot de passe codée en dur"),
    "aws_secret": ("AWS secret access key", "clé d'accès secrète AWS"),
    "generic": (None, None),
}


def _subject(f: Dict[str, Any], lang: str) -> str:
    """What a reader of the value would have to read."""
    plat = str(f.get("platform") or "").lower()
    mode = str(f.get("scan_mode") or f.get("analysis_mode") or "").lower()
    if mode == "source" or plat in ("source", "source_code", "web_source"):
        return "source code" if lang == "en" else "code source"
    if plat in ("android", "ios"):
        return "app package" if lang == "en" else "paquet de l'application"
    if plat == "container":
        return "container image" if lang == "en" else "image de conteneur"
    return "analysed files" if lang == "en" else "fichiers analysés"


def _location(f: Dict[str, Any]) -> str:
    file_ = f.get("file") or f.get("file_path")
    loc = f.get("location")
    line = f.get("line") or f.get("line_number")
    if not file_ and isinstance(loc, dict):
        file_ = loc.get("file") or loc.get("file_path") or loc.get("path")
        line = line or loc.get("line")
    if not file_ and isinstance(loc, str):
        return loc
    if not file_:
        return ""
    try:
        if line and int(line) > 0:
            return f"{file_}:{int(line)}"
    except (TypeError, ValueError):
        pass
    return str(file_)


def _wording(kind: str, provider: Optional[str], basis: str, confidence: str,
             masked: Optional[str], f: Dict[str, Any]) -> Dict[str, str]:
    if provider:
        lab_en, lab_fr = _PROVIDER_LABELS.get(provider, (provider, provider))
    else:
        lab_en, lab_fr = _KIND_LABELS.get(kind, (None, None))
    tag_en = "format match, not tested" if basis == "format" else "pattern match, not tested"
    tag_fr = ("correspondance de format, non testé" if basis == "format"
              else "correspondance de motif, non testé")
    title_en = (f"Potential secret: {lab_en} ({tag_en})" if lab_en
                else f"Potential secret ({tag_en})")
    title_fr = (f"Secret potentiel : {lab_fr} ({tag_fr})" if lab_fr
                else f"Secret potentiel ({tag_fr})")
    where = _location(f)
    art_en = _subject(f, "en")
    art_fr = _subject(f, "fr")
    if basis == "format":
        why_en = f"matches the published format of a {lab_en}"
        why_fr = f"correspond au format publié suivant : {lab_fr}"
        if provider == "github_token":
            why_en += " (checksum verified offline)"
            why_fr += " (somme de contrôle vérifiée hors ligne)"
        if provider == "private_key":
            why_en = "has the structure of a private key block"
            why_fr = "a la structure d'un bloc de clé privée"
    elif kind == "uri_credentials":
        why_en = "is a password written inside a URL"
        why_fr = "est un mot de passe écrit dans une URL"
    else:
        why_en = "is assigned to a credential-like name, or looks like key material"
        why_fr = "est affectée à un nom évoquant un identifiant, ou ressemble à une clé"
    loc_en = f" at {where}" if where else ""
    loc_fr = f" en {where}" if where else ""
    val_en = f" Value (masked): {masked}." if masked else ""
    val_fr = f" Valeur (masquée) : {masked}." if masked else ""
    conf_en = {"likely": "likely (the format is checked structurally)",
               "potential": "potential (no format check for this value)"}[confidence]
    conf_fr = {"likely": "probable (le format est vérifié structurellement)",
               "potential": "potentiel (aucune vérification de format pour cette valeur)"}[confidence]
    sev_en = ("Severity reflects the impact if this value is a real, active credential. Narvy "
              "did not test it.")
    sev_fr = ("La sévérité reflète l'impact si cette valeur est un identifiant réel et actif. "
              "Narvy ne l'a pas testée.")
    desc_en = (f"A value{loc_en} {why_en}.{val_en} Narvy did not test this value: it does not know "
               f"whether it is valid, active, revoked or restricted. Confidence: {conf_en}. If it is "
               f"a real credential, anyone who can read the {art_en} can read it too. {sev_en}")
    desc_fr = (f"Une valeur{loc_fr} {why_fr}.{val_fr} Narvy n'a pas testé cette valeur : il ne sait "
               f"pas si elle est valide, active, révoquée ou restreinte. Confiance : {conf_fr}. S'il "
               f"s'agit d'un véritable identifiant, toute personne pouvant lire le {art_fr} peut "
               f"aussi le lire. {sev_fr}")
    rem_en = ("Check whether this value is a real credential. If it is: remove it from the "
              f"{art_en} (keep it server-side, in a secrets manager, or inject it at build time "
              "from a protected store), then revoke it and issue a new one, because it may already "
              "have been copied. If it is not a credential (test value, identifier, public "
              "constant), mark the finding as a false positive.")
    rem_fr = ("Vérifiez s'il s'agit d'un véritable identifiant. Si oui : retirez-le du "
              f"{art_fr} (gardez-le côté serveur, dans un gestionnaire de secrets, ou injectez-le "
              "à la compilation depuis un stockage protégé), puis révoquez-le et émettez-en un "
              "nouveau, car il a pu être copié. Sinon (valeur de test, identifiant, constante "
              "publique), marquez le constat comme faux positif.")
    return {"title": title_en, "title_fr": title_fr, "description": desc_en,
            "description_fr": desc_fr, "remediation": rem_en, "remediation_fr": rem_fr,
            "severity_rationale": sev_en, "severity_rationale_fr": sev_fr}


def _public_wording(provider: str, masked: Optional[str], f: Dict[str, Any]) -> Dict[str, str]:
    lab_en, lab_fr = _PROVIDER_LABELS.get(provider, (provider, provider))
    where = _location(f)
    loc_en = f" at {where}" if where else ""
    loc_fr = f" en {where}" if where else ""
    val_en = f" Value (masked): {masked}." if masked else ""
    val_fr = f" Valeur (masquée) : {masked}." if masked else ""
    return {
        "title": f"Public client key: {lab_en} (not a secret, check its restrictions)",
        "title_fr": f"Clé client publique : {lab_fr} (pas un secret, vérifiez ses restrictions)",
        "description": (f"A {lab_en}{loc_en} is designed to ship in client apps and web pages, so "
                        f"it is not reported as a secret.{val_en} What protects it is its "
                        "configuration on the provider side (allowed apps, referrers, APIs, "
                        "quotas). Narvy did not test it and cannot see those restrictions."),
        "description_fr": (f"Une {lab_fr}{loc_fr} est conçue pour être livrée dans les applications "
                           f"et pages web clientes : elle n'est donc pas signalée comme un secret."
                           f"{val_fr} Ce qui la protège est sa configuration chez le fournisseur "
                           "(applications, référents, API autorisés, quotas). Narvy ne l'a pas "
                           "testée et ne voit pas ces restrictions."),
        "remediation": ("In the provider console, check that this key is restricted to your "
                        "apps or domains and to the APIs it needs."),
        "remediation_fr": ("Dans la console du fournisseur, vérifiez que cette clé est limitée à "
                           "vos applications ou domaines et aux API nécessaires."),
        "severity_rationale": "Informational: public by design, not a secret.",
        "severity_rationale_fr": "Informatif : publique par conception, pas un secret.",
    }


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

_CLIENT_FILE_RE = re.compile(
    r"(?i)(?:^|/)(?:google-services\.json|googleservice-info\.plist|strings\.xml|androidmanifest\.xml|"
    r"info\.plist|[^/]*\.(?:html?|vue|svelte|jsx|tsx|swift|m|mm|kt|java|dart|plist|xml|smali|bundle)|"
    r"(?:public|static|assets|www|frontend|client|web|src/app|app/src|res)/[^/]*\.[jt]sx?|"
    r"[^/]*firebase[^/]*\.[jt]s|environment[^/]*\.ts|[^/]*\.bundle\.js|index\.android\.bundle|main\.jsbundle)$")
_SERVER_HINT_RE = re.compile(r"(?i)(?:^|/)(?:server|backend|api|functions|lambda|cmd|internal|"
                             r"terraform|infra|deploy|scripts?)/|\.(?:py|go|rb|php|cs|env|tf|sh|ya?ml|"
                             r"toml|ini|cfg|conf)$")


def _is_client_context(f: Dict[str, Any]) -> bool:
    if f.get("secret_client_context") is True:
        return True  # set by the caller (web scanner: served to browsers)
    plat = str(f.get("platform") or "").lower()
    mode = str(f.get("scan_mode") or "").lower()
    path = _location(f).rsplit(":", 1)[0].replace("\\", "/")
    if path and _SERVER_HINT_RE.search(path):
        return False
    if plat in ("android", "ios", "flutter", "react_native") and mode != "source":
        return True  # a mobile app package is client code by definition
    if path and _CLIENT_FILE_RE.search(path):
        return True
    return plat in ("android", "ios")


def _kind_of(f: Dict[str, Any]) -> str:
    text = " ".join(_ids_of(f) + [_s(f.get("title"))]).lower()
    cwes = set(_cwes_of(f))
    if re.search(r"bcrypt|password[-_ ]hash", text):
        return "password_hash"
    if re.search(r"jwt|session[-_ ](?:hardcoded[-_ ])?secret|signing", text):
        return "jwt_secret"
    if re.search(r"in[-_ ]ur[il]|embedded in url|connection string", text) or "and-s-009" in text:
        return "uri_credentials"
    if re.search(r"private[-_ ]key", text):
        return "private_key"
    if re.search(r"aws[-_ ]?secret|secret[-_ ]?access[-_ ]?key", text):
        return "aws_secret"
    # CWE-321 alone (generic secret rules list it next to CWE-798, which
    # does not make every secret an encryption key).
    if ("CWE-321" in cwes and "CWE-798" not in cwes) \
            or re.search(r"encryption|crypto|symmetric|\baes\b|cipher", text) or "and-s-010" in text:
        return "crypto_key"
    if re.search(r"password|passwd|\bpwd\b", text) or "CWE-259" in cwes:
        return "password"
    return "generic"


def classify(f: Dict[str, Any]) -> Dict[str, Any]:
    """Decide provider / kind / basis / confidence / public-by-design for a
    secret finding, from the clear-text finding. Pure."""
    blob = "\n".join(s for k in _TEXT_KEYS if k in f for s in _strings(f.get(k)))
    blob += "\n" + "\n".join(v for v in _raw_values(f))
    tokens = find_provider_tokens(blob)
    pem = bool(_PEM_RE.search(blob)) or bool(_PEM_HEADER_ONLY_RE.search(blob))
    jwts = _JWT_RE.findall(blob)
    kind = _kind_of(f)
    provider = None
    strength = None
    public = False
    secret_tokens = []
    public_tokens = []
    for p, tok, st in tokens:
        if "EXAMPLE" in tok.upper() and p == "aws_access_key_id":
            continue
        is_pub = p in _PUBLIC_PROVIDERS or (p == "google_api_key" and _is_client_context(f))
        (public_tokens if is_pub else secret_tokens).append((p, tok, st))
    if secret_tokens:
        provider, tok, strength = secret_tokens[0]
        if provider == "github_token" and not _github_checksum_ok(tok):
            strength = "failed_checksum"
    elif pem:
        provider, strength = "private_key", "structure"
    elif public_tokens and kind != "password":
        provider, _tok, strength = public_tokens[0]
        public = True
    elif jwts and all(_jwt_role(j) == "anon" for j in jwts) and kind in ("generic", "jwt_secret"):
        provider, strength, public = "supabase_anon_key", "structure", True
    basis = "format" if provider and strength in ("structure", "checksum") else "pattern"
    if provider == "github_token" and strength == "failed_checksum":
        basis = "pattern"
    confidence = "potential"
    if basis == "format" and provider not in ("stripe_test_key",):
        confidence = "likely"
    ev = f.get("evidence")
    if isinstance(ev, dict) and ev.get("kind") == "inventory" and (ev.get("secret") or {}).get("provider"):
        prov = ev["secret"]["provider"]
        if prov in ("google_api_key", "stripe_publishable_key", "supabase_publishable_key"):
            public, provider, basis = True, prov, "format"
    return {"provider": provider, "kind": kind, "basis": basis, "confidence": confidence,
            "public": public}


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def _mask_container(obj: Any, raws: List[str]) -> Any:
    if isinstance(obj, str):
        return mask_text(obj, raws)
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if k in _IDENTITY_KEYS and k != "location":
                continue
            obj[k] = _mask_container(obj[k], raws)
        return obj
    if isinstance(obj, list):
        for i, x in enumerate(obj):
            obj[i] = _mask_container(x, raws)
        return obj
    return obj


def _deep_equal_json(a: Any, b: Any) -> bool:
    try:
        return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)
    except Exception:  # noqa: BLE001
        return False


def _view(f: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The finding as the classifier sees it: result-level platform /
    scan mode filled in when the finding itself does not carry them."""
    if not context:
        return f
    v = dict(f)
    for k in ("platform", "scan_mode"):
        if not v.get(k) and context.get(k):
            v[k] = context[k]
    return v


def present_finding(f: Any, context: Optional[Dict[str, Any]] = None) -> bool:
    """Mask + reword one finding in place. Returns True when it changed.
    `context`: {platform, scan_mode} of the result the finding belongs to."""
    if not isinstance(f, dict):
        return False
    secret = is_secret_finding(_view(f, context))
    if not secret or f.get("secret_presentation") == PRESENTATION_VERSION:
        # Fast path: nothing that looks like a secret format anywhere in it.
        try:
            if not _QUICK_RE.search(json.dumps(f, default=str, ensure_ascii=False)):
                return False
        except Exception:  # noqa: BLE001
            pass
    if not secret:
        # Not a secret finding: still never show a format-matched secret.
        updates = {}
        for k in _TEXT_KEYS:
            v = f.get(k)
            if isinstance(v, (str, dict, list)):
                try:
                    new = _mask_container(json.loads(json.dumps(v, default=str)), [])
                except Exception:  # noqa: BLE001
                    continue
                if not _deep_equal_json(new, v):
                    updates[k] = new
        if not updates:
            return False
        if not isinstance(f.get("fingerprint_mask_basis"), dict):
            f["fingerprint_mask_basis"] = fingerprint_basis_of(f)  # before the change
        f.update(updates)
        return True
    if f.get("secret_presentation") == PRESENTATION_VERSION:
        # Already presented: only re-mask (idempotent, catches late copies).
        _mask_container(f, [])
        return False
    fv = _view(f, context)
    info = classify(fv)
    raws = _raw_values(f)
    first_raw = next((r for r in raws if not _is_masked(r)), None)
    _stamp_basis(f)
    if first_raw and "secret_sha256" not in f:
        f["secret_sha256"] = secret_sha256(first_raw)
    masked = mask_value(first_raw) if first_raw else None
    if info["provider"] == "private_key":
        masked = "[private key material masked]"
    # Original wording kept (masked) for audit only, never displayed.
    if f.get("title") and "detector_title" not in f:
        f["detector_title"] = mask_text(_s(f.get("title")), raws)
    if info["public"]:
        words = _public_wording(info["provider"], masked, fv)
        f["secret_public_by_design"] = True
        f["is_secret"] = False
        if "original_severity" not in f:
            f["original_severity"] = f.get("severity")
        f["severity"] = "info"
        f.pop("secret_confidence", None)
    else:
        words = _wording(info["kind"], info["provider"], info["basis"], info["confidence"],
                         masked, fv)
        f["is_secret"] = True
        f["secret_confidence"] = info["confidence"]
        if not f.get("confidence"):
            f["confidence"] = info["confidence"]
    f["secret_kind"] = info["provider"] or info["kind"]
    f["secret_match_basis"] = info["basis"]
    f["secret_tested"] = False
    # Drop raw-value carrier keys outright (the masked text keeps the shape).
    for k in _VALUE_KEYS:
        if isinstance(f.get(k), str) and f.get(k).strip() in raws:
            f[k] = mask_value(f[k].strip())
    _mask_container(f, raws)
    f.update(words)
    if not isinstance(f.get("recommendation"), dict):
        f["recommendation"] = words["remediation"]
        f["recommendation_fr"] = words["remediation_fr"]
    if f.get("name") and not isinstance(f.get("name"), dict):
        f["name"] = words["title"]
    f["secret_presentation"] = PRESENTATION_VERSION
    return True


_RESULT_LISTS = ("vulnerabilities", "hidden_findings", "review_findings", "infrastructure_findings",
                 "all_vulnerabilities", "findings", "actionable_findings",
                 "actionable_vulnerabilities", "downgraded_findings", "filtered_findings",
                 "secrets", "results", "web_findings", "dast_findings", "sast_findings",
                 "premium_findings", "locked_findings")


def present_result(result: Any, move_public: bool = False) -> int:
    """present_finding over every finding list of a result dict (and of the
    nested report dicts some analyzers keep). With move_public=True, a
    public-by-design key found in `vulnerabilities` moves to
    `hidden_findings` (Info is hidden by default) and the counters are fixed.
    Returns the number of findings changed."""
    if not isinstance(result, dict):
        return 0
    n = 0
    seen: set = set()
    plat = str(result.get("platform") or "").lower()
    smode = str(result.get("scan_mode") or "").lower()
    if result.get("project_type") or smode == "source" or plat in ("source_code", "source"):
        smode = "source"
    context = {"platform": plat, "scan_mode": smode}

    def _walk(d: Dict[str, Any], depth: int) -> None:
        nonlocal n
        if depth > 3:
            return
        for key, val in list(d.items()):
            if isinstance(val, list) and key in _RESULT_LISTS and id(val) not in seen:
                seen.add(id(val))
                for f in val:
                    if isinstance(f, dict):
                        try:
                            if present_finding(f, context):
                                n += 1
                        except Exception:  # noqa: BLE001 - never lose a result
                            logging.getLogger(__name__).warning(
                                "secret presentation skipped one finding", exc_info=False)
            elif isinstance(val, dict) and key not in ("meta",):
                _walk(val, depth + 1)

    _walk(result, 0)
    if move_public and isinstance(result.get("vulnerabilities"), list):
        keep, moved = [], []
        for f in result["vulnerabilities"]:
            if isinstance(f, dict) and f.get("secret_public_by_design"):
                f["default_view_hidden"] = "public_client_key"
                moved.append(f)
            else:
                keep.append(f)
        if moved:
            result["vulnerabilities"] = keep
            hidden = result.get("hidden_findings")
            hidden = list(hidden) if isinstance(hidden, list) else []
            hidden.extend(moved)
            result["hidden_findings"] = hidden
            if "vulnerabilities_count" in result:
                result["vulnerabilities_count"] = len(keep)
            if "actionable_findings_count" in result:
                result["actionable_findings_count"] = len(keep)
            if "hidden_findings_count" in result or moved:
                result["hidden_findings_count"] = len(hidden)
    return n


def present_result_json(text: Any) -> Any:
    """For a stored JSON string: mask + reword, re-serialize only when
    something changed (no format drift otherwise). Never raises."""
    if not isinstance(text, str) or len(text) < 2 or text[0] not in "{[":
        return text
    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001
        return text
    try:
        if isinstance(obj, dict):
            changed = present_result(obj)
        elif isinstance(obj, list):
            changed = sum(1 for f in obj if isinstance(f, dict) and present_finding(f))
        else:
            return text
    except Exception:  # noqa: BLE001
        return text
    if not changed:
        return text
    return json.dumps(obj, default=str)


def localize_finding(f: Dict[str, Any], lang: str) -> Dict[str, Any]:
    """Copy of a presented finding with the FR wording in the display keys."""
    if lang != "fr" or not isinstance(f, dict) or not f.get("secret_presentation"):
        return f
    out = dict(f)
    for k in ("title", "description", "remediation", "recommendation", "severity_rationale"):
        if out.get(k + "_fr"):
            out[k] = out[k + "_fr"]
    return out


def localize_result(result: Any, lang: str) -> int:
    """In place: FR wording into the display keys of every presented finding
    of a result dict (call on a copy loaded for rendering only)."""
    if lang != "fr" or not isinstance(result, dict):
        return 0
    n = 0
    seen: set = set()

    def _walk(d: Dict[str, Any], depth: int) -> None:
        nonlocal n
        if depth > 3:
            return
        for key, val in list(d.items()):
            if isinstance(val, list) and key in _RESULT_LISTS and id(val) not in seen:
                seen.add(id(val))
                for f in val:
                    if isinstance(f, dict) and f.get("secret_presentation"):
                        for k in ("title", "description", "remediation", "recommendation",
                                  "severity_rationale"):
                            if f.get(k + "_fr"):
                                f[k] = f[k + "_fr"]
                        n += 1
            elif isinstance(val, dict) and key not in ("meta",):
                _walk(val, depth + 1)

    _walk(result, 0)
    return n


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

class SecretMaskingLogFilter(logging.Filter):
    """Masks provider-format tokens, PEM blocks, JWTs, URI passwords and
    bearer tokens in every log record that passes through."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        masked = mask_text(msg)
        if masked != msg:
            record.msg = masked
            record.args = ()
        return True


_FACTORY_INSTALLED = False


def install_log_masking() -> None:
    """Mask secrets in every log record of the process (record factory, so
    it covers loggers and handlers created later, celery's included)."""
    global _FACTORY_INSTALLED
    if _FACTORY_INSTALLED:
        return
    old = logging.getLogRecordFactory()
    filt = SecretMaskingLogFilter()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        rec = old(*args, **kwargs)
        filt.filter(rec)
        return rec

    logging.setLogRecordFactory(factory)
    _FACTORY_INSTALLED = True
