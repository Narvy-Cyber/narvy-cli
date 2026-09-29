"""Grade the value behind a secret finding that fired on a variable NAME.

Rules such as "Hardcoded Encryption/Secret Key Variable" or "credential-like
variable assigned a literal" match on the variable name (key, secret,
password, token...). The name alone says nothing about the value: most hits in
real apps are preference keys, intent extras, enum-like constants or labels.
A name-only hit is therefore capped at MEDIUM, and it keeps its original
severity only when the value itself is evidence:

  - it matches a known provider credential format (AWS, Google, Stripe, ...), or
  - it is key material of a real key length (hex / base64 / raw bytes of
    16, 24, 32, 48 or 64 bytes) with enough entropy.

Values that are plainly not secrets (URLs, file paths, dotted or snake_case
identifiers, UPPER_CASE constants, format strings, sentences, placeholders)
drop the finding.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from typing import Any, Dict, Optional

KEEP = "keep"          # value is evidence: keep the rule's severity
CAP = "cap"            # name-only: cap at MEDIUM
DROP = "drop"          # value is plainly not a secret

NAME_ONLY_CAP = "MEDIUM"

# Rule ids whose match is driven by the variable name, per engine.
NAME_ONLY_SECRET_RULES = frozenset({
    "AND-S-001",   # api_key / api_secret = "<16+ chars>"
    "AND-S-002",   # password = "..."
    "AND-S-010",   # *key* / *secret* = "..."
    "android-hardcoded-credential-java",
    "android-hardcoded-credential-kotlin",
    "IOS-OBJC-S-001",
    "IOS-OBJC-S-002",
    "ios-swift-hardcoded-secret-assignment",
    "IOS-BIN-SENSITIVE-001",
})

# Provider formats. A value matching one of these keeps its severity.
_PROVIDER_PATTERNS = [
    r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}",   # AWS key id
    r"AIza[0-9A-Za-z_\-]{35}",                                    # Google API key
    r"ya29\.[0-9A-Za-z_\-]{20,}",                                 # Google OAuth
    r"(?:sk|rk)_live_[0-9A-Za-z]{24,}",                           # Stripe secret / restricted
    r"sk_test_[0-9A-Za-z]{24,}",                                  # Stripe test secret
    r"xox[baprs]-[0-9A-Za-z\-]{10,48}",                          # Slack
    r"gh[pousr]_[A-Za-z0-9]{36}",                                 # GitHub tokens
    r"github_pat_[A-Za-z0-9_]{22,}",                              # GitHub fine-grained
    r"glpat-[A-Za-z0-9_\-]{20}",                                  # GitLab
    r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",               # SendGrid
    r"SK[0-9a-fA-F]{32}",                                         # Twilio API key
    r"AC[0-9a-fA-F]{32}",                                         # Twilio account SID
    r"sq0(?:atp|csp)-[0-9A-Za-z_\-]{22,43}",                      # Square
    r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}",                          # OpenAI
    r"npm_[A-Za-z0-9]{36}",                                       # npm
    r"\d{8,10}:AA[0-9A-Za-z_\-]{33}",                             # Telegram bot
    r"key-[0-9a-f]{32}",                                          # Mailgun
    r"[0-9a-f]{32}-us\d{1,2}",                                    # Mailchimp
    r"EAA[0-9A-Za-z]{90,}",                                       # Facebook token
    r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",  # JWT
    r"-----BEGIN[ A-Z]*PRIVATE KEY-----",                         # PEM private key
    r"shpat_[0-9a-fA-F]{32}",                                     # Shopify
    r"AccountKey=[A-Za-z0-9+/=]{40,}",                            # Azure storage
]
_PROVIDER_RE = re.compile("|".join(f"(?:{p})" for p in _PROVIDER_PATTERNS))

_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x+|\*+|\.+|-+|_+|0+|null|nil|none|undefined|true|false|default|"
    r"changeme|change_me|password|passwd|secret|token|key|value|string|"
    r"todo|fixme|tbd|n/?a|test|example|sample|dummy|fake|placeholder|"
    r"<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[a-z0-9_]*%)$")
_PLACEHOLDER_WORD_RE = re.compile(
    r"(?i)(?:your[_\- ]?(?:api|secret|key|token|password)|replace[_\- ]?me|"
    r"insert[_\- ]?(?:key|token|here)|placeholder|xxxx|<your|enter[_\- ]?your)")
_URL_RE = re.compile(r"(?i)^[a-z][a-z0-9+.\-]*://")
_PATH_RE = re.compile(r"^(?:/|\./|\.\./|[A-Za-z]:\\|~/)")
_RESOURCE_RE = re.compile(r"^[@?][A-Za-z_]+/")
_DOTTED_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
_LOWER_SEP_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[_\-:.][a-z0-9]+)+$")
_UPPER_CONST_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:[_\-.][A-Z0-9]+)*$")
_FORMAT_RE = re.compile(r"%(?:\d+\$)?[-+ #0]*\d*(?:\.\d+)?[sdifxXu@]|\{\d*\}|\$\{|\$\(")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# A regular expression, not a value: (?=.*\d), [a-z], .{6,20}, \w+ ...
_REGEX_RE = re.compile(r"\(\?[=!:<]|\[[^\]]*-[^\]]*\]|\.\{\d|\\[dwsDWS]|\.\*|\^\(|\)\$")
_CRED_WORDS = {"password", "passwd", "pwd", "pass", "token", "secret", "credential",
               "credentials", "apikey", "auth", "key"}
_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")


def _words(value: str):
    """camelCase / snake_case / spaced components: ProtectPassword -> Protect, Password."""
    return _WORD_RE.findall(value)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]+={0,2}$")

_KEY_BYTES = (16, 24, 32, 48, 64)
_STRING_LITERAL_RE = re.compile(r'@?"((?:[^"\\\n]|\\.)*)"')


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _char_classes(value: str) -> int:
    return sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))


def is_provider_secret(value: str) -> bool:
    return bool(_PROVIDER_RE.search(value or ""))


def is_key_material(value: str) -> bool:
    """High-entropy value of a real key length (hex, base64 or raw bytes)."""
    v = value.strip()
    if not v or (" " in v and len(v) not in _KEY_BYTES):
        return False
    # Hex-encoded key: 128/192/256/384/512 bits.
    if _HEX_RE.match(v) and len(v) // 2 in _KEY_BYTES and len(v) % 2 == 0:
        return len(set(v.lower())) >= 8 and shannon_entropy(v) >= 3.0
    # Base64 / base64url key material.
    if len(v) >= 22 and (_B64_RE.match(v) or _B64URL_RE.match(v)):
        raw = None
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                padded = v + "=" * (-len(v) % 4)
                raw = dec(padded)
                break
            except (binascii.Error, ValueError):
                continue
        if raw is not None and len(raw) in _KEY_BYTES:
            return shannon_entropy(v) >= 3.5 and _char_classes(v) >= 2
    # AWS secret access key shape: 40 base64 chars (30 bytes), high entropy.
    if len(v) == 40 and _B64_RE.match(v) and _char_classes(v) >= 3 and shannon_entropy(v) >= 4.0:
        return True
    # Raw string used directly as key bytes (e.g. SecretKeySpec("...".getBytes())).
    if len(v) in _KEY_BYTES:
        return shannon_entropy(v) >= 3.0 and len(set(v)) >= 8
    return False


def is_plain_non_secret(value: str) -> bool:
    v = value.strip()
    if len(v) < 4:
        return True
    if _PLACEHOLDER_RE.match(v) or _PLACEHOLDER_WORD_RE.search(v):
        return True
    if _URL_RE.match(v) or _PATH_RE.match(v) or _RESOURCE_RE.match(v):
        return True
    if _FORMAT_RE.search(v) or _REGEX_RE.search(v):
        return True
    # A label or field name that repeats the credential word: "Password",
    # "ProtectPassword", "access_token".
    if re.fullmatch(r"[A-Za-z][A-Za-z _\-]*", v) and any(
            w.lower() in _CRED_WORDS for w in _words(v)):
        return True
    if _UUID_RE.match(v):
        return False
    if _DOTTED_ID_RE.match(v):
        return True
    # pref_key_token / secret-token-pref; with digits it may be a real (weak) secret.
    if _LOWER_SEP_ID_RE.match(v) and not any(c.isdigit() for c in v):
        return True
    # Enum-like constant: API_KEY, SECRETKEY (not ABCDEF0123456789).
    if _UPPER_CONST_RE.match(v) and ("_" in v or not any(c.isdigit() for c in v)):
        return True
    return False


def _is_prose(value: str) -> bool:
    words = value.split()
    return len(words) >= 3 and sum(w.isalpha() for w in words) >= 2


def grade_value(value: Optional[str]) -> str:
    """KEEP, CAP or DROP for the literal assigned to a secret-named variable."""
    if value is None:
        return CAP
    v = value.strip()
    if is_provider_secret(v):
        return KEEP
    if is_plain_non_secret(v):
        return DROP
    if is_key_material(v):
        return KEEP
    if _is_prose(v):
        return DROP
    return CAP


def literal_from_text(text: str) -> Optional[str]:
    """The string literal assigned on a line (the one after '=' or ':')."""
    if not text:
        return None
    for sep in ("=", ":"):
        idx = text.find(sep)
        if idx != -1:
            m = _STRING_LITERAL_RE.search(text, idx)
            if m:
                return m.group(1)
    m = _STRING_LITERAL_RE.search(text)
    return m.group(1) if m else None


_NOTE = (" [Narvy: only the variable name suggests a secret; the value is not a "
         "known provider credential format or key material of a real key length, "
         "so severity is capped at MEDIUM. Confirm what this value is.]")


def apply(finding: Dict[str, Any], value: Optional[str]) -> Optional[Dict[str, Any]]:
    """Re-grade one name-only secret finding. None means drop it."""
    verdict = grade_value(value)
    if verdict == DROP:
        return None
    if verdict == KEEP:
        finding["value_evidence"] = "provider_format" if is_provider_secret(value or "") else "key_material"
        return finding
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if order.get(finding.get("severity"), 5) < order[NAME_ONLY_CAP]:
        finding["original_severity"] = finding.get("severity")
        finding["severity"] = NAME_ONLY_CAP
    finding["confidence"] = "LOW"
    finding["value_evidence"] = "name_only"
    details = finding.get("details")
    if isinstance(details, dict):
        details = dict(details)
        details["description"] = (details.get("description") or "").rstrip() + _NOTE
        finding["details"] = details
    return finding


def regrade_findings_from_files(findings, root: str, read_line) -> list:
    """Re-grade name-only secret findings in place; read_line(path, line) -> text."""
    out = []
    for f in findings:
        if f.get("rule_id") not in NAME_ONLY_SECRET_RULES or f.get("value_evidence"):
            out.append(f)
            continue
        try:
            text = read_line(f.get("file_path", ""), int(f.get("line") or 0))
        except Exception:
            text = None
        graded = apply(f, literal_from_text(text) if text else None)
        if graded is not None:
            out.append(graded)
    return out
