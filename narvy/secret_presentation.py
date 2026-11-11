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
  and last 4 characters) in every text field of the finding. A value of 8 to
  19 characters shows its first 2 and last 2 (``ab\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022yz``) and the
  description states its length; a shorter one is fully masked (2026-11-04,
  persona "Claire": a fully masked 9-character "password" could not be
  triaged). File and line stay visible. A ``secret_sha256`` of the first raw
  value is kept for dedup.
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
_MIN_PARTIAL_LEN = 20  # from this length: first 4 + last 4 (at least 12 chars hidden)
_MIN_SHORT_PARTIAL_LEN = 8  # 8..19: first 2 + last 2 (at least half hidden); below: fully masked

# ---------------------------------------------------------------------------
# Masking primitives
# ---------------------------------------------------------------------------


def mask_value(value: Any) -> str:
    """First 4 + last 4 characters, the rest replaced by a fixed-width fill
    (the masked string never reveals the length). A value of 8 to 19
    characters shows its first 2 and last 2 (at least half of it hidden), a
    shorter one is fully masked."""
    v = str(value or "")
    if len(v) < _MIN_SHORT_PARTIAL_LEN:
        return MASK_FILL
    if len(v) < _MIN_PARTIAL_LEN:
        return v[:2] + MASK_FILL + v[-2:]
    return v[:4] + MASK_FILL + v[-4:]


def masked_length(value: Any) -> Optional[int]:
    """The length a reader is told for a masked value: only for a value
    shorter than 20 characters (a long key's length says nothing useful and
    stays hidden)."""
    v = str(value or "")
    return len(v) if 0 < len(v) < _MIN_PARTIAL_LEN else None


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
# Unquoted assignment (YAML, .env, .properties, "name: value" evidence text):
# `admin_password_hash: $2a$10$...`, `DB_PASSWORD=...`.
_UNQUOTED_ASSIGN_RE = re.compile(
    r"(?im)(?:^|[\s{,;(\"'`])(?P<name>[A-Za-z0-9_\-.]*" + _CRED_NAME + r"[A-Za-z0-9_\-]*)"
    r"[ \t]*(?::=|=|:)[ \t]*(?P<v>[^\s\"'`,;#<>(){}\[\]]{6,512})")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]*")


def _unquoted_value_ok(v: str, anchored: bool = False) -> bool:
    """An unquoted right-hand side that is a value, not code / a reference /
    an Objective-C selector part / a placeholder. ``anchored``: the text is
    the matched line of a SECRET finding (its snippet / evidence): the value
    is the secret whatever its entropy or character classes (rel86c judge
    B1: a letters-only POSTGRES_PASSWORD stayed in clear). Entropy and
    identifier gates only apply to values with no such anchor."""
    v = _strip_trunc(v)
    if len(v) < 6 or not _plausible_value(v) or v.endswith(":"):
        return False
    low = v.lower()
    if low.startswith(("http://", "https://", "/", "./", "${", "%", "{{", "<", "process.env",
                       "os.environ", "getenv", "env.", "env(", "this.", "self.", "r.string",
                       "@string/", "secrets.", "vars.", "settings.", "config.")):
        return False
    if v.startswith("$") and not re.match(r"\$2[abxy]?\$", v):
        return False  # shell / template variable (a bcrypt hash is kept)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", v) and not any(
            c.isdigit() for c in v):
        return False  # a dotted reference (config.db.password)
    if anchored:
        return True
    if v.isdigit():
        return False
    if _IDENT_RE.fullmatch(v) and not any(c.isdigit() for c in v):
        return False  # an identifier (camelCase / snake_case / dotted path)
    return _entropy(v) >= 2.5


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


_ELLIPSES = ("...", "…")
_MIN_TRUNC_PREFIX = 8  # a clear prefix this long, cut by an ellipsis, is masked


def _mask_fragments(text: str, raw: str, glued_ok: bool = False) -> str:
    """Analyzers cut values: "api_key: AbCdEfGhIjKlMnOpQrSt..." keeps the
    head, a context window "...<tail of the secret> next = ..." keeps the
    tail (rel86c judge B2: the React Native analyzer took 40 characters before
    a match, starting inside the neighbouring secret). The full value never
    matches, but any clear piece of it of 8+ characters is still the secret.
    Every maximal run of `text` that is a substring of `raw` (at least 8
    characters, shorter than raw) is masked: a head shows its first 4, any
    other piece shows nothing."""
    n = _MIN_TRUNC_PREFIX
    if len(raw) <= n or len(text) < n:
        return text
    grams: Dict[str, List[int]] = {}
    for k in range(len(raw) - n + 1):
        grams.setdefault(raw[k:k + n], []).append(k)
    if not any(g in text for g in grams):
        return text
    out, i, last = [], 0, 0
    while i <= len(text) - n:
        starts = grams.get(text[i:i + n])
        if not starts:
            i += 1
            continue
        best_len, best_k = 0, 0
        for k in starts:
            L = n
            while k + L < len(raw) and i + L < len(text) and text[i + L] == raw[k + L]:
                L += 1
            if L > best_len:
                best_len, best_k = L, k
        if best_len >= len(raw):  # the whole value: mask_value already ran
            i += best_len
            continue
        before_ok = i == 0 or not text[i - 1].isalnum()
        after_ok = i + best_len >= len(text) or not text[i + best_len].isalnum()
        if not glued_ok and not (before_ok and after_ok):
            i += 1  # a piece glued to other letters is another word, not a cut value
            continue
        out.append(text[last:i])
        out.append((raw[:4] + MASK_FILL) if best_k == 0 else MASK_FILL)
        i += best_len
        last = i
    out.append(text[last:])
    return "".join(out)


def _is_pw_placeholder(pw: str) -> bool:
    """<password>, ${MONGO_PW}, $PW, %s, password, changeme...: rule text, not a value."""
    return bool(_FORMAT_PLACEHOLDER_RE.fullmatch(pw) or _PLACEHOLDER_RE.fullmatch(pw)
                or re.fullmatch(r"(?i)\$\w+|\$\{[^}]*\}|%\(?\w*\)?s|pass|passwd|pwd|secret", pw))


def _uri_cred_sub(m: "re.Match[str]") -> str:
    pw = m.group(2)
    if _is_masked(pw) or _DIGEST_AFTER_RE.match(m.string[m.end():m.end() + 8]) \
            or _is_pw_placeholder(pw):
        return m.group(0)  # masked already, an image digest, or a placeholder (<password>, ${PW})
    return m.group(1) + MASK_FILL + m.group(3)


def _mask_formats(out: str) -> str:
    """Provider formats, PEM blocks, JWTs, URI passwords, bearer tokens."""
    out = _PEM_RE.sub(lambda m: f"{m.group(1)}[private key material masked]{m.group(4)}", out)
    out = _PEM_HEADER_ONLY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[private key material masked]", out)
    for _provider, token, _s in find_provider_tokens(out):
        out = out.replace(token, mask_value(token))
    out = _JWT_RE.sub(lambda m: mask_value(m.group(0)), out)
    out = _URI_CRED_RE.sub(_uri_cred_sub, out)
    out = _BEARER_RE.sub(lambda m: m.group(1) + mask_value(m.group(2))
                         if not _is_masked(m.group(2)) else m.group(0), out)
    return out


def _any_piece_in(raw: str, text: str) -> bool:
    """Any 8-character piece of ``raw`` in ``text`` (a cut head or tail
    counts, not only the start of the value)."""
    n = _MIN_TRUNC_PREFIX
    if len(raw) <= n:
        return raw in text
    return any(raw[k:k + n] in text for k in range(len(raw) - n + 1))


def _random_looking(v: str) -> bool:
    """Letters of both cases and digits, 16+ characters: a generated key, not
    a word. Its pieces and glued copies are hunted everywhere; a word-like
    value's only inside secret findings and as whole tokens."""
    return (len(v) >= 16 and any(c.isdigit() for c in v) and any(c.islower() for c in v)
            and any(c.isupper() for c in v))


def _value_maskable(raw: str) -> bool:
    """A raw value this module may hunt in text. Never a PEM marker or a
    rule-text example ("'-----BEGIN ... PRIVATE KEY-----'" quoted by a rule
    description became a "value", its pieces broke the PEM header and the
    key body stayed in clear: rel86c re-judge blocker)."""
    return not (_PEM_MARK_RE.search(raw) or "..." in raw or "\u2026" in raw)


_PEM_MARK_RE = re.compile(r"-----|PRIVATE KEY|BEGIN [A-Z]")


def mask_text(text: str, raw_values: Iterable[str] = (), fragments: bool = True) -> str:
    """Mask every provider-format / PEM / JWT / URI-password / bearer token
    in `text` FIRST, then every known raw value: whole, or any clear piece of
    8+ characters of it (a head or a tail cut by a context window).
    Idempotent."""
    if not text or not isinstance(text, str):
        return text
    raw_values = [r for r in raw_values if r and _value_maskable(r)]
    if not raw_values and not _QUICK_RE.search(text):
        return text
    out = _mask_formats(text)
    for raw in sorted({r for r in raw_values if r and len(r) >= 4}, key=len, reverse=True):
        if raw in out:
            if len(raw) >= _MIN_TRUNC_PREFIX:
                # A value cut by an ellipsis may be only the head of the
                # secret: show its first 4, never its last 4.
                for e in _ELLIPSES:
                    if raw + e in out:
                        out = out.replace(raw + e, raw[:4] + MASK_FILL + e)
            if _random_looking(raw):
                # A random value glued to other characters is still the value.
                out = out.replace(raw, mask_value(raw))
            else:
                # Whole tokens only: a word-like value is never masked inside
                # a longer word ("entropy" in a rule id, "postgres" in
                # "postgresql").
                out = re.sub(r"(?<![A-Za-z0-9])" + re.escape(raw) + r"(?![A-Za-z0-9])",
                             lambda _m, _r=raw: mask_value(_r), out)
        if (fragments or _random_looking(raw)) and len(raw) > _MIN_TRUNC_PREFIX \
                and not _is_masked(raw) and not any(c.isspace() for c in raw):
            out = _mask_fragments(out, raw, glued_ok=_random_looking(raw))
    return out


# rel48: the masking runs on DECODED strings (a JSON tree, before
# json.dumps), where a backslash is a literal character of the value:
# "token=abc\def" used to come out "token=••••••••\def" (the end of the
# secret in clear). A backslash is now part of a URL / value, except one that
# escapes a following quote (a JSON text embedded in a string value: the
# masked value then never eats that escape, rel46 judge B1); an escaped
# backslash pair stays one unit. The result is a Python string: json.dumps
# of the tree is always valid JSON.
_BS = r"(?:\\\\|\\(?![\"\\]))"   # \\ pair, or a lone \ not before " or \
_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{1,15}://(?:[^\s'\"`<>\\]|" + _BS + r")+")
# scheme://user:password@host, any scheme (the password is group 2).
_URL_USERINFO_RE = re.compile(r"(?i)^([a-z][a-z0-9+.\-]*://[^\s:@/?#\\\"]*:)((?:[^\s@/?#\\\"]|"
                              + _BS + r")+)(@)")
# An image reference is not a URL with credentials: docker://python:3.12@sha256:...
# reads as user "python", password "3.12" (rel86c judge: 12 prod strings).
_IMAGE_REF_RE = re.compile(r"(?i)^(?:docker|oci|oci-archive|docker-archive|docker-daemon|containers-storage|"
                           r"registry|image)://|^[^@\s]*@sha(?:256|384|512):")
# A format / template placeholder, not a value: %@, %s, {token}, ${TOKEN}, {{t}}, :token
_FORMAT_PLACEHOLDER_RE = re.compile(r"%[@sdifu]|%\d*\$?[@sdifu]|\$?\{\{?[^}]*\}\}?|:[A-Za-z_]\w*|<[^>]*>")
_DIGEST_AFTER_RE = re.compile(r"(?i)^sha(?:256|384|512):")
# Query / fragment parameters whose VALUE is a credential.
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&;#](?:[A-Za-z0-9_.\-]*[_.\-])?"
    r"(?:api[_\-]?key|apikey|key|access[_\-]?token|refresh[_\-]?token|id[_\-]?token|auth[_\-]?token|"
    r"auth|token|secret|client[_\-]?secret|password|passwd|pass|pwd|sig|signature|session|sessionid|"
    r"sid|jwt|private[_\-]?token|access[_\-]?key|secret[_\-]?key)=)((?:[^&#;\s'\"`<>\\]|" + _BS + r")+)")


def mask_url_secrets(text: Any) -> Any:
    """``text`` with the credentials of every URL it contains masked: the
    password of ``scheme://user:password@host`` (user kept, as the results
    page / PDF / SARIF show it: ``adm:••••••••``) and the value of credential
    query parameters (``?api_key=••••••••``). Anything else unchanged;
    idempotent; non-strings returned as they are.

    rel46 (prod QA rel44): the JSON export shipped
    ``https://adm:pw1234@api.acmeco.io`` five times (sample_locations,
    detected_instances, instances) on an iOS "Hardcoded URLs" finding, which
    is not a secret finding, so present_result never touched it."""
    if not isinstance(text, str) or "://" not in text:
        return text

    def _one(m: "re.Match[str]") -> str:
        u = m.group(0)
        if "@" in u and not _IMAGE_REF_RE.match(u):
            u = _URL_USERINFO_RE.sub(lambda c: c.group(1) + MASK_FILL + c.group(3)
                                 if not _is_masked(c.group(2)) and not _is_pw_placeholder(c.group(2))
                                 else c.group(0), u)
        if "=" in u:
            u = _QUERY_SECRET_RE.sub(lambda c: c.group(1) + MASK_FILL
                                     if not _is_masked(c.group(2)) and not _FORMAT_PLACEHOLDER_RE.fullmatch(c.group(2))
                                     else c.group(0), u)
        return u

    return _URL_RE.sub(_one, text)


def mask_url_secrets_tree(node: Any, depth: int = 0) -> Any:
    """In place over a JSON tree (dicts / lists): every string value through
    ``mask_url_secrets``. Returns ``node`` (a bare string: its masked copy)."""
    if depth > 60:
        return node
    if isinstance(node, str):
        return mask_url_secrets(node)
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str):
                if "://" in v:
                    node[k] = mask_url_secrets(v)
            elif isinstance(v, (dict, list)):
                mask_url_secrets_tree(v, depth + 1)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                if "://" in v:
                    node[i] = mask_url_secrets(v)
            elif isinstance(v, (dict, list)):
                mask_url_secrets_tree(v, depth + 1)
    return node


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
                  "tracker_identity", "registry_rule", "references", "reference", "links", "link",
                  "see_also",
                  "type", "vulnerability_type", "vuln_type", "cwe", "cwe_id", "owasp", "masvs",
                  "masvs_id", "fingerprint", "secret_sha256", "fingerprint_mask_basis",
                  "fingerprint_basis", "line", "line_number", "start_line", "end_line", "severity",
                  "category", "platform", "component", "activity", "service", "class", "class_name",
                  "function", "function_name", "method", "url", "endpoint", "parameter", "param",
                  "template_id", "template-id", "host", "package", "package_name", "scan_id",
                  "secret_client_context", "secret_presentation", "secret_kind",
                  "secret_match_basis", "secret_confidence"}


# The matched code / line of a finding (not prose): an assignment there is
# the matched secret itself.
_SNIPPET_KEYS = ("code_snippet", "snippet", "code", "vulnerable_code", "sink", "evidence",
                 "evidence_text", "context", "context_lines", "line_content", "matched_line",
                 "lines", "content", "location", "match", "Match", "matched", "matched_string",
                 "raw", "detection_context", "match_info")

# Prose inside a snippet-ish container (evidence.secret.notes, proofs...):
# never read as "name: value".
_PROSE_KEYS = {"notes", "note", "proof", "reason", "why", "message", "description", "remediation",
               "recommendation", "refutations", "refuted_by", "preconditions", "scope", "provider",
               "validator", "masked_value", "kind", "engine", "engine_version", "title"}


def _code_strings(v: Any, depth: int = 0) -> Iterable[str]:
    if depth > 20:
        return
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            if k not in _PROSE_KEYS and (k not in _IDENTITY_KEYS or k == "location"):
                yield from _code_strings(x, depth + 1)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _code_strings(x, depth + 1)


# Wording this module writes itself (never a source of raw values).
_WORDING_KEYS = {"title_fr", "description_fr", "remediation_fr", "recommendation_fr",
                 "severity_rationale", "severity_rationale_fr", "detector_title",
                 "secret_tested", "is_secret", "secret_public_by_design", "original_severity",
                 "secret_length"}


def _location_str(node: Dict[str, Any], k: str) -> bool:
    """A "file:line" / URL location string: identity (never rewritten),
    except the password of a URL in it (rel86c re-judge)."""
    if k == "location" and isinstance(node.get(k), str):
        if "://" in node[k] and "@" in node[k]:
            node[k] = mask_url_secrets(node[k])
        return True
    return False


def _skip_key(k: str, v: Any) -> bool:
    """Never rewritten: identity keys, and a "file:line" location string
    (a location DICT is rewritten: its code / context carry values)."""
    if k == "location":
        return isinstance(v, str)
    return k in _IDENTITY_KEYS


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
    if _PLACEHOLDER_RE.fullmatch(v):
        return False
    if _PEM_MARK_RE.search(v):
        return False  # a PEM header / rule-text example, never a value
    return True


# Obvious placeholders: never a secret, never masked (rel86c judge).
_PLACEHOLDER_RE = re.compile(
    r"(?i)(?:my|your|the|some|a|an|enter|insert|replace|put|add)?[_\-. ]?(?:own[_\-. ]?)?"
    r"(?:pass(?:word|wd|phrase)?s?|pwd|secret(?:[_\-]?key)?s?|tokens?|api[_\-]?keys?|keys?|credentials?)"
    r"(?:[_\-. ]?(?:here|goes[_\-. ]?here|placeholder|example|value))?"
    r"|change[_\-]?(?:me|it|this)|example|placeholder|dummy|sample|redacted|test(?:ing)?|"
    r"x{3,}|\*{3,}|\.{3,}|<[^>]*>|\[[^\]]*\]|\{[^}]*\}|your[_\-][\w\-]+|[\w\-]*_here")


def _raw_values(f: Dict[str, Any], fallback: bool = True,
                anchored_out: Optional[List[str]] = None) -> List[str]:
    """The clear secret values one finding carries. ``fallback``: when none
    is found, take the single quoted literal of the snippet (first
    presentation only; a presented finding never guesses).
    ``anchored_out``: receives the values found from an anchor (an explicit
    matched-value field, a provider format, a URI password, an assignment to
    a credential name in the matched code), never the guesses from prose or
    the fallback literal. Only those may be hunted elsewhere in the document."""
    vals: List[str] = []
    anchored: List[str] = []
    for k in _VALUE_KEYS:
        v = f.get(k)
        if isinstance(v, str) and _plausible_value(v) and len(v) >= 6:
            anchored.append(v.strip())
        elif isinstance(v, list):
            anchored.extend(x.strip() for x in v if isinstance(x, str) and _plausible_value(x) and len(x) >= 6)
    for k in ("metadata", "extra"):
        sub = f.get(k)
        if isinstance(sub, dict):
            for kk in ("secret", "secret_value", "matched_value", "match"):
                v = sub.get(kk)
                if isinstance(v, str) and _plausible_value(v) and len(v) >= 6:
                    anchored.append(v.strip())
    blob_parts = []
    for k in _TEXT_KEYS:
        if k in f:
            blob_parts.extend(_strings(f.get(k)))
    blob = "\n".join(blob_parts)
    # Every other non-identity field too (evidence_text, detection_context,
    # sample_locations, matched_string, merged copies...): a provider-format
    # token is wherever an analyzer put it.
    wide = "\n".join(s for k, v in f.items()
                     if k not in _TEXT_KEYS and k not in _IDENTITY_KEYS and k not in _WORDING_KEYS
                     for s in _strings(v))
    for _p, tok, _s2 in find_provider_tokens(blob + "\n" + wide):
        anchored.append(tok)
    secret = is_secret_finding(f)
    # The matched code / line (never prose): assignments to a credential name.
    snippet = "\n".join(s2 for k in _SNIPPET_KEYS if k in f for s2 in _code_strings(f.get(k)))
    for m in _ASSIGN_RE.finditer(snippet):
        v = m.group("v")
        if _plausible_value(v) and not v.lower().startswith(("http://", "https://")):
            anchored.append(v)
    for m in _UNQUOTED_ASSIGN_RE.finditer(snippet):
        if _unquoted_value_ok(m.group("v"), anchored=secret):
            anchored.append(_strip_trunc(m.group("v")))
    for m in _ASSIGN_RE.finditer(blob):
        v = m.group("v")
        if _plausible_value(v) and not v.lower().startswith(("http://", "https://")):
            vals.append(v)
    for m in _URI_CRED_RE.finditer(blob + "\n" + snippet):
        if _plausible_value(m.group(2)) and not _DIGEST_AFTER_RE.match(
                (blob + "\n" + snippet)[m.end():m.end() + 8]):
            anchored.append(m.group(2))
    for m in _XML_VALUE_RE.finditer(blob):
        if _plausible_value(m.group("v")):
            anchored.append(m.group("v"))
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
    if not vals and not anchored and fallback:
        lits = [m.group(1) for m in _QUOTED_RE.finditer(blob)
                if _plausible_value(m.group(1)) and " " not in m.group(1).strip()
                and not m.group(1).lower().startswith(("http://", "https://"))]
        vals.extend(lits[:3])
    seen, out = set(), []
    anchored_set = {_strip_trunc(x) for x in anchored}
    for v in (_strip_trunc(x) for x in anchored + vals):
        if v not in seen and _plausible_value(v):
            seen.add(v)
            out.append(v)
            if anchored_out is not None and v in anchored_set:
                anchored_out.append(v)
    return out


# A mask this module (or a validator using mask_value) wrote: 4 + fill + 4
# for a value of 20+ characters, 2 + fill + 2 for 8 to 19.
_MASK44_RE = re.compile(r"([^\s\"'`=:<>(){}\[\],;•]{4})" + MASK_FILL + r"([^\s\"'`<>(){}\[\],;•]{4})")
_MASK22_RE = re.compile(r"(?:^|(?<=[\s\"'`=:(\[,]))([^\s\"'`=:<>(){}\[\],;•]{2})" + MASK_FILL
                        + r"([^\s\"'`<>(){}\[\],;•]{2})(?=$|[\s\"'`,;.)\]}])")
_TOKEN_RE = re.compile(r"[^\s\"'`<>]+")
_TOKEN_EDGE = "()[]{},;:="


def _finding_strings(f: Dict[str, Any]) -> List[str]:
    return [s for k, v in f.items() if k not in _IDENTITY_KEYS and k not in _WORDING_KEYS
            for s in _strings(v)]


def _twin_values(f: Dict[str, Any], sha_out: Optional[List[str]] = None) -> Tuple[List[str], List[str]]:
    """Clear copies of a value this finding already shows masked
    (``abcd<fill>wxyz`` somewhere, the clear ``abcd...wxyz`` elsewhere: a field
    an enricher added or rewrote after masking, or a validator masked one
    field and the snippet kept the value), and of the value its
    ``secret_sha256`` names. Returns (whole values, clear heads cut by an
    ellipsis). Only this finding's own strings are searched."""
    strings = _finding_strings(f)
    if not strings:
        return [], []
    joined = "\n".join(strings)
    whole: List[str] = []
    heads: List[str] = []
    pairs44 = set(_MASK44_RE.findall(joined)) if MASK_FILL in joined else set()
    pairs22 = set(_MASK22_RE.findall(joined)) if MASK_FILL in joined else set()
    target = f.get("secret_sha256") if isinstance(f.get("secret_sha256"), str) else None
    if not pairs44 and not pairs22 and not target:
        return [], []
    for s in strings:
        for m in _TOKEN_RE.finditer(s):
            tok = m.group(0)
            if MASK_FILL in tok:
                continue
            for pre, suf in pairs44:
                i = tok.find(pre)
                if i < 0:
                    continue
                rest = tok[i:]
                j = rest.rfind(suf)
                if j >= 8 and j + 4 >= 12:
                    whole.append(rest[: j + 4])
                for e in _ELLIPSES:
                    if rest.endswith(e) and len(rest) - len(e) >= _MIN_TRUNC_PREFIX:
                        heads.append(rest[: -len(e)])
            if pairs22:
                core = tok.strip(_TOKEN_EDGE)
                if 8 <= len(core) <= 19 and "/" not in core:
                    for pre, suf in pairs22:
                        if core.startswith(pre) and core.endswith(suf):
                            whole.append(core)
            if target:
                for cand in {tok, tok.strip(_TOKEN_EDGE), tok.rstrip(".,;:)")}:
                    if len(cand) >= 4 and secret_sha256(cand) == target:
                        whole.append(cand)
                        if sha_out is not None:
                            sha_out.append(cand)
                        break
    out_w = [v for v in dict.fromkeys(whole) if _plausible_value(v)]
    out_h = [v for v in dict.fromkeys(heads) if _plausible_value(v) and v not in out_w]
    return out_w, out_h


def _mask_heads(obj: Any, heads: List[str]) -> Any:
    """Replace each clear head (a value cut by an ellipsis) by its first 4
    characters and the fill. Identity keys untouched."""
    if not heads:
        return obj
    if isinstance(obj, str):
        out = obj
        for h in sorted(set(heads), key=len, reverse=True):
            for e in _ELLIPSES:
                if h + e in out:
                    out = out.replace(h + e, h[:4] + MASK_FILL + e)
        return out
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if _location_str(obj, k) or _skip_key(k, obj[k]):
                continue
            obj[k] = _mask_heads(obj[k], heads)
        return obj
    if isinstance(obj, list):
        for i, x in enumerate(obj):
            obj[i] = _mask_heads(x, heads)
        return obj
    return obj


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
    # A bytecode finding without a source line (R8 build, quick scan) names
    # its method (src/android/bytecode_analyzer._secret_location_fields).
    meth = f.get("bytecode_method")
    if isinstance(meth, str) and meth.strip() and len(meth) <= 120:
        return f"{file_} {meth.strip()}"
    return str(file_)


def _wording(kind: str, provider: Optional[str], basis: str, confidence: str,
             masked: Optional[str], f: Dict[str, Any],
             length: Optional[int] = None) -> Dict[str, str]:
    if provider:
        lab_en, lab_fr = _PROVIDER_LABELS.get(provider, (provider, provider))
    else:
        lab_en, lab_fr = _KIND_LABELS.get(kind, (None, None))
    tag_en = "format match, not tested" if basis == "format" else "pattern match, not tested"
    tag_fr = ("correspondance de format, non testé" if basis == "format"
              else "correspondance de motif, non testé")
    title_en = (f"Potential secret: {lab_en} ({tag_en})" if lab_en
                else f"Potential secret ({tag_en})")
    title_fr = (f"Secret potentiel : {lab_fr} ({tag_fr})" if lab_fr
                else f"Secret potentiel ({tag_fr})")
    where = _location(f)
    art_en = _subject(f, "en")
    art_fr = _subject(f, "fr")
    if basis == "format":
        why_en = f"matches the published format of a {lab_en}"
        why_fr = f"correspond au format publié suivant : {lab_fr}"
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
    loc_fr = f" dans {where}" if where else ""
    val_en = f" Value (masked): {masked}." if masked else ""
    val_fr = f" Valeur (masquée) : {masked}." if masked else ""
    if masked and length:
        val_en = f" Value (masked): {masked}, {int(length)} characters long."
        val_fr = f" Valeur (masquée) : {masked}, longueur {int(length)} caractères."
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
    desc_fr = (f"Une valeur{loc_fr} {why_fr}.{val_fr} Narvy n'a pas testé cette valeur : il ne sait "
               f"pas si elle est valide, active, révoquée ou restreinte. Confiance : {conf_fr}. S'il "
               f"s'agit d'un véritable identifiant, toute personne pouvant lire le {art_fr} peut "
               f"aussi le lire. {sev_fr}")
    rem_en = ("Check whether this value is a real credential. If it is: remove it from the "
              f"{art_en} (keep it server-side, in a secrets manager, or inject it at build time "
              "from a protected store), then revoke it and issue a new one, because it may already "
              "have been copied. If it is not a credential (test value, identifier, public "
              "constant), mark the finding as a false positive.")
    rem_fr = ("Vérifiez s'il s'agit d'un véritable identifiant. Si oui : retirez-le du "
              f"{art_fr} (gardez-le côté serveur, dans un gestionnaire de secrets, ou injectez-le "
              "à la compilation depuis un stockage protégé), puis révoquez-le et émettez-en un "
              "nouveau, car il a pu être copié. Sinon (valeur de test, identifiant, constante "
              "publique), marquez le constat comme faux positif.")
    return {"title": title_en, "title_fr": title_fr, "description": desc_en,
            "description_fr": desc_fr, "remediation": rem_en, "remediation_fr": rem_fr,
            "severity_rationale": sev_en, "severity_rationale_fr": sev_fr}


_SUBJECTS = (("source code", "code source"), ("app package", "paquet de l'application"),
             ("container image", "image de conteneur"), ("analysed files", "fichiers analysés"))
_STORED_FR: Optional[Dict[str, str]] = None
_STORED_RX: Optional[List[Tuple[Any, Dict[str, str], Dict[str, str], str]]] = None


def _stored_tables() -> None:
    """EN -> FR of every sentence this module stamps, built from the same
    wording functions (one source): the fixed ones in a dict, the ones that
    carry a location / masked value as regexes."""
    global _STORED_FR, _STORED_RX
    if _STORED_FR is not None:
        return
    fixed: Dict[str, str] = {}
    labels = [(k, None) for k in _KIND_LABELS] + [("generic", p) for p in _PROVIDER_LABELS]
    whys: Dict[str, str] = {}
    confs: Dict[str, str] = {}
    arts = {en: fr for en, fr in _SUBJECTS}
    plat_for = {"source code": {"scan_mode": "source"}, "app package": {"platform": "android"},
                "container image": {"platform": "container"}, "analysed files": {}}
    for kind, prov in labels:
        for basis in ("format", "pattern"):
            for conf in ("likely", "potential"):
                for art_en, f in plat_for.items():
                    w = _wording(kind, prov, basis, conf, None, f)
                    for k in ("title", "remediation", "severity_rationale"):
                        fixed[w[k]] = w[k + "_fr"]
                    # Decompose the description into its varying parts.
                    d_en, d_fr = w["description"], w["description_fr"]
                    why_en = d_en[len("A value "):d_en.index(". Narvy did not test")]
                    why_fr = d_fr[len("Une valeur "):d_fr.index(". Narvy n'a pas testé")]
                    whys[why_en] = why_fr
                    c_en = d_en.split("Confidence: ", 1)[1].split(". If it is", 1)[0]
                    c_fr = d_fr.split("Confiance : ", 1)[1].split(". S'il", 1)[0]
                    confs[c_en] = c_fr
    for prov in _PROVIDER_LABELS:
        w = _public_wording(prov, None, {})
        for k in ("title", "remediation", "severity_rationale"):
            fixed[w[k]] = w[k + "_fr"]
    w0 = _wording("generic", None, "pattern", "potential", None, {})
    sev_en, sev_fr = w0["severity_rationale"], w0["severity_rationale_fr"]

    def alt(d: Dict[str, str]) -> str:
        return "|".join(re.escape(k) for k in sorted(d, key=len, reverse=True))

    desc_rx = re.compile(
        r"^A value(?: at (?P<where>.+?))? (?P<why>" + alt(whys) + r")\."
        r"(?: Value \(masked\): (?P<masked>.+?)(?:, (?P<n>\d+) characters long)?\.)?"
        r" Narvy did not test this value: it does not "
        r"know whether it is valid, active, revoked or restricted\. Confidence: (?P<conf>"
        + alt(confs) + r")\. If it is a real credential, anyone who can read the (?P<art>"
        + alt(arts) + r") can read it too\. " + re.escape(sev_en) + r"$", re.S)
    desc_fr = ("Une valeur{loc} {why}.{val} Narvy n'a pas testé cette valeur : il ne sait pas si "
               "elle est valide, active, révoquée ou restreinte. Confiance : {conf}. S'il s'agit "
               "d'un véritable identifiant, toute personne pouvant lire le {art} peut aussi le "
               "lire. " + sev_fr)
    pub_labels = {en: fr for en, fr in _PROVIDER_LABELS.values()}
    pub_rx = re.compile(
        r"^A (?P<lab>" + alt(pub_labels) + r")(?: at (?P<where>.+?))? is designed to ship in "
        r"client apps and web pages, so it is not reported as a secret\."
        r"(?: Value \(masked\): (?P<masked>.+?)\.)? What protects it is its configuration on the "
        r"provider side \(allowed apps, referrers, APIs, quotas\)\. Narvy did not test it and "
        r"cannot see those restrictions\.$", re.S)
    pub_fr = ("Une {lab}{loc} est conçue pour être livrée dans les applications et pages web "
              "clientes : elle n'est donc pas signalée comme un secret.{val} Ce qui la protège est "
              "sa configuration chez le fournisseur (applications, référents, API autorisés, "
              "quotas). Narvy ne l'a pas testée et ne voit pas ces restrictions.")
    _STORED_RX = [(desc_rx, {"why": whys, "conf": confs, "art": arts}, {}, desc_fr),
                  (pub_rx, {"lab": pub_labels}, {}, pub_fr)]
    _STORED_FR = fixed


def stored_text_fr(text: Any) -> Optional[str]:
    """French of a sentence this module wrote in English (title, description,
    remediation, severity rationale), or None when ``text`` is not one.

    A finding stored before ``*_fr`` keys existed, or a surface that only
    kept the English column (vulnerability tracker rows, dashboard top
    findings), still shows its French through this (2026-10-20, prod QA:
    "Potential secret (pattern match, not tested)" stayed English in FR)."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        _stored_tables()
        s = text.strip()
        hit = (_STORED_FR or {}).get(s)
        if hit is not None:
            return hit
        if not (s.startswith("A value") or s.startswith("A ")):
            return None
        for rx, maps, _unused, tpl in (_STORED_RX or []):
            m = rx.match(s)
            if not m:
                continue
            g = m.groupdict()
            vals = {k: maps[k][g[k]] for k in maps}
            vals["loc"] = f" dans {g['where']}" if g.get("where") else ""
            vals["val"] = f" Valeur (masquée) : {g['masked']}." if g.get("masked") else ""
            if g.get("masked") and g.get("n"):
                vals["val"] = f" Valeur (masquée) : {g['masked']}, longueur {g['n']} caractères."
            return tpl.format(**vals)
    except Exception:  # noqa: BLE001 - presentation never raises
        return None
    return None


def _public_wording(provider: str, masked: Optional[str], f: Dict[str, Any]) -> Dict[str, str]:
    lab_en, lab_fr = _PROVIDER_LABELS.get(provider, (provider, provider))
    where = _location(f)
    loc_en = f" at {where}" if where else ""
    loc_fr = f" dans {where}" if where else ""
    val_en = f" Value (masked): {masked}." if masked else ""
    val_fr = f" Valeur (masquée) : {masked}." if masked else ""
    return {
        "title": f"Public client key: {lab_en} (not a secret, check its restrictions)",
        "title_fr": f"Clé client publique : {lab_fr} (pas un secret, vérifiez ses restrictions)",
        "description": (f"A {lab_en}{loc_en} is designed to ship in client apps and web pages, so "
                        f"it is not reported as a secret.{val_en} What protects it is its "
                        "configuration on the provider side (allowed apps, referrers, APIs, "
                        "quotas). Narvy did not test it and cannot see those restrictions."),
        "description_fr": (f"Une {lab_fr}{loc_fr} est conçue pour être livrée dans les applications "
                           f"et pages web clientes : elle n'est donc pas signalée comme un secret."
                           f"{val_fr} Ce qui la protège est sa configuration chez le fournisseur "
                           "(applications, référents, API autorisés, quotas). Narvy ne l'a pas "
                           "testée et ne voit pas ces restrictions."),
        "remediation": ("In the provider console, check that this key is restricted to your "
                        "apps or domains and to the APIs it needs."),
        "remediation_fr": ("Dans la console du fournisseur, vérifiez que cette clé est limitée à "
                           "vos applications ou domaines et aux API nécessaires."),
        "severity_rationale": "Informational: public by design, not a secret.",
        "severity_rationale_fr": "Informatif : publique par conception, pas un secret.",
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
            if _location_str(obj, k) or _skip_key(k, obj[k]):
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


def _masked_copy(v: Any, raws: List[str], heads: List[str]) -> Any:
    new = _mask_container(json.loads(json.dumps(v, default=str)), raws)
    new = _mask_heads(new, heads)
    return mask_url_secrets_tree(new)


def _feed(sink: Optional[List[str]], weak_sink: Optional[List[str]], anchored: List[str],
          twins: List[str], by_sha: List[str]) -> None:
    """Values for the document-wide sweep: anchored values and the clear
    twins of a mask go to ``sink``; a secret_sha256 match goes to
    ``weak_sink`` (the stored sha may name a guessed value of an older
    version: masked in secret findings only)."""
    if sink is None:
        return
    sink.extend(v for v in anchored if not _is_masked(v))
    sink.extend(v for v in twins if v not in by_sha)
    sink.extend(v for v in by_sha if _random_looking(v))
    (weak_sink if weak_sink is not None else sink).extend(v for v in by_sha if not _random_looking(v))


def _remask_presented(f: Dict[str, Any], sink: Optional[List[str]] = None,
                      weak_sink: Optional[List[str]] = None) -> bool:
    """A presented finding met again (a later stage added or rewrote a field
    after masking, or it was masked by an older version of this module):
    mask its raw values again, found from its fields, from the masks it
    already shows and from its secret_sha256. Never guesses a literal.
    Returns True when a field changed. The fingerprint basis stamped at the
    first presentation stays (first basis wins)."""
    anchored: List[str] = []
    raws = [r for r in _raw_values(f, fallback=False, anchored_out=anchored) if not _is_masked(r)]
    by_sha: List[str] = []
    twins, heads = _twin_values(f, by_sha)
    raws = list(dict.fromkeys(raws + twins))
    _feed(sink, weak_sink, anchored, twins, by_sha)
    changed = False
    for k in list(f.keys()):
        if _location_str(f, k) or _skip_key(k, f[k]):
            continue
        v = f[k]
        if not isinstance(v, (str, dict, list)):
            continue
        try:
            new = _masked_copy(v, raws, heads)
        except Exception:  # noqa: BLE001
            continue
        if not _deep_equal_json(new, v):
            f[k] = new
            changed = True
    if raws and "secret_length" not in f and f.get("secret_sha256"):
        for r in raws:
            if secret_sha256(r) == f["secret_sha256"]:
                f["secret_length"] = len(r)
                changed = True
                break
    return changed


def present_finding(f: Any, context: Optional[Dict[str, Any]] = None,
                    sink: Optional[List[str]] = None, weak_sink: Optional[List[str]] = None) -> bool:
    """Mask + reword one finding in place. Returns True when it changed.
    `context`: {platform, scan_mode} of the result the finding belongs to.
    `sink`: when given, the clear values found are appended to it (the caller
    masks them in the rest of the document, never stores them)."""
    if not isinstance(f, dict):
        return False
    secret = is_secret_finding(_view(f, context))
    has_mask = False
    if not secret:
        # Fast path: nothing that looks like a secret format anywhere in it,
        # and no masked value whose clear twin could sit in another field.
        try:
            dumped = json.dumps(f, default=str, ensure_ascii=False)
            has_mask = MASK_FILL in dumped
            if not has_mask and not _QUICK_RE.search(dumped):
                return False
        except Exception:  # noqa: BLE001
            pass
    if not secret:
        # Not a secret finding: still never show a format-matched secret or
        # a URL credential, in any field (2026-11-10: matched_string,
        # detected_instances and sample_locations of a "Hardcoded URLs"
        # finding carried a scheme://user:password@host in clear), nor the
        # clear twin of a value a validator masked in another field.
        by_sha: List[str] = []
        twins, heads = _twin_values(f, by_sha) if has_mask else ([], [])
        _feed(sink, weak_sink, [], twins, by_sha)
        updates = {}
        loc = f.get("location")
        if isinstance(loc, str) and "://" in loc and "@" in loc:
            new_loc = mask_url_secrets(loc)
            if new_loc != loc:
                updates["location"] = new_loc
        for k, v in f.items():
            if k == "location" and isinstance(v, str):
                continue
            if _skip_key(k, v):
                continue
            if isinstance(v, (str, dict, list)):
                try:
                    new = _masked_copy(v, twins, heads)
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
        # Already presented: re-mask (idempotent, catches late copies). A
        # change counts, so a stored JSON is rewritten (present_result_json).
        return _remask_presented(f, sink, weak_sink)
    fv = _view(f, context)
    info = classify(fv)
    anchored: List[str] = []
    raws = _raw_values(f, anchored_out=anchored)
    by_sha: List[str] = []
    twins, heads = _twin_values(f, by_sha)
    raws = list(dict.fromkeys(raws + [t for t in twins if t not in raws]))
    first_raw = next((r for r in raws if not _is_masked(r)), None)
    _feed(sink, weak_sink, anchored, twins, by_sha)
    _stamp_basis(f)
    if first_raw and "secret_sha256" not in f:
        f["secret_sha256"] = secret_sha256(first_raw)
    if first_raw and "secret_length" not in f:
        f["secret_length"] = len(first_raw)
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
                         masked, fv,
                         length=(masked_length(first_raw)
                                 if first_raw and info["provider"] != "private_key" else None))
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
    _mask_heads(f, heads)
    for k in list(f.keys()):
        if not _skip_key(k, f[k]) and isinstance(f[k], (str, dict, list)):
            f[k] = mask_url_secrets_tree(f[k])
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
                 "premium_findings", "locked_findings",
                 # 2026-11-10: grouped views keep whole finding copies too
                 # (a PEM block sat in clear in grouped_vulnerabilities[]
                 # .instances[].match_info.detection_context).
                 "grouped_vulnerabilities", "grouped_findings", "instances")

# Keys of the stored document never rewritten by the document-wide sweep.
_SWEEP_SKIP_KEYS = {"secret_sha256", "fingerprint_mask_basis", "fingerprint", "tracker_identity",
                    "registry_rule", "references", "reference", "links", "link", "see_also",
                    "scan_id", "id", "file", "file_path", "path", "filename", "rule_id",
                    "check_id", "vuln_id", "cwe", "cwe_id", "masvs", "masvs_id", "package",
                    "package_name"}
_SWEEP_MIN_LEN = 6


def _sweep_raw_ok(v: str) -> bool:
    """A clear value to mask everywhere in the document. Every value reaching
    the sweep is anchored (a secret finding's matched value, the clear twin
    of a mask, a secret_sha256 match), so no entropy / character-class gate
    (rel86c judge B1): only length, placeholders and URLs."""
    return (isinstance(v, str) and len(v) >= _SWEEP_MIN_LEN and " " not in v and "\n" not in v
            and not _is_masked(v) and _plausible_value(v)
            # A URL the detector quoted is not a value to hunt for in
            # other findings (its credentials are masked by mask_url_secrets).
            and not re.match(r"(?i)[a-z][a-z0-9+.\-]*://", v))


def _strong_value(v: str) -> bool:
    """Distinctive enough to hunt in every field of the document (random-
    looking, or letters mixed with digits). A weaker anchored value is still
    masked, but only inside secret findings."""
    return _entropy(v) >= 3.0 or (any(c.isdigit() for c in v) and any(c.isalpha() for c in v))


def _looks_like_finding(d: Dict[str, Any]) -> bool:
    return "severity" in d and any(k in d for k in ("title", "rule_id", "check_id", "type", "name"))


# In a finding dict: its identity / fingerprint inputs stay as they are
# (title / name feed some fingerprints; a secret finding's title is reworded
# by present_finding anyway). location is swept (its code carries values).
_SWEEP_FINDING_SKIP = (_SWEEP_SKIP_KEYS | _IDENTITY_KEYS | {"title", "name", "detector_title"}) - {"location"}


def _sweep_fields(node: Dict[str, Any], raws: List[str], skip: Any, depth: int,
                  weak: List[str] = (), in_secret: bool = False) -> Tuple[Dict[str, Any], int]:
    here = list(raws) + list(weak) if in_secret else raws
    changes = 0
    for k in list(node.keys()):
        if k in skip:
            continue
        v = node[k]
        if isinstance(v, str):
            if _location_str(node, k):
                continue  # a "file:line" location string is identity
            new = mask_text(v, here, fragments=in_secret)
            if new != v:
                node[k] = new
                changes += 1
        elif isinstance(v, (dict, list)):
            _new, c = _sweep(v, raws, None, depth + 1, weak, in_secret)
            changes += c
    return node, changes


def _sweep(node: Any, raws: List[str], finding: Optional[Dict[str, Any]], depth: int,
           weak: List[str] = (), in_secret: bool = False) -> Tuple[Any, int]:
    """Document-wide: every string leaf, at any depth, with the known clear
    values and every format-matched token masked. ``weak``: anchored values
    too common to hunt everywhere (letters only, low entropy: "postgres"):
    masked only inside secret findings. A finding dict gets its fingerprint
    basis stamped before its first change. Returns (node, changes)."""
    if depth > 60:
        return node, 0
    if isinstance(node, str):
        new = mask_text(node, list(raws) + list(weak) if in_secret else raws, fragments=in_secret)
        return new, (1 if new != node else 0)
    changes = 0
    if isinstance(node, dict):
        is_f = _looks_like_finding(node)
        if is_f and not in_secret and weak and is_secret_finding(node):
            in_secret = True
        here = list(raws) + list(weak) if in_secret else raws
        skip = _SWEEP_FINDING_SKIP if is_f else _SWEEP_SKIP_KEYS
        if is_f or depth == 0:
            # Cheap exit: nothing in this subtree that mask_text could change.
            try:
                dumped = json.dumps(node, default=str, ensure_ascii=False)
            except Exception:  # noqa: BLE001
                dumped = None
            if dumped is not None and not _QUICK_RE.search(dumped) and not any(
                    _any_piece_in(json.dumps(r, ensure_ascii=False)[1:-1], dumped)
                    for r in (list(raws) + list(weak) if (in_secret or depth == 0) else raws)):
                return node, 0
        if is_f and not isinstance(node.get("fingerprint_mask_basis"), dict):
            # Stamp the clear-text basis before the first change (a probe on
            # a copy decides whether anything will change).
            probe = json.loads(json.dumps(node, default=str))
            _p, c = _sweep_fields(probe, raws, skip, depth, weak, in_secret)
            if c:
                node["fingerprint_mask_basis"] = fingerprint_basis_of(node)
        changes += _sweep_fields(node, raws, skip, depth, weak, in_secret)[1]
        return node, changes
    if isinstance(node, list):
        for i, v in enumerate(node):
            new, c = _sweep(v, raws, finding, depth + 1, weak, in_secret)
            if c:
                node[i] = new
                changes += c
        return node, changes
    return node, 0


def clear_values(f: Any) -> List[str]:
    """The clear secret values of one finding (its raw values when it is a
    secret finding, plus the clear twins of masks it shows). For callers that
    mask other copies of the same finding (a stored occurrence row, a report
    file). Never logged, never stored."""
    if not isinstance(f, dict):
        return []
    vals: List[str] = []
    if is_secret_finding(f):
        vals.extend(r for r in _raw_values(f, fallback=not f.get("secret_presentation"))
                    if not _is_masked(r))
    twins, heads = _twin_values(f)
    vals.extend(twins)
    vals.extend(heads)
    return list(dict.fromkeys(v for v in vals if v))


def mask_clues(result: Any) -> Tuple[set, set]:
    """(secret_sha256 values, (first 4, last 4) of every 4+4 mask) found in a
    stored result: what a report file rendered from the clear result can be
    matched against once the result itself is masked."""
    shas, pairs = set(), set()

    def _w(n: Any, depth: int = 0) -> None:
        if depth > 60:
            return
        if isinstance(n, dict):
            v = n.get("secret_sha256")
            if isinstance(v, str) and len(v) == 64:
                shas.add(v)
            for x in n.values():
                _w(x, depth + 1)
        elif isinstance(n, list):
            for x in n:
                _w(x, depth + 1)
        elif isinstance(n, str) and MASK_FILL in n:
            pairs.update(_MASK44_RE.findall(n))

    _w(result)
    return shas, pairs


def clear_values_in_text(text: str, shas: Iterable[str], pairs: Iterable[Tuple[str, str]]) -> List[str]:
    """Clear tokens of `text` whose SHA-256 is one of `shas`, or that start
    and end like one of the 4+4 masks `pairs` (at least 12 characters)."""
    shas = set(shas or ())
    pairs = set(pairs or ())
    if not text or (not shas and not pairs):
        return []
    out: List[str] = []
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0)
        if MASK_FILL in tok or len(tok) < 4:
            continue
        cands = {tok, tok.strip(_TOKEN_EDGE), tok.rstrip(".,;:)")}
        if shas:
            for c in cands:
                if secret_sha256(c) in shas:
                    out.append(c)
        if pairs and len(tok) >= 12:
            for pre, suf in pairs:
                i = tok.find(pre)
                if i < 0:
                    continue
                rest = tok[i:]
                j = rest.rfind(suf)
                if j >= 8:
                    out.append(rest[: j + 4])
                for e in _ELLIPSES:
                    if rest.endswith(e) and len(rest) - len(e) >= _MIN_TRUNC_PREFIX:
                        out.append(rest[: -len(e)])
    return [v for v in dict.fromkeys(out) if _plausible_value(v)]


def mask_secrets_tree(node: Any, raw_values: Iterable[str] = ()) -> Any:
    """In place over a JSON tree: every string (any depth, identity keys
    excepted) through mask_text with ``raw_values``; a finding dict in it gets
    its fingerprint basis stamped before its first change. Returns ``node``
    (a bare string: its masked copy)."""
    raws = sorted({v for v in raw_values if isinstance(v, str) and v}, key=len, reverse=True)
    if isinstance(node, str):
        return mask_text(node, raws)
    try:
        return _sweep(node, raws, None, 0)[0]
    except Exception:  # noqa: BLE001
        return node


def present_result(result: Any, move_public: bool = False) -> int:
    """present_finding over every finding list of a result dict (and of the
    nested report dicts some analyzers keep), then a document-wide sweep: the
    clear values found in the secret findings, and every format-matched token,
    are masked wherever else the document copied them (grouped views,
    architecture quick wins, AI explanations, PoCs...). With
    move_public=True, a public-by-design key found in `vulnerabilities`
    moves to `hidden_findings` (Info is hidden by default) and the counters
    are fixed. Returns the number of findings (and swept fields) changed."""
    if not isinstance(result, dict):
        return 0
    n = 0
    seen: set = set()
    plat = str(result.get("platform") or "").lower()
    smode = str(result.get("scan_mode") or "").lower()
    if result.get("project_type") or smode == "source" or plat in ("source_code", "source"):
        smode = "source"
    context = {"platform": plat, "scan_mode": smode}
    found: List[str] = []
    weak_found: List[str] = []

    def _walk(d: Dict[str, Any], depth: int) -> None:
        nonlocal n
        if depth > 6:
            return
        for key, val in list(d.items()):
            if isinstance(val, list) and key in _RESULT_LISTS and id(val) not in seen:
                seen.add(id(val))
                for f in val:
                    if isinstance(f, dict):
                        try:
                            if present_finding(f, context, found, weak_found):
                                n += 1
                        except Exception:  # noqa: BLE001 - never lose a result
                            logging.getLogger(__name__).warning(
                                "secret presentation skipped one finding", exc_info=False)
                        # A group / instance list nested in the finding.
                        _walk(f, depth + 1)
            elif isinstance(val, dict) and key not in ("meta",):
                _walk(val, depth + 1)

    _walk(result, 0)
    try:
        # Values anchored by the scan's own secret_sha256 / 4+4 masks, wherever
        # they sit (a finding presented earlier keeps no raw value).
        shas, pairs = mask_clues(result)
        if shas or pairs:
            leaves: List[str] = []

            def _lv(node: Any, depth: int = 0) -> None:
                if depth > 60:
                    return
                if isinstance(node, str):
                    leaves.append(node)
                elif isinstance(node, dict):
                    for k, x in node.items():
                        if k not in _SWEEP_SKIP_KEYS:
                            _lv(x, depth + 1)
                elif isinstance(node, list):
                    for x in node:
                        _lv(x, depth + 1)

            _lv(result)
            for leaf in leaves:
                # sha / mask matches across the document: secret findings only
                weak_found.extend(clear_values_in_text(leaf, shas, pairs))
        ok = {v for v in found if _sweep_raw_ok(v)}
        strong = sorted({v for v in ok if _strong_value(v)}, key=len, reverse=True)
        # A secret_sha256 / mask-edge match that looks generated (both cases
        # and digits, 16+) is certain: hunted everywhere. A word-like one may
        # name an older version's guess: secret findings only.
        sure = {v for v in weak_found if _sweep_raw_ok(v) and _random_looking(v)}
        strong = sorted(set(strong) | sure, key=len, reverse=True)
        weak = sorted(({v for v in weak_found if _sweep_raw_ok(v)} | ok) - set(strong),
                      key=len, reverse=True)
        _node, swept = _sweep(result, strong, None, 0, weak)
        n += swept
    except Exception:  # noqa: BLE001 - never lose a result
        logging.getLogger(__name__).warning("secret sweep skipped", exc_info=False)
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
