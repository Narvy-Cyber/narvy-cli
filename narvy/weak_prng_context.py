"""Grade `android-weak-prng` matches as security, non-security or unknown. Nothing is dropped."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

RULE_ID = "android-weak-prng"

SEVERITY_SECURITY = "HIGH"
SEVERITY_UNKNOWN = "LOW"
SEVERITY_NON_SECURITY = "INFO"

_FALLBACK_BACK = 6
_FALLBACK_FWD = 12
_MAX_BLOCK_LINES = 120

# Platform class names, so these survive minification.
_SEC_API_RE = re.compile(
    r"\b(?:"
    r"SecretKeySpec|IvParameterSpec|PBEKeySpec|GCMParameterSpec|"
    r"KeyGenerator|KeyPairGenerator|KeyGenParameterSpec|SecureRandom|"
    r"Cipher\s*\.\s*getInstance|Mac\s*\.\s*getInstance|"
    r"MessageDigest\s*\.\s*getInstance|Signature\s*\.\s*getInstance|"
    r"KeyStore\s*\.\s*getInstance|PublicKeyCredential"
    r")\b"
)

# Raw byte output is almost always key/nonce/IV/salt material; survives obfuscation.
_NEXT_BYTES_RE = re.compile(r"\.\s*nextBytes\s*\(")

# Strong identifiers only; 'key'/'iv'/'mac'/'auth'/'crypto'/'uuid' are too ambiguous.
_SEC_TOKEN_RE = re.compile(
    r"(?<![a-z])(?:"
    r"token|nonce|salt|otp|passwd|password|passphrase|secret|"
    r"apikey|api_key|privatekey|private_key|keymaterial|key_material|"
    r"seedbytes|challenge|credential|csrf|xsrf|verifier|"
    r"sessionkey|session_key|authcode|auth_code|encrypt|decrypt|signing"
    r")(?![a-z])",
    re.IGNORECASE,
)

# Package layout usually survives obfuscation, so this holds on minified code.
_SEC_PATH_RE = re.compile(
    r"(?:^|/)(?:auth|authentication|authenticator|identity|crypto|"
    r"cryptography|security|keystore|keychain|credentials?|login|signin|"
    r"session|oauth|jwt|fido|webauthn|password)(?:s)?(?:/|$)",
    re.IGNORECASE,
)

# Language-level sink shapes, so these survive obfuscation too.
_NONSEC_SINK_RE = re.compile(
    r"(?:"
    r"Thread\s*\.\s*sleep\s*\(|"
    r"\.\s*postDelayed\s*\(|"
    r"\.\s*setDuration\s*\(|"
    r"\.\s*setStartDelay\s*\(|"
    r"\.\s*setPeriodic\s*\(|"
    r"\.\s*setInexactRepeating\s*\(|"
    r"\.\s*scheduleAtFixedRate\s*\(|"
    r"\.\s*scheduleWithFixedDelay\s*\(|"
    r"ValueAnimator|ObjectAnimator|PropertyValuesHolder|AnimatorSet|"
    r"\bPaint\b|\bCanvas\b|\.\s*setColor\s*\(|\.\s*setAlpha\s*\(|"
    r"\bJobInfo\s*\.\s*Builder\b|\bAlarmManager\b|"
    r"\bColor\s*\.\s*(?:HSVToColor|argb|rgb|parseColor)\s*\(|"
    r"\.\s*setBackgroundColor\s*\("
    r")"
)

_SAMPLING_CMP_RE = re.compile(
    r"(?:Math\s*\.\s*random\s*\(\s*\)|\.\s*next(?:Int|Double|Float)\s*\([^;]*\))"
    r"[^;]*?[<>]=?"
)

_NONSEC_PATH_RE = re.compile(
    r"(?:metric|metrics|analytic|analytics|telemetry|tracking|clickstream|"
    r"nexus|minerva|weblab|logging|logger|sampling|sample|experiment|canary|"
    r"abtest|ab_test|animation|animator|particle|firefly|backoff|retry|"
    r"throttle|ratelimiter|rate_limiter|jitter|splash|onboarding)",
    re.IGNORECASE,
)

_NONSEC_TOKEN_RE = re.compile(
    r"(?<![a-z])(?:"
    r"jitter|backoff|back_off|retry|retries|throttle|samplerate|sample_rate|"
    r"sampling|analytics|telemetry|clickstream|animator|animation|"
    r"interpolator|dialup|bucket|placeholder|shuffle|avatar|confetti|"
    r"filename|file_name|tmpfile|tmp_file|tempfile|temp_file|"
    r"displayid|display_id|nickname"
    r")(?![a-z])",
    re.IGNORECASE,
)

_ASSIGN_RE = re.compile(
    r"(?:^|[^\w.])(?:(?:private|public|protected|static|final|volatile|"
    r"transient)\s+)*(?:java\.util\.)?Random\s+(\w+)\s*="
)
_FIELD_ASSIGN_RE = re.compile(r"this\s*\.\s*(\w+)\s*=\s*new\s+(?:java\.util\.)?Random\s*\(")


def _enclosing_block(lines: List[str], line_idx: int) -> Tuple[int, int]:
    """Best-effort enclosing method body for a 0-based line index."""
    start = max(0, line_idx - _FALLBACK_BACK)
    cur_indent = len(lines[line_idx]) - len(lines[line_idx].lstrip())
    for i in range(line_idx, max(-1, line_idx - _MAX_BLOCK_LINES), -1):
        stripped = lines[i].strip()
        if not stripped:
            continue
        indent = len(lines[i]) - len(lines[i].lstrip())
        if indent < cur_indent and stripped.endswith("{"):
            start = i
            break

    depth = 0
    end = min(len(lines) - 1, line_idx + _FALLBACK_FWD)
    opened = False
    for i in range(start, min(len(lines), start + _MAX_BLOCK_LINES)):
        depth += lines[i].count("{") - lines[i].count("}")
        if lines[i].count("{"):
            opened = True
        if opened and depth <= 0 and i >= line_idx:
            end = i
            break
    return start, max(end, line_idx)


def _assigned_name(line: str) -> Optional[str]:
    m = _FIELD_ASSIGN_RE.search(line)
    if m:
        return m.group(1)
    m = _ASSIGN_RE.search(line)
    if m:
        return m.group(1)
    return None


def _usage_lines(lines: List[str], name: str, decl_idx: int) -> List[str]:
    """Every line in the file that calls a method on `name`."""
    use_re = re.compile(r"(?<![\w.])(?:this\s*\.\s*)?" + re.escape(name) + r"\s*\.\s*\w+\s*\(")
    out = []
    for i, ln in enumerate(lines):
        if i == decl_idx:
            continue
        if use_re.search(ln):
            out.append(ln)
            if len(out) >= 40:
                break
    return out


def classify(content: str, line: int, file_path: str = "") -> Dict[str, Any]:
    """Grade one weak-PRNG hit. `line` is 1-based, per semgrep."""
    lines = content.split("\n")
    idx = max(0, min(len(lines) - 1, line - 1))

    start, end = _enclosing_block(lines, idx)
    block = "\n".join(lines[start:end + 1])

    name = _assigned_name(lines[idx])
    uses = _usage_lines(lines, name, idx) if name else []
    scan = block + "\n" + "\n".join(uses)

    path_norm = (file_path or "").replace("\\", "/")

    # Evidence precedence: what the value flows to outranks where the file lives.
    if _NEXT_BYTES_RE.search(scan):
        return _res("security", "random value read as raw bytes (nextBytes) - "
                                "key/nonce/credential material shape")
    m = _SEC_API_RE.search(scan)
    if m:
        return _res("security", f"used in the same block as a crypto/security API ({m.group(0)})")
    m = _SEC_TOKEN_RE.search(scan)
    if m:
        return _res("security", f"security-material identifier near the call site ('{m.group(0)}')")

    m = _NONSEC_SINK_RE.search(scan)
    if m:
        return _res("non_security", f"value flows to a non-security sink ({m.group(0).strip()})")
    if _SAMPLING_CMP_RE.search(scan):
        return _res("non_security", "value compared against a rate threshold (sampling / coin flip)")

    m = _SEC_PATH_RE.search(path_norm)
    if m:
        return _res("security", f"call site is inside a security component path ('{m.group(0).strip('/')}')")

    m = _NONSEC_TOKEN_RE.search(scan)
    if m:
        return _res("non_security", f"non-security usage keyword near the call site ('{m.group(0)}')")
    m = _NONSEC_PATH_RE.search(path_norm)
    if m:
        return _res("non_security", f"call site is inside a non-security component path ('{m.group(0)}')")

    return _res("unknown", "no evidence found that the value is (or is not) used as security material")


def _res(context: str, evidence: str) -> Dict[str, Any]:
    sev = {
        "security": SEVERITY_SECURITY,
        "non_security": SEVERITY_NON_SECURITY,
        "unknown": SEVERITY_UNKNOWN,
    }[context]
    return {"context": context, "severity": sev, "evidence": evidence}


_MESSAGES = {
    "security": (
        "java.util.Random / Math.random() is not cryptographically secure, and "
        "the value produced here reaches security-sensitive material. Use "
        "java.security.SecureRandom."
    ),
    "non_security": (
        "java.util.Random / Math.random() used in what looks like a "
        "NON-security context. Kept for completeness at Info severity - "
        "review only if this value ever becomes security-relevant. Use "
        "SecureRandom for tokens, keys, nonces, salts and session ids."
    ),
    "unknown": (
        "java.util.Random / Math.random() is not cryptographically secure. No "
        "evidence was found that this value is used as security material, and "
        "none that it isn't - graded Low pending review. Use SecureRandom for "
        "tokens, keys, nonces, salts and session ids."
    ),
}


def apply(findings: List[Dict[str, Any]], source_dir: str) -> List[Dict[str, Any]]:
    """Re-grade every android-weak-prng finding in place (unreadable file keeps original severity)."""
    import os

    cache: Dict[str, Optional[str]] = {}
    for f in findings:
        if f.get("rule_id") != RULE_ID:
            continue
        rel = f.get("file_path") or ""
        abs_path = os.path.join(source_dir, rel)
        if abs_path not in cache:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                    cache[abs_path] = fh.read()
            except OSError:
                cache[abs_path] = None
        content = cache[abs_path]
        if content is None:
            f.setdefault("details", {})["prng_context"] = "unreadable"
            continue

        verdict = classify(content, int(f.get("line") or 1), rel)
        f["original_severity"] = f.get("severity")
        f["severity"] = verdict["severity"]
        details = f.setdefault("details", {})
        details["prng_context"] = verdict["context"]
        details["prng_context_evidence"] = verdict["evidence"]
        details["description"] = _MESSAGES[verdict["context"]]
        details["recommendation"] = _MESSAGES[verdict["context"]]
        f["name"] = _MESSAGES[verdict["context"]][:120]
    return findings


def dedupe_by_location(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse identical (rule_id, file_path, line) findings."""
    seen = set()
    out = []
    for f in findings:
        key = (f.get("rule_id"), f.get("file_path"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
