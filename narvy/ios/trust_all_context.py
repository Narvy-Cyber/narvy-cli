"""Context gate for the `ios-swift-trust-all-certs` rule: detect an explicit
per-request opt-in trust flag guarding the trust-all finding so the caller can
downgrade rather than drop it."""
from __future__ import annotations

import re
from typing import Optional

# Identifier substrings meaning the user opted in to relaxing cert validation.
_OPT_IN_TRUST_TOKENS = (
    "allowuntrusted",
    "allowinvalidcert",
    "allowinvalidcertificate",
    "allowselfsigned",
    "allowbadcert",
    "allowanycert",
    "allowanyhttpscert",
    "trustallcert",
    "trustanycert",
    "trustall",
    "allowinsecure",
    "disablecertvalidation",
    "disablecertificatevalidation",
    "disablesslvalidation",
    "skipcertvalidation",
    "skiptlsvalidation",
    "skipservertrust",
    "ignorecert",
    "ignoressl",
    "insecureskipverify",
    "acceptselfsigned",
    "acceptanycert",
)

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_MAX_LOOKBACK_LINES = 80

_FUNC_START_RE = re.compile(r"\b(func|init)\b")


def _window_bounds(lines: list, finding_idx: int) -> tuple:
    """Return (start, end) idx of the enclosing-function window, falling back to a fixed look-back."""
    start = max(0, finding_idx - _MAX_LOOKBACK_LINES)
    for i in range(finding_idx, start - 1, -1):
        if _FUNC_START_RE.search(lines[i]):
            return i, finding_idx
    return start, finding_idx


def opt_in_trust_flag(content: str, line_no: int) -> Optional[str]:
    """Return the opt-in trust flag guarding the trust-all finding at `line_no`, else None."""
    if not content or line_no < 1:
        return None
    lines = content.splitlines()
    if line_no > len(lines):
        return None
    finding_idx = line_no - 1
    start, end = _window_bounds(lines, finding_idx)

    for i in range(start, end + 1):
        for tok in _IDENT_RE.findall(lines[i]):
            low = tok.lower()
            if any(key in low for key in _OPT_IN_TRUST_TOKENS):
                return tok
    return None
