"""Comment-aware masking for C-family source (Java, Kotlin, Objective-C, Swift):
mark byte offsets inside `//` and `/* */` comments so regex rules don't fire on
commented-out code. String literals excluded; when unsure, treated as code (never drops a finding)."""
from __future__ import annotations

from typing import List

_ST_CODE = 0
_ST_LINE = 1
_ST_BLOCK = 2


def build_comment_mask(content: str) -> List[bool]:
    """Return mask where mask[i] is True iff content[i] is inside a comment."""
    n = len(content)
    mask = [False] * n
    state = _ST_CODE
    block_depth = 0
    i = 0
    while i < n:
        c = content[i]

        if state == _ST_LINE:
            mask[i] = True
            if c == "\n":
                state = _ST_CODE
            i += 1
            continue

        if state == _ST_BLOCK:
            mask[i] = True
            # Kotlin/Swift allow nested block comments.
            if c == "/" and i + 1 < n and content[i + 1] == "*":
                block_depth += 1
                mask[i + 1] = True
                i += 2
                continue
            if c == "*" and i + 1 < n and content[i + 1] == "/":
                block_depth -= 1
                mask[i + 1] = True
                i += 2
                if block_depth == 0:
                    state = _ST_CODE
                continue
            i += 1
            continue

        if c == "/" and i + 1 < n:
            nxt = content[i + 1]
            if nxt == "/":
                state = _ST_LINE
                mask[i] = True
                i += 1
                continue
            if nxt == "*":
                state = _ST_BLOCK
                block_depth = 1
                mask[i] = True
                i += 1
                continue

        # Swift raw string: optional leading '#'s then a quote.
        if c == "#":
            j = i
            while j < n and content[j] == "#":
                j += 1
            hashes = j - i
            if hashes > 0 and j < n and content[j] == '"':
                # Closing delimiter is '"' followed by `hashes` '#'.
                closing = '"' + ("#" * hashes)
                end = content.find(closing, j + 1)
                if end == -1:
                    i = n
                else:
                    i = end + len(closing)
                continue
            i += 1
            continue

        # Triple-quoted string (Swift multiline / Kotlin / Java text block).
        if c == '"' and content.startswith('"""', i):
            end = content.find('"""', i + 3)
            if end == -1:
                i = n
            else:
                i = end + 3
            continue

        # Normal double/single-quoted string with backslash escapes.
        if c == '"' or c == "'":
            quote = c
            i += 1
            while i < n:
                cc = content[i]
                if cc == "\\":
                    i += 2
                    continue
                if cc == quote:
                    i += 1
                    break
                if cc == "\n":
                    # Unterminated string: stop at newline.
                    break
                i += 1
            continue

        i += 1

    return mask


def line_col_to_offset(content: str, line: int, col: int) -> int:
    """Convert a 1-based Semgrep (line, col) to a 0-based char offset, -1 if out of range."""
    if line < 1:
        return -1
    idx = 0
    cur_line = 1
    while cur_line < line:
        nl = content.find("\n", idx)
        if nl == -1:
            return -1
        idx = nl + 1
        cur_line += 1
    off = idx + max(col - 1, 0)
    if off >= len(content):
        return -1
    return off


def line_col_in_comment(content: str, line: int, col: int, mask: List[bool]) -> bool:
    off = line_col_to_offset(content, line, col)
    if off < 0 or off >= len(mask):
        return False
    return mask[off]
