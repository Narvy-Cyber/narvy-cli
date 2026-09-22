#!/usr/bin/env python3
"""Remove full-line comments from shipped rule packs and re-add a short header.

A `#` inside a YAML block scalar is rule content, not a comment, so block
scalars are tracked and never touched. The parsed document is compared before
and after; any difference aborts the write.
"""
from __future__ import annotations

import os
import re
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BLOCK_HEADER = re.compile(r":\s*[|>][+-]?\d*\s*(#.*)?$")


def strip_comments(text: str) -> str:
    out = []
    lines = text.split("\n")
    block_indent = None
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if block_indent is not None:
            if stripped == "" or indent > block_indent:
                out.append(line)
                continue
            block_indent = None

        if stripped.startswith("#"):
            continue
        out.append(line)
        if BLOCK_HEADER.search(line):
            block_indent = indent
    return "\n".join(out)


def collapse_blank_runs(text: str) -> str:
    out = []
    blanks = 0
    for line in text.split("\n"):
        if line.strip() == "":
            blanks += 1
            if blanks > 1:
                continue
        else:
            blanks = 0
        out.append(line)
    return "\n".join(out)


def process(path: str, header: str) -> str:
    with open(path) as f:
        original = f.read()
    before = yaml.safe_load(original)
    body = collapse_blank_runs(strip_comments(original)).lstrip("\n")
    new = header.rstrip("\n") + "\n\n" + body
    after = yaml.safe_load(new)
    if before != after:
        raise SystemExit(f"PARSE MISMATCH on {path}, not written")
    if not new.endswith("\n"):
        new += "\n"
    with open(path, "w") as f:
        f.write(new)
    count = len(after["rules"]) if isinstance(after, dict) else len(after)
    return (f"{path}: {len(original.split(chr(10)))} -> "
            f"{len(new.split(chr(10)))} lines, {count} rules preserved")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    path, header = argv[0], argv[1]
    print(process(os.path.join(REPO, path), header))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
