#!/usr/bin/env python3
"""Report comment and docstring density.

    python3 tools/comment_density.py [<git-ref>]
"""
from __future__ import annotations

import ast
import io
import os
import subprocess
import sys
import tokenize

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def measure(src: str):
    total = len(src.split("\n"))
    comment_lines = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                comment_lines.add(tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    doc_lines = set()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return total, len(comment_lines), 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            n = body[0].value
            doc_lines.update(range(n.lineno, (n.end_lineno or n.lineno) + 1))
    return total, len(comment_lines), len(doc_lines - comment_lines)


def main(argv):
    ref = argv[0] if argv else None
    files = subprocess.run(
        ["git", "ls-files", "narvy/**/*.py", "narvy/*.py"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.split()
    tot = com = doc = 0
    for rel in sorted(set(files)):
        if ref:
            r = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=REPO,
                               capture_output=True, text=True)
            if r.returncode != 0:
                continue
            src = r.stdout
        else:
            with open(os.path.join(REPO, rel)) as f:
                src = f.read()
        t, c, d = measure(src)
        tot += t
        com += c
        doc += d
    label = ref or "working tree"
    print(f"{label}: {tot} lines, {com} comment lines, {doc} docstring lines, "
          f"combined {100 * (com + doc) / tot:.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
