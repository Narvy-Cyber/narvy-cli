#!/usr/bin/env python3
"""Compare two revisions of the package for logic equality.

Parses every module at both revisions, strips docstrings, and dumps the AST.
Any difference means something other than a comment or docstring changed.

    python3 tools/verify_no_logic_change.py <git-ref>
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = "narvy"


def strip_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return tree


def normalise(src: str) -> str:
    return ast.dump(strip_docstrings(ast.parse(src)))


def main(argv):
    if len(argv) != 1:
        return 2
    ref = argv[0]
    files = subprocess.run(
        ["git", "ls-files", f"{PKG}/**/*.py", f"{PKG}/*.py"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.split()
    bad, checked, missing = [], 0, []
    for rel in sorted(set(files)):
        old = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=REPO,
                             capture_output=True, text=True)
        if old.returncode != 0:
            missing.append(rel)
            continue
        with open(os.path.join(REPO, rel)) as f:
            new = f.read()
        try:
            same = normalise(old.stdout) == normalise(new)
        except SyntaxError as exc:
            bad.append(f"{rel}: parse error {exc}")
            continue
        checked += 1
        if not same:
            bad.append(rel)
    for rel in missing:
        print("NEW FILE (not in ref):", rel)
    for b in bad:
        print("LOGIC CHANGED:", b)
    print(f"checked {checked} modules against {ref}: "
          f"{'IDENTICAL' if not bad else str(len(bad)) + ' DIFFER'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
