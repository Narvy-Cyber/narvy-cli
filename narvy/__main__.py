"""`python -m narvy` (or `py -m narvy` on Windows) runs the CLI.

Works even when pip put the `narvy` command in a Scripts/bin directory that is
not on PATH, which is the default for a user install on Windows and macOS.
"""
import os
import sys


def _prog() -> str:
    """Name shown in usage lines: the interpreter the user actually typed, plus -m narvy."""
    argv0 = (getattr(sys, "orig_argv", None) or [""])[0]
    name = os.path.basename(argv0)
    if name.lower().endswith(".exe"):
        name = name[:-4]
    if not name.lower().startswith(("python", "py")):
        name = "python"
    return f"{name} -m narvy"


def main() -> None:
    from .pathhint import maybe_print_path_hint
    from .main import cli

    maybe_print_path_hint()
    cli(prog=_prog())


if __name__ == "__main__":
    main()
