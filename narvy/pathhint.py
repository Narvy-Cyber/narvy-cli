"""One-line hint when `narvy` was installed but its directory is not on PATH.

Only used by `python -m narvy`: someone who typed `narvy` already has it on
PATH. PATH is never changed for the user, the hint prints the command to run.
"""
from __future__ import annotations

import os
import shutil
import sys
import sysconfig
from typing import List, Optional

MARKER = os.path.join(os.path.expanduser("~/.narvy"), "path_hint_shown")


def _launcher_names() -> List[str]:
    if os.name == "nt":
        return ["narvy.exe", "narvy"]
    return ["narvy"]


def _candidate_script_dirs() -> List[str]:
    """Where pip may have written the `narvy` launcher for this interpreter."""
    dirs: List[str] = []
    schemes = [None]
    try:
        user_scheme = sysconfig.get_preferred_scheme("user")
    except (AttributeError, KeyError):  # Python < 3.10 or a patched distro build
        user_scheme = f"{os.name}_user"
    schemes.append(user_scheme)
    for scheme in schemes:
        try:
            path = sysconfig.get_path("scripts") if scheme is None else sysconfig.get_path("scripts", scheme)
        except KeyError:
            continue
        if path and path not in dirs:
            dirs.append(path)
    return dirs


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path.strip().strip('"'))) if path.strip() else ""


def find_unlisted_scripts_dir(environ=None) -> Optional[str]:
    """The directory holding the `narvy` launcher when it is not on PATH, else None."""
    environ = os.environ if environ is None else environ
    path_value = environ.get("PATH", "")
    if shutil.which("narvy", path=path_value):
        return None
    on_path = {_norm(p) for p in path_value.split(os.pathsep) if p.strip()}
    for d in _candidate_script_dirs():
        if _norm(d) in on_path:
            continue
        if any(os.path.isfile(os.path.join(d, n)) for n in _launcher_names()):
            return d
    return None


def hint_text(scripts_dir: str, platform: str = sys.platform) -> str:
    if platform == "win32":
        ps_dir = scripts_dir.replace("'", "''")  # PowerShell single-quote escape
        return (
            f"narvy: the `narvy` command was installed to {scripts_dir}, which is not on PATH. "
            "To add it for good, run in PowerShell: "
            "[Environment]::SetEnvironmentVariable('Path', "
            "[Environment]::GetEnvironmentVariable('Path', 'User') + "
            f"';{ps_dir}', 'User')  then open a new terminal. "
            "Until then `py -m narvy` (or `python -m narvy`) works."
        )
    shell_rc = "~/.zshrc" if platform == "darwin" else "~/.bashrc"
    return (
        f"narvy: the `narvy` command was installed to {scripts_dir}, which is not on PATH. "
        f"To add it, run: echo 'export PATH=\"{scripts_dir}:$PATH\"' >> {shell_rc}  "
        "then open a new terminal. Until then `python3 -m narvy` works."
    )


def maybe_print_path_hint() -> None:
    """Print the hint once per machine, on an interactive terminal only. Never raises."""
    try:
        if os.environ.get("NARVY_NO_PATH_HINT") or not sys.stderr.isatty():
            return
        if os.path.exists(MARKER):
            return
        scripts_dir = find_unlisted_scripts_dir()
        if not scripts_dir:
            return
        sys.stderr.write(hint_text(scripts_dir) + "\n")
        try:
            os.makedirs(os.path.dirname(MARKER), exist_ok=True)
            with open(MARKER, "w", encoding="utf-8") as fh:
                fh.write(scripts_dir + "\n")
        except OSError:
            pass
    except Exception:
        pass
