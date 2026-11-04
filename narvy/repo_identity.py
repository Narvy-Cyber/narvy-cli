"""What the server needs to file an uploaded scan under the right app.

The app used to be matched on the folder name only, so a GitHub archive
("microservices-demo-main") was a different app from the clone
("microservices-demo") and hit the asset limit. The upload now also sends the
git remote and branch of the scanned folder when it is the root of a git
checkout; the server matches on the remote, then on the name with and without
the archive suffix (-main, -master, -<branch>, -<sha>). `--app` overrides all
of it.

Only the remote URL (credentials removed) and the branch name are read; no
other git data, and never any code.
"""
import os
import re
import shutil
import subprocess
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

_GIT_TIMEOUT_S = 5


def _git(cwd: str, *args: str) -> Optional[str]:
    if not shutil.which("git"):
        return None
    try:
        out = subprocess.run(
            ["git", "-C", cwd, *args], capture_output=True, text=True,
            timeout=_GIT_TIMEOUT_S, check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def strip_credentials(url: Optional[str]) -> Optional[str]:
    """The remote URL without user / password / token (a CI checkout carries
    e.g. https://gitlab-ci-token:<token>@gitlab.com/...). scp-like
    git@host:owner/repo keeps no secret beyond the user name, dropped too."""
    raw = str(url or "").strip()
    if not raw:
        return None
    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        if not host:
            return None
        netloc = host + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    m = re.match(r"^(?:[^@/]+@)?([A-Za-z0-9.-]+):(.+)$", raw)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    return None


def git_identity(target_path: str) -> Tuple[Optional[str], Optional[str]]:
    """(remote URL without credentials, branch) of ``target_path`` when it is
    the ROOT of a git checkout, else (None, None). A folder inside some other
    repository (an extracted archive under a checked-out tree) is not that
    repository."""
    path = os.path.abspath(target_path)
    if not os.path.isdir(path):
        return None, None
    top = _git(path, "rev-parse", "--show-toplevel")
    if not top or os.path.realpath(top) != os.path.realpath(path):
        return None, None
    remote = _git(path, "config", "--get", "remote.origin.url")
    if not remote:
        names = (_git(path, "remote") or "").split()
        if names:
            remote = _git(path, "config", "--get", f"remote.{names[0]}.url")
    branch = _git(path, "symbolic-ref", "--short", "-q", "HEAD")
    if not branch:  # detached (CI checkouts): name it from CI env if set
        branch = (os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME")
                  or os.environ.get("CI_COMMIT_REF_NAME") or None)
    return strip_credentials(remote), branch
