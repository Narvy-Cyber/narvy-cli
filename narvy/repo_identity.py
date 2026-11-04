"""What the server needs to file an uploaded scan under the right app.

The app used to be matched on the folder name only, so a GitHub archive
("microservices-demo-main") was a different app from the clone
("microservices-demo") and hit the asset limit. The upload now also sends the
git remote and branch of the scanned folder when it is the root of a git
checkout; the server matches on the remote, then on the name with and without
the archive suffix (-main, -master, -<branch>, -<sha>). `--app` overrides all
of it.

Only the remote URL (credentials removed, local paths never) and the branch name are read; no
other git data, and never any code.
"""
import os
import re
import shutil
import subprocess
from typing import Optional, Tuple

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


_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_NETWORK_SCHEMES = ("https", "http", "ssh", "git", "git+ssh", "ssh+git")
_LOCAL_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[A-Za-z]:$|[\\/.~])")


def strip_credentials(url: Optional[str]) -> Optional[str]:
    """The remote URL without user / password / token (a CI checkout carries
    e.g. https://gitlab-ci-token:<token>@gitlab.com/...), or None when it
    cannot be read with certainty. Never raises.

    Parsed by hand, not with urlsplit: a password with an unencoded "/", "#"
    or "?" (or a bad port) made urlsplit raise, or left part of the password
    in the "path". Everything up to the LAST "@" is credentials, in every form
    (scheme://, scp-like user@host:path, scheme-less user:pw@host/path)."""
    raw = str(url or "").strip()
    if not raw or any(c.isspace() for c in raw):
        return None
    scheme = ""
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://(.*)$", raw)
    if m:
        scheme, raw = m.group(1).lower(), m.group(2)
        # file:// (and any non-network scheme) names a path on this machine.
        if scheme not in _NETWORK_SCHEMES:
            return None
    elif _LOCAL_PATH_RE.match(raw):
        # C:/..., C:\..., \\server\share, /srv/..., ./..., ../..., ~/...: a local path.
        return None
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1]
    if scheme:
        authority, _sep, path = raw.partition("/")
        host, _c, port = authority.partition(":")
        if not host or not _HOST_RE.match(host) or not path:
            return None
        if port and not (port.isdigit() and 0 < int(port) < 65536):
            port = ""
        path = re.split(r"[?#]", path, 1)[0]
        return f"{scheme}://{host}{':' + port if port else ''}/{path}"
    scp = re.match(r"^([A-Za-z0-9.-]+):(?!//)([^?#]+)$", raw)
    if scp:
        return f"{scp.group(1)}:{scp.group(2)}"
    bare = re.match(r"^([A-Za-z0-9.-]+\.[A-Za-z]{2,})/([^?#]+)$", raw)
    if bare:
        return f"{bare.group(1)}/{bare.group(2)}"
    return None


def repo_name(remote: Optional[str]) -> Optional[str]:
    """The repository name of a remote (last path segment, without .git), or None.

    A CI clone lives in a directory named by the runner, not after the repo
    (Bitbucket .../build, Azure .../s, CircleCI ~/project), so the folder name
    would file every repository under one app."""
    raw = str(remote or "").strip().rstrip("/")
    if not raw:
        return None
    last = re.split(r"[/:]", raw)[-1]
    if last.lower().endswith(".git"):
        last = last[:-4]
    return last if last and last not in (".", "..") else None


def git_identity(target_path: str) -> Tuple[Optional[str], Optional[str]]:
    """(remote URL without credentials, branch) of ``target_path`` when it is
    the ROOT of a git checkout, else (None, None). A folder inside some other
    repository (an extracted archive under a checked-out tree) is not that
    repository."""
    try:
        return _git_identity(target_path)
    except Exception:  # noqa: BLE001 - identity is best effort, never fail an upload
        return None, None


def _git_identity(target_path: str) -> Tuple[Optional[str], Optional[str]]:
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
