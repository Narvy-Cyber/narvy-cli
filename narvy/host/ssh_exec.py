"""Run commands on a host with the system ssh client, using a temp key file and per-call known_hosts."""

from __future__ import annotations

import logging
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120
# accept-new trusts an unknown host on first contact but rejects a CHANGED key.
DEFAULT_HOSTKEY_POLICY = "accept-new"

# Leading '-' is rejected to prevent ssh option smuggling.
_HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9._:\-]{1,255}$")
_USER_RE = re.compile(r"^(?!-)[A-Za-z0-9._\-]{1,64}$")


class SSHExecError(RuntimeError):
    """Transport or parameter-validation failure; a non-zero remote exit is not one."""


@dataclass
class SSHResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class HostConn:
    """Connection parameters for one target host; credentials are plaintext here."""

    hostname: str
    user: str
    port: int = 22
    private_key: Optional[str] = None
    password: Optional[str] = None
    known_host_key: Optional[str] = None
    hostkey_policy: str = DEFAULT_HOSTKEY_POLICY
    # True lets ssh resolve auth from ~/.ssh/config/agent instead of explicit credentials.
    use_ambient_identity: bool = False


def _validate_conn(conn: HostConn) -> None:
    if not conn.hostname or not _HOSTNAME_RE.match(conn.hostname):
        raise SSHExecError("invalid hostname (charset / leading-dash rejected)")
    if not conn.user or not _USER_RE.match(conn.user):
        raise SSHExecError("invalid ssh user (charset / leading-dash rejected)")
    try:
        port = int(conn.port)
    except (TypeError, ValueError):
        raise SSHExecError("invalid ssh port")
    if not (1 <= port <= 65535):
        raise SSHExecError("ssh port out of range")
    if conn.password and not conn.private_key and not conn.known_host_key:
        # Without a pinned key a first-connect MITM captures the cleartext password.
        raise SSHExecError(
            "password auth requires a pinned host key (known_host_key); "
            "refusing accept-new TOFU for password targets")


def known_hosts_entry_host(hostname: str, port: int) -> str:
    """known_hosts keys a non-default port as `[host]:port`."""
    return hostname if int(port) == 22 else f"[{hostname}]:{int(port)}"


def capture_host_key(hostname: str, port: int = 22,
                     timeout: int = 15) -> Optional[str]:
    """ssh-keyscan the host and return its strongest host key ("algo base64")."""
    if not _HOSTNAME_RE.match(hostname or ""):
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not (1 <= port <= 65535):
        return None
    try:
        proc = subprocess.run(
            ["ssh-keyscan", "-p", str(port), "-T", str(timeout), hostname],
            capture_output=True, text=True, timeout=timeout + 10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    best = None
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        algo, key = parts[1], parts[2]
        entry = f"{algo} {key}"
        if algo == "ssh-ed25519":
            return entry
        if best is None:
            best = entry
    return best


def _base_ssh_opts(conn: HostConn, key_path: Optional[str],
                   known_hosts_path: str) -> list[str]:
    policy = "yes" if conn.known_host_key else conn.hostkey_policy

    if conn.use_ambient_identity:
        return [
            "-o", f"StrictHostKeyChecking={policy}",
            "-o", f"UserKnownHostsFile={known_hosts_path}",
            "-o", "ConnectTimeout=15",
            "-p", str(int(conn.port)),
            "-l", conn.user,
        ]

    opts = [
        "-o", f"StrictHostKeyChecking={policy}",
        "-o", f"UserKnownHostsFile={known_hosts_path}",
        "-o", "ConnectTimeout=15",
        "-o", "NumberOfPasswordPrompts=1",
        # Never offer this machine's own identities or agent to the target.
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-p", str(int(conn.port)),
        "-l", conn.user,
    ]
    if key_path:
        opts += ["-i", key_path, "-o", "BatchMode=yes"]
    else:
        opts += [
            "-o", "BatchMode=no",
            "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password",
        ]
    return opts


def ssh_exec(conn: HostConn, remote_cmd: str,
             timeout: int = DEFAULT_TIMEOUT) -> SSHResult:
    """Run one command on `conn` over SSH; `remote_cmd` reaches the shell as one arg. Non-zero exit is returned, not raised."""
    _validate_conn(conn)

    key_path: Optional[str] = None
    known_hosts_path: Optional[str] = None
    try:
        kh_fd, known_hosts_path = tempfile.mkstemp(prefix="host_audit_kh_")
        with os.fdopen(kh_fd, "w") as kh:
            if conn.known_host_key:
                kh.write(f"{known_hosts_entry_host(conn.hostname, conn.port)} "
                         f"{conn.known_host_key}\n")

        if conn.private_key:
            fd, key_path = tempfile.mkstemp(prefix="host_audit_key_", suffix=".pem")
            with os.fdopen(fd, "w") as fh:
                fh.write(conn.private_key)
                if not conn.private_key.endswith("\n"):
                    fh.write("\n")
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

        argv = ["ssh", *_base_ssh_opts(conn, key_path, known_hosts_path),
                conn.hostname, remote_cmd]

        env = os.environ.copy()
        if conn.password and not conn.private_key:
            if _have("sshpass"):
                env["SSHPASS"] = conn.password
                argv = ["sshpass", "-e", *argv]
            else:
                raise SSHExecError(
                    "password auth requested but sshpass is not installed")

        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise SSHExecError(
                f"ssh to {conn.hostname}:{conn.port} timed out "
                f"after {timeout}s") from exc

        # ssh reserves exit 255 for its own failures; remote codes are < 255.
        if proc.returncode == 255:
            raise SSHExecError(
                f"ssh transport failure to {conn.hostname}:{conn.port}: "
                f"{_scrub(proc.stderr)[:240]}")

        return SSHResult(proc.returncode, proc.stdout, proc.stderr)
    finally:
        for p in (key_path, known_hosts_path):
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    logger.warning("ssh_exec: could not remove temp file")


def ssh_probe(conn: HostConn, timeout: int = 20) -> SSHResult:
    """Cheap connectivity and identity check."""
    return ssh_exec(conn, "echo NARVY_SSH_OK; id -un; uname -a", timeout=timeout)


def _have(binary: str) -> bool:
    from shutil import which
    return which(binary) is not None


def _scrub(text: str) -> str:
    if not text:
        return ""
    return text.replace("\r", " ").strip()
