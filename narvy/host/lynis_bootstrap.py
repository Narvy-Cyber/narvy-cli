"""Copy a checksum-pinned Lynis to a temp dir on the host, run it, then remove it."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid
from typing import Optional

from .ssh_exec import (
    HostConn,
    SSHExecError,
    _have,
    _scrub,
    _validate_conn,
    known_hosts_entry_host,
    ssh_exec,
)

logger = logging.getLogger(__name__)

# Bumping the version means re-verifying the upstream tarball signature before
# recording the new hash.
LYNIS_VERSION = "3.1.7"
LYNIS_SHA256 = "b5314a07fd85fa3ffc7da57b508f0108ec3280d84e4af823f805d95cbbc2428c"
LYNIS_URL = f"https://downloads.cisofy.com/lynis/lynis-{LYNIS_VERSION}.tar.gz"

# The tmp fallback keeps unprivileged workers working when /opt is not writable.
CACHE_DIRS = (
    "/opt/narvy/vendor",
    os.path.join(tempfile.gettempdir(), "narvy_vendor"),
)
CACHE_FILENAME = f"lynis-{LYNIS_VERSION}.tar.gz"

DOWNLOAD_TIMEOUT = 60
_REMOTE_PREFIX = "/tmp/narvy_lynis_"
# The only shape of path this module will ever `rm -rf` on a remote host.
_WORKDIR_RE = re.compile(r"^/tmp/narvy_lynis_[0-9a-f]{16}$")

# Non-interactive SSH sessions often omit sbin, where lynis is usually installed.
_PROBE_PATH = "$PATH:/usr/local/sbin:/usr/sbin:/sbin"


class LynisBootstrapError(RuntimeError):
    """Lynis could not be made available on the target. Message is always scrubbed."""


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _cached_tarball() -> Optional[str]:
    for directory in CACHE_DIRS:
        path = os.path.join(directory, CACHE_FILENAME)
        if not os.path.isfile(path):
            continue
        try:
            digest = _sha256_file(path)
        except OSError:
            continue
        if digest == LYNIS_SHA256:
            return path
        logger.warning(
            "lynis_bootstrap: cached tarball %s failed the pinned checksum; "
            "discarding and re-downloading", path)
        try:
            os.remove(path)
        except OSError:
            pass
    return None


def _download_tarball(timeout: int = DOWNLOAD_TIMEOUT) -> str:
    last_err = ""
    for directory in CACHE_DIRS:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            last_err = f"cache dir {directory} not creatable: {exc.strerror}"
            continue
        if not os.access(directory, os.W_OK):
            last_err = f"cache dir {directory} not writable"
            continue

        final = os.path.join(directory, CACHE_FILENAME)
        tmp_path: Optional[str] = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=".lynis_dl_", dir=directory)
            os.close(fd)
            with urllib.request.urlopen(LYNIS_URL, timeout=timeout) as resp, \
                    open(tmp_path, "wb") as out:
                while True:
                    chunk = resp.read(1024 * 256)
                    if not chunk:
                        break
                    out.write(chunk)

            digest = _sha256_file(tmp_path)
            if digest != LYNIS_SHA256:
                raise LynisBootstrapError(
                    f"lynis tarball checksum MISMATCH (supply-chain guard): "
                    f"expected {LYNIS_SHA256}, got {digest} from {LYNIS_URL}. "
                    f"Refusing to ship unverified code to a customer host.")

            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR |
                     stat.S_IRGRP | stat.S_IROTH)
            # Checksum is verified before the file is published into the cache.
            os.replace(tmp_path, final)
            tmp_path = None
            logger.info("lynis_bootstrap: cached verified lynis %s at %s",
                        LYNIS_VERSION, final)
            return final
        except LynisBootstrapError:
            raise
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            continue
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    raise LynisBootstrapError(
        f"could not obtain lynis {LYNIS_VERSION} from {LYNIS_URL} "
        f"(worker needs outbound HTTPS to downloads.cisofy.com on first use): "
        f"{last_err}")


def local_tarball(timeout: int = DOWNLOAD_TIMEOUT) -> str:
    cached = _cached_tarball()
    if cached:
        return cached
    return _download_tarball(timeout=timeout)


def _scp_opts(conn: HostConn, key_path: Optional[str],
              known_hosts_path: str) -> list[str]:
    policy = "yes" if conn.known_host_key else conn.hostkey_policy

    # Mirrors ssh_exec._base_ssh_opts: ambient identity uses no key/password.
    if conn.use_ambient_identity:
        return [
            "-o", f"StrictHostKeyChecking={policy}",
            "-o", f"UserKnownHostsFile={known_hosts_path}",
            "-o", "ConnectTimeout=15",
            "-o", f"User={conn.user}",
            "-P", str(int(conn.port)),   # scp spells it -P, ssh spells it -p
        ]

    opts = [
        "-o", f"StrictHostKeyChecking={policy}",
        "-o", f"UserKnownHostsFile={known_hosts_path}",
        "-o", "ConnectTimeout=15",
        "-o", "NumberOfPasswordPrompts=1",
        # Never offer this machine's own identities/agent to the target host.
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        # User via -o, not user@host, so no ssh option can be smuggled through.
        "-o", f"User={conn.user}",
        "-P", str(int(conn.port)),   # scp spells it -P, ssh spells it -p
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


def scp_to_remote(conn: HostConn, local_path: str, remote_path: str,
                  timeout: int = 120) -> None:
    try:
        _validate_conn(conn)
    except SSHExecError as exc:
        raise LynisBootstrapError(f"invalid connection: {exc}") from None

    if not os.path.isfile(local_path):
        raise LynisBootstrapError("local file to transfer does not exist")

    key_path: Optional[str] = None
    known_hosts_path: Optional[str] = None
    try:
        kh_fd, known_hosts_path = tempfile.mkstemp(prefix="lynis_boot_kh_")
        with os.fdopen(kh_fd, "w") as kh:
            if conn.known_host_key:
                # Non-default ports live under [host]:port in known_hosts.
                entry_host = known_hosts_entry_host(conn.hostname, conn.port)
                kh.write(f"{entry_host} {conn.known_host_key}\n")

        if conn.private_key:
            fd, key_path = tempfile.mkstemp(prefix="lynis_boot_key_",
                                            suffix=".pem")
            with os.fdopen(fd, "w") as fh:
                fh.write(conn.private_key)
                if not conn.private_key.endswith("\n"):
                    fh.write("\n")
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

        # `--` keeps the destination from being reinterpreted as a flag.
        argv = ["scp", *_scp_opts(conn, key_path, known_hosts_path),
                "--", local_path, f"{conn.hostname}:{remote_path}"]

        env = os.environ.copy()
        if conn.password and not conn.private_key:
            if not _have("sshpass"):
                raise LynisBootstrapError(
                    "password auth requested but sshpass is not installed")
            env["SSHPASS"] = conn.password       # env, never argv
            argv = ["sshpass", "-e", *argv]

        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:
            raise LynisBootstrapError(
                f"scp to {conn.hostname}:{conn.port} timed out after "
                f"{timeout}s") from None
        except OSError as exc:
            raise LynisBootstrapError(
                f"scp could not be executed: {exc.strerror}") from None

        if proc.returncode != 0:
            raise LynisBootstrapError(
                f"scp to {conn.hostname}:{conn.port} failed "
                f"(rc={proc.returncode}): {_scrub(proc.stderr)[:240]}")
    finally:
        for path in (key_path, known_hosts_path):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    logger.warning(
                        "lynis_bootstrap: could not remove temp file")


def _new_workdir() -> str:
    return f"{_REMOTE_PREFIX}{uuid.uuid4().hex[:16]}"


def workdir_for_cmd(lynis_cmd: str) -> Optional[str]:
    if not lynis_cmd or not lynis_cmd.startswith(_REMOTE_PREFIX):
        return None
    candidate = "/".join(lynis_cmd.split("/")[:3])
    return candidate if _WORKDIR_RE.match(candidate) else None


def _probe_system_lynis(conn: HostConn, privilege_prefix: str,
                        timeout: int) -> Optional[str]:
    probes = [
        ("plain", "command -v lynis 2>/dev/null || true"),
        ("sbin", f'PATH="{_PROBE_PATH}" command -v lynis 2>/dev/null || true'),
    ]
    if privilege_prefix.strip():
        # `command` is a shell builtin, so sudo needs a shell to run it.
        probes.append(
            ("privileged",
             f"{privilege_prefix}sh -c 'PATH=\"{_PROBE_PATH}\" command -v lynis' "
             f"2>/dev/null || true"))

    for kind, cmd in probes:
        try:
            res = ssh_exec(conn, cmd, timeout=timeout)
        except SSHExecError:
            # A failed probe means no SSH session at all, not a Lynis-availability result.
            raise
        found = (res.stdout or "").strip().splitlines()
        found = [ln.strip() for ln in found if ln.strip().startswith("/")]
        if not found:
            continue
        return "lynis" if kind == "plain" else found[0]
    return None


def ensure_lynis(conn: HostConn, privilege_prefix: str,
                 timeout: int = 120) -> tuple[str, bool]:
    """Make lynis runnable on `conn`; returns (lynis_cmd, ephemeral). When ephemeral, caller MUST cleanup_lynis(). privilege_prefix must match the audit's."""
    privilege_prefix = privilege_prefix or ""

    existing = _probe_system_lynis(conn, privilege_prefix, timeout=min(timeout, 30))
    if existing:
        logger.info("lynis_bootstrap: using system lynis on target")
        return (existing, False)

    tarball = local_tarball()
    workdir = _new_workdir()
    remote_tar = f"{workdir}/lynis.tar.gz"
    wrapper = f"{workdir}/narvy-lynis"
    lynis_script = f"{workdir}/lynis/lynis"

    # umask 077 keeps other local users from tampering with a tree we execute.
    try:
        res = ssh_exec(conn, f"umask 077; mkdir -p {workdir} && echo NARVY_MKDIR_OK",
                       timeout=timeout)
    except SSHExecError as exc:
        raise LynisBootstrapError(f"could not create remote workdir: {exc}") from None
    if "NARVY_MKDIR_OK" not in (res.stdout or ""):
        raise LynisBootstrapError(
            f"could not create remote workdir under /tmp "
            f"(rc={res.returncode}): {_scrub(res.stderr)[:160]}")

    try:
        scp_to_remote(conn, tarball, remote_tar, timeout=timeout)

        # Written via `printf`, so \\n are literal backslash-n that printf turns into newlines.
        wrapper_body = (
            f"#!/bin/sh\\n"
            f"# Narvy ephemeral lynis wrapper - removed after the audit.\\n"
            f"cd {workdir}/lynis || exit 1\\n"
            f'exec ./lynis --usecwd --logfile {workdir}/lynis.log "$@" < /dev/null\\n'
        )
        setup = (
            f"umask 077; cd {workdir} && "
            f"tar -xzf lynis.tar.gz && rm -f lynis.tar.gz && "
            f"test -f {lynis_script} && chmod 0700 {lynis_script} && "
            f"printf '{wrapper_body}' > {wrapper} && chmod 0700 {wrapper} && "
            f"test -x {lynis_script} && test -x {wrapper} && echo NARVY_SETUP_OK"
        )
        try:
            res = ssh_exec(conn, setup, timeout=timeout)
        except SSHExecError as exc:
            raise LynisBootstrapError(f"remote extraction failed: {exc}") from None
        if "NARVY_SETUP_OK" not in (res.stdout or ""):
            raise LynisBootstrapError(
                f"remote extraction failed (rc={res.returncode}): "
                f"{_scrub(res.stderr)[:200]}")

        # Chown the tree to root before a privileged run (root executing a user-writable tree is a TOCTOU).
        if privilege_prefix.strip():
            try:
                res = ssh_exec(conn, f"{privilege_prefix}chown -R 0:0 {workdir} "
                                     f"&& echo NARVY_CHOWN_OK", timeout=timeout)
            except SSHExecError as exc:
                raise LynisBootstrapError(
                    f"could not root-own the lynis tree for the privileged "
                    f"audit: {exc}") from None
            if "NARVY_CHOWN_OK" not in (res.stdout or ""):
                raise LynisBootstrapError(
                    f"could not root-own the lynis tree for the privileged "
                    f"audit (rc={res.returncode}): {_scrub(res.stderr)[:160]}")

        # Probe through the wrapper so the cd-into-untarred-dir requirement is exercised.
        try:
            res = ssh_exec(conn, f"{privilege_prefix}{wrapper} --version",
                           timeout=60)
        except SSHExecError as exc:
            raise LynisBootstrapError(
                f"uploaded lynis failed to execute: {exc}") from None
        version = (res.stdout or "").strip()
        if res.returncode != 0 or not version:
            raise LynisBootstrapError(
                f"uploaded lynis did not run (rc={res.returncode}): "
                f"{_scrub(res.stderr)[:200]}")

        logger.info("lynis_bootstrap: uploaded ephemeral lynis %s to target",
                    version.splitlines()[0][:16])
        return (wrapper, True)
    except Exception:
        cleanup_lynis(conn, workdir)
        raise


def cleanup_lynis(conn: HostConn, workdir: str) -> None:
    """Best-effort `rm -rf` of an uploaded tree; refuses any path outside /tmp/narvy_lynis_<hex16>. Never raises."""
    if not workdir or not _WORKDIR_RE.match(workdir):
        logger.error(
            "lynis_bootstrap: refusing to rm -rf a non-Narvy path")
        return
    try:
        res = ssh_exec(conn, f"rm -rf {workdir} 2>/dev/null; "
                             f"test -e {workdir} && echo NARVY_STILL_THERE || "
                             f"echo NARVY_CLEAN_OK", timeout=60)
        if "NARVY_STILL_THERE" not in (res.stdout or ""):
            return
        # Lynis run under sudo may have left root-owned files behind.
        ssh_exec(conn, f"sudo -n rm -rf {workdir} 2>/dev/null || true",
                 timeout=60)
    except SSHExecError:
        logger.warning(
            "lynis_bootstrap: could not remove remote workdir; it is under "
            "/tmp and will not survive a reboot")
    except Exception:  # noqa: BLE001
        logger.warning("lynis_bootstrap: unexpected error during cleanup")
