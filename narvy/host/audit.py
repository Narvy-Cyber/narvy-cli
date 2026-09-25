"""Run Lynis on a remote host over SSH. Full coverage needs a root key or NOPASSWD sudo."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any, Dict

from .lynis_bootstrap import (LynisBootstrapError, cleanup_lynis, ensure_lynis,
                              workdir_for_cmd)
from .lynis_parser import parse_lynis_report
from .ssh_exec import HostConn, SSHExecError, ssh_exec

logger = logging.getLogger(__name__)

LYNIS_TIMEOUT = 600


@dataclass
class AuditOutcome:
    ok: bool
    findings: list
    hardening_index: Any
    meta: Dict[str, str]
    error: str = ""
    # Raw Lynis .dat report, captured for --verbose; never streamed on its own.
    raw: str = ""


def _lynis_prefix(privilege: str) -> str:
    if privilege == "root":
        return ""
    if privilege == "nopasswd_sudo":
        return "sudo -n "
    return ""


def _absent_kernel_modules(conn, prefix: str) -> set:
    """Return probed modules absent on this kernel; empty set on failure keeps every finding."""
    probed = ("dccp", "sctp", "rds", "tipc", "usb-storage")
    checks = "; ".join(
        f'{prefix}modprobe -n -v {m} >/dev/null 2>&1 && echo "OK {m}" || echo "ABSENT {m}"'
        for m in probed
    )
    try:
        res = ssh_exec(conn, checks, timeout=45)
    except SSHExecError:
        logger.warning("audit_host: kernel module probe failed; keeping all findings")
        return set()
    absent = set()
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "ABSENT":
            absent.add(parts[1])
    return absent


def detect_privilege(conn) -> str:
    """Probe the privilege actually held on the target: root, nopasswd_sudo or none."""
    try:
        r = ssh_exec(
            conn,
            "id -u; sudo -n true 2>/dev/null && echo SUDO_OK || echo SUDO_NO",
            timeout=30,
        )
    except SSHExecError:
        return "none"
    out = (r.stdout or "").split()
    uid = out[0] if out else ""
    if uid == "0":
        return "root"
    if "SUDO_OK" in (r.stdout or ""):
        return "nopasswd_sudo"
    return "none"


def audit_host(conn: HostConn, privilege: str = "auto") -> AuditOutcome:
    """Run a Lynis audit on `conn`; `privilege` is downgraded to what the probe finds. Never raises: returns ok=False with a scrubbed error."""
    report_path = f"/tmp/narvy_host_audit_{uuid.uuid4().hex[:12]}.dat"

    detected = detect_privilege(conn)
    if privilege == "auto":
        privilege = detected
    elif privilege != detected:
        logger.info("audit_host: privilege %r requested, %r detected, using "
                    "detected", privilege, detected)
        privilege = detected
    prefix = _lynis_prefix(privilege)

    try:
        lynis_cmd, ephemeral = ensure_lynis(conn, prefix)
    except SSHExecError as exc:
        return AuditOutcome(False, [], None, {}, f"ssh_connect_failed: {exc}")
    except LynisBootstrapError as exc:
        return AuditOutcome(False, [], None, {}, f"lynis_unavailable: {exc}")

    # umask 077 keeps the report 0600 on the target.
    run_cmd = (
        f"umask 077; {prefix}{lynis_cmd} audit system --quick --no-colors "
        f"--report-file {report_path} >/dev/null 2>&1; echo RC=$?"
    )
    dat = ""
    run_tail = ""
    try:
        try:
            run = ssh_exec(conn, run_cmd, timeout=LYNIS_TIMEOUT)
            run_tail = (run.stdout or "").strip()[-40:]
        except SSHExecError as exc:
            return AuditOutcome(False, [], None, {}, f"lynis_run_failed: {exc}")

        try:
            cat = ssh_exec(conn, f"{prefix}cat {report_path} 2>/dev/null", timeout=60)
            dat = cat.stdout or ""
        except SSHExecError as exc:
            return AuditOutcome(False, [], None, {}, f"report_read_failed: {exc}")
    finally:
        try:
            ssh_exec(conn, f"{prefix}rm -f {report_path}", timeout=30)
        except SSHExecError:
            logger.warning("audit_host: could not remove remote report %s",
                           report_path)
        if ephemeral:
            wd = workdir_for_cmd(lynis_cmd)
            if wd:
                cleanup_lynis(conn, wd)

    if "hardening_index=" not in dat and "warning[]=" not in dat:
        return AuditOutcome(
            False, [], None, {},
            f"empty_or_invalid_report (lynis {run_tail}); "
            f"privilege={privilege} may be insufficient")

    # Lynis reports modules the kernel lacks, so confirm existence first.
    absent_modules = _absent_kernel_modules(conn, prefix)

    parsed = parse_lynis_report(dat, absent_modules=absent_modules)

    narvy_findings: list = []
    try:
        from .narvy_checks import run_narvy_host_checks
        narvy_findings = run_narvy_host_checks(conn, prefix)
    except Exception:  # noqa: BLE001
        logger.warning("audit_host: narvy host checks failed; continuing with "
                       "Lynis baseline findings only", exc_info=True)

    meta = dict(parsed["meta"])
    meta["audit_privilege"] = privilege
    meta["coverage"] = "partial" if privilege == "none" else "full"
    meta["scan_engine"] = (
        "Narvy internal host checks + Lynis (GPL-3.0) hardening baseline, "
        "orchestrated by Narvy")
    return AuditOutcome(
        ok=True,
        findings=list(parsed["findings"]) + list(narvy_findings),
        hardening_index=parsed["hardening_index"],
        meta=meta,
        raw=dat,
    )
