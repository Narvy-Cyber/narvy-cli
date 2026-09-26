"""Run external tools in their own process group so nothing outlives narvy."""
from __future__ import annotations

import os
import signal
import subprocess
import time
from typing import List, Optional

_POSIX = os.name == "posix"


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _kill_tree(proc: subprocess.Popen) -> None:
    if not _POSIX:
        if proc.poll() is None:
            proc.kill()
    else:
        # The leader can exit on SIGTERM while its workers keep running, so wait on the group.
        pgid = proc.pid
        try:
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            proc.poll()
            if not _group_alive(pgid):
                break
            time.sleep(0.05)
        else:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_tree(cmd: List[str], timeout: Optional[float] = None, check: bool = False,
             **kwargs) -> subprocess.CompletedProcess:
    """Like subprocess.run(capture_output=True, text=True), but kills the whole process group on abort."""
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.PIPE)
    kwargs.setdefault("text", True)
    if _POSIX and "preexec_fn" not in kwargs:
        kwargs["start_new_session"] = True
    elif _POSIX:
        # preexec_fn (e.g. an rlimit setter) and a new session are compatible: wrap both.
        inner = kwargs.pop("preexec_fn")

        def _preexec(inner=inner):
            os.setsid()
            inner()
        kwargs["preexec_fn"] = _preexec
    proc = subprocess.Popen(cmd, **kwargs)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        raise subprocess.TimeoutExpired(cmd, timeout)
    except BaseException:
        _kill_tree(proc)
        raise
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=out, stderr=err)
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def install_termination_handlers() -> None:
    """Route SIGTERM/SIGHUP through the Ctrl-C path so child cleanup runs."""
    def _raise(signum, frame):
        raise KeyboardInterrupt()
    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _raise)
        except (ValueError, OSError):
            pass
