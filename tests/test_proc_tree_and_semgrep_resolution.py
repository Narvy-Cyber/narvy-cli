"""run_tree must not orphan grandchildren; semgrep must be found without the venv on PATH."""
import os
import subprocess
import sys
import tempfile
import time
from unittest import mock

import pytest

from narvy import semgrep_engine
from narvy.proc import run_tree

POSIX = os.name == "posix"


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie reparented to init still answers kill(0); check its state.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split()[2] != "Z"
    except OSError:
        return True


@pytest.mark.skipif(not POSIX, reason="process groups are POSIX-only")
def test_timeout_kills_grandchild():
    with tempfile.TemporaryDirectory() as d:
        pidfile = os.path.join(d, "gc.pid")
        # The child spawns a long-lived grandchild (like pysemgrep -> semgrep-core), then waits.
        script = (
            "import subprocess,sys,time;"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
            f"open({pidfile!r},'w').write(str(p.pid));time.sleep(60)"
        )
        with pytest.raises(subprocess.TimeoutExpired):
            run_tree([sys.executable, "-c", script], timeout=3)
        gc = int(open(pidfile).read())
        deadline = time.time() + 15
        while _alive(gc) and time.time() < deadline:
            time.sleep(0.1)
        assert not _alive(gc), "grandchild survived the timeout (orphaned worker)"


@pytest.mark.skipif(not POSIX, reason="process groups are POSIX-only")
def test_timeout_kills_worker_that_ignores_sigterm():
    # Leader exits on SIGTERM, the worker ignores it (seen with semgrep-core).
    with tempfile.TemporaryDirectory() as d:
        pidfile = os.path.join(d, "gc.pid")
        worker = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
        script = (
            "import subprocess,sys,time;"
            f"p=subprocess.Popen([sys.executable,'-c',{worker!r}]);"
            f"open({pidfile!r},'w').write(str(p.pid));time.sleep(60)"
        )
        with pytest.raises(subprocess.TimeoutExpired):
            run_tree([sys.executable, "-c", script], timeout=3)
        gc = int(open(pidfile).read())
        deadline = time.time() + 1
        while _alive(gc) and time.time() < deadline:
            time.sleep(0.05)
        assert not _alive(gc), "worker ignoring SIGTERM outlived run_tree"


def test_normal_run_returns_output_and_rc():
    r = run_tree([sys.executable, "-c", "import sys;print('hi');sys.exit(3)"], timeout=30)
    assert r.returncode == 3
    assert r.stdout.strip() == "hi"


def test_check_raises_called_process_error():
    with pytest.raises(subprocess.CalledProcessError):
        run_tree([sys.executable, "-c", "import sys;sys.exit(2)"], timeout=30, check=True)


def test_semgrep_found_next_to_interpreter_when_not_on_path(tmp_path):
    """pipx / un-activated venv: only the `narvy` shim is on PATH."""
    fake = tmp_path / ("semgrep.exe" if os.name == "nt" else "semgrep")
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    with mock.patch.object(semgrep_engine.sys, "executable", str(tmp_path / "python")), \
         mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
        assert semgrep_engine.semgrep_bin() == str(fake)
        assert semgrep_engine.is_available()


def test_sibling_semgrep_preferred_over_path(tmp_path):
    """The pinned copy in narvy's own env wins over an unrelated semgrep on PATH."""
    venv_bin = tmp_path / "venv"
    other = tmp_path / "other"
    venv_bin.mkdir()
    other.mkdir()
    for d in (venv_bin, other):
        f = d / "semgrep"
        f.write_text("#!/bin/sh\n")
        f.chmod(0o755)
    with mock.patch.object(semgrep_engine.sys, "executable", str(venv_bin / "python")), \
         mock.patch.dict(os.environ, {"PATH": str(other)}):
        assert semgrep_engine.semgrep_bin() == str(venv_bin / "semgrep")


def test_semgrep_env_disables_version_check_and_metrics(monkeypatch):
    # The version check blocks for ~100s when semgrep.dev is unreachable.
    monkeypatch.setenv("SEMGREP_ENABLE_VERSION_CHECK", "1")
    env = semgrep_engine.semgrep_env()
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert env["SEMGREP_SEND_METRICS"] == "off"
