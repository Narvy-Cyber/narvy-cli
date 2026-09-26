"""Anonymous usage telemetry: one small event per command, sent in the background.

Off with `narvy telemetry off`, NARVY_TELEMETRY=0 or DO_NOT_TRACK=1.
"""
from __future__ import annotations

import json
import os
import platform
import sys
import threading
import uuid
from typing import Any, Dict, Iterable, Optional

from narvy import __version__

ENDPOINT = (os.environ.get("NARVY_URL") or "https://narvy.io").rstrip("/") + "/api/v1/telemetry"
TIMEOUT_S = 1.0
SCHEMA_VERSION = 1

CONFIG_DIR = os.path.expanduser("~/.narvy")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

COMMANDS = frozenset({
    "scan", "web-scan", "host-audit", "cloud-scan", "login", "logout", "scans",
    "doctor", "init-ci", "upload-all",
})
SURFACES = frozenset({"android", "ios", "web", "source", "host", "cloud", "none"})
SEVERITIES = ("critical", "high", "medium", "low", "info")

_CI_ENV_VARS = (
    "CI", "GITHUB_ACTIONS", "GITLAB_CI", "BITBUCKET_BUILD_NUMBER", "JENKINS_URL",
    "BUILDKITE", "CIRCLECI", "TF_BUILD", "TEAMCITY_VERSION", "DRONE",
)

NOTICE = (
    "Narvy CLI sends anonymous usage statistics: a random install id, the CLI, "
    "Python and OS versions, the command and scan type, rounded duration and "
    "finding counts, and the exit code. Never code, file or project names, paths, "
    "URLs, hosts, findings or account details. Turn it off with `narvy telemetry "
    "off`, NARVY_TELEMETRY=0 or DO_NOT_TRACK=1."
)

# Filled by the running command (surface, findings); read when the event is built.
_context: Dict[str, Any] = {}
_thread: Optional[threading.Thread] = None


# ---------------------------------------------------------------- config

def _load_config() -> Dict[str, Any]:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_config(cfg: Dict[str, Any]) -> bool:
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, CONFIG_PATH)
        return True
    except OSError:
        return False


def set_enabled(enabled: bool) -> bool:
    cfg = _load_config()
    cfg["telemetry"] = bool(enabled)
    return _save_config(cfg)


def _env_off() -> Optional[str]:
    """Name of the environment variable that disables telemetry, if any."""
    val = os.environ.get("NARVY_TELEMETRY", "").strip().lower()
    if val in ("0", "false", "off", "no"):
        return "NARVY_TELEMETRY"
    dnt = os.environ.get("DO_NOT_TRACK", "").strip().lower()
    if dnt and dnt not in ("0", "false", "no"):
        return "DO_NOT_TRACK"
    return None


def status() -> Dict[str, Any]:
    """Whether telemetry is on, and why."""
    env = _env_off()
    if env:
        return {"enabled": False, "reason": f"disabled by the {env} environment variable"}
    if _load_config().get("telemetry") is False:
        return {"enabled": False, "reason": f"disabled in {CONFIG_PATH}"}
    return {"enabled": True, "reason": "enabled (default)"}


def is_enabled() -> bool:
    return status()["enabled"]


def install_id() -> Optional[str]:
    """Random id created on first use. Not derived from the machine or the user."""
    cfg = _load_config()
    iid = cfg.get("install_id")
    try:
        if iid and uuid.UUID(str(iid)).version == 4:
            return str(iid)
    except ValueError:
        pass
    iid = str(uuid.uuid4())
    cfg["install_id"] = iid
    return iid if _save_config(cfg) else None


# ---------------------------------------------------------------- event

def note(surface: Optional[str] = None, findings: Optional[Iterable[Dict[str, Any]]] = None,
         get_severity=lambda f: f.get("severity")) -> None:
    """Called by a command once it knows what it scanned and what it found."""
    if surface is not None:
        _context["surface"] = surface if surface in SURFACES else "none"
    if findings is not None:
        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            try:
                sev = str(get_severity(f) or "").strip().lower()
            except Exception:
                sev = ""
            if sev in counts:
                counts[sev] += 1
        _context["findings"] = counts


def surface_for_scan_mode(scan_mode: str) -> str:
    if scan_mode in ("android", "android-bundle"):
        return "android"
    if scan_mode == "ios-binary":
        return "ios"
    if scan_mode in ("android-source", "ios-source", "web-source"):
        return "source"
    return "none"


def _count_bucket(n: int) -> str:
    if n <= 0:
        return "0"
    if n <= 5:
        return "1-5"
    if n <= 20:
        return "6-20"
    if n <= 100:
        return "21-100"
    if n <= 500:
        return "101-500"
    return ">500"


def _duration_bucket(seconds: float) -> str:
    if seconds < 10:
        return "<10s"
    if seconds < 60:
        return "10s-1m"
    if seconds < 300:
        return "1-5m"
    if seconds < 900:
        return "5-15m"
    if seconds < 3600:
        return "15-60m"
    return ">60m"


def _os_family() -> str:
    s = platform.system().lower()
    if s in ("linux", "darwin", "windows"):
        return s
    return "other"


def _is_ci() -> bool:
    return any(os.environ.get(v, "").strip() not in ("", "0", "false") for v in _CI_ENV_VARS)


def _error_class(exc: Optional[BaseException]) -> Optional[str]:
    if exc is None or isinstance(exc, SystemExit):
        return None
    name = type(exc).__name__
    return name if name.isidentifier() and len(name) <= 64 else "Exception"


def build_event(command: str, duration_s: float, exit_code: int,
                exc: Optional[BaseException] = None) -> Optional[Dict[str, Any]]:
    iid = install_id()
    if iid is None or command not in COMMANDS:
        return None
    counts = _context.get("findings") or {s: 0 for s in SEVERITIES}
    try:
        code = int(exit_code)
    except (TypeError, ValueError):
        code = 1
    return {
        "schema": SCHEMA_VERSION,
        "install_id": iid,
        "cli_version": __version__,
        "python_version": f"{sys.version_info[0]}.{sys.version_info[1]}",
        "os": _os_family(),
        "ci": _is_ci(),
        "command": command,
        "surface": _context.get("surface", "none"),
        "duration_bucket": _duration_bucket(duration_s),
        "findings": {s: _count_bucket(int(counts.get(s, 0))) for s in SEVERITIES},
        "exit_code": max(0, min(255, code)),
        "error_class": _error_class(exc),
    }


# ---------------------------------------------------------------- sending

def _post(event: Dict[str, Any]) -> None:
    try:
        import requests
        requests.post(ENDPOINT, json=event, timeout=TIMEOUT_S)
    except Exception:
        pass


def _run(event: Dict[str, Any]) -> None:
    try:
        _post(event)
    except Exception:
        pass


def maybe_show_notice(out=None) -> None:
    """Print the first-run notice once (stderr), then remember it was shown."""
    if not is_enabled():
        return
    cfg = _load_config()
    if cfg.get("telemetry_notice_shown"):
        return
    try:
        (out or sys.stderr).write(NOTICE + "\n")
    except Exception:
        return
    cfg["telemetry_notice_shown"] = True
    _save_config(cfg)


def send(command: str, duration_s: float, exit_code: int,
         exc: Optional[BaseException] = None) -> None:
    """Fire and forget. Any failure is swallowed."""
    global _thread
    try:
        if not is_enabled():
            return
        event = build_event(command, duration_s, exit_code, exc)
        if event is None:
            return
        _thread = threading.Thread(target=_run, args=(event,), daemon=True)
        _thread.start()
    except Exception:
        pass


def flush(max_wait_s: float = TIMEOUT_S) -> None:
    """At exit, give the in-flight POST at most its own timeout to finish."""
    t = _thread
    if t is not None and t.is_alive():
        t.join(max_wait_s)
