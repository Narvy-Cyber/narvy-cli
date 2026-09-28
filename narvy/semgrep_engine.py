"""Run semgrep over the jadx output for the Android rule pack."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

import yaml

from .proc import run_tree

from .third_party_filter import THIRD_PARTY_PREFIXES
from .scope_config import ScopeConfig
from . import weak_prng_context

RULES_PATH = os.path.join(os.path.dirname(__file__), 'rules', 'android.yml')
# Third-party prefixes as --exclude globs; leading '**/' de-anchors from the scan root.
_EXCLUDE_ARGS = []
for _p in THIRD_PARTY_PREFIXES:
    _EXCLUDE_ARGS += ['--exclude', f"**/{_p.replace('.', '/').rstrip('/')}/**"]

SEVERITY_MAP = {
    'ERROR': 'CRITICAL',
    'WARNING': 'HIGH',
    'INFO': 'MEDIUM',
}

# Whole-run timeout scales with tree size; a timeout is recorded in LAST_RUN.
SEMGREP_BASE_TIMEOUT_SEC = 600
SEMGREP_MAX_TIMEOUT_SEC = 1800
SEMGREP_TIMEOUT_PER_1K_FILES = 120

# Callers read this to tell "0 findings" apart from "never finished".
LAST_RUN: Dict[str, Any] = {
    'status': 'not_run',      # ok | timeout | error | unavailable | not_run
    'timeout_s': None,
    'file_count': None,
    'degraded': False,
    'message': None,
}


def count_source_files(source_dir: str) -> int:
    """Cheap file count used to size the semgrep timeout."""
    skip = {'.git', 'node_modules', 'build', '.gradle', '.idea', 'Pods',
            'Carthage', '__pycache__', '.venv', 'venv', 'DerivedData'}
    n = 0
    try:
        for dirpath, dirnames, filenames in os.walk(source_dir):
            dirnames[:] = [d for d in dirnames if d not in skip]
            n += len(filenames)
    except OSError:
        return 0
    return n


def compute_semgrep_timeout(source_dir: str,
                            base: int = SEMGREP_BASE_TIMEOUT_SEC) -> int:
    """Scale the whole-run timeout with tree size. Never below `base`."""
    return compute_semgrep_timeout_for_count(count_source_files(source_dir), base)


def compute_semgrep_timeout_for_count(files: int,
                                      base: int = SEMGREP_BASE_TIMEOUT_SEC) -> int:
    env_to = os.environ.get('NARVY_SEMGREP_TIMEOUT', '').strip()
    if env_to.isdigit():
        return int(env_to)
    if files < 2000:
        return base
    extra = ((files - 2000) // 1000) * SEMGREP_TIMEOUT_PER_1K_FILES
    return min(base + extra, SEMGREP_MAX_TIMEOUT_SEC)


# Resource caps for every semgrep run. Uncapped, it uses one worker per core
# and passed 13 GB on the Linux kernel tree.
DEFAULT_MAX_JOBS = 4
# semgrep --max-memory (MiB). A file that would exceed it is skipped and
# reported as an error.
DEFAULT_MAX_MEMORY_MB = 3072


def _env_int(name: str) -> Optional[int]:
    raw = os.environ.get(name, '').strip()
    if raw.isdigit():
        return int(raw)
    return None


def semgrep_jobs(single: bool = False) -> int:
    """semgrep worker count (NARVY_SEMGREP_JOBS overrides). `single` forces 1 for PHP."""
    if single:
        return 1
    env = _env_int('NARVY_SEMGREP_JOBS')
    if env:
        return env
    return max(1, min(DEFAULT_MAX_JOBS, os.cpu_count() or 1))


_TAINT_CACHE: Dict[str, bool] = {}


def config_has_taint(path: str) -> bool:
    """True when a rule file holds a `mode: taint` rule (unreadable = True).

    semgrep with more than one worker drops taint results at random, with no
    error in its output, so such configs always run with one worker.
    """
    key = os.path.abspath(path)
    if key not in _TAINT_CACHE:
        try:
            with open(key, 'r', encoding='utf-8', errors='ignore') as fh:
                _TAINT_CACHE[key] = bool(re.search(r'(?m)^\s*mode:\s*taint\b', fh.read()))
        except OSError:
            _TAINT_CACHE[key] = True
    return _TAINT_CACHE[key]


def semgrep_max_memory_mb() -> int:
    """NARVY_SEMGREP_MAX_MEMORY_MB overrides; 0 disables the ceiling."""
    env = _env_int('NARVY_SEMGREP_MAX_MEMORY_MB')
    return DEFAULT_MAX_MEMORY_MB if env is None else env


def resource_args(jobs: int) -> List[str]:
    return ['--jobs', str(jobs), '--max-memory', str(semgrep_max_memory_mb())]


def _record_run(status: str, timeout_s: Optional[int] = None,
                file_count: Optional[int] = None,
                message: Optional[str] = None) -> None:
    LAST_RUN.update({
        'status': status,
        'timeout_s': timeout_s,
        'file_count': file_count,
        'degraded': status in ('timeout', 'error'),
        'message': message,
    })


def degraded_coverage_note() -> Optional[str]:
    """User-facing sentence when the last pass did not complete, else None."""
    if not LAST_RUN.get('degraded'):
        return None
    if LAST_RUN.get('status') == 'timeout':
        return (
            "The regex, taint and SCA passes completed here with full results. "
            f"The deep structural (Semgrep) pass is time-bounded to "
            f"{LAST_RUN.get('timeout_s')}s locally and this target is large "
            f"({LAST_RUN.get('file_count')} files); the hosted engine runs that "
            "pass to completion with no local time budget - use `narvy scan "
            "--upload` for the full structural pass, or raise "
            "NARVY_SEMGREP_TIMEOUT / narrow the path to finish it locally."
        )
    return (
        "The regex, taint and SCA passes completed here with full results. The "
        "deep structural (Semgrep) pass runs to completion on the hosted engine "
        f"({LAST_RUN.get('message')}) - use `narvy scan --upload` for it."
    )


def semgrep_bin() -> Optional[str]:
    """Path to semgrep, preferring the copy next to this interpreter (pipx/venv), or None."""
    exe = 'semgrep.exe' if os.name == 'nt' else 'semgrep'
    # pip installed semgrep next to narvy: in the interpreter's Scripts/bin, or,
    # for `pip install --user`, the user Scripts/bin (%APPDATA%\Python\Python3xx\Scripts,
    # ~/Library/Python/3.x/bin, ~/.local/bin), which is often not on PATH. Run as
    # `python -m narvy`, the PATH lookup alone missed it and the code pass was skipped.
    from .pathhint import _candidate_script_dirs
    dirs = [os.path.dirname(sys.executable or '')]
    try:
        dirs += _candidate_script_dirs()
    except Exception:
        pass
    for d in dirs:
        if not d:
            continue
        cand = os.path.join(d, exe)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which('semgrep')


def semgrep_env() -> Dict[str, str]:
    """Environment for semgrep runs: no version check and no metrics (both call out to semgrep.dev)."""
    env = os.environ.copy()
    env['SEMGREP_ENABLE_VERSION_CHECK'] = '0'
    env['SEMGREP_SEND_METRICS'] = 'off'
    # semgrep is Python: on Windows it would write its JSON in the console code page.
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    # semgrep (osemgrep) execs `pysemgrep` through PATH; when semgrep sits in a
    # Scripts/bin dir that is not on PATH, it fails with "execvp pysemgrep".
    bin_path = semgrep_bin()
    if bin_path:
        bin_dir = os.path.dirname(bin_path)
        parts = env.get('PATH', '').split(os.pathsep) if env.get('PATH') else []
        if bin_dir and os.path.normcase(bin_dir) not in {os.path.normcase(p) for p in parts}:
            env['PATH'] = os.pathsep.join([bin_dir] + parts)
    return env


def is_available() -> bool:
    return semgrep_bin() is not None


def load_rule_defs(rules_path: str = RULES_PATH) -> List[Dict[str, Any]]:
    """Synthesize a rule-def dict per rule id in the YAML pack, for SARIF."""
    try:
        with open(rules_path, 'r') as f:
            data = yaml.safe_load(f)
    except OSError:
        return []
    defs = []
    for rule in (data or {}).get('rules', []):
        meta = rule.get('metadata', {}) or {}
        defs.append({
            'id': rule['id'],
            'name': rule.get('message', rule['id'])[:120],
            'severity': SEVERITY_MAP.get(rule.get('severity', 'INFO'), 'MEDIUM'),
            'details': {
                'cwe': meta.get('cwe', ''),
                'masvs': meta.get('masvs', ''),
                'description': rule.get('message', ''),
                'recommendation': rule.get('message', ''),
            },
        })
    return defs


def _attempt(cmd: List[str], timeout: int):
    """One semgrep run: (status, data, message). Raises TimeoutExpired."""
    proc = run_tree(cmd, timeout=timeout, env=semgrep_env())
    if not proc.stdout:
        if proc.returncode not in (0, 1):
            return 'error', None, _rc_message(proc)
        return 'ok', {'results': []}, None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return 'error', None, "semgrep output was not valid JSON"
    if not isinstance(data, dict):
        return 'error', None, "semgrep output was not valid JSON"
    if proc.returncode not in (0, 1) and not data.get('results'):
        # Exit 2+ with a JSON body is a fatal error (bad config, crash), not a clean pass.
        errs = [e.get('message') or e.get('type') for e in data.get('errors') or []
                if isinstance(e, dict)]
        detail = next((str(e) for e in errs if e), None)
        return 'error', None, _rc_message(proc, detail)
    return 'ok', data, None


def _rc_message(proc, detail: Optional[str] = None) -> str:
    text = detail or (proc.stderr or '').strip()
    text = ' '.join(str(text).split())[:200]
    return f"semgrep exited rc={proc.returncode}" + (f": {text}" if text else "")


def _scanned_nothing(data: Optional[Dict[str, Any]]) -> bool:
    paths = (data or {}).get('paths')
    return isinstance(paths, dict) and 'scanned' in paths and not paths['scanned']


def _count_own_code_files(source_dir: str, own_roots) -> int:
    from .third_party_filter import is_own_package_path
    n = 0
    for dirpath, _dirs, files in os.walk(source_dir):
        for f in files:
            if f.endswith(('.java', '.kt')) and is_own_package_path(
                    os.path.relpath(os.path.join(dirpath, f), source_dir), own_roots):
                n += 1
    return n


def run_semgrep(source_dir: str, timeout: Optional[int] = None,
                 own_roots: Optional[set] = None,
                 override_config: Optional[ScopeConfig] = None,
                 include_path_prefixes: Optional[List[str]] = None) -> Optional[List[Dict[str, Any]]]:
    """Run the Semgrep rule pack against source_dir; findings, or None if semgrep is unavailable. own_roots scopes --include; include_path_prefixes replaces the 'sources/' anchor."""
    if not is_available():
        _record_run('unavailable')
        return None

    file_count = count_source_files(source_dir)
    if timeout is None:
        env_to = os.environ.get('NARVY_SEMGREP_TIMEOUT', '').strip()
        timeout = (int(env_to) if env_to.isdigit()
                   else compute_semgrep_timeout(source_dir))

    override_own = {e for e in (override_config.own if override_config else ())
                     if not e.endswith('*')}
    override_vendor = {e for e in (override_config.vendor if override_config else ())
                        if not e.endswith('*')}

    if own_roots or override_own:
        scope_args = []
        prefixes = include_path_prefixes if include_path_prefixes is not None else ["sources/"]
        anchor = "**/" if include_path_prefixes is not None else ""
        for root in (set(own_roots or ()) | override_own):
            root_path = root.replace('.', '/')
            for prefix in prefixes:
                scope_args += ['--include', f"{anchor}{prefix}{root_path}/**"]
    else:
        scope_args = list(_EXCLUDE_ARGS)

    for entry in override_vendor:
        # --exclude wins over --include in semgrep's path filtering, so this
        # suppresses a vendor entry nested inside an included own_root.
        scope_args += ['--exclude', f"**/{entry.replace('.', '/')}/**"]

    def _cmd(jobs: int, scope: List[str]) -> List[str]:
        return (
            [semgrep_bin() or 'semgrep', '--config', RULES_PATH, source_dir,
             '--json', '--quiet', '--no-git-ignore', '--no-rewrite-rule-ids',
             '--timeout', '60']  # per-file timeout, not the whole run
            + resource_args(jobs)
            + scope
        )

    jobs = semgrep_jobs()
    try:
        status, data, message = _attempt(_cmd(jobs, scope_args), timeout)
        if status == 'error' and jobs > 1:
            # A crashed multi-worker run is retried once with one worker before
            # the pass is reported as incomplete.
            status, data, message = _attempt(_cmd(1, scope_args), timeout)
    except subprocess.TimeoutExpired:
        # LAST_RUN stops the caller presenting the empty list as a clean pass.
        _record_run('timeout', timeout_s=timeout, file_count=file_count)
        return []

    if status == 'ok' and own_roots and _scanned_nothing(data):
        expected = _count_own_code_files(source_dir, own_roots)
        if expected:
            # The --include globs matched none of the app's own files: say so
            # instead of reporting a clean pass over nothing.
            status, message = 'error', (
                f"the structural pass matched none of the {expected} app source files")

    if status != 'ok':
        _record_run('error', timeout_s=timeout, file_count=file_count, message=message)
        return []

    _record_run('ok', timeout_s=timeout, file_count=file_count)
    findings = []
    for r in data.get('results', []):
        rel_path = os.path.relpath(r.get('path', ''), source_dir)
        extra = r.get('extra', {})
        meta = extra.get('metadata', {})
        # Strip semgrep's dotted config namespace; our own ids never contain dots.
        check_id = r.get('check_id', 'semgrep-finding').rsplit('.', 1)[-1]
        findings.append({
            'rule_id': check_id,
            'file_path': rel_path,
            'name': extra.get('message', r.get('check_id', ''))[:120],
            'severity': SEVERITY_MAP.get(extra.get('severity', 'INFO'), 'MEDIUM'),
            'line': r.get('start', {}).get('line', 1),
            'details': {
                'cwe': meta.get('cwe', ''),
                'masvs': meta.get('masvs', ''),
                'description': extra.get('message', ''),
                'recommendation': extra.get('message', ''),
            },
            'engine': 'semgrep',
        })

    # Dedupe before grading: one source line can hold several Random calls.
    findings = weak_prng_context.dedupe_by_location(findings)
    weak_prng_context.apply(findings, source_dir)
    return findings
