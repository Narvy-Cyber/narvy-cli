"""Recognize report files written by narvy itself, so a re-run never scans them."""
import json
import os
from typing import Dict, Optional, Set

# A real report of ours is far below this; bigger files are left to the rules.
_MAX_REPORT_BYTES = 256 * 1024 * 1024

_output_path: Optional[str] = None
_cache: Dict[str, bool] = {}
# Report files whose findings were dropped this run, for the end-of-scan note.
SKIPPED: Set[str] = set()


def set_output_path(path: Optional[str]) -> None:
    """The --file target of this run: whatever it holds now gets overwritten."""
    global _output_path
    _output_path = os.path.realpath(path) if path and path != "-" else None


def _has_narvy_marker(data) -> bool:
    if not isinstance(data, dict):
        return False
    tool = data.get("tool")
    if isinstance(tool, str) and tool.startswith("Narvy"):
        return True
    runs = data.get("runs")
    if isinstance(runs, list) and runs:
        for run in runs:
            tool = run.get("tool") if isinstance(run, dict) else None
            driver = tool.get("driver") if isinstance(tool, dict) else None
            name = driver.get("name") if isinstance(driver, dict) else None
            if not (isinstance(name, str) and name.startswith("Narvy")):
                return False
        return True
    return False


def is_own_report(path: str) -> bool:
    """True for this run's --file target or a JSON/SARIF report narvy wrote."""
    try:
        real = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    if _output_path and real == _output_path:
        return True
    if real in _cache:
        return _cache[real]
    result = False
    try:
        if os.path.isfile(real) and os.path.getsize(real) <= _MAX_REPORT_BYTES:
            with open(real, "rb") as f:
                if f.read(256).lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{"):
                    f.seek(0)
                    result = _has_narvy_marker(json.load(f))
    except (OSError, ValueError, RecursionError):
        result = False
    _cache[real] = result
    return result


def drop_own_reports(findings, target_dir: str):
    """Findings minus those inside narvy report files, for a source-directory scan."""
    kept = []
    for f in findings:
        fp = f.get("file_path") or ""
        full = fp if os.path.isabs(fp) else os.path.join(target_dir, fp)
        if fp and is_own_report(full):
            SKIPPED.add(os.path.relpath(full, target_dir))
        else:
            kept.append(f)
    return kept
