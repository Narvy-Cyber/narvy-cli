"""One canonical spelling for a scan root, so path filters and reported paths agree.

The same directory can have several spellings: a Windows 8.3 short name
(C:\\Users\\RUNNER~1\\...), a symlink or junction, a relative path. semgrep
resolves the scan root to its physical path to find the project root and
evaluates --include/--exclude globs against paths relative to that root; a
symlinked scan root is not followed at all (0 files scanned). Handing every
tool the same canonical path, and computing our own relative paths against
it, removes that whole class of mismatch.
"""
from __future__ import annotations

import os

_IS_WINDOWS = os.name == "nt"


def _long_path_name(path: str) -> str:
    """Expand 8.3 short components (RUNNER~1 -> runneradmin). Windows only; else unchanged."""
    if not _IS_WINDOWS or "~" not in path:
        return path
    try:
        import ctypes
        from ctypes import wintypes

        fn = ctypes.windll.kernel32.GetLongPathNameW
        fn.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        fn.restype = wintypes.DWORD
        size = fn(path, None, 0)
        if not size:
            return path
        buf = ctypes.create_unicode_buffer(size)
        if not fn(path, buf, size):
            return path
        return buf.value or path
    except Exception:
        return path


def _is_unc(path: str) -> bool:
    return path.startswith("\\\\") or path.startswith("//")


def canonical_path(path: str) -> str:
    """Absolute, long-name, symlink-resolved spelling of an existing path.

    Falls back to the absolute long-name form when resolving fails, and on
    Windows never swaps a drive-letter path for a UNC one (mapped drives).
    """
    if not path:
        return path
    absolute = _long_path_name(os.path.abspath(path))
    try:
        resolved = os.path.realpath(absolute)
    except (OSError, ValueError):
        return absolute
    resolved = _long_path_name(resolved)
    if _IS_WINDOWS and _is_unc(resolved) and not _is_unc(absolute):
        return absolute
    return resolved
