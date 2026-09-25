"""Load `.narvy-scope.yml` (own/vendor overrides). Never raises; a bad file gives EMPTY."""
from __future__ import annotations

import os
import sys
from typing import Dict, FrozenSet, NamedTuple, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

SCOPE_CONFIG_FILENAME = ".narvy-scope.yml"
SCOPE_CONFIG_FILENAMES = (SCOPE_CONFIG_FILENAME,)

MAX_ENTRIES_PER_LIST = 500


class ScopeConfig(NamedTuple):
    """Validated config: lower-cased patterns, exact unless they end in `*`."""
    own: FrozenSet[str] = frozenset()
    vendor: FrozenSet[str] = frozenset()
    reasons: Dict[str, str] = {}
    source_path: Optional[str] = None

    def __bool__(self) -> bool:
        return bool(self.own) or bool(self.vendor)


EMPTY = ScopeConfig()


def _warn(msg: str) -> None:
    print(f"[narvy] WARNING: {msg}", file=sys.stderr)


def entry_matches(entry: str, candidate: str) -> bool:
    """Match an undelimited token: exact, or prefix if entry ends in '*'. Args lower-cased."""
    if entry.endswith("*"):
        return candidate.startswith(entry[:-1])
    return candidate == entry


def segment_prefix_match(entry: str, candidate: str, delimiter: str = ".") -> bool:
    """Whole-segment prefix match for delimiter-separated identifiers. Args lower-cased."""
    e = entry[:-1] if entry.endswith("*") else entry
    e = e.rstrip(delimiter)
    if not e:
        return False
    entry_segs = e.split(delimiter)
    cand_segs = candidate.split(delimiter)
    return cand_segs[:len(entry_segs)] == entry_segs


def find_scope_config_path(target_path: str) -> Optional[str]:
    """First `.narvy-scope.yml` in the cwd, then next to target_path."""
    target_dir = target_path if os.path.isdir(target_path) else os.path.dirname(
        os.path.abspath(target_path))
    target_dir = target_dir or "."

    # cwd is checked before the target dir.
    for base in (os.getcwd(), target_dir):
        for name in SCOPE_CONFIG_FILENAMES:
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _parse_entry(item, key: str, path: str):
    """Return (name, reason) for one list item, or None if it is malformed."""
    if isinstance(item, str):
        name = item.strip()
        if not name:
            _warn(f"{path}: '{key}' contains an empty string entry - skipping it.")
            return None
        return name.lower(), None
    if isinstance(item, dict):
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            _warn(f"{path}: '{key}' has a mapping entry with no valid 'name' "
                  f"({item!r}) - skipping it.")
            return None
        reason = item.get("reason")
        reason = reason.strip() if isinstance(reason, str) and reason.strip() else None
        return name.strip().lower(), reason
    _warn(f"{path}: '{key}' contains an entry that is neither a string nor a "
          f"{{name, reason}} mapping ({item!r}) - skipping it.")
    return None


def _as_pattern_list(data: dict, key: str, path: str):
    """(name, reason) tuples in file order, or None if data[key] is malformed."""
    val = data.get(key)
    if val is None:
        return []
    if not isinstance(val, list):
        _warn(f"{path}: '{key}' should be a YAML list, got "
              f"{type(val).__name__} - ignoring this config file, continuing "
              f"with no overrides.")
        return None
    if len(val) > MAX_ENTRIES_PER_LIST:
        _warn(f"{path}: '{key}' has {len(val)} entries, more than the "
              f"{MAX_ENTRIES_PER_LIST} cap - using only the first "
              f"{MAX_ENTRIES_PER_LIST} (in file order).")
        val = val[:MAX_ENTRIES_PER_LIST]
    out = []
    for item in val:
        parsed = _parse_entry(item, key, path)
        if parsed is not None:
            out.append(parsed)
    return out


def _strip_star(pattern: str) -> str:
    return pattern[:-1] if pattern.endswith("*") else pattern


def _patterns_overlap(a: str, b: str) -> bool:
    """Load-time heuristic: could an own and a vendor pattern both match?"""
    sa, sb = _strip_star(a), _strip_star(b)
    return sa == sb or sa.startswith(sb) or sb.startswith(sa)


def load_scope_config(target_path: str) -> ScopeConfig:
    """Auto-detect and parse the scope config. Never raises: degrades to EMPTY."""
    path = find_scope_config_path(target_path)
    if path is None:
        return EMPTY

    if yaml is None:  # pragma: no cover
        _warn(f"found {path} but PyYAML is not installed - overrides ignored.")
        return EMPTY

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        _warn(f"could not read/parse {path} ({e.__class__.__name__}: {e}) - "
              f"continuing with no overrides.")
        return EMPTY

    if data is None:
        return EMPTY
    if not isinstance(data, dict):
        _warn(f"{path} does not look like a valid scope config (expected a "
              f"YAML mapping with 'own'/'vendor' keys, got "
              f"{type(data).__name__}) - continuing with no overrides.")
        return EMPTY

    own_entries = _as_pattern_list(data, "own", path)
    vendor_entries = _as_pattern_list(data, "vendor", path)
    if own_entries is None or vendor_entries is None:
        return EMPTY

    own_names = {name for name, _ in own_entries}
    vendor_names = {name for name, _ in vendor_entries}

    # Identical entry in both lists: ambiguous, drop from both.
    conflicts = own_names & vendor_names
    if conflicts:
        plural = len(conflicts) != 1
        _warn(
            f"{path}: entr{'ies' if plural else 'y'} "
            f"{', '.join(sorted(conflicts))!r} listed in BOTH 'own' and "
            f"'vendor' - ambiguous, falling back to automatic classification "
            f"for {'them' if plural else 'it'}."
        )
        own_names -= conflicts
        vendor_names -= conflicts

    # Two patterns that could both match: warn, drop neither ('own' wins at match time).
    overlap_pairs = sorted({
        (o, v) for o in own_names for v in vendor_names if _patterns_overlap(o, v)
    })
    for o, v in overlap_pairs:
        _warn(
            f"{path}: 'own' pattern {o!r} and 'vendor' pattern {v!r} could "
            f"both match the same name - 'own' wins for anything matched by "
            f"both, per policy."
        )

    if not own_names and not vendor_names:
        return EMPTY

    reasons = {name: reason for name, reason in (own_entries + vendor_entries) if reason}
    return ScopeConfig(
        own=frozenset(own_names),
        vendor=frozenset(vendor_names),
        reasons=reasons,
        source_path=path,
    )
