"""Local OSV database: download per ecosystem, match on this machine.

The dependency check no longer sends package names anywhere. For each
ecosystem a scan needs, the CLI downloads the public OSV export of that
ecosystem (https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip,
documented at https://google.github.io/osv.dev/data/#data-dumps), turns it into
one SQLite file under ~/.cache/narvy/osv/ and answers every lookup from it.
The download request carries the ecosystem name and nothing else.

File format: the same tables as the Narvy platform's OSV mirror
(meta / vulns / entities / sources), one file per ecosystem:

  vulns(id, modified, withdrawn, data)      full OSV record, zlib-compressed JSON
  entities(eco, name, vuln_id, kind, payload, cmin, cmax)
                                            one row per matchable unit, the
                                            "AffectedVersions" entities the
                                            OSV.dev API builds at import time

Matching reproduces the OSV.dev API (go/internal/database/datastore/
vulnerability_matching.go): per-ecosystem name normalisation (PyPI PEP 503),
the coarse-version prefilter, `versions` lists compared by ecosystem equality,
ECOSYSTEM and SEMVER ranges walked with the ecosystem's version ordering
(osv_semantic: SemVer, PEP 440, Maven, RubyGems, Packagist, NuGet), GIT ranges
ignored, string matching when a version cannot be parsed, withdrawn records
never matched.

Refresh: a file older than 24 hours (NARVY_OSV_MAX_AGE_HOURS) is downloaded
again before use; `narvy db update` forces it. The new file is built next to
the old one and renamed over it, so a failed download leaves the old file in
place. With --offline nothing is downloaded.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import zipfile
import zlib
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import quote

import requests

from .. import __version__
from . import osv_semantic as sem

logger = logging.getLogger(__name__)

# 2: NuGet and crates.io names stored lower-cased.
SCHEMA_VERSION = "2"
DEFAULT_EXPORT_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
DEFAULT_MAX_AGE_HOURS = 24.0
# A copy older than this is never used: the dependency check is reported incomplete.
HARD_MAX_AGE_HOURS = 7 * 24
DOWNLOAD_TIMEOUT_SECONDS = 120
COMMIT_EVERY = 5000
# A real export is never this small; anything below is refused as truncated.
MIN_ZIP_BYTES = 22

# Ecosystems the CLI can download (the ones its scanners query).
ECOSYSTEMS = (
    "npm", "PyPI", "Go", "Maven", "Packagist", "RubyGems", "crates.io",
    "NuGet", "SwiftURL", "OSS-Fuzz",
)

_MAX_VERSIONS_PER_ENTITY = 1000
KIND_RANGE = 0
KIND_VERSIONS = 1
KIND_EMPTY = 2
_EVENT_ORDER = {"introduced": 0, "last_affected": 1, "fixed": 2, "limit": 3}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS vulns (
    id TEXT PRIMARY KEY,
    modified TEXT NOT NULL,
    withdrawn INTEGER NOT NULL DEFAULT 0,
    data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
    eco TEXT NOT NULL,
    name TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    kind INTEGER NOT NULL,
    payload TEXT NOT NULL,
    cmin TEXT NOT NULL,
    cmax TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    eco TEXT NOT NULL,
    id TEXT NOT NULL,
    modified TEXT NOT NULL,
    PRIMARY KEY (eco, id)
);
"""


class LocalDBError(Exception):
    """No usable local database for an ecosystem. `kind` is a short code."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


# ---------------------------------------------------------------------------
# Paths / config
# ---------------------------------------------------------------------------


def cache_dir() -> Path:
    raw = os.environ.get("NARVY_OSV_DB_DIR", "").strip()
    if raw:
        return Path(raw).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "narvy" / "osv"


def export_base() -> str:
    return (os.environ.get("NARVY_OSV_EXPORT_URL", "").strip() or DEFAULT_EXPORT_BASE).rstrip("/")


def max_age_hours() -> float:
    try:
        return float(os.environ.get("NARVY_OSV_MAX_AGE_HOURS", "") or DEFAULT_MAX_AGE_HOURS)
    except ValueError:
        return DEFAULT_MAX_AGE_HOURS


def _safe_name(eco: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", eco)


def db_path(eco: str, directory: Optional[Path] = None) -> Path:
    return Path(directory or cache_dir()) / ("%s.db" % _safe_name(eco))


def export_url(eco: str, base: Optional[str] = None) -> str:
    return "%s/%s/all.zip" % ((base or export_base()).rstrip("/"), quote(eco, safe=""))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Record -> entity rows (same function as the platform mirror)
# ---------------------------------------------------------------------------


# api.osv.dev matches these names case-insensitively (checked against the API).
_CASE_INSENSITIVE = {"NuGet", "crates.io"}


def normalize_name(eco: str, name: str) -> str:
    """Package name as stored and looked up: PEP 503 for PyPI, lower case for NuGet and crates.io."""
    base = sem.base_ecosystem(eco)
    if base in _CASE_INSENSITIVE:
        return name.lower()
    if sem.supports(eco):
        return sem.normalize_package_name(eco, name)
    return name


def _remove_variants(eco: str) -> str:
    if eco.startswith("Ubuntu"):
        return eco.replace(":Pro", "").replace(":LTS", "")
    return ""


def _event_of(e: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    for t in ("introduced", "last_affected", "fixed", "limit"):
        v = e.get(t)
        if v:
            return t, str(v)
    return None


def sort_events(eco: str, events: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """By version then event type; by (string, type) if a version does not parse."""
    if not sem.supports(eco):
        return list(events)
    try:
        parsed = [(sem.parse(eco, v), t, v) for t, v in events]
    except (sem.InvalidVersion, ValueError):
        return sorted(events, key=lambda tv: (tv[1], _EVENT_ORDER[tv[0]]))

    def _cmp(a, b):
        c = sem.compare(a[0], b[0])
        if c:
            return c
        return _EVENT_ORDER[a[1]] - _EVENT_ORDER[b[1]]

    try:
        parsed.sort(key=cmp_to_key(_cmp))
    except ValueError:
        return sorted(events, key=lambda tv: (tv[1], _EVENT_ORDER[tv[0]]))
    return [(t, v) for _, t, v in parsed]


def _coarse_or(eco: str, v: str) -> Optional[str]:
    if not sem.supports(eco):
        return None
    try:
        return sem.coarse(eco, v)
    except (sem.InvalidVersion, ValueError):
        return None


def compute_entities(record: Dict[str, Any], only_ecosystems: Optional[Iterable[str]] = None
                     ) -> List[Tuple[str, str, str, int, str, str, str]]:
    """Rows (eco, name, vuln_id, kind, payload_json, cmin, cmax) for a record."""
    vid = str(record.get("id") or "")
    keep = set(only_ecosystems) if only_ecosystems is not None else None
    rows: List[Tuple[str, str, str, int, str, str, str]] = []
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        pkg_eco = str(pkg.get("ecosystem") or "")
        if not pkg_eco:
            continue
        ecos = {pkg_eco, pkg_eco.split(":", 1)[0]}
        rv = _remove_variants(pkg_eco)
        if rv:
            ecos.add(rv)
        ecos_l = sorted(ecos)
        if keep is not None:
            ecos_l = [e for e in ecos_l if e in keep or e.split(":", 1)[0] in keep]
            if not ecos_l:
                continue
        helper = sem.supports(pkg_eco)
        name = normalize_name(pkg_eco, str(pkg.get("name") or ""))
        has_affected = False
        for r in affected.get("ranges") or []:
            rtype = str(r.get("type") or "").upper()
            if rtype not in ("ECOSYSTEM", "SEMVER"):
                continue
            raw_events = r.get("events") or []
            if not raw_events:
                continue
            has_affected = True
            events = [ev for ev in (_event_of(e) for e in raw_events) if ev]
            if helper:
                events = sort_events(pkg_eco, events)
            cmin, cmax = sem.COARSE_MIN, sem.COARSE_MAX
            if helper:
                for t, v in events:
                    if t == "introduced":
                        c = _coarse_or(pkg_eco, v)
                        if c is not None:
                            cmin = c
                        lt, lv = events[-1]
                        if lt != "introduced":
                            c = _coarse_or(pkg_eco, lv)
                            if c is not None:
                                cmax = c
                        break
            payload = json.dumps(events, separators=(",", ":"))
            for e in ecos_l:
                rows.append((e, name, vid, KIND_RANGE, payload, cmin, cmax))
        versions = [str(v) for v in (affected.get("versions") or [])]
        if name and versions:
            has_affected = True
            for i in range(0, len(versions), _MAX_VERSIONS_PER_ENTITY):
                chunk = versions[i:i + _MAX_VERSIONS_PER_ENTITY]
                cmin, cmax = sem.COARSE_MIN, sem.COARSE_MAX
                if helper:
                    cs = sorted(c for c in (_coarse_or(pkg_eco, v) for v in chunk) if c is not None)
                    if cs:
                        cmin, cmax = cs[0], cs[-1]
                payload = json.dumps(chunk, separators=(",", ":"))
                for e in ecos_l:
                    rows.append((e, name, vid, KIND_VERSIONS, payload, cmin, cmax))
        if name and not has_affected:
            for e in ecos_l:
                rows.append((e, name, vid, KIND_EMPTY, "[]", sem.COARSE_MIN, sem.COARSE_MAX))
    return rows


def encode_record(record: Dict[str, Any]) -> bytes:
    return zlib.compress(json.dumps(record, separators=(",", ":"), ensure_ascii=False)
                         .encode("utf-8"), 6)


def decode_record(blob: bytes) -> Dict[str, Any]:
    return json.loads(zlib.decompress(blob).decode("utf-8"))


# ---------------------------------------------------------------------------
# String fallback (versionIsMatchString + fuzzyMatchString)
# ---------------------------------------------------------------------------

_CANDIDATE = re.compile(r"(?i:\d+|rc\d*|alpha\d*|beta\d*|preview\d*)")
_CANON = re.compile(r"[-_.]+")


def _normalize_tag(v: str) -> str:
    if v.startswith("."):
        v = "0" + v
    comps = []
    for m in _CANDIDATE.finditer(v):
        s = m.group(0)
        if s[:1].isalpha() and "a" <= s[:1].lower() <= "z":
            if m.start() > 0 and re.match(r"(?i)^[a-z]$", v[m.start() - 1]):
                continue
        comps.append(s)
    if not comps:
        return v
    return "-".join(comps)


def _canonicalize(v: str) -> str:
    return _CANON.sub(".", v.lower()).strip(".")


def _string_match(version: str, versions: List[str]) -> bool:
    if version in versions:
        return True
    n, c = _normalize_tag(version), _canonicalize(version)
    return any(_normalize_tag(x) == n or _canonicalize(x) == c for x in versions)


def _matcher(eco: str, version: str, helper: bool) -> Callable[[int, str, str, str], bool]:
    if version == "":
        return lambda kind, payload, cmin, cmax: True

    def string_match(kind, payload, cmin, cmax):
        if kind != KIND_VERSIONS:
            return False
        return _string_match(version, json.loads(payload))

    if not helper:
        return string_match
    try:
        ver = sem.parse(eco, version)
    except (sem.InvalidVersion, ValueError):
        return string_match
    try:
        qc: Optional[str] = sem.coarse(eco, version)
    except (sem.InvalidVersion, ValueError):
        qc = None

    def eco_match(kind, payload, cmin, cmax):
        if qc is not None and not (cmin <= qc <= cmax):
            return False
        if kind == KIND_VERSIONS:
            for v in json.loads(payload):
                try:
                    if sem.compare(ver, sem.parse(eco, v)) == 0:
                        return True
                except (sem.InvalidVersion, ValueError):
                    continue
            return False
        if kind != KIND_RANGE:
            return False
        events = json.loads(payload)
        for t, v in reversed(events):
            try:
                c = sem.compare(ver, sem.parse(eco, v))
            except (sem.InvalidVersion, ValueError):
                continue
            if c < 0:
                continue
            if t == "introduced":
                return True
            if c == 0:
                return t == "last_affected"
            return False
        return False

    return eco_match


# ---------------------------------------------------------------------------
# Reader (one file = one ecosystem)
# ---------------------------------------------------------------------------


class EcosystemDB:
    """Read-only view of one ecosystem file. The file is never written in
    place (a refresh renames a new file over it), so it is opened immutable.

    Every read goes through `_guard`: any SQLite, zlib or JSON error (a
    damaged file) is raised as LocalDBError('local_db_corrupt'), never as a
    raw exception that would end the dependency check."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._local = threading.local()
        self._meta: Optional[Dict[str, str]] = None

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        if not self.path.exists():
            raise LocalDBError("no_local_db", "no local vulnerability database at %s" % self.path)
        try:
            conn = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro&immutable=1",
                                   uri=True, check_same_thread=False, timeout=5)
            conn.execute("SELECT 1 FROM meta LIMIT 1")
        except sqlite3.Error as exc:
            raise LocalDBError("local_db_corrupt", "%s is corrupt (%s)" % (self.path.name, exc))
        self._local.conn = conn
        return conn

    def _guard(self, fn, *args):
        try:
            return fn(*args)
        except LocalDBError:
            raise
        except (sqlite3.Error, zlib.error, ValueError, TypeError, KeyError, IndexError) as exc:
            raise LocalDBError("local_db_corrupt", "%s is corrupt (%s: %s)"
                               % (self.path.name, exc.__class__.__name__, str(exc)[:120]))

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None

    def meta(self) -> Dict[str, str]:
        if self._meta is None:
            self._meta = self._guard(lambda: {k: v for k, v in self._conn().execute("SELECT k, v FROM meta")})
        return self._meta

    def verify(self) -> None:
        """Size and sha256 against the sidecar written at build time."""
        side = sidecar_path(self.path)
        try:
            want = json.loads(side.read_text())
        except (OSError, ValueError):
            raise LocalDBError("local_db_corrupt", "%s has no integrity record" % self.path.name)
        try:
            size = self.path.stat().st_size
        except OSError as exc:
            raise LocalDBError("no_local_db", "%s: %s" % (self.path.name, exc))
        if size != want.get("bytes") or sha256_file(self.path) != want.get("sha256"):
            raise LocalDBError("local_db_corrupt", "%s does not match its integrity record "
                               "(size or sha256 changed)" % self.path.name)
        if self.meta().get("schema_version") != SCHEMA_VERSION:
            raise LocalDBError("local_db_outdated", "%s was built by another CLI version" % self.path.name)

    def snapshot_utc(self) -> Optional[str]:
        return self.meta().get("snapshot_utc")

    def age_hours(self, now: Optional[float] = None) -> Optional[float]:
        raw = self.snapshot_utc()
        if not raw:
            return None
        try:
            snap = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        now = now if now is not None else time.time()
        return max(0.0, (now - snap.timestamp()) / 3600.0)

    def match_ids(self, ecosystem: str, name: str, version: str = "") -> List[str]:
        if not name:
            return []
        return self._guard(self._match_ids, ecosystem, name, version)

    def _match_ids(self, ecosystem: str, name: str, version: str) -> List[str]:
        helper = sem.supports(ecosystem)
        name = normalize_name(ecosystem, name)
        rows = self._conn().execute(
            "SELECT vuln_id, kind, payload, cmin, cmax FROM entities "
            "WHERE eco = ? AND name = ? ORDER BY vuln_id", (ecosystem, name)).fetchall()
        match = _matcher(ecosystem, version, helper)
        out: List[str] = []
        last = None
        for vid, kind, payload, cmin, cmax in rows:
            if vid == last:
                continue
            if match(kind, payload, cmin, cmax):
                out.append(vid)
                last = vid
        if out:
            withdrawn = self._withdrawn(out)
            if withdrawn:
                out = [v for v in out if v not in withdrawn]
        return out

    def _withdrawn(self, ids: List[str]) -> set:
        out = set()
        conn = self._conn()
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            q = "SELECT id FROM vulns WHERE withdrawn = 1 AND id IN (%s)" % ",".join("?" * len(chunk))
            out.update(r[0] for r in conn.execute(q, chunk))
        return out

    def get_records(self, ids: List[str]) -> List[Dict[str, Any]]:
        if not ids:
            return []
        return self._guard(self._get_records, ids)

    def _get_records(self, ids: List[str]) -> List[Dict[str, Any]]:
        conn = self._conn()
        found: Dict[str, Dict[str, Any]] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            q = "SELECT id, data FROM vulns WHERE id IN (%s)" % ",".join("?" * len(chunk))
            for vid, blob in conn.execute(q, chunk):
                found[vid] = decode_record(blob)
        missing = [i for i in ids if i not in found]
        if missing:
            raise LocalDBError("local_db_corrupt", "%s: matched records missing (%s)"
                               % (self.path.name, missing[0]))
        return [found[i] for i in ids]

    def get_modified(self, ids: List[str]) -> Dict[str, str]:
        if not ids:
            return {}
        return self._guard(self._get_modified, ids)

    def _get_modified(self, ids: List[str]) -> Dict[str, str]:
        conn = self._conn()
        out: Dict[str, str] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            q = "SELECT id, modified FROM vulns WHERE id IN (%s)" % ",".join("?" * len(chunk))
            out.update({vid: mod for vid, mod in conn.execute(q, chunk)})
        return out


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


INDEXES = "CREATE INDEX IF NOT EXISTS idx_entities_pkg ON entities(eco, name, vuln_id);"


def sidecar_path(db: Path) -> Path:
    return Path(str(db) + ".sha256.json")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_sidecar(db: Path, dest_db: Optional[Path] = None) -> None:
    """Integrity record for `db`, written next to `dest_db` (default: db)."""
    side = sidecar_path(dest_db or db)
    tmp = Path(str(side) + ".tmp")
    tmp.write_text(json.dumps({"bytes": db.stat().st_size, "sha256": sha256_file(db)}))
    os.replace(tmp, side)


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('schema_version', ?)", (SCHEMA_VERSION,))


def upsert_record(conn: sqlite3.Connection, eco: str, record: Dict[str, Any], fresh: bool = False) -> None:
    """`fresh`: the file is being built from scratch, no earlier rows to delete."""
    vid = str(record.get("id") or "")
    if not vid:
        return
    modified = str(record.get("modified") or "")
    withdrawn = 1 if record.get("withdrawn") else 0
    conn.execute("INSERT OR REPLACE INTO vulns(id, modified, withdrawn, data) VALUES (?,?,?,?)",
                 (vid, modified, withdrawn, encode_record(record)))
    conn.execute("INSERT OR REPLACE INTO sources(eco, id, modified) VALUES (?,?,?)", (eco, vid, modified))
    if not fresh:
        # Same id twice in one export (not seen in practice): last copy wins.
        conn.execute("DELETE FROM entities WHERE vuln_id = ?", (vid,))
    rows = compute_entities(record, only_ecosystems=[eco])
    if rows:
        conn.executemany("INSERT INTO entities(eco, name, vuln_id, kind, payload, cmin, cmax) "
                         "VALUES (?,?,?,?,?,?,?)", rows)


def set_meta(conn: sqlite3.Connection, **kv: Any) -> None:
    for k, v in kv.items():
        if not isinstance(v, str):
            v = json.dumps(v)
        conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", (k, v))


def iter_zip_records(zf: zipfile.ZipFile) -> Iterator[Dict[str, Any]]:
    for info in zf.infolist():
        if not info.filename.endswith(".json"):
            continue
        with zf.open(info) as fh:
            try:
                rec = json.load(fh)
            except ValueError:
                logger.warning("OSV export: unreadable member %s skipped", info.filename)
                continue
        if isinstance(rec, dict):
            yield rec


def build_db(eco: str, records: Iterable[Dict[str, Any]], dest: Path, snapshot_utc: Optional[str] = None,
             **extra_meta: Any) -> int:
    """Write `records` into a new file at `dest` (replaced if present), plus its
    integrity record. Returns the record count."""
    dest = Path(dest)
    dest.unlink(missing_ok=True)
    conn = sqlite3.connect(str(dest))
    n = 0
    try:
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
        create_schema(conn)
        seen = set()
        for rec in records:
            vid = str(rec.get("id") or "")
            upsert_record(conn, eco, rec, fresh=vid not in seen)
            seen.add(vid)
            n += 1
            if n % COMMIT_EVERY == 0:
                conn.commit()
        set_meta(conn, snapshot_utc=snapshot_utc or utc_now_iso(), ecosystem=eco, ecosystems=[eco],
                 built_at=utc_now_iso(), records=n, **extra_meta)
        conn.executescript(INDEXES)
        conn.commit()
        chk = conn.execute("PRAGMA quick_check").fetchone()[0]
        if chk != "ok":
            raise LocalDBError("local_db_build_failed", "integrity check failed: %s" % chk)
        conn.execute("ANALYZE")
        conn.commit()
    finally:
        conn.close()
    write_sidecar(dest)
    return n


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def _md5_from_goog_hash(header: str) -> Optional[str]:
    for part in (header or "").split(","):
        k, _, v = part.strip().partition("=")
        if k == "md5" and v:
            try:
                return base64.b64decode(v + "=" * (-len(v) % 4)).hex()
            except ValueError:
                return None
    return None


def _flock(fh, blocking: bool = True) -> bool:
    try:
        import fcntl
    except ImportError:
        return True
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        return True
    except OSError:
        return False


class _Lock:
    """Advisory per-ecosystem lock so two scans do not build the same file at once."""

    def __init__(self, path: Path):
        self.path = path
        self._fh = None

    def __enter__(self):
        self._fh = open(self.path, "a")
        _flock(self._fh)
        return self

    def __exit__(self, *exc):
        try:
            import fcntl
            fcntl.flock(self._fh, fcntl.LOCK_UN)
        except (ImportError, OSError):
            pass
        self._fh.close()
        return False


def _lock_path(directory: Path, eco: str) -> Path:
    return directory / (".%s.lock" % _safe_name(eco))


def cleanup_orphans(directory: Optional[Path] = None) -> List[str]:
    """Remove `.zip.part` / `.db.building` files left by an interrupted run.
    Skipped for an ecosystem whose lock another process holds (a live download)."""
    directory = Path(directory or cache_dir())
    removed: List[str] = []
    if not directory.is_dir():
        return removed
    for eco in ECOSYSTEMS:
        leftovers = [p for p in (directory / ("%s.zip.part" % _safe_name(eco)),
                                 directory / ("%s.db.building" % _safe_name(eco)),
                                 Path(str(directory / ("%s.db.building" % _safe_name(eco))) + ".sha256.json"))
                     if p.exists()]
        if not leftovers:
            continue
        try:
            with open(_lock_path(directory, eco), "a") as fh:
                if not _flock(fh, blocking=False):
                    continue
                for p in leftovers:
                    p.unlink(missing_ok=True)
                    removed.append(p.name)
        except OSError:
            continue
    return removed


def _fresh_file(live: Path, max_age: float) -> Optional[EcosystemDB]:
    if not live.exists():
        return None
    db = EcosystemDB(live)
    try:
        db.verify()
        age = db.age_hours()
    except LocalDBError:
        db.close()
        return None
    if age is None or age > max_age:
        db.close()
        return None
    return db


def download(eco: str, directory: Optional[Path] = None, session: Optional[requests.Session] = None,
             base: Optional[str] = None, notify: Optional[Callable[[str], None]] = None,
             skip_if_younger_than: Optional[float] = None) -> Dict[str, Any]:
    """Download `eco`/all.zip, check it, build the file and swap it in.

    The request is a plain GET of a public URL naming the ecosystem; nothing
    about the scanned project is sent. Raises LocalDBError on any failure,
    leaving the previous file (if any) untouched. With `skip_if_younger_than`
    (hours), nothing is downloaded when, once the lock is held, the file is
    already that fresh (another scan refreshed it meanwhile).
    """
    if eco not in ECOSYSTEMS:
        raise LocalDBError("ecosystem_not_covered", "ecosystem %s has no OSV export the CLI downloads" % eco)
    directory = Path(directory or cache_dir())
    live = db_path(eco, directory)
    part = directory / ("%s.zip.part" % _safe_name(eco))
    building = directory / ("%s.db.building" % _safe_name(eco))
    url = export_url(eco, base)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        lock = _Lock(_lock_path(directory, eco))
        lock.__enter__()
    except OSError as exc:
        raise LocalDBError("cache_not_writable", "cannot write the OSV cache directory %s (%s)"
                           % (directory, exc.strerror or exc))
    t0 = time.time()
    started = utc_now_iso()
    try:
        if skip_if_younger_than is not None:
            db = _fresh_file(live, skip_if_younger_than)
            if db is not None:
                db.close()
                return {"ecosystem": eco, "skipped": True, "path": str(live)}
        s = session or requests.Session()
        headers = {"User-Agent": "narvy-cli/%s" % __version__}
        for p in (part, building, sidecar_path(building)):
            p.unlink(missing_ok=True)
        try:
            try:
                with s.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT_SECONDS, headers=headers) as r:
                    if r.status_code != 200:
                        raise LocalDBError("download_failed", "%s: HTTP %s" % (url, r.status_code))
                    want_len = r.headers.get("content-length")
                    want_md5 = _md5_from_goog_hash(r.headers.get("x-goog-hash", ""))
                    if notify:
                        size = ("%.0f MB" % (int(want_len) / 1e6)) if want_len and want_len.isdigit() else "size unknown"
                        notify("Downloading the OSV database for %s (%s) from %s" % (eco, size, url))
                    md5 = hashlib.md5()
                    got = 0
                    with open(part, "wb") as f:
                        for chunk in r.iter_content(1 << 20):
                            f.write(chunk)
                            md5.update(chunk)
                            got += len(chunk)
            except requests.RequestException as exc:
                raise LocalDBError("download_failed", "%s: %s" % (url, exc.__class__.__name__))
            if want_len and want_len.isdigit() and got != int(want_len):
                raise LocalDBError("download_failed", "%s: got %d bytes, expected %s" % (url, got, want_len))
            if got < MIN_ZIP_BYTES:
                raise LocalDBError("download_failed", "%s: file too small (%d bytes)" % (url, got))
            if want_md5 and md5.hexdigest() != want_md5:
                raise LocalDBError("download_failed", "%s: md5 mismatch" % url)
            if not zipfile.is_zipfile(part):
                raise LocalDBError("download_failed", "%s: not a valid zip file" % url)
            download_s = time.time() - t0
            try:
                with zipfile.ZipFile(part) as zf:
                    bad = zf.testzip()
                    if bad is not None:
                        raise LocalDBError("download_failed", "%s: corrupt member %s" % (url, bad))
                    n = build_db(eco, iter_zip_records(zf), building, snapshot_utc=started,
                                 source=url, zip_bytes=got, zip_md5=md5.hexdigest())
            except (zipfile.BadZipFile, sqlite3.Error) as exc:
                raise LocalDBError("local_db_build_failed", "%s: %s" % (eco, exc))
            if n == 0:
                raise LocalDBError("download_failed", "%s: the export holds no record" % url)
            # Opens read-only, matches its integrity record, or the old file stays.
            check = EcosystemDB(building)
            check.verify()
            check.close()
            try:
                os.replace(sidecar_path(building), sidecar_path(live))
                os.replace(building, live)
                # A damaged copy moved aside earlier is no longer needed.
                Path(str(live) + ".corrupt").unlink(missing_ok=True)
            except OSError as exc:  # e.g. Windows, file held open by another scan
                raise LocalDBError("local_db_build_failed", "%s: cannot replace %s (%s)" % (eco, live, exc))
        except OSError as exc:  # disk full, permission denied
            raise LocalDBError("download_failed", "%s: %s" % (eco, exc.strerror or exc))
        finally:
            for p in (part, building, sidecar_path(building)):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
    finally:
        lock.__exit__(None, None, None)
    total_s = time.time() - t0
    info = {"ecosystem": eco, "records": n, "zip_bytes": got, "db_bytes": live.stat().st_size,
            "download_seconds": round(download_s, 1), "total_seconds": round(total_s, 1), "path": str(live)}
    if notify:
        notify("OSV database for %s ready: %d records, %.0f MB on disk, %.0f s"
               % (eco, n, info["db_bytes"] / 1e6, total_s))
    return info


def quarantine(eco: str, directory: Optional[Path] = None) -> Optional[Path]:
    """Move a damaged file aside as `<eco>.db.corrupt` (shown by `narvy db status`)."""
    directory = Path(directory or cache_dir())
    live = db_path(eco, directory)
    bad = Path(str(live) + ".corrupt")
    try:
        if live.exists():
            os.replace(live, bad)
        sidecar_path(live).unlink(missing_ok=True)
        return bad
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Store: picks / refreshes the file for each ecosystem
# ---------------------------------------------------------------------------


class LocalStore:
    """Hands out one EcosystemDB per ecosystem, downloading it when missing,
    damaged or older than `max_age` hours, unless `offline`. A copy older than
    HARD_MAX_AGE_HOURS is never used."""

    def __init__(self, directory: Optional[Path] = None, offline: bool = False,
                 max_age: Optional[float] = None, session: Optional[requests.Session] = None,
                 base: Optional[str] = None, notify: Optional[Callable[[str], None]] = None,
                 hard_max_age: Optional[float] = None):
        self.directory = Path(directory or cache_dir())
        self.offline = offline
        self.max_age = max_age_hours() if max_age is None else max_age
        self.hard_max_age = HARD_MAX_AGE_HOURS if hard_max_age is None else hard_max_age
        self.session = session
        self.base = base
        self.notify = notify
        self._dbs: Dict[str, EcosystemDB] = {}
        self._errors: Dict[str, LocalDBError] = {}
        self.stale: Dict[str, float] = {}
        self.downloads: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._cleaned = False

    def get(self, eco: str) -> EcosystemDB:
        with self._lock:
            if eco in self._dbs:
                return self._dbs[eco]
            if eco in self._errors:
                raise self._errors[eco]
            if not self._cleaned:
                self._cleaned = True
                cleanup_orphans(self.directory)
            try:
                db = self._open(eco)
            except LocalDBError as exc:
                self._errors[eco] = exc
                raise
            self._dbs[eco] = db
            return db

    def recover(self, eco: str, cause: LocalDBError) -> EcosystemDB:
        """A read failed on a damaged file: move it aside and download it again
        (not with --offline). Raises LocalDBError if no good copy can be had."""
        with self._lock:
            db = self._dbs.pop(eco, None)
            if db is not None:
                db.close()
            self.stale.pop(eco, None)
            logger.warning("OSV: %s; moved aside as %s.db.corrupt", cause, eco)
            quarantine(eco, self.directory)
            try:
                if self.offline:
                    raise LocalDBError(
                        "local_db_corrupt_offline",
                        "--offline: the cached OSV database for %s is corrupt (%s); run `narvy db update "
                        "--ecosystem %s` while online" % (eco, cause, eco))
                try:
                    db = self._open(eco)
                except LocalDBError as exc:
                    raise LocalDBError("local_db_corrupt", "the cached OSV database for %s was corrupt and "
                                       "a new copy could not be downloaded (%s)" % (eco, exc))
            except LocalDBError as exc:
                self._errors[eco] = exc
                raise
            self._dbs[eco] = db
            return db

    def _existing(self, eco: str) -> Tuple[Optional[EcosystemDB], Optional[LocalDBError]]:
        p = db_path(eco, self.directory)
        if not p.exists():
            return None, None
        db = EcosystemDB(p)
        try:
            db.verify()
            db.age_hours()
        except LocalDBError as exc:
            db.close()
            if exc.kind == "local_db_corrupt":
                logger.warning("OSV: %s; moved aside as %s.db.corrupt", exc, eco)
                quarantine(eco, self.directory)
            return None, exc
        return db, None

    def _open(self, eco: str) -> EcosystemDB:
        if eco not in ECOSYSTEMS:
            raise LocalDBError("ecosystem_not_covered", "ecosystem %s is not covered" % eco)
        db, bad = self._existing(eco)
        age = db.age_hours() if db else None
        if db is not None and age is not None and age <= self.max_age:
            return db
        if self.offline:
            if db is None:
                if bad is not None and bad.kind == "local_db_corrupt":
                    raise LocalDBError(
                        "local_db_corrupt_offline",
                        "--offline: the cached OSV database for %s is corrupt (%s); run `narvy db update "
                        "--ecosystem %s` while online" % (eco, bad, eco))
                if bad is not None:
                    raise LocalDBError(
                        "local_db_unreadable",
                        "--offline: the cached OSV database for %s cannot be used (%s); run `narvy db update "
                        "--ecosystem %s` while online" % (eco, bad, eco))
                raise LocalDBError(
                    "no_local_db_offline",
                    "--offline: no local OSV database for %s in %s; run `narvy db update --ecosystem %s` "
                    "while online first" % (eco, self.directory, eco))
            return self._stale_or_refuse(eco, db, age)
        if db is not None:
            db.close()
        try:
            self.downloads.append(download(eco, self.directory, self.session, self.base, self.notify,
                                           skip_if_younger_than=self.max_age))
        except LocalDBError as exc:
            if db is not None:
                # One message: either the old copy is used, or it is refused (too old).
                kept = self._stale_or_refuse(eco, EcosystemDB(db.path), age, refresh_error=exc)
                logger.warning("OSV: refresh of the %s database failed (%s); using the copy from %s",
                               eco, exc, db.snapshot_utc())
                return kept
            if bad is not None and bad.kind == "local_db_corrupt":
                raise LocalDBError("local_db_corrupt", "the cached OSV database for %s was corrupt and "
                                   "a new copy could not be downloaded (%s)" % (eco, exc))
            raise
        return EcosystemDB(db_path(eco, self.directory))

    def _stale_or_refuse(self, eco: str, db: EcosystemDB, age: Optional[float],
                         refresh_error: Optional[LocalDBError] = None) -> EcosystemDB:
        if age is None or age > self.hard_max_age:
            db.close()
            raise LocalDBError(
                "local_db_too_old",
                "the cached OSV database for %s is %s old (limit %d days)%s; run `narvy db update "
                "--ecosystem %s`" % (eco, ("%.0f h" % age) if age is not None else "of unknown age",
                                     self.hard_max_age // 24,
                                     (" and the refresh failed (%s)" % refresh_error) if refresh_error else "",
                                     eco))
        self.stale[eco] = age
        return db

    def info(self, eco: str) -> Optional[Dict[str, Any]]:
        db = self._dbs.get(eco)
        if db is None:
            return None
        try:
            return {"snapshot_utc": db.snapshot_utc(), "age_hours": round(db.age_hours() or 0.0, 1),
                    "stale": eco in self.stale}
        except LocalDBError:
            return None

    def error(self, eco: str) -> Optional[LocalDBError]:
        return self._errors.get(eco)


def status(directory: Optional[Path] = None) -> List[Dict[str, Any]]:
    """One row per ecosystem file present in the cache, damaged ones included."""
    directory = Path(directory or cache_dir())
    out = []
    for eco in ECOSYSTEMS:
        p = db_path(eco, directory)
        moved = Path(str(p) + ".corrupt")
        if not p.exists():
            if moved.exists():
                out.append({"ecosystem": eco, "path": str(moved), "db_bytes": moved.stat().st_size,
                            "error": "corrupt, moved aside; run `narvy db update -e %s`" % eco})
            continue
        row: Dict[str, Any] = {"ecosystem": eco, "path": str(p), "db_bytes": p.stat().st_size}
        db = EcosystemDB(p)
        try:
            db.verify()
            m = db.meta()
            row.update(snapshot_utc=m.get("snapshot_utc"), records=int(m.get("records", "0") or 0),
                       age_hours=round(db.age_hours() or 0.0, 1))
            if row["age_hours"] > HARD_MAX_AGE_HOURS:
                row["error"] = "older than %d days, not used; run `narvy db update -e %s`" % (
                    HARD_MAX_AGE_HOURS // 24, eco)
        except LocalDBError as exc:
            row["error"] = ("corrupt" if exc.kind == "local_db_corrupt" else "outdated format") + \
                "; run `narvy db update -e %s`" % eco
        except ValueError:
            row["error"] = "corrupt; run `narvy db update -e %s`" % eco
        finally:
            db.close()
        out.append(row)
    return out


def cached_ecosystems(directory: Optional[Path] = None) -> List[str]:
    return [r["ecosystem"] for r in status(directory)]
