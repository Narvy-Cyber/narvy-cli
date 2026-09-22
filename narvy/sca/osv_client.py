"""OSV.dev client for SCA: version-range CVE lookups with a local SQLite cache
and offline fallback."""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# Overridable for airgapped or mirrored deployments.
OSV_API_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev/v1/query")
OSV_BATCH_URL = os.environ.get("OSV_BATCH_API_URL", "https://api.osv.dev/v1/querybatch")

_DEFAULT_CACHE_PATH = Path.home() / ".narvy" / "osv_cache.db"

DEFAULT_TTL_SECONDS = 7 * 24 * 3600

# CVE ids older than modern mobile package managers are noise.
MIN_CVE_YEAR = 2010

# OSV has no "CocoaPods" ecosystem (rejected as invalid); Swift packages live
# under "SwiftURL", keyed by the bare `github.com/<owner>/<repo>` path.
ECOSYSTEMS = {
    "Maven",
    "PyPI",
    "npm",
    "Go",
    "RubyGems",
    "crates.io",
    "Packagist",
    "NuGet",
    "SwiftURL",
}

_SEVERITY_BUCKETS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]


@dataclass
class OSVFinding:
    """Normalized OSV vulnerability, ready to merge into the CLI finding schema."""

    rule_id: str = "SCA-VULNERABLE-LIBRARY"
    title: str = ""
    cve: str = ""
    osv_id: str = ""
    cwe: str = "CWE-1104"
    severity: str = "MEDIUM"
    cvss_score: float = 0.0
    summary: str = ""
    details: str = ""
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    published: str = ""
    modified: str = ""
    package_name: str = ""
    package_version: str = ""
    ecosystem: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "cve": self.cve,
            "cve_id": self.cve,
            "osv_id": self.osv_id,
            "cwe": self.cwe,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "summary": self.summary,
            "details": self.details,
            "fixed_version": self.fixed_version,
            "recommendation": (
                f"Update {self.package_name} to version {self.fixed_version} or later"
                if self.fixed_version
                else "Update to the latest patched version (no fixed version listed)"
            ),
            "references": self.references,
            "aliases": self.aliases,
            "published": self.published,
            "modified": self.modified,
            "package": self.package_name,
            "version": self.package_version,
            "ecosystem": self.ecosystem,
            "source": "OSV",
        }


class OSVCache:
    """Thread-safe SQLite cache for OSV responses, opened per call."""

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS osv_cache (
            package TEXT NOT NULL,
            version TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            response TEXT NOT NULL,
            cached_at INTEGER NOT NULL,
            PRIMARY KEY (package, version, ecosystem)
        );
        CREATE INDEX IF NOT EXISTS idx_osv_cache_age ON osv_cache(cached_at);
    """

    def __init__(self, db_path: Optional[Path] = None, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self.db_path = self._resolve_path(db_path)
        self._lock = threading.Lock()
        self._init_db()

        self.hits = 0
        self.misses = 0
        self.writes = 0

    @staticmethod
    def _resolve_path(db_path: Optional[Path]) -> Path:
        if db_path:
            db_path = Path(db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            return db_path
        try:
            _DEFAULT_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            return _DEFAULT_CACHE_PATH
        except (PermissionError, OSError):
            fallback = Path("/tmp/narvy_osv_cache.db")
            fallback.parent.mkdir(parents=True, exist_ok=True)
            return fallback

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(self._SCHEMA)

    def get(self, package: str, version: str, ecosystem: str) -> Optional[List[Dict[str, Any]]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT response, cached_at FROM osv_cache "
                "WHERE package = ? AND version = ? AND ecosystem = ?",
                (package, version, ecosystem),
            ).fetchone()
        if not row:
            self.misses += 1
            return None
        if (time.time() - row["cached_at"]) > self.ttl_seconds:
            self.misses += 1
            return None
        try:
            self.hits += 1
            return json.loads(row["response"])
        except json.JSONDecodeError:
            self.misses += 1
            return None

    def get_stale(self, package: str, version: str, ecosystem: str) -> Optional[List[Dict[str, Any]]]:
        """Cached response ignoring the TTL, for the offline fallback path."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT response FROM osv_cache "
                "WHERE package = ? AND version = ? AND ecosystem = ?",
                (package, version, ecosystem),
            ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["response"])
        except json.JSONDecodeError:
            return None

    def put(self, package: str, version: str, ecosystem: str, vulns: List[Dict[str, Any]]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO osv_cache(package, version, ecosystem, "
                "response, cached_at) VALUES (?, ?, ?, ?, ?)",
                (package, version, ecosystem, json.dumps(vulns), int(time.time())),
            )
            conn.commit()
        self.writes += 1

    def stats(self) -> Dict[str, int]:
        return {"hits": self.hits, "misses": self.misses, "writes": self.writes}

    def size(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM osv_cache").fetchone()
        return int(row["n"]) if row else 0


def _osv_severity_to_ours(score: float) -> str:
    if score is None:
        return "MEDIUM"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"
    for threshold, label in _SEVERITY_BUCKETS:
        if score >= threshold:
            return label
    return "INFO"


def _cvss3_base_score(vector: str) -> float:
    """CVSS v3.x base score from a vector string (FIRST.org formula), 0.0 on error."""
    import math
    try:
        parts = vector.split("/")
        if len(parts) < 2 or not parts[0].startswith("CVSS:3"):
            return 0.0
        metrics: dict = {}
        for p in parts[1:]:
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k] = v

        _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        _AC = {"L": 0.77, "H": 0.44}
        _PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
        _PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
        _UI = {"N": 0.85, "R": 0.62}
        _CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

        scope = metrics.get("S", "U")
        pr_table = _PR_C if scope == "C" else _PR_U

        av = _AV.get(metrics.get("AV", ""), None)
        ac = _AC.get(metrics.get("AC", ""), None)
        pr = pr_table.get(metrics.get("PR", ""), None)
        ui = _UI.get(metrics.get("UI", ""), None)
        c = _CIA.get(metrics.get("C", ""), None)
        i = _CIA.get(metrics.get("I", ""), None)
        a = _CIA.get(metrics.get("A", ""), None)

        if any(x is None for x in (av, ac, pr, ui, c, i, a)):
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui  # type: ignore[operator]
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))    # type: ignore[operator]

        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            return 0.0

        raw = min(exploitability + impact, 10) if scope == "U" else min(1.08 * (exploitability + impact), 10)
        return math.ceil(raw * 10) / 10
    except Exception:
        return 0.0


def _parse_cvss_score(vector_or_score: Any) -> float:
    if vector_or_score is None:
        return 0.0
    if isinstance(vector_or_score, (int, float)):
        return float(vector_or_score)
    if isinstance(vector_or_score, str):
        try:
            return float(vector_or_score)
        except ValueError:
            pass
        if vector_or_score.startswith("CVSS:3"):
            return _cvss3_base_score(vector_or_score)
        return 0.0
    return 0.0


def _highest_cvss(severity_entries: List[Dict[str, Any]]) -> float:
    best = 0.0
    for entry in severity_entries or []:
        score = _parse_cvss_score(entry.get("score"))
        if score > best:
            best = score
    return best


def _extract_year(cve_id: str) -> Optional[int]:
    if not cve_id or not cve_id.startswith(("CVE-", "GHSA-")):
        return None
    if cve_id.startswith("CVE-"):
        try:
            return int(cve_id.split("-")[1])
        except (IndexError, ValueError):
            return None
    return None


_GIT_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")

_PLATFORM_SUFFIX_RE = re.compile(
    r"-(?:x86_64|x86|aarch64|arm64|arm|amd64|i386|i686|"
    r"java|universal|mingw32|mswin32|"
    r"darwin|linux|linux-gnu|linux-musl|windows|win32|freebsd|solaris)\b.*$",
    re.IGNORECASE,
)


def _is_git_sha(value: str) -> bool:
    return bool(value) and bool(_GIT_SHA_RE.match(value.strip()))


def _strip_platform_suffix(version: str) -> str:
    if not version:
        return version
    return _PLATFORM_SUFFIX_RE.sub("", version.strip())


def _version_key(version: str):
    core = _strip_platform_suffix(version or "").lstrip("vV")
    m = re.match(r"^([0-9]+(?:\.[0-9]+)*)", core)
    if not m:
        return (0,)
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return (0,)


def _pick_fixed_version(
    raw: Dict[str, Any],
    package_name: str,
    installed_version: str,
) -> Optional[str]:
    """Lowest fixed version above the installed one (ECOSYSTEM then SEMVER, never GIT)."""
    inst_key = _version_key(installed_version)
    _TYPE_RANK = {"ECOSYSTEM": 0, "SEMVER": 1}
    candidates = []
    for affected in raw.get("affected", []) or []:
        for r in affected.get("ranges", []) or []:
            rtype = str(r.get("type", "")).upper()
            if rtype == "GIT":
                continue
            rank = _TYPE_RANK.get(rtype, 2)
            for evt in r.get("events", []) or []:
                fv = evt.get("fixed")
                if not fv or _is_git_sha(str(fv)):
                    continue
                candidates.append((rank, str(fv)))

    if not candidates:
        return None

    best_rank = min(c[0] for c in candidates)
    same_rank = [c[1] for c in candidates if c[0] == best_rank]
    greater = sorted(
        (v for v in same_rank if _version_key(v) > inst_key),
        key=_version_key,
    )
    if greater:
        return greater[0]
    return sorted(same_rank, key=_version_key)[-1]


def _parse_osv_vuln(
    raw: Dict[str, Any],
    package_name: str,
    package_version: str,
    ecosystem: str,
) -> Optional[OSVFinding]:
    """One raw OSV vulnerability as an OSVFinding, or None if it is filtered out."""
    osv_id = raw.get("id", "")
    aliases = raw.get("aliases", []) or []

    cve_id = ""
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break
    if not cve_id:
        cve_id = osv_id

    year = _extract_year(cve_id)
    if year is not None and year < MIN_CVE_YEAR:
        logger.debug(f"OSV: dropping pre-{MIN_CVE_YEAR} CVE {cve_id} on {package_name}@{package_version}")
        return None

    severity_label = "MEDIUM"
    cvss_score = 0.0

    sev_arr = raw.get("severity", []) or []
    if sev_arr:
        cvss_score = _highest_cvss(sev_arr)
        if cvss_score > 0:
            severity_label = _osv_severity_to_ours(cvss_score)

    if cvss_score == 0.0:
        db_specific = raw.get("database_specific", {}) or {}
        sev_str = db_specific.get("severity", "")
        _LABEL_NORM = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
                       "MEDIUM": "MEDIUM", "LOW": "LOW"}
        if isinstance(sev_str, str) and sev_str.upper() in _LABEL_NORM:
            severity_label = _LABEL_NORM[sev_str.upper()]
            cvss_score = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}[severity_label]

    if cvss_score == 0.0:
        eco_specific = raw.get("ecosystem_specific", {}) or {}
        sev_str = eco_specific.get("severity", "")
        _LABEL_NORM2 = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
                        "MEDIUM": "MEDIUM", "LOW": "LOW"}
        if isinstance(sev_str, str) and sev_str.upper() in _LABEL_NORM2:
            severity_label = _LABEL_NORM2[sev_str.upper()]
            cvss_score = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}[severity_label]

    fixed_version: Optional[str] = _pick_fixed_version(raw, package_name, package_version)

    refs = []
    for ref in raw.get("references", []) or []:
        url = ref.get("url")
        if url:
            refs.append(url)
    refs = refs[:10]

    summary = raw.get("summary", "") or ""
    details = raw.get("details", "") or ""

    title = f"{package_name}@{package_version} affected by {cve_id}"
    if summary:
        title = f"{title}: {summary[:120]}"

    return OSVFinding(
        rule_id="SCA-VULNERABLE-LIBRARY",
        title=title,
        cve=cve_id,
        osv_id=osv_id,
        severity=severity_label,
        cvss_score=cvss_score,
        summary=summary,
        details=details,
        fixed_version=fixed_version,
        references=refs,
        aliases=aliases,
        published=raw.get("published", ""),
        modified=raw.get("modified", ""),
        package_name=package_name,
        package_version=package_version,
        ecosystem=ecosystem,
    )


class OSVClient:
    """OSV client with cache, offline fallback and a querybatch pre-filter."""

    def __init__(
        self,
        cache: Optional[OSVCache] = None,
        api_url: str = OSV_API_URL,
        batch_url: str = OSV_BATCH_URL,
        timeout: float = 10.0,
        session: Optional[requests.Session] = None,
    ):
        self.api_url = api_url
        self.batch_url = batch_url
        self.timeout = timeout
        self.cache = cache or OSVCache()
        # Coverage counters: tell "0 CVEs because OSV said so" from "0 because OSV was unreachable".
        self.batch_failures = 0
        self.query_failures_no_cache = 0
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "User-Agent": "Narvy-CLI-SCA/1.0 (OSV; +https://narvy.io)",
            }
        )

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str = "Maven",
        use_cache: bool = True,
    ) -> List[OSVFinding]:
        """Vulnerabilities for `package_name@version`; falls back to stale cache when offline."""
        if not package_name or not version:
            return []
        if ecosystem not in ECOSYSTEMS:
            logger.warning(f"OSV: unknown ecosystem '{ecosystem}', querying anyway")

        if use_cache:
            cached = self.cache.get(package_name, version, ecosystem)
            if cached is not None:
                return [
                    f
                    for f in (
                        _parse_osv_vuln(v, package_name, version, ecosystem)
                        for v in cached
                    )
                    if f is not None
                ]

        body = {
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version,
        }
        try:
            resp = self._session.post(self.api_url, json=body, timeout=self.timeout)
            resp.raise_for_status()
            payload = resp.json()
            raw_vulns = payload.get("vulns", []) or []

            self.cache.put(package_name, version, ecosystem, raw_vulns)

            findings = [
                f
                for f in (
                    _parse_osv_vuln(v, package_name, version, ecosystem)
                    for v in raw_vulns
                )
                if f is not None
            ]
            return findings

        except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
            logger.warning(f"OSV query failed for {package_name}@{version}: {exc}")
            stale = self.cache.get_stale(package_name, version, ecosystem)
            if stale is not None:
                logger.warning(
                    f"OSV: serving STALE cache for {package_name}@{version} "
                    f"(network unreachable)"
                )
                return [
                    f
                    for f in (
                        _parse_osv_vuln(v, package_name, version, ecosystem)
                        for v in stale
                    )
                    if f is not None
                ]
            # Failed and nothing cached: this dependency is UNKNOWN, not clean.
            self.query_failures_no_cache += 1
            return []

    def query_dict(self, package_name: str, version: str, ecosystem: str = "Maven") -> List[Dict[str, Any]]:
        # OSV lists one CVE under several advisory ids (GHSA/PYSEC/CVE); dedupe on the CVE.
        out: List[Dict[str, Any]] = []
        seen = set()
        for f in self.query(package_name, version, ecosystem):
            key = getattr(f, "cve", "") or getattr(f, "osv_id", "") or id(f)
            if key in seen:
                continue
            seen.add(key)
            out.append(f.to_dict())
        return out

    def has_any_vuln_batch(
        self,
        packages: List[tuple],
        ecosystem: str = "Maven",
        batch_size: int = 100,
    ) -> Dict[tuple, bool]:
        """Pre-filter (name, version) tuples through OSV's id-only batch endpoint."""
        result = {pkg: False for pkg in packages}
        if not packages:
            return result

        # Mark cached packages True so query() still runs (from cache); False would
        # silently drop their CVEs for the whole cache TTL.
        uncached = []
        for pkg in packages:
            if self.cache.get(pkg[0], pkg[1], ecosystem) is not None:
                result[pkg] = True
            else:
                uncached.append(pkg)
        if not uncached:
            return result

        for i in range(0, len(uncached), batch_size):
            chunk = uncached[i:i + batch_size]
            queries = [
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                for name, version in chunk
            ]
            try:
                resp = self._session.post(self.batch_url, json={"queries": queries}, timeout=self.timeout)
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", []) or []
                # A short/empty results array leaves some queried deps unanswered:
                # mark each unresolved (defer to query()) so the coverage gate sees it.
                incomplete = False
                for idx in range(len(chunk)):
                    r = results[idx] if idx < len(results) else None
                    if not isinstance(r, dict):
                        result[chunk[idx]] = True
                        incomplete = True
                    elif r.get("vulns"):
                        result[chunk[idx]] = True
                if incomplete:
                    self.batch_failures += 1
            except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
                logger.warning(f"OSV batch query failed (chunk {i}-{i+len(chunk)}): {exc}")
                self.batch_failures += 1
                # Unknown for this chunk: defer to query() rather than under-report.
                for name, version in chunk:
                    result[(name, version)] = True

        return result


_default_client: Optional[OSVClient] = None
_default_lock = threading.Lock()


def get_default_client() -> OSVClient:
    global _default_client
    with _default_lock:
        if _default_client is None:
            _default_client = OSVClient()
        return _default_client
