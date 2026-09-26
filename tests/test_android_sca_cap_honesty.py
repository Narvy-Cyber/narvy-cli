"""Android SCA counts reflect the OSV detail-query cap. Offline."""
from __future__ import annotations

import os
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.sca import android_deps
from narvy.sca.osv_client import OSVCache, OSVClient


class _StubResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _StubSession:
    """Fake OSV session that answers from a fixed set and records requests."""

    def __init__(self, vulnerable=()):
        self.vulnerable = set(vulnerable)   # {(maven_name, version), ...}
        self.batched = []
        self.queried = []
        self.headers = {}

    def update(self, *_a, **_k):
        pass

    def post(self, url, json=None, timeout=None):
        body = json or {}
        if "queries" in body:                       # /v1/querybatch
            results = []
            for q in body["queries"]:
                key = (q["package"]["name"], q["version"])
                self.batched.append(key)
                results.append({"vulns": [{"id": "STUB-1"}]} if key in self.vulnerable else {})
            return _StubResponse({"results": results})
        key = (body["package"]["name"], body["version"])     # /v1/query
        self.queried.append(key)
        if key not in self.vulnerable:
            return _StubResponse({"vulns": []})
        return _StubResponse({"vulns": [{
            "id": "CVE-STUB-0001",
            "summary": "stub advisory",
            "affected": [{
                "package": {"name": key[0], "ecosystem": "Maven"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }],
        }]})


def _client(tmpdir: str, vulnerable=()):
    cache = OSVCache(db_path=Path(tmpdir) / "osv.db")
    session = _StubSession(vulnerable)
    return OSVClient(cache=cache, session=session), cache, session


def _make_apk(path: str, coords) -> str:
    """Synthetic APK: one META-INF/maven/.../pom.properties per coordinate."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00stub")
        for group, artifact, version in coords:
            zf.writestr(
                f"META-INF/maven/{group}/{artifact}/pom.properties",
                f"groupId={group}\nartifactId={artifact}\nversion={version}\n",
            )
    return path


def _coords(n: int, prefix: str = "com.example.pkg"):
    return [(f"{prefix}{i}", f"lib{i}", "1.0.0") for i in range(n)]


def test_capped_scan_reports_the_post_cap_checked_count():
    over = android_deps._MAX_DETAIL_QUERIES + 50
    with tempfile.TemporaryDirectory() as d:
        apk = _make_apk(os.path.join(d, "capped.apk"), _coords(over))
        client, _cache, session = _client(d)
        _findings, _rules, stats = android_deps.scan(apk, osv_client=client)

    assert stats["dependencies_capped"] is True
    assert stats["unique_dependencies_detected"] == over, stats
    assert stats["unique_dependencies_checked"] == android_deps._MAX_DETAIL_QUERIES, (
        f"reported {stats['unique_dependencies_checked']} checked but the cap is "
        f"{android_deps._MAX_DETAIL_QUERIES} - this is the exact number main.py "
        f"prints to the user as 'SCA: checked N unique dependencies'"
    )
    assert len(session.batched) == stats["unique_dependencies_checked"], (
        f"{len(session.batched)} packages were really sent to OSV but the stats "
        f"claim {stats['unique_dependencies_checked']}"
    )


def test_uncapped_scan_reports_detected_equals_checked():
    with tempfile.TemporaryDirectory() as d:
        apk = _make_apk(os.path.join(d, "small.apk"), _coords(12))
        client, _cache, session = _client(d)
        _findings, _rules, stats = android_deps.scan(apk, osv_client=client)

    assert stats["dependencies_capped"] is False
    assert stats["unique_dependencies_detected"] == 12
    assert stats["unique_dependencies_checked"] == 12
    assert len(session.batched) == 12


def test_empty_apk_stats_still_carry_both_counts():
    """The early `if not deduped: return` path must not drop keys main.py reads."""
    with tempfile.TemporaryDirectory() as d:
        apk = _make_apk(os.path.join(d, "empty.apk"), [])
        client, _cache, _session = _client(d)
        _findings, _rules, stats = android_deps.scan(apk, osv_client=client)

    for key in ("total_dependencies_detected", "unique_dependencies_detected",
                "unique_dependencies_checked", "dependencies_capped",
                "cves_found", "vulnerable_dependencies"):
        assert key in stats, f"stats missing {key} - main.py reads it"
    assert stats["unique_dependencies_detected"] == 0
    assert stats["unique_dependencies_checked"] == 0


def test_main_py_surfaces_the_cap_on_the_android_path():
    """Structural guard over the shipped main.py source."""
    main_py = Path(__file__).resolve().parent.parent / "narvy" / "main.py"
    src = main_py.read_text()

    start = src.index("sca_android_deps.scan(")
    block = src[start:start + 2000]
    assert "dependencies_capped" in block, (
        "main.py's Android SCA block never reads stats['dependencies_capped'] - "
        "a capped (incomplete) scan would print as if it were complete"
    )
    assert "SCA is INCOMPLETE" in block, (
        "main.py's Android SCA block does not print an INCOMPLETE warning"
    )
    assert "unique_dependencies_detected" in block, (
        "main.py's Android SCA block never shows the pre-cap total, so the user "
        "cannot see how many dependencies went unchecked"
    )
    warn_idx = block.index("SCA is INCOMPLETE")
    assert "console.print" in block[max(0, warn_idx - 400):warn_idx], (
        "the INCOMPLETE warning is not printed via console.print - a "
        "logger.warning here is invisible/mangled under rich Progress"
    )


def test_android_path_does_not_regress_the_osv_batch_cache_false_negative():
    """Two scans of the same APK with a warm cache must report the same CVEs."""
    coords = [("com.squareup.okhttp3", "okhttp", "4.9.0"),
              ("com.google.code.gson", "gson", "2.8.5"),
              ("org.jetbrains.kotlinx", "kotlinx-coroutines-core", "1.6.0")]
    vulnerable = [("com.squareup.okhttp3:okhttp", "4.9.0")]
    with tempfile.TemporaryDirectory() as d:
        apk = _make_apk(os.path.join(d, "twice.apk"), coords)
        client, _cache, session = _client(d, vulnerable=vulnerable)

        first, _r, s1 = android_deps.scan(apk, osv_client=client)
        second, _r2, s2 = android_deps.scan(apk, osv_client=client)

        assert session.batched, "first run should have used the batch endpoint"
        batched_after_first = len(session.batched)
        assert len(session.batched) == batched_after_first

    assert s1["cves_found"] == 1, s1
    assert s2["cves_found"] == s1["cves_found"], (
        f"second scan of the identical APK found {s2['cves_found']} CVEs vs "
        f"{s1['cves_found']} on the first - the batch-cache false-negative is back"
    )
    assert {f["rule_id"] for f in second} == {f["rule_id"] for f in first}


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"PASS: {len(fns)} Android SCA cap-honesty tests OK")
