"""has_any_vuln_batch keeps cached packages reportable. Offline."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.sca.osv_client import OSVCache, OSVClient


class _StubSession:
    """Answers the batch endpoint from a fixed table and records every call."""

    def __init__(self, vulnerable):
        self.vulnerable = set(vulnerable)   # {(name, version), ...}
        self.batched = []                   # (name, version) sent to /querybatch
        self.queried = []                   # (name, version) sent to /query
        self.headers = {}

    def update(self, *_a, **_k):
        pass

    def post(self, url, json=None, timeout=None):
        body = json or {}
        if "queries" in body:                     # /v1/querybatch
            results = []
            for q in body["queries"]:
                key = (q["package"]["name"], q["version"])
                self.batched.append(key)
                results.append({"vulns": [{"id": "STUB-1"}]} if key in self.vulnerable else {})
            return _StubResponse({"results": results})
        # /v1/query (single package, full details)
        key = (body["package"]["name"], body["version"])
        self.queried.append(key)
        if key not in self.vulnerable:
            return _StubResponse({"vulns": []})
        return _StubResponse({"vulns": [{
            "id": "STUB-1",
            "summary": "stub advisory",
            "affected": [{
                "package": {"name": key[0], "ecosystem": "crates.io"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }],
        }]})


class _StubResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _client(tmpdir: str, vulnerable=()) -> tuple:
    cache = OSVCache(db_path=Path(tmpdir) / "osv.db")
    session = _StubSession(vulnerable)
    client = OSVClient(cache=cache, session=session)
    return client, cache, session


def test_cached_vulnerable_package_still_reported_when_list_is_mixed():
    """A cached-and-vulnerable package must come back True in a mixed call."""
    with tempfile.TemporaryDirectory() as d:
        client, cache, session = _client(d)
        cache.put("rsa", "0.9.10", "crates.io", [{"id": "CVE-2023-49092"}])

        result = client.has_any_vuln_batch(
            [("rsa", "0.9.10"), ("serde", "1.0.999999")],
            ecosystem="crates.io",
        )

    assert result[("rsa", "0.9.10")] is True, (
        "cached-and-vulnerable package reported as clean"
    )
    assert ("rsa", "0.9.10") not in session.batched
    assert ("serde", "1.0.999999") in session.batched


def test_cached_clean_package_also_marked_true_and_answered_from_cache():
    """True here means "let query() answer", and query() serves it from cache."""
    with tempfile.TemporaryDirectory() as d:
        client, cache, session = _client(d)
        cache.put("serde", "1.0.197", "crates.io", [])   # cached, no vulns

        result = client.has_any_vuln_batch(
            [("serde", "1.0.197"), ("tokio", "1.36.0")],
            ecosystem="crates.io",
        )
        assert result[("serde", "1.0.197")] is True
        assert ("serde", "1.0.197") not in session.batched
        assert client.query("serde", "1.0.197", ecosystem="crates.io") == []


def test_all_cached_short_circuits_without_any_network_call():
    with tempfile.TemporaryDirectory() as d:
        client, cache, session = _client(d)
        cache.put("rsa", "0.9.10", "crates.io", [{"id": "CVE-2023-49092"}])
        cache.put("serde", "1.0.197", "crates.io", [])

        result = client.has_any_vuln_batch(
            [("rsa", "0.9.10"), ("serde", "1.0.197")],
            ecosystem="crates.io",
        )
        assert result == {("rsa", "0.9.10"): True, ("serde", "1.0.197"): True}
        assert session.batched == [], "no batch call should be made when everything is cached"


def test_uncached_vulnerable_package_still_detected_via_batch():
    """The batch endpoint's answer still drives the result for uncached packages."""
    with tempfile.TemporaryDirectory() as d:
        client, _cache, session = _client(d, vulnerable=[("openssl", "0.10.55")])
        result = client.has_any_vuln_batch(
            [("openssl", "0.10.55"), ("serde", "1.0.197")],
            ecosystem="crates.io",
        )
    assert result[("openssl", "0.10.55")] is True
    assert result[("serde", "1.0.197")] is False


def test_second_identical_scan_reports_the_same_cves_as_the_first():
    """The same package list, run twice: a warm cache must not change the answer."""
    packages = [("openssl", "0.10.55"), ("serde", "1.0.197"), ("tokio", "1.36.0")]
    with tempfile.TemporaryDirectory() as d:
        client, _cache, _session = _client(d, vulnerable=[("openssl", "0.10.55")])

        def _run():
            has_vuln = client.has_any_vuln_batch(packages, ecosystem="crates.io")
            vulnerable = set()
            for name, version in packages:
                if not has_vuln.get((name, version)):
                    continue
                if client.query_dict(name, version, ecosystem="crates.io"):
                    vulnerable.add(name)
            return vulnerable

        first = _run()
        second = _run()

    assert first == {"openssl"}, first
    assert second == first, (
        f"second scan of the identical dependency set reported {second} but the "
        f"first reported {first} - SCA results must not decay with cache warmth"
    )


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"PASS: {len(fns)} OSV batch/cache regression tests OK")
