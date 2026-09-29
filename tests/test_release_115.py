"""1.1.5: dependency check against the Narvy EU OSV mirror, failure = incomplete, iOS without GitHub.

No real network: every HTTP exchange goes to a local http.server thread or a stub.
"""
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from rich.console import Console

from narvy import main as narvy_main
from narvy.sca import ios_deps, osv_client, web_deps
from narvy.sca.ios_deps import _IOSDep
from narvy.sca.osv_client import OSVCache, OSVClient

NARVY_LINE = ("Checking dependencies against Narvy's EU vulnerability database "
              "(sends package names and versions only, never code)...")


# --- local OSV-compatible server -------------------------------------------

class _Mirror:
    """Scripted OSV-compatible server; `behave(path, body)` -> (status, headers, payload)."""

    def __init__(self, behave):
        self.behave = behave
        self.requests = []
        mirror = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                mirror.requests.append((self.path, body, dict(self.headers)))
                status, headers, payload = mirror.behave(self.path, body)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/api/v1/osv"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.server.shutdown()
        self.server.server_close()

    def paths(self):
        return [p for p, _, _ in self.requests]


_SNAP = {"X-OSV-Snapshot": "2026-09-29T05:10:01Z", "X-OSV-Snapshot-Age-Hours": "1.5"}

_VULN = {
    "id": "GHSA-test-0001",
    "aliases": ["CVE-2024-0001"],
    "summary": "test advisory",
    "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}],
}


def _vulnerable(names):
    """Healthy mirror: packages in `names` have _VULN, everything else is clean."""
    def behave(path, body):
        if path.endswith("/querybatch"):
            res = [{"vulns": [{"id": _VULN["id"], "modified": "2026-01-01T00:00:00Z"}]}
                   if q["package"]["name"] in names else {} for q in body["queries"]]
            return 200, _SNAP, {"results": res}
        if body["package"]["name"] in names:
            return 200, _SNAP, {"vulns": [_VULN]}
        return 200, _SNAP, {}
    return behave


def _stale(path, body):
    return 503, {}, {"code": 14, "message": "mirror snapshot is 71h old", "error": "mirror_stale",
                     "snapshot_utc": "2026-09-26T06:00:00Z"}


@pytest.fixture
def cache(tmp_path):
    return OSVCache(db_path=tmp_path / "osv_cache.db")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("OSV_API_URL", "OSV_BATCH_API_URL", "NARVY_GITHUB_ADVISORIES", "GITHUB_TOKEN"):
        monkeypatch.delenv(k, raising=False)


def _npm_project(tmp_path, deps):
    pk = {"": {"name": "app"}}
    for name, ver in deps:
        pk[f"node_modules/{name}"] = {"version": ver}
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": pk}))
    return str(tmp_path)


# --- endpoint resolution ------------------------------------------------------

def test_default_endpoint_is_narvy_eu_mirror(cache):
    q, b = osv_client.resolve_osv_endpoints(None, None)
    assert q == "https://narvy.io/api/v1/osv/query"
    assert b == "https://narvy.io/api/v1/osv/querybatch"
    c = OSVClient(cache=cache)
    assert (c.api_url, c.batch_url) == (q, b)


def test_env_full_query_url_kept_as_is_and_batch_follows(monkeypatch, cache):
    monkeypatch.setenv("OSV_API_URL", "https://api.osv.dev/v1/query")
    c = OSVClient(cache=cache)
    assert c.api_url == "https://api.osv.dev/v1/query"
    assert c.batch_url == "https://api.osv.dev/v1/querybatch"


def test_env_bare_base_gets_paths_appended(monkeypatch, cache):
    monkeypatch.setenv("OSV_API_URL", "https://osv.internal.example/mirror/")
    c = OSVClient(cache=cache)
    assert c.api_url == "https://osv.internal.example/mirror/query"
    assert c.batch_url == "https://osv.internal.example/mirror/querybatch"


def test_env_explicit_batch_url_wins(monkeypatch, cache):
    monkeypatch.setenv("OSV_API_URL", "https://a.example/v1")
    monkeypatch.setenv("OSV_BATCH_API_URL", "https://b.example/v1/querybatch")
    c = OSVClient(cache=cache)
    assert c.api_url == "https://a.example/v1/query"
    assert c.batch_url == "https://b.example/v1/querybatch"


def test_user_agent_carries_no_internal_info(cache):
    ua = OSVClient(cache=cache)._session.headers["User-Agent"]
    import re
    assert re.fullmatch(r"narvy-cli/[0-9.]+ \(dependency check; \+https://narvy\.io\)", ua), ua


# --- console line ---------------------------------------------------------------

def test_egress_notice_default_is_exact_text():
    assert osv_client.egress_notice("https://narvy.io/api/v1/osv/query") == NARVY_LINE
    assert osv_client.egress_notice() == NARVY_LINE


def test_egress_notice_names_other_host_and_does_not_claim_narvy():
    line = osv_client.egress_notice("https://api.osv.dev/v1/query")
    assert "api.osv.dev" in line and "Narvy" not in line
    assert "package names and versions only, never code" in line


def test_egress_line_printed_on_stderr_console(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(narvy_main, "console", Console(file=buf, width=300, color_system=None))
    monkeypatch.setattr(osv_client, "_default_client", None)
    narvy_main._print_sca_egress()
    assert NARVY_LINE in buf.getvalue()


# --- healthy mirror ------------------------------------------------------------

def test_healthy_mirror_finds_vuln_and_records_snapshot(tmp_path, cache):
    with _Mirror(_vulnerable({"lodash"})) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        findings, _, stats = web_deps.scan(_npm_project(tmp_path, [("lodash", "4.17.0"), ("ms", "2.1.3")]), osv_client=c)
    assert [f["rule_id"] for f in findings] == ["SCA-CVE-2024-0001"]
    assert stats["osv_unreachable"] is False
    assert stats["vulnerability_db"]["snapshot_utc"] == "2026-09-29T05:10:01Z"
    assert stats["vulnerability_db"]["snapshot_age_hours"] == 1.5
    assert narvy_main._sca_coverage(stats)["status"] == "complete"
    # Only names/ecosystems/versions leave the machine.
    for path, body, _ in m.requests:
        for q in body.get("queries", [body]):
            assert set(q) == {"package", "version"} and set(q["package"]) == {"name", "ecosystem"}


# --- failures are INCOMPLETE, never clean ---------------------------------------

def test_503_stale_mirror_is_degraded_not_clean(tmp_path, cache):
    with _Mirror(_stale) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        findings, _, stats = web_deps.scan(_npm_project(tmp_path, [("a", "1.0.0"), ("b", "2.0.0")]), osv_client=c)
    assert findings == []
    assert stats["osv_unreachable"] is True
    assert stats["osv_dependencies_unresolved"] == 2
    cov = narvy_main._sca_coverage(stats)
    assert cov["status"] == "degraded" and "osv_unreachable" in cov["degraded_reasons"]
    assert cov["vulnerability_db"]["last_error"] == "mirror_stale"
    assert cov["vulnerability_db"]["snapshot_utc"] == "2026-09-26T06:00:00Z"
    # The batch failed; the circuit then stops further calls for this run.
    assert m.paths() == ["/api/v1/osv/querybatch"]


def test_batch_failure_never_means_no_vulns(cache):
    with _Mirror(_stale) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        res = c.has_any_vuln_batch([("x", "1"), ("y", "2")], ecosystem="npm")
    assert res == {("x", "1"): True, ("y", "2"): True}
    assert c.batch_failures == 1


def test_429_retries_once_honouring_retry_after(cache):
    calls = {"n": 0}

    def behave(path, body):
        calls["n"] += 1
        if calls["n"] == 1:
            return 429, {"Retry-After": "3"}, {"code": 8, "message": "slow down"}
        return 200, _SNAP, {"vulns": [_VULN]}

    slept = []
    with _Mirror(behave) as m:
        c = OSVClient(cache=cache, api_url=m.base, sleep=slept.append)
        got = c.query("lodash", "4.17.0", "npm")
    assert slept == [3.0]
    assert len(got) == 1 and c.query_failures_no_cache == 0


def test_429_persistent_is_incomplete_and_retry_bounded(tmp_path, cache):
    slept = []
    with _Mirror(lambda p, b: (429, {"Retry-After": "3600"}, {"code": 8})) as m:
        c = OSVClient(cache=cache, api_url=m.base, sleep=slept.append)
        _, _, stats = web_deps.scan(_npm_project(tmp_path, [("a", "1.0.0")]), osv_client=c)
    assert slept and max(slept) <= 10.0
    assert stats["osv_unreachable"] is True
    assert stats["vulnerability_db"]["last_error"] == "rate_limited"
    assert narvy_main._sca_coverage(stats)["status"] == "degraded"


def test_unreachable_server_is_incomplete(tmp_path, cache):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    c = OSVClient(cache=cache, api_url=f"http://127.0.0.1:{port}/osv", timeout=2)
    _, _, stats = web_deps.scan(_npm_project(tmp_path, [("a", "1.0.0"), ("b", "1.0.0")]), osv_client=c)
    assert stats["osv_dependencies_unresolved"] == 2
    assert stats["vulnerability_db"]["last_error"] == "unreachable"
    assert narvy_main._sca_coverage(stats)["status"] == "degraded"


def test_400_is_incomplete(cache):
    with _Mirror(lambda p, b: (400, {}, {"code": 3, "message": "invalid ecosystem"})) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        assert c.query("a", "1.0.0", "npm") == []
    assert c.query_failures_no_cache == 1 and c.last_error == "bad_request"


def test_404_wrong_endpoint_is_incomplete(cache):
    with _Mirror(lambda p, b: (404, {}, {"error": "not found"})) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        c.query("a", "1.0.0", "npm")
        c.query("b", "1.0.0", "npm")
    assert c.query_failures_no_cache == 2
    assert len(m.requests) == 1  # circuit open after the first 404


def test_stale_cache_fallback_is_flagged(tmp_path, cache):
    cache.put("a", "1.0.0", "npm", [_VULN])
    import sqlite3
    with sqlite3.connect(str(cache.db_path)) as conn:
        conn.execute("UPDATE osv_cache SET cached_at = 0")
    with _Mirror(_stale) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        findings, _, stats = web_deps.scan(_npm_project(tmp_path, [("a", "1.0.0")]), osv_client=c)
    assert len(findings) == 1
    assert stats["osv_stale_cache_served"] == 1
    cov = narvy_main._sca_coverage(stats)
    assert "osv_stale_cache" in cov["degraded_reasons"] and cov["dependencies_from_stale_cache"] == 1


# --- batch size ------------------------------------------------------------------

def test_batch_split_at_1000(cache):
    with _Mirror(_vulnerable(set())) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        pkgs = [(f"p{i}", "1.0.0") for i in range(2500)]
        res = c.has_any_vuln_batch(pkgs, ecosystem="npm")
    sizes = [len(b["queries"]) for p, b, _ in m.requests if p.endswith("/querybatch")]
    assert sizes == [1000, 1000, 500]
    assert not any(res.values()) and c.batch_failures == 0


def test_batch_split_keeps_body_under_cap(cache, monkeypatch):
    monkeypatch.setattr(osv_client, "MAX_BATCH_BODY_BYTES", 5000)
    with _Mirror(_vulnerable(set())) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        c.has_any_vuln_batch([(f"package-{i:04d}", "1.0.0") for i in range(300)], ecosystem="npm")
    for p, b, _ in m.requests:
        assert len(json.dumps(b)) <= 5000
    assert sum(len(b["queries"]) for _, b, _ in m.requests) == 300


def test_batch_413_splits_in_halves_down_to_one(cache):
    """Batches of more than 2 queries or containing 'huge' get 413; a lone 'huge' still 413s."""
    def behave(path, body):
        if path.endswith("/querybatch"):
            qs = body["queries"]
            if len(qs) > 2 or any(q["package"]["name"] == "huge" for q in qs):
                return 413, {}, {"code": 8, "message": "Batch too expensive for one request; split it into smaller batches."}
            return 200, _SNAP, {"results": [{"vulns": [{"id": "X"}]} if q["package"]["name"] == "bad" else {} for q in qs]}
        if body["package"]["name"] == "huge":
            return 413, {}, {"code": 8, "message": "too expensive"}
        return 200, _SNAP, {}

    with _Mirror(behave) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        pkgs = [("a", "1"), ("b", "1"), ("bad", "1"), ("huge", "1"), ("c", "1")]
        res = c.has_any_vuln_batch(pkgs, ecosystem="npm")
        sizes = [len(b["queries"]) for p, b, _ in m.requests if p.endswith("/querybatch")]
        # 5 -> 2 ok + 3 (413) -> 1 ok + 2 (413) -> 1 (413, alone) + 1 ok
        assert sizes == [5, 2, 3, 1, 2, 1, 1]
        # Split answers are kept: clean deps clean, the vulnerable one flagged,
        # the lone 413 one deferred (never clean).
        assert res == {("a", "1"): False, ("b", "1"): False, ("bad", "1"): True,
                       ("huge", "1"): True, ("c", "1"): False}
        before = c.counters()
        c.query("huge", "1", "npm")
        stats = c.coverage_stats(before)
    assert stats["osv_dependencies_unresolved"] == 1
    assert stats["vulnerability_db"]["last_error"] == "too_large"
    assert narvy_main._sca_coverage(dict(stats, unique_dependencies_checked=5))["status"] == "degraded"
    # A 413 is not an outage: the client keeps working afterwards.
    assert c._circuit_open is False


def test_413_through_scan_is_incomplete_not_clean(tmp_path, cache):
    def behave(path, body):
        return 413, {}, {"code": 8, "message": "too expensive"}
    with _Mirror(behave) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        findings, _, stats = web_deps.scan(_npm_project(tmp_path, [("a", "1.0.0"), ("b", "1.0.0")]), osv_client=c)
    assert findings == [] and stats["osv_dependencies_unresolved"] == 2
    assert narvy_main._sca_coverage(stats)["status"] == "degraded"


def test_429_budget_is_bounded_across_many_batches(cache):
    slept = []
    with _Mirror(lambda p, b: (429, {"Retry-After": "60"}, {"code": 8})) as m:
        c = OSVClient(cache=cache, api_url=m.base, sleep=slept.append)
        c.has_any_vuln_batch([(f"p{i}", "1") for i in range(5000)], ecosystem="npm")
        for i in range(20):
            c.query(f"q{i}", "1", "npm")
    # One retry, then the circuit opens: 2 requests total, one sleep capped at 10 s.
    assert len(m.requests) == 2 and slept == [10.0]


# --- ecosystems the mirror does not carry -----------------------------------------

def test_unsupported_ecosystem_not_sent_and_counted_unverified(cache):
    with _Mirror(_vulnerable(set())) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        before = c.counters()
        assert c.has_any_vuln_batch([("Alamofire", "4.0.0")], ecosystem="CocoaPods") == {("Alamofire", "4.0.0"): True}
        assert c.query("Alamofire", "4.0.0", "CocoaPods") == []
        assert c.query("http", "1.0.0", "Pub") == []
        stats = c.coverage_stats(before)
    assert m.requests == []
    assert stats["osv_unsupported_ecosystem"] == 2
    cov = narvy_main._sca_coverage(dict(stats, unique_dependencies_checked=2, total_dependencies_detected=2))
    assert "ecosystem_not_covered" in cov["degraded_reasons"]
    assert cov["dependencies_unverified"] == 2 and cov["status"] != "complete"


# --- iOS: no api.github.com by default ---------------------------------------------

class _GHSpy:
    def __init__(self):
        self.calls = []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))

        class R:
            status_code = 200
            headers = {"X-RateLimit-Remaining": "50"}
            text = "[]"

            def json(self_inner):
                return []
        return R()


def test_ios_makes_zero_github_calls_by_default(monkeypatch, cache, tmp_path):
    monkeypatch.setattr(ios_deps, "_GH_CACHE_DIR", tmp_path / "gh")
    spy = _GHSpy()
    monkeypatch.setattr(ios_deps.requests, "get", spy)
    with _Mirror(_vulnerable({"CocoaMQTT"})) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        deps = [
            _IOSDep("Alamofire", "5.8.0", "podfile.lock", "github.com/Alamofire/Alamofire"),
            _IOSDep("CocoaMQTT", "2.2.1", "podfile.lock", None),
            _IOSDep("SomeInternalPod", "1.0.0", "podfile.lock", None),
        ]
        findings, _, stats = ios_deps._scan_deps(deps, c)
    assert spy.calls == []
    assert stats["github_queries_made"] == 0 and stats["github_advisories_enabled"] is False
    # Bare-name SwiftURL lookup still finds advisories published under a bare name.
    assert [f["sca"]["package"] for f in findings] == ["CocoaMQTT"]
    sent = {q["package"]["name"] for p, b, _ in m.requests for q in b.get("queries", [b])}
    assert sent == {"github.com/Alamofire/Alamofire", "CocoaMQTT", "SomeInternalPod"}
    assert all(q["package"]["ecosystem"] == "SwiftURL" for p, b, _ in m.requests for q in b.get("queries", [b]))
    # Deps without a repo URL are unverified, not clean.
    assert stats["dependencies_unmapped"] == 2
    cov = narvy_main._sca_coverage(stats)
    assert "no_swifturl_mapping" in cov["degraded_reasons"] and cov["dependencies_unverified"] == 2


def test_ios_github_lookup_is_opt_in_and_uses_token(monkeypatch, cache, tmp_path):
    monkeypatch.setenv("NARVY_GITHUB_ADVISORIES", "1")
    monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
    monkeypatch.setattr(ios_deps, "_GH_CACHE_DIR", tmp_path / "gh")
    spy = _GHSpy()
    monkeypatch.setattr(ios_deps.requests, "get", spy)
    with _Mirror(_vulnerable(set())) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        _, _, stats = ios_deps._scan_deps([_IOSDep("Foo", "1.0.0", "podfile.lock", None)], c)
    assert len(spy.calls) == 1 and spy.calls[0][0] == "https://api.github.com/advisories"
    assert spy.calls[0][1]["headers"]["Authorization"] == "Bearer t0ken"
    assert stats["github_advisories_enabled"] is True


def test_ios_mirror_down_is_degraded(monkeypatch, cache, tmp_path):
    monkeypatch.setattr(ios_deps.requests, "get", _GHSpy())
    with _Mirror(_stale) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        _, _, stats = ios_deps._scan_deps(
            [_IOSDep("Alamofire", "5.8.0", "package.resolved", "github.com/Alamofire/Alamofire")], c)
    assert stats["osv_unreachable"] is True
    assert narvy_main._sca_coverage(stats)["status"] == "degraded"


# --- end to end through the CLI ---------------------------------------------------

def _cli_env(tmp_path, base):
    env = dict(os.environ)
    env.update({"HOME": str(tmp_path / "home"), "USERPROFILE": str(tmp_path / "home"),
                "NARVY_TELEMETRY": "0", "OSV_API_URL": base})
    env.pop("OSV_BATCH_API_URL", None)
    return env


def test_cli_json_stdout_stays_clean_and_reports_stale_mirror(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.js").write_text("console.log('hi')\n")
    _npm_project(proj, [("lodash", "4.17.0")])
    with _Mirror(_stale) as m:
        out = subprocess.run(
            [sys.executable, "-m", "narvy", "scan", str(proj), "--output", "json", "--file", "-",
             "--fail-on", "critical"],
            capture_output=True, text=True, timeout=600, env=_cli_env(tmp_path, m.base))
    data = json.loads(out.stdout)
    cov = data["summary"]["sca_coverage"]
    assert cov["status"] == "degraded"
    assert cov["vulnerability_db"]["last_error"] == "mirror_stale"
    assert out.returncode == 2, out.stderr[-2000:]
    import re
    err = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", out.stderr).split())
    assert "OSV-compatible server at 127.0.0.1" in err
    assert "SCA is INCOMPLETE" in err and "stale mirror" in err


# --- log volume when the database fails (QA 1.1.5: 42-44 lines, one per dep) -----

def _osv_warnings(caplog):
    return [r.getMessage() for r in caplog.records
            if r.name.startswith("narvy.sca") and r.levelno >= 30]


@pytest.mark.parametrize("behave", [
    _stale,
    lambda p, b: (429, {"Retry-After": "0"}, {"code": 8}),
    lambda p, b: (404, {}, {}),
])
def test_outage_logs_one_line_and_stops_querying(tmp_path, cache, caplog, behave):
    import logging
    caplog.set_level(logging.DEBUG)
    deps = [(f"pkg{i}", "1.0.0") for i in range(40)]
    with _Mirror(behave) as m:
        c = OSVClient(cache=cache, api_url=m.base, sleep=lambda s: None)
        findings, _, stats = web_deps.scan(_npm_project(tmp_path, deps), osv_client=c)
    warnings = _osv_warnings(caplog)
    assert len([w for w in warnings if "unavailable" in w]) == 1, warnings
    assert not [w for w in warnings if "OSV query failed" in w or "batch query failed" in w]
    assert len(warnings) == 1, warnings
    # the circuit is open after the first failure: nothing else is sent
    assert len([p for p in m.paths() if not p.endswith("querybatch")]) == 0
    assert len(m.paths()) <= 2          # the batch (+ one 429 retry at most)
    # and the result is still incomplete, never clean
    assert findings == []
    assert stats["osv_dependencies_unresolved"] == 40
    assert c.skipped_after_circuit == 40
    assert narvy_main._sca_coverage(stats)["status"] == "degraded"


def test_unreachable_logs_one_line(tmp_path, cache, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    c = OSVClient(cache=cache, api_url=f"http://127.0.0.1:{port}/osv", timeout=2)
    _, _, stats = web_deps.scan(_npm_project(tmp_path, [(f"p{i}", "1.0.0") for i in range(30)]),
                                osv_client=c)
    warnings = _osv_warnings(caplog)
    assert len(warnings) == 1 and "unavailable (unreachable" in warnings[0], warnings
    assert stats["osv_dependencies_unresolved"] == 30


def test_per_dependency_400_logged_once_but_each_counted(tmp_path, cache, caplog):
    import logging
    caplog.set_level(logging.DEBUG)

    def behave(path, body):
        if path.endswith("/querybatch"):
            return 200, _SNAP, {"results": [{"vulns": [{"id": "X"}]}] * len(body["queries"])}
        return 400, {}, {"code": 3, "message": "invalid version"}
    with _Mirror(behave) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        _, _, stats = web_deps.scan(_npm_project(tmp_path, [(f"p{i}", "1.0.0") for i in range(12)]),
                                    osv_client=c)
    warnings = _osv_warnings(caplog)
    assert len([w for w in warnings if "OSV query failed" in w]) == 1, warnings
    assert stats["osv_dependencies_unresolved"] == 12   # 400 does not open the circuit
    assert len([p for p in m.paths() if p.endswith("/query")]) == 12


# --- per-scan dependency cap (20,000, same as the platform) + pacing ------------

def test_dependency_cap_matches_the_platform():
    from narvy.sca import android_deps
    assert osv_client.MAX_DEPENDENCIES_PER_SCAN == 20_000
    assert web_deps._MAX_DETAIL_QUERIES == android_deps._MAX_DETAIL_QUERIES == 20_000


def test_600_dependencies_are_all_checked_not_capped(tmp_path, cache):
    """A netbox-sized project (554 unique deps) used to be capped at 400 (partial)."""
    deps = [(f"pkg{i}", "1.0.0") for i in range(600)]
    with _Mirror(_vulnerable({"pkg7"})) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        findings, _, stats = web_deps.scan(_npm_project(tmp_path, deps), osv_client=c)
    assert stats["dependencies_capped"] is False
    assert stats["unique_dependencies_checked"] == 600
    sizes = [len(b["queries"]) for p, b, _ in m.requests if p.endswith("/querybatch")]
    assert sizes == [600]
    assert len(findings) == 1
    assert narvy_main._sca_coverage(stats)["status"] == "complete"


def test_over_cap_is_partial_and_batches_stay_at_1000(tmp_path, cache, monkeypatch):
    monkeypatch.setattr(web_deps, "_MAX_DETAIL_QUERIES", 2500)
    deps = [(f"pkg{i}", "1.0.0") for i in range(2600)]
    with _Mirror(_vulnerable(set())) as m:
        c = OSVClient(cache=cache, api_url=m.base)
        _, _, stats = web_deps.scan(_npm_project(tmp_path, deps), osv_client=c)
    sizes = [len(b["queries"]) for p, b, _ in m.requests if p.endswith("/querybatch")]
    assert sizes == [1000, 1000, 500]
    assert stats["dependencies_capped"] is True
    assert stats["unique_dependencies_detected"] == 2600 and stats["unique_dependencies_checked"] == 2500
    cov = narvy_main._sca_coverage(stats)
    assert cov["status"] != "complete" and "osv_dependency_cap" in cov["degraded_reasons"]


class _PaceSession:
    def __init__(self):
        self.headers = {}
        self.posts = []

    def post(self, url, json=None, timeout=None):
        self.posts.append(url)

        class R:
            status_code = 200
            headers = {}

            def raise_for_status(self):
                pass

            def json(self_inner):
                if url.endswith("/querybatch"):
                    return {"results": [{} for _ in json["queries"]]}
                return {}
        return R()


class _FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def test_narvy_endpoint_batches_are_paced_under_30_per_minute(cache):
    clk = _FakeClock()
    s = _PaceSession()
    c = OSVClient(cache=cache, api_url="https://narvy.io/api/v1/osv", session=s,
                  sleep=clk.sleep, clock=clk)
    c.has_any_vuln_batch([(f"p{i}", "1") for i in range(30_000)], ecosystem="npm")
    assert len(s.posts) == 30
    # 25 per rolling minute: the 26th waits for the window, never a burst of 30.
    assert clk.t - 1000.0 >= 60.0
    assert c.batch_failures == 0 and not c._circuit_open


def test_small_scan_on_narvy_endpoint_is_not_slowed(cache):
    clk = _FakeClock()
    c = OSVClient(cache=cache, api_url="https://narvy.io/api/v1/osv", session=_PaceSession(),
                  sleep=clk.sleep, clock=clk)
    for i in range(50):
        c.query(f"q{i}", "1", "npm")
        clk.t += 0.1   # real round trip
    assert clk.slept == []


def test_other_servers_are_not_paced(cache):
    clk = _FakeClock()
    s = _PaceSession()
    c = OSVClient(cache=cache, api_url="https://api.osv.dev/v1", session=s,
                  sleep=clk.sleep, clock=clk)
    c.has_any_vuln_batch([(f"p{i}", "1") for i in range(30_000)], ecosystem="npm")
    assert len(s.posts) == 30 and clk.slept == []
