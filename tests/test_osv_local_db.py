"""Local OSV database (1.3.0): download per ecosystem, local matching, no package name sent."""

import base64
import hashlib
import io
import json
import os
import socket
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from narvy import main as narvy_main
from narvy.sca import osv_client, osv_localdb, web_deps
from narvy.sca.osv_client import LocalOSVClient, OSVClient


def _rec(vid, eco, name, events=None, versions=None, **extra):
    aff = {"package": {"ecosystem": eco, "name": name}}
    if events is not None:
        aff["ranges"] = [{"type": "SEMVER" if eco in ("npm", "Go", "crates.io") else "ECOSYSTEM",
                          "events": events}]
    if versions is not None:
        aff["versions"] = versions
    r = {"id": vid, "modified": "2026-10-01T00:00:00Z", "aliases": [], "summary": vid + " summary",
         "affected": [aff], "database_specific": {"severity": "HIGH"}}
    r.update(extra)
    return r


NPM_RECORDS = [
    _rec("GHSA-aaaa-0001", "npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}],
         aliases=["CVE-2021-23337"]),
    _rec("GHSA-aaaa-0002", "npm", "minimist", [{"introduced": "1.0.0"}, {"last_affected": "1.2.5"}]),
    _rec("GHSA-aaaa-0003", "npm", "ms", [{"introduced": "0"}, {"fixed": "2.0.0"}]),
    _rec("GHSA-aaaa-0004", "npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}], withdrawn="2026-01-01T00:00:00Z"),
    _rec("GHSA-aaaa-0005", "npm", "semver", [{"introduced": "7.0.0"}, {"fixed": "7.5.2"}]),
]
PYPI_RECORDS = [
    _rec("PYSEC-2023-0001", "PyPI", "Django", [{"introduced": "4.0"}, {"fixed": "4.2.4"}], aliases=["CVE-2023-0001"]),
    _rec("PYSEC-2023-0002", "PyPI", "zope.interface", versions=["5.0.0", "5.1.0"]),
    _rec("PYSEC-2023-0003", "PyPI", "requests", [{"introduced": "2.0.0"}, {"fixed": "2.31.0rc1"}]),
]


def _zip_bytes(records):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in records:
            zf.writestr(r["id"] + ".json", json.dumps(r))
    return buf.getvalue()


class _Export:
    """Local stand-in for osv-vulnerabilities.storage.googleapis.com; logs every request."""

    def __init__(self, files):
        self.files = dict(files)  # path -> bytes, or callable(handler)
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append({"path": self.path, "headers": dict(self.headers),
                                       "body_len": int(self.headers.get("content-length") or 0)})
                body = outer.files.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                if callable(body):
                    return body(self)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
                self.send_header("x-goog-hash", "crc32c=AAAA, md5=" + md5)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.server.shutdown()
        self.server.server_close()


def _npm_project(tmp_path, deps):
    d = tmp_path / "proj"
    d.mkdir()
    pk = {"name": "proj", "lockfileVersion": 3, "packages": {"": {"name": "proj"}}}
    for name, ver in deps:
        pk["packages"]["node_modules/" + name] = {"version": ver}
    (d / "package-lock.json").write_text(json.dumps(pk))
    (d / "package.json").write_text(json.dumps({"name": "proj", "dependencies": {n: v for n, v in deps}}))
    return str(d)


def _iso(hours_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - hours_ago * 3600))


def _build(tmp_path, eco, records, snapshot=None):
    p = osv_localdb.db_path(eco, tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    osv_localdb.build_db(eco, records, p, snapshot_utc=snapshot)
    return p


class _NoSockets:
    """Any outbound connection attempt fails the test."""

    def __init__(self, monkeypatch):
        self.attempts = []
        real_connect = socket.socket.connect

        def connect(sock, addr, *a, **k):
            self.attempts.append(addr)
            raise AssertionError("socket opened during a cached local scan: %r" % (addr,))

        def create_connection(addr, *a, **k):
            self.attempts.append(addr)
            raise AssertionError("socket opened during a cached local scan: %r" % (addr,))

        monkeypatch.setattr(socket.socket, "connect", connect)
        monkeypatch.setattr(socket.socket, "connect_ex", connect)
        monkeypatch.setattr(socket, "create_connection", create_connection)
        self._real = real_connect


@pytest.fixture
def dbdir(tmp_path, monkeypatch):
    d = tmp_path / "osvdb"
    monkeypatch.setenv("NARVY_OSV_DB_DIR", str(d))
    monkeypatch.setenv("NARVY_OSV_EXPORT_URL", "http://127.0.0.1:9")  # nothing listens there
    yield d
    osv_client.configure()


# --- matching -------------------------------------------------------------------

def test_local_matching_ranges_versions_withdrawn_and_pep503(tmp_path):
    _build(tmp_path, "npm", NPM_RECORDS)
    _build(tmp_path, "PyPI", PYPI_RECORDS)
    store = osv_localdb.LocalStore(directory=tmp_path, offline=True)
    npm, pypi = store.get("npm"), store.get("PyPI")
    assert npm.match_ids("npm", "lodash", "4.17.20") == ["GHSA-aaaa-0001"]  # 0004 withdrawn
    assert npm.match_ids("npm", "lodash", "4.17.21") == []
    assert npm.match_ids("npm", "minimist", "1.2.5") == ["GHSA-aaaa-0002"]  # last_affected inclusive
    assert npm.match_ids("npm", "minimist", "1.2.6") == []
    assert npm.match_ids("npm", "semver", "7.5.2-rc.1") == ["GHSA-aaaa-0005"]  # prerelease < fixed
    assert npm.match_ids("npm", "semver", "6.3.0") == []
    assert pypi.match_ids("PyPI", "django", "4.2.3") == ["PYSEC-2023-0001"]
    assert pypi.match_ids("PyPI", "Django", "4.2.4") == []
    assert pypi.match_ids("PyPI", "Zope_Interface", "5.1") == ["PYSEC-2023-0002"]  # name + PEP 440 equality
    assert pypi.match_ids("PyPI", "requests", "2.31.0b1") == ["PYSEC-2023-0003"]
    assert pypi.match_ids("PyPI", "requests", "2.31.0") == []


def test_cached_scan_opens_no_socket(tmp_path, dbdir, monkeypatch):
    _build(dbdir, "npm", NPM_RECORDS)
    project = _npm_project(tmp_path, [("lodash", "4.17.20"), ("ms", "2.1.3"), ("minimist", "1.2.5")])
    guard = _NoSockets(monkeypatch)
    osv_client.configure()
    client = osv_client.get_default_client()
    assert isinstance(client, LocalOSVClient)
    findings, _, stats = web_deps.scan(project)
    assert guard.attempts == []
    ids = sorted(f.get("cve_id") or f["rule_id"] for f in findings)
    assert len(findings) == 2, ids
    assert stats["osv_unreachable"] is False
    assert stats["vulnerability_db"]["source"] == "local"
    assert narvy_main._sca_coverage(stats)["status"] == "complete"


def test_cli_scan_with_cache_opens_no_socket(tmp_path, dbdir, monkeypatch, capsys):
    """Whole `narvy scan <dir> --output json` on a cached database: no connection at all."""
    _build(dbdir, "npm", NPM_RECORDS)
    project = _npm_project(tmp_path, [("lodash", "4.17.20")])
    out = tmp_path / "r.json"
    guard = _NoSockets(monkeypatch)
    monkeypatch.setattr("sys.argv", ["narvy", "scan", project, "--output", "json", "--file", str(out)])
    try:
        narvy_main.cli()
    except SystemExit as e:
        assert e.code in (0, None, 1)
    assert guard.attempts == []
    data = json.loads(out.read_text())
    assert "GHSA-aaaa-0001" in json.dumps(data) or "CVE-2021-23337" in json.dumps(data)


# --- offline --------------------------------------------------------------------

def test_offline_without_cache_is_incomplete_and_never_calls_an_api(tmp_path, dbdir, monkeypatch):
    project = _npm_project(tmp_path, [("lodash", "4.17.20"), ("ms", "2.1.3")])
    guard = _NoSockets(monkeypatch)
    osv_client.configure(offline=True)
    findings, _, stats = web_deps.scan(project)
    assert guard.attempts == []
    assert findings == []
    assert stats["osv_unreachable"] is True
    assert stats["osv_dependencies_unresolved"] == 2
    assert stats["vulnerability_db"]["last_error"] == "no_local_db_offline"
    cov = narvy_main._sca_coverage(stats)
    assert cov["status"] == "degraded"
    host, why = narvy_main._sca_db_problem(cov)
    assert "--offline" in why and "narvy db update" in why


def test_offline_uses_an_old_cache_and_reports_it_stale(tmp_path, dbdir, monkeypatch):
    _build(dbdir, "npm", NPM_RECORDS, snapshot=_iso(48))
    project = _npm_project(tmp_path, [("lodash", "4.17.20")])
    _NoSockets(monkeypatch)
    osv_client.configure(offline=True)
    findings, _, stats = web_deps.scan(project)
    assert len(findings) == 1
    assert stats["osv_stale_cache_served"] == 1
    assert stats["vulnerability_db"]["ecosystems"]["npm"]["stale"] is True


def test_offline_and_osv_api_are_mutually_exclusive(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["narvy", "scan", ".", "--offline", "--osv-api"])
    with pytest.raises(SystemExit) as e:
        narvy_main.cli()
    assert e.value.code != 0
    assert "not allowed with" in capsys.readouterr().err


# --- download -------------------------------------------------------------------

def test_download_sends_only_the_ecosystem_and_swaps_atomically(tmp_path):
    z = _zip_bytes(NPM_RECORDS)
    with _Export({"/npm/all.zip": z}) as ex:
        info = osv_localdb.download("npm", tmp_path, base=ex.base)
    assert info["records"] == len(NPM_RECORDS)
    assert [r["path"] for r in ex.requests] == ["/npm/all.zip"]
    hdrs = {k.lower() for k in ex.requests[0]["headers"]}
    assert hdrs <= {"host", "user-agent", "accept-encoding", "accept", "connection"}
    assert ex.requests[0]["body_len"] == 0
    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.startswith(".")) == ["npm.db", "npm.db.sha256.json"]


@pytest.mark.parametrize("bad", ["md5", "truncated", "not_zip", "empty_zip", "http500"])
def test_bad_download_keeps_the_previous_file(tmp_path, bad):
    old = _build(tmp_path, "npm", NPM_RECORDS[:1], snapshot=_iso(48))
    before = old.read_bytes()
    good = _zip_bytes(NPM_RECORDS)

    def serve(h):
        if bad == "http500":
            h.send_response(500)
            h.end_headers()
            return
        body = {"truncated": good, "not_zip": b"x" * 4096, "empty_zip": _zip_bytes([]),
                "md5": good}[bad]
        h.send_response(200)
        h.send_header("Content-Length", str(len(body) + (100 if bad == "truncated" else 0)))
        md5 = hashlib.md5(b"other" if bad == "md5" else body).digest()
        h.send_header("x-goog-hash", "md5=" + base64.b64encode(md5).decode())
        h.end_headers()
        h.wfile.write(body)

    with _Export({"/npm/all.zip": serve}) as ex:
        with pytest.raises(osv_localdb.LocalDBError):
            osv_localdb.download("npm", tmp_path, base=ex.base)
    assert old.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.startswith(".")) == ["npm.db", "npm.db.sha256.json"]


def test_failed_refresh_falls_back_to_previous_copy_as_stale(tmp_path, dbdir, monkeypatch):
    _build(dbdir, "npm", NPM_RECORDS, snapshot=_iso(48))
    project = _npm_project(tmp_path, [("lodash", "4.17.20")])
    osv_client.configure()  # online, export base points at a closed port
    findings, _, stats = web_deps.scan(project)
    assert len(findings) == 1
    assert stats["osv_stale_cache_served"] == 1
    assert stats["osv_unreachable"] is False


def test_missing_db_is_downloaded_then_reused(tmp_path, monkeypatch):
    project = _npm_project(tmp_path, [("lodash", "4.17.20")])
    with _Export({"/npm/all.zip": _zip_bytes(NPM_RECORDS)}) as ex:
        store = osv_localdb.LocalStore(directory=tmp_path / "db", base=ex.base)
        f1, _, s1 = web_deps.scan(project, osv_client=LocalOSVClient(store=store))
        store2 = osv_localdb.LocalStore(directory=tmp_path / "db", base=ex.base)
        f2, _, s2 = web_deps.scan(project, osv_client=LocalOSVClient(store=store2))
    assert len(ex.requests) == 1  # second run: file fresh, no request
    assert len(f1) == len(f2) == 1


def test_download_without_cache_failing_is_incomplete(tmp_path, dbdir):
    project = _npm_project(tmp_path, [("lodash", "4.17.20")])
    osv_client.configure()
    findings, _, stats = web_deps.scan(project)
    assert findings == []
    assert stats["osv_unreachable"] is True
    assert stats["vulnerability_db"]["last_error"] == "download_failed"


# --- --osv-api ------------------------------------------------------------------

def test_osv_api_flag_selects_the_network_client_and_warns(monkeypatch):
    buf = io.StringIO()
    from rich.console import Console
    monkeypatch.setattr(narvy_main, "console", Console(file=buf, width=300, color_system=None))

    class A:
        osv_api = True
        offline = False

    narvy_main._configure_osv(A())
    try:
        c = osv_client.get_default_client()
        assert type(c) is OSVClient
        assert "names and versions of your dependencies are sent to narvy.io" in buf.getvalue()
    finally:
        osv_client.configure()
    assert isinstance(osv_client.get_default_client(), LocalOSVClient)


def test_local_client_has_no_network_session():
    c = LocalOSVClient(store=osv_localdb.LocalStore(directory=Path("/nonexistent-narvy"), offline=True))
    with pytest.raises(RuntimeError):
        c._session.post("https://api.osv.dev/v1/query", json={})


# --- 1.3.0 review: corrupt files, 7-day limit, case, lock, read-only, orphans, offline --

GO_RECORDS = [
    _rec("GO-2020-0015", "Go", "golang.org/x/text", [{"introduced": "0"}, {"fixed": "0.3.3"}],
         aliases=["CVE-2020-14040"]),
    _rec("GO-2021-0113", "Go", "golang.org/x/text", [{"introduced": "0"}, {"fixed": "0.3.7"}],
         aliases=["CVE-2021-38561"]),
]


def _go_tiny(tmp_path):
    """The reviewer's go_tiny repro: one go.mod requiring golang.org/x/text v0.3.0."""
    d = tmp_path / "go_tiny"
    d.mkdir()
    (d / "go.mod").write_text("module example.com/tiny\n\ngo 1.20\n\nrequire golang.org/x/text v0.3.0\n")
    (d / "main.go").write_text('package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hi") }\n')
    return d


def _corrupt_pages(path, keep_sidecar_valid):
    """Overwrite the middle of the file with junk (meta page intact). With
    keep_sidecar_valid the integrity record is rewritten to match, as if the
    damage happened before it was computed: only the SQL reads can catch it."""
    data = bytearray(path.read_bytes())
    mid = len(data) // 2
    data[4096:len(data) - 4096] = b"\xff" * (len(data) - 8192)
    path.write_bytes(bytes(data))
    if keep_sidecar_valid:
        osv_localdb.write_sidecar(path)


def _run_cli(monkeypatch, argv):
    monkeypatch.setattr("sys.argv", ["narvy"] + argv)
    try:
        narvy_main.cli()
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    return 0


def _big_go_records(n=400):
    # Enough rows that the entities/vulns pages are past the first 4 KB.
    recs = list(GO_RECORDS)
    for i in range(n):
        recs.append(_rec("GO-2099-%04d" % i, "Go", "example.com/pkg%d" % i,
                         [{"introduced": "0"}, {"fixed": "1.%d.0" % i}], details="x" * 400))
    return recs


@pytest.mark.parametrize("keep_sidecar_valid", [False, True])
def test_corrupt_db_offline_is_degraded_and_fail_on_exits_2(tmp_path, dbdir, monkeypatch, keep_sidecar_valid):
    p = _build(dbdir, "Go", _big_go_records())
    _corrupt_pages(p, keep_sidecar_valid)
    proj = _go_tiny(tmp_path)
    out = tmp_path / "r.json"
    code = _run_cli(monkeypatch, ["scan", str(proj), "--offline", "--fail-on", "low",
                                  "--output", "json", "--file", str(out)])
    cov = json.loads(out.read_text())["summary"]["sca_coverage"]
    assert cov["status"] == "degraded", cov
    assert cov["vulnerability_db"]["last_error"] == "local_db_corrupt_offline"
    assert code == 2
    rows = osv_localdb.status(dbdir)
    assert rows and "corrupt" in rows[0]["error"]


@pytest.mark.parametrize("keep_sidecar_valid", [False, True])
def test_corrupt_db_online_is_moved_aside_and_downloaded_again(tmp_path, dbdir, monkeypatch, keep_sidecar_valid):
    p = _build(dbdir, "Go", _big_go_records())
    _corrupt_pages(p, keep_sidecar_valid)
    proj = _go_tiny(tmp_path)
    with _Export({"/Go/all.zip": _zip_bytes(GO_RECORDS)}) as ex:
        monkeypatch.setenv("NARVY_OSV_EXPORT_URL", ex.base)
        osv_client.configure()
        findings, _, stats = web_deps.scan(str(proj))
    assert [r["path"] for r in ex.requests] == ["/Go/all.zip"]
    assert len(findings) == 2
    assert narvy_main._sca_coverage(stats)["status"] == "complete"
    assert not (dbdir / "Go.db.corrupt").exists()  # removed once a good copy is in place
    assert "error" not in osv_localdb.status(dbdir)[0]


def test_sca_exception_is_degraded_never_clean(tmp_path, dbdir, monkeypatch):
    proj = _go_tiny(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("database disk image is malformed")

    monkeypatch.setattr(web_deps, "scan", boom)
    out = tmp_path / "r.json"
    code = _run_cli(monkeypatch, ["scan", str(proj), "--fail-on", "low", "--output", "json", "--file", str(out)])
    cov = json.loads(out.read_text())["summary"]["sca_coverage"]
    assert cov["status"] == "degraded"
    assert code == 2


@pytest.mark.parametrize("offline", [True, False])
def test_db_older_than_7_days_is_incomplete_and_fail_on_exits_2(tmp_path, dbdir, monkeypatch, offline):
    _build(dbdir, "Go", GO_RECORDS, snapshot=_iso(8 * 24))
    proj = _go_tiny(tmp_path)
    out = tmp_path / "r.json"
    code = _run_cli(monkeypatch, ["scan", str(proj), "--fail-on", "low", "--output", "json", "--file", str(out)]
                    + (["--offline"] if offline else []))
    data = json.loads(out.read_text())
    cov = data["summary"]["sca_coverage"]
    assert cov["status"] == "degraded"
    assert cov["vulnerability_db"]["last_error"] == "local_db_too_old"
    assert not [f for f in data["findings"] if f.get("engine") == "sca"]
    assert code == 2


def test_db_between_1_and_7_days_is_used_and_flagged_stale(tmp_path, dbdir, monkeypatch):
    _build(dbdir, "Go", GO_RECORDS, snapshot=_iso(6 * 24))
    osv_client.configure(offline=True)
    findings, _, stats = web_deps.scan(str(_go_tiny(tmp_path)))
    assert len(findings) == 2
    assert stats["osv_stale_cache_served"] == 1


def test_nuget_and_crates_names_match_case_insensitively(tmp_path):
    _build(tmp_path, "NuGet", [_rec("GHSA-n-1", "NuGet", "Newtonsoft.Json", [{"introduced": "0"}, {"fixed": "13.0.1"}])])
    _build(tmp_path, "crates.io", [_rec("RUSTSEC-1", "crates.io", "Tokio", [{"introduced": "0"}, {"fixed": "1.0.0"}])])
    store = osv_localdb.LocalStore(directory=tmp_path, offline=True)
    assert store.get("NuGet").match_ids("NuGet", "newtonsoft.json", "12.0.3") == ["GHSA-n-1"]
    assert store.get("NuGet").match_ids("NuGet", "NEWTONSOFT.JSON", "12.0.3") == ["GHSA-n-1"]
    assert store.get("crates.io").match_ids("crates.io", "tokio", "0.2.0") == ["RUSTSEC-1"]


def test_download_after_lock_skips_when_another_run_refreshed(tmp_path):
    with _Export({"/npm/all.zip": _zip_bytes(NPM_RECORDS)}) as ex:
        osv_localdb.download("npm", tmp_path, base=ex.base, skip_if_younger_than=24)
        info = osv_localdb.download("npm", tmp_path, base=ex.base, skip_if_younger_than=24)
    assert info.get("skipped") is True
    assert len(ex.requests) == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permissions")
def test_db_update_on_read_only_cache_prints_a_clean_message(tmp_path, monkeypatch, capsys):
    ro = tmp_path / "ro"
    ro.mkdir()
    _build(ro, "Go", GO_RECORDS, snapshot=_iso(48))
    ro.chmod(0o500)
    monkeypatch.setenv("NARVY_OSV_DB_DIR", str(ro))
    from rich.console import Console
    buf = io.StringIO()
    monkeypatch.setattr(narvy_main, "console", Console(file=buf, width=300, color_system=None))
    try:
        code = _run_cli(monkeypatch, ["db", "update", "-e", "Go"])
    finally:
        ro.chmod(0o700)
    out = buf.getvalue()
    assert code == narvy_main.EXIT_ERROR
    assert "Go: update failed" in out and "cannot write the OSV cache directory" in out
    assert "Unexpected error" not in out and "Traceback" not in out


def test_orphan_part_files_are_removed(tmp_path):
    (tmp_path / "npm.zip.part").write_bytes(b"x" * 100)
    (tmp_path / "PyPI.db.building").write_bytes(b"x" * 100)
    removed = osv_localdb.cleanup_orphans(tmp_path)
    assert sorted(removed) == ["PyPI.db.building", "npm.zip.part"]
    assert not list(tmp_path.glob("*.part")) and not list(tmp_path.glob("*.building"))


def test_offline_never_calls_github_advisories_or_telemetry(tmp_path, dbdir, monkeypatch):
    _build(dbdir, "SwiftURL", [])
    monkeypatch.setenv("NARVY_GITHUB_ADVISORIES", "1")
    monkeypatch.delenv("NARVY_TELEMETRY", raising=False)
    from narvy import telemetry
    from narvy.sca import ios_deps
    sent = []
    monkeypatch.setattr(telemetry, "send", lambda *a, **k: sent.append(a))
    monkeypatch.setattr(ios_deps, "_query_github_advisories_swift",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("GitHub called")))
    guard = _NoSockets(monkeypatch)
    d = tmp_path / "ios"
    d.mkdir()
    (d / "Podfile.lock").write_text("PODS:\n  - Alamofire (4.0.0)\n\nCOCOAPODS: 1.11.0\n")
    (d / "App.swift").write_text("import UIKit\n")
    _run_cli(monkeypatch, ["scan", str(d), "--offline", "--output", "json", "--file", str(tmp_path / "r.json")])
    assert guard.attempts == []
    assert sent == []


def test_offline_with_upload_is_refused(tmp_path, monkeypatch):
    code = _run_cli(monkeypatch, ["scan", str(_go_tiny(tmp_path)), "--offline", "--upload"])
    assert code != 0


def test_ci_templates_cache_the_osv_database():
    import yaml
    base = Path(narvy_main.__file__).parent / "ci_templates"
    gh = yaml.safe_load((base / "github.yml").read_text())
    steps = gh["jobs"]["narvy"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert "actions/cache/restore@v4" in uses and "actions/cache/save@v4" in uses
    save = next(s for s in steps if s.get("uses") == "actions/cache/save@v4")
    assert save["if"] == "always()" and save["with"]["path"] == "~/.cache/narvy/osv"
    assert "osv_day" in save["with"]["key"]
    gl = yaml.safe_load((base / "gitlab.yml").read_text())["narvy_sast"]
    assert gl["variables"]["NARVY_OSV_DB_DIR"] == "$CI_PROJECT_DIR/.narvy-osv"
    assert gl["cache"]["paths"] == [".narvy-osv/"] and gl["cache"]["when"] == "always"


# --- --offline never downloads a tool (jadx, JRE) -------------------------------

MAVEN_RECORDS = [_rec("GHSA-m-1", "Maven", "com.squareup.okhttp3:okhttp",
                      [{"introduced": "0"}, {"fixed": "4.9.2"}], aliases=["CVE-2021-0341"])]


def _synthetic_apk(tmp_path, with_dep=True):
    p = tmp_path / "app.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00stub")
        zf.writestr("classes.dex", b"dex\n035\x00")
        if with_dep:
            zf.writestr("META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties",
                        "groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.9.0\n")
    return p


def _no_tools(monkeypatch, tmp_path, missing):
    from narvy import decompiler
    if missing == "jadx":
        monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)
        monkeypatch.setattr(decompiler, "JADX_BIN", str(tmp_path / "no-jadx"))
    else:
        monkeypatch.setattr(decompiler, "resolve_jadx_binary", lambda: "/bin/true")
        monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)
        monkeypatch.setattr(decompiler, "JRE_HOME", str(tmp_path / "no-jre"))
    calls = []
    monkeypatch.setattr(decompiler.requests, "get", lambda *a, **k: calls.append(a) or 1 / 0)
    return calls


@pytest.mark.parametrize("missing", ["jadx", "java"])
def test_offline_apk_scan_never_downloads_a_tool(tmp_path, dbdir, monkeypatch, missing):
    _build(dbdir, "Maven", MAVEN_RECORDS)
    apk = _synthetic_apk(tmp_path)
    calls = _no_tools(monkeypatch, tmp_path, missing)
    guard = _NoSockets(monkeypatch)
    out = tmp_path / "r.json"
    code = _run_cli(monkeypatch, ["scan", str(apk), "--offline", "--fail-on", "low",
                                  "--output", "json", "--file", str(out)])
    assert guard.attempts == [] and calls == []
    data = json.loads(out.read_text())
    summ = data["summary"]
    assert summ["code_coverage"]["status"] == "not_run"
    assert "narvy doctor" in summ["code_coverage"]["note"]
    assert summ["structural_coverage"]["status"] == "not_run"
    # The raw-APK passes still ran: the vulnerable okhttp is reported.
    assert [f for f in data["findings"] if f.get("engine") == "sca"]
    assert code == narvy_main.EXIT_FAIL_ON


def test_offline_apk_scan_without_tools_and_no_finding_exits_2(tmp_path, dbdir, monkeypatch):
    _build(dbdir, "Maven", MAVEN_RECORDS)
    apk = _synthetic_apk(tmp_path, with_dep=False)
    _no_tools(monkeypatch, tmp_path, "jadx")
    _NoSockets(monkeypatch)
    code = _run_cli(monkeypatch, ["scan", str(apk), "--offline", "--fail-on", "low",
                                  "--output", "json", "--file", str(tmp_path / "r.json")])
    assert code == narvy_main.EXIT_COVERAGE


def test_refused_old_copy_logs_one_message(tmp_path, caplog):
    _build(tmp_path, "Go", GO_RECORDS, snapshot=_iso(8 * 24))
    store = osv_localdb.LocalStore(directory=tmp_path, base="http://127.0.0.1:9")
    with caplog.at_level("WARNING"):
        with pytest.raises(osv_localdb.LocalDBError) as e:
            store.get("Go")
    assert e.value.kind == "local_db_too_old" and "refresh failed" in str(e.value)
    assert not any("using the copy" in r.getMessage() for r in caplog.records)


def test_corrupt_copy_removed_after_successful_download(tmp_path):
    (tmp_path / "Go.db.corrupt").write_bytes(b"junk")
    with _Export({"/Go/all.zip": _zip_bytes(GO_RECORDS)}) as ex:
        osv_localdb.download("Go", tmp_path, base=ex.base)
    assert not (tmp_path / "Go.db.corrupt").exists()
