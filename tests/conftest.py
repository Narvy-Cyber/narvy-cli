import pytest


@pytest.fixture(autouse=True)
def _no_telemetry(monkeypatch):
    """No test may send a usage event; telemetry tests opt back in explicitly."""
    monkeypatch.setenv("NARVY_TELEMETRY", "0")


@pytest.fixture(autouse=True)
def _no_osv_download(monkeypatch, tmp_path_factory):
    """No test downloads the real OSV export or writes to ~/.cache/narvy/osv:
    the local database lives in a per-test empty dir and the export URL points
    at a closed port. Tests that need a database build or serve one."""
    monkeypatch.setenv("NARVY_OSV_DB_DIR", str(tmp_path_factory.mktemp("osvdb")))
    monkeypatch.setenv("NARVY_OSV_EXPORT_URL", "http://127.0.0.1:9")
    from narvy import decompiler
    from narvy.sca import osv_client
    osv_client.configure()
    decompiler.OFFLINE = False
    yield
    osv_client.configure()
    decompiler.OFFLINE = False


@pytest.fixture(autouse=True)
def _isolated_get_only_cache(monkeypatch, tmp_path):
    """No test may write the template verdict cache into the real home dir."""
    from narvy.web.scanner import NucleiScanner
    monkeypatch.setenv("NARVY_GET_ONLY_CACHE", str(tmp_path / "get_only_cache.json"))
    monkeypatch.setattr(NucleiScanner, "_GET_ONLY_CACHE", {})
    monkeypatch.setattr(NucleiScanner, "_GET_ONLY_DISK_LOADED", False)
    monkeypatch.setattr(NucleiScanner, "_GET_ONLY_DIRTY", False)
