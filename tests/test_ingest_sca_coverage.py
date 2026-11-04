"""`scan --upload` sends summary.sca_coverage (1.3.1).

The platform closes dependency rows missing from an upload only when the
ingest body says summary.sca_coverage == "complete"
(website/security_task._sca_coverage_complete, read from routes.api_ingest:
a string or {"status": ...}). No earlier CLI sent it, so a CLI upload never
closed a fixed dependency. One status word, nothing else.
"""
import io
import json

import pytest
from rich.console import Console

from narvy import main as cli_main
from narvy import repo_identity, uploader
from narvy.sca import web_deps


class _Client:
    def __init__(self, unreachable=False, stale=0, unsupported=0):
        self.unreachable, self.stale, self.unsupported = unreachable, stale, unsupported

    def has_any_vuln_batch(self, pairs, ecosystem=None):
        return {p: False for p in pairs}

    def query_dict(self, *a, **k):
        return []

    def counters(self):
        return {"unresolved": 0, "unsupported": 0, "stale": 0}

    def coverage_stats(self, before=None):
        return {"osv_dependencies_unresolved": 3 if self.unreachable else 0,
                "osv_unreachable": self.unreachable,
                "osv_unsupported_ecosystem": self.unsupported,
                "osv_stale_cache_served": self.stale}


def _status(root, client):
    _f, _r, stats = web_deps.scan(str(root), osv_client=client)
    return cli_main._sca_coverage_word({"sca_coverage": cli_main._sca_coverage(stats)})


def _npm(root):
    (root / "package.json").write_text(json.dumps({"dependencies": {"qs": "6.5.2"}}))
    return root


def test_complete(tmp_path):
    assert _status(_npm(tmp_path), _Client()) == "complete"


def test_partial_on_an_unparsed_manifest(tmp_path):
    _npm(tmp_path)
    (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "rails", "~> 7.0"\n')
    assert _status(tmp_path, _Client()) == "partial"


def test_partial_on_an_ecosystem_the_database_does_not_carry(tmp_path):
    assert _status(_npm(tmp_path), _Client(unsupported=1)) == "partial"


@pytest.mark.parametrize("client", [_Client(unreachable=True), _Client(stale=2)])
def test_degraded_when_the_database_is_missing_failing_or_stale(tmp_path, client):
    assert _status(_npm(tmp_path), client) == "degraded"


def test_degraded_when_the_check_stopped_on_an_error(monkeypatch):
    monkeypatch.setattr(cli_main, "console", Console(file=io.StringIO()))
    cov = cli_main._sca_failed_coverage(RuntimeError("boom"))
    assert cli_main._sca_coverage_word({"sca_coverage": cov}) == "degraded"


def test_none_without_a_manifest(tmp_path):
    assert _status(tmp_path, _Client()) == "none"


@pytest.mark.parametrize("meta", [{}, None, {"sca_coverage": None}, {"sca_coverage": {"status": "weird"}}])
def test_none_when_the_check_did_not_run(meta):
    assert cli_main._sca_coverage_word(meta) == "none"


# ------------------------------------------------------------ what is sent

def test_body_carries_one_status_word_in_summary(monkeypatch):
    seen = []

    class R:
        status_code = 201

        def json(self):
            return {"scan_id": "s"}

    monkeypatch.setattr(uploader.requests, "post",
                        lambda url, headers=None, json=None, timeout=None: seen.append(json) or R())
    uploader.ingest_results("t", "app", "web", "web-source", [], sca_coverage="complete")
    uploader.ingest_results("t", "app", "web", "web-source", [])
    assert seen[0]["summary"] == {"sca_coverage": "complete"}
    assert "summary" not in seen[1]


@pytest.mark.parametrize("word", ["complete", "partial", "degraded", "none"])
def test_upload_sends_the_scan_coverage(monkeypatch, tmp_path, word):
    monkeypatch.setattr(cli_main, "console", Console(file=io.StringIO()))
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    calls = []
    monkeypatch.setattr(cli_main.uploader, "ingest_results",
                        lambda token, **kw: calls.append(kw) or (201, {"scan_id": "s"}))
    meta = {"sca_coverage": {"status": word}} if word != "none" else {}
    cli_main._submit_results_by_surface([], "web-source", str(tmp_path), meta)
    assert calls[-1]["sca_coverage"] == word
