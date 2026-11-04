"""--upload app identity, --app, the asset-limit message and the wording
fixes from persona QA 2026-11-04 ("Karim", CI).

* the upload sends the git remote (credentials stripped) and branch of the
  scanned folder when it is the ROOT of a checkout, never a parent repo's;
* --app NAME_OR_ID is sent as `app` and only with --upload;
* a 402 says what was looked for and how to target an existing app;
* the SCA line and the closing sentence use one count and one label;
* "free rule set" / "paid plan" wording only for a free-tier user.
"""
import os
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from narvy import main as cli_main
from narvy import repo_identity, uploader
from narvy.web import source_analyzer

needs_git = pytest.mark.skipif(not shutil.which("git"), reason="git not installed")


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_CONFIG_NOSYSTEM": "1"})


# --------------------------------------------------------------- git identity

@pytest.mark.parametrize("url,expected", [
    ("https://gitlab-ci-token:glpat-SECRET@gitlab.com/shop/api.git", "https://gitlab.com/shop/api.git"),
    ("https://x-access-token:ghs_SECRET@github.com:443/a/b", "https://github.com:443/a/b"),
    ("https://github.com/a/b.git", "https://github.com/a/b.git"),
    ("git@github.com:a/b.git", "github.com:a/b.git"),
    ("ssh://git@github.com/a/b.git", "ssh://github.com/a/b.git"),
    ("", None),
])
def test_strip_credentials(url, expected):
    assert repo_identity.strip_credentials(url) == expected


@needs_git
def test_git_identity_root_of_checkout(tmp_path):
    repo = tmp_path / "microservices-demo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "remote", "add", "origin",
         "https://gitlab-ci-token:SECRET@github.com/GoogleCloudPlatform/microservices-demo.git")
    remote, branch = repo_identity.git_identity(str(repo))
    assert remote == "https://github.com/GoogleCloudPlatform/microservices-demo.git"
    assert "SECRET" not in remote
    assert branch == "main"


@needs_git
def test_git_identity_ignores_a_parent_repository(tmp_path):
    """An extracted archive inside some other checkout is not that repo."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "remote", "add", "origin", "https://github.com/someone/unrelated.git")
    sub = tmp_path / "targets" / "microservices-demo-main"
    sub.mkdir(parents=True)
    assert repo_identity.git_identity(str(sub)) == (None, None)


def test_git_identity_not_a_repo(tmp_path):
    assert repo_identity.git_identity(str(tmp_path)) == (None, None)
    assert repo_identity.git_identity(str(tmp_path / "missing")) == (None, None)


# --------------------------------------------------------------- uploader body

def test_ingest_results_sends_identity_fields(monkeypatch):
    seen = {}

    class R:
        status_code = 201

        def json(self):
            return {"scan_id": "s"}

    def fake_post(url, headers=None, json=None, timeout=None):
        seen["body"] = json
        return R()
    monkeypatch.setattr(uploader.requests, "post", fake_post)
    uploader.ingest_results("t", "microservices-demo-main", "web", "web-source", [],
                            app="42", git_remote="https://github.com/a/b.git", git_branch="main")
    b = seen["body"]
    assert b["app"] == "42" and b["git_remote"] == "https://github.com/a/b.git" and b["git_branch"] == "main"
    uploader.ingest_results("t", "x", "web", "web-source", [])
    assert not {"app", "git_remote", "git_branch"} & set(seen["body"])


# --------------------------------------------------------------- 402 message

def test_asset_limit_message_says_what_it_tried_and_how_to_target():
    data = {"error": "asset_limit_exceeded", "current": 10, "max": 10, "upgrade_url": "/billing",
            "tried": ['name "microservices-demo-main"', 'name "microservices-demo"']}
    msg = cli_main._format_asset_limit_error(data, tried=['name "microservices-demo-main"'])
    assert "(10/10)" in msg
    assert 'name "microservices-demo-main", name "microservices-demo"' in msg
    assert "--app <name or app ID>" in msg and "narvy scans" in msg
    assert "/billing" in msg
    # Old server (no "tried"): what the CLI sent.
    old = dict(data)
    old.pop("tried")
    msg = cli_main._format_asset_limit_error(old, tried=['git remote https://github.com/a/b.git',
                                                          'name "b-main"'])
    assert 'git remote https://github.com/a/b.git, name "b-main"' in msg
    # Commands without --app keep the plain message.
    assert "--app" not in cli_main._format_asset_limit_error(data)


def _creds(monkeypatch, creds):
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: creds)


def test_submit_sends_folder_name_remote_and_app(monkeypatch, tmp_path):
    _creds(monkeypatch, {"token": "t", "email": "k@example.org", "plan": "titan"})
    calls = []

    def fake_ingest(token, **kw):
        calls.append(kw)
        return 201, {"scan_id": "s", "app_id": 7, "app_matched_by": "normalized_name"}
    monkeypatch.setattr(cli_main.uploader, "ingest_results", fake_ingest)
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: ("https://github.com/a/b.git", "main"))
    target = tmp_path / "microservices-demo-main"
    target.mkdir()
    cli_main._submit_results_ingest([], "web-source", str(target))
    assert calls[-1]["app_name"] == "microservices-demo-main"
    assert calls[-1]["git_remote"] == "https://github.com/a/b.git" and calls[-1]["app"] is None
    cli_main._submit_results_ingest([], "web-source", str(target), app="microservices-demo")
    assert calls[-1]["app"] == "microservices-demo" and calls[-1]["git_remote"] is None


def test_submit_402_exit_4_with_the_tried_names(monkeypatch, tmp_path, capsys):
    _creds(monkeypatch, {"token": "t", "email": "k@example.org", "plan": "titan"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    monkeypatch.setattr(cli_main.uploader, "ingest_results", lambda token, **kw: (402, {
        "error": "asset_limit_exceeded", "current": 10, "max": 10, "upgrade_url": "/billing"}))
    target = tmp_path / "other-shop-main"
    target.mkdir()
    with pytest.raises(SystemExit) as e:
        cli_main._submit_results_ingest([], "web-source", str(target))
    assert e.value.code == cli_main.EXIT_ERROR
    out = capsys.readouterr()
    text = " ".join((out.out + out.err).split())
    assert 'name "other-shop-main"' in text and "--app" in text


def test_submit_unknown_app_id_is_a_bad_target(monkeypatch, tmp_path):
    _creds(monkeypatch, {"token": "t", "plan": "titan"})
    monkeypatch.setattr(cli_main.uploader, "ingest_results", lambda token, **kw: (404, {
        "error": "app_not_found", "message": 'No app "999" in your account.'}))
    with pytest.raises(SystemExit) as e:
        cli_main._submit_results_ingest([], "web-source", str(tmp_path), app="999")
    assert e.value.code == cli_main.EXIT_BAD_TARGET


@pytest.mark.parametrize("upload,upload_binary,app", [
    (False, False, "x"), (True, True, "x"), (True, False, "  "),
])
def test_app_flag_requires_results_upload(tmp_path, upload, upload_binary, app):
    args = SimpleNamespace(apk_path=str(tmp_path), upload=upload, upload_binary=upload_binary, app=app)
    with pytest.raises(SystemExit) as e:
        cli_main.cmd_scan(args)
    assert e.value.code == cli_main.EXIT_BAD_TARGET


# --------------------------------------------------------------- wording

def test_sca_line_counts_distinct_advisories():
    line = cli_main._sca_result_line({"unique_dependencies_checked": 481, "cves_found": 127,
                                      "advisories_found": 109, "vulnerable_dependencies": 28})
    assert "found 109 known advisory(ies) across 28 dependency(ies)" in line
    assert "CVE" not in line and "127" not in line


def test_web_sca_stats_count_distinct_advisories(monkeypatch, tmp_path):
    from narvy.sca import web_deps
    findings = [{"rule_id": "SCA-GHSA-1"}, {"rule_id": "SCA-GHSA-1"}, {"rule_id": "SCA-CVE-2"}]
    assert len({f["rule_id"] for f in findings}) == 2
    src = open(web_deps.__file__).read()
    assert 'stats["advisories_found"] = len({f["rule_id"] for f in findings})' in src


@pytest.mark.parametrize("creds,free", [
    (None, True),
    ({"token": "t", "plan": "free"}, True),
    ({"token": "t", "plan": "community"}, True),
    ({"token": "t", "plan": "titan"}, False),
    ({"token": "t", "plan": "Business"}, False),
    ({"token": "t", "plan": None}, False),   # NARVY_TOKEN alone: plan unknown
])
def test_on_free_tier(monkeypatch, creds, free):
    _creds(monkeypatch, creds)
    assert cli_main._on_free_tier() is free


def test_premium_note_wording_by_tier():
    counts = {"dotnet": 10, "flask": 10}
    free = source_analyzer.premium_checks_note(counts, free_tier=True)
    paid = source_analyzer.premium_checks_note(counts, free_tier=False)
    assert "free rule set" in free and "paid plan" in free
    assert "free" not in paid.lower() and "paid" not in paid.lower()
    assert paid.startswith("20 additional framework check(s) for C#/.NET, Flask")


def test_csharp_limited_coverage_wording_by_tier():
    paid = source_analyzer._LOW_COVERAGE_STACKS_PAID["csharp"]
    assert "free" not in paid.lower() and "paid" not in paid.lower()
    assert "free rule set" in source_analyzer._LOW_COVERAGE_STACKS["csharp"]
