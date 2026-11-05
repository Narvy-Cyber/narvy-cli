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
    # unencoded / # ? in the password: urlsplit raised or kept a fragment
    ("https://ci:pa/ss#wo?rd@gitlab.com/shop/api.git", "https://gitlab.com/shop/api.git"),
    ("https://ci:pa:ss@gitlab.com:notaport/shop/api.git", "https://gitlab.com/shop/api.git"),
    ("https://ci:x@gitlab.com:99999/shop/api.git", "https://gitlab.com/shop/api.git"),
    # scheme-less user:SECRET@host/o/r
    ("deploy:SECRET@github.com/o/r", "github.com/o/r"),
    ("deploy:SECRET@github.com:o/r.git", "github.com:o/r.git"),
    ("not a url", None),
    ("https://@/x", None),
])
def test_strip_credentials(url, expected):
    got = repo_identity.strip_credentials(url)
    assert got == expected
    assert "SECRET" not in str(got) and "pa" not in str(got).split("/")[0]


def test_git_identity_never_raises(monkeypatch, tmp_path):
    """A remote that breaks the parser must not fail the upload after the scan."""
    monkeypatch.setattr(repo_identity, "_git_identity",
                        lambda p: (_ for _ in ()).throw(ValueError("Port could not be cast")))
    assert repo_identity.git_identity(str(tmp_path)) == (None, None)


def test_malformed_remote_with_secret_never_echoed(monkeypatch, tmp_path, capsys):
    """Real checkout whose remote has an unencoded password: upload goes on,
    no fragment of the password is printed, even on a 402."""
    if not shutil.which("git"):
        pytest.skip("git not installed")
    repo = tmp_path / "shop"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", "https://ci:TOP/SEC#RET@gitlab.com:bad/shop/api.git")
    _creds(monkeypatch, {"token": "t", "plan": "titan"})
    sent = {}

    def fake_ingest(token, **kw):
        sent.update(kw)
        return 402, {"error": "asset_limit_exceeded", "current": 1, "max": 1, "upgrade_url": "/billing",
                     "tried": ["git remote gitlab.com/shop/api", 'name "shop"']}
    monkeypatch.setattr(cli_main.uploader, "ingest_results", fake_ingest)
    with pytest.raises(SystemExit):
        cli_main._submit_results_ingest([], "web-source", str(repo))
    out = capsys.readouterr()
    text = out.out + out.err
    for frag in ("TOP", "SEC", "RET", "gitlab.com"):
        assert frag not in text, frag
    assert sent["git_remote"] == "https://gitlab.com/shop/api.git"
    assert "its git remote" in " ".join(text.split())


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
    assert 'its git remote, name "b-main"' in msg and "github.com" not in msg
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
    # A checkout with a remote is named after the repository, not the folder.
    assert calls[-1]["app_name"] == "b"
    assert calls[-1]["git_remote"] == "https://github.com/a/b.git" and calls[-1]["app"] is None
    cli_main._submit_results_ingest([], "web-source", str(target), app="microservices-demo")
    assert calls[-1]["app"] == "microservices-demo" and calls[-1]["git_remote"] is None
    assert calls[-1]["app_name"] == "microservices-demo-main"


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


# --------------------------------------------------------------- app_matched_by

@pytest.mark.parametrize("matched_by,expected", [
    ("package_id", "App ID 7 (matched by package id)."),
    ("git_remote", "App ID 7 (matched by repository)."),
    ("name", "App ID 7 (matched by name)."),
    ("normalized_name", "App ID 7 (matched by repository name)."),
    ("cloud_account", "App ID 7 (matched by cloud account)."),
    ("app", "App ID 7 (matched by --app)."),
    ("new", "App ID 7 (new app)."),
    (None, "App ID 7."),
    ("something_else", "App ID 7."),
    ("", "App ID 7."),
    (42, "App ID 7."),
])
def test_upload_line_names_how_the_app_was_matched(monkeypatch, tmp_path, matched_by, expected):
    import io
    from rich.console import Console
    buf = io.StringIO()
    monkeypatch.setattr(cli_main, "console", Console(file=buf, width=240, no_color=True, highlight=False))
    _creds(monkeypatch, {"token": "t", "plan": "titan"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    body = {"scan_id": "s", "app_id": 7}
    if matched_by is not None:
        body["app_matched_by"] = matched_by
    monkeypatch.setattr(cli_main.uploader, "ingest_results", lambda token, **kw: (201, body))
    cli_main._submit_results_ingest([], "web-source", str(tmp_path))
    out = buf.getvalue()
    assert expected in out
    if matched_by != "new":
        assert "new app" not in out
