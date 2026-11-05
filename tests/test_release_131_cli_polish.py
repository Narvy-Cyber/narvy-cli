"""1.3.1 polish from persona QA 2026-11-04.

* `narvy scan . --upload` names the app after the directory, not ".";
  the SBOM / CBOM component name follows the same rule;
* NARVY_API_TOKEN is read as an alias of NARVY_TOKEN;
* the plan is shown by its public name ("Pro", not "titan");
* --upload checks the token before the scan and exits 4 on a rejected
  token or an unreachable server;
* the local-scan hint only says "run narvy login" when logged out, and is
  never printed with --upload.
"""
import argparse
import os
import shutil
import subprocess
import io
import zipfile

import pytest
from rich.console import Console

from narvy import auth, cbom, repo_identity, sbom
from narvy import main as cli_main


def _console(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(cli_main, "console", Console(file=buf, width=240, no_color=True, highlight=False))
    return buf


# --------------------------------------------------------------- "." target

def test_dot_target_uploads_under_the_directory_name(monkeypatch, tmp_path):
    _console(monkeypatch)
    repo = tmp_path / "shop-api"
    repo.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    sent = {}
    monkeypatch.setattr(cli_main.uploader, "ingest_results",
                        lambda token, **kw: sent.update(kw) or (201, {"scan_id": "s"}))
    cli_main._submit_results_ingest([], "web-source", ".")
    assert sent["app_name"] == "shop-api"
    cli_main._submit_results_ingest([], "web-source", "./")
    assert sent["app_name"] == "shop-api"


def test_dot_target_bom_component_is_the_directory_name(monkeypatch, tmp_path):
    repo = tmp_path / "shop-api"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "x"}')
    monkeypatch.chdir(repo)
    assert sbom.build_sbom(".")["metadata"]["component"]["name"] == "shop-api"
    assert cbom.build_cbom(".")[0]["metadata"]["component"]["name"] == "shop-api"


# --------------------------------------------------------------- token env

def test_narvy_api_token_is_an_alias(monkeypatch, tmp_path):
    monkeypatch.setattr(auth, "CREDENTIALS_PATH", str(tmp_path / "none"))
    monkeypatch.setenv("NARVY_API_TOKEN", "alias-token")
    assert auth.load_credentials()["token"] == "alias-token"
    monkeypatch.setenv("NARVY_TOKEN", "main-token")
    assert auth.load_credentials()["token"] == "main-token"


# --------------------------------------------------------------- plan name

@pytest.mark.parametrize("raw,shown", [
    ("titan", "Pro"), ("starter", "Starter"), ("community", "Community"), ("free", "Community"),
    ("business", "Business"), ("solo", "Solo"), ("enterprise", "Enterprise"), ("newtier", "Newtier"),
])
def test_plan_public_name(raw, shown):
    assert cli_main._plan_name(raw) == shown


def test_login_and_scans_show_the_public_plan_name(monkeypatch, tmp_path):
    buf = _console(monkeypatch)
    monkeypatch.setattr(cli_main.uploader, "whoami", lambda t: (200, {"email": "k@example.org", "plan": "titan"}))
    monkeypatch.setattr(cli_main.auth, "save_token", lambda *a: None)
    cli_main.cmd_login(argparse.Namespace(token="tok"))
    assert "(Pro plan)" in buf.getvalue() and "titan" not in buf.getvalue()

    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "k@example.org", "plan": "titan"})
    monkeypatch.setattr(cli_main.uploader, "list_scans", lambda *a, **k: (200, {"scans": [
        {"scan_id": "abcdef123", "app_name": "a", "status": "done"}]}))
    out = io.StringIO()
    monkeypatch.setattr(cli_main, "out_console", Console(file=out, width=240, no_color=True))
    cli_main.cmd_scans(argparse.Namespace(limit=10, status=None, format="table"))
    assert "k@example.org, Pro" in out.getvalue() and "titan" not in out.getvalue()


# --------------------------------------------------------------- token check

def _scan_args(target, upload):
    return argparse.Namespace(apk_path=str(target), max_mem="4g", force=False, upload=upload,
                              upload_binary=False, app=None, output="console", file=None)


def _stub_scan(monkeypatch, tmp_path, mode="web-source"):
    ran = []
    monkeypatch.setattr(cli_main, "_detect_scan_mode", lambda p: mode)
    monkeypatch.setattr(cli_main, "load_scope_config", lambda p: None)
    monkeypatch.setattr(cli_main, "_run_web_source_scan", lambda *a, **k: ran.append(1) or ([], [], {}))
    target = tmp_path / "repo"
    target.mkdir()
    return target, ran


@pytest.mark.parametrize("status,data", [
    (401, {"error": "invalid token"}),
    (403, {"error": "forbidden"}),
    (0, {"error": "could not reach the Narvy server"}),
])
def test_upload_rejected_token_exits_4_before_the_scan(monkeypatch, tmp_path, status, data):
    buf = _console(monkeypatch)
    target, ran = _stub_scan(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "bad"})
    monkeypatch.setattr(cli_main.uploader, "whoami", lambda t: (status, data))
    with pytest.raises(SystemExit) as e:
        cli_main.cmd_scan(_scan_args(target, upload=True))
    assert e.value.code == cli_main.EXIT_ERROR == 4
    assert ran == [], "the scan ran before the token was checked"
    out = buf.getvalue()
    if status == 401:
        assert "HTTP 401" in out and "rejected" in out and "narvy login" in out
    if status == 403:
        assert "HTTP 403" in out and "forbidden" in out and "rejected" not in out


def test_403_subscription_shows_the_server_message_not_token_rejected(monkeypatch, tmp_path):
    buf = _console(monkeypatch)
    target, ran = _stub_scan(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t"})
    monkeypatch.setattr(cli_main.uploader, "whoami", lambda t: (403, {
        "error": "Subscription expired",
        "message": "Your subscription has expired. Please renew to continue using the API."}))
    with pytest.raises(SystemExit) as e:
        cli_main.cmd_scan(_scan_args(target, upload=True))
    out = " ".join(buf.getvalue().split())
    assert e.value.code == 4 and ran == []
    assert "Your subscription has expired" in out and "rejected" not in out
    assert "narvy.io/pricing" in out


def test_upload_not_logged_in_exits_4_before_the_scan(monkeypatch, tmp_path):
    _console(monkeypatch)
    target, ran = _stub_scan(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: None)
    with pytest.raises(SystemExit) as e:
        cli_main.cmd_scan(_scan_args(target, upload=True))
    assert e.value.code == 4 and ran == []


def test_no_token_check_without_upload(monkeypatch, tmp_path):
    _console(monkeypatch)
    target, ran = _stub_scan(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_main.uploader, "whoami",
                        lambda t: (_ for _ in ()).throw(AssertionError("whoami called without --upload")))
    cli_main.cmd_scan(_scan_args(target, upload=False))
    assert ran == [1]


# --------------------------------------------------------------- local hint

def test_local_hint_depends_on_login(monkeypatch, tmp_path):
    buf = _console(monkeypatch)
    target, _ = _stub_scan(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: None)
    cli_main.cmd_scan(_scan_args(target, upload=False))
    assert "run `narvy login` and add --upload" in buf.getvalue()

    buf.truncate(0)
    buf.seek(0)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    cli_main.cmd_scan(_scan_args(target, upload=False))
    out = buf.getvalue()
    assert "Local scan only" in out and "add --upload" in out and "narvy login" not in out


def test_upload_never_prints_the_local_only_hint(monkeypatch, tmp_path):
    buf = _console(monkeypatch)
    target, _ = _stub_scan(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    monkeypatch.setattr(cli_main, "_submit_results_by_surface", lambda *a, **k: None)
    cli_main.cmd_scan(_scan_args(target, upload=True))
    out = buf.getvalue()
    assert "Local scan only" not in out and "narvy login" not in out


# --------------------------------------------------------------- init-ci templates

def test_ci_templates_upload_only_with_a_token_and_cache_osv():
    import os
    import yaml
    base = os.path.join(os.path.dirname(cli_main.__file__), "ci_templates")
    text = {n: open(os.path.join(base, n + ".yml")).read() for n in ("github", "gitlab", "bitbucket")}
    for name, t in text.items():
        yaml.safe_load(t)
        assert "${NARVY_TOKEN:+--upload}" in t, name
        assert "—" not in t, name
    gh = yaml.safe_load(text["github"])
    scan = next(s for s in gh["jobs"]["narvy"]["steps"] if s.get("name") == "Run Narvy scan")
    assert scan["env"]["NARVY_TOKEN"] == "${{ secrets.NARVY_TOKEN }}"
    assert "actions/cache/restore@v4" in text["github"]
    assert yaml.safe_load(text["gitlab"])["narvy_sast"]["cache"]["paths"] == [".narvy-osv/"]
    bb = yaml.safe_load(text["bitbucket"])
    assert bb["definitions"]["caches"]["narvy-osv"] == "~/.cache/narvy/osv"
    assert bb["pipelines"]["default"][0]["step"]["caches"] == ["narvy-osv"]


def test_token_expansion_adds_upload_only_when_set(tmp_path):
    import shutil
    import subprocess
    sh = shutil.which("sh")
    if not sh:
        pytest.skip("no sh")
    cmd = 'printf "%s|" narvy scan . ${NARVY_TOKEN:+--upload}'
    with_token = subprocess.run([sh, "-c", cmd], env={"NARVY_TOKEN": "x", "PATH": "/usr/bin:/bin"},
                                capture_output=True, text=True).stdout
    empty = subprocess.run([sh, "-c", cmd], env={"NARVY_TOKEN": "", "PATH": "/usr/bin:/bin"},
                           capture_output=True, text=True).stdout
    assert with_token == "narvy|scan|.|--upload|" and empty == "narvy|scan|.|"


# --------------------------------------------------------------- CI clone dirs

@pytest.mark.parametrize("clone_dir,remote,expected", [
    ("opt/atlassian/pipelines/agent/build", "https://x-token-auth:SECRET@bitbucket.org/acme/payments-api.git",
     "payments-api"),                                                    # Bitbucket
    ("home/vsts/work/1/s", "https://acme@dev.azure.com/acme/shop/_git/shop-web", "shop-web"),  # Azure
    ("home/circleci/project", "git@github.com:acme/mobile-app.git", "mobile-app"),            # CircleCI
])
def test_ci_clone_dir_uploads_under_the_repo_name(monkeypatch, tmp_path, clone_dir, remote, expected):
    if not shutil.which("git"):
        pytest.skip("git not installed")
    _console(monkeypatch)
    repo = tmp_path / clone_dir
    repo.mkdir(parents=True)
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, env=env)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", remote], check=True, env=env)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    sent = {}
    monkeypatch.setattr(cli_main.uploader, "ingest_results",
                        lambda token, **kw: sent.update(kw) or (201, {"scan_id": "s"}))
    cli_main._submit_results_ingest([], "web-source", ".")
    assert sent["app_name"] == expected
    assert "SECRET" not in str(sent)


def test_checkout_without_remote_keeps_the_directory_name(monkeypatch, tmp_path):
    _console(monkeypatch)
    repo = tmp_path / "shop-api"
    repo.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, "main"))
    sent = {}
    monkeypatch.setattr(cli_main.uploader, "ingest_results",
                        lambda token, **kw: sent.update(kw) or (201, {"scan_id": "s"}))
    cli_main._submit_results_ingest([], "web-source", ".")
    assert sent["app_name"] == "shop-api"


@pytest.mark.parametrize("remote,name", [
    ("https://github.com/acme/api.git", "api"), ("https://github.com/acme/api/", "api"),
    ("git@gitlab.com:group/sub/tool.git", "tool"), ("https://dev.azure.com/o/p/_git/web", "web"),
    ("", None), (None, None),
])
def test_repo_name(remote, name):
    assert repo_identity.repo_name(remote) == name


@pytest.mark.parametrize("remote", [
    "C:/Users/dev/repos/shop", "C:\\Users\\dev\\repos\\shop", "c:/x", "D:", "\\\\server\\share\\repo",
    "file:///home/dev/shop.git", "file://host/srv/shop.git", "/srv/git/shop.git", "../shop",
    "./shop", "~/repos/shop",
])
def test_local_path_remotes_are_never_sent(remote):
    assert repo_identity.strip_credentials(remote) is None


# --------------------------------------------------------------- severity mapping

@pytest.mark.parametrize("raw,mapped", [
    ("ERROR", "HIGH"), ("WARNING", "MEDIUM"), ("INFO", "LOW"), ("error", "HIGH"),
    (None, "LOW"), ("", "LOW"), ("BOGUS", "MEDIUM"),
])
def test_semgrep_severity_matches_the_platform(raw, mapped):
    from narvy import semgrep_engine
    assert semgrep_engine.map_severity(raw) == mapped


def test_no_semgrep_path_maps_error_to_critical():
    import inspect
    from narvy import semgrep_engine
    from narvy.ios import source_analyzer as ios_src
    from narvy.web import source_analyzer as web_src
    assert "CRITICAL" not in semgrep_engine.SEVERITY_MAP.values()
    for mod in (ios_src, web_src):
        assert "_SEMGREP_SEVERITY_MAP" not in inspect.getsource(mod)


def test_ci_templates_never_pin_below_1_3_1():
    import os
    import re
    base = os.path.join(os.path.dirname(cli_main.__file__), "ci_templates")
    for n in ("github", "gitlab", "bitbucket"):
        t = open(os.path.join(base, n + ".yml")).read()
        for spec in re.findall(r'narvy-cli([<>=!~][^"\s]*)?', t):
            assert spec in ("", ">=1.3.1"), (n, spec)


def test_readme_lists_the_token_check():
    import os
    readme = open(os.path.join(os.path.dirname(cli_main.__file__), "..", "README.md")).read()
    assert "/api/v1/whoami" in readme and "API token only" in readme
