"""1.3.3: monorepo workspaces in the dependency check, Info in the upload,
the --fail-on rule of the platform, the 'reactivated' upload line."""
import io
import json

import pytest
from rich.console import Console

from narvy import main as cli_main
from narvy import repo_identity
from narvy.sca import web_deps


class _VulnClient:
    def has_any_vuln_batch(self, pairs, ecosystem=None):
        return {p: True for p in pairs}

    def query_dict(self, name, version, ecosystem=None):
        return [{"cve": "CVE-2099-0001", "severity": "HIGH", "fixed_version": "9.9.9", "summary": "x"}]


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _pkg(path, deps=None, dev=None, **extra):
    body = {"name": extra.pop("name", path.parent.name), **extra}
    if deps:
        body["dependencies"] = deps
    if dev:
        body["devDependencies"] = dev
    _write(path, json.dumps(body))


def _npm_workspace(root, with_lock=True):
    """Root + packages/a + packages/b, every dependency in the root lockfile."""
    _pkg(root / "package.json", dev={"typescript": "5.4.5"}, workspaces=["packages/*"], name="mono")
    _pkg(root / "packages" / "a" / "package.json", {"lodash": "^4.17.20", "express": "4.17.1"})
    _pkg(root / "packages" / "b" / "package.json", {"lodash": "^4.17.20", "axios": "0.21.1",
                                                     "minimist": "1.2.5"})
    if with_lock:
        lock = {"name": "mono", "lockfileVersion": 3, "packages": {
            "": {"name": "mono", "workspaces": ["packages/*"]},
            "node_modules/a": {"resolved": "packages/a", "link": True},
            "node_modules/b": {"resolved": "packages/b", "link": True},
            "packages/a": {"version": "1.0.0"},
            "packages/b": {"version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/express": {"version": "4.17.1"},
            "node_modules/axios": {"version": "0.21.1"},
            "node_modules/minimist": {"version": "1.2.5"},
            "node_modules/typescript": {"version": "5.4.5", "dev": True},
        }}
        _write(root / "package-lock.json", json.dumps(lock))
    return root


def _coords(deps):
    return sorted((d.name, d.version) for d in deps)


# ------------------------------------------------------------- workspaces

def test_packages_dir_is_walked():
    assert "packages" not in web_deps._MANIFEST_SKIP_DIR_NAMES
    for kept in ("node_modules", "vendor", ".git", "build", "dist", "target"):
        assert kept in web_deps._MANIFEST_SKIP_DIR_NAMES


def test_workspace_without_lockfile_reads_every_member(tmp_path):
    """BUG D: packages/ was skipped, the members' dependencies were lost."""
    _npm_workspace(tmp_path, with_lock=False)
    deps = web_deps._dedupe(web_deps.collect_dependencies(str(tmp_path)))
    assert _coords(deps) == [("axios", "0.21.1"), ("express", "4.17.1"), ("lodash", "4.17.20"),
                             ("minimist", "1.2.5"), ("typescript", "5.4.5")]
    srcs = {d.name: d.source for d in deps}
    assert srcs["axios"] == "packages/b/package.json"
    assert srcs["express"] == "packages/a/package.json"


def test_root_lockfile_and_member_manifests_count_each_package_once(tmp_path):
    _npm_workspace(tmp_path)
    deps = web_deps._dedupe(web_deps.collect_dependencies(str(tmp_path)))
    assert _coords(deps) == [("axios", "0.21.1"), ("express", "4.17.1"), ("lodash", "4.17.20"),
                             ("minimist", "1.2.5"), ("typescript", "5.4.5")]
    assert {d.source for d in deps} == {"package-lock.json"}
    # The members' own package.json version is not a second copy.
    assert len(deps) == len({(d.name, d.version) for d in deps})


def test_findings_list_every_manifest_of_one_package(tmp_path):
    """express@4.17.1 pinned in two members, no lockfile: one finding, both manifests listed."""
    _pkg(tmp_path / "package.json", workspaces=["packages/*"], name="mono")
    _pkg(tmp_path / "packages" / "a" / "package.json", {"express": "4.17.1"})
    _pkg(tmp_path / "packages" / "b" / "package.json", {"express": "4.17.1"})
    findings, _r, stats = web_deps.scan(str(tmp_path), osv_client=_VulnClient())
    assert len(findings) == 1
    f = findings[0]
    assert f["file_path"] == "packages/a/package.json"
    assert f["sca"]["manifests"] == ["packages/a/package.json", "packages/b/package.json"]
    assert stats["unique_dependencies_detected"] == 1


def test_single_manifest_finding_has_no_manifests_list(tmp_path):
    _pkg(tmp_path / "package.json", {"express": "4.17.1"})
    findings, _r, _s = web_deps.scan(str(tmp_path), osv_client=_VulnClient())
    assert "manifests" not in findings[0]["sca"]


def test_workspace_globs_reach_a_member_the_walk_skips(tmp_path):
    """A declared member under a folder name the walk prunes (build/) is still read;
    a negated glob is left out."""
    _pkg(tmp_path / "package.json", name="mono",
         workspaces={"packages": ["build/tools/*", "libs/*", "!libs/legacy"]})
    _pkg(tmp_path / "build" / "tools" / "gen" / "package.json", {"minimist": "1.2.5"})
    _pkg(tmp_path / "libs" / "core" / "package.json", {"axios": "0.21.1"})
    _pkg(tmp_path / "libs" / "legacy" / "package.json", {"request": "2.88.0"})
    members = web_deps._npm_workspace_members(str(tmp_path))
    rel = sorted(p[len(str(tmp_path)) + 1:] for p in members)
    assert rel == ["build/tools/gen", "libs/core"]
    deps = web_deps._dedupe(web_deps.collect_dependencies(str(tmp_path)))
    names = {d.name for d in deps}
    assert {"minimist", "axios"} <= names
    # libs/legacy is not declared, but it is a manifest the walk meets anyway.
    assert "request" in names


def test_workspace_globs_never_leave_the_root(tmp_path):
    root = tmp_path / "repo"
    _pkg(tmp_path / "outside" / "package.json", {"lodash": "4.17.4"})
    _pkg(root / "package.json", name="mono", workspaces=["../outside", "/etc", "packages/*"])
    _pkg(root / "node_modules" / "x" / "package.json", {"lodash": "4.17.4"})
    _pkg(root / "package.json", name="mono", workspaces=["../outside", "/etc", "node_modules/*"])
    assert web_deps._npm_workspace_members(str(root)) == []


def test_pnpm_workspace_yaml_and_lerna_are_read(tmp_path):
    _pkg(tmp_path / "package.json", name="mono")
    _write(tmp_path / "pnpm-workspace.yaml", "packages:\n  - 'apps/*'\n  - \"tools/**\"\n")
    _write(tmp_path / "lerna.json", json.dumps({"packages": ["modules/*"]}))
    for d in ("apps/web", "tools/x/y", "modules/m"):
        _pkg(tmp_path / d / "package.json", {"axios": "0.21.1"})
    rel = sorted(p[len(str(tmp_path)) + 1:] for p in web_deps._npm_workspace_members(str(tmp_path)))
    assert {"apps/web", "tools/x/y", "modules/m"} <= set(rel)


def test_pnpm_workspace_yaml_line_reader_without_yaml(tmp_path, monkeypatch):
    import builtins
    real_import = builtins.__import__

    def _no_yaml(name, *a, **kw):
        if name == "yaml":
            raise ModuleNotFoundError(name)
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", _no_yaml)
    p = tmp_path / "pnpm-workspace.yaml"
    _write(p, "packages:\n  - 'packages/*'   # members\n  - apps/*\ncatalog:\n  - nope\n")
    assert web_deps._pnpm_workspace_globs(str(p)) == ["packages/*", "apps/*"]


def test_nuget_restore_packages_folder_is_still_pruned(tmp_path):
    _write(tmp_path / "packages.config",
           '<packages><package id="Newtonsoft.Json" version="12.0.1" /></packages>')
    _write(tmp_path / "packages" / "Newtonsoft.Json.12.0.1" / "Newtonsoft.Json.12.0.1.nupkg", "x")
    _write(tmp_path / "packages" / "Newtonsoft.Json.12.0.1" / "build" / "x.targets",
           '<Project><ItemGroup><PackageReference Include="Bogus" Version="1.0.0" /></ItemGroup></Project>')
    found = web_deps._walk_manifests(str(tmp_path), lambda f: f.endswith(".targets"))
    assert found == []


def test_python_and_go_monorepo_dirs_under_packages(tmp_path):
    _write(tmp_path / "packages" / "svc" / "requirements.txt", "django==2.2.0\n")
    _write(tmp_path / "packages" / "gosvc" / "go.mod",
           "module example.com/gosvc\n\ngo 1.21\n\nrequire golang.org/x/net v0.0.1\n")
    deps = web_deps._dedupe(web_deps.collect_dependencies(str(tmp_path)))
    assert ("django", "2.2.0") in _coords(deps)
    assert ("golang.org/x/net", "v0.0.1") in _coords(deps)


def test_cargo_workspace_members_and_root_lock(tmp_path):
    _write(tmp_path / "Cargo.toml", '[workspace]\nmembers = [\n  "crates/*", # all\n]\n')
    _write(tmp_path / "crates" / "a" / "Cargo.toml",
           '[package]\nname = "a"\n\n[dependencies]\nserde = "1.0.100"\n')
    _write(tmp_path / "Cargo.lock",
           '[[package]]\nname = "serde"\nversion = "1.0.150"\n'
           'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
    rel = [p[len(str(tmp_path)) + 1:] for p in web_deps._cargo_workspace_members(str(tmp_path))]
    assert rel == ["crates/a"]
    deps = web_deps._dedupe(web_deps.collect_dependencies(str(tmp_path)))
    # The root Cargo.lock resolves serde: the member's range floor is not a second version.
    assert [(d.name, d.version, d.source) for d in deps] == [("serde", "1.0.150", "Cargo.lock")]


def test_go_work_use_dirs(tmp_path):
    _write(tmp_path / "go.work", "go 1.21\n\nuse (\n\t./svc // main\n\t./lib\n)\n")
    for d in ("svc", "lib"):
        _write(tmp_path / d / "go.mod", f"module example.com/{d}\n")
    rel = sorted(p[len(str(tmp_path)) + 1:] for p in web_deps._go_work_members(str(tmp_path)))
    assert rel == ["lib", "svc"]


# ------------------------------------------------------------- Info in the upload

def _console(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(cli_main, "console", Console(file=buf, width=240, no_color=True, highlight=False))
    return buf


def test_info_findings_are_in_the_upload_payload(monkeypatch, tmp_path):
    _console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    sent = {}

    def _ingest(token, **kw):
        sent.update(kw)
        return 201, {"scan_id": "s", "dismissed": []}
    monkeypatch.setattr(cli_main.uploader, "ingest_results", _ingest)
    findings = [
        {"rule_id": "R1", "name": "n", "severity": "INFO", "file_path": "a.js", "line": 1},
        {"rule_id": "R2", "name": "n", "severity": "info", "file_path": "b.js", "line": 2},
        {"rule_id": "R3", "name": "n", "severity": "LOW", "file_path": "c.js", "line": 3},
    ]
    cli_main._submit_results_by_surface(findings, "web-source", str(tmp_path), {})
    assert [f["rule_id"] for f in sent["findings"]] == ["R1", "R2", "R3"]


# ------------------------------------------------------------- --fail-on

def _gate(findings, fail_on):
    try:
        cli_main._exit_on_fail_on(findings, fail_on)
    except SystemExit as e:
        return e.code
    return 0


@pytest.mark.parametrize("fail_on", ["any", "low", "medium", "high", "critical"])
def test_info_never_fails_the_gate(monkeypatch, fail_on):
    _console(monkeypatch)
    assert _gate([{"severity": "info"}, {"severity": "INFO"}], fail_on) == 0


def test_low_fails_low_and_any(monkeypatch):
    _console(monkeypatch)
    assert _gate([{"severity": "low"}], "low") == cli_main.EXIT_FAIL_ON
    assert _gate([{"severity": "LOW"}], "any") == cli_main.EXIT_FAIL_ON
    assert _gate([{"severity": "low"}], "medium") == 0


def test_breach_message_does_not_count_info(monkeypatch):
    buf = _console(monkeypatch)
    assert _gate([{"severity": "low"}, {"severity": "info"}], "any") == cli_main.EXIT_FAIL_ON
    out = buf.getvalue()
    assert "found 1 low" in out and "info" not in out.split("found", 1)[1]


def test_dismissed_low_does_not_fail_low(monkeypatch):
    _console(monkeypatch)
    low = {"severity": "low"}
    kept = cli_main._gate_findings([low], [low], "low")
    assert _gate(kept, "low") == 0


# ------------------------------------------------------------- reactivated

@pytest.mark.parametrize("matched_on,expected", [
    ("git_remote", "App ID 7 (reactivated, matched by repository)."),
    ("app", "App ID 7 (reactivated, matched by --app)."),
    (None, "App ID 7 (reactivated)."),
    ("new", "App ID 7 (reactivated)."),
])
def test_upload_line_says_reactivated(monkeypatch, tmp_path, matched_on, expected):
    buf = _console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    body = {"scan_id": "s", "app_id": 7, "app_matched_by": "reactivated"}
    if matched_on:
        body["app_matched_on"] = matched_on
    monkeypatch.setattr(cli_main.uploader, "ingest_results", lambda token, **kw: (201, body))
    cli_main._submit_results_ingest([], "web-source", str(tmp_path))
    assert expected in buf.getvalue()


def test_upload_line_package_upgrade(monkeypatch, tmp_path):
    buf = _console(monkeypatch)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t", "plan": "titan"})
    monkeypatch.setattr(repo_identity, "git_identity", lambda p: (None, None))
    monkeypatch.setattr(cli_main.uploader, "ingest_results",
                        lambda token, **kw: (201, {"scan_id": "s", "app_id": 7,
                                                   "app_matched_by": "package_upgrade"}))
    cli_main._submit_results_ingest([], "android", str(tmp_path))
    assert "App ID 7 (matched by package id)." in buf.getvalue()
