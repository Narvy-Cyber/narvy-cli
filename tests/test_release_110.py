"""1.1.0 changes: nested iOS, exit codes, SCA wording, upload links, CI progress, semgrep limits."""
import io
import json
import os
import subprocess
import sys
import time

import pytest
from rich.console import Console

from narvy import main as cli_main
from narvy import semgrep_engine
from narvy.web import source_analyzer as web_sa


def _write(root, rel, text="x"):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def _console(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(cli_main, "console",
                        Console(file=buf, width=240, force_terminal=False,
                                no_color=True, highlight=False))
    return buf


# ------------------------------------------------------------ nested iOS

def _igoat_like(root):
    _write(root, "server/app.rb", "get '/' do\n  params[:x]\nend\n")
    _write(root, "server/checkout.php", "<?php echo $_GET['p'];\n")
    _write(root, "App/App.xcodeproj/project.pbxproj", "// pbx\n")
    _write(root, "App/App/ViewController.swift", "import UIKit\n")


def test_nested_xcode_project_is_found_as_an_extra_surface(tmp_path):
    root = str(tmp_path)
    _igoat_like(root)
    assert cli_main._detect_scan_mode(root) == "web-source"
    roots = cli_main._nested_ios_project_roots(root)
    assert roots == [os.path.join(root, "App")]


def test_nested_ios_note_disappears_once_the_surface_is_scanned(tmp_path):
    root = str(tmp_path)
    _igoat_like(root)
    roots = cli_main._nested_ios_project_roots(root)
    notes = cli_main._uncovered_surface_notes(root, "web-source", extra_ios_roots=roots)
    assert not any("iOS" in n for n in notes), notes


def test_package_swift_in_subdir_counts(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", "{}")
    _write(root, "index.js", "console.log(1)\n")
    _write(root, "mobile/Package.swift", "// swift-tools-version:5.9\n")
    _write(root, "mobile/Sources/App/App.swift", "import Foundation\n")
    assert cli_main._nested_ios_project_roots(root) == [os.path.join(root, "mobile")]


@pytest.mark.parametrize("sample_dir", ["examples", "Example", "samples", "demo", "docs",
                                        "node_modules", "Pods", "tests"])
def test_sample_and_vendored_xcode_projects_are_ignored(tmp_path, sample_dir):
    root = str(tmp_path)
    _write(root, "package.json", "{}")
    _write(root, "index.js", "console.log(1)\n")
    _write(root, f"{sample_dir}/Demo/Demo.xcodeproj/project.pbxproj", "// pbx\n")
    assert cli_main._nested_ios_project_roots(root) == []


def test_loose_swift_note_points_at_a_real_directory(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", "{}")
    _write(root, "src/index.js", "console.log(1)\n")
    _write(root, "native/ios/Bridge.swift", "import Foundation\n")
    notes = cli_main._uncovered_surface_notes(root, "web-source")
    joined = " ".join(notes)
    assert "Native iOS" in joined
    assert os.path.join(root, "native", "ios") in joined


def test_cmd_scan_merges_nested_ios_findings(monkeypatch, tmp_path):
    root = str(tmp_path)
    _igoat_like(root)
    buf = _console(monkeypatch)
    monkeypatch.setattr(cli_main, "_run_web_source_scan",
                        lambda p: ([{"rule_id": "w", "name": "w", "severity": "HIGH",
                                     "file_path": "server/checkout.php", "line": 1}],
                                   [], {"sca_coverage": None}))
    seen = []

    def fake_ios(p):
        seen.append(p)
        return ([{"rule_id": "i", "name": "i", "severity": "MEDIUM",
                  "file_path": "App/ViewController.swift", "line": 3}], [], {"sca_coverage": None})
    monkeypatch.setattr(cli_main, "_run_ios_source_scan", fake_ios)
    out = tmp_path / "r.json"
    args = cli_main.argparse.Namespace(apk_path=root, max_mem="4g", force=False, upload=False,
                                       output="json", file=str(out))
    cli_main.cmd_scan(args)
    assert seen == [os.path.join(root, "App")]
    rep = json.loads(out.read_text())
    paths = sorted(f["file_path"] for f in rep["findings"])
    assert paths == [os.path.join("App", "App", "ViewController.swift"), "server/checkout.php"]
    assert [s["mode"] for s in rep["summary"]["surfaces"]] == ["web-source", "ios-source"]


def test_upload_splits_surfaces(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(cli_main, "_submit_results_ingest",
                        lambda f, mode, path: calls.append((mode, os.path.basename(path),
                                                            [x["file_path"] for x in f])))
    findings = [{"file_path": "server/a.php"},
                {"file_path": os.path.join("App", "V.swift"), "_surface_root": "App"}]
    meta = {"surfaces": [{"mode": "web-source", "path": "."}, {"mode": "ios-source", "path": "App"}]}
    cli_main._submit_results_by_surface(findings, "web-source", str(tmp_path), meta)
    assert calls[0] == ("web-source", os.path.basename(str(tmp_path)), ["server/a.php"])
    assert calls[1] == ("ios-source", "App", ["V.swift"])


# ------------------------------------------------------------ exit codes

def _run_cli(*argv):
    env = dict(os.environ, NARVY_TELEMETRY="0")
    return subprocess.run([sys.executable, "-c", "from narvy.main import cli; cli()", *argv],
                          capture_output=True, text=True, env=env, timeout=120)


def test_missing_target_exits_3(tmp_path):
    r = _run_cli("scan", str(tmp_path / "nope.apk"))
    assert r.returncode == cli_main.EXIT_BAD_TARGET == 3


def test_unsupported_target_exits_3(tmp_path):
    (tmp_path / "notes.txt").write_text("hello")
    r = _run_cli("scan", str(tmp_path / "notes.txt"))
    assert r.returncode == 3


def test_usage_error_exits_3_not_2(tmp_path):
    r = _run_cli("scan", str(tmp_path), "--fail-on", "catastrophic")
    assert r.returncode == 3


def test_exit_codes_are_documented_in_help():
    r = _run_cli("scan", "--help")
    assert r.returncode == 0
    for line in ("exit codes:", "1  --fail-on", "2  --fail-on", "3  the target", "4  the scan"):
        assert line in r.stdout
    assert "--fail-on" in r.stdout and "CI gate" in r.stdout


@pytest.mark.parametrize("cmd", ["web-scan", "host-audit", "cloud-scan"])
def test_fail_on_has_help_everywhere(cmd):
    r = _run_cli(cmd, "--help")
    assert "CI gate" in r.stdout


def test_fail_on_threshold_is_still_1():
    with pytest.raises(SystemExit) as e:
        cli_main._exit_on_fail_on([{"severity": "HIGH"}], "high")
    assert e.value.code == 1


# ------------------------------------------------------------ SCA wording

def test_sca_zero_dependencies_is_not_applicable_not_clean(monkeypatch):
    buf = _console(monkeypatch)
    assert cli_main._sca_not_applicable({"unique_dependencies_detected": 0,
                                         "unique_dependencies_checked": 0}, "apk")
    out = buf.getvalue()
    assert "not applicable" in out and "not a clean result" in out
    cov = cli_main._sca_coverage({"unique_dependencies_detected": 0,
                                  "unique_dependencies_checked": 0})
    assert cov["status"] == "none" and cov["applicable"] is False


def test_sca_with_dependencies_keeps_normal_line(monkeypatch):
    _console(monkeypatch)
    assert not cli_main._sca_not_applicable({"unique_dependencies_detected": 3}, "apk")


# ------------------------------------------------------------ upload links

def test_scan_link_is_absolute(monkeypatch):
    monkeypatch.setattr(cli_main.uploader, "API_BASE", "https://narvy.io")
    assert cli_main._scan_dashboard_url({"scan_id": "abc"}) == "https://narvy.io/analysis/s/abc"
    assert cli_main._scan_dashboard_url({"scan_url": "/analysis/s/x"}) == "https://narvy.io/analysis/s/x"
    assert cli_main._absolute_url("/pricing") == "https://narvy.io/pricing"
    assert cli_main._absolute_url("https://x.io/y") == "https://x.io/y"


def test_asset_limit_message_has_absolute_url(monkeypatch):
    monkeypatch.setattr(cli_main.uploader, "API_BASE", "https://narvy.io")
    msg = cli_main._format_asset_limit_error({"error": "asset_limit_exceeded", "upgrade_url": "/pricing"})
    assert "https://narvy.io/pricing" in msg


def test_ingest_success_prints_direct_link(monkeypatch):
    buf = _console(monkeypatch)
    monkeypatch.setattr(cli_main.uploader, "API_BASE", "https://narvy.io")
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.c", "plan": "starter"})
    monkeypatch.setattr(cli_main.uploader, "ingest_results",
                        lambda *a, **k: (201, {"scan_id": "s-1", "total_detected": 1}))
    cli_main._submit_results_ingest([], "web-source", "/x/repo")
    assert "https://narvy.io/analysis/s/s-1" in buf.getvalue()


def test_ingest_403_prints_absolute_upgrade_url(monkeypatch):
    buf = _console(monkeypatch)
    monkeypatch.setattr(cli_main.uploader, "API_BASE", "https://narvy.io")
    monkeypatch.setattr(cli_main.auth, "load_credentials",
                        lambda: {"token": "t", "email": "a@b.c", "plan": "community"})
    monkeypatch.setattr(cli_main.uploader, "ingest_results",
                        lambda *a, **k: (403, {"error": "needs plan", "upgrade_url": "/pricing"}))
    with pytest.raises(SystemExit) as e:
        cli_main._submit_results_ingest([], "web-source", "/x/repo")
    assert e.value.code == cli_main.EXIT_ERROR
    assert "https://narvy.io/pricing" in buf.getvalue()


def test_scope_tip_links_public_docs():
    src = open(cli_main.__file__).read()
    assert "CLI's SETUP.md" not in src
    assert cli_main.DOCS_URL.startswith("https://")


# ------------------------------------------------------------ CI progress

def test_plain_progress_prints_heartbeat():
    buf = io.StringIO()
    con = Console(file=buf, width=200, force_terminal=False, no_color=True)
    with cli_main._PlainProgress(con, interval=0.05) as p:
        p.add_task("[cyan]Scanning web/backend source...")
        time.sleep(0.25)
    out = buf.getvalue()
    assert out.count("still running") >= 2
    assert "Scanning web/backend source" in out


def test_plain_progress_heartbeat_can_be_disabled(monkeypatch):
    monkeypatch.setenv("NARVY_PROGRESS_INTERVAL", "0")
    buf = io.StringIO()
    con = Console(file=buf, width=200, force_terminal=False, no_color=True)
    with cli_main._PlainProgress(con) as p:
        p.add_task("step")
        time.sleep(0.1)
    assert "still running" not in buf.getvalue()


# ------------------------------------------------------------ semgrep resources

def test_resource_args_cap_jobs_and_memory(monkeypatch):
    monkeypatch.delenv("NARVY_SEMGREP_JOBS", raising=False)
    monkeypatch.delenv("NARVY_SEMGREP_MAX_MEMORY_MB", raising=False)
    jobs = semgrep_engine.semgrep_jobs()
    assert 1 <= jobs <= semgrep_engine.DEFAULT_MAX_JOBS
    args = semgrep_engine.resource_args(jobs)
    assert args[:2] == ["--jobs", str(jobs)]
    assert args[2:] == ["--max-memory", str(semgrep_engine.DEFAULT_MAX_MEMORY_MB)]
    monkeypatch.setenv("NARVY_SEMGREP_JOBS", "7")
    monkeypatch.setenv("NARVY_SEMGREP_MAX_MEMORY_MB", "0")
    assert semgrep_engine.semgrep_jobs() == 7
    assert semgrep_engine.resource_args(7) == ["--jobs", "7", "--max-memory", "0"]
    assert semgrep_engine.semgrep_jobs(single=True) == 1


def test_php_packs_run_single_worker():
    cfgs = ["/r/web/php.yml", "/r/web/javascript.yml", "/r/web/secrets.yml"]
    groups = web_sa._semgrep_groups(cfgs)
    php = [g for g in groups if "/r/web/php.yml" in g[0]]
    assert php and php[0][1] == 1 and php[0][0] == ["/r/web/php.yml"]
    other = [g for g in groups if "/r/web/php.yml" not in g[0]][0]
    assert "/r/web/javascript.yml" in other[0]


def test_non_php_packs_keep_one_group():
    groups = web_sa._semgrep_groups(["/r/web/python.yml", "/r/web/secrets.yml"])
    assert len(groups) == 1


def test_memory_skipped_files_are_counted():
    data = {"errors": [
        {"type": "Out of memory", "message": "Out of memory at line a.php:1", "path": "a.php"},
        {"type": ["OutOfMemory", []], "message": "", "path": "b.py"},
        {"type": "Timeout", "message": "t", "path": "c.py"},
    ]}
    assert web_sa._count_memory_skipped(data) == 2


def test_batch_plan_covers_every_file_once_and_respects_ignores(tmp_path):
    root = str(tmp_path)
    for d in ("a", "b/x", "b/y", "c"):
        for i in range(6):
            _write(root, f"{d}/f{i}.py", "x = 1\n")
    _write(root, "root.py")
    _write(root, "bundle.min.js")
    _write(root, "node_modules/lib/index.js")
    _write(root, "b/tests/test_x.py")
    batches = web_sa._plan_batches(root, 8)
    flat = [p for b in batches for p in b]
    assert len(flat) == len(set(flat))
    assert os.path.join(root, "root.py") in flat
    assert os.path.join(root, "bundle.min.js") not in flat
    assert not any("node_modules" in p for p in flat)
    assert not any(p.endswith("tests") for p in flat)
    covered = set()
    for p in flat:
        if os.path.isdir(p):
            for r, ds, fs in os.walk(p):
                ds[:] = [d for d in ds if d not in web_sa._SEMGREP_DEFAULT_IGNORED_DIRS]
                covered.update(os.path.join(r, f) for f in fs)
        else:
            covered.add(p)
    expected = {os.path.join(root, d, f"f{i}.py") for d in ("a", "b/x", "b/y", "c") for i in range(6)}
    assert expected <= covered
    assert all(sum(web_sa._count_target_files(p) for p in b) <= 8 or len(b) == 1 for b in batches)


@pytest.mark.skipif(not semgrep_engine.is_available(), reason="semgrep not installed")
def test_batched_scan_finds_the_same_as_a_single_run(tmp_path, monkeypatch):
    root = str(tmp_path)
    for d in ("svc/a", "svc/b", "lib"):
        for i in range(3):
            _write(root, f"{d}/m{i}.py",
                   "import os\nfrom flask import request\n"
                   "def f():\n    os.system('ping ' + request.args.get('h'))\n")
    _write(root, "requirements.txt", "flask==2.0.0\n")
    cfgs = web_sa._resolve_configs({"python"})
    monkeypatch.setenv("NARVY_SEMGREP_BATCH_THRESHOLD", "100000")
    single = web_sa._run_web_semgrep(root, cfgs)
    monkeypatch.setenv("NARVY_SEMGREP_BATCH_THRESHOLD", "1")
    monkeypatch.setenv("NARVY_SEMGREP_BATCH_FILES", "3")
    batched = web_sa._run_web_semgrep(root, cfgs)
    assert web_sa.LAST_RUN_BATCHES > 1
    key = lambda fs: sorted((f["rule_id"], f["file_path"], f["line"]) for f in fs)
    assert single and key(single) == key(batched)


# ------------------------------------------------------------ premium split

_FRAMEWORK_TOKENS = ("spring", "django", "drf", "flask", "fastapi", "express", "nestjs",
                     "laravel", "blade", "symfony", "rails", "gin", "jpa", "mybatis")


def _shipped_rule_ids():
    import glob
    import yaml
    root = os.path.join(os.path.dirname(cli_main.__file__), "rules")
    ids = []
    for p in glob.glob(os.path.join(root, "**", "*.yml"), recursive=True):
        d = yaml.safe_load(open(p))
        if isinstance(d, dict):
            ids += [(os.path.relpath(p, root), r["id"]) for r in d.get("rules", [])]
    return ids


# Cookie-flag hygiene is community on every plan, Flask included (1.1.1).
_COMMUNITY_FRAMEWORK_IDS = {
    "narvy.python.session.flask-set-cookie-missing-httponly.flask-set-cookie-missing-httponly",
    "narvy.python.session.flask-set-cookie-missing-secure.flask-set-cookie-missing-secure",
}


def test_no_framework_specific_rule_is_shipped():
    import re
    tok = re.compile(r"(?:^|[.\-_])(" + "|".join(_FRAMEWORK_TOKENS) + r")(?:[.\-_]|$)", re.I)
    bad = [(p, i) for p, i in _shipped_rule_ids()
           if tok.search(i) and not p.startswith("web/secrets") and i not in _COMMUNITY_FRAMEWORK_IDS]
    assert bad == []
    shipped = {i for _, i in _shipped_rule_ids()}
    assert _COMMUNITY_FRAMEWORK_IDS <= shipped


def test_no_local_house_packs_are_shipped():
    root = os.path.join(os.path.dirname(cli_main.__file__), "rules", "web", "local")
    leftover = []
    if os.path.isdir(root):
        for r, _, fs in os.walk(root):
            leftover += [f for f in fs if f.endswith((".yml", ".yaml"))]
    assert leftover == []


@pytest.mark.skipif(not semgrep_engine.is_available(), reason="semgrep not installed")
def test_every_shipped_pack_is_valid_and_alias_free():
    import glob
    root = os.path.join(os.path.dirname(cli_main.__file__), "rules")
    for p in glob.glob(os.path.join(root, "web", "*.yml")) + glob.glob(os.path.join(root, "*.yml")):
        text = open(p).read()
        assert "&id0" not in text and "*id0" not in text, p
        r = subprocess.run([semgrep_engine.semgrep_bin(), "--validate", "--metrics=off",
                            "--quiet", "--config", p], capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, (p, r.stdout[-500:], r.stderr[-500:])


def test_premium_note_only_for_matching_frameworks(tmp_path):
    root = str(tmp_path)
    _write(root, "requirements.txt", "Django==4.2\n")
    _write(root, "manage.py", "")
    counts = web_sa.detect_premium_frameworks(root)
    assert counts == {"django": web_sa.PREMIUM_CHECKS["django"][1]}
    note = web_sa.premium_checks_note(counts)
    assert "Django" in note and "paid plan" in note
    plain = tmp_path / "plain"
    plain.mkdir()
    _write(str(plain), "requirements.txt", "requests==2.31\n")
    assert web_sa.detect_premium_frameworks(str(plain)) == {}
    assert web_sa.premium_checks_note({}) is None
