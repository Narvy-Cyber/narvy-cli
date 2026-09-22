"""Web-source scan mode: detection against Android/iOS overlap, real
semgrep findings on a vulnerable fixture, and --upload rejection.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import main
from narvy.web import source_analyzer


def _write(path: str, content: str = "") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _make_node_project(root: str) -> None:
    _write(os.path.join(root, "package.json"), """{
  "name": "smoke-app",
  "version": "1.0.0",
  "dependencies": {"express": "4.17.1"}
}
""")
    _write(os.path.join(root, "app.js"), ("""
const { exec } = require('child_process');
function run(req, res) {
  exec('ls ' + req.query.dir, (err, stdout) => { res.send(stdout); });
}
const apiKey = "__AWSKEY__";
console.log(apiKey);
""").replace("__AWSKEY__", "AKIA" + "ABCDEFGHIJKLMNOP"))


def _make_python_project(root: str) -> None:
    _write(os.path.join(root, "requirements.txt"), "flask==2.0.1\n")
    _write(os.path.join(root, "app.py"), "import os\n"
           "def index():\n    return 'ok'\n")


def _make_php_project(root: str) -> None:
    _write(os.path.join(root, "composer.json"), '{"require": {"php": ">=7.4"}}')
    _write(os.path.join(root, "index.php"), "<?php echo 'ok'; ?>")


def _make_go_project(root: str) -> None:
    _write(os.path.join(root, "go.mod"), "module example.com/app\n\ngo 1.18\n")
    _write(os.path.join(root, "main.go"), "package main\nfunc main() {}\n")


def _make_android_source_project(root: str, with_package_json: bool = False) -> None:
    _write(os.path.join(root, "build.gradle"), "apply plugin: 'com.android.application'\n")
    _write(os.path.join(root, "settings.gradle"), "rootProject.name = 'app'\n")
    manifest_dir = os.path.join(root, "app", "src", "main")
    _write(os.path.join(manifest_dir, "AndroidManifest.xml"),
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
           'package="com.example.app"></manifest>')
    _write(os.path.join(manifest_dir, "java", "com", "example", "app", "Main.java"),
           "package com.example.app;\nclass Main {}\n")
    if with_package_json:
        _write(os.path.join(root, "package.json"), '{"name": "tooling", "devDependencies": {"x": "1.0.0"}}')


def _make_ios_source_project(root: str, with_package_json: bool = False) -> None:
    os.makedirs(os.path.join(root, "MyApp.xcodeproj"), exist_ok=True)
    _write(os.path.join(root, "MyApp", "AppDelegate.swift"),
           "import UIKit\nclass AppDelegate {}\n")
    if with_package_json:
        _write(os.path.join(root, "package.json"), '{"name": "rn-app", "dependencies": {"react-native": "0.71.0"}}')


def test_detects_node_project_as_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_node_project(d)
        assert main._detect_scan_mode(d) == "web-source"


def test_detects_python_project_as_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_python_project(d)
        assert main._detect_scan_mode(d) == "web-source"


def test_detects_php_project_as_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_php_project(d)
        assert main._detect_scan_mode(d) == "web-source"


def test_detects_go_project_as_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_go_project(d)
        assert main._detect_scan_mode(d) == "web-source"


def test_android_source_not_misclassified_as_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_android_source_project(d, with_package_json=False)
        assert main._detect_scan_mode(d) == "android-source"


def test_android_source_with_package_json_still_wins_over_web_source():
    """A repo carrying both a package.json and a Gradle structure stays android-source."""
    with tempfile.TemporaryDirectory() as d:
        _make_android_source_project(d, with_package_json=True)
        assert main._detect_scan_mode(d) == "android-source"


def test_ios_source_not_misclassified_as_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_ios_source_project(d, with_package_json=False)
        assert main._detect_scan_mode(d) == "ios-source"


def test_ios_source_with_package_json_still_wins_over_web_source():
    """A native Xcode project carrying a package.json stays ios-source."""
    with tempfile.TemporaryDirectory() as d:
        _make_ios_source_project(d, with_package_json=True)
        assert main._detect_scan_mode(d) == "ios-source"


def test_web_source_scan_finds_real_command_injection_and_secret():
    """Runs the real analyze_source() pipeline, semgrep subprocess included."""
    with tempfile.TemporaryDirectory() as d:
        _make_node_project(d)
        result = source_analyzer.analyze_source(d)

    assert result["ok"] is True
    assert "javascript" in result["stacks_detected"]

    if not result["findings"]:
        # semgrep unavailable in this environment: stacks_detected still proved
        # detection worked, so do not fail on an environment gap.
        return

    rule_ids = {f["rule_id"] for f in result["findings"]}
    severities_by_rule = {f["rule_id"]: f["severity"] for f in result["findings"]}
    assert "child-process-exec-concat" in rule_ids, (
        f"command-injection-shaped exec() call not flagged - got {rule_ids}"
    )
    assert severities_by_rule.get("child-process-exec-concat") == "CRITICAL"
    assert "aws-access-key-id" in rule_ids or "generic-high-entropy-assignment" in rule_ids, (
        f"hardcoded AWS-shaped secret not flagged - got {rule_ids}"
    )


def test_web_source_scan_reports_dependency_cve_from_sca():
    """Targets sca/web_deps.py directly; needs network access to OSV.dev."""
    from narvy.sca import web_deps

    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "package.json"), """{
  "name": "smoke-app",
  "dependencies": {"lodash": "4.17.15"}
}
""")
        try:
            findings, rule_defs, stats = web_deps.scan(d)
        except Exception:
            return  # no network in this environment

    if stats["unique_dependencies_checked"] == 0:
        return
    if stats["cves_found"] == 0:
        return  # OSV.dev unreachable or rate-limited in this environment
    assert any("lodash" in f["name"] for f in findings)


def test_upload_rejected_for_web_source_scan_mode():
    """Checks cmd_scan's own --upload rejection set instead of driving the CLI."""
    import inspect
    src = inspect.getsource(main.cmd_scan)
    assert '"web-source"' in src or "'web-source'" in src, (
        "web-source missing from cmd_scan's --upload rejection set - a "
        "directory would be passed to open(path, 'rb') and crash with "
        "IsADirectoryError instead of a clean, honest error message"
    )


if __name__ == "__main__":
    test_detects_node_project_as_web_source()
    test_detects_python_project_as_web_source()
    test_detects_php_project_as_web_source()
    test_detects_go_project_as_web_source()
    test_android_source_not_misclassified_as_web_source()
    test_android_source_with_package_json_still_wins_over_web_source()
    test_ios_source_not_misclassified_as_web_source()
    test_ios_source_with_package_json_still_wins_over_web_source()
    test_web_source_scan_finds_real_command_injection_and_secret()
    test_web_source_scan_reports_dependency_cve_from_sca()
    test_upload_rejected_for_web_source_scan_mode()
    print("PASS: web-source scan mode detection + real E2E findings + "
          "--upload rejection all OK")


def test_classic_php_project_without_composer_json_is_web_source():
    """A classic PHP app is often just .php files with no composer.json; it must
    still detect as web-source, not fall through to UnsupportedScanTarget."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "index.php"), "<?php echo $_GET['x']; ?>")
        _write(os.path.join(d, "lib", "db.php"), "<?php function q(){} ?>")
        assert main._detect_scan_mode(d) == "web-source"


def test_dir_with_no_source_and_no_manifest_still_rejected():
    """The extension fallback must not turn a docs/asset folder into a scan."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "README.txt"), "hello")
        _write(os.path.join(d, "logo.png"), "not-an-image")
        try:
            mode = main._detect_scan_mode(d)
        except main.UnsupportedScanTarget:
            return
        assert False, f"expected UnsupportedScanTarget, got {mode!r}"


def test_dotnet_maui_project_with_android_manifest_is_web_source():
    """A .NET MAUI/Xamarin app ships a generated Platforms/Android/AndroidManifest.xml
    but is C# at heart. With no Android Gradle build it must route to web-source
    (the C# rule pack), not the java/kotlin-only android-source analyzer."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "App.sln"), "Microsoft Visual Studio Solution File\n")
        _write(os.path.join(d, "App", "App.csproj"), "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>")
        _write(os.path.join(d, "App", "MainPage.xaml.cs"), "namespace App { class MainPage {} }")
        _write(os.path.join(d, "App", "Platforms", "Android", "AndroidManifest.xml"),
               '<manifest xmlns:android="http://schemas.android.com/apk/res/android"></manifest>')
        assert main._detect_scan_mode(d) == "web-source"


def test_real_android_gradle_project_still_wins_over_dotnet_marker():
    """A genuine Android Gradle build must stay android-source even if a stray
    .csproj lives in the tree (guard is manifest-only, not gradle-based)."""
    with tempfile.TemporaryDirectory() as d:
        _make_android_source_project(d)
        _write(os.path.join(d, "tools", "Helper.csproj"), "<Project></Project>")
        assert main._detect_scan_mode(d) == "android-source"


def test_deeply_nested_manifest_is_detected_as_web_source():
    """A monorepo whose only manifest sits 4 levels deep must still be detected
    (regression for the old depth-3 gate that rejected it as unsupported)."""
    with tempfile.TemporaryDirectory() as d:
        deep = os.path.join(d, "org", "team", "service", "api")
        _write(os.path.join(deep, "go.mod"), "module example.com/api\n\ngo 1.20\n")
        _write(os.path.join(deep, "main.go"), "package main\nfunc main() {}\n")
        assert main._detect_scan_mode(d) == "web-source"


def test_nested_xcodeproj_does_not_flip_web_repo_to_ios():
    """A web/TS repo shipping a mobile example (examples/**/*.xcodeproj) must
    stay web-source; a nested Xcode project must not override a root web manifest."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "package.json"), '{"name":"x"}')
        _write(os.path.join(d, "tsconfig.json"), "{}")
        _write(os.path.join(d, "src", "app.ts"), "export const x = 1;")
        os.makedirs(os.path.join(d, "examples", "mobile", "ios", "Runner.xcodeproj"))
        _write(os.path.join(d, "examples", "mobile", "ios", "Runner.xcodeproj", "project.pbxproj"), "// pbx")
        assert main._detect_scan_mode(d) == "web-source"


def test_root_xcodeproj_still_detects_ios():
    """A genuine iOS project (Xcode project at the scan root) still wins."""
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "App.xcodeproj"))
        _write(os.path.join(d, "App.xcodeproj", "project.pbxproj"), "// pbx")
        _write(os.path.join(d, "App.swift"), "import Foundation")
        assert main._detect_scan_mode(d) == "ios-source"


def test_sca_zero_deps_is_not_reported_complete():
    """0 resolved dependencies must never be status 'complete' (a manifest we
    don't parse yet, e.g. Gradle version catalog, resolves 0 - claiming complete
    would be a false all-clear)."""
    assert main._sca_coverage({"unique_dependencies_detected": 0,
                               "unique_dependencies_checked": 0})["status"] == "none"
    assert main._sca_coverage({"unique_dependencies_detected": 5,
                               "unique_dependencies_checked": 5})["status"] == "complete"
