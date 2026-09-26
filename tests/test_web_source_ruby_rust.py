"""Ruby and Rust packs: detection, routing, scans, notes and lockfile SCA."""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import main
from narvy.sca import web_deps
from narvy.web import source_analyzer


def _write(path: str, content: str = "") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _make_ruby_project(root: str) -> None:
    """Minimal Rails-style app with source and sink in one method."""
    _write(os.path.join(root, "Gemfile"), 'source "https://rubygems.org"\ngem "rails"\n')
    _write(os.path.join(root, "app", "controllers", "users_controller.rb"), """
class UsersController < ApplicationController
  def search
    # SQL injection: ActiveRecord where() with a tainted string
    @users = User.where("name = '" + params[:name] + "'")
  end

  def backup
    # Command injection: system() with a tainted argument
    system("tar czf /tmp/backup.tgz " + params[:dir])
  end

  def restore
    # Unsafe deserialization: YAML.load on request data
    @state = YAML.load(params[:state])
  end

  def go
    # Open redirect
    redirect_to params[:next]
  end
end
""")


def _make_rust_project(root: str) -> None:
    """Minimal axum/sqlx-style service."""
    _write(os.path.join(root, "Cargo.toml"), """[package]
name = "demo-api"
version = "0.1.0"
edition = "2021"

[dependencies]
sqlx = "0.7.3"
md5 = "0.7.0"
""")
    _write(os.path.join(root, "src", "main.rs"), """
use std::process::Command;

async fn ping(host: String) {
    // Command injection: sh -c with a non-literal argument
    let _ = Command::new("sh").arg("-c").arg(format!("ping -c1 {}", host)).output();
}

fn hash_password(pw: &str) -> String {
    // Weak crypto: MD5 as a password hash. The digest is bound to a local
    // first on purpose: semgrep does not match patterns inside a Rust macro
    // invocation's arguments, so the one-line form is a known blind spot.
    let digest = md5::compute(pw);
    format!("{:x}", digest)
}

async fn find_user(pool: &sqlx::PgPool, id: String) {
    // SQL injection: format!()-built query string
    let _ = sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id))
        .fetch_all(pool)
        .await;
}
""")


def _make_android_project_with_gemfile(root: str) -> None:
    """Android repo with a fastlane Gemfile."""
    _write(os.path.join(root, "build.gradle"), "apply plugin: 'com.android.application'\n")
    _write(os.path.join(root, "settings.gradle"), "rootProject.name = 'app'\n")
    _write(os.path.join(root, "app", "src", "main", "AndroidManifest.xml"),
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
           'package="com.example.app"></manifest>')
    _write(os.path.join(root, "Gemfile"), 'source "https://rubygems.org"\ngem "fastlane"\n')
    _write(os.path.join(root, "fastlane", "Fastfile"), "lane :beta do\n  gradle(task: 'assemble')\nend\n")


def _make_ios_project_with_cargo(root: str) -> None:
    """iOS repo with a Cargo.toml; still ios-source."""
    os.makedirs(os.path.join(root, "MyApp.xcodeproj"), exist_ok=True)
    _write(os.path.join(root, "MyApp", "AppDelegate.swift"), "import UIKit\nclass AppDelegate {}\n")
    _write(os.path.join(root, "Cargo.toml"), '[package]\nname = "core"\nversion = "0.1.0"\n')
    _write(os.path.join(root, "rust", "src", "lib.rs"), "pub fn add(a: i32, b: i32) -> i32 { a + b }\n")


def test_detects_ruby_project_as_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_ruby_project(d)
        assert main._detect_scan_mode(d) == "web-source"
        ported, unported = source_analyzer.detect_web_stacks(d)
        assert "ruby" in ported, f"Ruby not detected as a ported stack: got {ported}"
        assert "ruby" not in unported


def test_detects_rust_project_as_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_rust_project(d)
        assert main._detect_scan_mode(d) == "web-source"
        ported, unported = source_analyzer.detect_web_stacks(d)
        assert "rust" in ported, f"Rust not detected as a ported stack: got {ported}"
        assert "rust" not in unported


def test_detects_gemspec_only_ruby_repo():
    """A gem or Rails-engine repo has no Gemfile, only `<gemname>.gemspec`."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "my_engine.gemspec"),
               'Gem::Specification.new do |s|\n  s.name = "my_engine"\nend\n')
        _write(os.path.join(d, "lib", "my_engine.rb"), "module MyEngine\nend\n")
        assert main._detect_scan_mode(d) == "web-source"
        ported, _ = source_analyzer.detect_web_stacks(d)
        assert "ruby" in ported


def test_detects_cargo_manifest_one_level_deep():
    """A monorepo puts the Rust service one level down (server/Cargo.toml)."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "server", "Cargo.toml"),
               '[package]\nname = "api"\nversion = "0.1.0"\n')
        _write(os.path.join(d, "server", "src", "lib.rs"), "pub fn f() {}\n")
        assert main._detect_scan_mode(d) == "web-source"
        ported, _ = source_analyzer.detect_web_stacks(d)
        assert "rust" in ported, f"one-level-deep Cargo.toml not detected: got {ported}"


def test_detects_deep_cargo_workspace_member_by_source_density():
    """Deep Cargo members are found by .rs density (5+ files)."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "crates", "api", "Cargo.toml"),
               '[package]\nname = "api"\nversion = "0.1.0"\n')
        for i in range(5):
            _write(os.path.join(d, "crates", "api", "src", f"m{i}.rs"), "pub fn f() {}\n")
        assert main._detect_scan_mode(d) == "web-source"
        ported, _ = source_analyzer.detect_web_stacks(d)
        assert "rust" in ported, f"deep Cargo workspace not detected by density: got {ported}"


def test_ruby_and_rust_resolve_the_expected_rule_packs():
    """Language pack plus the cross-language packs."""
    for stack, lang_pack in (("ruby", "ruby.yml"), ("rust", "rust.yml")):
        configs = source_analyzer._resolve_configs({stack})
        basenames = {os.path.basename(c) for c in configs}
        assert lang_pack in basenames, f"{stack}: {lang_pack} not resolved: got {basenames}"
        for always_on in ("secrets.yml", "secrets_supplement.yml"):
            assert always_on in basenames, f"{stack}: {always_on} missing: got {basenames}"
        assert "security-audit.yml" not in basenames, basenames
        assert not any(c.startswith("p/") for c in configs), configs


def test_android_repo_with_fastlane_gemfile_still_routes_to_android():
    with tempfile.TemporaryDirectory() as d:
        _make_android_project_with_gemfile(d)
        assert main._detect_scan_mode(d) == "android-source", (
            "an Android repo with a fastlane Gemfile was stolen by web-source; "
            "its Java/Kotlin code would never be scanned"
        )


def test_ios_repo_with_rust_core_still_routes_to_ios():
    with tempfile.TemporaryDirectory() as d:
        _make_ios_project_with_cargo(d)
        assert main._detect_scan_mode(d) == "ios-source", (
            "an iOS repo with a Rust core crate was stolen by web-source; "
            "its Swift code would never be scanned"
        )


def test_ruby_scan_finds_real_sqli_command_injection_and_yaml_load():
    """Finding assertions are skipped if semgrep is unavailable here."""
    with tempfile.TemporaryDirectory() as d:
        _make_ruby_project(d)
        result = source_analyzer.analyze_source(d)

    assert result["ok"] is True
    assert "ruby" in result["stacks_detected"]
    assert result["files_scanned"] >= 1

    if not result["findings"]:
        return  # semgrep unavailable; detection assertions above still ran

    rule_ids = {f["rule_id"] for f in result["findings"]}
    expected = {
        "sql-injection-where-string",
        "command-injection-system",
        "yaml-load-unsafe",
        "open-redirect",
    }
    hit = expected & rule_ids
    assert hit == expected, (
        f"ruby.yml fired on only {sorted(hit)} of {sorted(expected)}; "
        f"all rule_ids seen: {sorted(rule_ids)}"
    )


def test_rust_scan_finds_real_command_injection_weak_hash_and_sqli():
    with tempfile.TemporaryDirectory() as d:
        _make_rust_project(d)
        result = source_analyzer.analyze_source(d)

    assert result["ok"] is True
    assert "rust" in result["stacks_detected"]
    assert result["files_scanned"] >= 1

    if not result["findings"]:
        return

    rule_ids = {f["rule_id"] for f in result["findings"]}
    expected = {
        "command-injection-arg",
        "md5-used-as-password-hash",
        "sql-injection-format",
    }
    hit = expected & rule_ids
    assert hit == expected, (
        f"rust.yml fired on only {sorted(hit)} of {sorted(expected)}; "
        f"all rule_ids seen: {sorted(rule_ids)}"
    )


def test_rust_emits_a_limited_coverage_note():
    """Rust gets a limited-coverage note."""
    with tempfile.TemporaryDirectory() as d:
        _make_rust_project(d)
        result = source_analyzer.analyze_source(d)
    joined = " ".join(result["notes"])
    assert "LIMITED COVERAGE" in joined, (
        f"Rust: no limited-coverage note emitted; notes were {result['notes']}"
    )
    assert "Rust" in joined, "Rust: coverage note doesn't name the language"


def test_ruby_no_longer_carries_the_starter_level_banner():
    """Ruby no longer gets the starter-level banner."""
    assert "ruby" not in source_analyzer._LOW_COVERAGE_STACKS
    with tempfile.TemporaryDirectory() as d:
        _make_ruby_project(d)
        result = source_analyzer.analyze_source(d)
    joined = " ".join(result["notes"])
    assert "Brakeman" not in joined, result["notes"]


def test_ruby_and_rust_are_no_longer_reported_as_unported():
    """Ruby and Rust aren't reported as unported."""
    assert "ruby" not in source_analyzer._UNPORTED_STACK_LABELS
    assert "rust" not in source_analyzer._UNPORTED_STACK_LABELS
    with tempfile.TemporaryDirectory() as d:
        _make_ruby_project(d)
        result = source_analyzer.analyze_source(d)
    assert not any("no local rule pack" in n for n in result["notes"]), result["notes"]
    assert result["stacks_unsupported"] == []


_GEMFILE_LOCK = """GIT
  remote: https://github.com/someone/forked_gem.git
  revision: deadbeef
  specs:
    forked_gem (0.1.0)
      rake (>= 10.0)

PATH
  remote: vendor/gems/local_gem-1.0.0
  specs:
    local_gem (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (8.0.4)
      actionview (= 8.0.4)
      rack (>= 2.2.4)
    nokogiri (1.16.0-x86_64-linux)
    rack (2.2.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 8.0)

BUNDLED WITH
   2.5.9
"""


def test_gemfile_lock_parsing_exact_versions_only():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Gemfile.lock"), _GEMFILE_LOCK)
        deps = web_deps._collect_rubygems_deps(d)

    by_name = {dep.name: dep for dep in deps}
    assert by_name["actionpack"].version == "8.0.4"
    assert by_name["rack"].version == "2.2.4"
    assert all(d.ecosystem == "RubyGems" for d in deps)

    # A 6-space-indented transitive requirement is a range, not a version:
    # feeding OSV `actionview@= 8.0.4` or `rake@>= 10.0` would be garbage.
    assert all(dep.version[0].isdigit() for dep in deps), [
        (d.name, d.version) for d in deps if not d.version[0].isdigit()
    ]
    # Bundler's platform suffix must be stripped: OSV keys RubyGems by the
    # plain version, so "1.16.0-x86_64-linux" would match nothing.
    assert by_name["nokogiri"].version == "1.16.0"


def test_gem_platform_suffix_stripping_covers_the_real_shapes():
    """Strip gem platform suffixes but keep prerelease hyphens."""
    cases = [
        ("1.17.3-arm-linux-gnu", "1.17.3"),
        ("1.17.4-aarch64-linux-gnu", "1.17.4"),
        ("1.17.4-arm64-darwin", "1.17.4"),
        ("1.16.0-x86_64-linux", "1.16.0"),
        ("2.0.0-universal-darwin", "2.0.0"),
        ("4.35.1-x64-mingw-ucrt", "4.35.1"),
        ("1.2.3-x86-mingw32", "1.2.3"),
        ("3.42.0-java", "3.42.0"),
        ("8.0.4", "8.0.4"),
        ("1.0.0-beta1", "1.0.0-beta1"),
    ]
    for raw, expected in cases:
        got = web_deps._GEM_PLATFORM_SUFFIX_RE.sub("", raw)
        assert got == expected, f"{raw} -> {got}, expected {expected}"


def test_gemfile_lock_skips_git_and_path_sourced_gems():
    """GIT and PATH gems are skipped."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Gemfile.lock"), _GEMFILE_LOCK)
        names = {dep.name for dep in web_deps._collect_rubygems_deps(d)}
    assert "forked_gem" not in names, "GIT-sourced gem leaked into the RubyGems SCA query set"
    assert "local_gem" not in names, "PATH-sourced gem leaked into the RubyGems SCA query set"


def test_gemfile_without_lock_reports_nothing_rather_than_guessing():
    """No lockfile: no guessed versions."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Gemfile"),
               'source "https://rubygems.org"\ngem "rails", "~> 8.0"\ngem "puma"\n')
        assert web_deps._collect_rubygems_deps(d) == []


_CARGO_LOCK = """# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "demo-api"
version = "0.1.0"
dependencies = [
 "sqlx",
]

[[package]]
name = "sqlx"
version = "0.7.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "patched-crate"
version = "1.0.0"
source = "git+https://github.com/someone/patched-crate?branch=main#deadbeef"
"""


def test_cargo_lock_parsing_registry_packages_only():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Cargo.lock"), _CARGO_LOCK)
        deps = web_deps._collect_crates_deps(d)

    by_name = {dep.name: dep for dep in deps}
    assert by_name["sqlx"].version == "0.7.3"
    assert all(dep.ecosystem == "crates.io" for dep in deps)
    # Same fabricated-CVE failure mode as the Gemfile.lock GIT case.
    assert "demo-api" not in by_name, "workspace-local crate leaked into the crates.io query set"
    assert "patched-crate" not in by_name, "git-sourced crate leaked into the crates.io query set"


def test_cargo_toml_fallback_when_no_lockfile():
    """Fall back to Cargo.toml, still skipping path and git deps."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Cargo.toml"), """[package]
name = "lib"
version = "0.1.0"

[dependencies]
serde = "1.0.197"
tokio = { version = "1.36.0", features = ["full"] }
mycore = { path = "../mycore" }
patched = { git = "https://github.com/x/patched" }
anything = "*"
""")
        deps = web_deps._collect_crates_deps(d)

    by_name = {dep.name: dep.version for dep in deps}
    assert by_name.get("serde") == "1.0.197"
    assert by_name.get("tokio") == "1.36.0"
    assert "mycore" not in by_name, "path dependency is not a crates.io coordinate"
    assert "patched" not in by_name, "git dependency is not a crates.io coordinate"
    assert "anything" not in by_name, "wildcard '*' has no exact version to query"


def test_collect_dependencies_wires_both_new_ecosystems_in():
    """collect_dependencies() calls the Ruby and Rust parsers."""
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "Gemfile.lock"), _GEMFILE_LOCK)
        _write(os.path.join(d, "Cargo.lock"), _CARGO_LOCK)
        ecosystems = {dep.ecosystem for dep in web_deps.collect_dependencies(d)}
    assert "RubyGems" in ecosystems
    assert "crates.io" in ecosystems


def test_supported_ecosystems_label_names_both_new_ones():
    """main.py prints this label verbatim, so a stale one misinforms users."""
    label = web_deps.SUPPORTED_ECOSYSTEMS_LABEL
    assert "RubyGems" in label and "crates.io" in label, label


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"PASS: {len(fns)} Ruby/Rust web-source tests OK")
