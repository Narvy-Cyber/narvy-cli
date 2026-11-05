"""Every dependency finding says where its version came from (1.3.1).

`version_source` takes the classes of the Narvy platform's lockfile parser:
lockfile (resolved), declared_exact (exact pin in a manifest), declared_range
(lower bound of a range: the installed version may be newer). The platform
reads it to apply its default-view policy. 1.3.0 sent `^0.4.0` as 0.4.0 and
said nothing.
"""

import json

import pytest

from narvy.sca import web_deps
from narvy.sca.web_deps import _WebDep, _finding_from_osv, version_source_for

_OSV = {"cve": "CVE-2099-0001", "severity": "LOW", "fixed_version": "9.9.9", "summary": "x"}


@pytest.mark.parametrize("spec,expected", [
    ("1.2.3", ("1.2.3", "declared_exact")),
    ("1.2.3-beta.1", ("1.2.3-beta.1", "declared_exact")),
    ("^0.4.0", ("0.4.0", "declared_range")),
    ("~1.2.3", ("1.2.3", "declared_range")),
    (">=1.2.3", ("1.2.3", "declared_range")),
    ("=1.2.3", ("1.2.3", "declared_range")),
    ("1.2", ("1.2", "declared_range")),
    ("1.x", ("1.x", "declared_range")),
    ("*", None),
    ("latest", None),
    (">=1 <2", None),
    ("git+https://x/y.git", None),
])
def test_npm_spec_classes_match_the_platform(spec, expected):
    assert web_deps._npm_declared(spec) == expected
    assert web_deps._strip_npm_range(spec) == (expected[0] if expected else None)


@pytest.mark.parametrize("spec,expected", [
    ("1.2.3", ("1.2.3", "declared_exact")),
    ("^7.4", ("7.4", "declared_range")),
    ("~2.0.1", ("2.0.1", "declared_range")),
    ("2.1", ("2.1", "declared_range")),
    ("dev-main", None),
])
def test_composer_spec_classes_match_the_platform(spec, expected):
    assert web_deps._php_declared(spec) == expected


@pytest.mark.parametrize("spec,expected", [
    ("1.2.3", ("1.2.3", "declared_range")),   # Cargo: a bare version is ^1.2.3
    ("^1.2.3", ("1.2.3", "declared_range")),
    ("=1.2.3", ("1.2.3", "declared_exact")),
    ("= 1.2.3", ("1.2.3", "declared_exact")),
    (">=1.2.3", ("1.2.3", "declared_range")),
    ("=1.2", ("1.2", "declared_range")),
])
def test_cargo_spec_classes(spec, expected):
    assert web_deps._cargo_declared(spec) == expected


@pytest.mark.parametrize("source,expected", [
    ("package-lock.json", "lockfile"), ("sub/yarn.lock", "lockfile"),
    ("pnpm-lock.yaml", "lockfile"), ("poetry.lock", "lockfile"), ("composer.lock", "lockfile"),
    ("Gemfile.lock", "lockfile"), ("Cargo.lock", "lockfile"), ("packages.lock.json", "lockfile"),
    ("requirements.txt", "declared_exact"), ("Gemfile", "declared_exact"),
    ("go.mod", "declared_exact"), ("app/pom.xml", "declared_exact"),
    ("build.gradle.kts", "declared_exact"), ("gradle/libs.versions.toml", "declared_exact"),
    ("src/App.csproj", "declared_exact"), ("packages.config", "declared_exact"),
    ("package.json", "declared_range"), ("composer.json", "declared_range"),
    ("Cargo.toml", "declared_range"),
    ("something.else", None),
])
def test_source_file_classes(source, expected):
    assert version_source_for(source) == expected


def test_finding_carries_version_source_top_level_and_in_sca():
    """Top level too: the platform keeps a large finding's short scalars only."""
    f = _finding_from_osv(_WebDep("qs", "0.4.0", "npm", "package.json", "declared_range"), _OSV)
    assert f["version_source"] == "declared_range"
    assert f["sca"]["version_source"] == "declared_range"
    assert "lower bound of the range declared in package.json" in f["details"]["description"]
    f = _finding_from_osv(_WebDep("qs", "6.0.0", "npm", "package-lock.json"), _OSV)
    assert f["version_source"] == f["sca"]["version_source"] == "lockfile"
    assert "lower bound" not in f["details"]["description"]


def test_manifest_scan_tags_each_dependency(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text(json.dumps(
        {"dependencies": {"ranged": "^0.4.0", "pinned": "1.2.3"}}))
    deps = {d.name: d for d in web_deps._parse_package_json(str(tmp_path / "package.json"))}
    assert deps["ranged"].version == "0.4.0"
    assert version_source_for(deps["ranged"].source, deps["ranged"].version_source) == "declared_range"
    assert version_source_for(deps["pinned"].source, deps["pinned"].version_source) == "declared_exact"


def test_dedupe_keeps_the_exact_pin_over_a_range_floor():
    a = _WebDep("x", "1.2.3", "npm", "a/package.json", "declared_range")
    b = _WebDep("x", "1.2.3", "npm", "b/package.json", "declared_exact")
    (kept,) = web_deps._dedupe([a, b])
    assert kept.version_source == "declared_exact"


def test_matches_the_hosted_engine_fallback_classes():
    """Same classes as src/sast_shared/cli_sca_fields.py infers from the file
    name when a payload carries none (the CLI now sends a more precise one for
    package.json / composer.json exact pins)."""
    import os
    saas = os.environ.get("NARVY_HOSTED_ENGINE_DIR", os.path.join(os.path.expanduser("~"), "titanshield"))
    path = os.path.join(saas, "src", "sast_shared", "cli_sca_fields.py")
    if not os.path.isfile(path):
        pytest.skip("hosted engine checkout not available")
    text = open(path, encoding="utf-8").read()
    ns = {}
    start = text.index("_SCA_LOCKFILES")
    end = text.index("def is_cli_sca_type")
    exec(text[start:end], ns)  # the three frozensets only
    for base in ns["_SCA_LOCKFILES"]:
        assert version_source_for(base) == "lockfile", base
    for base in ns["_SCA_EXACT_MANIFESTS"]:
        assert version_source_for(base) == "declared_exact", base
    for base in ns["_SCA_RANGE_MANIFESTS"]:
        assert version_source_for(base) == "declared_range", base


@pytest.mark.parametrize("summary", ["Prototype Pollution in minimist", "Prototype Pollution in minimist.",
                                     "Prototype Pollution in minimist  "])
def test_range_sentence_starts_a_new_sentence(summary):
    osv = dict(_OSV, summary=summary)
    f = _finding_from_osv(_WebDep("minimist", "0.0.8", "npm", "package.json", "declared_range"), osv)
    d = f["details"]["description"]
    assert "Prototype Pollution in minimist. 0.0.8 is the lower bound" in d
    assert ".." not in d
