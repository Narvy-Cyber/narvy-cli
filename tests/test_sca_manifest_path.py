"""Dependency findings name their manifest by its path from the scan root (1.3.1).

The platform keys dependency rows by manifest (website/vulnerability_fingerprint
.dependency_manifest: forward slashes, no leading "./" or "/"). 1.3.0 sent the
bare file name ("package.json") and merged one package@version across every
manifest, so a monorepo with sequelize@4.13.10 in package.json and
backend/package.json reported one finding.
"""
import json

import pytest

from narvy import sbom
from narvy.sca import web_deps
from narvy.sca.web_deps import _WebDep


class _VulnClient:
    """Every queried package is vulnerable to one advisory."""

    def has_any_vuln_batch(self, pairs, ecosystem=None):
        return {p: True for p in pairs}

    def query_dict(self, name, version, ecosystem=None):
        return [{"cve": "CVE-2099-0001", "severity": "HIGH", "fixed_version": "9.9.9", "summary": "x"}]


def _pkg(path, deps):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"name": "x", "dependencies": deps}))


def _monorepo(root):
    _pkg(root / "package.json", {"sequelize": "4.13.10"})
    _pkg(root / "backend" / "package.json", {"sequelize": "4.13.10", "lodash": "4.17.4"})
    return root


def test_monorepo_reports_each_manifest_with_its_relative_path(tmp_path):
    findings, _rules, _stats = web_deps.scan(str(_monorepo(tmp_path)), osv_client=_VulnClient())
    seq = sorted(f["file_path"] for f in findings if f["sca"]["package"] == "sequelize")
    assert seq == ["backend/package.json", "package.json"]
    for f in findings:
        assert f["sca"]["detected_via"] == f["file_path"]
        assert not f["file_path"].startswith(("/", "./")) and "\\" not in f["file_path"]
        assert str(tmp_path) not in json.dumps(f)
        # version_source still read from the file name
        assert f["version_source"] == "declared_exact"


def test_lockfile_dedupe_stays_within_its_directory(tmp_path):
    root = _monorepo(tmp_path)
    (root / "backend" / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3, "packages": {
            "": {"name": "x"},
            "node_modules/sequelize": {"version": "4.13.10"},
            "node_modules/lodash": {"version": "4.17.21"}}}))
    deps = {(d.name, d.version, d.source) for d in web_deps._dedupe(web_deps.collect_dependencies(str(root)))}
    # backend: the lockfile resolves both, the package.json guesses are dropped
    assert ("sequelize", "4.13.10", "backend/package-lock.json") in deps
    assert ("lodash", "4.17.21", "backend/package-lock.json") in deps
    assert not [d for d in deps if d[2] == "backend/package.json"]
    # the root package.json has no lockfile at or above it: kept
    assert ("sequelize", "4.13.10", "package.json") in deps


def test_root_lockfile_covers_a_workspace_member(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3, "packages": {"": {"name": "x"},
                                           "node_modules/lodash": {"version": "4.17.21"}}}))
    _pkg(tmp_path / "packages" / "cli" / "package.json", {"lodash": "^4.17.4"})
    deps = {(d.name, d.version, d.source) for d in web_deps._dedupe(web_deps.collect_dependencies(str(tmp_path)))}
    assert deps == {("lodash", "4.17.21", "package-lock.json")}


def test_same_directory_keeps_the_strongest_proof(tmp_path):
    deps = [_WebDep("a:b", "1.0", "Maven", "svc/pom.xml"),
            _WebDep("a:b", "1.0", "Maven", "svc/build.gradle")]
    assert len(web_deps._dedupe(deps)) == 1


@pytest.mark.parametrize("raw,sent", [
    ("backend/package.json", "backend/package.json"),
    ("./backend/package.json", "backend/package.json"),
    ("backend\\api\\pom.xml", "backend/api/pom.xml"),
    ("/home/dev/repo/package.json", "package.json"),
    ("C:/Users/dev/repo/package.json", "package.json"),
    ("../other/package.json", "package.json"),
    ("package.json", "package.json"),
])
def test_manifest_path_is_relative_and_inside_the_root(raw, sent):
    assert web_deps._safe_rel_source(raw) == sent


def test_version_source_reads_the_basename_of_a_path():
    assert web_deps.version_source_for("backend/package.json") == "declared_range"
    assert web_deps.version_source_for("backend/package-lock.json") == "lockfile"
    assert web_deps.version_source_for("svc\\api\\pom.xml") == "declared_exact"


def test_sbom_keeps_one_component_per_package_version(tmp_path):
    comps, _scope = sbom.collect_components(str(_monorepo(tmp_path)))
    seq = [c for c in comps if c["name"] == "sequelize"]
    assert len(seq) == 1
