"""Dependency severity = the platform's (1.3.2).

morgan@1.9.0 (CVE-2019-5413) was CRITICAL in the CLI (raw OSV rating) and Low
on narvy.io (severity_calibration: fix_within_declared_range: dvna declares
^1.9.0 and 1.9.1 fixes it), so `--fail-on high` broke a build for a finding
the dashboard shows Low. narvy/sca/severity_calibration.py is a byte-for-byte
port of the platform's src/sast_shared/sca_severity.py; web_deps applies it
like src/web/sca/web_sca._finding_from_osv_group.
"""
import os
import shutil

import pytest

from narvy.sca import severity_calibration as cal
from narvy.sca import web_deps
from narvy.sca.web_deps import _WebDep

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "dvna_package.json")


def _rec(cve, sev, fixed, **kw):
    return {"cve": cve, "osv_id": kw.pop("osv_id", "GHSA-" + cve[-4:]), "severity": sev,
            "fixed_version": fixed, "summary": "s", "references": [], **kw}


class _Client:
    """morgan / mysql2 advisories as OSV returns them for dvna."""

    DATA = {
        ("morgan", "1.9.0"): [_rec("CVE-2019-5413", "CRITICAL", "1.9.1")],
        ("mysql2", "1.4.2"): [_rec("CVE-2024-21508", "CRITICAL", "3.9.4")],
    }

    def has_any_vuln_batch(self, pairs, ecosystem=None):
        return {p: p in self.DATA for p in pairs}

    def query_dict(self, name, version, ecosystem=None, platform_grouping=False):
        return [dict(r) for r in self.DATA.get((name, version), [])]


def _scan(tmp_path):
    shutil.copy(FIXTURE, tmp_path / "package.json")
    findings, _r, _s = web_deps.scan(str(tmp_path), osv_client=_Client())
    return {f["sca"]["package"]: f for f in findings}


def test_dvna_morgan_is_low_like_the_dashboard(tmp_path):
    f = _scan(tmp_path)["morgan"]
    assert f["severity"] == "LOW"
    assert f["severity_advisory"] == "CRITICAL"
    assert f["severity_calibration"] == ["fix_within_declared_range"]
    assert "fresh install" in f["details"]["description"]


def test_dvna_mysql2_fix_outside_the_range_stays_critical(tmp_path):
    f = _scan(tmp_path)["mysql2"]
    assert f["severity"] == "CRITICAL" and "severity_advisory" not in f


def test_exact_pin_is_never_range_calibrated():
    dep = _WebDep("morgan", "1.9.0", "npm", "package.json", "declared_exact")
    c = web_deps._calibrate(dep, [_rec("CVE-2019-5413", "CRITICAL", "1.9.1")], None)
    assert c["shown"] == "Critical"


def test_one_cve_in_range_one_not_keeps_the_open_one():
    dep = _WebDep("x", "1.0.0", "npm", "package.json", "declared_range", declared_spec="^1.0.0")
    recs = [_rec("CVE-2020-0001", "CRITICAL", "1.0.1"), _rec("CVE-2020-0002", "MEDIUM", "2.0.0")]
    c = web_deps._calibrate(dep, recs, None)
    assert c["shown"] == "Medium" and "fix_within_declared_range" in c["reasons"]
    f = [web_deps._finding_from_osv(dep, r) for r in recs]
    for fi, r in zip(f, recs):
        web_deps._apply_calibration(fi, r, c)
    assert sorted(x["severity"] for x in f) == ["LOW", "MEDIUM"]


def test_reviewed_label_and_local_vector():
    dep = _WebDep("certifi", "2024.2.2", "PyPI", "poetry.lock")
    reviewed = _rec("CVE-2024-39689", "HIGH", "2024.7.4", reviewed_severity="LOW",
                    mirror_worst_severity="High")
    assert web_deps._calibrate(dep, [reviewed], None)["shown"] == "Low"
    local = _rec("CVE-2024-0001", "CRITICAL", "9.9", osv_id="PYSEC-1",
                 cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert web_deps._calibrate(dep, [local], None)["shown"] == "Medium"


def test_dev_dependency_is_low():
    dep = _WebDep("jest", "1.0.0", "npm", "package-lock.json", scope="dev")
    assert web_deps._calibrate(dep, [_rec("CVE-2021-0001", "HIGH", None)], None)["shown"] == "Low"


def test_dev_scope_from_files(tmp_path):
    (tmp_path / "package.json").write_text('{"devDependencies": {"jest": "^1.0.0"}}')
    (deps,) = web_deps.collect_dependencies(str(tmp_path))
    assert deps.scope == "dev" and deps.declared_spec == "^1.0.0"


def test_runtime_copy_beats_dev_copy():
    a = _WebDep("x", "1.0.0", "npm", "package-lock.json", scope="dev")
    b = _WebDep("x", "1.0.0", "npm", "sub/package-lock.json", scope="runtime")
    (kept,) = web_deps._dedupe([a, b])
    assert kept.scope == "runtime"


def test_go_affected_package_not_imported():
    dep = _WebDep("golang.org/x/crypto", "0.1.0", "Go", "go.mod")
    rec = _rec("CVE-2022-0001", "HIGH", "0.2.0", affected_imports=["golang.org/x/crypto/openpgp"])
    assert web_deps._calibrate(dep, [rec], {"golang.org/x/crypto/ssh"})["shown"] == "Low"
    assert web_deps._calibrate(dep, [rec], {"golang.org/x/crypto/openpgp"})["shown"] == "High"


def test_port_is_identical_to_the_platform_module():
    saas = os.path.join(os.environ.get("NARVY_HOSTED_ENGINE_DIR",
                                       os.path.join(os.path.expanduser("~"), "titanshield")),
                        "src", "sast_shared", "sca_severity.py")
    if not os.path.isfile(saas):
        pytest.skip("platform checkout not available")
    def code(p):
        t = open(p).read()
        return t[t.index("from __future__"):]
    assert code(saas) == code(cal.__file__)
