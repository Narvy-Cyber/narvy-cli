"""Vulnerable-dependency findings carry CWE-1395, as on the platform (1.3.1).

The platform stamps CWE-1395 (Dependency on Vulnerable Third-Party Component)
with CWE-1035 as secondary on every vulnerable-dependency finding of both
engines (src/web/sca/web_sca.SCA_DEPENDENCY_CWE). The CLI said CWE-1104, so
console / SARIF / JSON / GitLab output named another CWE than the dashboard.
"""
import pytest

from narvy.reporter import generate_sarif_report
from narvy.sca import android_deps, ios_deps, osv_client, web_deps

_OSV = {"cve": "CVE-2099-0001", "severity": "HIGH", "fixed_version": "9.9.9", "summary": "x"}


def _findings():
    return [
        web_deps._finding_from_osv(web_deps._WebDep("qs", "6.5.2", "npm", "package-lock.json"), dict(_OSV)),
        android_deps._finding_from_osv(android_deps._Dep("com.squareup.okhttp3", "okhttp", "3.12.0", "pom"),
                                       dict(_OSV)),
        ios_deps._finding_from_cve(ios_deps._IOSDep("AFNetworking", "2.5.0", "podfile.lock"),
                                   dict(_OSV, cwe="CWE-295"), "curated"),
    ]


def test_one_constant_same_as_the_platform():
    assert osv_client.SCA_DEPENDENCY_CWE == "CWE-1395"
    assert osv_client.SCA_DEPENDENCY_CWE_SECONDARY == "CWE-1035"
    assert osv_client.OSVFinding().cwe == "CWE-1395"


@pytest.mark.parametrize("i", range(3))
def test_every_engine_says_cwe_1395(i):
    f = _findings()[i]
    assert f["details"]["cwe"] == "CWE-1395"
    assert f["details"]["cwe_secondary"] == "CWE-1035"


def test_ios_advisory_cwe_is_kept_beside_it():
    f = _findings()[2]
    assert f["sca"]["advisory_cwe"] == "CWE-295"
    assert "advisory_cwe" not in _findings()[0]["sca"]


def test_sarif_names_cwe_1395_never_1104():
    rules = [{"id": f["rule_id"], "name": f["name"], "severity": f["severity"],
              "details": dict(f["details"])} for f in _findings()]
    text = str(generate_sarif_report(_findings(), rules))
    assert "CWE-1395" in text and "CWE-1104" not in text


def test_ios_advisory_without_cwe_adds_nothing():
    f = ios_deps._finding_from_cve(ios_deps._IOSDep("Foo", "1.0", "podfile.lock"), dict(_OSV, cwe=None), "GitHub")
    assert f["details"]["cwe"] == "CWE-1395" and "advisory_cwe" not in f["sca"]
