import json
from typing import List, Dict, Any

from narvy import __version__

# Canonical SARIF severity mapping, shared by every emitter (scan + web/host/cloud).
# level = SARIF's per-result rank; security-severity = GitHub/GitLab 0-10 code-scanning score.
_SARIF_LEVEL_BY_SEV = {
    "critical": "error", "high": "error",
    "medium": "warning",
    "low": "note", "info": "note",
}
_SARIF_SECURITY_SEVERITY_BY_SEV = {
    "critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0", "info": "0.0",
}


def sarif_level(severity: str) -> str:
    """SARIF result level (error/warning/note) for a finding severity."""
    return _SARIF_LEVEL_BY_SEV.get(str(severity or "").strip().lower(), "warning")


def sarif_security_severity(severity: str) -> str:
    """GitHub/GitLab code-scanning security-severity (0-10 string) for a finding severity."""
    return _SARIF_SECURITY_SEVERITY_BY_SEV.get(str(severity or "").strip().lower(), "0.0")


_FAIRPLAY_RULE_ID = "IOS-FAIRPLAY-ENCRYPTED"
_FAIRPLAY_COVERAGE_TEXT = (
    "Partial coverage: this iOS binary is FairPlay-encrypted (App Store DRM, "
    "cryptid=1), so its __TEXT code section is ciphertext and could not be read "
    "statically. Info.plist, entitlements, URL schemes/ATS, load commands and "
    "Objective-C metadata WERE analyzed. The app's own code and string literals "
    "were NOT. Zero findings from the code/string rules on this run means 'not "
    "visible', not 'clean' - do not treat this scan as a clean bill of health."
)


def generate_sarif_report(findings: List[Dict[str, Any]], rules: List[Dict[str, Any]],
                          encrypted: bool = False,
                          encrypted_artifact_uri: str = None) -> Dict[str, Any]:
    """Generate a SARIF v2.1.0 report."""
    _SARIF_PRECISION = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}

    # SARIF's standard per-result field; properties.severity keeps our own label.
    _SARIF_LEVEL = {
        "CRITICAL": "error", "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note", "INFO": "note",
    }

    results = []
    for finding in findings:
        confidence = finding.get('confidence', 'MEDIUM')
        _sev = str(finding.get('severity', '') or '').upper()
        results.append({
            "ruleId": finding['rule_id'],
            "level": _SARIF_LEVEL.get(_sev, "warning"),
            "message": {
                "text": finding['details']['description']
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding['file_path']
                    },
                    "region": {
                        "startLine": finding.get('line', 1)
                    }
                }
            }],
            "properties": {
                "confidence": confidence,
                "precision": _SARIF_PRECISION.get(confidence, "medium"),
                "severity": _sev or "UNKNOWN",
                "security-severity": sarif_security_severity(_sev),
                **({"prngContext": finding['details']['prng_context'],
                    "prngContextEvidence": finding['details'].get('prng_context_evidence', '')}
                   if isinstance(finding.get('details'), dict)
                   and finding['details'].get('prng_context') else {}),
            }
        })

    if encrypted:
        _coverage_result: Dict[str, Any] = {
            "ruleId": _FAIRPLAY_RULE_ID,
            "level": "note",
            "message": {"text": _FAIRPLAY_COVERAGE_TEXT},
            "properties": {
                "confidence": "HIGH",
                "precision": "very-high",
                "severity": "INFO",
            },
        }
        if encrypted_artifact_uri:
            _coverage_result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": encrypted_artifact_uri},
                    "region": {"startLine": 1},
                }
            }]
        results.append(_coverage_result)

    tool_rules = []
    for rule in rules:
        rule_confidence = rule.get('confidence', 'MEDIUM')
        _rule_sev = str(rule.get('severity', '') or '').lower()
        tool_rules.append({
            "id": rule['id'],
            "name": rule['name'],
            "shortDescription": {
                "text": rule['details']['description']
            },
            "fullDescription": {
                "text": rule['details']['recommendation']
            },
            "help": {
                "text": f"CWE: {rule['details'].get('cwe')}\nMASVS: {rule['details'].get('masvs')}"
            },
            "defaultConfiguration": {"level": sarif_level(_rule_sev)},
            "properties": {
                "tags": ["security", "android", rule.get('masvs', '').lower()],
                "precision": _SARIF_PRECISION.get(rule_confidence, "medium"),
                "problem.severity": rule.get('severity', 'UNKNOWN').lower(),
                "security-severity": sarif_security_severity(_rule_sev),
            }
        })

    if encrypted:
        # GitHub's SARIF ingester resolves results[].ruleId against
        # tool.driver.rules[].id, so the result above needs this descriptor.
        tool_rules.append({
            "id": _FAIRPLAY_RULE_ID,
            "name": "FairPlayEncryptedBinaryPartialCoverage",
            "shortDescription": {
                "text": "Binary is FairPlay-encrypted - static analysis coverage is partial."
            },
            "fullDescription": {"text": _FAIRPLAY_COVERAGE_TEXT},
            "help": {
                "text": "Scan a decrypted binary (jailbroken-device dump) to analyze the "
                        "app's own code and string literals. This is a property of App "
                        "Store distribution, not a defect in the app."
            },
            "properties": {
                "tags": ["security", "ios", "coverage"],
                "precision": "very-high",
                "problem.severity": "note",
            },
        })

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Narvy CLI",
                "version": __version__,
                "informationUri": "https://narvy.io",
                "rules": tool_rules
            }
        },
        "results": results
    }
    if encrypted:
        run["invocations"] = [{
            # The invocation object's only required property (SARIF 2.1.0).
            "executionSuccessful": True,
            "toolExecutionNotifications": [{
                "level": "note",
                "message": {"text": _FAIRPLAY_COVERAGE_TEXT},
            }],
        }]

    report = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [run]
    }
    return report