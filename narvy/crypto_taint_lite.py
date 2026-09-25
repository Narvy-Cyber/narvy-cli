"""Match hardcoded key/IV literals to SecretKeySpec/IvParameterSpec by variable name, one file at a time."""
from __future__ import annotations

import re
from typing import Any, Dict, List

_LITERAL_STRING_ASSIGN = re.compile(
    r'\b(?:private\s+|public\s+|protected\s+|static\s+|final\s+)*'
    r'String\s+(\w+)\s*=\s*"([^"]{8,})"'
)
_LITERAL_ARRAY_ASSIGN = re.compile(
    r'\b(?:private\s+|public\s+|protected\s+|static\s+|final\s+)*'
    r'byte\[\]\s+(\w+)\s*=\s*\{[\d,\s]+\}'
)
_GETBYTES_ALIAS = re.compile(
    r'\b(\w+)\s*=\s*(?:this\.)?(\w+)\.getBytes\('
)
_SINK = re.compile(
    r'new\s+(SecretKeySpec|IvParameterSpec)\s*\(\s*(?:this\.)?(\w+)'
)

_RULE_INFO = {
    "SecretKeySpec": {
        "rule_id": "AND-CRYPTO-010",
        "name": "Hardcoded Symmetric Encryption Key (indirect)",
        "severity": "CRITICAL",
        "cwe": "CWE-321",
        "masvs": "MSTG-CRYPTO-1",
        "description": "A symmetric encryption key is built from a variable that traces back to a hardcoded string literal elsewhere in this file. Anyone who decompiles the app recovers the exact key used to encrypt/decrypt all protected data.",
        "recommendation": "Never embed encryption keys in source code, even indirectly through a named field. Derive keys via the Android Keystore system, or retrieve them from a secure backend at runtime.",
    },
    "IvParameterSpec": {
        "rule_id": "AND-CRYPTO-009",
        "name": "Hardcoded Cryptographic IV (indirect)",
        "severity": "HIGH",
        "cwe": "CWE-329",
        "masvs": "MSTG-CRYPTO-3",
        "description": "A hardcoded, static initialization vector (IV) - traced back to a literal byte array elsewhere in this file - is used for encryption. Reusing a static IV defeats the security properties of most cipher modes.",
        "recommendation": "Generate a fresh, random IV for every encryption operation using SecureRandom, and store/transmit it alongside the ciphertext (it does not need to be secret).",
    },
}


def check_file(content: str) -> List[Dict[str, Any]]:
    literal_vars = set()
    for m in _LITERAL_STRING_ASSIGN.finditer(content):
        literal_vars.add(m.group(1))
    for m in _LITERAL_ARRAY_ASSIGN.finditer(content):
        literal_vars.add(m.group(1))
    if not literal_vars:
        return []

    for m in _GETBYTES_ALIAS.finditer(content):
        alias, source = m.group(1), m.group(2)
        if source in literal_vars:
            literal_vars.add(alias)

    findings = []
    for m in _SINK.finditer(content):
        ctor, arg_var = m.group(1), m.group(2)
        if arg_var not in literal_vars:
            continue
        info = _RULE_INFO[ctor]
        line = content.count("\n", 0, m.start()) + 1
        findings.append({
            "rule_id": info["rule_id"],
            "name": info["name"],
            "severity": info["severity"],
            "line": line,
            "confidence": "MEDIUM",
            "engine": "crypto_taint_lite",
            "details": {
                "cwe": info["cwe"],
                "masvs": info["masvs"],
                "description": info["description"],
                "recommendation": info["recommendation"],
            },
        })
    return findings
