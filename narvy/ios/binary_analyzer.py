"""iOS IPA binary-mode SAST: symbol, string and Mach-O metadata checks on the
main executable and on first-party embedded frameworks.
"""
from __future__ import annotations

import os
import re
import struct
import shutil
import subprocess
import plistlib
import zipfile
from typing import Any, Dict, List, Optional, Tuple

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import icdump  # noqa: F401
    ICDUMP_AVAILABLE = True
except ImportError:
    ICDUMP_AVAILABLE = False

from .third_party_filter import (
    classify_ios_framework,
    check_ios_override,
    get_own_bundle_id,
    TIER_FIRST_PARTY,
    TIER_THIRD_PARTY,
    TIER_UNCONFIRMED,
)
from ..scope_config import ScopeConfig


def icdump_available() -> bool:
    return ICDUMP_AVAILABLE


# icdump.objc.parse() is a native extension that can SIGSEGV on some binaries,
# with no catchable Python exception, so it always runs out of process.
_ICDUMP_PROBE_SCRIPT = (
    "import sys, json, icdump\n"
    "md = icdump.objc.parse(sys.argv[1])\n"
    "print(json.dumps({'classes': len(md.classes), "
    "'methods': sum(len(c.methods) for c in md.classes)}))\n"
)


def _icdump_class_count(binary_path: str, timeout: int = 60
                          ) -> Tuple[bool, int, int, Optional[str]]:
    """Returns (ok, n_classes, n_methods, error)."""
    import sys as _sys
    try:
        proc = subprocess.run(
            [_sys.executable, "-c", _ICDUMP_PROBE_SCRIPT, binary_path],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, 0, 0, f"timed out after {timeout}s"
    except Exception as e:
        return False, 0, 0, str(e)
    if proc.returncode < 0:
        return False, 0, 0, f"crashed (signal {-proc.returncode})"
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, 0, 0, (detail[-1] if detail else f"exit code {proc.returncode}")
    try:
        import json as _json
        data = _json.loads(proc.stdout.strip().splitlines()[-1])
        return True, int(data["classes"]), int(data["methods"]), None
    except Exception as e:
        return False, 0, 0, f"could not parse subprocess output: {e}"


_RULES: Dict[str, Dict[str, Any]] = {}


def _register(rule_id: str, name: str, severity: str, cwe: str, masvs: str,
               description: str, recommendation: str) -> None:
    _RULES[rule_id] = {
        "id": rule_id,
        "name": name,
        "severity": severity,
        "details": {
            "cwe": cwe,
            "masvs": masvs,
            "description": description,
            "recommendation": recommendation,
        },
    }


def _finding(rule_id: str, file_path: str, description: Optional[str] = None,
             name: Optional[str] = None, severity: Optional[str] = None,
             location_symbol: Optional[str] = None) -> Dict[str, Any]:
    """`line` is a placeholder: a release binary carries no line-number table."""
    r = _RULES[rule_id]
    details = dict(r["details"])
    if description:
        details["description"] = description
    f: Dict[str, Any] = {
        "rule_id": rule_id,
        "file_path": file_path,
        "name": name or r["name"],
        "severity": severity or r["severity"],
        "line": 1,
        "engine": "binary",
        "details": details,
    }
    if location_symbol:
        f["location_symbol"] = location_symbol
    return f


def all_rule_defs() -> List[Dict[str, Any]]:
    return list(_RULES.values())


_register("IOS-BIN-CRYPTO-001", "Weak Cryptographic Algorithm", "HIGH", "CWE-327",
           "MSTG-CRYPTO-4",
           "Binary imports/uses a weak cryptographic algorithm (DES/3DES/RC2/RC4/ECB mode).",
           "Use AES-256 in GCM or CBC (with a random IV) mode instead.")
_register("IOS-BIN-CRYPTO-002", "Weak Hash Algorithm", "HIGH", "CWE-328",
           "MSTG-CRYPTO-4",
           "Binary imports/uses a weak or broken hash algorithm (MD2/MD4/MD5/SHA1).",
           "Replace with SHA-256 or stronger.")
_register("IOS-BIN-CRYPTO-003", "Non-Cryptographic RNG API Linked", "INFO", "CWE-338",
           "MSTG-CRYPTO-6",
           "Binary links a non-cryptographic RNG API (rand/srand/random) and also links "
           "cryptographic APIs. INFORMATIONAL ONLY: this is symbol co-presence, not "
           "evidence of insecure key/nonce generation - establishing that needs call-site "
           "analysis this binary-mode scanner does not perform. Statically linked zlib/"
           "ffmpeg/sqlite pull in rand() on their own.",
           "No action required on this finding alone. If you do generate keys, tokens, IVs "
           "or nonces, confirm those specific call sites use SecRandomCopyBytes (or "
           "arc4random_buf), not rand()/random().")

_register("IOS-BIN-SEC-001", "Missing PIE (Position Independent Executable)", "HIGH",
           "CWE-693", "MSTG-CODE-9",
           "Binary is not compiled as a Position Independent Executable.",
           "Enable PIE (default in Xcode; verify no -Wl,-no_pie / legacy build setting).")
_register("IOS-BIN-SEC-002", "Missing Stack Canary", "HIGH", "CWE-693", "MSTG-CODE-9",
           "Native (C/Objective-C) code in this binary is compiled without stack-smashing "
           "protection (___stack_chk_guard/___stack_chk_fail absent).",
           "Build with -fstack-protector-all (Xcode default; verify custom build flags "
           "haven't disabled it).")
_register("IOS-BIN-SEC-003", "Missing ARC (Automatic Reference Counting)", "MEDIUM",
           "CWE-401", "MSTG-CODE-9",
           "Objective-C code in this binary appears to be compiled without ARC "
           "(objc_retain/objc_release symbols absent despite custom Objective-C classes).",
           "Enable ARC (CLANG_ENABLE_OBJC_ARC = YES) for automatic memory management and "
           "use-after-free prevention.")
_register("IOS-BIN-SEC-004", "Binary Missing Code Signature", "HIGH", "CWE-345",
           "MSTG-CODE-9",
           "No LC_CODE_SIGNATURE load command found - this binary is not code-signed.",
           "Ensure the IPA is built and exported for distribution (ad-hoc/App Store) with "
           "a valid signing identity; iOS refuses to run unsigned binaries on real devices.")

_register("IOS-BIN-SENSITIVE-001", "Hardcoded Credential in Binary", "HIGH", "CWE-798",
           "MSTG-STORAGE-1",
           "A binary string looks like a hardcoded password/API key/secret-key assignment.",
           "Remove hardcoded credentials; use Keychain for anything secret at runtime, and "
           "fetch API keys from a backend/config service instead of compiling them in.")
_register("IOS-BIN-SENSITIVE-002", "SQL Query Built with String Formatting", "HIGH",
           "CWE-89", "MSTG-CODE-8",
           "A compiled-in SQL statement contains a format-string placeholder "
           "(SELECT/INSERT/UPDATE/DELETE ... %), consistent with a query assembled by "
           "string interpolation rather than parameter binding.",
           "Use parameterized queries / prepared statements (sqlite3_bind_*, NSPredicate, "
           "or an ORM) instead of formatting SQL text.")
_register("IOS-BIN-SENSITIVE-003", "Sensitive Data Logged", "MEDIUM", "CWE-532",
           "MSTG-STORAGE-3",
           "A compiled-in NSLog format string references password/token/secret, "
           "consistent with sensitive data being written to the device console log.",
           "Remove sensitive values from log statements, or strip logging in release "
           "builds.")
_register("IOS-BIN-SENSITIVE-004", "Insecure Deserialization API", "MEDIUM", "CWE-502",
           "MSTG-PLATFORM-8",
           "Binary references the legacy NSKeyedUnarchiver "
           "unarchiveObjectWithData:/unarchiveObjectWithFile: selectors, which decode "
           "without a class allowlist unless the caller has opted into secure coding.",
           "Use unarchivedObjectOfClasses:fromData:error: (NSSecureCoding) instead of the "
           "legacy unarchiveObjectWithData:/unarchiveObjectWithFile: APIs.")

_register("IOS-BIN-API-001", "Insecure Keychain Accessibility (Always)", "HIGH", "CWE-522",
           "MSTG-STORAGE-1",
           "Binary references kSecAttrAccessibleAlways, which keeps Keychain items "
           "readable even when the device is locked AND lets them sync to iCloud Keychain "
           "and unencrypted backups (they leave the device).",
           "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or "
           "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly for background needs).")
_register("IOS-BIN-API-006", "Keychain Accessibility Always (Device-Bound)", "MEDIUM",
           "CWE-522", "MSTG-STORAGE-1",
           "Binary references kSecAttrAccessibleAlwaysThisDeviceOnly: the item is readable "
           "even while the device is locked. It is device-bound (never synced to iCloud "
           "Keychain, never restored to another device from a backup), so the risk is "
           "materially lower than the plain kSecAttrAccessibleAlways it is often confused "
           "with, but a locked/stolen device still exposes it.",
           "Prefer kSecAttrAccessibleWhenUnlockedThisDeviceOnly, or "
           "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly if a background task genuinely "
           "needs the item before first unlock.")
_register("IOS-BIN-API-002", "Deprecated Insecure WebView (UIWebView)", "HIGH", "CWE-79",
           "MSTG-PLATFORM-2",
           "Binary links against the deprecated, insecure UIWebView (Apple has rejected "
           "App Store submissions using it since Dec 2020).",
           "Migrate to WKWebView.")
_register("IOS-BIN-API-003", "No File Protection on Written Data", "HIGH", "CWE-311",
           "MSTG-STORAGE-1",
           "Binary references NSDataWritingFileProtectionNone, explicitly disabling "
           "iOS Data Protection encryption for the written file.",
           "Use NSDataWritingFileProtectionComplete (or "
           "CompleteUnlessOpen/CompleteUntilFirstUserAuthentication as appropriate).")
_register("IOS-BIN-API-004", "Deprecated Networking API (NSURLConnection)", "MEDIUM",
           "CWE-477", "MSTG-NETWORK-1",
           "Binary references the deprecated NSURLConnection API (deprecated iOS 9+).",
           "Migrate to URLSession.")
_register("IOS-BIN-API-005", "Deprecated Low-Level SSL/TLS API", "MEDIUM", "CWE-327",
           "MSTG-NETWORK-2",
           "Binary references the deprecated Secure Transport SSLCreateContext API.",
           "Use URLSession/Network.framework, which negotiate current TLS versions and "
           "handle certificate validation correctly by default.")

_register("IOS-BIN-RASP-001", "No Runtime Application Self-Protection Detected", "MEDIUM",
           "CWE-693", "MSTG-RESILIENCE-1",
           "No commercial RASP SDK and no anti-tampering signal (ptrace/jailbreak/"
           "Frida-detection strings) found in this binary.",
           "For high-risk apps (banking, health, payments) consider a RASP SDK "
           "(commercial: Zimperium/Guardsquare/Digital.ai/Promon, or open-source "
           "Talsec freeRASP) plus basic ptrace/jailbreak/Frida-detection.")

_register("IOS-BIN-URL-001", "Custom URL Scheme Registered", "MEDIUM", "CWE-284",
           "MSTG-PLATFORM-3",
           "App registers a custom (non-system) URL scheme. Any other app can register "
           "the same scheme and potentially hijack deep links.",
           "Prefer Universal Links (https://) for deep linking; if a custom scheme is "
           "required, validate the calling app via options[.sourceApplication].")
_register("IOS-BIN-URL-002", "Custom URL Schemes Without Universal Links", "MEDIUM",
           "CWE-284", "MSTG-PLATFORM-3",
           "App declares custom URL scheme(s) but its entitlements carry no "
           "applinks: associated domain, so it has no Universal Links fallback.",
           "Implement Universal Links (com.apple.developer.associated-domains "
           "entitlement + apple-app-site-association on your domain).")
_register("IOS-BIN-URL-003", "App Transport Security Disabled", "HIGH", "CWE-319",
           "MSTG-NETWORK-2",
           "NSAllowsArbitraryLoads is true in Info.plist - ATS is disabled app-wide, "
           "permitting cleartext HTTP to any host.",
           "Remove NSAllowsArbitraryLoads (or set it false); use per-domain exceptions "
           "only where a real third-party requirement forces cleartext.")
_register("IOS-BIN-URL-004", "ATS Insecure HTTP Exception for Domain", "MEDIUM",
           "CWE-319", "MSTG-NETWORK-2",
           "NSExceptionAllowsInsecureHTTPLoads is true for a specific domain in "
           "NSAppTransportSecurity.",
           "Use HTTPS for this domain; remove the exception once the backend supports TLS.")
_register("IOS-BIN-URL-005", "ATS Insecure HTTP for All Subdomains", "HIGH", "CWE-319",
           "MSTG-NETWORK-2",
           "NSIncludesSubdomains + NSExceptionAllowsInsecureHTTPLoads together allow "
           "cleartext HTTP to every subdomain of the exception domain.",
           "Scope the exception to the exact subdomain that needs it; do not combine "
           "NSIncludesSubdomains with an insecure-HTTP exception.")
_register("IOS-BIN-URL-006", "Querying Sensitive App URL Schemes", "MEDIUM", "CWE-200",
           "MSTG-PLATFORM-3",
           "LSApplicationQueriesSchemes includes schemes suggestive of banking/health/"
           "finance/auth apps, which can be used to fingerprint installed apps.",
           "Only query schemes that are essential for a real integration; avoid using "
           "canOpenURL as an app-presence fingerprinting signal.")


_STRINGS_BIN = shutil.which("strings")

# Pure-Python fallback for `strings -a`: runs of >=4 printable ASCII bytes.
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _get_strings(binary_path: str) -> List[str]:
    """ASCII strings in the file. Never raises: returns [] on any failure."""
    if _STRINGS_BIN:
        try:
            out = subprocess.check_output(
                [_STRINGS_BIN, "-a", binary_path],
                stderr=subprocess.DEVNULL, timeout=60,
            )
            return out.decode("utf-8", errors="ignore").split("\n")
        except Exception:
            pass
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
        return [m.decode("ascii") for m in _PRINTABLE_RUN_RE.findall(data)]
    except OSError:
        return []


class ParsedMachO:
    """Keeps a Mach-O slice and the parent FatBinary it was yielded from alive
    together: a slice whose FatBinary is collected dangles and segfaults."""

    __slots__ = ("_fat", "binary")

    def __init__(self, fat, binary):
        self._fat = fat
        self.binary = binary


def _pick_best_slice(binary_path: str) -> Optional[ParsedMachO]:
    """Return the best single-arch slice of a Mach-O, arm64 first, or None."""
    if not LIEF_AVAILABLE:
        return None
    try:
        fat = lief.MachO.parse(binary_path)
    except Exception:
        return None
    if not fat or len(fat) == 0:
        return None
    best = None
    best_rank = -1
    for b in fat:
        try:
            cpu = str(b.header.cpu_type)
        except Exception:
            cpu = ""
        rank = 3 if "ARM64" in cpu else 2 if "ARM" in cpu else 1 if "X86_64" in cpu else 0
        if rank > best_rank:
            best, best_rank = b, rank
    if best is None:
        return None
    return ParsedMachO(fat, best)


def _symbol_names(parsed: Optional["ParsedMachO"]) -> List[str]:
    if parsed is None:
        return []
    try:
        return [s.name for s in parsed.binary.symbols if getattr(s, "name", None)]
    except Exception:
        return []


# Mach-O nlist n_type bit fields (<mach-o/nlist.h>), read off `Symbol.raw_type`:
# LIEF's `Symbol.type` enum masks N_TYPE without first stripping the N_STAB bits.
_N_STAB = 0xe0
_N_TYPE = 0x0e
_N_UNDF = 0x00


def _symbol_is_defined(sym) -> bool:
    """True if this Mach-O defines `sym`, rather than importing or debug-listing it."""
    raw = getattr(sym, "raw_type", None)
    if raw is not None:
        try:
            raw = int(raw)
            if raw & _N_STAB:
                return False
            return (raw & _N_TYPE) != _N_UNDF
        except (TypeError, ValueError):
            pass
    try:
        return not (bool(getattr(sym, "is_external", False))
                    and int(getattr(sym, "value", 0)) == 0)
    except Exception:
        return True


def _defined_symbol_names(parsed: Optional["ParsedMachO"]) -> List[str]:
    if parsed is None:
        return []
    try:
        return [s.name for s in parsed.binary.symbols
                if getattr(s, "name", None) and _symbol_is_defined(s)]
    except Exception:
        return []


# A Swift class exposed to the ObjC runtime gets an _OBJC_CLASS_$__TtC... symbol
# emitted by the Swift compiler, which is not hand-written Objective-C.
_SWIFT_OBJC_THUNK_MARKER = "_TtC"


def _has_custom_objc_classes(defined_symbol_names: List[str]) -> bool:
    skip = ("NSObject", "NSString", "NSArray", "NSDictionary", "NSNumber",
            "NSData", "NSError", "NSException", "NSValue", "NSURL", "NSDate",
            "NSSet", "PodsDummy_", "Swift")
    return any(
        "_OBJC_CLASS_$_" in n
        and _SWIFT_OBJC_THUNK_MARKER not in n
        and not any(s in n for s in skip)
        for n in defined_symbol_names
    )


def _is_swift(symbol_names: List[str]) -> bool:
    return any(n.startswith("_$s") or n.startswith("$s") for n in symbol_names)


def _has_arc_symbols(symbol_names: List[str]) -> bool:
    return any(n in symbol_names for n in
               ("_objc_release", "_objc_retain", "_objc_autoreleaseReturnValue"))


def _has_canary_symbols(symbol_names: List[str]) -> bool:
    return any(n in symbol_names for n in ("___stack_chk_fail", "___stack_chk_guard"))


_WEAK_CRYPTO_ALGOS = {
    "kCCAlgorithmDES": ("DES", "HIGH"), "CCAlgorithmDES": ("DES", "HIGH"),
    "kCCAlgorithm3DES": ("3DES", "MEDIUM"), "CCAlgorithm3DES": ("3DES", "MEDIUM"),
    "kCCAlgorithmRC2": ("RC2", "HIGH"),
    "kCCAlgorithmRC4": ("RC4", "HIGH"),
    "kCCOptionECBMode": ("ECB Mode", "HIGH"), "kCCModeECB": ("ECB Mode", "HIGH"),
}
_WEAK_HASH_ALGOS = {
    "CC_MD2": ("MD2", "HIGH"), "CC_MD4": ("MD4", "HIGH"), "CC_MD5": ("MD5", "HIGH"),
    "kCCHmacAlgMD5": ("HMAC-MD5", "HIGH"),
    "CC_SHA1": ("SHA1", "MEDIUM"), "kCCHmacAlgSHA1": ("HMAC-SHA1", "MEDIUM"),
}
_INSECURE_RANDOM_SYMBOLS = ("_srand", "_random", "_rand")


def _check_crypto(corpus_blob: str, symbol_names: List[str], file_path: str,
                   findings: List[Dict[str, Any]]) -> None:
    # Match against the joined symbol text, not exact token membership.
    seen_algo = set()
    for token, (algo_name, sev) in _WEAK_CRYPTO_ALGOS.items():
        if token in corpus_blob and algo_name not in seen_algo:
            seen_algo.add(algo_name)
            findings.append(_finding(
                "IOS-BIN-CRYPTO-001", file_path, severity=sev,
                description=f"Binary references weak cryptographic algorithm: {algo_name} "
                            f"(symbol/constant: {token}).",
                location_symbol=token))
    seen_hash = set()
    for token, (algo_name, sev) in _WEAK_HASH_ALGOS.items():
        if token in corpus_blob and algo_name not in seen_hash:
            seen_hash.add(algo_name)
            findings.append(_finding(
                "IOS-BIN-CRYPTO-002", file_path, severity=sev,
                description=f"Binary references weak hash algorithm: {algo_name} "
                            f"(symbol/constant: {token}).",
                location_symbol=token))
    uses_crypto_api = any(t in corpus_blob for t in
                           ("CCCrypt", "SecKeyEncrypt", "kCCAlgorithmAES", "CC_SHA256"))
    if uses_crypto_api:
        for sym in _INSECURE_RANDOM_SYMBOLS:
            if sym in symbol_names:
                has_csprng = any(t in corpus_blob for t in
                                  ("_arc4random", "arc4random_buf", "SecRandomCopyBytes"))
                csprng_note = (
                    " This binary already links a CSPRNG (arc4random/SecRandomCopyBytes), "
                    "so the security-sensitive paths are most likely already correct."
                    if has_csprng else "")
                findings.append(_finding(
                    "IOS-BIN-CRYPTO-003", file_path,
                    description=f"Binary links the non-cryptographic RNG API "
                                f"{sym.lstrip('_')}() and also links cryptographic APIs. "
                                f"Informational only - no evidence of insecure key/nonce "
                                f"generation: this is symbol co-presence with no call-site "
                                f"link, and statically linked zlib/ffmpeg/sqlite import "
                                f"rand() by themselves.{csprng_note}",
                    location_symbol=sym))
                break


def _check_macho_security(parsed: "ParsedMachO", symbol_names: List[str], file_path: str,
                           is_main_binary: bool, findings: List[Dict[str, Any]]) -> None:
    binary = parsed.binary
    defined_names = _defined_symbol_names(parsed)
    # PIE is only meaningful for the main executable: dylibs are always
    # position-independent by construction.
    if is_main_binary:
        try:
            pie = bool(binary.is_pie)
        except Exception:
            pie = True
        if not pie:
            findings.append(_finding("IOS-BIN-SEC-001", file_path,
                                      location_symbol="Mach-O header (MH_PIE flag)"))

    is_swift = _is_swift(symbol_names)
    has_objc = _has_custom_objc_classes(defined_names)
    is_swift_only = is_swift and not has_objc

    # A fully stripped binary exposes no symbols at all, which is the absence of
    # any signal, not evidence that a canary or ARC is missing.
    has_any_symbols = bool(symbol_names)
    # Stack canary and ARC only apply to native C/Obj-C code; Swift is memory-safe.
    if has_any_symbols and not is_swift_only:
        if not _has_canary_symbols(symbol_names):
            # clang emits a canary only for functions owning a stack buffer, so a
            # small framework can legitimately have none.
            findings.append(_finding(
                "IOS-BIN-SEC-002", file_path,
                severity=None if is_main_binary else "INFO",
                description=None if is_main_binary else (
                    "No ___stack_chk_guard/___stack_chk_fail reference in this embedded "
                    "framework. INFORMATIONAL ONLY: clang emits a stack canary only for "
                    "functions that own a stack buffer, so a small module can legitimately "
                    "have none while stack protection is enabled. This is not evidence "
                    "-fstack-protector was disabled - confirm against the module's build "
                    "settings before acting on it."),
                location_symbol="symbol table (___stack_chk_fail/___stack_chk_guard absent)"))
        if has_objc and not _has_arc_symbols(symbol_names):
            findings.append(_finding(
                "IOS-BIN-SEC-003", file_path,
                location_symbol="symbol table (objc_retain/objc_release absent)"))

    try:
        signed = bool(binary.has_code_signature)
    except Exception:
        signed = True
    if not signed:
        findings.append(_finding(
            "IOS-BIN-SEC-004", file_path,
            location_symbol="code signature (LC_CODE_SIGNATURE load command absent)"))


_CRED_FP_MARKERS = (
    "%@", "%s", "%d", "%ld", "%lld", "%lu", "%u", "%i", "%f", "{0}", "{1}",
    "${", "$(", "<key>", "<string>", "placeholder",
    "x-api-key", "authorization:", "content-type",
)
_CRED_FP_VALUES = {
    "true", "false", "nil", "null", "none", "undefined", "value", "string",
    "header", "token", "apikey", "secretkey", "password", "username",
    "yes", "no", "example", "<value>",
}
_CRED_VALUE_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret[_-]?key|password|pwd|passwd)"
    r"\s*[=:\"']\s*([A-Za-z0-9+/=._\-]{8,})"
)
# Display only: which keyword matched. Detection stays with _CRED_VALUE_RE.
_CRED_KEYWORD_RE = re.compile(r"(?i)(api[_-]?key|secret[_-]?key|password|pwd|passwd)")


def _looks_like_real_secret_assignment(line: str) -> Optional[str]:
    """Return the assigned value, or None: a bare keyword is not a secret."""
    low = line.lower().strip()
    if any(m in low for m in _CRED_FP_MARKERS):
        return None
    m = _CRED_VALUE_RE.search(line)
    if not m:
        return None
    val = m.group(1)
    if val.lower() in _CRED_FP_VALUES:
        return None
    # Reject Obj-C selector fragments ("keyword:value:moreKeyword:"), where the
    # captured value is immediately followed by another colon.
    if m.end() < len(line) and line[m.end()] == ":":
        return None
    if any(c.isdigit() for c in val) or len(val) >= 16:
        return val
    return None


# `%` is also SQL's LIKE wildcard, so only a real conversion specifier outside a
# single-quoted literal counts as interpolation.
_SQL_FORMAT_SPEC = (
    r"%(?:\d+\$)?[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L|q)?[@dioufFeEgGxXsScCp]"
)
_SQL_FORMAT_SPEC_RE = re.compile(_SQL_FORMAT_SPEC)
_SQL_SINGLE_QUOTED_LITERAL_RE = re.compile(r"'[^']*'")

_SQL_FORMAT_RE = re.compile(
    r"(?i)(?:SELECT\s+.+\s+FROM\s+.+\s+WHERE\s+.+" + _SQL_FORMAT_SPEC + r"|"
    r"INSERT\s+INTO\s+.+\s+VALUES\s*\(.+" + _SQL_FORMAT_SPEC + r"|"
    r"UPDATE\s+.+\s+SET\s+.+\s+WHERE\s+.+" + _SQL_FORMAT_SPEC + r"|"
    r"DELETE\s+FROM\s+.+\s+WHERE\s+.+" + _SQL_FORMAT_SPEC + r")"
)


def _blank_sql_like_wildcard_literals(line: str) -> str:
    def _repl(m: "re.Match") -> str:
        body = m.group(0)
        if "%" not in body:
            return body
        # Whatever stays percent-shaped after stripping real specifiers is a
        # LIKE wildcard, making the whole literal a pattern rather than a slot.
        residue = _SQL_FORMAT_SPEC_RE.sub("", body)
        return "''" if "%" in residue else body
    return _SQL_SINGLE_QUOTED_LITERAL_RE.sub(_repl, line)


def _sql_built_by_string_formatting(line: str) -> bool:
    if "%" not in line:
        return False
    return bool(_SQL_FORMAT_RE.search(_blank_sql_like_wildcard_literals(line)))
_NSLOG_SENSITIVE_RE = re.compile(r"(?i)NSLog.{0,60}(?:password|token|secret)")
_DESERIALIZATION_RE = re.compile(r"unarchiveObjectWith(?:Data|File)")


def _check_sensitive_strings(strings_list: List[str], file_path: str,
                              findings: List[Dict[str, Any]]) -> None:
    seen_cred = False
    seen_sql = False
    seen_log = False
    seen_deser = False
    for line in strings_list:
        if not seen_cred and ("password" in line.lower() or "api" in line.lower()
                               or "secret" in line.lower()):
            val = _looks_like_real_secret_assignment(line)
            if val:
                seen_cred = True
                kw_match = _CRED_KEYWORD_RE.search(line)
                kw = kw_match.group(1) if kw_match else "credential"
                findings.append(_finding(
                    "IOS-BIN-SENSITIVE-001", file_path,
                    description=f"Hardcoded credential-like assignment found in binary "
                                f"strings: {line.strip()[:120]!r}.",
                    location_symbol=f"string constant (matched keyword: {kw})"))
        if not seen_sql and _sql_built_by_string_formatting(line):
            seen_sql = True
            findings.append(_finding(
                "IOS-BIN-SENSITIVE-002", file_path,
                description=f"SQL statement with a format-string placeholder found in "
                            f"binary strings: {line.strip()[:150]!r}.",
                location_symbol="string constant (SQL statement)"))
        if not seen_log and _NSLOG_SENSITIVE_RE.search(line):
            seen_log = True
            findings.append(_finding(
                "IOS-BIN-SENSITIVE-003", file_path,
                description=f"Log format string references sensitive data: "
                            f"{line.strip()[:150]!r}.",
                location_symbol="string constant (NSLog format string)"))
        if not seen_deser and _DESERIALIZATION_RE.search(line):
            seen_deser = True
            deser_match = _DESERIALIZATION_RE.search(line)
            findings.append(_finding(
                "IOS-BIN-SENSITIVE-004", file_path,
                location_symbol=f"selector: {deser_match.group(0)}"))
        if seen_cred and seen_sql and seen_log and seen_deser:
            break


# The bare name also shows up in unrelated allowlists. These linkage markers
# identify UIWebView usage via the binary's linkage/metadata sections.
_UIWEBVIEW_LINKAGE_MARKERS = (
    "_OBJC_CLASS_$_UIWebView", "_OBJC_METACLASS_$_UIWebView",
    '@"UIWebView"', "So9UIWebView", "UIWebViewDelegate",
)

_DANGEROUS_API_STRING_CHECKS = (
    ("NSDataWritingFileProtectionNone", "IOS-BIN-API-003"),
    ("NSURLConnection", "IOS-BIN-API-004"),
    ("SSLCreateContext", "IOS-BIN-API-005"),
)

# The lookahead stops the bare constant matching inside the materially different
# kSecAttrAccessibleAlwaysThisDeviceOnly.
_KEYCHAIN_ALWAYS_BARE_RE = re.compile(r"kSecAttrAccessibleAlways(?!ThisDeviceOnly)")
_KEYCHAIN_ALWAYS_DEVICE_ONLY_RE = re.compile(r"kSecAttrAccessibleAlwaysThisDeviceOnly")


def _check_keychain_accessibility(corpus_blob: str, file_path: str,
                                   findings: List[Dict[str, Any]]) -> None:
    if _KEYCHAIN_ALWAYS_BARE_RE.search(corpus_blob):
        findings.append(_finding(
            "IOS-BIN-API-001", file_path,
            description="Binary references kSecAttrAccessibleAlways (the bare constant, "
                        "not ...ThisDeviceOnly): Keychain items stay readable while the "
                        "device is locked AND are eligible for iCloud Keychain sync and "
                        "unencrypted backup restore onto another device.",
            location_symbol="kSecAttrAccessibleAlways"))
    if _KEYCHAIN_ALWAYS_DEVICE_ONLY_RE.search(corpus_blob):
        findings.append(_finding(
            "IOS-BIN-API-006", file_path,
            description="Binary references kSecAttrAccessibleAlwaysThisDeviceOnly: the "
                        "Keychain item is readable while the device is locked, but it is "
                        "device-bound (no iCloud Keychain sync, not restorable to another "
                        "device), so the exfiltration risk of the plain "
                        "kSecAttrAccessibleAlways does not apply here.",
            location_symbol="kSecAttrAccessibleAlwaysThisDeviceOnly"))


def _check_dangerous_apis(corpus_blob: str, file_path: str,
                           findings: List[Dict[str, Any]]) -> None:
    uiwebview_hit = next((m for m in _UIWEBVIEW_LINKAGE_MARKERS if m in corpus_blob), None)
    if uiwebview_hit:
        findings.append(_finding("IOS-BIN-API-002", file_path,
                                  location_symbol=f"symbol/string: {uiwebview_hit}"))
    for token, rule_id in _DANGEROUS_API_STRING_CHECKS:
        if token in corpus_blob:
            findings.append(_finding(rule_id, file_path, location_symbol=token))
    _check_keychain_accessibility(corpus_blob, file_path, findings)


_RASP_SIGNATURES = {
    "Guardsquare iXGuard": ("ixguard", "iXGuard", "GuardsquareSDK", "dexguard", "DexGuard"),
    "Zimperium zShield": ("zimperium", "Zimperium", "zShield", "zIPS", "ZDetection"),
    "Digital.ai (Arxan)": ("arxan", "Arxan", "digital_ai", "TransformIT"),
    "Promon SHIELD": ("promon", "Promon", "PromonShield"),
    "Appdome": ("appdome", "Appdome", "APPDOME_"),
    "Talsec freeRASP": ("talsec", "Talsec", "freeRASP", "FreeRasp", "TalsecSecurity"),
}
# Anti-tamper / anti-debug / jailbreak-detection indicator strings.
_ANTI_TAMPER_PATTERNS = (
    "ptrace", "PT_DENY_ATTACH", "P_TRACED", "isDebugged", "debugger_attached",
    "frida", "substrate", "cycript", "objection", "SSLKillSwitch", "trustkit",
    "jailbroken", "jailbreak", "Cydia", "MobileSubstrate", "libhooker",
    "/var/jb", "DYLD_INSERT",
)

# Unambiguous on their own, so one hit is enough where the generic list needs two.
_STRONG_ANTI_TAMPER_PATTERNS = (
    "jailbroken", "jailbreak", "Cydia", "MobileSubstrate", "libhooker", "/var/jb",
)

# Matching is case-insensitive: the real symbols are CamelCase identifiers.

def _check_rasp(strings_list: List[str], symbol_names: List[str], file_path: str,
                 findings: List[Dict[str, Any]], notes: List[str],
                 encrypted: bool = False) -> None:
    corpus = " ".join(strings_list) + " " + " ".join(symbol_names)
    corpus_lower = corpus.lower()
    detected_libs = []
    for lib_name, sigs in _RASP_SIGNATURES.items():
        if any(s in corpus for s in sigs):
            detected_libs.append(lib_name)
    anti_tamper_hits = [p for p in _ANTI_TAMPER_PATTERNS if p.lower() in corpus_lower]
    strong_hits = [p for p in _STRONG_ANTI_TAMPER_PATTERNS if p.lower() in corpus_lower]

    if detected_libs:
        notes.append(f"RASP/anti-tampering SDK detected ({', '.join(detected_libs)}) - "
                      f"informational, no finding raised.")
    elif strong_hits or len(anti_tamper_hits) >= 2:
        notes.append(f"Custom anti-tampering signals present ({len(anti_tamper_hits)} "
                      f"patterns: {', '.join(anti_tamper_hits[:5])}) - informational, "
                      f"no finding raised.")
    elif encrypted:
        notes.append(
            "RASP/anti-tampering: UNKNOWN, not assessed - this binary is FairPlay-encrypted "
            "so its own strings are unreadable and this check cannot assess it. No finding "
            "raised (an absence of evidence here is not evidence of absence).")
    else:
        findings.append(_finding(
            "IOS-BIN-RASP-001", file_path,
            location_symbol="binary-wide string/symbol scan (no signal found)"))


# com.apple.developer.associated-domains is an entitlements key, never an
# Info.plist key, so Universal Links can only be read out of the signature blob.
_CSMAGIC_EMBEDDED_ENTITLEMENTS = b"\xfa\xde\x71\x71"
_MAX_ENTITLEMENTS_BLOB = 1_000_000


def extract_entitlements_from_binary(binary_path: str) -> Dict[str, Any]:
    """Read entitlements out of a Mach-O code signature. {} means unreadable."""
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except OSError:
        return {}
    offset = 0
    while True:
        index = data.find(_CSMAGIC_EMBEDDED_ENTITLEMENTS, offset)
        if index < 0:
            return {}
        offset = index + 4
        try:
            length = struct.unpack(">I", data[index + 4:index + 8])[0]
        except struct.error:
            continue
        if not (8 < length < _MAX_ENTITLEMENTS_BLOB):
            continue
        blob = data[index + 8:index + length]
        if b"<plist" not in blob:
            continue
        try:
            parsed = plistlib.loads(blob)
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


# Apple back-deployment dylibs bundled directly under Frameworks/, matched by
# filename convention rather than by the ObjC/Swift class-prefix convention.
_APPLE_REDIST_DYLIB_PREFIXES = ("libswift", "libSystem", "libobjc", "libc++", "libz.",
                                 "libsqlite3", "libicucore", "libnetwork", "libDER")

_SYSTEM_URL_SCHEMES = {"http", "https", "mailto", "tel", "sms", "facetime", "facetime-audio"}
_SENSITIVE_SCHEME_MARKERS = ("bank", "health", "medical", "finance", "password", "auth")


def _check_url_schemes(plist: Dict[str, Any], entitlements: Optional[Dict[str, Any]],
                        findings: List[Dict[str, Any]]) -> None:
    file_path = "Info.plist"
    url_types = plist.get("CFBundleURLTypes") or []
    custom_schemes = []
    for ut in url_types:
        for scheme in ut.get("CFBundleURLSchemes") or []:
            if isinstance(scheme, str) and scheme.lower() not in _SYSTEM_URL_SCHEMES:
                custom_schemes.append(scheme)
    if custom_schemes:
        findings.append(_finding(
            "IOS-BIN-URL-001", file_path,
            description=f"Custom URL scheme(s) registered: {', '.join(custom_schemes)}.",
            location_symbol="Info.plist key: CFBundleURLTypes/CFBundleURLSchemes"))

    if custom_schemes and entitlements is not None:
        domains = entitlements.get("com.apple.developer.associated-domains") or []
        has_universal_links = any(
            isinstance(d, str) and d.startswith("applinks:") for d in domains)
        if not has_universal_links:
            findings.append(_finding(
                "IOS-BIN-URL-002", file_path,
                location_symbol="entitlement: com.apple.developer.associated-domains (absent)"))

    query_schemes = plist.get("LSApplicationQueriesSchemes") or []
    sensitive = [s for s in query_schemes if isinstance(s, str)
                 and any(m in s.lower() for m in _SENSITIVE_SCHEME_MARKERS)]
    if sensitive:
        findings.append(_finding(
            "IOS-BIN-URL-006", file_path,
            description=f"LSApplicationQueriesSchemes includes schemes suggestive of "
                        f"sensitive apps: {', '.join(sensitive[:5])}.",
            location_symbol="Info.plist key: LSApplicationQueriesSchemes"))

    ats = plist.get("NSAppTransportSecurity") or {}
    if ats.get("NSAllowsArbitraryLoads"):
        findings.append(_finding(
            "IOS-BIN-URL-003", file_path,
            location_symbol="Info.plist key: NSAppTransportSecurity/NSAllowsArbitraryLoads"))
    for domain, cfg in (ats.get("NSExceptionDomains") or {}).items():
        if not isinstance(cfg, dict):
            continue
        insecure = bool(cfg.get("NSExceptionAllowsInsecureHTTPLoads"))
        if insecure and cfg.get("NSIncludesSubdomains"):
            findings.append(_finding(
                "IOS-BIN-URL-005", file_path,
                description=f"Insecure HTTP allowed for all subdomains of {domain!r} "
                            f"(NSIncludesSubdomains + NSExceptionAllowsInsecureHTTPLoads).",
                location_symbol=f"Info.plist key: NSExceptionDomains.{domain}"))
        elif insecure:
            findings.append(_finding(
                "IOS-BIN-URL-004", file_path,
                description=f"Insecure HTTP allowed for domain {domain!r} "
                            f"(NSExceptionAllowsInsecureHTTPLoads).",
                location_symbol=f"Info.plist key: NSExceptionDomains.{domain}"))


def _detect_cross_platform_framework(all_names: List[str], notes: List[str]) -> None:
    lower_names = [n.lower() for n in all_names]
    if any("hermes.framework" in n or "libhermes" in n or "react.framework" in n
           or "main.jsbundle" in n for n in lower_names):
        notes.append("React Native runtime detected (Hermes/React.framework/"
                      "main.jsbundle) - informational, not itself a vulnerability. "
                      "JS-bundle-level analysis is out of scope for binary-mode SAST.")
    elif any("flutter.framework" in n or "app.framework" in n and "flutter" in n
             for n in lower_names):
        notes.append("Flutter runtime detected (Flutter.framework) - informational, not "
                      "itself a vulnerability. Dart AOT code is opaque to Mach-O-level "
                      "static analysis.")
    elif any("cordova" in n or ("www" in n and n.endswith("/index.html")) for n in lower_names):
        notes.append("Cordova/PhoneGap hybrid runtime detected - informational, not itself "
                      "a vulnerability. HTML/JS bundle content is out of scope for "
                      "binary-mode SAST.")


def _analyze_one_binary(binary_path: str, display_path: str, is_main_binary: bool
                         ) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = _pick_best_slice(binary_path)
    symbol_names = _symbol_names(parsed)
    strings_list = _get_strings(binary_path)
    corpus_blob = "\n".join(strings_list) + "\n" + "\n".join(symbol_names)

    if parsed is not None:
        _check_macho_security(parsed, symbol_names, display_path, is_main_binary, findings)
    _check_crypto(corpus_blob, symbol_names, display_path, findings)
    _check_sensitive_strings(strings_list, display_path, findings)
    _check_dangerous_apis(corpus_blob, display_path, findings)
    return findings


def _read_framework_bundle_id(zf: zipfile.ZipFile, framework_dir_member: str) -> Optional[str]:
    plist_member = framework_dir_member.rstrip("/") + "/Info.plist"
    try:
        data = zf.read(plist_member)
    except KeyError:
        return None
    try:
        pl = plistlib.loads(data)
    except Exception:
        return None
    return get_own_bundle_id(pl)


_UNCONFIRMED_ORIGIN_SUMMARY = (
    "this framework's origin (first-party vs third-party) could not be "
    "automatically confirmed - verify before treating this as the app "
    "developer's own code"
)


def _tag_unconfirmed_origin(findings: List[Dict[str, Any]], reason: str) -> None:
    """Tag, never suppress, every finding from an unconfirmed-origin framework."""
    for f in findings:
        f["name"] = f"[Unconfirmed Origin] {f['name']}"
        f["origin_uncertain"] = True
        f["origin_note"] = f"{_UNCONFIRMED_ORIGIN_SUMMARY} ({reason})."
        base_desc = f["details"].get("description", "")
        f["details"]["description"] = (
            f"{base_desc} NOTE: {_UNCONFIRMED_ORIGIN_SUMMARY} ({reason})."
        ).strip()


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for f in findings:
        key = (f["rule_id"], f["file_path"], f["details"].get("description"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def analyze_ipa(ipa_path: str, override_config: Optional[ScopeConfig] = None) -> Dict[str, Any]:
    """Analyze a single .ipa file. override_config is consulted before the
    automatic first-party/third-party classification of every framework."""
    result: Dict[str, Any] = {
        "ok": False,
        "error": None,
        "encrypted": False,
        "encrypted_message": None,
        "findings": [],
        "rule_defs": all_rule_defs(),
        "icdump_used": False,
        "notes": [],
    }

    if not LIEF_AVAILABLE:
        result["error"] = (
            "The `lief` package is required for iOS binary-mode scanning but is not "
            "installed. Run `pip install lief` (or reinstall narvy, which "
            "declares it as a dependency)."
        )
        return result

    if not os.path.isfile(ipa_path):
        result["error"] = f"File not found: {ipa_path}"
        return result

    try:
        zf = zipfile.ZipFile(ipa_path, "r")
    except zipfile.BadZipFile as e:
        result["error"] = f"Could not open {ipa_path} as a zip archive: {e}. Not a valid IPA?"
        return result

    try:
        with zf:
            names = zf.namelist()
            info_plist_candidates = [
                n for n in names
                if n.endswith(".app/Info.plist") and n.count("/") == 2
                and n.split("/", 1)[0].lower() == "payload"
            ]
            if not info_plist_candidates:
                # Some re-zips do not keep a clean Payload/ root.
                info_plist_candidates = sorted(
                    (n for n in names if n.endswith(".app/Info.plist")),
                    key=lambda n: n.count("/"))
            if not info_plist_candidates:
                result["error"] = (
                    f"No Payload/*.app/Info.plist found inside {ipa_path} - this doesn't "
                    f"look like a valid IPA (expected a Payload/ directory with exactly "
                    f"one .app bundle)."
                )
                return result

            info_plist_member = info_plist_candidates[0]
            app_dir_member = info_plist_member.rsplit("/Info.plist", 1)[0]

            try:
                plist = plistlib.loads(zf.read(info_plist_member))
            except Exception as e:
                result["error"] = f"Could not parse Info.plist inside {ipa_path}: {e}"
                return result

            app_bundle_id = get_own_bundle_id(plist)

            exe_name = plist.get("CFBundleExecutable")
            if not exe_name:
                result["error"] = (
                    f"Info.plist inside {ipa_path} has no CFBundleExecutable key - cannot "
                    f"locate the main binary."
                )
                return result

            main_binary_member = f"{app_dir_member}/{exe_name}"
            if main_binary_member not in names:
                result["error"] = (
                    f"Info.plist declares CFBundleExecutable={exe_name!r} but "
                    f"{main_binary_member} is not present in the archive."
                )
                return result

            frameworks_prefix = app_dir_member + "/Frameworks/"
            framework_members = [n for n in names if n.startswith(frameworks_prefix)]

            import tempfile
            with tempfile.TemporaryDirectory(prefix="narvy-ios-") as tmpdir:
                main_binary_path = _safe_extract_member(zf, main_binary_member, tmpdir)
                if main_binary_path is None:
                    result["error"] = f"Failed to extract main binary {main_binary_member} " \
                                       f"from {ipa_path} (zip-bomb guard or I/O error)."
                    return result

                main_parsed = _pick_best_slice(main_binary_path)
                encrypted = False
                if main_parsed is not None:
                    try:
                        b = main_parsed.binary
                        if b.has_encryption_info and b.encryption_info.crypt_id == 1:
                            encrypted = True
                    except Exception:
                        pass
                result["encrypted"] = encrypted
                if encrypted:
                    result["encrypted_message"] = (
                        "This IPA is FairPlay-encrypted (Apple App Store DRM). Narvy covers "
                        "it across two surfaces. The hosted engine runs its full rule set + "
                        "ML triage + MASVS mapping over the readable, cleartext surface "
                        "(Info.plist, entitlements, URL schemes / ATS, linked and embedded "
                        "frameworks, Objective-C class/method metadata), and Narvy dynamic "
                        "analysis executes the app decrypted on a real device to cover the "
                        "app's own code and strings. This local run reads the cleartext "
                        "surface only - run `narvy scan --upload` and Narvy dynamic analysis "
                        "on the platform for the complete picture of this app."
                    )

                findings = _analyze_one_binary(main_binary_path, exe_name, is_main_binary=True)

                entitlements = extract_entitlements_from_binary(main_binary_path)
                if not entitlements:
                    entitlements = None  # unknown, not "no entitlements"
                _check_url_schemes(plist, entitlements, findings)

                arch = "Unknown"
                linked_frameworks: List[str] = []
                if main_parsed is not None:
                    b = main_parsed.binary
                    try:
                        arch = str(b.header.cpu_type).replace("CPU_TYPE.", "")
                    except Exception:
                        pass
                    try:
                        linked_frameworks = sorted({
                            re.search(r"/([^/]+)\.framework/", lib.name).group(1)
                            for lib in b.libraries
                            if lib.name and "/System/Library/Frameworks/" in lib.name
                            and re.search(r"/([^/]+)\.framework/", lib.name)
                        })
                    except Exception:
                        pass
                result["notes"].append(
                    f"Main binary: {exe_name} (arch: {arch}, "
                    f"{len(linked_frameworks)} system frameworks linked).")

                icdump_used = False
                if ICDUMP_AVAILABLE:
                    ok_icdump, n_classes, n_methods, icdump_err = _icdump_class_count(main_binary_path)
                    if ok_icdump:
                        result["notes"].append(
                            f"icdump recovered {n_classes} Objective-C classes / "
                            f"{n_methods} methods from the main binary.")
                        icdump_used = True
                    else:
                        result["notes"].append(
                            f"icdump failed to parse the main binary ({icdump_err}) - "
                            f"continuing with LIEF symbol-table-only Obj-C detection for "
                            f"this binary.")
                else:
                    result["notes"].append(
                        "icdump not installed - full Obj-C class/method/property "
                        "introspection needs Linux/macOS/WSL "
                        "(pip install narvy-cli[ios-full]). Falling back to binary "
                        "symbol-table scanning only."
                    )
                result["icdump_used"] = icdump_used

                # Apple's two packaging shapes for an embedded dependency: a bare
                # "X.dylib" file, or an "X.framework/" directory.
                fw_entries: Dict[str, Tuple[str, str]] = {}
                for m in framework_members:
                    rel = m[len(frameworks_prefix):]
                    top = rel.split("/", 1)[0]
                    if not top or top in fw_entries:
                        continue
                    if top.endswith(".dylib") and "/" not in rel:
                        fw_entries[top] = ("dylib", m)
                    elif top.endswith(".framework"):
                        fw_stripped = top[: -len(".framework")]
                        fw_entries[top] = ("framework", f"{frameworks_prefix}{top}/{fw_stripped}")

                analyzed_fw = 0
                skipped_fw = 0
                unconfirmed_fw = 0
                override_own_fw = 0
                override_vendor_fw = 0
                for fw_entry, (kind, fw_binary_member) in sorted(fw_entries.items()):
                    fw_stripped = fw_entry[: -len(".framework")] if kind == "framework" else fw_entry[: -len(".dylib")]
                    # A bare dylib has no Info.plist and so no bundle id, so the
                    # filename convention has to be checked before classification.
                    if kind == "dylib" and fw_stripped.startswith(_APPLE_REDIST_DYLIB_PREFIXES):
                        skipped_fw += 1
                        continue

                    fw_bundle_id = None
                    if kind == "framework":
                        fw_dir_member = f"{frameworks_prefix}{fw_entry}"
                        fw_bundle_id = _read_framework_bundle_id(zf, fw_dir_member)

                    override_tier = check_ios_override(fw_stripped, fw_bundle_id, override_config)
                    if override_tier == "own":
                        override_own_fw += 1
                        tier, tier_reason = TIER_FIRST_PARTY, (
                            "forced first-party by .narvy-scope.yml 'own' override")
                    elif override_tier == "vendor":
                        override_vendor_fw += 1
                        tier, tier_reason = TIER_THIRD_PARTY, (
                            "forced third-party by .narvy-scope.yml 'vendor' override")
                    else:
                        tier, tier_reason = classify_ios_framework(fw_stripped, fw_bundle_id, app_bundle_id)

                    if tier == TIER_THIRD_PARTY:
                        skipped_fw += 1
                        continue
                    if fw_binary_member not in names:
                        continue
                    fw_local_path = _safe_extract_member(zf, fw_binary_member, tmpdir)
                    if fw_local_path is None:
                        continue
                    fw_display = f"Frameworks/{fw_entry}"
                    fw_findings = _analyze_one_binary(fw_local_path, fw_display, is_main_binary=False)
                    if tier == TIER_UNCONFIRMED:
                        _tag_unconfirmed_origin(fw_findings, tier_reason)
                        unconfirmed_fw += 1
                    findings.extend(fw_findings)
                    analyzed_fw += 1
                fw_names = list(fw_entries.keys())
                if fw_names:
                    result["notes"].append(
                        f"Embedded frameworks: {analyzed_fw} binaries analyzed for content "
                        f"(crypto/sensitive-strings/dangerous-API) - {unconfirmed_fw} of "
                        f"those flagged [Unconfirmed Origin] (bundle id neither matched the "
                        f"app's own reverse-DNS root nor a known vendor, see per-finding "
                        f"notes), {skipped_fw} confirmed third-party SDKs skipped "
                        f"(bundle-id and/or name match), out of {len(fw_names)} total.")
                if override_own_fw or override_vendor_fw:
                    result["notes"].append(
                        f".narvy-scope.yml overrides ({override_config.source_path}): "
                        f"{override_own_fw} framework(s) forced first-party, "
                        f"{override_vendor_fw} framework(s) forced third-party-excluded.")

                main_strings = _get_strings(main_binary_path)
                main_symbols = _symbol_names(main_parsed)
                _check_rasp(main_strings, main_symbols, exe_name, findings,
                            result["notes"], encrypted=encrypted)

                _detect_cross_platform_framework(names + fw_names, result["notes"])

                result["findings"] = _dedupe_findings(findings)
                result["ok"] = True
                return result

    except Exception as e:  # noqa: BLE001
        result["error"] = f"Unexpected error analyzing {ipa_path}: {e}"
        result["ok"] = False
        return result


def _safe_extract_member(zf: zipfile.ZipFile, member: str, dest_dir: str,
                          max_bytes: int = 3 * 1024 * 1024 * 1024) -> Optional[str]:
    """Stream one zip member to disk under a size cap. None means skip-this-one."""
    try:
        info = zf.getinfo(member)
    except KeyError:
        return None
    if info.file_size > max_bytes:
        return None
    dest_path = os.path.join(dest_dir, os.path.basename(member) + f"_{abs(hash(member))}")
    try:
        with zf.open(member) as src, open(dest_path, "wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
    except Exception:
        return None
    return dest_path
