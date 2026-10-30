"""Open cryptographic inventory (CBOM, CycloneDX 1.6) with a basic post-quantum readiness score.

This is Narvy's open, basic version. The Narvy platform has a deeper PQC
analysis; none of its rules are copied here.

What it finds:
  * Source directory: algorithm names at API call sites, matched by regex in
    Java/Kotlin, Swift/Objective-C, Python, JS/TS, Go, C#, PHP, Ruby, Rust and
    C/C++ files. Comments in C-family files and type declarations (.d.ts,
    flow-typed) are skipped. Vendored, build and
    test folders (node_modules, Pods, vendor, build, tests...) and test files
    are skipped.
  * APK/AAB: algorithm names stored as exact dex string constants (what
    Cipher/Signature/KeyPairGenerator.getInstance receive). Library code is
    included: the inventory covers the whole app, not only first-party code.
  * IPA: CommonCrypto / Security framework / CryptoKit symbol names and Go
    crypto package names in the app, framework and extension binaries.

What it does not do: data flow, key sizes, TLS configuration negotiated at
runtime, or crypto reached only through a wrapper library.

Score (0-100), per algorithm family found, not per occurrence:
    score = 100 * pqc_families / (pqc_families + quantum_vulnerable_families)
  * quantum-vulnerable (Shor): RSA, ECDSA, ECDH, DH, DSA, X25519/Ed25519
  * post-quantum: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+)
  * classically weak (MD5, SHA-1, 3DES, DES) is listed but does not change
    the score: it is a problem today, not a quantum one.
No asymmetric algorithm found -> no score (null), never 100.
APK/AAB bundling Bouncy Castle: its post-quantum names are listed but not
scored (the provider ships them whether the app uses them or not).
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import uuid
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import __version__
from .comment_filter import build_comment_mask

SPEC_VERSION = "1.6"

# family -> (category, primitive, NIST quantum security level, replacement)
FAMILIES: Dict[str, Tuple[str, str, int, str]] = {
    "RSA":     ("quantum-vulnerable", "pke", 0, "ML-KEM (FIPS 203) for encryption, ML-DSA (FIPS 204) for signatures"),
    "ECDSA":   ("quantum-vulnerable", "signature", 0, "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"),
    "ECDH":    ("quantum-vulnerable", "key-agree", 0, "hybrid X25519+ML-KEM-768, then ML-KEM (FIPS 203)"),
    "DH":      ("quantum-vulnerable", "key-agree", 0, "ML-KEM (FIPS 203)"),
    "DSA":     ("quantum-vulnerable", "signature", 0, "ML-DSA (FIPS 204)"),
    "X25519":  ("quantum-vulnerable", "key-agree", 0, "hybrid X25519+ML-KEM-768"),
    "Ed25519": ("quantum-vulnerable", "signature", 0, "ML-DSA (FIPS 204)"),
    "ML-KEM":  ("post-quantum", "kem", 3, ""),
    "ML-DSA":  ("post-quantum", "signature", 3, ""),
    "SLH-DSA": ("post-quantum", "signature", 1, ""),
    "MD5":     ("classically-weak", "hash", 0, "SHA-256 or stronger"),
    "SHA-1":   ("classically-weak", "hash", 0, "SHA-256 or stronger"),
    "3DES":    ("classically-weak", "block-cipher", 0, "AES-256-GCM"),
    "DES":     ("classically-weak", "block-cipher", 0, "AES-256-GCM"),
}

_Q = r"""["']"""  # opening quote of a string literal

# (family, regex). Each pattern needs an API shape or a quoted algorithm name, never a bare word.
_SOURCE_PATTERNS: List[Tuple[str, str]] = [
    # --- RSA
    ("RSA", _Q + r"RSA(?:/[A-Za-z0-9-]+/[A-Za-z0-9-]+)?" + _Q),
    ("RSA", _Q + r"(?:SHA-?\d+|MD5)withRSA(?:/PSS|andMGF1)?" + _Q),
    ("RSA", r"\bKEY_ALGORITHM_RSA\b|\bkSecAttrKeyTypeRSA\b|\bRSACryptoServiceProvider\b|\bRSA\.Create\s*\("),
    ("RSA", r"\brsa\.(?:generate_private_key|GenerateKey|EncryptPKCS1v15|EncryptOAEP|SignPKCS1v15|SignPSS)\b"),
    ("RSA", r"""\bgenerateKeyPair(?:Sync)?\s*\(\s*["']rsa(?:-pss)?["']|\bOPENSSL_KEYTYPE_RSA\b|\bRSA_generate_key(?:_ex)?\b|\bOpenSSL::PKey::RSA\b|\bRsaPrivateKey::new\b"""),
    # --- ECDSA
    ("ECDSA", _Q + r"(?:SHA-?\d+|NONE)withECDSA" + _Q + "|" + _Q + r"ECDSA" + _Q),
    ("ECDSA", r"\bKEY_ALGORITHM_EC\b|\bkSecAttrKeyTypeECSECPrimeRandom\b|\bkSecAttrKeyTypeEC\b|\bECDsa(?:Cng)?\.Create\s*\(|\bP(?:256|384|521)\.Signing\b"),
    ("ECDSA", r"\becdsa\.(?:GenerateKey|Sign|SignASN1)\b|\bec\.ECDSA\s*\(|\bEC_KEY_new_by_curve_name\b|\bOpenSSL::PKey::EC\b"),
    ("ECDSA", r"getInstance\s*\(\s*" + _Q + r"EC" + _Q),
    # --- ECDH
    ("ECDH", _Q + r"ECDH" + _Q + r"|\bec\.ECDH\s*\(|\bcreateECDH\s*\(|\bP(?:256|384|521)\.KeyAgreement\b|\bECDiffieHellman(?:Cng)?\b|\becdh\.P(?:256|384|521)\s*\("),
    # --- DH
    ("DH", r"getInstance\s*\(\s*" + _Q + r"(?:DH|DiffieHellman)" + _Q + r"|\bcreateDiffieHellman(?:Group)?\s*\(|\bdh\.generate_parameters\s*\(|\bDH_generate_key\b"),
    # --- DSA
    ("DSA", _Q + r"(?:SHA-?\d+)withDSA" + _Q + r"|getInstance\s*\(\s*" + _Q + r"DSA" + _Q + r"|\bdsa\.generate_private_key\s*\(|\bdsa\.GenerateKey\b|\bDSACryptoServiceProvider\b"),
    # --- X25519 / Ed25519
    ("X25519", _Q + r"(?:X25519|XDH)" + _Q + r"|\bCurve25519\.KeyAgreement\b|\bx25519\.X25519PrivateKey\b|\bX25519(?:PrivateKey|PublicKey|KeyPair)\b|\bcurve25519\.X25519\s*\("),
    ("Ed25519", _Q + r"Ed25519" + _Q + r"|\bCurve25519\.Signing\b|\bed25519\.(?:Ed25519PrivateKey|GenerateKey|Sign)\b|\bEd25519(?:PrivateKey|Signer|KeyPair)\b|\bSigningKey::generate\b"),
    # --- post-quantum
    ("ML-KEM", r"\bML[-_]?KEM[-_]?(?:512|768|1024)?\b|\bMLKEM(?:512|768|1024)?\b|\bKyber(?:512|768|1024)\b|\bX25519MLKEM768\b"),
    ("ML-DSA", r"\bML[-_]?DSA[-_]?(?:44|65|87)?\b|\bMLDSA(?:44|65|87)?\b|\bDilithium[235]\b"),
    ("SLH-DSA", r"\bSLH[-_]?DSA\b|\bSPHINCS(?:\+|Plus)?\b"),
    # --- classically weak
    ("MD5", _Q + r"MD5" + _Q + r"|\bhashlib\.md5\b|\bCC_MD5\b|\bInsecure\.MD5\b|\bMD5\.Create\s*\(|\bmd5\.(?:New|Sum)\b|createHash\s*\(\s*" + _Q + r"md5" + _Q + r"|\bDigest::MD5\b"),
    ("SHA-1", _Q + r"SHA-?1" + _Q + r"|\bhashlib\.sha1\b|\bCC_SHA1\b|\bInsecure\.SHA1\b|\bSHA1\.Create\s*\(|\bsha1\.(?:New|Sum)\b|createHash\s*\(\s*" + _Q + r"sha1" + _Q + r"|\bDigest::SHA1\b"),
    ("3DES", _Q + r"DESede(?:/[A-Za-z0-9-]+/[A-Za-z0-9-]+)?" + _Q + r"|\bkCCAlgorithm3DES\b|\bTripleDES(?:\.Create\s*\(|CryptoServiceProvider)|\bdes-ede3"),
    ("DES", _Q + r"DES(?:/[A-Za-z0-9-]+/[A-Za-z0-9-]+)?" + _Q + r"|\bkCCAlgorithmDES\b|\bDESCryptoServiceProvider\b"),
]
_COMPILED = [(fam, re.compile(rx)) for fam, rx in _SOURCE_PATTERNS]

_SOURCE_EXTS = (".java", ".kt", ".kts", ".swift", ".m", ".mm", ".h", ".py", ".js", ".jsx", ".mjs", ".cjs",
                ".ts", ".tsx", ".go", ".cs", ".php", ".rb", ".rs", ".c", ".cc", ".cpp", ".hpp", ".dart")
_C_FAMILY = (".java", ".kt", ".kts", ".swift", ".m", ".mm", ".h", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
             ".go", ".cs", ".php", ".rs", ".c", ".cc", ".cpp", ".hpp", ".dart")
_SKIP_DIRS = {"node_modules", "Pods", "Carthage", "vendor", "third_party", "third-party", "build", "dist", ".git",
              ".gradle", ".idea", "DerivedData", ".build", "target", "__pycache__", ".venv", "venv", "site-packages",
              ".next", "coverage", "bower_components", "flow-typed", "@types"}
_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "androidTest", "testDebug", "e2e", "playwright",
              "cypress", "fixtures", "__mocks__", "testdata"}
_TEST_FILE_RE = re.compile(r"(\.(?:test|spec)\.[a-z]+$|^test_.*\.py$|_test\.(?:py|go)$|Tests?\.(?:java|kt|swift|cs)$)")
_MAX_FILE_BYTES = 1_500_000
_MAX_OCCURRENCES_PER_FAMILY = 50

# Exact dex string constants -> family (APK/AAB).
_DEX_EXACT: Dict[str, str] = {}
for _n in ("RSA", "RSA/ECB/PKCS1Padding", "RSA/ECB/OAEPPadding", "RSA/NONE/PKCS1Padding", "RSA/NONE/OAEPPadding",
           "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RSA/ECB/NoPadding",
           "SHA256withRSA", "SHA1withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withRSA/PSS", "MD5withRSA"):
    _DEX_EXACT[_n] = "RSA"
for _n in ("ECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "SHA1withECDSA", "NONEwithECDSA"):
    _DEX_EXACT[_n] = "ECDSA"
for _n in ("ECDH",):
    _DEX_EXACT[_n] = "ECDH"
for _n in ("DH", "DiffieHellman"):
    _DEX_EXACT[_n] = "DH"
for _n in ("DSA", "SHA1withDSA", "SHA256withDSA"):
    _DEX_EXACT[_n] = "DSA"
for _n in ("X25519", "XDH"):
    _DEX_EXACT[_n] = "X25519"
for _n in ("Ed25519", "EdDSA"):
    _DEX_EXACT[_n] = "Ed25519"
for _n in ("ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "Kyber", "KYBER", "X25519MLKEM768"):
    _DEX_EXACT[_n] = "ML-KEM"
for _n in ("ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Dilithium", "DILITHIUM"):
    _DEX_EXACT[_n] = "ML-DSA"
for _n in ("SLH-DSA", "SPHINCSPlus", "SPHINCS+"):
    _DEX_EXACT[_n] = "SLH-DSA"
for _n in ("MD5",):
    _DEX_EXACT[_n] = "MD5"
for _n in ("SHA-1", "SHA1"):
    _DEX_EXACT[_n] = "SHA-1"
for _n in ("DESede", "DESede/CBC/PKCS5Padding", "DESede/ECB/PKCS5Padding", "TripleDES"):
    _DEX_EXACT[_n] = "3DES"
for _n in ("DES", "DES/CBC/PKCS5Padding", "DES/ECB/PKCS5Padding"):
    _DEX_EXACT[_n] = "DES"

# Mach-O symbol / constant names -> family (IPA).
_MACHO_SYMBOLS: List[Tuple[bytes, str]] = [
    (b"kSecAttrKeyTypeRSA", "RSA"),
    (b"kSecKeyAlgorithmRSA", "RSA"),
    (b"kSecAttrKeyTypeECSECPrimeRandom", "ECDSA"),
    (b"kSecKeyAlgorithmECDSA", "ECDSA"),
    (b"kSecKeyAlgorithmECDH", "ECDH"),
    (b"_CC_MD5", "MD5"),
    (b"_CC_SHA1", "SHA-1"),
    (b"kCCAlgorithm3DES", "3DES"),
    # CryptoKit (Swift mangled type names).
    (b"9CryptoKit4P256O7Signing", "ECDSA"), (b"9CryptoKit4P384O7Signing", "ECDSA"),
    (b"9CryptoKit4P521O7Signing", "ECDSA"),
    (b"9CryptoKit4P256O12KeyAgreement", "ECDH"), (b"9CryptoKit4P384O12KeyAgreement", "ECDH"),
    (b"9CryptoKit4P521O12KeyAgreement", "ECDH"),
    (b"9CryptoKit10Curve25519O7Signing", "Ed25519"), (b"9CryptoKit10Curve25519O12KeyAgreement", "X25519"),
    (b"9CryptoKit6InsecureO3MD5", "MD5"), (b"9CryptoKit6InsecureO4SHA1", "SHA-1"),
    # Go standard library packages linked into the binary (gomobile frameworks).
    (b"crypto/rsa.", "RSA"), (b"crypto/ecdsa.", "ECDSA"), (b"crypto/ecdh.", "ECDH"),
    (b"crypto/ed25519.", "Ed25519"), (b"crypto/dsa.", "DSA"), (b"crypto/mlkem.", "ML-KEM"),
    (b"crypto/md5.", "MD5"), (b"crypto/sha1.", "SHA-1"), (b"crypto/des.", "3DES"),
]


@dataclass
class Occurrence:
    family: str
    location: str
    line: Optional[int]
    snippet: str


def _iter_source_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _SKIP_DIRS and d not in _TEST_DIRS and not d.startswith(".")
                       and not d.endswith(("Tests", "Test", "UITests"))]
        for fn in filenames:
            if (fn.endswith(_SOURCE_EXTS) and not fn.endswith((".min.js", ".bundle.js", ".d.ts", ".d.mts", ".d.cts"))
                    and not _TEST_FILE_RE.search(fn)):
                yield os.path.join(dirpath, fn)


def scan_source(root: str) -> Tuple[List[Occurrence], int]:
    occ: List[Occurrence] = []
    files = 0
    for path in _iter_source_files(root):
        try:
            if os.path.getsize(path) > _MAX_FILE_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue
        files += 1
        mask = None
        c_family = path.endswith(_C_FAMILY)
        rel = os.path.relpath(path, root)
        for fam, rx in _COMPILED:
            for m in rx.finditer(content):
                if c_family:
                    if mask is None:
                        mask = build_comment_mask(content)
                    if mask[m.start()]:
                        continue
                if path.endswith(".py") and _in_python_comment(content, m.start()):
                    continue
                line_no = content.count("\n", 0, m.start()) + 1
                line_start = content.rfind("\n", 0, m.start()) + 1
                line_end = content.find("\n", m.start())
                snippet = content[line_start: line_end if line_end != -1 else len(content)].strip()[:160]
                if snippet.startswith(("declare ", "export declare ")):
                    continue  # type declaration, not a call site
                occ.append(Occurrence(fam, rel, line_no, snippet))
    return _dedupe(occ), files


def _in_python_comment(content: str, pos: int) -> bool:
    line_start = content.rfind("\n", 0, pos) + 1
    return "#" in content[line_start:pos]


def _dedupe(occ: List[Occurrence]) -> List[Occurrence]:
    seen = set()
    out = []
    for o in occ:
        key = (o.family, o.location, o.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(o)
    return out


def dex_strings(data: bytes) -> List[str]:
    """Every entry of a dex string table (header string_ids), decoded leniently."""
    import struct

    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        return []
    size, off = struct.unpack_from("<II", data, 0x38)
    if off + 4 * size > len(data):
        return []
    out = []
    for i in range(size):
        (p,) = struct.unpack_from("<I", data, off + 4 * i)
        # skip the uleb128 utf16 length
        while p < len(data) and data[p] & 0x80:
            p += 1
        p += 1
        end = data.find(b"\x00", p)
        if end == -1:
            break
        out.append(data[p:end].decode("utf-8", errors="replace"))
    return out


# Crypto providers that carry a catalog of algorithm names (PQC included) whether the app uses them or not.
_PROVIDER_PREFIXES = {"Lorg/bouncycastle/": "Bouncy Castle", "Lorg/spongycastle/": "Spongy Castle"}

# Set by the last scan_apk call: bundled crypto providers found.
LAST_APK_PROVIDERS: List[str] = []


def scan_apk(path: str) -> Tuple[List[Occurrence], int]:
    occ: List[Occurrence] = []
    dex_count = 0
    providers = set()
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.endswith(".dex"):
                continue
            dex_count += 1
            try:
                strings = set(dex_strings(zf.read(name)))
            except Exception:
                continue
            for s in sorted(strings):
                fam = _DEX_EXACT.get(s)
                if fam:
                    occ.append(Occurrence(fam, name, None, s))
                elif s.startswith("L"):
                    for prefix, label in _PROVIDER_PREFIXES.items():
                        if s.startswith(prefix):
                            providers.add(label)
    LAST_APK_PROVIDERS[:] = sorted(providers)
    return occ, dex_count


def scan_ipa(path: str) -> Tuple[List[Occurrence], int]:
    occ: List[Occurrence] = []
    binaries = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            n = info.filename
            parts = n.split("/")
            # Payload/X.app/X, Payload/X.app/Frameworks/Y.framework/Y, Payload/X.app/PlugIns/Z.appex/Z
            if len(parts) < 3 or not parts[1].endswith(".app") or info.is_dir():
                continue
            parent = parts[-2]
            base = parent.rsplit(".", 1)[0]
            if parts[-1] != base or not parent.endswith((".app", ".framework", ".appex")):
                continue
            if info.file_size > 400_000_000:
                continue
            data = zf.read(n)
            if data[:4] not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe"):
                continue
            binaries += 1
            for sym, fam in _MACHO_SYMBOLS:
                if sym in data:
                    occ.append(Occurrence(fam, n, None, sym.decode().lstrip("_")))
    return occ, binaries


def score(families: Iterable[str]) -> Optional[int]:
    fams = set(families)
    vuln = sum(1 for f in fams if FAMILIES[f][0] == "quantum-vulnerable")
    pqc = sum(1 for f in fams if FAMILIES[f][0] == "post-quantum")
    if vuln + pqc == 0:
        return None
    return round(100 * pqc / (pqc + vuln))


_SCOPE = {
    "source-directory": ("Algorithm names at API call sites in first-party source files (regex, comments skipped "
                         "in C-family files; vendored, build and test folders skipped). No data flow, no key sizes."),
    "android-binary": ("Algorithm names stored as exact dex string constants, library code included. "
                       "Names built at runtime or held in native code are not seen."),
    "ios-binary": ("CommonCrypto, Security framework and CryptoKit symbols, and Go crypto packages, in the app, "
                   "framework and extension binaries. Strings inside FairPlay-encrypted code, statically linked C "
                   "libraries (OpenSSL) and CryptoKit post-quantum types are not seen."),
}


def build_cbom(target: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(CycloneDX CBOM document, console summary)."""
    lower = target.lower()
    if os.path.isdir(target):
        kind = "source-directory"
        occ, scanned = scan_source(target)
        scanned_label = "source files scanned"
    elif lower.endswith((".apk", ".aab")):
        kind = "android-binary"
        occ, scanned = scan_apk(target)
        scanned_label = "dex files scanned"
    elif lower.endswith(".ipa"):
        kind = "ios-binary"
        occ, scanned = scan_ipa(target)
        scanned_label = "Mach-O binaries scanned"
    else:
        raise ValueError("CBOM needs a source directory, an .apk/.aab or an .ipa")

    by_family: Dict[str, List[Occurrence]] = {}
    for o in occ:
        by_family.setdefault(o.family, []).append(o)

    components = []
    for fam in sorted(by_family):
        category, primitive, nist_level, replacement = FAMILIES[fam]
        items = by_family[fam]
        evidence = []
        for o in items[:_MAX_OCCURRENCES_PER_FAMILY]:
            e: Dict[str, Any] = {"location": o.location, "additionalContext": o.snippet}
            if o.line:
                e["line"] = o.line
            evidence.append(e)
        props = [
            {"name": "narvy:quantum-status", "value": category},
            {"name": "narvy:occurrences", "value": str(len(items))},
        ]
        if replacement:
            props.append({"name": "narvy:replacement", "value": replacement})
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto/algorithm/{fam}",
            "name": fam,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": primitive, "nistQuantumSecurityLevel": nist_level},
            },
            "evidence": {"occurrences": evidence},
            "properties": props,
        })

    # A bundled provider (Bouncy Castle) lists PQC names it ships, not ones the app calls:
    # report them, but never let them raise the score.
    providers = list(LAST_APK_PROVIDERS) if kind == "android-binary" else []
    scored = [f for f in by_family if not (providers and FAMILIES[f][0] == "post-quantum")]
    s = score(scored)
    vuln = sorted(f for f in by_family if FAMILIES[f][0] == "quantum-vulnerable")
    pqc = sorted(f for f in by_family if FAMILIES[f][0] == "post-quantum")
    weak = sorted(f for f in by_family if FAMILIES[f][0] == "classically-weak")
    meta_props = [
        {"name": "narvy:scope", "value": _SCOPE[kind]},
        {"name": "narvy:edition", "value": "open basic inventory (narvy-cli)"},
        {"name": "narvy:pqc-score", "value": "none (no asymmetric algorithm found)" if s is None else str(s)},
        {"name": "narvy:pqc-score-formula",
         "value": "100 * post-quantum families / (post-quantum + quantum-vulnerable families)"},
        {"name": "narvy:quantum-vulnerable", "value": ", ".join(vuln) or "none found"},
        {"name": "narvy:post-quantum", "value": ", ".join(pqc) or "none found"},
        {"name": "narvy:classically-weak", "value": ", ".join(weak) or "none found"},
        {"name": f"narvy:{scanned_label.replace(' ', '-')}", "value": str(scanned)},
    ]
    if providers:
        meta_props.append({"name": "narvy:bundled-crypto-provider",
                           "value": (", ".join(providers) + " bundled: its algorithm names are listed even if the "
                                     "app does not call them. Post-quantum names do not count in the score.")})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "narvy-cli", "version": __version__}]},
            "component": {"type": "application", "name": os.path.basename(os.path.normpath(target)) or target,
                          "bom-ref": "target"},
            "properties": meta_props,
        },
        "components": components,
    }, {"kind": kind, "score": s, "vulnerable": vuln, "pqc": pqc, "weak": weak,
        "scanned": scanned, "scanned_label": scanned_label, "providers": providers,
        "occurrences": {f: len(v) for f, v in by_family.items()}}
