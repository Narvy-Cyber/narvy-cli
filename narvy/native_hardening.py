"""ELF hardening checks (NX, PIE, RELRO, stack canary, RPATH) for the native
.so libraries shipped inside an APK/AAB.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .stack_protector_evidence import has_instrumentable_stack_code

logger = logging.getLogger(__name__)

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


# Only one ABI is analyzed: per-ABI builds share the same hardening flags.
_ARCH_PREFERENCE = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

# Zip-bomb guard on a single extracted .so.
_MAX_SO_BYTES = 500 * 1024 * 1024

# Lower-cased, matched against the .so basename only.
_VENDOR_SO_EXACT = {
    "libc++_shared.so", "libc++abi.so", "libstlport_shared.so", "libgnustl_shared.so",
    "libssl.so", "libcrypto.so", "libsqlite3.so", "libsqlcipher.so",
    "libconscrypt_jni.so", "libwebviewchromium.so",
}
_VENDOR_SO_PREFIXES = (
    "libandroidx.",
    "libflutter", "libapp",
    "libhermes", "libjsc", "libreactnative", "libfb", "libyoga",
    "libil2cpp", "libmono", "libunity",
    "libcrashlytics", "libbugsnag", "libsentry",
    "libcronet", "libquic",
    "libdatadog", "libgojni",
)
# A .so whose JNI entry points all sit under these namespaces is bundled third-party code.
_VENDOR_JNI_PACKAGE_PREFIXES = (
    "androidx.", "android.", "com.android.",
    "com.google.", "com.googlecode.",
    "io.flutter.", "com.facebook.", "com.reactnativecommunity.",
    "org.chromium.", "com.unity3d.", "org.webrtc.",
    "io.sentry.", "com.bugsnag.", "com.crashlytics.", "com.datadog.",
    "org.sqlite.", "net.sqlcipher.", "org.conscrypt.",
)


def _jni_java_packages(symbol_names) -> List[str]:
    """Java package prefixes of every `Java_<pkg>_<Class>_<method>` JNI export."""
    # JNI mangling maps '.'->'_' and escapes '_' as '_1'; package recoverable as a prefix only.
    out: List[str] = []
    for name in symbol_names:
        if not name.startswith("Java_"):
            continue
        body = name[len("Java_"):]
        if not body:
            continue
        out.append(body.replace("_1", "\x00").replace("_", ".").replace("\x00", "_"))
    return out


def _is_vendor_by_jni(symbol_names) -> bool:
    packages = _jni_java_packages(symbol_names)
    if not packages:
        return False
    return all(
        any(pkg.startswith(prefix) for prefix in _VENDOR_JNI_PACKAGE_PREFIXES)
        for pkg in packages
    )


@dataclass
class _SoFacts:
    basename: str
    zip_member: str
    is_vendor: bool
    has_nx: bool
    # ET_DYN is the PIE equivalent for a .so; LIEF's is_pie also requires PT_INTERP.
    is_dyn: bool
    relro: str             # "full" | "partial" | "none"
    has_canary: bool
    rpath: Optional[str]
    runpath: Optional[str]
    # None means no analysis available for this architecture, not "no".
    instrumentable: Optional[bool] = None


def _is_vendor_lib(basename: str, symbol_names=()) -> bool:
    lower = basename.lower()
    if lower in _VENDOR_SO_EXACT:
        return True
    if any(lower.startswith(p) for p in _VENDOR_SO_PREFIXES):
        return True
    return _is_vendor_by_jni(symbol_names)


def _is_weak_search_path(raw: str) -> bool:
    if not raw:
        return False
    for entry in raw.split(":"):
        entry = entry.strip()
        if not entry:
            continue
        if not entry.startswith("/") and not entry.startswith("$ORIGIN"):
            return True
        if ".." in entry:
            return True
        lowered = entry.lower()
        if any(bad in lowered for bad in ("/data/local/tmp", "/sdcard", "/storage/emulated", "/tmp")):
            return True
    return False


def _pick_arch(namelist: List[str]) -> Optional[str]:
    available = set()
    for name in namelist:
        if name.startswith("lib/") and name.endswith(".so"):
            parts = name.split("/")
            if len(parts) >= 3 and parts[2]:
                available.add(parts[1])
    if not available:
        return None
    for pref in _ARCH_PREFERENCE:
        if pref in available:
            return pref
    return sorted(available)[0]


def _safe_extract(zf: zipfile.ZipFile, member: str, dest_dir: str) -> Optional[str]:
    try:
        info = zf.getinfo(member)
    except KeyError:
        return None
    if info.file_size > _MAX_SO_BYTES:
        logger.debug(f"[native-hardening] {member} exceeds size cap, skipping")
        return None
    dest_path = os.path.join(dest_dir, os.path.basename(member) + f"_{abs(hash(member))}")
    try:
        with zf.open(member) as src, open(dest_path, "wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
    except Exception as e:
        logger.debug(f"[native-hardening] extraction failed for {member}: {e}")
        return None
    return dest_path


def _compute_relro(binary) -> str:
    has_seg = any(seg.type == lief.ELF.Segment.TYPE.GNU_RELRO for seg in binary.segments)
    if not has_seg:
        return "none"
    bind_now = False
    try:
        if binary.has(lief.ELF.DynamicEntry.TAG.FLAGS):
            entry = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS)
            bind_now = bind_now or any("BIND_NOW" in str(f) for f in entry.flags)
        if binary.has(lief.ELF.DynamicEntry.TAG.FLAGS_1):
            entry = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)
            bind_now = bind_now or any("NOW" in str(f) for f in entry.flags)
    except Exception as e:
        logger.debug(f"[native-hardening] RELRO/BIND_NOW inspection failed: {e}")
    return "full" if bind_now else "partial"


def _analyze_so(local_path: str, basename: str, zip_member: str) -> Optional[_SoFacts]:
    try:
        binary = lief.ELF.parse(local_path)
    except Exception as e:
        logger.debug(f"[native-hardening] LIEF failed to parse {basename}: {e}")
        return None
    if binary is None:
        return None

    try:
        has_nx = bool(binary.has_nx)
        is_dyn = binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
        relro = _compute_relro(binary)
        has_canary = bool(binary.has_symbol("__stack_chk_fail"))
        # Only pay for the .text decode when it can still change the finding.
        instrumentable: Optional[bool] = None
        if not has_canary:
            instrumentable = has_instrumentable_stack_code(binary)
        symbol_names = [s.name for s in binary.dynamic_symbols]
        rpath = None
        runpath = None
        if binary.has(lief.ELF.DynamicEntry.TAG.RPATH):
            rpath = binary.get(lief.ELF.DynamicEntry.TAG.RPATH).rpath
        if binary.has(lief.ELF.DynamicEntry.TAG.RUNPATH):
            runpath = binary.get(lief.ELF.DynamicEntry.TAG.RUNPATH).runpath
    except Exception as e:
        logger.debug(f"[native-hardening] fact extraction failed for {basename}: {e}")
        return None

    return _SoFacts(
        basename=basename,
        zip_member=zip_member,
        is_vendor=_is_vendor_lib(basename, symbol_names),
        has_nx=has_nx,
        is_dyn=is_dyn,
        relro=relro,
        has_canary=has_canary,
        rpath=rpath,
        runpath=runpath,
        instrumentable=instrumentable,
    )


def _mk_finding(facts: _SoFacts, rule_id: str, name: str, severity: str, cwe: str,
                description: str, recommendation: str,
                location_symbol: Optional[str] = None) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "rule_id": rule_id,
        "file_path": facts.zip_member,
        "name": name,
        "severity": "LOW" if facts.is_vendor else severity,
        "details": {
            "description": description,
            "recommendation": recommendation,
            "cwe": cwe,
            "masvs": "MSTG-CODE-9",
        },
        "line": 1,
        "engine": "native-hardening",
        "native_lib": {
            "basename": facts.basename,
            "own_code": not facts.is_vendor,
        },
    }
    # Console display only; SARIF output keeps using `line`.
    if location_symbol:
        f["location_symbol"] = location_symbol
    return f


def _canary_evidence_note(facts: _SoFacts) -> str:
    """Explain why an absent stack-canary symbol is treated as a real finding."""
    if facts.instrumentable is True:
        return (
            "This library does contain code the protector would have instrumented "
            "(it materialises the address of a stack slot into a register - a local "
            "array or an escaping local), so the absent symbol really does mean the "
            "flag was off, not that there was nothing to protect. "
        )
    return (
        "NOTE: this architecture has no instrumentable-code decoder in this "
        "scanner, so the absent symbol has not been corroborated - verify the "
        "build flags before acting on it. "
    )


def _facts_to_findings(facts: _SoFacts) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    tag = "[Third-party/bundled library] " if facts.is_vendor else ""
    scope_note = (
        "This is a well-known bundled/third-party native library, not code the app's own "
        "developer built - not directly actionable by them (any fix belongs to the "
        "upstream vendor); shown for completeness, not at the same urgency as a gap in "
        "the app's own native code."
        if facts.is_vendor else
        "This is one of the app's own native libraries (not a recognized bundled/"
        "third-party SDK)."
    )

    if not facts.has_nx:
        out.append(_mk_finding(
            facts, "AND-BIN-001", tag + "Native Library Missing NX (Executable Stack)",
            severity="MEDIUM", cwe="CWE-119",
            description=(
                f"{facts.basename} does not have the NX bit enabled (its PT_GNU_STACK "
                f"segment is marked executable, or is absent) - the stack is executable, "
                f"making injected-shellcode exploitation of any memory-corruption bug in "
                f"this library meaningfully easier. {scope_note}"
            ),
            recommendation=(
                "Rebuild the native library without `-z execstack` - the modern Android "
                "NDK toolchain disables this by default, so this usually indicates a "
                "custom/legacy linker flag override."
            ),
            location_symbol="PT_GNU_STACK segment (NX flag)",
        ))

    if not facts.is_dyn:
        out.append(_mk_finding(
            facts, "AND-BIN-002", tag + "Native Library Not Built as Position-Independent (No PIE)",
            severity="MEDIUM", cwe="CWE-693",
            description=(
                f"{facts.basename} is not a Dynamic Shared Object (ET_DYN) - unusual for "
                f"a .so file, and it defeats ASLR for this library's mapped address "
                f"range, making return-to-libc/ROP-style exploitation of any other bug in "
                f"it meaningfully more reliable. {scope_note}"
            ),
            recommendation=(
                "Rebuild with `-fPIC`/`-shared` (the standard, default way to build any "
                "Android .so) - this typically indicates a broken or hand-rolled build "
                "step, not a deliberate choice."
            ),
            location_symbol="ELF header (e_type != ET_DYN)",
        ))

    if facts.relro != "full":
        is_none = facts.relro == "none"
        label = "No RELRO" if is_none else "Partial RELRO (GOT Not Fully Read-Only)"
        detail = (
            "its Global Offset Table (GOT) is fully writable at runtime"
            if is_none else
            "its GOT is marked read-only after relocation (PT_GNU_RELRO present) but "
            "lazy binding is still active (no DT_FLAGS/DT_FLAGS_1 BIND_NOW), leaving the "
            ".got.plt section writable until first use"
        )
        out.append(_mk_finding(
            facts, "AND-BIN-003", tag + label,
            severity="MEDIUM" if is_none else "LOW", cwe="CWE-732",
            description=(
                f"{facts.basename} does not have full RELRO protection - {detail}, making "
                f"GOT-overwrite exploitation of any other memory-corruption bug in this "
                f"library easier. {scope_note}"
            ),
            recommendation=(
                "Relink with `-Wl,-z,relro -Wl,-z,now` (Full RELRO) - standard practice, "
                "no meaningful runtime cost for a mobile app."
            ),
            location_symbol="PT_GNU_RELRO segment / DT_FLAGS(_1) BIND_NOW",
        ))

    # Absent `__stack_chk_fail` only proves the protector was off if there was code to instrument.
    if not facts.has_canary and facts.instrumentable is not False:
        out.append(_mk_finding(
            facts, "AND-BIN-004", tag + "Native Library Missing Stack Canary",
            severity="MEDIUM", cwe="CWE-121",
            description=(
                f"{facts.basename} was not built with a stack protector (no "
                f"`__stack_chk_fail` symbol) - a stack buffer overflow in this library's "
                f"own code cannot be detected before a corrupted return address is used. "
                f"{_canary_evidence_note(facts)}{scope_note}"
            ),
            recommendation=(
                "Rebuild with `-fstack-protector-strong` (or `-all`) - on by default in a "
                "modern NDK, so this usually means a custom/legacy toolchain or an "
                "explicit override."
            ),
            location_symbol="symbol table (__stack_chk_fail absent)",
        ))

    weak_path = facts.rpath or facts.runpath
    if weak_path:
        which = "RPATH" if facts.rpath else "RUNPATH"
        is_weak = _is_weak_search_path(weak_path)
        extra = (
            ", and this entry is relative and/or points at a location an on-device "
            "attacker could plausibly write to (app-private external storage, a "
            "world-writable tmp dir, ...) - a library planted there would be loaded "
            "instead of the real one (uncontrolled search path / library injection)."
            if is_weak else
            ", an unusual thing for a well-hardened release Android library to ship at "
            "all (Android apps normally rely on the default linker search order)."
        )
        out.append(_mk_finding(
            facts, "AND-BIN-005", tag + f"{which} Set in Native Library",
            severity="MEDIUM" if is_weak else "LOW", cwe="CWE-427",
            description=(
                f"{facts.basename} embeds a {which} value ('{weak_path}') - the dynamic "
                f"linker will search this path for dependent libraries at load time{extra} "
                f"{scope_note}"
            ),
            recommendation=(
                "Remove the RPATH/RUNPATH from the link step - check for a stray "
                "`-rpath`/`-Wl,-rpath` flag left over from a local/dev build config."
            ),
            location_symbol=f"DT_{which} entry: {weak_path}",
        ))

    return out


# Canonical rule catalog, SARIF "tool.driver.rules" style.
_RULE_CATALOG: Dict[str, Dict[str, Any]] = {
    "AND-BIN-001": {
        "id": "AND-BIN-001", "name": "Native Library Missing NX (Executable Stack)",
        "severity": "MEDIUM", "masvs": "MSTG-CODE-9",
        "details": {
            "description": "A native (.so) library ships without the NX bit set, leaving its stack executable.",
            "recommendation": "Rebuild without `-z execstack`; modern NDK toolchains disable this by default.",
            "cwe": "CWE-119", "masvs": "MSTG-CODE-9",
        },
    },
    "AND-BIN-002": {
        "id": "AND-BIN-002", "name": "Native Library Not Built as Position-Independent (No PIE)",
        "severity": "MEDIUM", "masvs": "MSTG-CODE-9",
        "details": {
            "description": "A native (.so) library is not a Dynamic Shared Object (ET_DYN), defeating ASLR for its mapped range.",
            "recommendation": "Rebuild with `-fPIC`/`-shared`, the standard way to build any Android .so.",
            "cwe": "CWE-693", "masvs": "MSTG-CODE-9",
        },
    },
    "AND-BIN-003": {
        "id": "AND-BIN-003", "name": "Native Library Missing/Partial RELRO",
        "severity": "MEDIUM", "masvs": "MSTG-CODE-9",
        "details": {
            "description": "A native (.so) library's GOT is not fully read-only at runtime (no/partial RELRO), easing GOT-overwrite exploitation.",
            "recommendation": "Relink with `-Wl,-z,relro -Wl,-z,now` for Full RELRO.",
            "cwe": "CWE-732", "masvs": "MSTG-CODE-9",
        },
    },
    "AND-BIN-004": {
        "id": "AND-BIN-004", "name": "Native Library Missing Stack Canary",
        "severity": "MEDIUM", "masvs": "MSTG-CODE-9",
        "details": {
            "description": "A native (.so) library was not built with a stack protector (no `__stack_chk_fail`), so stack buffer overflows go undetected.",
            "recommendation": "Rebuild with `-fstack-protector-strong` (or `-all`).",
            "cwe": "CWE-121", "masvs": "MSTG-CODE-9",
        },
    },
    "AND-BIN-005": {
        "id": "AND-BIN-005", "name": "RPATH/RUNPATH Set in Native Library",
        "severity": "MEDIUM", "masvs": "MSTG-CODE-9",
        "details": {
            "description": "A native (.so) library embeds an RPATH/RUNPATH, an uncontrolled search path for the dynamic linker.",
            "recommendation": "Remove the RPATH/RUNPATH from the link step.",
            "cwe": "CWE-427", "masvs": "MSTG-CODE-9",
        },
    },
}


def scan(apk_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Run the ELF hardening checks over an APK/AAB. Returns (findings, rule_defs, stats). Never raises."""
    stats: Dict[str, Any] = {
        "lief_available": LIEF_AVAILABLE,
        "arch_analyzed": None,
        "libs_found_total": 0,
        "libs_analyzed": 0,
        "own_libs_analyzed": 0,
        "vendor_libs_analyzed": 0,
        "parse_failures": 0,
        "findings": 0,
    }
    findings: List[Dict[str, Any]] = []

    if not LIEF_AVAILABLE:
        logger.debug("[native-hardening] lief not importable - skipping native hardening checks")
        return findings, [], stats

    used_rule_ids: set = set()

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()
            all_so = [n for n in namelist if n.startswith("lib/") and n.endswith(".so")]
            stats["libs_found_total"] = len(all_so)

            arch = _pick_arch(namelist)
            if arch is None:
                return findings, [], stats

            stats["arch_analyzed"] = arch
            prefix = f"lib/{arch}/"
            arch_members: Dict[str, str] = {}
            for n in all_so:
                if n.startswith(prefix):
                    basename = n[len(prefix):]
                    if "/" in basename:
                        continue
                    arch_members.setdefault(basename, n)

            if not arch_members:
                return findings, [], stats

            with tempfile.TemporaryDirectory(prefix="narvy-nh-") as tmpdir:
                for basename in sorted(arch_members):
                    member = arch_members[basename]
                    local_path = _safe_extract(zf, member, tmpdir)
                    if local_path is None:
                        stats["parse_failures"] += 1
                        continue
                    facts = _analyze_so(local_path, basename, member)
                    if facts is None:
                        stats["parse_failures"] += 1
                        continue
                    stats["libs_analyzed"] += 1
                    if facts.is_vendor:
                        stats["vendor_libs_analyzed"] += 1
                    else:
                        stats["own_libs_analyzed"] += 1
                    lib_findings = _facts_to_findings(facts)
                    for f in lib_findings:
                        used_rule_ids.add(f["rule_id"])
                    findings.extend(lib_findings)
    except zipfile.BadZipFile:
        logger.error(f"[native-hardening] Invalid APK/AAB file: {apk_path}")
    except Exception as e:
        logger.error(f"[native-hardening] Unexpected error scanning {apk_path}: {e}")

    rule_defs = [_RULE_CATALOG[rid] for rid in sorted(used_rule_ids)]
    stats["findings"] = len(findings)
    return findings, rule_defs, stats
