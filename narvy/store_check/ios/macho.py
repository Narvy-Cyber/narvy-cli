"""Mach-O reader for the iOS checks.

Reads, per architecture slice: imported (undefined) symbols from LC_SYMTAB and
from the LC_DYLD_CHAINED_FIXUPS import table, Objective-C selector references
(__objc_selrefs resolved into __objc_methname), LC_BUILD_VERSION /
LC_VERSION_MIN_IPHONEOS, LC_ENCRYPTION_INFO and the entitlements blob of the
embedded code signature. Layouts follow Apple's <mach-o/loader.h>,
<mach-o/nlist.h>, <mach-o/fixup-chains.h> and <kern/cs_blobs.h>.
"""
from __future__ import annotations

import plistlib
import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_VERSION_MIN_IPHONEOS = 0x25
LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_DYLD_CHAINED_FIXUPS = 0x80000034

CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171

PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst", 7: "iOSSimulator",
             8: "tvOSSimulator", 9: "watchOSSimulator", 11: "visionOS", 12: "visionOSSimulator"}


class MachOError(Exception):
    pass


def ver(v: int) -> str:
    major, minor, patch = v >> 16, (v >> 8) & 0xFF, v & 0xFF
    return f"{major}.{minor}" + (f".{patch}" if patch else "")


@dataclass
class Section:
    segname: str
    sectname: str
    addr: int
    size: int
    offset: int


@dataclass
class Slice:
    cputype: int
    is64: bool
    filetype: int
    imports: Set[str] = field(default_factory=set)
    selrefs: Optional[Set[str]] = None  # None = could not be determined
    selrefs_note: str = ""
    platform: Optional[int] = None
    minos: Optional[str] = None
    sdk: Optional[str] = None
    encrypted: bool = False
    entitlements: Optional[dict] = None
    signed: bool = False
    dylibs: List[str] = field(default_factory=list)

    @property
    def arch(self) -> str:
        return {CPU_TYPE_ARM64: "arm64", CPU_TYPE_ARM: "armv7"}.get(self.cputype, f"cpu{self.cputype:#x}")


def _cstr(buf: bytes, off: int, limit: int = 4096) -> str:
    end = buf.find(b"\x00", off, min(len(buf), off + limit))
    if end < 0:
        end = min(len(buf), off + limit)
    return buf[off:end].decode("utf-8", errors="replace")


def _parse_slice(buf: bytes, base: int, size: int) -> Slice:
    data = buf[base:base + size] if (base or size != len(buf)) else buf
    if len(data) < 28:
        raise MachOError("truncated Mach-O header")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == MH_MAGIC_64:
        is64 = True
        hdr = 32
    elif magic == MH_MAGIC:
        is64 = False
        hdr = 28
    else:
        raise MachOError(f"unknown Mach-O magic 0x{magic:08x}")
    cputype, _sub, filetype, ncmds, sizeofcmds = struct.unpack_from("<iIIII", data, 4)
    sl = Slice(cputype=cputype & 0xFFFFFFFF, is64=is64, filetype=filetype)
    if hdr + sizeofcmds > len(data) or ncmds > 100000:
        raise MachOError("load commands out of bounds")
    sections: List[Section] = []
    segments: List[Tuple[str, int, int, int, int]] = []  # name, vmaddr, vmsize, fileoff, filesize
    symtab = None
    dysymtab = None
    chained = None
    crypt = None
    codesig = None
    off = hdr
    for _ in range(ncmds):
        if off + 8 > hdr + sizeofcmds:
            raise MachOError("load command out of bounds")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > hdr + sizeofcmds:
            raise MachOError("bad load command size")
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].split(b"\x00")[0].decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            for i in range(nsects):
                s = off + 72 + i * 80
                sectname = data[s:s + 16].split(b"\x00")[0].decode("ascii", "replace")
                sseg = data[s + 16:s + 32].split(b"\x00")[0].decode("ascii", "replace")
                addr, ssize = struct.unpack_from("<QQ", data, s + 32)
                soff = struct.unpack_from("<I", data, s + 48)[0]
                sections.append(Section(sseg, sectname, addr, ssize, soff))
        elif cmd == LC_SEGMENT:
            segname = data[off + 8:off + 24].split(b"\x00")[0].decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<IIII", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 48)[0]
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            for i in range(nsects):
                s = off + 56 + i * 68
                sectname = data[s:s + 16].split(b"\x00")[0].decode("ascii", "replace")
                sseg = data[s + 16:s + 32].split(b"\x00")[0].decode("ascii", "replace")
                addr, ssize, soff = struct.unpack_from("<III", data, s + 32)
                sections.append(Section(sseg, sectname, addr, ssize, soff))
        elif cmd == LC_SYMTAB:
            symtab = struct.unpack_from("<IIII", data, off + 8)
        elif cmd == LC_DYSYMTAB:
            dysymtab = struct.unpack_from("<IIIIII", data, off + 8)
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            chained = struct.unpack_from("<II", data, off + 8)
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            crypt = struct.unpack_from("<III", data, off + 8)
        elif cmd == LC_CODE_SIGNATURE:
            codesig = struct.unpack_from("<II", data, off + 8)
        elif cmd == LC_BUILD_VERSION:
            platform, minos, sdk = struct.unpack_from("<III", data, off + 8)
            sl.platform, sl.minos, sl.sdk = platform, ver(minos), ver(sdk)
        elif cmd == LC_VERSION_MIN_IPHONEOS and sl.platform is None:
            v, sdk = struct.unpack_from("<II", data, off + 8)
            sl.platform, sl.minos, sl.sdk = 2, ver(v), ver(sdk)
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            name_off = struct.unpack_from("<I", data, off + 8)[0]
            sl.dylibs.append(_cstr(data, off + name_off, cmdsize))
        off += cmdsize

    # ---- imported symbols from the symbol table
    if symtab is not None:
        symoff, nsyms, stroff, strsize = symtab
        entsize = 16 if is64 else 12
        first, count = 0, nsyms
        if dysymtab is not None:
            first, count = dysymtab[4], dysymtab[5]  # iundefsym, nundefsym
        if symoff + (first + count) * entsize <= len(data) and stroff + strsize <= len(data):
            for i in range(first, first + count):
                p = symoff + i * entsize
                n_strx, n_type = struct.unpack_from("<IB", data, p)
                if n_type & 0xE0:  # stab
                    continue
                if (n_type & 0x0E) == 0 and (n_type & 0x01) and n_strx < strsize:
                    sl.imports.add(_cstr(data, stroff + n_strx, 1024))

    # ---- imported symbols from chained fixups
    pointer_formats: Set[int] = set()
    if chained is not None:
        dataoff, datasize = chained
        blob = data[dataoff:dataoff + datasize]
        if len(blob) >= 28:
            (_ver, starts_off, imports_off, symbols_off, imports_count, imports_format,
             symbols_format) = struct.unpack_from("<IIIIIII", blob, 0)
            syms = blob[symbols_off:]
            if symbols_format == 1:
                try:
                    syms = zlib.decompress(syms)
                except zlib.error:
                    syms = b""
            for i in range(imports_count):
                name_off = None
                ordinal = 0
                if imports_format in (1, 2):
                    p = imports_off + i * (4 if imports_format == 1 else 8)
                    if p + 4 <= len(blob):
                        v = struct.unpack_from("<I", blob, p)[0]
                        ordinal = v & 0xFF
                        if ordinal >= 0xF0:
                            ordinal -= 0x100  # special ordinals: 0 self, -1 main, -2 flat, -3 weak
                        name_off = v >> 9
                elif imports_format == 3:
                    p = imports_off + i * 16
                    if p + 8 <= len(blob):
                        v = struct.unpack_from("<Q", blob, p)[0]
                        ordinal = v & 0xFFFF
                        if ordinal >= 0xFFF0:
                            ordinal -= 0x10000
                        name_off = v >> 32
                # Only imports bound to a named dependent library count: ordinal 0 (this
                # image), -1 (main executable), -2 (flat lookup) and -3 (weak coalescing)
                # can resolve to the app's own definitions.
                if name_off is not None and ordinal >= 1 and name_off < len(syms):
                    sl.imports.add(_cstr(syms, name_off, 1024))
            # pointer formats used by segments (to decode selector references)
            if starts_off + 4 <= len(blob):
                seg_count = struct.unpack_from("<I", blob, starts_off)[0]
                for i in range(min(seg_count, 64)):
                    so = struct.unpack_from("<I", blob, starts_off + 4 + i * 4)[0]
                    if so and starts_off + so + 8 <= len(blob):
                        pointer_formats.add(struct.unpack_from("<H", blob, starts_off + so + 8)[0])

    # ---- encryption
    if crypt is not None and crypt[2] != 0:
        sl.encrypted = True

    # ---- selector references
    sl.selrefs, sl.selrefs_note = _selrefs(data, is64, sections, segments, crypt, pointer_formats)

    # ---- entitlements
    if codesig is not None:
        sl.signed = True
        sl.entitlements = _entitlements(data, codesig[0], codesig[1])
    return sl


def _selrefs(data: bytes, is64: bool, sections: List[Section], segments, crypt, pointer_formats):
    methname = next((s for s in sections if s.sectname == "__objc_methname"), None)
    selref_secs = [s for s in sections if s.sectname == "__objc_selrefs"]
    if not selref_secs:
        return set(), "no __objc_selrefs section"
    if methname is None:
        return None, "__objc_selrefs without __objc_methname"
    if crypt is not None and crypt[2] != 0:
        coff, csize = crypt[0], crypt[1]
        if methname.offset < coff + csize and coff < methname.offset + methname.size:
            return None, "selector names are inside the FairPlay-encrypted range"
    m_lo, m_hi = methname.addr, methname.addr + methname.size
    text_base = next((s[1] for s in segments if s[0] == "__TEXT"), 0)
    out: Set[str] = set()
    unresolved = 0
    ptr = 8 if is64 else 4
    for sec in selref_secs:
        n = sec.size // ptr
        if sec.offset + n * ptr > len(data):
            return None, "__objc_selrefs out of bounds"
        for i in range(n):
            if is64:
                v = struct.unpack_from("<Q", data, sec.offset + i * 8)[0]
            else:
                v = struct.unpack_from("<I", data, sec.offset + i * 4)[0]
            target = None
            for cand in _candidates(v, text_base, is64):
                if m_lo <= cand < m_hi:
                    target = cand
                    break
            if target is None:
                unresolved += 1
                continue
            foff = methname.offset + (target - m_lo)
            out.add(_cstr(data, foff, 1024))
    if unresolved and not out:
        return None, f"{unresolved} selector references could not be decoded"
    note = f"{unresolved} selector references not decoded" if unresolved else ""
    return out, note


def _candidates(v: int, text_base: int, is64: bool):
    if not is64:
        yield v
        return
    if v >> 63:  # arm64e authenticated pointer: rebase target is a 32-bit runtime offset
        if not (v >> 62) & 1:
            yield text_base + (v & 0xFFFFFFFF)
        return
    if (v >> 62) & 1:  # bind, not a rebase
        return
    yield v  # plain pointer (no chained fixups)
    t36 = v & 0xFFFFFFFFF
    yield t36  # DYLD_CHAINED_PTR_64: vmaddr
    yield text_base + t36  # DYLD_CHAINED_PTR_64_OFFSET: runtime offset
    t43 = v & 0x7FFFFFFFFFF
    yield t43  # DYLD_CHAINED_PTR_ARM64E rebase: vmaddr
    yield text_base + t43  # ARM64E_USERLAND(24): runtime offset


def _entitlements(data: bytes, off: int, size: int) -> Optional[dict]:
    blob = data[off:off + size]
    if len(blob) < 12:
        return None
    magic, _length, count = struct.unpack_from(">III", blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return None
    for i in range(min(count, 64)):
        if 12 + i * 8 + 8 > len(blob):
            break
        _typ, boff = struct.unpack_from(">II", blob, 12 + i * 8)
        if boff + 8 > len(blob):
            continue
        bmagic, blen = struct.unpack_from(">II", blob, boff)
        if bmagic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            try:
                return plistlib.loads(blob[boff + 8:boff + blen])
            except Exception:  # noqa: BLE001
                return None
    return {}  # signed, but without an entitlements blob


def parse_macho(buf: bytes) -> List[Slice]:
    if len(buf) < 8:
        raise MachOError("file too small")
    magic_be = struct.unpack_from(">I", buf, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        n = struct.unpack_from(">I", buf, 4)[0]
        if n == 0 or n > 32:
            raise MachOError("bad fat header")
        out = []
        for i in range(n):
            if magic_be == FAT_MAGIC:
                cputype, _sub, offset, size, _align = struct.unpack_from(">iIIII", buf, 8 + i * 20)
            else:
                cputype, _sub, offset, size, _align, _r = struct.unpack_from(">iIQQII", buf, 8 + i * 32)
            if offset + size > len(buf):
                raise MachOError("fat slice out of bounds")
            out.append(_parse_slice(buf, offset, size))
        return out
    return [_parse_slice(buf, 0, len(buf))]


def is_macho(head: bytes) -> bool:
    if len(head) < 4:
        return False
    le = struct.unpack_from("<I", head, 0)[0]
    be = struct.unpack_from(">I", head, 0)[0]
    return le in (MH_MAGIC, MH_MAGIC_64) or be in (FAT_MAGIC, FAT_MAGIC_64)
