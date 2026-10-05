"""Builders for minimal synthetic fixtures (APK, AAB, split sets, ELF, Mach-O, IPA).

They produce real binary formats (validated against aapt, llvm-readelf and
llvm-nm in test_builders.py when those tools are installed), so each rule can
be exercised with a positive and a negative case.
"""
from __future__ import annotations

import io
import plistlib
import struct
import zipfile
from typing import Dict, List, Optional, Sequence, Tuple

ANDROID_NS = "http://schemas.android.com/apk/res/android"

ATTR = {
    "name": 0x01010003, "permission": 0x01010006, "enabled": 0x0101000E, "debuggable": 0x0101000F,
    "exported": 0x01010010, "minSdkVersion": 0x0101020C, "versionCode": 0x0101021B, "versionName": 0x0101021C,
    "required": 0x0101028E, "targetSdkVersion": 0x01010270, "maxSdkVersion": 0x01010271,
    "extractNativeLibs": 0x010104EA, "usesCleartextTraffic": 0x010104EC, "networkSecurityConfig": 0x01010527,
    "foregroundServiceType": 0x01010599,
}

FGS = {"dataSync": 0x01, "mediaPlayback": 0x02, "phoneCall": 0x04, "location": 0x08, "connectedDevice": 0x10,
       "mediaProjection": 0x20, "camera": 0x40, "microphone": 0x80, "health": 0x100, "remoteMessaging": 0x200,
       "systemExempted": 0x400, "shortService": 0x800, "mediaProcessing": 0x2000, "specialUse": 0x40000000}


# ----------------------------------------------------------------------------- XML model
class E:
    """Element spec. attrs: {name: value}; android attrs use 'android:' prefix.
    Values: bool, int, str, or ('ref', 0x7f...) or ('hex', int)."""

    def __init__(self, tag: str, attrs: Optional[dict] = None, children: Optional[list] = None, text: str = ""):
        self.tag = tag
        self.attrs = attrs or {}
        self.children = children or []
        self.text = text


def manifest(package="com.example.app", target=36, min_sdk=24, app_attrs=None, app_children=None,
             perms: Sequence[str] = (), features: Sequence[Tuple[str, Optional[bool]]] = (), extra=None) -> E:
    uses_sdk = {"android:minSdkVersion": min_sdk}
    if target is not None:
        uses_sdk["android:targetSdkVersion"] = target
    children = [E("uses-sdk", uses_sdk)]
    for p in perms:
        children.append(E("uses-permission", {"android:name": p}))
    for f, req in features:
        a = {"android:name": f}
        if req is not None:
            a["android:required"] = req
        children.append(E("uses-feature", a))
    children.extend(extra or [])
    children.append(E("application", app_attrs or {}, app_children or []))
    return E("manifest", {"package": package, "android:versionCode": 1, "android:versionName": "1.0"}, children)


# ----------------------------------------------------------------------------- AXML writer
def _pool(strings: List[str]) -> bytes:
    offs = []
    data = b""
    for s in strings:
        offs.append(len(data))
        enc = s.encode("utf-16-le")
        n = len(s)
        data += struct.pack("<H", n) + enc + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    hdr_size = 28
    strings_start = hdr_size + 4 * len(strings)
    body = struct.pack(f"<{len(offs)}I", *offs) + data
    size = hdr_size + len(body)
    return struct.pack("<HHIIIIII", 0x0001, hdr_size, size, len(strings), 0, 0, strings_start, 0) + body


def axml(root: E) -> bytes:
    # collect attribute names: android attrs with ids first (resource map order)
    attr_names: List[str] = []
    ids: List[int] = []
    other: List[str] = []

    def walk(e: E):
        for k in e.attrs:
            if k.startswith("android:"):
                n = k[8:]
                if n not in attr_names:
                    attr_names.append(n)
                    ids.append(ATTR[n])
        for c in e.children:
            walk(c)
    walk(root)
    strings = list(attr_names)
    index = {s: i for i, s in enumerate(strings)}

    def sid(s: str) -> int:
        if s not in index:
            index[s] = len(strings)
            strings.append(s)
        return index[s]
    sid(ANDROID_NS)
    sid("android")

    chunks = b""

    def elem(e: E):
        nonlocal chunks
        attrs = []
        for k, v in e.attrs.items():
            if k.startswith("android:"):
                ns, name_i = sid(ANDROID_NS), index[k[8:]]
            else:
                ns, name_i = 0xFFFFFFFF, sid(k)
            raw = 0xFFFFFFFF
            if isinstance(v, bool):
                dtype, data = 0x12, 0xFFFFFFFF if v else 0
            elif isinstance(v, int):
                dtype, data = 0x10, v & 0xFFFFFFFF
            elif isinstance(v, tuple) and v[0] == "ref":
                dtype, data = 0x01, v[1]
            elif isinstance(v, tuple) and v[0] == "hex":
                dtype, data = 0x11, v[1]
            else:
                raw = sid(str(v))
                dtype, data = 0x03, raw
            attrs.append(struct.pack("<IIIHBBI", ns, name_i, raw, 8, 0, dtype, data))
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, sid(e.tag), 20, 20, len(attrs), 0, 0, 0)
        body = ext + b"".join(attrs)
        chunks += struct.pack("<HHIII", 0x0102, 16, 16 + len(body), 1, 0xFFFFFFFF) + body
        if e.text:
            cd = struct.pack("<I", sid(e.text)) + struct.pack("<HBBI", 8, 0, 0x03, sid(e.text))
            chunks += struct.pack("<HHIII", 0x0104, 16, 16 + len(cd), 1, 0xFFFFFFFF) + cd
        for c in e.children:
            elem(c)
        endb = struct.pack("<II", 0xFFFFFFFF, sid(e.tag))
        chunks += struct.pack("<HHIII", 0x0103, 16, 16 + len(endb), 1, 0xFFFFFFFF) + endb

    ns_body = struct.pack("<II", sid("android"), sid(ANDROID_NS))
    elem(root)
    start_ns = struct.pack("<HHIII", 0x0100, 16, 24, 1, 0xFFFFFFFF) + ns_body
    end_ns = struct.pack("<HHIII", 0x0101, 16, 24, 1, 0xFFFFFFFF) + ns_body
    pool = _pool(strings)
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(ids)) + struct.pack(f"<{len(ids)}I", *ids)
    body = pool + resmap + start_ns + chunks + end_ns
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


# ----------------------------------------------------------------------------- ARSC writer
def arsc(entries: Dict[int, Tuple[str, object]], package="com.example.app") -> bytes:
    """entries: res_id -> ('file', 'res/xml/x.xml') | ('bool', True). Single default config."""
    values: List[str] = []
    by_type: Dict[int, Dict[int, Tuple[int, int]]] = {}
    for rid, (kind, val) in entries.items():
        t = (rid >> 16) & 0xFF
        e = rid & 0xFFFF
        if kind == "file":
            values.append(val)
            by_type.setdefault(t, {})[e] = (0x03, len(values) - 1)
        elif kind == "bool":
            by_type.setdefault(t, {})[e] = (0x12, 0xFFFFFFFF if val else 0)
    max_t = max(by_type) if by_type else 1
    type_names = [f"t{i}" for i in range(1, max_t + 1)]
    key_names = []
    pkg_chunks = b""
    for t, ents in sorted(by_type.items()):
        count = max(ents) + 1
        spec = struct.pack("<HHIBBHI", 0x0202, 16, 16 + 4 * count, t, 0, 0, count) + b"\x00" * (4 * count)
        config = struct.pack("<I", 64) + b"\x00" * 60
        offsets = []
        edata = b""
        for i in range(count):
            if i not in ents:
                offsets.append(0xFFFFFFFF)
                continue
            key_names.append(f"k{t}_{i}")
            offsets.append(len(edata))
            dtype, data = ents[i]
            edata += struct.pack("<HHI", 8, 0, len(key_names) - 1) + struct.pack("<HBBI", 8, 0, dtype, data)
        hsize = 20 + len(config)
        entries_start = hsize + 4 * count
        tchunk = struct.pack("<HHIBBHII", 0x0201, hsize, entries_start + len(edata), t, 0, 0, count, entries_start)
        tchunk += config + struct.pack(f"<{count}I", *offsets) + edata
        pkg_chunks += spec + tchunk
    type_pool = _pool(type_names)
    key_pool = _pool(key_names or ["k"])
    name = package.encode("utf-16-le")[:254].ljust(256, b"\x00")
    phsize = 288
    pheader = struct.pack("<HHII", 0x0200, phsize, 0, 0x7F) + name + struct.pack(
        "<IIIII", phsize, len(type_names), phsize + len(type_pool), 0, 0)
    pkg = pheader + type_pool + key_pool + pkg_chunks
    pkg = pkg[:4] + struct.pack("<I", len(pkg)) + pkg[8:]
    vpool = _pool(values or ["x"])
    body = vpool + pkg
    return struct.pack("<HHII", 0x0002, 12, 12 + len(body), 1) + body


# ----------------------------------------------------------------------------- ELF writer
def elf64(aligns: Sequence[int], machine: int = 183) -> bytes:
    """Minimal ELF64 shared object with one PT_LOAD per alignment value."""
    phnum = len(aligns)
    eh = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    eh += struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    ph = b""
    off = 0
    for a in aligns:
        ph += struct.pack("<IIQQQQQQ", 1, 5, off, off, off, 0x1000, 0x1000, a)
        off += 0x10000
    return eh + ph + b"\x00" * 64


def elf32(aligns: Sequence[int], machine: int = 40) -> bytes:
    phnum = len(aligns)
    eh = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    eh += struct.pack("<HHIIIIIHHHHHH", 3, machine, 1, 0, 52, 0, 0, 52, 32, phnum, 40, 0, 0)
    ph = b""
    for a in aligns:
        ph += struct.pack("<IIIIIIII", 1, 0, 0, 0, 0x1000, 0x1000, 5, a)
    return eh + ph


# ----------------------------------------------------------------------------- APK / split sets
def apk(man: E, files: Optional[Dict[str, bytes]] = None, stored: Sequence[str] = (), align_stored: Optional[int] = None,
        misalign: bool = False) -> bytes:
    """Build an APK. Paths in `stored` are written uncompressed; if align_stored is
    given, their data is padded (via the local extra field) to that alignment,
    or deliberately offset by 4 bytes when misalign=True."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", axml(man))
        for name, data in (files or {}).items():
            if name in stored:
                zi = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_STORED
                if align_stored:
                    header_off = buf.tell()
                    data_off = header_off + 30 + len(name.encode())
                    pad = (-(data_off + 4)) % align_stored
                    if misalign:
                        pad = (pad + 4) % align_stored or 4
                    zi.extra = struct.pack("<HH", 0xD935, pad) + b"\x00" * pad
                z.writestr(zi, data)
            else:
                z.writestr(name, data)
    return buf.getvalue()


def split_set(apks: Dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for n, d in apks.items():
            z.writestr(n, d)
    return buf.getvalue()


# ----------------------------------------------------------------------------- protobuf (AAB)
def _varint(n: int) -> bytes:
    if n < 0:
        n += 1 << 64
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def _f(no: int, wt: int, payload) -> bytes:
    key = _varint((no << 3) | wt)
    if wt == 0:
        return key + _varint(payload)
    if isinstance(payload, str):
        payload = payload.encode()
    return key + _varint(len(payload)) + payload


def _pb_item(v) -> Tuple[str, bytes]:
    if isinstance(v, bool):
        return ("true" if v else "false"), _f(7, 2, _f(8, 0, 1 if v else 0))
    if isinstance(v, int):
        return str(v), _f(7, 2, _f(6, 0, v))
    if isinstance(v, tuple) and v[0] == "ref":
        return f"@0x{v[1]:08x}", _f(1, 2, _f(2, 0, v[1]))
    if isinstance(v, tuple) and v[0] == "hex":
        return hex(v[1]), _f(7, 2, _f(7, 0, v[1]))
    return str(v), _f(2, 2, _f(1, 2, str(v)))


def pb_xml(e: E) -> bytes:
    def element(e: E) -> bytes:
        out = _f(3, 2, e.tag)
        for k, v in e.attrs.items():
            if k.startswith("android:"):
                n = k[8:]
                raw, item = _pb_item(v)
                a = _f(1, 2, ANDROID_NS) + _f(2, 2, n) + _f(3, 2, raw) + _f(5, 0, ATTR[n]) + _f(6, 2, item)
            else:
                raw, item = _pb_item(v)
                a = _f(2, 2, k) + _f(3, 2, raw)
                if not isinstance(v, str):
                    a += _f(6, 2, item)
            out += _f(4, 2, a)
        if e.text:
            out += _f(5, 2, _f(2, 2, e.text))
        for c in e.children:
            out += _f(5, 2, _f(1, 2, element(c)))
        return out
    return _f(1, 2, element(e))


def pb_resources(entries: Dict[int, Tuple[str, object]]) -> bytes:
    types: Dict[int, List[bytes]] = {}
    for rid, (kind, val) in entries.items():
        t, e = (rid >> 16) & 0xFF, rid & 0xFFFF
        if kind == "file":
            item = _f(5, 2, _f(1, 2, val))
        else:
            item = _f(7, 2, _f(8, 0, 1 if val else 0))
        cv = _f(2, 2, _f(4, 2, item))
        entry = _f(1, 2, _f(1, 0, e)) + _f(2, 2, f"e{e}") + _f(6, 2, cv)
        types.setdefault(t, []).append(entry)
    pkg = _f(1, 2, _f(1, 0, 0x7F)) + _f(2, 2, "com.example.app")
    for t, ents in types.items():
        pkg += _f(3, 2, _f(1, 2, _f(1, 0, t)) + _f(2, 2, f"t{t}") + b"".join(_f(3, 2, x) for x in ents))
    return _f(2, 2, pkg)


def aab(man: E, files: Optional[Dict[str, bytes]] = None, resources: Optional[Dict[int, Tuple[str, object]]] = None,
        xml_files: Optional[Dict[str, E]] = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("base/manifest/AndroidManifest.xml", pb_xml(man))
        if resources:
            z.writestr("base/resources.pb", pb_resources(resources))
        for p, el in (xml_files or {}).items():
            z.writestr("base/" + p, pb_xml(el))
        for n, d in (files or {}).items():
            z.writestr(n, d)
        z.writestr("BundleConfig.pb", b"")
    return buf.getvalue()


# ----------------------------------------------------------------------------- Mach-O writer
def macho(imports: Sequence[str] = (), sdk=(26, 0), minos=(15, 0), selectors: Sequence[str] = (),
          entitlements: Optional[dict] = None, encrypted: bool = False, defined: Sequence[str] = ()) -> bytes:
    """Minimal arm64 MH_EXECUTE with LC_SEGMENT_64(__TEXT with __objc_methname,
    __DATA with __objc_selrefs), LC_SYMTAB, LC_DYSYMTAB, LC_BUILD_VERSION,
    optional LC_ENCRYPTION_INFO_64 and LC_CODE_SIGNATURE."""
    base = 0x100000000
    # strings
    strtab = b"\x00"
    syms = []
    for name in list(defined) + list(imports):
        syms.append((len(strtab), name in defined))
        strtab += name.encode() + b"\x00"
    while len(strtab) % 8:
        strtab += b"\x00"
    methname = b""
    sel_offs = []
    for s in selectors:
        sel_offs.append(len(methname))
        methname += s.encode() + b"\x00"
    methname = methname or b"\x00"
    # layout: header+cmds at 0, methname at 0x4000 (__TEXT), selrefs at 0x8000 (__DATA), linkedit at 0xC000
    text_off, data_off, link_off = 0x4000, 0x8000, 0xC000
    methname_addr = base + text_off
    selrefs = b"".join(struct.pack("<Q", methname_addr + o) for o in sel_offs)
    nlist = b""
    ndef = len(defined)
    for i, (strx, is_def) in enumerate(syms):
        if is_def:
            nlist += struct.pack("<IBBHQ", strx, 0x0F, 1, 0, base + text_off)
        else:
            nlist += struct.pack("<IBBHQ", strx, 0x01, 0, 0x0100, 0)
    symoff = link_off
    stroff = symoff + len(nlist)
    linkedit = nlist + strtab
    sig = b""
    if entitlements is not None:
        ent = plistlib.dumps(entitlements)
        eblob = struct.pack(">II", 0xFADE7171, 8 + len(ent)) + ent
        sig = struct.pack(">III", 0xFADE0CC0, 12 + 8 + len(eblob), 1) + struct.pack(">II", 5, 20) + eblob
    sig_off = link_off + len(linkedit)
    while sig_off % 16:
        sig_off += 1
    cmds = b""
    ncmds = 0

    def seg(name, vmaddr, vmsize, fileoff, filesize, sects):
        b = struct.pack("<II16sQQQQiiII", 0x19, 72 + 80 * len(sects), name.encode(), vmaddr, vmsize, fileoff, filesize,
                        5, 5, len(sects), 0)
        for sn, sg, addr, size, off in sects:
            b += struct.pack("<16s16sQQIIIIIIII", sn.encode(), sg.encode(), addr, size, off, 0, 0, 0, 0, 0, 0, 0)
        return b
    cmds += seg("__TEXT", base, 0x8000, 0, 0x8000, [("__objc_methname", "__TEXT", methname_addr, len(methname), text_off)])
    cmds += seg("__DATA", base + data_off, 0x4000, data_off, 0x4000,
                [("__objc_selrefs", "__DATA", base + data_off, len(selrefs), data_off)] if selectors else [])
    total_link = (sig_off - link_off) + len(sig)
    cmds += seg("__LINKEDIT", base + link_off, 0x4000, link_off, total_link, [])
    ncmds += 3
    cmds += struct.pack("<IIIIII", 0x2, 24, symoff, len(syms), stroff, len(strtab))
    cmds += struct.pack("<II18I", 0xB, 80, 0, 0, 0, ndef, ndef, len(syms) - ndef, *([0] * 12))
    ncmds += 2
    cmds += struct.pack("<IIIIII", 0x32, 24, 2, (minos[0] << 16) | (minos[1] << 8), (sdk[0] << 16) | (sdk[1] << 8), 0)
    ncmds += 1
    if encrypted:
        cmds += struct.pack("<IIIIII", 0x2C, 24, 0x4000, 0x4000, 1, 0)
        ncmds += 1
    if entitlements is not None:
        cmds += struct.pack("<IIII", 0x1D, 16, sig_off, len(sig))
        ncmds += 1
    hdr = struct.pack("<IiIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, ncmds, len(cmds), 0, 0)
    out = bytearray(sig_off + len(sig))
    out[0:len(hdr) + len(cmds)] = hdr + cmds
    out[text_off:text_off + len(methname)] = methname
    out[data_off:data_off + len(selrefs)] = selrefs
    out[link_off:link_off + len(linkedit)] = linkedit
    out[sig_off:sig_off + len(sig)] = sig
    return bytes(out)


def privacy_manifest(categories: Dict[str, List[str]]) -> bytes:
    return plistlib.dumps({
        "NSPrivacyTracking": False,
        "NSPrivacyAccessedAPITypes": [
            {"NSPrivacyAccessedAPIType": c, "NSPrivacyAccessedAPITypeReasons": r} for c, r in categories.items()],
    }, fmt=plistlib.FMT_XML)


def ipa(info: Optional[dict] = None, executable: Optional[bytes] = None, files: Optional[Dict[str, bytes]] = None,
        app_name="Demo") -> bytes:
    base_info = {
        "CFBundleIdentifier": "com.example.demo", "CFBundleExecutable": app_name,
        "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1", "MinimumOSVersion": "15.0",
        "CFBundleSupportedPlatforms": ["iPhoneOS"], "DTSDKName": "iphoneos26.0", "DTPlatformVersion": "26.0",
        "DTXcode": "2600",
    }
    base_info.update(info or {})
    for k in [k for k, v in base_info.items() if v is None]:
        del base_info[k]
    d = f"Payload/{app_name}.app/"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(d + "Info.plist", plistlib.dumps(base_info, fmt=plistlib.FMT_BINARY))
        z.writestr(d + app_name, executable if executable is not None else macho())
        for rel, data in (files or {}).items():
            z.writestr(d + rel, data)
    return buf.getvalue()


def framework(name: str, executable: bytes, manifest: Optional[bytes] = None) -> Dict[str, bytes]:
    d = f"Frameworks/{name}.framework/"
    out = {d + "Info.plist": plistlib.dumps({"CFBundleExecutable": name, "CFBundleIdentifier": f"org.sdk.{name}"}),
           d + name: executable}
    if manifest is not None:
        out[d + "PrivacyInfo.xcprivacy"] = manifest
    return out
