"""Parser for Android binary XML (AXML), as found in APK files.

Implements the subset of the ResXMLTree format from AOSP
(frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h) needed to
rebuild an element tree: string pool, resource map, namespace and element
chunks. Malformed input raises AXMLError; the caller turns that into a
"not determined" verdict, never into a guess.
"""
from __future__ import annotations

import struct
from typing import List, Optional

from .xmlmodel import Attr, Element, Value, K_BOOL, K_INT, K_OTHER, K_REF, K_STRING

RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

UTF8_FLAG = 0x100

# Res_value data types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

NO_INDEX = 0xFFFFFFFF


class AXMLError(Exception):
    pass


class StringPool:
    def __init__(self, buf: bytes, off: int) -> None:
        try:
            _t, hsize, size = struct.unpack_from("<HHI", buf, off)
            count, _styles, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", buf, off + 8)
        except struct.error as exc:
            raise AXMLError(f"truncated string pool: {exc}") from exc
        if off + size > len(buf) or count > 10_000_000:
            raise AXMLError("string pool out of bounds")
        self._buf = buf
        self._utf8 = bool(flags & UTF8_FLAG)
        self._offsets = struct.unpack_from(f"<{count}I", buf, off + hsize) if count else ()
        self._base = off + strings_start
        self._end = off + size
        self._cache: dict = {}

    def __len__(self) -> int:
        return len(self._offsets)

    def get(self, idx: int) -> str:
        if idx == NO_INDEX or idx < 0 or idx >= len(self._offsets):
            return ""
        if idx in self._cache:
            return self._cache[idx]
        p = self._base + self._offsets[idx]
        b = self._buf
        try:
            if self._utf8:
                # utf16 length (skipped), then utf8 byte length
                n = b[p]
                p += 2 if n & 0x80 else 1
                n = b[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | b[p + 1]
                    p += 2
                else:
                    p += 1
                s = b[p:p + n].decode("utf-8", errors="replace")
            else:
                n = struct.unpack_from("<H", b, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", b, p)[0]
                    p += 2
                s = b[p:p + n * 2].decode("utf-16-le", errors="replace")
        except (IndexError, struct.error) as exc:
            raise AXMLError(f"bad string #{idx}: {exc}") from exc
        self._cache[idx] = s
        return s


def decode_value(dtype: int, data: int, raw: str, pool: StringPool) -> Value:
    if dtype == TYPE_STRING:
        return Value(K_STRING, pool.get(data) if raw == "" else raw, raw)
    if dtype == TYPE_INT_BOOLEAN:
        return Value(K_BOOL, data != 0, raw)
    if dtype in (TYPE_INT_DEC, TYPE_INT_HEX):
        if data & 0x80000000 and dtype == TYPE_INT_DEC:
            data = data - 0x100000000
        return Value(K_INT, data, raw)
    if dtype == TYPE_REFERENCE:
        return Value(K_REF, data, raw)
    if raw:
        return Value(K_STRING, raw, raw)
    return Value(K_OTHER, data, raw)


def parse_axml(buf: bytes) -> Element:
    if len(buf) < 8:
        raise AXMLError("file too small for AXML")
    ftype, fhsize, fsize = struct.unpack_from("<HHI", buf, 0)
    if ftype != RES_XML_TYPE:
        raise AXMLError(f"not binary XML (chunk type 0x{ftype:04x})")
    end = min(fsize, len(buf)) if fsize >= 8 else len(buf)
    off = fhsize
    pool: Optional[StringPool] = None
    resmap: List[int] = []
    ns_uris: dict = {}
    root: Optional[Element] = None
    stack: List[Element] = []
    guard = 0
    while off + 8 <= end:
        guard += 1
        if guard > 5_000_000:
            raise AXMLError("too many chunks")
        ctype, chsize, csize = struct.unpack_from("<HHI", buf, off)
        if csize < 8 or off + csize > end:
            raise AXMLError(f"bad chunk size at {off}")
        if ctype == RES_STRING_POOL_TYPE:
            pool = StringPool(buf, off)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            n = (csize - chsize) // 4
            resmap = list(struct.unpack_from(f"<{n}I", buf, off + chsize))
        elif ctype in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
            if pool is None:
                raise AXMLError("namespace before string pool")
            prefix_i, uri_i = struct.unpack_from("<II", buf, off + chsize)
            ns_uris[uri_i] = pool.get(uri_i)
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            if pool is None:
                raise AXMLError("element before string pool")
            line = struct.unpack_from("<I", buf, off + 8)[0]
            ext = off + chsize
            ns_i, name_i, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", buf, ext)
            el = Element(tag=pool.get(name_i), line=line)
            if attr_size < 20:
                attr_size = 20
            a_off = ext + attr_start
            for i in range(attr_count):
                p = a_off + i * attr_size
                if p + 20 > off + csize:
                    raise AXMLError("attribute out of chunk bounds")
                a_ns, a_name, a_raw, _vsize, _res0, dtype, data = struct.unpack_from("<IIIHBBI", buf, p)
                name = pool.get(a_name)
                res_id = resmap[a_name] if a_name < len(resmap) and resmap[a_name] != 0 else None
                raw = pool.get(a_raw) if a_raw != NO_INDEX else ""
                ns = pool.get(a_ns) if a_ns != NO_INDEX else ""
                el.attrs.append(Attr(ns=ns, name=name, res_id=res_id, value=decode_value(dtype, data, raw, pool)))
            if stack:
                stack[-1].children.append(el)
            elif root is None:
                root = el
            stack.append(el)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        elif ctype == RES_XML_CDATA_TYPE:
            if pool is not None and stack:
                data_i = struct.unpack_from("<I", buf, off + chsize)[0]
                stack[-1].text += pool.get(data_i)
        # unknown chunks are skipped
        off += csize
    if root is None:
        raise AXMLError("no root element")
    return root
