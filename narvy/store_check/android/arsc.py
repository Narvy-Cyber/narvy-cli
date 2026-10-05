"""Minimal resources.arsc reader: resolves a resource id to its values in every
configuration. Used only to follow references from the manifest (for example
android:networkSecurityConfig="@xml/network_security_config" or a boolean
attribute set through @bool/...). Implements ResTable / ResTable_package /
ResTable_type from AOSP ResourceTypes.h, including sparse, 16-bit offset and
compact entries.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Tuple

from .axml import AXMLError, StringPool, decode_value, RES_STRING_POOL_TYPE, RES_TABLE_TYPE
from .xmlmodel import Value

RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201

FLAG_SPARSE = 0x01
FLAG_OFFSET16 = 0x02

ENTRY_FLAG_COMPLEX = 0x0001
ENTRY_FLAG_COMPACT = 0x0008


class ResourceTable:
    def __init__(self, buf: bytes) -> None:
        self._buf = buf
        ttype, thsize, tsize = struct.unpack_from("<HHI", buf, 0)
        if ttype != RES_TABLE_TYPE:
            raise AXMLError("not a resource table")
        self.values_pool: StringPool = None  # type: ignore[assignment]
        # (pkg_id, type_id) -> list of type chunk offsets
        self._types: Dict[Tuple[int, int], List[int]] = {}
        off = thsize
        end = min(tsize, len(buf))
        while off + 8 <= end:
            ctype, chsize, csize = struct.unpack_from("<HHI", buf, off)
            if csize < 8:
                raise AXMLError("bad table chunk")
            if ctype == RES_STRING_POOL_TYPE and self.values_pool is None:
                self.values_pool = StringPool(buf, off)
            elif ctype == RES_TABLE_PACKAGE_TYPE:
                self._parse_package(off, chsize, csize)
            off += csize
        if self.values_pool is None:
            raise AXMLError("resource table without value string pool")

    def _parse_package(self, off: int, hsize: int, size: int) -> None:
        buf = self._buf
        pkg_id = struct.unpack_from("<I", buf, off + 8)[0]
        p = off + hsize
        end = off + size
        while p + 8 <= end:
            ctype, chsize, csize = struct.unpack_from("<HHI", buf, p)
            if csize < 8:
                raise AXMLError("bad package chunk")
            if ctype == RES_TABLE_TYPE_TYPE:
                type_id = buf[p + 8]
                self._types.setdefault((pkg_id, type_id), []).append(p)
            p += csize

    def resolve(self, res_id: int) -> List[Value]:
        """All values of a resource across configurations (complex entries skipped)."""
        pkg_id = (res_id >> 24) & 0xFF
        type_id = (res_id >> 16) & 0xFF
        entry_idx = res_id & 0xFFFF
        out: List[Value] = []
        buf = self._buf
        for p in self._types.get((pkg_id, type_id), []):
            _ct, chsize, csize = struct.unpack_from("<HHI", buf, p)
            flags = buf[p + 9]
            entry_count, entries_start = struct.unpack_from("<II", buf, p + 12)
            offs_base = p + chsize
            entry_off = None
            if flags & FLAG_SPARSE:
                for i in range(entry_count):
                    idx, o = struct.unpack_from("<HH", buf, offs_base + i * 4)
                    if idx == entry_idx:
                        entry_off = o * 4
                        break
            elif flags & FLAG_OFFSET16:
                if entry_idx < entry_count:
                    o = struct.unpack_from("<H", buf, offs_base + entry_idx * 2)[0]
                    if o != 0xFFFF:
                        entry_off = o * 4
            else:
                if entry_idx < entry_count:
                    o = struct.unpack_from("<I", buf, offs_base + entry_idx * 4)[0]
                    if o != 0xFFFFFFFF:
                        entry_off = o
            if entry_off is None:
                continue
            e = p + entries_start + entry_off
            if e + 8 > p + csize:
                continue
            esize, eflags = struct.unpack_from("<HH", buf, e)
            if eflags & ENTRY_FLAG_COMPACT:
                # compact entry: key(16) flags(16) data(32); dataType = flags >> 8
                dtype = eflags >> 8
                data = struct.unpack_from("<I", buf, e + 4)[0]
                out.append(decode_value(dtype, data, "", self.values_pool))
                continue
            if eflags & ENTRY_FLAG_COMPLEX:
                continue
            v = e + esize
            _vsize, _res0, dtype, data = struct.unpack_from("<HBBI", buf, v)
            out.append(decode_value(dtype, data, "", self.values_pool))
        return out
