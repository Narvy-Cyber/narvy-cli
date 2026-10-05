"""Readers for the protobuf formats used inside Android App Bundles (AAB).

Bundles store manifests and XML resources as aapt2 ``XmlNode`` messages and the
resource table as ``ResourceTable`` (frameworks/base/tools/aapt2/Resources.proto).
This is a schema-aware decoder for the few fields we need, built on a tiny
generic protobuf wire-format reader (no dependency on the protobuf package).
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from .xmlmodel import Attr, Element, Value, K_BOOL, K_INT, K_OTHER, K_REF, K_STRING


class ProtoError(Exception):
    pass


def _varint(buf: bytes, p: int) -> Tuple[int, int]:
    shift = 0
    result = 0
    while True:
        if p >= len(buf):
            raise ProtoError("truncated varint")
        b = buf[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, p
        shift += 7
        if shift > 70:
            raise ProtoError("varint too long")


def fields(buf: bytes) -> Dict[int, list]:
    """Decode one message level: field number -> list of raw values.

    Varints are ints, length-delimited are bytes, fixed32/64 are ints.
    """
    out: Dict[int, list] = {}
    p = 0
    n = len(buf)
    while p < n:
        key, p = _varint(buf, p)
        fno, wt = key >> 3, key & 7
        if wt == 0:
            v, p = _varint(buf, p)
        elif wt == 2:
            ln, p = _varint(buf, p)
            if p + ln > n:
                raise ProtoError("length-delimited field out of bounds")
            v = buf[p:p + ln]
            p += ln
        elif wt == 5:
            if p + 4 > n:
                raise ProtoError("truncated fixed32")
            v = struct.unpack_from("<I", buf, p)[0]
            p += 4
        elif wt == 1:
            if p + 8 > n:
                raise ProtoError("truncated fixed64")
            v = struct.unpack_from("<Q", buf, p)[0]
            p += 8
        else:
            raise ProtoError(f"unsupported wire type {wt}")
        out.setdefault(fno, []).append(v)
    return out


def _s(f: Dict[int, list], no: int) -> str:
    v = f.get(no)
    if not v:
        return ""
    return v[-1].decode("utf-8", errors="replace") if isinstance(v[-1], bytes) else str(v[-1])


def _int(f: Dict[int, list], no: int, default: Optional[int] = None) -> Optional[int]:
    v = f.get(no)
    return v[-1] if v else default


def decode_item(item: bytes, raw: str = "") -> Value:
    """Resources.proto Item -> Value."""
    f = fields(item)
    if 1 in f:  # Reference
        rf = fields(f[1][-1])
        rid = _int(rf, 2, 0) or 0
        return Value(K_REF, rid, raw or _s(rf, 3))
    if 2 in f:  # String
        return Value(K_STRING, _s(fields(f[2][-1]), 1), raw)
    if 3 in f:  # RawString
        return Value(K_STRING, _s(fields(f[3][-1]), 1), raw)
    if 5 in f:  # FileReference
        return Value(K_STRING, _s(fields(f[5][-1]), 1), raw)
    if 7 in f:  # Primitive
        pf = fields(f[7][-1])
        if 8 in pf:
            return Value(K_BOOL, bool(pf[8][-1]), raw)
        if 6 in pf:
            v = pf[6][-1]
            if v >= 1 << 63:
                v -= 1 << 64
            elif v >= 1 << 31 and v < 1 << 32:
                v -= 1 << 32
            return Value(K_INT, v, raw)
        if 7 in pf:
            return Value(K_INT, pf[7][-1], raw)
        return Value(K_OTHER, None, raw)
    return Value(K_STRING, raw, raw) if raw else Value(K_OTHER, None, raw)


def _parse_element(buf: bytes, depth: int = 0) -> Element:
    if depth > 200:
        raise ProtoError("XML nesting too deep")
    f = fields(buf)
    el = Element(tag=_s(f, 3))
    for ab in f.get(4, []):
        af = fields(ab)
        raw = _s(af, 3)
        rid = _int(af, 5)
        if rid == 0:
            rid = None
        if 6 in af:
            val = decode_item(af[6][-1], raw)
        else:
            val = _text_value(raw)
        el.attrs.append(Attr(ns=_s(af, 1), name=_s(af, 2), res_id=rid, value=val))
    for cb in f.get(5, []):
        cf = fields(cb)
        if 1 in cf:
            el.children.append(_parse_element(cf[1][-1], depth + 1))
        elif 2 in cf:
            el.text += _s(cf, 2)
    return el


def _text_value(raw: str) -> Value:
    if raw in ("true", "false"):
        return Value(K_BOOL, raw == "true", raw)
    try:
        return Value(K_INT, int(raw, 0), raw)
    except ValueError:
        return Value(K_STRING, raw, raw)


def parse_xmlnode(buf: bytes) -> Element:
    f = fields(buf)
    if 1 not in f:
        raise ProtoError("XmlNode without element")
    return _parse_element(f[1][-1])


class ProtoResourceTable:
    """resources.pb: resolve a resource id to its values in every configuration."""

    def __init__(self, buf: bytes) -> None:
        self._entries: Dict[int, List[Value]] = {}
        top = fields(buf)
        for pkb in top.get(2, []):
            pf = fields(pkb)
            pkg_id = _int(fields(pf[1][-1]), 1, 0) if 1 in pf else 0x7F
            for tb in pf.get(3, []):
                tf = fields(tb)
                type_id = _int(fields(tf[1][-1]), 1, 0) if 1 in tf else 0
                for eb in tf.get(3, []):
                    ef = fields(eb)
                    entry_id = _int(fields(ef[1][-1]), 1, 0) if 1 in ef else 0
                    rid = ((pkg_id or 0) << 24) | ((type_id or 0) << 16) | (entry_id or 0)
                    vals: List[Value] = []
                    for cvb in ef.get(6, []):
                        cvf = fields(cvb)
                        if 2 not in cvf:
                            continue
                        vf = fields(cvf[2][-1])
                        if 4 in vf:  # Item
                            vals.append(decode_item(vf[4][-1]))
                    self._entries[rid] = vals

    def resolve(self, res_id: int) -> List[Value]:
        return list(self._entries.get(res_id, []))
