"""Format-neutral XML element model used for both binary AXML (APK) and
protobuf XML (AAB). Attribute identity is the framework resource id when the
compiler kept it (robust against stripped attribute names), else the name.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Framework attribute resource ids (android.R.attr), verified against
# `aapt dump xmltree` output on real APKs.
ATTR_IDS = {
    "name": 0x01010003,
    "permission": 0x01010006,
    "enabled": 0x0101000E,
    "debuggable": 0x0101000F,
    "exported": 0x01010010,
    "minSdkVersion": 0x0101020C,
    "required": 0x0101028E,
    "targetSdkVersion": 0x01010270,
    "maxSdkVersion": 0x01010271,
    "extractNativeLibs": 0x010104EA,
    "usesCleartextTraffic": 0x010104EC,
    "networkSecurityConfig": 0x01010527,
    "foregroundServiceType": 0x01010599,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    # network security config attributes
    "cleartextTrafficPermitted": None,  # NSC attrs are not framework attrs
    "includeSubdomains": None,
}
ID_TO_NAME = {v: k for k, v in ATTR_IDS.items() if v is not None}

# Value kinds (normalized)
K_STRING = "string"
K_BOOL = "bool"
K_INT = "int"
K_REF = "ref"
K_OTHER = "other"


@dataclass
class Value:
    kind: str
    data: object  # str for string, bool, int, int resource id for ref
    raw: str = ""  # textual form when available

    def as_text(self) -> str:
        if self.kind == K_REF:
            return f"@0x{int(self.data):08x}"
        if self.kind == K_BOOL:
            return "true" if self.data else "false"
        return str(self.data)


@dataclass
class Attr:
    ns: str
    name: str
    res_id: Optional[int]
    value: Value

    @property
    def key(self) -> str:
        if self.res_id is not None and self.res_id in ID_TO_NAME:
            return ID_TO_NAME[self.res_id]
        return self.name


@dataclass
class Element:
    tag: str
    attrs: List[Attr] = field(default_factory=list)
    children: List["Element"] = field(default_factory=list)
    line: int = 0
    text: str = ""

    def attr(self, key: str, android_only: bool = True) -> Optional[Value]:
        """Look an attribute up by android attribute name.

        Framework attributes are matched by resource id only, exactly like the
        Android package parser (it reads them through R.styleable, i.e. by id,
        and ignores an attribute whose name matches but whose id does not).
        Non-framework attributes (network security config) match by name.
        """
        rid = ATTR_IDS.get(key)
        if rid is not None:
            for a in self.attrs:
                if a.res_id == rid:
                    return a.value
            return None
        for a in self.attrs:
            if a.name == key and (not android_only or a.ns in ("", ANDROID_NS)):
                return a.value
        return None

    def iter(self, tag: Optional[str] = None):
        if tag is None or self.tag == tag:
            yield self
        for c in self.children:
            yield from c.iter(tag)

    def find_children(self, tag: str) -> List["Element"]:
        return [c for c in self.children if c.tag == tag]
