"""Load an Android container (APK, AAB, or a split-APK set such as .apks/.xapk/.apkm)
into a normalized in-memory view used by the checks."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..archive import Archive, ArchiveError
from .arsc import ResourceTable
from .axml import AXMLError, parse_axml
from .protoxml import ProtoError, ProtoResourceTable, parse_xmlnode
from .xmlmodel import Element, Value, K_REF

ABI_RE = re.compile(r"(?:^|/)lib/([^/]+)/([^/]+\.so)$")


class AndroidLoadError(Exception):
    pass


@dataclass
class NativeLib:
    container_label: str  # e.g. "base.apk" or "" for the main file
    path: str  # path inside that container
    abi: str
    stored: bool  # uncompressed in the zip
    data_offset: Optional[int]  # absolute data offset inside its container
    read_head: Callable[[int], bytes]
    size: int

    @property
    def display(self) -> str:
        return f"{self.container_label}!{self.path}" if self.container_label else self.path


@dataclass
class AndroidApp:
    container: str  # apk | aab | apks
    manifest: Element
    manifest_path: str
    resolve: Callable[[int], List[Value]]
    read_xml: Callable[[str], Element]
    native_libs: List[NativeLib] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    # for apk/apks: whether zip alignment of native libs is meaningful
    zip_alignment_relevant: bool = True

    @property
    def package(self) -> Optional[str]:
        v = self.manifest.attr("package", android_only=False)
        return str(v.data) if v is not None else None


def _apk_view(arc: Archive, label: str):
    try:
        manifest = parse_axml(arc.read("AndroidManifest.xml"))
    except (AXMLError, ArchiveError, KeyError) as exc:
        raise AndroidLoadError(f"{label or 'APK'}: cannot parse AndroidManifest.xml: {exc}") from exc
    table = None
    if arc.has("resources.arsc"):
        try:
            table = ResourceTable(arc.read("resources.arsc"))
        except (AXMLError, ArchiveError, Exception):  # noqa: BLE001 - any parse failure = unresolvable
            table = None

    def resolve(rid: int) -> List[Value]:
        if table is None:
            return []
        try:
            return table.resolve(rid)
        except Exception:  # noqa: BLE001
            return []

    def read_xml(path: str) -> Element:
        return parse_axml(arc.read(path))

    libs = []
    for name in arc.names():
        m = ABI_RE.search(name)
        if not m or not name.startswith("lib/"):
            continue
        info = arc.info(name)
        libs.append(NativeLib(
            container_label=label, path=name, abi=m.group(1),
            stored=info.compress_type == 0, data_offset=arc.data_offset(name),
            read_head=(lambda n, _a=arc, _p=name: _a.read_head(_p, n)), size=info.file_size))
    return manifest, resolve, read_xml, libs


def load_android(arc: Archive) -> AndroidApp:
    names = arc.names()
    if arc.has("AndroidManifest.xml"):
        manifest, resolve, read_xml, libs = _apk_view(arc, "")
        return AndroidApp("apk", manifest, "AndroidManifest.xml", resolve, read_xml, libs)

    if arc.has("base/manifest/AndroidManifest.xml"):
        try:
            manifest = parse_xmlnode(arc.read("base/manifest/AndroidManifest.xml"))
        except (ProtoError, ArchiveError) as exc:
            raise AndroidLoadError(f"cannot parse base/manifest/AndroidManifest.xml: {exc}") from exc
        table = None
        if arc.has("base/resources.pb"):
            try:
                table = ProtoResourceTable(arc.read("base/resources.pb"))
            except Exception:  # noqa: BLE001
                table = None

        def resolve(rid: int) -> List[Value]:
            return table.resolve(rid) if table is not None else []

        def read_xml(path: str) -> Element:
            # resource paths in resources.pb are module-relative ("res/xml/x.xml")
            full = path if path.startswith("base/") else "base/" + path
            return parse_xmlnode(arc.read(full))

        libs = []
        for name in names:
            m = ABI_RE.search(name)
            if not m:
                continue
            parts = name.split("/")
            if len(parts) != 4 or parts[1] != "lib":
                continue
            info = arc.info(name)
            libs.append(NativeLib("", name, m.group(1), info.compress_type == 0, None,
                                  (lambda n, _p=name: arc.read_head(_p, n)), info.file_size))
        app = AndroidApp("aab", manifest, "base/manifest/AndroidManifest.xml", resolve, read_xml, libs)
        # Google Play builds the APKs from the bundle and handles their zip alignment.
        app.zip_alignment_relevant = False
        return app

    apk_names = [n for n in names if n.lower().endswith(".apk") and "/" not in n.strip("/")]
    bundletool_splits = [n for n in names if n.startswith("splits/") and n.lower().endswith(".apk")]
    if bundletool_splits:  # bundletool .apks: use the split set, ignore standalones/
        apk_names = bundletool_splits
    if apk_names:
        base = None
        libs: List[NativeLib] = []
        notes: List[str] = []
        for n in sorted(apk_names):
            try:
                inner = Archive.from_bytes(arc.read(n), label=n)
            except ArchiveError as exc:
                raise AndroidLoadError(f"{n}: {exc}") from exc
            if not inner.has("AndroidManifest.xml"):
                continue
            manifest, resolve, read_xml, inner_libs = _apk_view(inner, n)
            libs.extend(inner_libs)
            split = manifest.attr("split", android_only=False)
            if split is None and base is None:
                base = (n, manifest, resolve, read_xml)
        if base is None:
            raise AndroidLoadError("split APK set without a base APK")
        notes.append("Split APK set: only the splits present in this file were inspected "
                     "(a device-specific set may not contain every ABI).")
        app = AndroidApp("apks", base[1], f"{base[0]}!AndroidManifest.xml", base[2], base[3], libs, notes)
        return app

    raise AndroidLoadError("no AndroidManifest.xml, base/manifest/AndroidManifest.xml or embedded APKs found")
