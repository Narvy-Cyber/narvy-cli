"""Load an IPA into bundles (app, extensions, frameworks) without extracting it."""
from __future__ import annotations

import plistlib
import posixpath
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..archive import Archive, ArchiveError
from .macho import MachOError, Slice, is_macho, parse_macho

APP_RE = re.compile(r"^Payload/([^/]+\.app)/$")


class IOSLoadError(Exception):
    pass


@dataclass
class Bundle:
    kind: str  # app | appex | framework | dylib
    path: str  # directory inside the IPA, ending with "/" (dylib: the file path)
    name: str
    info: Optional[dict]
    executable_path: Optional[str]
    slices: Optional[List[Slice]] = None
    load_error: str = ""
    own_manifests: List[str] = field(default_factory=list)  # PrivacyInfo.xcprivacy paths that cover this binary
    nested_manifests: List[str] = field(default_factory=list)  # resource-bundle manifests (static SDKs)

    @property
    def imports(self):
        out = set()
        for s in self.slices or []:
            out |= s.imports
        return out


@dataclass
class IPA:
    app_dir: str
    info: dict
    bundles: List[Bundle]
    manifests: Dict[str, Optional[dict]]  # path -> parsed plist (None if invalid)
    manifest_errors: Dict[str, str]
    names: List[str]

    @property
    def main(self) -> Bundle:
        return self.bundles[0]


def _plist(arc: Archive, path: str) -> dict:
    data = arc.read(path, limit=16 * 1024 * 1024)
    obj = plistlib.loads(data)
    if not isinstance(obj, dict):
        raise ValueError("top level is not a dictionary")
    return obj


def _app_dir(arc: Archive) -> str:
    candidates = set()
    for n in arc.names():
        m = re.match(r"^Payload/([^/]+\.app)/", n)
        if m:
            candidates.add(f"Payload/{m.group(1)}/")
    if len(candidates) != 1:
        raise IOSLoadError(f"expected exactly one Payload/*.app directory, found {len(candidates)}")
    return candidates.pop()


def load_ipa(arc: Archive, max_binary: int = 1024 * 1024 * 1024) -> IPA:
    app_dir = _app_dir(arc)
    names = arc.names()
    try:
        info = _plist(arc, app_dir + "Info.plist")
    except (KeyError, ArchiveError, Exception) as exc:  # noqa: BLE001
        raise IOSLoadError(f"cannot read {app_dir}Info.plist: {exc}") from exc

    # ---- discover bundles
    bundle_dirs: List[tuple] = [("app", app_dir)]
    seen = {app_dir}
    for n in names:
        if not n.startswith(app_dir):
            continue
        rel = n[len(app_dir):]
        for kind, pat in (("framework", r"^((?:[^/]+/)*?[^/]+\.framework)/"), ("appex", r"^((?:[^/]+/)*?[^/]+\.appex)/"),
                          ("app", r"^((?:[^/]+/)*?[^/]+\.app)/")):
            m = re.match(pat, rel)
            if m:
                d = app_dir + m.group(1) + "/"
                if d not in seen:
                    seen.add(d)
                    bundle_dirs.append((kind, d))
    # nested bundles discovered from deeper paths: make sure each is a real bundle (has Info.plist or binary)
    bundles: List[Bundle] = []
    for kind, d in bundle_dirs:
        try:
            binfo = info if d == app_dir else _plist(arc, d + "Info.plist")
        except Exception:  # noqa: BLE001
            binfo = None
        exe = None
        if binfo and isinstance(binfo.get("CFBundleExecutable"), str):
            exe = d + binfo["CFBundleExecutable"]
        elif kind == "framework":
            exe = d + posixpath.basename(d.rstrip("/"))[:-len(".framework")]
        if exe is not None and not arc.has(exe):
            exe = None
        name = posixpath.basename(d.rstrip("/"))
        bundles.append(Bundle(kind=kind if d != app_dir else "app", path=d, name=name, info=binfo, executable_path=exe))
    # loose dylibs in Frameworks/ (outside .framework bundles)
    for n in names:
        if n.startswith(app_dir) and n.endswith(".dylib") and ".framework/" not in n:
            bundles.append(Bundle(kind="dylib", path=n, name=posixpath.basename(n), info=None, executable_path=n))

    # ---- privacy manifests, assigned to the innermost enclosing code bundle
    manifest_paths = [n for n in names if n.startswith(app_dir) and posixpath.basename(n) == "PrivacyInfo.xcprivacy"]
    manifests: Dict[str, Optional[dict]] = {}
    errors: Dict[str, str] = {}
    for mp in manifest_paths:
        try:
            manifests[mp] = _plist(arc, mp)
        except Exception as exc:  # noqa: BLE001
            manifests[mp] = None
            errors[mp] = str(exc)[:200]
    code_bundles = [b for b in bundles if b.kind != "dylib"]
    for mp in manifest_paths:
        owner = max((b for b in code_bundles if mp.startswith(b.path)), key=lambda b: len(b.path), default=None)
        if owner is None:
            continue
        rel = mp[len(owner.path):]
        if rel == "PrivacyInfo.xcprivacy":
            owner.own_manifests.append(mp)
        else:
            # inside a resource bundle (e.g. Foo_Privacy.bundle/PrivacyInfo.xcprivacy): a statically
            # linked SDK's manifest, which covers code linked into the owner's executable
            owner.nested_manifests.append(mp)

    # ---- parse executables
    for b in bundles:
        if b.executable_path is None:
            b.load_error = "no executable found"
            continue
        try:
            head = arc.read_head(b.executable_path, 8)
            if not is_macho(head):
                b.load_error = "executable is not a Mach-O file"
                continue
            b.slices = parse_macho(arc.read(b.executable_path, limit=max_binary))
        except (MachOError, ArchiveError, Exception) as exc:  # noqa: BLE001
            b.load_error = f"cannot parse executable: {str(exc)[:200]}"
            b.slices = None
    return IPA(app_dir=app_dir, info=info, bundles=bundles, manifests=manifests, manifest_errors=errors, names=names)
