"""Entry point: detect the container type and run the matching checks.

The analysis is offline and read-only: the input file is opened for reading,
every archive entry is read into memory, nothing is written anywhere.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
from typing import Optional

from . import __version__
from .archive import Archive, ArchiveError
from .model import Report


class InputError(Exception):
    pass


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect(arc: Archive) -> str:
    names = arc.names()
    if arc.has("AndroidManifest.xml"):
        return "apk"
    if arc.has("base/manifest/AndroidManifest.xml"):
        return "aab"
    if any(n.startswith("Payload/") and ".app/" in n for n in names):
        return "ipa"
    if any(n.lower().endswith(".apk") for n in names):
        return "apks"
    raise InputError("unrecognised file: not an APK, AAB, split-APK set (.apks/.xapk/.apkm) or IPA")


def analyze(path: str, as_of: Optional[dt.date] = None) -> Report:
    as_of = as_of or dt.date.today()
    if not os.path.isfile(path):
        raise InputError(f"no such file: {path}")
    try:
        arc = Archive(path)
    except ArchiveError as exc:
        raise InputError(str(exc)) from exc
    try:
        kind = detect(arc)
        sha = _sha256(path)
        name = os.path.basename(path)
        if kind == "ipa":
            from .ios.checks import app_info, run_ios_checks
            from .ios.loader import IOSLoadError, load_ipa
            try:
                ipa = load_ipa(arc)
            except IOSLoadError as exc:
                raise InputError(str(exc)) from exc
            return Report(__version__, name, sha, "ios", "ipa", as_of.isoformat(), app_info(ipa),
                          run_ios_checks(ipa, as_of))
        from .android.checks import app_info, run_android_checks
        from .android.loader import AndroidLoadError, load_android
        try:
            app = load_android(arc)
        except AndroidLoadError as exc:
            raise InputError(str(exc)) from exc
        return Report(__version__, name, sha, "android", app.container, as_of.isoformat(), app_info(app),
                      run_android_checks(app, as_of), notes=list(app.notes))
    finally:
        arc.close()
