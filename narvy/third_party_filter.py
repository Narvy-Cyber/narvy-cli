"""Tell app code from third-party SDK code by package name."""
from __future__ import annotations

import os
import re
from typing import Optional

from .scope_config import ScopeConfig, segment_prefix_match

# jadx's manifest output path depends on the input container type.
_MANIFEST_RELATIVE_PATHS = (
    os.path.join("resources", "AndroidManifest.xml"),           # plain .apk
    os.path.join("resources", "base", "manifest", "AndroidManifest.xml"),  # .aab
)


def _find_decompiled_manifest_path(decompiled_root: str) -> Optional[str]:
    for rel in _MANIFEST_RELATIVE_PATHS:
        candidate = os.path.join(decompiled_root, rel)
        if os.path.isfile(candidate):
            return candidate
    return None


def parse_manifest_package_attr(manifest_content: str) -> Optional[str]:
    m = re.search(r'package\s*=\s*"([a-zA-Z0-9_.]+)"', manifest_content)
    return m.group(1) if m else None


def detect_own_package(decompiled_root: str) -> str | None:
    manifest_path = _find_decompiled_manifest_path(decompiled_root)
    if not manifest_path:
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(4096)
    except OSError:
        return None
    return parse_manifest_package_attr(head)


_COMPONENT_TAG_RE = re.compile(
    r'<(?:activity|service|receiver|provider|application)\b[^>]*?'
    r'android:name\s*=\s*"([^"]+)"',
    re.DOTALL,
)

# Too generic to trust as a one-segment namespace root, so 2 segments are used.
_GENERIC_TLD_SEGMENTS = {"com", "org", "io", "net", "edu", "gov", "co"}


def _root_is_known_third_party(candidate: str) -> bool:
    cand_path = candidate.replace(".", "/") + "/"
    for p in THIRD_PARTY_PREFIXES:
        p_path = p.replace(".", "/")
        if cand_path.startswith(p_path) or p_path.startswith(cand_path):
            return True
    return False


def extract_component_package_roots(manifest_content: str, root_pkg: Optional[str] = None) -> set[str]:
    roots: set[str] = set()
    for m in _COMPONENT_TAG_RE.finditer(manifest_content):
        name = m.group(1)
        if name.startswith("."):
            if not root_pkg:
                continue
            name = root_pkg + name
        segments = [s for s in name.rsplit(".", 1)[0].split(".") if s]
        if not segments:
            continue
        if segments[0].lower() in _GENERIC_TLD_SEGMENTS and len(segments) >= 2:
            candidate = ".".join(segments[:2])
        else:
            candidate = segments[0]
        if _root_is_known_third_party(candidate):
            continue
        roots.add(candidate)
    return roots


def get_own_package_roots(decompiled_root: str) -> set[str]:
    """The manifest's applicationId plus the root of every declared component."""
    roots: set[str] = set()
    root_pkg = detect_own_package(decompiled_root)
    if root_pkg:
        roots.add(root_pkg)

    manifest_path = _find_decompiled_manifest_path(decompiled_root)
    if not manifest_path:
        return roots
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return roots

    roots |= extract_component_package_roots(content, root_pkg)
    return roots


# Anchors for a file's package path: jadx uses 'sources/', Gradle 'src/<variant>/java|kotlin/'.
JADX_SOURCE_MARKERS = (r"sources/",)
GRADLE_SOURCE_MARKERS = (r"src/[^/]+/java/", r"src/[^/]+/kotlin/")


def _rightmost_marker_match(fp: str, markers) -> Optional["re.Match"]:
    best = None
    for marker in markers:
        for m in re.finditer(marker, fp):
            if best is None or m.start() > best.start():
                best = m
    return best


def is_own_package_path(file_path: str, own_roots, markers=JADX_SOURCE_MARKERS) -> bool:
    """True if this source file lives under any of own_roots (a string or set)."""
    if isinstance(own_roots, str):
        own_roots = {own_roots}
    fp = file_path.replace("\\", "/").lower()
    for root in own_roots:
        root_path = re.escape(root.replace(".", "/").lower())
        for marker in markers:
            if re.search(marker + root_path + "/", fp):
                return True
    return False


# Dotted form, matched against the path with '/' as the separator.
THIRD_PARTY_PREFIXES = (
    "org.bouncycastle.", "org.spongycastle.", "com.google.crypto.tink.", "org.conscrypt.",
    "org.acra.", "io.sentry.", "com.bugsnag.", "com.crashlytics.", "io.fabric.",
    "com.microsoft.appcenter.", "com.microsoft.azure.",
    "com.google.android.", "com.google.firebase.", "com.google.gson.",
    "com.google.protobuf.", "com.google.common.", "com.google.api.", "com.google.auth.",
    "com.google.maps.",
    # An own applicationId under com.android is added by the manifest read, not this denylist.
    "com.android.",
    "com.huawei.",
    "androidx.", "android.support.", "android.arch.",
    "kotlin.", "kotlinx.",
    "org.jetbrains.",
    "okhttp3.", "okio.", "retrofit2.", "com.squareup.",
    "io.reactivex.", "rx.",
    "com.facebook.",
    "dagger.", "hilt.", "javax.inject.", "butterknife.",
    "timber.log.", "org.slf4j.", "ch.qos.logback.", "org.apache.log4j.",
    "com.bumptech.glide.", "com.airbnb.lottie.",
    "org.apache.",
    "com.amazonaws.", "com.newrelic.", "com.appsflyer.", "com.adjust.",
    "com.segment.", "com.mixpanel.", "com.amplitude.", "io.netty.", "io.grpc.",
    "com.fasterxml.", "org.json.", "io.flutter.", "com.flurry.",
    "io.ktor.", "ktor.",
    "com.liulishuo.",
)

_THIRD_PARTY_SLASHED = tuple(p.replace(".", "/") for p in THIRD_PARTY_PREFIXES)


def is_third_party_path(file_path: str, markers=JADX_SOURCE_MARKERS) -> bool:
    """True if this file lives under a known third-party SDK namespace (marker stripped first so a 'kotlin' source-root doesn't collide with the 'kotlin.' prefix)."""
    fp = file_path.replace("\\", "/").lower()
    for marker in markers:
        m = re.search(marker, fp)
        if m:
            fp = fp[m.end():]
            break
    for prefix in _THIRD_PARTY_SLASHED:
        if f"/{prefix}" in fp or fp.startswith(prefix):
            return True
    return False


def _file_package_path(file_path: str, markers=JADX_SOURCE_MARKERS) -> Optional[str]:
    """The file's full dotted package path, or None if it matches no marker."""
    fp = file_path.replace("\\", "/").lower()
    m = _rightmost_marker_match(fp, markers)
    if m is None:
        return None
    segments = [s for s in fp[m.end():].split("/") if s][:-1]
    if not segments:
        return None
    return ".".join(segments)


def check_android_override(file_path: str, config: Optional[ScopeConfig], markers=JADX_SOURCE_MARKERS) -> Optional[str]:
    """Return 'own', 'vendor', or None for this file, per .narvy-scope.yml."""
    if not config:
        return None
    pkg_path = _file_package_path(file_path, markers=markers)
    if pkg_path is None:
        return None
    if any(segment_prefix_match(e, pkg_path) for e in config.own):
        return "own"
    if any(segment_prefix_match(e, pkg_path) for e in config.vendor):
        return "vendor"
    return None


def resolve_file_scope(file_path: str, own_roots, override_config: Optional[ScopeConfig] = None,
                        markers=JADX_SOURCE_MARKERS) -> bool:
    """True to scan as first-party, False to skip as third-party. A .narvy-scope.yml entry wins over own_roots and the denylist; pass GRADLE_SOURCE_MARKERS for a Gradle checkout."""
    override = check_android_override(file_path, override_config, markers=markers)
    if override == "own":
        return True
    if override == "vendor":
        return False
    if own_roots:
        return file_path.endswith('.xml') or is_own_package_path(file_path, own_roots, markers=markers)
    return not is_third_party_path(file_path, markers=markers)
