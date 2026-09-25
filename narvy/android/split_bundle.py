"""Split-APK bundles (.apkm/.xapk/.apks): pull out the app module, ABI split and dex feature modules."""

import json
import logging
import os
import re
import shutil
import zipfile

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SPLIT_BUNDLE_EXTS = (".apkm", ".xapk", ".apks")

# A bundle is untrusted input: never trust a member name or a declared size.
_MAX_TOTAL_UNCOMPRESSED = 6 * 1024 * 1024 * 1024
_MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 200
_PEEK_MAX_BYTES = 64 * 1024 * 1024
_MAX_FEATURE_INPUT_BYTES = 128 * 1024 * 1024

# Duplicated (not imported) so this module stays importable without lief.
_ABI_PREFERENCE = ("arm64_v8a", "armeabi_v7a", "x86_64", "x86")

# config.<token>.apk, split_config.<token>.apk, <Feature>.config.<token>.apk.
_CONFIG_SPLIT_RE = re.compile(
    r"^(?:(?P<owner>[A-Za-z0-9_\-]+)\.)?(?:split_)?config[.\-_](?P<token>[A-Za-z0-9_\-]+)\.apk$",
    re.IGNORECASE,
)

_ABI_TOKENS = {"arm64_v8a", "armeabi_v7a", "armeabi", "x86", "x86_64", "mips", "mips64",
               "arm64-v8a", "armeabi-v7a"}
_DENSITY_TOKENS = {"ldpi", "mdpi", "hdpi", "tvdpi", "xhdpi", "xxhdpi", "xxxhdpi",
                   "nodpi", "anydpi"}

_EXPLICIT_BASE_NAMES = ("base.apk", "base-master.apk", "universal.apk")

# bundletool emits one master split per device variant, carrying the same code.
_MASTER_VARIANT_RE = re.compile(r"^(?:base-)?master(?:_\d+)?\.apk$", re.IGNORECASE)


class SplitBundleError(Exception):
    """Raised when a bundle cannot be turned into something scannable."""


@dataclass
class BundleMember:
    """One inner .apk inside the bundle."""
    name: str
    size: int
    kind: str
    token: Optional[str] = None
    owner: Optional[str] = None
    has_dex: Optional[bool] = None
    has_so: Optional[bool] = None


@dataclass
class ExtractedBundle:
    """What extract_for_scan() produced, and what it left out."""
    bundle_path: str
    bundle_format: str
    base_apk_path: str
    base_member: str
    native_apk_path: Optional[str] = None
    native_abi: Optional[str] = None
    native_source: str = "none"
    package_name: Optional[str] = None
    members: List[BundleMember] = field(default_factory=list)
    dex_bearing_splits: List[str] = field(default_factory=list)
    feature_apk_paths: List[str] = field(default_factory=list)
    skipped_feature_splits: List[str] = field(default_factory=list)

    @property
    def split_count(self) -> int:
        return sum(1 for m in self.members if m.kind != "base")


def is_split_bundle(path: str) -> bool:
    """Extension-only check; real validation happens in extract_for_scan."""
    return os.path.splitext(path)[1].lower() in SPLIT_BUNDLE_EXTS


def bundle_format(path: str) -> Optional[str]:
    ext = os.path.splitext(path)[1].lower()
    return ext.lstrip(".") if ext in SPLIT_BUNDLE_EXTS else None


def _classify_by_name(member: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Name-only classification of an inner .apk, as (kind, token, owner)."""
    base = os.path.basename(member)
    lowered = base.lower()

    if lowered in _EXPLICIT_BASE_NAMES or _MASTER_VARIANT_RE.match(lowered):
        return "base", None, None

    def _kind_for(token: str) -> str:
        if token in _ABI_TOKENS:
            return "abi"
        if token in _DENSITY_TOKENS:
            return "density"
        return "language"

    # Matched against original basename: the owner group is shown to the user.
    m = _CONFIG_SPLIT_RE.match(base)
    if m:
        token = m.group("token").lower()
        owner = m.group("owner")
        return _kind_for(token), token, owner

    m2 = re.match(r"^base-([A-Za-z0-9_\-]+)\.apk$", lowered)
    if m2:
        token = m2.group(1).lower()
        return _kind_for(token), token, None

    return "unknown", None, None


def _read_packer_metadata(zf: zipfile.ZipFile, names: List[str]) -> Tuple[Optional[str], Optional[str]]:
    if "manifest.json" in names:
        try:
            data = json.loads(zf.read("manifest.json").decode("utf-8", "replace"))
            return data.get("package_name") or None, data.get("name") or None
        except Exception as exc:
            logger.debug(f"[split-bundle] unreadable manifest.json: {exc}")
    if "info.json" in names:
        try:
            data = json.loads(zf.read("info.json").decode("utf-8", "replace"))
            return data.get("pname") or None, data.get("app_name") or None
        except Exception as exc:
            logger.debug(f"[split-bundle] unreadable info.json: {exc}")
    return None, None


def _validate_zip_safety(zf: zipfile.ZipFile, bundle_path: str) -> None:
    """Zip-bomb / path-traversal guard. Raises SplitBundleError."""
    total_uncompressed = 0
    total_compressed = 0
    for info in zf.infolist():
        name = info.filename
        if name.startswith("/") or name.startswith("\\") or ".." in name.replace("\\", "/").split("/"):
            raise SplitBundleError(
                f"Refusing to open {os.path.basename(bundle_path)}: it contains a member with a "
                f"path-traversal name ({name!r}). This is not a normal split-APK bundle."
            )
        if info.file_size > _MAX_MEMBER_BYTES:
            raise SplitBundleError(
                f"Refusing to open {os.path.basename(bundle_path)}: member {name!r} declares "
                f"{info.file_size / (1024 ** 3):.1f} GB uncompressed, over the "
                f"{_MAX_MEMBER_BYTES / (1024 ** 3):.0f} GB per-file ceiling."
            )
        total_uncompressed += info.file_size
        total_compressed += info.compress_size

    if total_uncompressed > _MAX_TOTAL_UNCOMPRESSED:
        raise SplitBundleError(
            f"Refusing to open {os.path.basename(bundle_path)}: {total_uncompressed / (1024 ** 3):.1f} GB "
            f"uncompressed, over the {_MAX_TOTAL_UNCOMPRESSED / (1024 ** 3):.0f} GB ceiling."
        )
    if total_compressed > 0 and (total_uncompressed / total_compressed) > _MAX_COMPRESSION_RATIO:
        raise SplitBundleError(
            f"Refusing to open {os.path.basename(bundle_path)}: compression ratio "
            f"{total_uncompressed / total_compressed:.0f}:1 looks like a zip bomb "
            f"(a real split bundle is ~2:1 - its members are already-compressed APKs)."
        )


def _peek_member(zf: zipfile.ZipFile, member: str) -> Tuple[Optional[bool], Optional[bool]]:
    """(has_dex, has_so) for a small inner APK, or (None, None) if not inspected."""
    try:
        info = zf.getinfo(member)
    except KeyError:
        return None, None
    if info.file_size > _PEEK_MAX_BYTES:
        return None, None
    try:
        with zf.open(member) as fh:
            inner = zipfile.ZipFile(fh)
            names = inner.namelist()
        has_dex = any(n.endswith(".dex") for n in names)
        has_so = any(n.startswith("lib/") and n.endswith(".so") for n in names)
        return has_dex, has_so
    except Exception as exc:
        logger.debug(f"[split-bundle] could not peek into {member}: {exc}")
        return None, None


def _validate_base_apk(path: str) -> Optional[str]:
    """None if the picked member really is an app module, else a short reason."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return "not a valid ZIP/APK"
    except OSError as exc:
        return f"unreadable ({exc})"
    if not any(n.endswith("AndroidManifest.xml") for n in names):
        return "no AndroidManifest.xml"
    if not any(n.endswith(".dex") for n in names):
        return "no classes.dex (looks like a config split, not the app module)"
    return None


def _base_candidates(members: List[BundleMember], package_name: Optional[str]) -> List[BundleMember]:
    """Candidate app modules, most explicit signal first (caller content-verifies)."""
    ordered: List[BundleMember] = []
    seen = set()

    def _add(m: BundleMember):
        if m.name not in seen:
            seen.add(m.name)
            ordered.append(m)

    for m in members:
        if m.kind == "base" and "/" not in m.name:
            _add(m)
    if package_name:
        want = f"{package_name.lower()}.apk"
        for m in members:
            if m.name.lower() == want:
                _add(m)
    # Sorted so the pick doesn't depend on zip member order.
    for m in sorted((m for m in members if m.kind == "base"), key=lambda m: m.name):
        _add(m)
    for m in sorted((m for m in members if m.kind in ("unknown", "feature")),
                    key=lambda m: m.size, reverse=True):
        _add(m)
    return ordered


def _pick_abi_member(members: List[BundleMember]) -> Optional[BundleMember]:
    """The app module's own ABI split to hand to native_hardening."""
    # `owner is None` filters out feature-module ABI splits sharing the token.
    by_token: Dict[str, BundleMember] = {}
    for m in members:
        if m.kind == "abi" and m.token and m.owner is None:
            by_token.setdefault(m.token.replace("-", "_"), m)
    for pref in _ABI_PREFERENCE:
        if pref in by_token:
            return by_token[pref]
    if by_token:
        return by_token[sorted(by_token)[0]]
    return None


def _extract_member(zf: zipfile.ZipFile, member: str, dest_dir: str, as_name: str) -> str:
    dest = os.path.join(dest_dir, as_name)
    with zf.open(member) as src, open(dest, "wb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
    return dest


def extract_for_scan(bundle_path: str, dest_dir: str) -> ExtractedBundle:
    """Extract the files the Android scan path needs from a split bundle."""
    fmt = bundle_format(bundle_path)
    if fmt is None:
        raise SplitBundleError(f"{bundle_path} is not a .apkm/.xapk/.apks bundle.")

    os.makedirs(dest_dir, exist_ok=True)

    try:
        zf = zipfile.ZipFile(bundle_path, "r")
    except zipfile.BadZipFile:
        raise SplitBundleError(
            f"{os.path.basename(bundle_path)} is not a valid ZIP archive. A .{fmt} bundle is a ZIP "
            f"containing base.apk plus its config splits - this file is either corrupt, truncated, "
            f"or not really a {fmt.upper()} bundle."
        )
    except OSError as exc:
        raise SplitBundleError(f"Could not read {bundle_path}: {exc}")

    with zf:
        _validate_zip_safety(zf, bundle_path)
        names = zf.namelist()
        package_name, _app_title = _read_packer_metadata(zf, names)

        apk_names = [n for n in names if n.lower().endswith(".apk")]
        if not apk_names:
            raise SplitBundleError(
                f"{os.path.basename(bundle_path)} contains no .apk files at all "
                f"({len(names)} other entries). A .{fmt} bundle must contain at least a base APK - "
                f"this file isn't one."
            )

        members: List[BundleMember] = []
        for name in apk_names:
            kind, token, owner = _classify_by_name(name)
            member = BundleMember(name=name, size=zf.getinfo(name).file_size,
                                  kind=kind, token=token, owner=owner)
            if kind == "unknown":
                member.has_dex, member.has_so = _peek_member(zf, name)
                if member.has_dex is not None:
                    member.kind = "feature"
            members.append(member)

        base_path = None
        base_member = None
        rejected: List[str] = []
        for cand in _base_candidates(members, package_name):
            candidate_path = _extract_member(zf, cand.name, dest_dir, "base.apk")
            reason = _validate_base_apk(candidate_path)
            if reason is None:
                base_path, base_member = candidate_path, cand
                break
            rejected.append(f"{cand.name} ({reason})")
            try:
                os.remove(candidate_path)
            except OSError:
                pass

        if base_path is None:
            detail = "; ".join(rejected) if rejected else "no candidate members"
            raise SplitBundleError(
                f"Could not find the app module (base.apk) inside "
                f"{os.path.basename(bundle_path)}. Tried: {detail}. Every member either lacks an "
                f"AndroidManifest.xml or lacks a classes.dex, so none of them is the real app - "
                f"nothing was scanned rather than scanning a config split and reporting a "
                f"misleading 'no issues found'."
            )
        base_member.kind = "base"
        # Other app-module-looking members are device variants: don't scan twice.
        for m in members:
            if m.kind == "base" and m.name != base_member.name:
                m.kind = "variant"

        native_path: Optional[str] = None
        native_abi: Optional[str] = None
        native_source = "none"
        try:
            with zipfile.ZipFile(base_path, "r") as bzf:
                base_has_so = any(n.startswith("lib/") and n.endswith(".so") for n in bzf.namelist())
        except Exception:
            base_has_so = False

        if base_has_so:
            # Pulling in an ABI split too would double-report the same libs.
            native_source = "base"
        else:
            abi_member = _pick_abi_member(members)
            if abi_member is not None:
                native_path = _extract_member(
                    zf, abi_member.name, dest_dir, os.path.basename(abi_member.name)
                )
                native_abi = (abi_member.token or "").replace("_", "-")
                native_source = "abi-split"

        # Dex-bearing feature modules join the app module's jadx run (first input's manifest wins).
        dex_bearing: List[str] = []
        feature_paths: List[str] = []
        skipped_features: List[str] = []
        budget = _MAX_FEATURE_INPUT_BYTES
        for m in sorted((m for m in members
                         if m.name != base_member.name and m.has_dex is True),
                        key=lambda m: m.size):
            dex_bearing.append(m.name)
            if m.size > budget:
                skipped_features.append(m.name)
                continue
            budget -= m.size
            # Prefixed so a feature named base.apk can't overwrite dest_dir files.
            safe_name = "feature_" + os.path.basename(m.name)
            feature_paths.append(_extract_member(zf, m.name, dest_dir, safe_name))

    return ExtractedBundle(
        bundle_path=bundle_path,
        bundle_format=fmt,
        base_apk_path=base_path,
        base_member=base_member.name,
        native_apk_path=native_path,
        native_abi=native_abi,
        native_source=native_source,
        package_name=package_name,
        members=members,
        dex_bearing_splits=dex_bearing,
        feature_apk_paths=feature_paths,
        skipped_feature_splits=skipped_features,
    )


def summary_lines(bundle: ExtractedBundle) -> List[Tuple[str, str]]:
    """User-facing scope disclosure, as (style, text) pairs for rich."""
    lines: List[Tuple[str, str]] = []
    kinds: Dict[str, int] = {}
    for m in bundle.members:
        if m.kind != "base":
            kinds[m.kind] = kinds.get(m.kind, 0) + 1

    pieces = []
    for kind, label in (("abi", "architecture"), ("density", "screen-density"),
                        ("language", "language"), ("feature", "feature-module"),
                        ("variant", "device-variant"), ("unknown", "unrecognised")):
        if kinds.get(kind):
            pieces.append(f"{kinds[kind]} {label}")
    breakdown = ", ".join(pieces) if pieces else "no"

    pkg = f" [{bundle.package_name}]" if bundle.package_name else ""
    lines.append((
        "cyan",
        f"Detected .{bundle.bundle_format} split-APK bundle{pkg}: "
        f"{bundle.split_count} split(s) alongside the app module ({breakdown}). "
        f"Scanning '{bundle.base_member}' - it carries the full manifest, all "
        f"Dalvik code and all dependency metadata."
    ))

    if bundle.native_source == "abi-split":
        lines.append((
            "cyan",
            f"Native libraries live in the '{bundle.native_abi}' split (none in the app module) - "
            f"analysing that split for NX/PIE/RELRO/canary/RPATH. Other architecture splits are "
            f"not separately analysed."
        ))
    elif bundle.native_source == "base":
        lines.append(("dim", "Native libraries ship inside the app module itself - analysed as usual."))
    else:
        abi_present = any(m.kind == "abi" for m in bundle.members)
        if abi_present:
            lines.append((
                "yellow",
                "This bundle has architecture splits but no usable one was extracted - "
                "native-library hardening was NOT checked."
            ))

    if kinds.get("variant"):
        lines.append((
            "dim",
            f"{kinds['variant']} additional device-variant cop{'y' if kinds['variant'] == 1 else 'ies'} "
            f"of the same app module (bundletool emits one master split per device variant) - "
            f"same code, scanned once."
        ))

    skipped = [k for k in ("density", "language") if kinds.get(k)]
    if skipped:
        lines.append((
            "dim",
            f"{'/'.join(skipped)} splits contain only resources (resources.arsc) - "
            f"not separately analysed, they carry no code."
        ))

    if bundle.feature_apk_paths:
        scanned = [n for n in bundle.dex_bearing_splits if n not in bundle.skipped_feature_splits]
        lines.append((
            "cyan",
            f"{len(scanned)} dynamic feature module(s) carry their own Dalvik code and are "
            f"decompiled together with the app module: " + ", ".join(scanned) + "."
        ))

    if bundle.skipped_feature_splits:
        lines.append((
            "bold yellow",
            "INCOMPLETE SCAN: these dynamic feature module(s) carry their own Dalvik code but were "
            "too large to add to this run and were NOT analysed: "
            + ", ".join(bundle.skipped_feature_splits)
            + ". Treat their code as UNSCANNED, not as clean."
        ))

    feature_configs = [m.name for m in bundle.members if m.owner]
    if feature_configs:
        lines.append((
            "dim",
            f"{len(feature_configs)} config split(s) belong to feature modules rather than the app "
            f"module (e.g. {feature_configs[0]}) - not separately analysed."
        ))

    unclassified = [m.name for m in bundle.members if m.kind == "unknown"]
    if unclassified:
        lines.append((
            "yellow",
            "Could not determine what these bundle member(s) are, and they were NOT analysed: "
            + ", ".join(unclassified) + "."
        ))

    return lines
