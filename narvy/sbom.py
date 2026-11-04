"""CycloneDX 1.6 SBOM from the dependencies the SCA pass already reads, with optional Ed25519 signing.

Scope (stated in the SBOM itself):
  * Source directory: npm, PyPI, Packagist, Go, RubyGems, crates.io, Maven/Gradle,
    NuGet manifests and lockfiles, plus CocoaPods (Podfile.lock) and SwiftPM
    (Package.resolved).
  * APK/AAB: Maven coordinates the binary still carries (pom.properties,
    *.version files, Gradle metadata, dex string constants).
  * IPA: embedded third-party frameworks with a version in their Info.plist.
  * No network: the SBOM is built offline. Vulnerabilities are not embedded;
    `narvy scan` does the OSV lookup.
  * Licenses only where recorded locally (package-lock.json v2/v3, installed node_modules,
    composer.lock). Every other component has no license field.

Signing follows JSF (JSON Signature Format), the scheme CycloneDX documents:
the `signature` object sits at the document root, the signed bytes are the
canonical JSON (RFC 8785 for this ASCII-keyed, float-free document) of the
whole document with `signature.value` left out. The embedded public key proves
the file was not changed since signing; it does not prove who signed it.
Compare the key with one you trust (`narvy verify-sbom --public-key`).
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from . import __version__

SPEC_VERSION = "1.6"
SIGN_ALGORITHM = "Ed25519"
SIGN_EXTRA_HINT = "pip install 'narvy-cli[sign]'"


class SigningUnavailable(RuntimeError):
    """The optional `cryptography` package is missing."""


# --------------------------------------------------------------------------- purl

_PURL_TYPE = {
    "npm": "npm",
    "PyPI": "pypi",
    "Packagist": "composer",
    "Go": "golang",
    "RubyGems": "gem",
    "crates.io": "cargo",
    "Maven": "maven",
    "NuGet": "nuget",
    "CocoaPods": "cocoapods",
    "SwiftPM": "swift",
}


def _q(part: str) -> str:
    return quote(part, safe="")


def purl(ecosystem: str, name: str, version: str, namespace_hint: Optional[str] = None) -> Optional[str]:
    """Package URL per the purl spec, or None for an ecosystem it has no type for."""
    ptype = _PURL_TYPE.get(ecosystem)
    if not ptype or not name:
        return None
    ver = f"@{_q(version)}" if version else ""
    if ptype == "npm":
        if name.startswith("@") and "/" in name:
            scope, base = name.split("/", 1)
            return f"pkg:npm/{_q(scope)}/{_q(base)}{ver}"
        return f"pkg:npm/{_q(name)}{ver}"
    if ptype == "pypi":
        norm = name.lower().replace("_", "-").replace(".", "-")
        return f"pkg:pypi/{_q(norm)}{ver}"
    if ptype in ("composer", "golang"):
        segs = [s for s in name.split("/") if s]
        return f"pkg:{ptype}/" + "/".join(_q(s) for s in segs) + ver
    if ptype == "maven":
        if ":" in name:
            group, artifact = name.split(":", 1)
            return f"pkg:maven/{_q(group)}/{_q(artifact)}{ver}"
        return f"pkg:maven/{_q(name)}{ver}"
    if ptype == "swift":
        if namespace_hint and "/" in namespace_hint:
            ns, base = namespace_hint.rsplit("/", 1)
            return f"pkg:swift/{'/'.join(_q(s) for s in ns.split('/'))}/{_q(base)}{ver}"
        return None
    return f"pkg:{ptype}/{_q(name)}{ver}"


# --------------------------------------------------------------------------- collection

def _license_index(source_dir: str) -> Dict[Tuple[str, str, str], List[str]]:
    """(ecosystem, name, version) -> license ids, read from lockfiles that record them."""
    from .sca import web_deps

    out: Dict[Tuple[str, str, str], List[str]] = {}
    for path in web_deps._walk_manifests(source_dir, lambda f: f == "package-lock.json"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        for key, meta in (data.get("packages") or {}).items():
            if not key or not isinstance(meta, dict):
                continue
            name = key.split("node_modules/")[-1]
            lic = meta.get("license")
            if name and meta.get("version") and isinstance(lic, str) and lic.strip():
                out[("npm", name, str(meta["version"]))] = [lic.strip()]
    # Installed npm packages: node_modules/<name>/package.json next to each manifest.
    roots = {os.path.dirname(p) for p in web_deps._walk_manifests(source_dir, lambda f: f == "package.json")}
    roots.add(source_dir)
    for root in sorted(roots):
        nm = os.path.join(root, "node_modules")
        if not os.path.isdir(nm):
            continue
        for entry in os.listdir(nm):
            names = ([f"{entry}/{s}" for s in _safe_listdir(os.path.join(nm, entry))]
                     if entry.startswith("@") else [entry])
            for name in names:
                pj = os.path.join(nm, name, "package.json")
                try:
                    with open(pj, "r", encoding="utf-8", errors="ignore") as f:
                        meta = json.load(f)
                except (OSError, ValueError):
                    continue
                lic = meta.get("license")
                if isinstance(lic, dict):
                    lic = lic.get("type")
                if meta.get("version") and isinstance(lic, str) and lic.strip():
                    out.setdefault(("npm", name, str(meta["version"])), [lic.strip()])
    for path in web_deps._walk_manifests(source_dir, lambda f: f == "composer.lock"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        for section in ("packages", "packages-dev"):
            for entry in data.get(section) or []:
                if not isinstance(entry, dict):
                    continue
                lic = entry.get("license")
                if isinstance(lic, str):
                    lic = [lic]
                if entry.get("name") and entry.get("version") and isinstance(lic, list) and lic:
                    out[("Packagist", entry["name"], str(entry["version"]).lstrip("vV"))] = \
                        [str(x) for x in lic if str(x).strip()]
    return out


def _safe_listdir(path: str) -> List[str]:
    try:
        return os.listdir(path)
    except OSError:
        return []


def _component(ecosystem: str, name: str, version: str, source: str,
               resolved: Optional[bool], licenses: Optional[List[str]] = None,
               namespace_hint: Optional[str] = None) -> Dict[str, Any]:
    comp: Dict[str, Any] = {"type": "library", "name": name}
    if version:
        comp["version"] = version
    p = purl(ecosystem, name, version, namespace_hint)
    if p:
        comp["purl"] = p
        comp["bom-ref"] = p
    else:
        comp["bom-ref"] = f"{ecosystem}:{name}@{version}"
    if licenses:
        comp["licenses"] = [_license_entry(x) for x in licenses]
    props = [
        {"name": "narvy:ecosystem", "value": ecosystem},
        {"name": "narvy:evidence", "value": source},
    ]
    if resolved is not None:
        props.append({"name": "narvy:version-source",
                      "value": "lockfile" if resolved else "manifest-range-floor"})
    comp["properties"] = props
    return comp


def _license_entry(lic: str) -> Dict[str, Any]:
    # SPDX expressions with operators go in `expression`; a bare id or name in `license`.
    if any(op in lic for op in (" OR ", " AND ", " WITH ", "(")):
        return {"expression": lic}
    return {"license": {"id": lic}} if _looks_spdx_id(lic) else {"license": {"name": lic}}


def _looks_spdx_id(lic: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9.+-]+", lic)) and lic.upper() not in ("SEE LICENSE IN LICENSE", "UNLICENSED")


def collect_components(target: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Components plus a scope description for a source directory, APK/AAB or IPA."""
    from .sca import android_deps, ios_deps, web_deps

    lower = target.lower()
    comps: List[Dict[str, Any]] = []
    scope: Dict[str, Any] = {}

    if os.path.isdir(target):
        scope["kind"] = "source-directory"
        deps = web_deps._dedupe(web_deps.collect_dependencies(target))
        # One component per package@version (bom-ref, below): the manifest with
        # the strongest version proof first, as before the per-manifest dedupe.
        deps.sort(key=lambda d: -web_deps._VERSION_SOURCE_RANK.get(
            web_deps.version_source_for(d.source, d.version_source), 0))
        licenses = _license_index(target)
        for d in deps:
            comps.append(_component(d.ecosystem, d.name, d.version, d.source,
                                    web_deps._is_resolved(d),
                                    licenses.get((d.ecosystem, d.name, d.version))))
        for d in ios_deps.extract_source_dependencies(target):
            eco = "CocoaPods" if d.source == "podfile.lock" else "SwiftPM"
            comps.append(_component(eco, d.name, d.version, d.source, True, None,
                                    namespace_hint=d.osv_package_name))
        scope["manifest_ecosystems_without_resolved_versions"] = web_deps._coverage_gaps(target, deps)
    elif lower.endswith((".apk", ".aab")):
        scope["kind"] = "android-binary"
        for d in android_deps._dedupe_by_coordinate(android_deps.extract_dependencies(target)):
            comps.append(_component("Maven", d.maven_name, d.version, d.source, None))
    elif lower.endswith(".ipa"):
        scope["kind"] = "ios-binary"
        for d in ios_deps.extract_binary_dependencies(target):
            comps.append(_component("CocoaPods", d.name, d.version, d.source, None,
                                    namespace_hint=d.osv_package_name))
    else:
        raise ValueError("SBOM needs a source directory, an .apk/.aab or an .ipa")

    # One component per bom-ref (the same pod can come from Podfile.lock and Package.resolved).
    seen = set()
    unique = []
    for c in comps:
        if c["bom-ref"] in seen:
            continue
        seen.add(c["bom-ref"])
        unique.append(c)
    unique.sort(key=lambda c: c["bom-ref"])
    scope["components"] = len(unique)
    scope["with_license"] = sum(1 for c in unique if c.get("licenses"))
    return unique, scope


_SCOPE_NOTE = {
    "source-directory": ("Dependencies read from manifests and lockfiles. A component marked "
                         "manifest-range-floor has no lockfile: its version is the lowest the range allows, "
                         "not necessarily the one installed."),
    "android-binary": ("Maven coordinates still present in the APK/AAB. Shrunk (R8/ProGuard) builds "
                       "drop most of them: a missing library is not proof of absence."),
    "ios-binary": ("Third-party frameworks embedded with a version in their Info.plist. Statically "
                   "linked libraries are not listed."),
}


def build_sbom(target: str) -> Dict[str, Any]:
    comps, scope = collect_components(target)
    kind = scope["kind"]
    props = [
        {"name": "narvy:scope", "value": _SCOPE_NOTE[kind]},
        {"name": "narvy:licenses", "value": "Only where recorded locally: package-lock.json, installed node_modules, composer.lock."},
        {"name": "narvy:vulnerabilities", "value": "Not included. Run `narvy scan` for the OSV lookup."},
        {"name": "narvy:component-count", "value": str(scope["components"])},
        {"name": "narvy:components-with-license", "value": str(scope["with_license"])},
    ]
    gaps = scope.get("manifest_ecosystems_without_resolved_versions") or []
    if gaps:
        props.append({"name": "narvy:unresolved-manifests", "value": ", ".join(gaps)})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "narvy-cli", "version": __version__}]},
            "component": {"type": "application",
                          "name": os.path.basename(os.path.abspath(target)) or target,
                          "bom-ref": "target"},
            "properties": props,
        },
        "components": comps,
    }


# --------------------------------------------------------------------------- signing (JSF / Ed25519)

def canonical_json(obj: Any) -> bytes:
    """RFC 8785 canonical form for documents with ASCII keys and no floats (what Narvy emits)."""
    _reject_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _reject_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise ValueError("canonical_json: floats are not supported in a signed document")
    if isinstance(obj, dict):
        for v in obj.values():
            _reject_floats(v)
    elif isinstance(obj, list):
        for v in obj:
            _reject_floats(v)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:  # pragma: no cover - exercised by the CLI message test
        raise SigningUnavailable(f"Signing needs the optional 'cryptography' package: {SIGN_EXTRA_HINT}") from e
    return serialization, ed25519


def load_private_key(path: str):
    serialization, ed25519 = _crypto()
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("The signing key must be an Ed25519 private key (PEM, no passphrase)")
    return key


def _raw_public(pub) -> bytes:
    serialization, _ = _crypto()
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign_document(doc: Dict[str, Any], private_key) -> Dict[str, Any]:
    doc = dict(doc)
    doc.pop("signature", None)
    doc["signature"] = {
        "algorithm": SIGN_ALGORITHM,
        "publicKey": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(_raw_public(private_key.public_key()))},
    }
    doc["signature"]["value"] = _b64u(private_key.sign(canonical_json(doc)))
    return doc


def verify_document(doc: Dict[str, Any], trusted_public_key_path: Optional[str] = None) -> Tuple[bool, str]:
    """(ok, reason). Checks the JSF Ed25519 signature; with a trusted key, also that it is that key."""
    serialization, ed25519 = _crypto()
    sig = doc.get("signature")
    if not isinstance(sig, dict) or "value" not in sig:
        return False, "unsigned"
    if sig.get("algorithm") != SIGN_ALGORITHM:
        return False, f"unsupported algorithm {sig.get('algorithm')!r}"
    jwk = sig.get("publicKey") or {}
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not jwk.get("x"):
        return False, "missing or malformed public key"
    try:
        raw = _b64u_dec(jwk["x"])
        pub = ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return False, "malformed public key"
    if trusted_public_key_path:
        with open(trusted_public_key_path, "rb") as f:
            trusted = serialization.load_pem_public_key(f.read())
        if not isinstance(trusted, ed25519.Ed25519PublicKey) or _raw_public(trusted) != raw:
            return False, "signed with a different key than the trusted one"
    unsigned = json.loads(json.dumps(doc))
    value = unsigned["signature"].pop("value")
    try:
        pub.verify(_b64u_dec(value), canonical_json(unsigned))
    except Exception:
        return False, "signature does not match the content"
    return True, "valid" + ("" if trusted_public_key_path else " (key not pinned: integrity only)")


def write_json(doc: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
