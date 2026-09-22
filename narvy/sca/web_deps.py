"""Dependency CVE scanning for web/backend source trees: parses manifests and
lockfiles (npm, PyPI, Packagist, Go, RubyGems, crates.io, Maven, NuGet), then
queries OSV through osv_client."""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from .osv_client import OSVClient, get_default_client

logger = logging.getLogger(__name__)

_MAX_DETAIL_QUERIES = 400

SUPPORTED_ECOSYSTEMS_LABEL = "npm/PyPI/Packagist/Go/RubyGems/crates.io/Maven/NuGet"

_MANIFEST_WALK_MAX_DEPTH = 6
_MAX_MANIFEST_FILES = 300


@dataclass(frozen=True)
class _WebDep:
    name: str
    version: str
    ecosystem: str
    source: str


_NPM_RANGE_PREFIX_RE = re.compile(r'^[\^~><=\s]+')
_NPM_NONREGISTRY_RE = re.compile(r'^(file:|link:|git\+|git:|github:|workspace:|https?://|npm:)', re.IGNORECASE)


def _strip_npm_range(spec: str) -> Optional[str]:
    """Exact version from a package.json range specifier, or None if not pinnable."""
    spec = (spec or "").strip()
    if not spec or spec in ("*", "latest"):
        return None
    if _NPM_NONREGISTRY_RE.match(spec):
        return None
    if "||" in spec or " - " in spec or " " in spec.strip():
        return None
    cleaned = _NPM_RANGE_PREFIX_RE.sub("", spec).strip()
    if not cleaned or not re.match(r'^\d', cleaned):
        return None
    return cleaned


def _parse_package_lock(path: str) -> List[_WebDep]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    deps: List[_WebDep] = []
    # lockfileVersion 2/3: flat "packages" map keyed by "node_modules/<name>";
    # the root project is keyed "".
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version:
                continue
            name = key.split("node_modules/")[-1]
            if not name:
                continue
            deps.append(_WebDep(name, version, "npm", "package-lock.json"))
        if deps:
            return deps
    # lockfileVersion 1: nested "dependencies" map.
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for name, meta in dependencies.items():
            if isinstance(meta, dict) and meta.get("version"):
                deps.append(_WebDep(name, meta["version"], "npm", "package-lock.json"))
    return deps


def _parse_package_json(path: str) -> List[_WebDep]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    deps: List[_WebDep] = []
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            version = _strip_npm_range(str(spec))
            if version:
                deps.append(_WebDep(name, version, "npm", "package.json"))
    return deps


# pnpm-lock.yaml `packages:` keys carry name@version; the leading "/" and a
# "(react@18)" peer suffix drift across lock versions, so match tolerantly.
_PNPM_PKG_KEY_RE = re.compile(r'^/?((?:@[^/@]+/)?[^/@][^@]*)@(\d[^()]*)')


def _parse_pnpm_lock(path: str) -> List[_WebDep]:
    try:
        import yaml
    except ModuleNotFoundError:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(data, dict):
        return []
    section = data.get("packages") or data.get("snapshots") or {}
    if not isinstance(section, dict):
        return []
    seen = set()
    deps: List[_WebDep] = []
    for key in section:
        m = _PNPM_PKG_KEY_RE.match(str(key))
        if not m:
            continue
        name, version = m.group(1), m.group(2).strip()
        if (name, version) in seen:
            continue
        seen.add((name, version))
        deps.append(_WebDep(name, version, "npm", "pnpm-lock.yaml"))
    return deps


# A yarn.lock spec header: one or more comma-separated "name@range" entries ending
# in ':'; the resolved version is on an indented `version "x"` (v1) or `version: x`
# (berry) line inside the block.
_YARN_VERSION_RE = re.compile(r'^\s+version:?\s+"?([0-9][^"\s]*)"?\s*$')


def _yarn_name_from_spec(spec: str) -> Optional[str]:
    """'@babel/code-frame@npm:^7.0.0' / 'js-tokens@^4.0.0' -> package name."""
    spec = spec.strip().strip('"').strip("'")
    if not spec:
        return None
    # rsplit on the last '@' drops the range while keeping a scoped '@scope/name'.
    name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
    return name or None


def _parse_yarn_lock(path: str) -> List[_WebDep]:
    """Parse yarn.lock (v1 and berry) resolved versions for OSV lookup."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []
    deps: List[_WebDep] = []
    seen: Set[Tuple[str, str]] = set()
    current_name: Optional[str] = None
    for raw in lines:
        line = raw.rstrip("\n")
        if not line or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            first = header.split(",")[0]
            current_name = _yarn_name_from_spec(first)
            continue
        if current_name:
            m = _YARN_VERSION_RE.match(line)
            if m:
                version = m.group(1)
                if (current_name, version) not in seen:
                    seen.add((current_name, version))
                    deps.append(_WebDep(current_name, version, "npm", "yarn.lock"))
                current_name = None
    return deps


def _collect_npm_deps(root_path: str) -> List[_WebDep]:
    # pnpm-lock.yaml is authoritative for pnpm workspaces; prefer it.
    pnpm = os.path.join(root_path, "pnpm-lock.yaml")
    if os.path.isfile(pnpm):
        locked = _parse_pnpm_lock(pnpm)
        if locked:
            return locked
    yarn = os.path.join(root_path, "yarn.lock")
    if os.path.isfile(yarn):
        locked = _parse_yarn_lock(yarn)
        if locked:
            return locked
    lock = os.path.join(root_path, "package-lock.json")
    if os.path.isfile(lock):
        locked = _parse_package_lock(lock)
        if locked:
            return locked
    manifest = os.path.join(root_path, "package.json")
    if os.path.isfile(manifest):
        return _parse_package_json(manifest)
    return []


_REQ_EXACT_RE = re.compile(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([0-9][A-Za-z0-9.*+!_-]*)')


def _parse_poetry_lock(path: str) -> List[_WebDep]:
    """Parse poetry.lock (TOML [[package]] tables) for resolved Python deps."""
    try:
        import tomllib as _toml  # py3.11+
    except ModuleNotFoundError:
        try:
            import tomli as _toml
        except ModuleNotFoundError:
            return []
    try:
        with open(path, "rb") as f:
            data = _toml.load(f)
    except (OSError, ValueError):
        return []
    deps: List[_WebDep] = []
    for pkg in (data.get("package") or []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version and re.match(r'^\d', str(version)):
            deps.append(_WebDep(str(name), str(version), "PyPI", "poetry.lock"))
    return deps


def _collect_pypi_deps(root_path: str) -> List[_WebDep]:
    # poetry.lock is authoritative and carries the full resolved tree; prefer it.
    poetry = os.path.join(root_path, "poetry.lock")
    if os.path.isfile(poetry):
        locked = _parse_poetry_lock(poetry)
        if locked:
            return locked
    path = os.path.join(root_path, "requirements.txt")
    if not os.path.isfile(path):
        return []
    deps: List[_WebDep] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith(("#", "-e ", "-r ", "--")):
            continue
        line = line.split(";", 1)[0].split("#", 1)[0].strip()
        m = _REQ_EXACT_RE.match(line)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        deps.append(_WebDep(name, version, "PyPI", "requirements.txt"))
    return deps


_PHP_RANGE_PREFIX_RE = re.compile(r'^[\^~><=\s]+')


def _strip_php_range(spec: str) -> Optional[str]:
    spec = (spec or "").strip()
    if not spec or spec in ("*", "dev-master", "dev-main"):
        return None
    if spec.startswith(("dev-", "@")):
        return None
    if "||" in spec or " " in spec or "," in spec:
        return None
    cleaned = _PHP_RANGE_PREFIX_RE.sub("", spec).strip()
    if not cleaned or not re.match(r'^\d', cleaned):
        return None
    return cleaned


def _parse_composer_lock(path: str) -> List[_WebDep]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    deps: List[_WebDep] = []
    for key in ("packages", "packages-dev"):
        for entry in data.get(key, []) or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if name and version:
                # composer.lock versions are sometimes prefixed "v".
                deps.append(_WebDep(name, str(version).lstrip("vV"), "Packagist", "composer.lock"))
    return deps


def _parse_composer_json(path: str) -> List[_WebDep]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    deps: List[_WebDep] = []
    for key in ("require", "require-dev"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            if name == "php" or name.startswith("ext-"):
                continue
            version = _strip_php_range(str(spec))
            if version:
                deps.append(_WebDep(name, version, "Packagist", "composer.json"))
    return deps


def _collect_packagist_deps(root_path: str) -> List[_WebDep]:
    lock = os.path.join(root_path, "composer.lock")
    if os.path.isfile(lock):
        locked = _parse_composer_lock(lock)
        if locked:
            return locked
    manifest = os.path.join(root_path, "composer.json")
    if os.path.isfile(manifest):
        return _parse_composer_json(manifest)
    return []


# go.mod versions are always exact ("v" + semver), so no pinnability filtering.
_GO_REQUIRE_LINE_RE = re.compile(
    r'^\s*([A-Za-z0-9][\w.\-/]*)\s+(v[0-9][\w.+-]*)(?:\s*//.*)?$'
)


def _collect_go_deps(root_path: str) -> List[_WebDep]:
    path = os.path.join(root_path, "go.mod")
    if not os.path.isfile(path):
        return []
    deps: List[_WebDep] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return []
    in_block = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        if line.startswith("//") or not line:
            continue
        m = _GO_REQUIRE_LINE_RE.match(line)
        if not m:
            continue
        module_path, version = m.group(1), m.group(2)
        deps.append(_WebDep(module_path, version, "Go", "go.mod"))
    return deps


# Gemfile.lock spec lines are 4-space-indented; 6-space are transitive ranges.
_GEMFILE_LOCK_SPEC_RE = re.compile(r'^ {4}([A-Za-z0-9][\w.-]*) \((\d[^)]*)\)\s*$')

# Strip Bundler's platform suffix ("1.16.0-x86_64-linux"); anchored on the CPU/OS
# token so a prerelease hyphen ("1.0.0-beta1") survives.
_GEM_PLATFORM_SUFFIX_RE = re.compile(
    r'-(?:x86_64|x86|x64|arm64|aarch64|arm|universal|riscv64|ppc64le|ppc64|s390x'
    r'|java|dalvik|mswin\d*|mingw\d*)'
    r'(?:[-_][\w.]+)*$'
)


# A Gemfile line pinning an EXACT version: `gem 'rails', '8.1.3.1'`. Range specs
# (`~> 5.0`, `>= 3.1.3`) start with an operator, so requiring a leading digit
# keeps only the OSV-resolvable pins.
_GEMFILE_EXACT_RE = re.compile(
    r"""^\s*gem\s+['"]([A-Za-z0-9][\w.-]*)['"]\s*,\s*['"](\d[\w.]*)['"]"""
)


def _parse_gemfile(path: str) -> List[_WebDep]:
    """Best-effort: exact-pinned gems from a Gemfile (fallback when no Gemfile.lock)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []
    deps: List[_WebDep] = []
    for raw in lines:
        m = _GEMFILE_EXACT_RE.match(raw.rstrip("\n"))
        if m:
            deps.append(_WebDep(m.group(1), m.group(2), "RubyGems", "Gemfile"))
    return deps


def _collect_rubygems_deps(root_path: str) -> List[_WebDep]:
    """Gemfile.lock's `GEM ... specs:` section; fall back to exact-pinned Gemfile gems."""
    path = os.path.join(root_path, "Gemfile.lock")
    if not os.path.isfile(path):
        # No lockfile: resolve the exactly-pinned gems from the Gemfile instead.
        gemfile = os.path.join(root_path, "Gemfile")
        if os.path.isfile(gemfile):
            return _parse_gemfile(gemfile)
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    deps: List[_WebDep] = []
    in_gem_section = False
    in_specs = False
    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if line and not line.startswith(" "):
            in_gem_section = line.strip() == "GEM"
            in_specs = False
            continue
        if not in_gem_section:
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if not in_specs:
            continue
        m = _GEMFILE_LOCK_SPEC_RE.match(line)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        version = _GEM_PLATFORM_SUFFIX_RE.sub("", version)
        deps.append(_WebDep(name, version, "RubyGems", "Gemfile.lock"))
    return deps


# Cargo.lock is TOML but parsed line-wise (tomllib is 3.11+; this CLI supports 3.10+).
_CARGO_LOCK_KV_RE = re.compile(r'^(name|version|source)\s*=\s*"([^"]*)"\s*$')
_CRATES_IO_REGISTRY_PREFIX = "registry+https://github.com/rust-lang/crates.io-index"


def _parse_cargo_lock(path: str) -> List[_WebDep]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    deps: List[_WebDep] = []
    cur: Dict[str, str] = {}

    def _flush() -> None:
        name, version, src = cur.get("name"), cur.get("version"), cur.get("source", "")
        if name and version and src.startswith(_CRATES_IO_REGISTRY_PREFIX):
            deps.append(_WebDep(name, version, "crates.io", "Cargo.lock"))

    for raw_line in lines:
        line = raw_line.strip()
        if line == "[[package]]":
            _flush()
            cur = {}
            continue
        if line.startswith("["):
            _flush()
            cur = {}
            continue
        m = _CARGO_LOCK_KV_RE.match(line)
        if m:
            cur[m.group(1)] = m.group(2)
    _flush()
    return deps


_CARGO_TOML_SIMPLE_DEP_RE = re.compile(r'^([A-Za-z0-9][\w.-]*)\s*=\s*"([^"]*)"\s*$')
_CARGO_TOML_TABLE_DEP_RE = re.compile(r'^([A-Za-z0-9][\w.-]*)\s*=\s*\{(.*)\}\s*$')
_CARGO_TOML_TABLE_VERSION_RE = re.compile(r'\bversion\s*=\s*"([^"]*)"')
_CARGO_TOML_DEP_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")
_CARGO_RANGE_PREFIX_RE = re.compile(r'^[\^~><=\s]+')


def _strip_cargo_range(spec: str) -> Optional[str]:
    spec = (spec or "").strip()
    if not spec or spec == "*":
        return None
    if "," in spec or "||" in spec:
        return None
    cleaned = _CARGO_RANGE_PREFIX_RE.sub("", spec).strip()
    if not cleaned or not re.match(r'^\d', cleaned):
        return None
    return cleaned


def _parse_cargo_toml(path: str) -> List[_WebDep]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    deps: List[_WebDep] = []
    in_dep_section = False
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("["):
            section = line.strip("[]").strip()
            in_dep_section = section.rsplit(".", 1)[-1] in _CARGO_TOML_DEP_SECTIONS
            continue
        if not in_dep_section or not line:
            continue
        m = _CARGO_TOML_SIMPLE_DEP_RE.match(line)
        if m:
            version = _strip_cargo_range(m.group(2))
            if version:
                deps.append(_WebDep(m.group(1), version, "crates.io", "Cargo.toml"))
            continue
        m = _CARGO_TOML_TABLE_DEP_RE.match(line)
        if m:
            body = m.group(2)
            if "path" in body or "git" in body:
                continue
            vm = _CARGO_TOML_TABLE_VERSION_RE.search(body)
            if vm:
                version = _strip_cargo_range(vm.group(1))
                if version:
                    deps.append(_WebDep(m.group(1), version, "crates.io", "Cargo.toml"))
    return deps


def _collect_crates_deps(root_path: str) -> List[_WebDep]:
    lock = os.path.join(root_path, "Cargo.lock")
    if os.path.isfile(lock):
        locked = _parse_cargo_lock(lock)
        if locked:
            return locked
    manifest = os.path.join(root_path, "Cargo.toml")
    if os.path.isfile(manifest):
        return _parse_cargo_toml(manifest)
    return []


_MANIFEST_SKIP_DIR_NAMES = frozenset({
    "node_modules", "vendor", "bower_components",
    ".venv", "venv", ".tox", "__pycache__",
    "Pods", "Carthage", "DerivedData",
    ".git", ".gradle", ".idea", ".vscode", ".vs",
    "build", "dist", "target", "out", "bin", "obj",
    ".next", ".nuxt", ".cache", "coverage", ".pytest_cache",
    "packages",
})


def _walk_manifests(root_path: str, matcher) -> List[str]:
    """Bounded, vendor-pruned walk for matching paths, sorted for a deterministic cap."""
    found: List[str] = []
    base_depth = root_path.rstrip(os.sep).count(os.sep)
    for cur_root, dirs, files in os.walk(root_path):
        depth = cur_root.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= _MANIFEST_WALK_MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs
                   if d not in _MANIFEST_SKIP_DIR_NAMES and not d.startswith(".")]
        for f in files:
            if matcher(f):
                found.append(os.path.join(cur_root, f))
        if len(found) >= _MAX_MANIFEST_FILES:
            break
    return sorted(found)[:_MAX_MANIFEST_FILES]


# ElementTree has no namespace-agnostic search, so lookups go through _xml_local_name.
_MAVEN_PROPERTY_RE = re.compile(r'\$\{([^}]+)\}')

_MAVEN_CONCRETE_VERSION_RE = re.compile(r'^\d[\w.\-+]*$')


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_children(element, name: str):
    for child in element:
        if _xml_local_name(child.tag) == name:
            yield child


def _xml_text(element, name: str) -> Optional[str]:
    for child in _xml_children(element, name):
        return (child.text or "").strip()
    return None


def _parse_pom(path: str):
    """(properties, managed_versions, declared_dependencies) for one pom, versions raw."""
    import xml.etree.ElementTree as ET

    properties: Dict[str, str] = {}
    managed: Dict[Tuple[str, str], str] = {}
    declared: List[Tuple[str, str, Optional[str]]] = []

    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return properties, managed, declared

    for props in _xml_children(root, "properties"):
        for prop in props:
            properties[_xml_local_name(prop.tag)] = (prop.text or "").strip()

    def _read_dependency_list(container, into_managed: bool) -> None:
        for dep in _xml_children(container, "dependency"):
            group = _xml_text(dep, "groupId")
            artifact = _xml_text(dep, "artifactId")
            version = _xml_text(dep, "version")
            if not group or not artifact:
                continue
            if into_managed:
                if version:
                    managed[(group, artifact)] = version
                # A `<scope>import</scope>` entry is a BOM, not a shipped dependency.
                if _xml_text(dep, "scope") == "import":
                    continue
            declared.append((group, artifact, version))

    for dep_mgmt in _xml_children(root, "dependencyManagement"):
        for deps in _xml_children(dep_mgmt, "dependencies"):
            _read_dependency_list(deps, into_managed=True)

    for deps in _xml_children(root, "dependencies"):
        _read_dependency_list(deps, into_managed=False)

    return properties, managed, declared


def _resolve_maven_version(raw: Optional[str], properties: Dict[str, str],
                           depth: int = 0) -> Optional[str]:
    """Concrete version for a raw `<version>`; ranges/SNAPSHOTs/unresolved `${...}` return None."""
    if not raw or depth > 5:
        return None
    raw = raw.strip()
    if not raw:
        return None
    if _MAVEN_PROPERTY_RE.search(raw):
        # `${project.*}` / `${pom.*}` refer to the module being built, not an artifact.
        def _expand(match):
            key = match.group(1)
            if key.startswith(("project.", "pom.")):
                return ""
            return properties.get(key, "")
        expanded = _MAVEN_PROPERTY_RE.sub(_expand, raw)
        if not expanded or _MAVEN_PROPERTY_RE.search(expanded):
            return None
        return _resolve_maven_version(expanded, properties, depth + 1)
    if raw.upper() in ("LATEST", "RELEASE"):
        return None
    if raw.upper().endswith("-SNAPSHOT"):
        return None
    if not _MAVEN_CONCRETE_VERSION_RE.match(raw):
        return None
    return raw


# Only the literal `group:artifact:version` form; catalogs/interpolation/BOMs are missed.
_GRADLE_DEP_RE = re.compile(
    r'''(?:^|\s)(?:api|implementation|compile|compileOnly|runtimeOnly|annotationProcessor'''
    r'''|kapt|ksp|testImplementation|testCompile|androidTestImplementation|classpath)'''
    r'''\s*[(\s]\s*["']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([^"'$]+)["']'''
)


def _parse_gradle(path: str) -> List[Tuple[str, str, str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return []
    out: List[Tuple[str, str, str]] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        m = _GRADLE_DEP_RE.search(line)
        if m:
            out.append((m.group(1), m.group(2), m.group(3).strip()))
    return out


# Gradle version catalog (gradle/libs.versions.toml): parsed line-wise so no
# tomllib dependency is needed (this CLI supports Python 3.10+).
_TOML_SECTION_RE = re.compile(r'^\s*\[([A-Za-z0-9_.\-]+)\]')
_TOML_VERSION_RE = re.compile(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"([^"]+)"\s*$')
_CATALOG_STRING_DEP_RE = re.compile(
    r'^\s*[A-Za-z0-9_.\-]+\s*=\s*"([^:"]+):([^:"]+):([^"]+)"\s*$'
)
_CATALOG_GROUP_RE = re.compile(r'\bgroup\s*=\s*"([^"]+)"')
_CATALOG_NAME_RE = re.compile(r'\bname\s*=\s*"([^"]+)"')
_CATALOG_MODULE_RE = re.compile(r'\bmodule\s*=\s*"([^"]+)"')
_CATALOG_VERSION_REF_RE = re.compile(r'\bversion\.ref\s*=\s*"([^"]+)"')
_CATALOG_VERSION_LIT_RE = re.compile(r'\bversion\s*=\s*"([^"]+)"')


def _parse_gradle_version_catalog(path: str) -> List[Tuple[str, str, str]]:
    """Resolve [libraries] entries to (group, artifact, version); [plugins]/[bundles] are not runtime deps."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    versions: Dict[str, str] = {}
    section = ""
    for line in lines:
        sec = _TOML_SECTION_RE.match(line)
        if sec:
            section = sec.group(1).lower()
            continue
        if section == "versions" and not line.lstrip().startswith("#"):
            m = _TOML_VERSION_RE.match(line)
            if m:
                versions[m.group(1)] = m.group(2)

    out: List[Tuple[str, str, str]] = []
    section = ""
    for line in lines:
        sec = _TOML_SECTION_RE.match(line)
        if sec:
            section = sec.group(1).lower()
            continue
        if section != "libraries" or line.lstrip().startswith("#"):
            continue

        sm = _CATALOG_STRING_DEP_RE.match(line)
        if sm:
            out.append((sm.group(1), sm.group(2), sm.group(3).strip()))
            continue

        module_m = _CATALOG_MODULE_RE.search(line)
        if module_m and ":" in module_m.group(1):
            group, artifact = module_m.group(1).split(":", 1)
        else:
            gm = _CATALOG_GROUP_RE.search(line)
            nm = _CATALOG_NAME_RE.search(line)
            if not (gm and nm):
                continue
            group, artifact = gm.group(1), nm.group(1)

        ref = _CATALOG_VERSION_REF_RE.search(line)
        if ref:
            version = versions.get(ref.group(1))
        else:
            lit = _CATALOG_VERSION_LIT_RE.search(line)
            version = lit.group(1) if lit else None
        if version:
            out.append((group.strip(), artifact.strip(), version.strip()))
    return out


def _collect_maven_deps(root_path: str) -> List[_WebDep]:
    """Collect Maven/Gradle deps: merge poms' properties repo-wide, then resolve each."""
    pom_paths = _walk_manifests(root_path, lambda f: f == "pom.xml")
    gradle_paths = _walk_manifests(
        root_path, lambda f: f in ("build.gradle", "build.gradle.kts")
    )
    catalog_paths = _walk_manifests(root_path, lambda f: f == "libs.versions.toml")
    if not pom_paths and not gradle_paths and not catalog_paths:
        return []

    all_properties: Dict[str, str] = {}
    all_managed: Dict[Tuple[str, str], str] = {}
    all_declared: List[Tuple[str, str, Optional[str], str]] = []

    parsed = []
    for pom_path in pom_paths:
        properties, managed, declared = _parse_pom(pom_path)
        parsed.append((pom_path, declared))
        all_properties.update(properties)
        all_managed.update(managed)

    for pom_path, declared in parsed:
        source = os.path.relpath(pom_path, root_path)
        for group, artifact, raw_version in declared:
            all_declared.append((group, artifact, raw_version, source))

    deps: List[_WebDep] = []
    for group, artifact, raw_version, source in all_declared:
        version = _resolve_maven_version(raw_version, all_properties)
        if version is None:
            managed_raw = all_managed.get((group, artifact))
            version = _resolve_maven_version(managed_raw, all_properties)
        if version is None:
            continue
        deps.append(_WebDep(f"{group}:{artifact}", version, "Maven", source))

    for gradle_path in gradle_paths:
        source = os.path.relpath(gradle_path, root_path)
        for group, artifact, version in _parse_gradle(gradle_path):
            if _MAVEN_CONCRETE_VERSION_RE.match(version) and not version.upper().endswith("-SNAPSHOT"):
                deps.append(_WebDep(f"{group}:{artifact}", version, "Maven", source))

    for catalog_path in catalog_paths:
        source = os.path.relpath(catalog_path, root_path)
        for group, artifact, version in _parse_gradle_version_catalog(catalog_path):
            if _MAVEN_CONCRETE_VERSION_RE.match(version) and not version.upper().endswith("-SNAPSHOT"):
                deps.append(_WebDep(f"{group}:{artifact}", version, "Maven", source))

    return deps


_NUGET_PROJECT_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".props", ".targets")
_MSBUILD_PROPERTY_RE = re.compile(r'\$\(([^)]+)\)')
# `[8.0.2]` pins one version; other bracket forms are intervals resolved at restore.
_NUGET_EXACT_PIN_RE = re.compile(r'^\[\s*([^,\[\]()]+?)\s*\]$')
_NUGET_CONCRETE_VERSION_RE = re.compile(r'^\d[\w.\-+]*$')


def _normalize_nuget_version(raw: Optional[str], properties: Dict[str, str],
                             depth: int = 0) -> Optional[str]:
    """Concrete version for a NuGet version string, or None for a range."""
    if not raw or depth > 5:
        return None
    raw = raw.strip()
    if not raw:
        return None
    if _MSBUILD_PROPERTY_RE.search(raw):
        def _expand(match):
            return properties.get(match.group(1), "")
        expanded = _MSBUILD_PROPERTY_RE.sub(_expand, raw)
        if not expanded or _MSBUILD_PROPERTY_RE.search(expanded):
            return None
        return _normalize_nuget_version(expanded, properties, depth + 1)
    pinned = _NUGET_EXACT_PIN_RE.match(raw)
    if pinned:
        raw = pinned.group(1).strip()
    if "*" in raw:
        return None
    if not _NUGET_CONCRETE_VERSION_RE.match(raw):
        return None
    return raw


def _parse_nuget_project(path: str) -> Tuple[Dict[str, str], List[Tuple[str, Optional[str]]]]:
    """(msbuild_properties, [(package_id, raw_version), ...]) for one project file."""
    import xml.etree.ElementTree as ET

    properties: Dict[str, str] = {}
    packages: List[Tuple[str, Optional[str]]] = []
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return properties, packages

    for element in root.iter():
        name = _xml_local_name(element.tag)
        if name == "PropertyGroup":
            for prop in element:
                properties[_xml_local_name(prop.tag)] = (prop.text or "").strip()
        elif name in ("PackageReference", "PackageVersion"):
            package_id = element.get("Include") or element.get("Update")
            if not package_id:
                continue
            version = element.get("Version") or element.get("VersionOverride")
            if version is None:
                version = _xml_text(element, "Version")
            packages.append((package_id.strip(), version))
    return properties, packages


def _parse_packages_config(path: str) -> List[Tuple[str, Optional[str]]]:
    import xml.etree.ElementTree as ET

    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []
    out: List[Tuple[str, Optional[str]]] = []
    for element in root.iter():
        if _xml_local_name(element.tag) != "package":
            continue
        package_id = element.get("id")
        if package_id:
            out.append((package_id.strip(), element.get("version")))
    return out


def _parse_packages_lock(path: str) -> List[Tuple[str, Optional[str]]]:
    """`packages.lock.json` entries, keyed {"dependencies": {tfm: {pkg: {resolved}}}}."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    out: List[Tuple[str, Optional[str]]] = []
    frameworks = data.get("dependencies")
    if not isinstance(frameworks, dict):
        return []
    for packages in frameworks.values():
        if not isinstance(packages, dict):
            continue
        for package_id, meta in packages.items():
            if isinstance(meta, dict) and meta.get("resolved"):
                out.append((package_id, str(meta["resolved"])))
    return out


def _collect_nuget_deps(root_path: str) -> List[_WebDep]:
    """Collect NuGet deps: lockfile-first per project, MSBuild properties merged first."""
    lock_paths = _walk_manifests(root_path, lambda f: f == "packages.lock.json")
    project_paths = _walk_manifests(
        root_path, lambda f: f.endswith(_NUGET_PROJECT_SUFFIXES)
    )
    config_paths = _walk_manifests(root_path, lambda f: f == "packages.config")
    if not lock_paths and not project_paths and not config_paths:
        return []

    locked_dirs = {os.path.dirname(p) for p in lock_paths}

    all_properties: Dict[str, str] = {}
    project_packages: List[Tuple[str, List[Tuple[str, Optional[str]]]]] = []
    for project_path in project_paths:
        properties, packages = _parse_nuget_project(project_path)
        all_properties.update(properties)
        project_packages.append((project_path, packages))

    deps: List[_WebDep] = []

    for lock_path in lock_paths:
        source = os.path.relpath(lock_path, root_path)
        for package_id, version in _parse_packages_lock(lock_path):
            if version:
                deps.append(_WebDep(package_id, version, "NuGet", source))

    for project_path, packages in project_packages:
        if os.path.dirname(project_path) in locked_dirs:
            continue
        source = os.path.relpath(project_path, root_path)
        for package_id, raw_version in packages:
            version = _normalize_nuget_version(raw_version, all_properties)
            if version:
                deps.append(_WebDep(package_id, version, "NuGet", source))

    for config_path in config_paths:
        if os.path.dirname(config_path) in locked_dirs:
            continue
        source = os.path.relpath(config_path, root_path)
        for package_id, raw_version in _parse_packages_config(config_path):
            version = _normalize_nuget_version(raw_version, all_properties)
            if version:
                deps.append(_WebDep(package_id, version, "NuGet", source))

    return deps


def _dedupe(deps: List[_WebDep]) -> List[_WebDep]:
    best: Dict[Tuple[str, str], _WebDep] = {}
    for dep in deps:
        key = (dep.ecosystem, dep.name)
        if key not in best:
            best[key] = dep
    return list(best.values())


def _finding_from_osv(dep: _WebDep, osv_finding_dict: Dict[str, Any]) -> Dict[str, Any]:
    cve_id = osv_finding_dict.get("cve") or osv_finding_dict.get("osv_id") or "UNKNOWN"
    severity = osv_finding_dict.get("severity", "MEDIUM")
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        severity = "MEDIUM"
    fixed_version = osv_finding_dict.get("fixed_version")
    summary = osv_finding_dict.get("summary") or (osv_finding_dict.get("details") or "")[:400] or "No summary available."

    description = (
        f"{dep.name}@{dep.version} ({dep.ecosystem}) is affected by {cve_id} "
        f"(detected via {dep.source}). {summary}"
    )
    recommendation = (
        f"Update {dep.name} to version {fixed_version} or later."
        if fixed_version
        else f"No fixed version is listed by OSV yet for {dep.name}. "
             f"Check its release notes / consider an alternative package."
    )

    rule_id = f"SCA-{cve_id}"
    return {
        "rule_id": rule_id,
        "file_path": dep.source,
        "name": f"{cve_id}: {dep.name}@{dep.version} (vulnerable dependency)",
        "severity": severity,
        "details": {
            "description": description,
            "recommendation": recommendation,
            "cwe": osv_finding_dict.get("cwe", "CWE-1104"),
            "masvs": "MSTG-CODE-5",
        },
        "line": 1,
        "engine": "sca",
        "sca": {
            "package": dep.name,
            "version": dep.version,
            "detected_via": dep.source,
            "fixed_version": fixed_version,
            "references": osv_finding_dict.get("references", []),
            "ecosystem": dep.ecosystem,
        },
    }


def _rule_def_from_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": finding["rule_id"],
        "name": finding["name"],
        "severity": finding["severity"],
        "masvs": finding["details"]["masvs"],
        "details": dict(finding["details"]),
    }


# Run a collector once per manifest-bearing directory, so monorepos and subdir
# backends are covered (scan()'s _dedupe collapses overlap).
def _collect_recursive(root_path: str, filenames, collector) -> List[_WebDep]:
    dirs = set()
    for fn in filenames:
        for p in _walk_manifests(root_path, lambda f, _fn=fn: f == _fn):
            dirs.add(os.path.dirname(p))
    if root_path not in dirs and any(
        os.path.isfile(os.path.join(root_path, fn)) for fn in filenames
    ):
        dirs.add(root_path)
    out: List[_WebDep] = []
    for d in sorted(dirs):
        out.extend(collector(d))
    return out


# Dependency-manifest filenames per ecosystem, used to tell "no manifest present"
# (honest 'none') apart from "manifest present but its deps never reached OSV"
# (dishonest if reported 'complete' -> force 'partial').
_ECOSYSTEM_MANIFESTS: Dict[str, Tuple[str, ...]] = {
    "npm": ("pnpm-lock.yaml", "yarn.lock", "package-lock.json", "package.json"),
    "PyPI": ("poetry.lock", "requirements.txt", "Pipfile", "Pipfile.lock", "setup.py", "pyproject.toml"),
    "Packagist": ("composer.lock", "composer.json"),
    "Go": ("go.mod",),
    "RubyGems": ("Gemfile.lock", "Gemfile"),
    "crates.io": ("Cargo.lock", "Cargo.toml"),
}
# Suffix-matched manifests (Maven/Gradle/NuGet project files).
_ECOSYSTEM_MANIFEST_SUFFIXES: Dict[str, Tuple[str, ...]] = {
    "Maven": ("pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml"),
    "NuGet": (".csproj", ".fsproj", ".vbproj", "packages.config", "packages.lock.json"),
}


def _present_manifest_ecosystems(source_dir: str) -> Set[str]:
    present: Set[str] = set()
    for eco, names in _ECOSYSTEM_MANIFESTS.items():
        if _walk_manifests(source_dir, lambda f, _n=names: f in _n):
            present.add(eco)
    for eco, sufs in _ECOSYSTEM_MANIFEST_SUFFIXES.items():
        if _walk_manifests(source_dir, lambda f, _s=sufs: f.endswith(_s)):
            present.add(eco)
    return present


def _coverage_gaps(source_dir: str, deps: List[_WebDep]) -> List[str]:
    """Ecosystems whose manifest is present but produced no resolvable deps, plus
    a Gemfile-without-lock note (its version ranges cannot be fully resolved)."""
    present = _present_manifest_ecosystems(source_dir)
    with_deps = {d.ecosystem for d in deps}
    gaps = sorted(present - with_deps)
    if _walk_manifests(source_dir, lambda f: f == "Gemfile") and \
       not _walk_manifests(source_dir, lambda f: f == "Gemfile.lock"):
        gaps.append("RubyGems:Gemfile-without-lock")
    return gaps


def collect_dependencies(source_dir: str) -> List[_WebDep]:
    deps: List[_WebDep] = []
    deps.extend(_collect_recursive(source_dir, ("pnpm-lock.yaml", "yarn.lock", "package-lock.json", "package.json"), _collect_npm_deps))
    deps.extend(_collect_recursive(source_dir, ("poetry.lock", "requirements.txt"), _collect_pypi_deps))
    deps.extend(_collect_recursive(source_dir, ("composer.lock", "composer.json"), _collect_packagist_deps))
    deps.extend(_collect_recursive(source_dir, ("go.mod",), _collect_go_deps))
    deps.extend(_collect_recursive(source_dir, ("Gemfile.lock", "Gemfile"), _collect_rubygems_deps))
    deps.extend(_collect_recursive(source_dir, ("Cargo.lock", "Cargo.toml"), _collect_crates_deps))
    deps.extend(_collect_maven_deps(source_dir))
    deps.extend(_collect_nuget_deps(source_dir))
    return deps


def scan(source_dir: str, osv_client: OSVClient = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Scan a source checkout's manifests: (findings, rule_defs, stats)."""
    client = osv_client or get_default_client()

    all_deps = collect_dependencies(source_dir)
    deduped = _dedupe(all_deps)

    # Manifests present but not (fully) resolved: reported so coverage never says
    # 'complete' over a Gemfile/lockfile whose deps never reached OSV.
    coverage_gaps = _coverage_gaps(source_dir, deduped)

    # "_detected" is the pre-cap count; "_checked" is what was actually queried.
    stats: Dict[str, Any] = {
        "total_dependencies_detected": len(all_deps),
        "unique_dependencies_detected": len(deduped),
        "unique_dependencies_checked": len(deduped),
        "dependencies_capped": False,
        "cves_found": 0,
        "vulnerable_dependencies": 0,
        "unparsed_manifests": coverage_gaps,
    }

    if not deduped:
        return [], [], stats

    if len(deduped) > _MAX_DETAIL_QUERIES:
        logger.warning(
            f"[SCA] {len(deduped)} unique dependencies detected - capping OSV "
            f"queries at {_MAX_DETAIL_QUERIES} to stay considerate of the free "
            f"public API."
        )
        stats["dependencies_capped"] = True
        deduped = deduped[:_MAX_DETAIL_QUERIES]
        stats["unique_dependencies_checked"] = len(deduped)

    # has_any_vuln_batch takes one ecosystem per call, so group first.
    by_ecosystem: Dict[str, List[_WebDep]] = {}
    for dep in deduped:
        by_ecosystem.setdefault(dep.ecosystem, []).append(dep)

    findings: List[Dict[str, Any]] = []
    rule_defs: List[Dict[str, Any]] = []
    vulnerable_coords: Set[str] = set()

    unresolved_before = getattr(client, "query_failures_no_cache", 0)

    for ecosystem, eco_deps in by_ecosystem.items():
        pkg_version_pairs = [(d.name, d.version) for d in eco_deps]
        has_vuln = client.has_any_vuln_batch(pkg_version_pairs, ecosystem=ecosystem)

        for dep in eco_deps:
            if not dep.version:
                continue
            key = (dep.name, dep.version)
            if not has_vuln.get(key, False):
                continue

            osv_findings = client.query_dict(dep.name, dep.version, ecosystem=ecosystem)
            for osv_finding in osv_findings:
                finding = _finding_from_osv(dep, osv_finding)
                findings.append(finding)
                rule_defs.append(_rule_def_from_finding(finding))
                stats["cves_found"] += 1
                vulnerable_coords.add(f"{dep.ecosystem}:{dep.name}")

    stats["vulnerable_dependencies"] = len(vulnerable_coords)
    unresolved = getattr(client, "query_failures_no_cache", 0) - unresolved_before
    stats["osv_dependencies_unresolved"] = unresolved
    stats["osv_unreachable"] = unresolved > 0
    return findings, rule_defs, stats
