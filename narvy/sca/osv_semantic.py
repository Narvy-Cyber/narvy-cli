"""OSV version ordering, ported from the code the OSV.dev API runs.

The public OSV.dev API (`api.osv.dev/v1/query`, Go server in
github.com/google/osv.dev/go/internal/api) compares versions with the
`semantic` package of github.com/google/osv-scalibr (v0.5.2 at the time of
this port) wrapped by github.com/google/osv.dev/go/osv/ecosystem. A local
mirror answers the same questions only if it orders versions the same way, so
this module is a line-by-line Python port of those two packages for the
ecosystems Narvy queries:

    npm, Go, crates.io, SwiftURL, Hex   -> SemverVersion
    NuGet                               -> NuGetVersion (4 numeric parts)
    Pub                                 -> PubVersion
    Maven                               -> MavenVersion (ComparableVersion)
    PyPI                                -> PyPIVersion (PEP 440 + legacy)
    RubyGems                            -> RubyGemsVersion (Gem::Version)
    Packagist                           -> PackagistVersion (version_compare)

plus the "coarse version" strings the API uses to pre-filter candidate
records (`coarse_min <= coarse(v) <= coarse_max`), which can change a result
at the edges, so they are ported too.

Quirks are kept on purpose (they are what the API returns): npm prerelease
ordering is plain SemVer 2.0 precedence, not npm range semantics; `v`
prefixes are ignored; a 4th numeric part of an npm version moves into the
build string; Go pseudo-versions sort as prereleases; unknown Maven
qualifiers sort after known ones; PyPI legacy (non PEP 440) versions sort
before every valid version.

Upstream code: Copyright 2025-2026 Google LLC, Apache License 2.0.
Port: Narvy, same license for this file.
"""

from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Callable, Dict, List, Optional, Tuple


class InvalidVersion(ValueError):
    """The ecosystem helper refuses this version string (osv.dev Parse error)."""


class VersionMismatch(ValueError):
    """Two versions from different ecosystems were compared."""


# ---------------------------------------------------------------------------
# Shared helpers (semantic/utilities.go, semantic/version.go)
# ---------------------------------------------------------------------------

# Go's big.Int.SetString(s, 10): optional sign, ASCII digits, nothing else.
_BIGINT_RE = re.compile(r"[+-]?[0-9]+\Z")


def _bigint(s: str) -> Optional[int]:
    if _BIGINT_RE.match(s):
        return int(s)
    return None


def _atoi(s: str) -> Optional[int]:
    # strconv.Atoi: same accepted syntax as SetString for our purposes.
    return _bigint(s)


def _sign(x: int) -> int:
    return (x > 0) - (x < 0)


def _cmp_components(a: List[int], b: List[int]) -> int:
    n = max(len(a), len(b))
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        if x != y:
            return 1 if x > y else -1
    return 0


def _go_compare(a: str, b: str) -> int:
    # strings.Compare is byte-wise on UTF-8; code point order is the same.
    return (a > b) - (a < b)


def _is_ascii_digit(c: str) -> bool:
    return "0" <= c <= "9"


# ---------------------------------------------------------------------------
# SemVer-like (semantic/version-semver-like.go, version-semver.go)
# ---------------------------------------------------------------------------


def _parse_semver_like(line: str) -> Tuple[List[int], str]:
    comps: List[int] = []
    current = ""
    found_build = False
    if line.startswith("v"):
        line = line[1:]
    for c in line:
        if found_build:
            current += c
            continue
        if _is_ascii_digit(c):
            current += c
            continue
        if current != "":
            comps.append(int(current))
            current = ""
        if c == ".":
            continue
        found_build = True
        current = c
    if not found_build and current != "":
        comps.append(int(current))
        current = ""
    return comps, current


def _parse_semver_like_max(line: str, max_components: int) -> Tuple[List[int], str]:
    comps, build = _parse_semver_like(line)
    if max_components == -1 or len(comps) <= max_components:
        return comps, build
    extra = comps[max_components:]
    return comps[:max_components], build + "".join(".%d" % c for c in extra)


def _semver_prerelease_cmp(a: List[str], b: List[str]) -> int:
    for i in range(min(len(a), len(b))):
        ai, bi = _bigint(a[i]), _bigint(b[i])
        if ai is not None and bi is not None:
            c = _sign(ai - bi)
        elif ai is None and bi is None:
            c = _go_compare(a[i], b[i])
        elif ai is not None:
            c = -1
        else:
            c = 1
        if c != 0:
            return c
    if len(a) > len(b):
        return 1
    if len(a) < len(b):
        return -1
    return 0


def _compare_build_components(a: str, b: str) -> int:
    a = a.split("+")[0]
    b = b.split("+")[0]
    if a.startswith("-"):
        a = a[1:]
    if b.startswith("-"):
        b = b[1:]
    if a == "" and b != "":
        return 1
    if a != "" and b == "":
        return -1
    return _semver_prerelease_cmp(a.split("."), b.split("."))


class _Version:
    kind = ""

    def cmp(self, other: "_Version") -> int:  # pragma: no cover - abstract
        raise NotImplementedError

    def _check(self, other: "_Version") -> None:
        if type(other) is not type(self):
            raise VersionMismatch("%s vs %s" % (type(self).__name__, type(other).__name__))


class SemverVersion(_Version):
    __slots__ = ("components", "build")

    def __init__(self, s: str):
        self.components, self.build = _parse_semver_like_max(s, 3)

    def cmp(self, other: "_Version") -> int:
        self._check(other)
        d = _cmp_components(self.components, other.components)  # type: ignore[attr-defined]
        if d:
            return d
        return _compare_build_components(self.build, other.build)  # type: ignore[attr-defined]


class NuGetVersion(_Version):
    __slots__ = ("components", "build")

    def __init__(self, s: str):
        self.components, self.build = _parse_semver_like_max(s, 4)

    def cmp(self, other: "_Version") -> int:
        self._check(other)
        d = _cmp_components(self.components, other.components)  # type: ignore[attr-defined]
        if d:
            return d
        return _compare_build_components(self.build.lower(), other.build.lower())  # type: ignore[attr-defined]


class PubVersion(_Version):
    __slots__ = ("components", "build")

    def __init__(self, s: str):
        self.components, self.build = _parse_semver_like_max(s, 3)

    def cmp(self, other: "_Version") -> int:
        self._check(other)
        d = _cmp_components(self.components, other.components)  # type: ignore[attr-defined]
        if d:
            return d
        d = _compare_build_components(self.build, other.build)  # type: ignore[attr-defined]
        if d:
            return d
        vb = self.build.split("+", 1)[1] if "+" in self.build else ""
        wb = other.build.split("+", 1)[1] if "+" in other.build else ""  # type: ignore[attr-defined]
        return _go_compare(vb, wb)


# ---------------------------------------------------------------------------
# Maven (semantic/version-maven.go)
# ---------------------------------------------------------------------------

_MAVEN_D_TO_ND = re.compile(r"[^0-9][0-9]")
_MAVEN_ND_TO_D = re.compile(r"[0-9][^0-9]")
_MAVEN_KEYWORDS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]


class _MavenToken:
    __slots__ = ("prefix", "value", "is_null")

    def __init__(self, prefix: str, value: str, is_null: bool = False):
        self.prefix = prefix
        self.value = value
        self.is_null = is_null

    def equal(self, o: "_MavenToken") -> bool:
        return self.prefix == o.prefix and self.value == o.value

    def should_trim(self) -> bool:
        return self.value in ("0", "", "final", "ga")

    def qualifier_order(self) -> int:
        if _bigint(self.value) is not None:
            if self.prefix == "-":
                return 2
            if self.prefix == ".":
                return 3
        if self.prefix == "-":
            return 1
        if self.prefix == ".":
            return 0
        raise InvalidVersion("unknown prefix '%s'" % self.prefix)

    def less_than(self, o: "_MavenToken") -> bool:
        if self.prefix == o.prefix:
            vv, wv = _bigint(self.value), _bigint(o.value)
            if vv is not None and wv is not None:
                return vv < wv
            if vv is not None and not self.is_null:
                return False
            if wv is not None and not o.is_null:
                return True
            li = _MAVEN_KEYWORDS.index(self.value) if self.value in _MAVEN_KEYWORDS else len(_MAVEN_KEYWORDS)
            ri = _MAVEN_KEYWORDS.index(o.value) if o.value in _MAVEN_KEYWORDS else len(_MAVEN_KEYWORDS)
            if li == len(_MAVEN_KEYWORDS) and ri == len(_MAVEN_KEYWORDS):
                return self.value < o.value
            return li < ri
        return self.qualifier_order() < o.qualifier_order()


def _maven_null_token(token: _MavenToken) -> _MavenToken:
    if token.prefix == ".":
        return _MavenToken(".", "" if token.value == "sp" else "0", True)
    if token.prefix == "-":
        return _MavenToken("-", "", True)
    raise InvalidVersion("unknown prefix '%s' (value '%s')" % (token.prefix, token.value))


def _split_chars_inclusive(s: str, chars: str) -> List[str]:
    out: List[str] = []
    while True:
        m = -1
        for i, c in enumerate(s):
            if c in chars:
                m = i
                break
        if m < 0:
            break
        out.append(s[:m])
        out.append(s[m:m + 1])
        s = s[m + 1:]
    out.append(s)
    return out


def _maven_transitions(token: str) -> List[int]:
    ints = [m.start() + 1 for m in _MAVEN_D_TO_ND.finditer(token)]
    ints += [m.start() + 1 for m in _MAVEN_ND_TO_D.finditer(token)]
    ints.sort()
    return ints


class MavenVersion(_Version):
    __slots__ = ("tokens",)

    def __init__(self, s: str):
        tokens: List[_MavenToken] = []
        raw = _split_chars_inclusive(s, "-.")
        for i in range(0, len(raw), 2):
            prefix = "" if i == 0 else raw[i - 1]
            transitions = _maven_transitions(raw[i]) + [len(raw[i])]
            prev = 0
            for j, tr in enumerate(transitions):
                if j > 0:
                    prefix = "-"
                current = raw[i][prev:tr].lower()
                if current == "":
                    current = "0"
                if current == "cr":
                    current = "rc"
                if current in ("ga", "final", "release"):
                    current = ""
                if tr != len(raw[i]):
                    if current == "a":
                        current = "alpha"
                    if current == "b":
                        current = "beta"
                    if current == "m":
                        current = "milestone"
                d = _bigint(current)
                if d is not None:
                    current = str(d)
                tokens.append(_MavenToken(prefix, current))
                prev = tr
        i = len(tokens) - 1
        while i > 0:
            if tokens[i].should_trim():
                del tokens[i]
                i -= 1
                continue
            while i >= 0 and tokens[i].prefix != "-":
                i -= 1
            i -= 1
        self.tokens = tokens

    def _equal(self, o: "MavenVersion") -> bool:
        if len(self.tokens) != len(o.tokens):
            return False
        return all(a.equal(b) for a, b in zip(self.tokens, o.tokens))

    def _less_than(self, o: "MavenVersion") -> bool:
        n = max(len(self.tokens), len(o.tokens))
        for i in range(n):
            left = _maven_null_token(o.tokens[i]) if i >= len(self.tokens) else self.tokens[i]
            right = _maven_null_token(self.tokens[i]) if i >= len(o.tokens) else o.tokens[i]
            if left.equal(right):
                continue
            return left.less_than(right)
        return False

    def cmp(self, other: "_Version") -> int:
        self._check(other)
        if self._equal(other):  # type: ignore[arg-type]
            return 0
        return -1 if self._less_than(other) else 1  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# NuGet / Packagist (semantic/version-packagist.go)
# ---------------------------------------------------------------------------

_PKG_SEP = re.compile(r"[-_+]")
_PKG_ND_D = re.compile(r"([^0-9.])([0-9])")
_PKG_D_ND = re.compile(r"([0-9])([^0-9.])")
_PKG_SPECIALS = ["dev", "a", "b", "rc", "#", "p"]


def _canonicalize_packagist(v: str) -> str:
    if v.startswith("v"):
        v = v[1:]
    if v.startswith("V"):
        v = v[1:]
    v = _PKG_SEP.sub(".", v)
    v = _PKG_ND_D.sub(r"\1.\2", v)
    v = _PKG_D_ND.sub(r"\1.\2", v)
    return v


def _weigh_packagist(s: str) -> int:
    if s.startswith("RC"):
        return 3
    for i, sp in enumerate(_PKG_SPECIALS):
        if s.startswith(sp):
            return i
    return 0


def _cmp_packagist_special(a: str, b: str) -> int:
    return _sign(_weigh_packagist(a) - _weigh_packagist(b))


def _cmp_packagist_components(a: List[str], b: List[str]) -> int:
    for i in range(min(len(a), len(b))):
        ai, bi = _bigint(a[i]), _bigint(b[i])
        if ai is not None and bi is not None:
            c = _sign(ai - bi)
        elif ai is None and bi is None:
            c = _cmp_packagist_special(a[i], b[i])
        elif ai is not None:
            c = _cmp_packagist_special("#", b[i])
        else:
            c = _cmp_packagist_special(a[i], "#")
        if c != 0:
            return c
    if len(a) > len(b):
        if _atoi(a[len(b)]) is not None:
            return 1
        return _cmp_packagist_components(a[len(b):], ["#"])
    if len(a) < len(b):
        if _atoi(b[len(a)]) is not None:
            return -1
        return _cmp_packagist_components(["#"], b[len(a):])
    return 0


class PackagistVersion(_Version):
    __slots__ = ("components",)

    def __init__(self, s: str):
        self.components = _canonicalize_packagist(s).split(".")

    def cmp(self, other: "_Version") -> int:
        self._check(other)
        return _cmp_packagist_components(self.components, other.components)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# RubyGems (semantic/version-rubygems.go)
# ---------------------------------------------------------------------------


def _canonicalize_rubygem(s: str) -> str:
    out = []
    check_previous = False
    previous_was_digit = True
    for c in s:
        if c == ".":
            check_previous = False
            out.append(".")
            continue
        is_digit = _is_ascii_digit(c)
        if check_previous and previous_was_digit != is_digit:
            out.append(".")
        out.append(c)
        previous_was_digit = is_digit
        check_previous = True
    return "".join(out)


def _remove_zeros(segs: List[str]) -> List[str]:
    i = len(segs) - 1
    while i >= 0:
        if segs[i] != "0":
            i += 1
            break
        i -= 1
    return segs[:max(i, 0)]


def _canonical_segments(segs: List[str]) -> List[str]:
    numbers: List[str] = []
    build: List[str] = []
    for seg in segs:
        if build or _bigint(seg) is None:
            build.append(seg)
            continue
        numbers.append(seg)
    return _remove_zeros(numbers) + _remove_zeros(build)


class RubyGemsVersion(_Version):
    __slots__ = ("segments",)

    def __init__(self, s: str):
        self.segments = _canonical_segments(_canonicalize_rubygem(s).split("."))

    def cmp(self, other: "_Version") -> int:
        self._check(other)
        a, b = self.segments, other.segments  # type: ignore[attr-defined]
        for i in range(max(len(a), len(b))):
            as_ = a[i] if i < len(a) else "0"
            bs = b[i] if i < len(b) else "0"
            ai, bi = _bigint(as_), _bigint(bs)
            if ai is not None and bi is not None:
                if ai != bi:
                    return 1 if ai > bi else -1
            elif ai is None and bi is None:
                d = _go_compare(as_, bs)
                if d:
                    return d
            elif ai is not None:
                return 1
            else:
                return -1
        return 0


# ---------------------------------------------------------------------------
# PyPI (semantic/version-pypi.go)
# ---------------------------------------------------------------------------

_PYPI_LOCAL_SPLIT = re.compile(r"[._-]")
_PYPI_PARTS = re.compile(r"(\d+|[a-z]+|\.|-)")
_PYPI_RE = re.compile(
    r"^\s*v?(?:(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?P<pre>[-_\.]?(?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))[-_\.]?(?P<pre_n>[0-9]+)?)?"
    r"(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?"
    r"(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?)"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?\s*$",
    re.ASCII,
)


def _letter_version(letter: str, number: str) -> Tuple[str, Optional[int]]:
    if letter:
        if number == "":
            number = "0"
        letter = letter.lower()
        letter = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc",
                  "rev": "post", "r": "post"}.get(letter, letter)
        return letter, int(number)
    if number:
        return "post", int(number)
    return "", None


def _go_split(pattern: "re.Pattern[str]", s: str) -> List[str]:
    # regexp.Split(s, -1): an empty input yields [""] (same as re.split).
    return pattern.split(s)


def _pypi_legacy_parts(s: str) -> List[str]:
    parts: List[str] = []
    splits = _PYPI_PARTS.findall(s) + ["final"]
    for part in splits:
        if part in ("", "."):
            continue
        part = {"pre": "c", "preview": "c", "-": "final-", "rc": "c", "dev": "@"}.get(part, part)
        if _is_ascii_digit(part[0]):
            part = part.rjust(8, "0")
        else:
            part = "*" + part
        if part.startswith("*"):
            if part < "*final":
                while parts and parts[-1] == "*final-":
                    parts.pop()
            while parts and parts[-1] == "00000000":
                parts.pop()
        parts.append(part)
    return parts


class PyPIVersion(_Version):
    __slots__ = ("epoch", "release", "pre", "post", "dev", "local", "legacy")

    def __init__(self, s: str):
        s = s.lower()
        m = _PYPI_RE.match(s)
        if not m:
            self.epoch = -1
            self.release: List[int] = []
            self.pre = ("", None)
            self.post = ("", None)
            self.dev = ("", None)
            self.local: List[str] = []
            self.legacy = _pypi_legacy_parts(s)
            return
        self.legacy = []
        self.epoch = int(m.group("epoch")) if m.group("epoch") else 0
        self.release = [int(r) for r in m.group("release").split(".")]
        self.pre = _letter_version(m.group("pre_l") or "", m.group("pre_n") or "")
        post_n = m.group("post_n1") or m.group("post_n2") or ""
        self.post = _letter_version(m.group("post_l") or "", post_n)
        self.dev = _letter_version(m.group("dev_l") or "", m.group("dev_n") or "")
        self.local = [p.lower() for p in _go_split(_PYPI_LOCAL_SPLIT, m.group("local") or "")]

    def _pre_trick(self) -> bool:
        return self.pre[1] is None and self.post[1] is None and self.dev[1] is not None

    def cmp(self, other: "_Version") -> int:
        self._check(other)
        o: PyPIVersion = other  # type: ignore[assignment]
        # legacy
        if self.legacy or o.legacy:
            if not self.legacy:
                return 1
            if not o.legacy:
                return -1
            d = _go_compare("".join(self.legacy), "".join(o.legacy))
            if d:
                return d
        d = _sign(self.epoch - o.epoch)
        if d:
            return d
        d = _cmp_components(self.release, o.release)
        if d:
            return d
        # pre
        a_t, b_t = self._pre_trick(), o._pre_trick()
        if a_t and b_t:
            d = 0
        elif a_t:
            d = -1
        elif b_t:
            d = 1
        elif self.pre[1] is None and o.pre[1] is None:
            d = 0
        elif self.pre[1] is None:
            d = 1
        elif o.pre[1] is None:
            d = -1
        else:
            ai, bi = self.pre[0][0], o.pre[0][0]
            if ai != bi:
                d = 1 if ai > bi else -1
            else:
                d = _sign(self.pre[1] - o.pre[1])
        if d:
            return d
        # post
        if self.post[1] is None and o.post[1] is None:
            d = 0
        elif self.post[1] is None:
            d = -1
        elif o.post[1] is None:
            d = 1
        else:
            d = _sign(self.post[1] - o.post[1])
        if d:
            return d
        # dev
        if self.dev[1] is None and o.dev[1] is None:
            d = 0
        elif self.dev[1] is None:
            d = 1
        elif o.dev[1] is None:
            d = -1
        else:
            d = _sign(self.dev[1] - o.dev[1])
        if d:
            return d
        # local
        for x, y in zip(self.local, o.local):
            xi, yi = _bigint(x), _bigint(y)
            if xi is not None and yi is not None:
                c = _sign(xi - yi)
            elif xi is None and yi is None:
                c = _go_compare(x, y)
            elif xi is not None:
                c = 1
            else:
                c = -1
            if c:
                return c
        return _sign(len(self.local) - len(o.local))


# ---------------------------------------------------------------------------
# osv.dev ecosystem wrapper (go/osv/ecosystem/wrapper.go): "0" is below all
# ---------------------------------------------------------------------------


class _Zero(_Version):
    __slots__ = ()


def _packagist_parse(s: str) -> _Version:
    if "#" in s:
        raise InvalidVersion("packagist version may not contain '#'")
    return PackagistVersion(s)


_PARSERS: Dict[str, Callable[[str], _Version]] = {
    "npm": SemverVersion,
    "Go": SemverVersion,
    "crates.io": SemverVersion,
    "SwiftURL": SemverVersion,
    "Hex": SemverVersion,
    "Bitnami": SemverVersion,
    "Julia": SemverVersion,
    "NuGet": NuGetVersion,
    "Pub": PubVersion,
    "Maven": MavenVersion,
    "PyPI": PyPIVersion,
    "RubyGems": RubyGemsVersion,
    "Packagist": _packagist_parse,
}


def base_ecosystem(ecosystem: str) -> str:
    return (ecosystem or "").split(":", 1)[0]


def supports(ecosystem: str) -> bool:
    """True when osv.dev has an ordered-ecosystem helper we ported."""
    return base_ecosystem(ecosystem) in _PARSERS


def parse(ecosystem: str, version: str) -> _Version:
    """osv.dev `Ecosystem.Parse` (wrapped). Raises InvalidVersion / KeyError."""
    if version == "0":
        return _Zero()
    return _PARSERS[base_ecosystem(ecosystem)](version)


def compare(a: _Version, b: _Version) -> int:
    """-1 / 0 / +1. Raises VersionMismatch on mixed ecosystems."""
    az, bz = isinstance(a, _Zero), isinstance(b, _Zero)
    if az or bz:
        if az and bz:
            return 0
        return -1 if az else 1
    return a.cmp(b)


def compare_str(ecosystem: str, a: str, b: str) -> int:
    return compare(parse(ecosystem, a), parse(ecosystem, b))


def sort_key(ecosystem: str):
    """functools key for sorting version strings in `ecosystem` order."""
    return cmp_to_key(lambda x, y: compare_str(ecosystem, x, y))


# ---------------------------------------------------------------------------
# Coarse versions (go/osv/ecosystem/util.go + per-ecosystem Coarse())
# ---------------------------------------------------------------------------

_MAX_PART = 99999999
_COARSE_MIN = "00:00000000.00000000.00000000"
_COARSE_MAX = "99:99999999.99999999.99999999"
_IMPLICIT = re.compile(r"[0-9]+|[^0-9]+")


def _is_decimal(s: str) -> bool:
    return s != "" and all(_is_ascii_digit(c) for c in s)


def _coarse_from_ints(epoch: int, parts: List[int]) -> str:
    if epoch < 0:
        return _COARSE_MIN
    if epoch > 99:
        return _COARSE_MAX
    strs: List[str] = []
    for p in parts:
        if len(strs) >= 3:
            break
        if p < 0:
            while len(strs) < 3:
                strs.append("00000000")
            break
        if p > _MAX_PART:
            while len(strs) < 3:
                strs.append("99999999")
            break
        strs.append("%08d" % p)
    while len(strs) < 3:
        strs.append("00000000")
    return "%02d:%s" % (epoch, ".".join(strs))


def _coarse_format(version: str, sep: str, truncate: Optional[str], implicit: bool,
                   empty_as: Optional[str], epoch: int = 0) -> str:
    if version == "0":
        return _coarse_from_ints(epoch, [0, 0, 0])
    main = version
    if truncate is not None:
        main = re.split(truncate, version, maxsplit=1)[0]
    parts = re.split(sep, main)
    if implicit:
        split_parts: List[str] = []
        for part in parts:
            if part == "":
                split_parts.append("")
                continue
            split_parts.extend(_IMPLICIT.findall(part))
        parts = split_parts
    if empty_as is not None:
        parts = [p if p != "" else empty_as for p in parts]
    else:
        parts = [p for p in parts if p != ""]
    comps: List[int] = []
    for p in parts:
        if len(comps) >= 3:
            break
        if not _is_decimal(p):
            break
        comps.append(int(p))
    return _coarse_from_ints(epoch, comps)


def _coarse_semver(v: str) -> str:
    return _coarse_format(v[1:] if v.startswith("v") else v, r"[.]", r"[-+]", True, None)


def _coarse_maven(v: str) -> str:
    return _coarse_format(v, r"[.]", r"-", True, "0")


def _coarse_rubygems(v: str) -> str:
    return _coarse_format(v, r"[.]", r"-", True, "")


_PYPI_CANON = re.compile(
    r"^\s*v?(?:(?:([0-9]+)!)?((?:[0-9]+(?:\.[0-9]+)*)(?:[-_\.]?(?:(?:a|b|c|rc|alpha|beta|pre|preview))"
    r"[-_\.]?(?:[0-9]+)?)?(?:(?:-(?:[0-9]+))|(?:[-_\.]?(?:post|rev|r)[-_\.]?(?:[0-9]+)?))?"
    r"(?:[-_\.]?(?:dev)[-_\.]?(?:[0-9]+)?)?)(?:\+(?:[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?)\s*$",
    re.ASCII,
)


def _coarse_pypi(v: str) -> str:
    v = v.lower()
    m = _PYPI_CANON.search(v)
    if not m:
        return _COARSE_MIN
    epoch_s = (m.group(1) or "").lstrip("0") or "0"
    if len(epoch_s) > 2:
        return _COARSE_MAX
    return _coarse_format(m.group(2), r"[.]", r"[+_-]", True, None, epoch=int(epoch_s))


_PKG_COARSE_SEP = re.compile(r"[-_+.]")


def _coarse_packagist(v: str) -> str:
    if "#" in v:
        raise InvalidVersion("packagist version may not contain '#'")
    if v.startswith("v"):
        v = v[1:]
    if v.startswith("V"):
        v = v[1:]
    parts: List[str] = []
    for sp in _PKG_COARSE_SEP.split(v):
        if sp == "":
            parts.append("")
            continue
        parts.extend(_IMPLICIT.findall(sp))
    comps: List[int] = []
    for p in parts:
        if len(comps) >= 3:
            break
        if p.startswith("p"):
            comps.append(100000000)
        elif not _is_decimal(p):
            break
        else:
            comps.append(int(p))
    return _coarse_from_ints(0, comps)


_COARSE: Dict[str, Callable[[str], str]] = {
    "npm": _coarse_semver, "Go": _coarse_semver, "crates.io": _coarse_semver,
    "SwiftURL": _coarse_semver, "Hex": _coarse_semver, "Bitnami": _coarse_semver,
    "Julia": _coarse_semver, "NuGet": _coarse_semver, "Pub": _coarse_semver,
    "Maven": _coarse_maven, "RubyGems": _coarse_rubygems, "PyPI": _coarse_pypi,
    "Packagist": _coarse_packagist,
}

COARSE_MIN = _COARSE_MIN
COARSE_MAX = _COARSE_MAX


def coarse(ecosystem: str, version: str) -> str:
    """osv.dev `Ecosystem.Coarse`. Raises InvalidVersion / KeyError."""
    return _COARSE[base_ecosystem(ecosystem)](version)


# ---------------------------------------------------------------------------
# Package-name normalisation (Ecosystem.NormalizePackageName)
# ---------------------------------------------------------------------------

_PYPI_NAME = re.compile(r"[-_.]+")


def normalize_package_name(ecosystem: str, name: str) -> str:
    if base_ecosystem(ecosystem) == "PyPI":
        return _PYPI_NAME.sub("-", name).lower()
    return name
