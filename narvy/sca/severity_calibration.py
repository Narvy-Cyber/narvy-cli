"""SCA severity calibration: a byte-for-byte port of the platform's
src/sast_shared/sca_severity.py (narvy.io, origin/main 4fb5d1643) so that a
dependency finding gets the same severity in the CLI as on the dashboard.
Keep in sync with that file; the original docstring follows.

SCA (vulnerable dependency) severity calibration (2026-09-26).

WHY: the 2026-09-26 precision audit (docs/PRECISION_AUDIT_2026-09-26.md)
measured SCA at 79.6 % precision but 13 of its 39 true positives were rated
two or more levels too high; on production apps it was 5 of 9. Every one of
those findings was a real CVE on a real version: the CVE was right, the
severity was not. The causes, read off the judges' verdicts:

  * the advisory rating came from the worst score across every mirror of the
    CVE (an NVD/PYSEC network-vector 7.5 beat the GitHub-reviewed "LOW" or
    "MODERATE" for the same CVE: certifi, idna, Jinja2);
  * dev-only packages (package-lock ``dev: true``) were rated like runtime
    code (uptime-kuma undici / uuid / minimatch);
  * the vulnerable sub-package of a Go module was never imported
    (golang.org/x/crypto/openpgp in miniflux);
  * with no lockfile, the lower bound of a range (``^6.37.3``) was taken as
    the installed version although a fixed release satisfies the range, so a
    fresh install resolves to a patched version (8 juice-shop false alarms).

This module maps "advisory severity + context" to the severity we show. It
never drops a finding and never deletes a CVE: the advisory's own rating is
kept on the finding (``severity_advisory``) with the list of reasons the
shown severity differs (``severity_calibration``). The default view then
decides visibility (src/sast_shared/default_view.py): a calibrated Low on a
CONFIRMED version (lockfile or exact pin) stays visible; a Low whose version
is only a declared-range guess is hidden by default (still counted, still in
"Show all" and in exports).

Mapping, applied in order (full table: docs/SCA_SEVERITY_POLICY.md):

 1. Per advisory: the GitHub-reviewed label (GHSA database_specific.severity)
    when a GHSA record exists for the CVE, else the CVSS v3 base score
    (>=9 Critical, >=7 High, >=4 Medium, >0 Low), else the database label.
    Without a reviewed label, an AV:L / AV:P vector (attacker needs local or
    physical access to the host running the dependency) caps at Medium.
 2. Declared range, no lockfile: a CVE whose fixed version satisfies the
    declared range is "likely patched on install" and does not drive the
    severity. If EVERY CVE of the finding is in that case, the finding is Low
    (``fix_within_declared_range``).
 3. Base = worst remaining advisory severity.
 4. Dev-only dependency (the lockfile / manifest says so): capped at Low
    (``dev_dependency``). Not shipped to the production runtime.
 4b. Build-only dependency (2026-10-09, src/web/sca/dep_graph_scope.py): the
    lockfile graph reaches the package only through build tooling (bundlers,
    compilers, CSS processors, linters, test runners) or from a static-site
    workspace (Docusaurus, Next.js static export). No deployed server process
    runs it: capped at Low (``build_only_dependency``).
 5. Go: the advisory lists the affected import paths and none of them is
    imported by first-party code: capped at Low
    (``affected_package_not_imported``). Another dependency may still import
    it, so it stays a finding, never Info.
 1b. (2026-10-10, src/web/sca/advisory_preconditions.py) an advisory listed
    with a precondition (proxy-addr trust subnet, ws server, nanoid custom /
    non-secure generators) whose precondition is not found statically, with
    no run-time configuration signal and only first-party / allowed
    dependents: that advisory is capped at Medium
    (``advisory_precondition_not_found``).
"""

from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional, Sequence, Set, Tuple

SEV_ORDER = ("Info", "Low", "Medium", "High", "Critical")
_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

REASON_FIX_IN_RANGE = "fix_within_declared_range"
REASON_DEV = "dev_dependency"
REASON_BUILD = "build_only_dependency"
REASON_NOT_IMPORTED = "affected_package_not_imported"
REASON_LOCAL_VECTOR = "local_attack_vector"
REASON_REVIEWED = "reviewed_advisory_rating"
REASON_PRECONDITION = "advisory_precondition_not_found"

# EN notes stored on the finding (JSON / SARIF exports). The page renders its
# own EN/FR label keyed on the reason ids.
REASON_NOTES_EN = {
    REASON_FIX_IN_RANGE: (
        "A fixed release satisfies the declared version range: a fresh install "
        "most likely resolves to a patched version. Commit a lockfile to confirm."
    ),
    REASON_DEV: "Development-only dependency: not shipped with the application.",
    REASON_BUILD: (
        "Only reached through build tooling or a static-site build: no deployed "
        "server process runs this package."
    ),
    REASON_NOT_IMPORTED: (
        "The affected package is not imported by the application's own code "
        "(it may still be reached through another dependency)."
    ),
    REASON_LOCAL_VECTOR: (
        "Exploitation needs local or physical access to the host running the "
        "dependency (CVSS attack vector L/P)."
    ),
    REASON_REVIEWED: (
        "Rated with the GitHub-reviewed advisory severity instead of the "
        "highest mirror score."
    ),
    REASON_PRECONDITION: (
        "The advisory only applies when the application uses a specific feature, "
        "and that use was not found in the application's code (run-time "
        "configuration cannot be ruled out): rated Medium."
    ),
}


def canonical(sev: Optional[str]) -> str:
    s = str(sev or "").strip().upper()
    return {
        "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
        "MODERATE": "Medium", "LOW": "Low", "INFO": "Info",
        "INFORMATIONAL": "Info", "NONE": "Info",
    }.get(s, "Medium")


def rank(sev: Optional[str]) -> int:
    return _RANK.get(canonical(sev), _RANK["Medium"])


def cap(sev: str, ceiling: str) -> str:
    return sev if rank(sev) <= rank(ceiling) else canonical(ceiling)


def worst(sevs: Iterable[str]) -> Optional[str]:
    best: Optional[str] = None
    for s in sevs:
        if best is None or rank(s) > rank(best):
            best = canonical(s)
    return best


def _attack_vector(vector: str) -> str:
    m = re.search(r"(?:^|/)AV:([NALP])(?:/|$)", vector or "")
    return m.group(1) if m else ""


def advisory_severity(osv_severity: str, reviewed_severity: str = "",
                      cvss_vector: str = "") -> Tuple[str, List[str]]:
    """Severity of ONE advisory record (step 1). Returns (severity, reasons)."""
    if reviewed_severity:
        sev = canonical(reviewed_severity)
        reasons = [REASON_REVIEWED] if rank(sev) < rank(osv_severity) else []
        return sev, reasons
    sev = canonical(osv_severity)
    if _attack_vector(cvss_vector) in ("L", "P") and rank(sev) > rank("Medium"):
        return "Medium", [REASON_LOCAL_VECTOR]
    return sev, []


# ---------------------------------------------------------------------------
# Version ranges (npm / Composer). Only what the manifest parsers accept.
# ---------------------------------------------------------------------------

_VER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?"
    r"(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]*)?$")


def parse_version(v: str) -> Optional[Tuple[Tuple[int, int, int], Tuple]]:
    """(release, prerelease-key) comparable key; None when unparseable.
    A release sorts after its own prereleases (1.0.0-rc.1 < 1.0.0)."""
    m = _VER_RE.match(str(v or "").strip())
    if not m:
        return None
    parts = []
    for g in m.group(1, 2, 3):
        parts.append(int(g) if g and g.isdigit() else 0)
    pre = m.group(4)
    if pre:
        pre_key: Tuple = (0,) + tuple(
            (0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    else:
        pre_key = (1,)
    return (parts[0], parts[1], parts[2]), pre_key


def _upper_bound(spec: str, ecosystem: str) -> Tuple[Optional[str], Optional[Tuple[int, int, int]]]:
    """(lower_bound, exclusive upper release) for a declared range.
    upper None = unbounded above. Raises ValueError when the spec is not a
    shape we understand (the caller then keeps the advisory severity)."""
    spec = (spec or "").strip()
    if not spec or any(t in spec for t in ("||", " - ", ",", "<")):
        raise ValueError(spec)
    if "|" in spec or " " in spec:
        raise ValueError(spec)
    op_m = re.match(r"^(\^|~>|~|>=|>|=)?\s*(.+)$", spec)
    if not op_m:
        raise ValueError(spec)
    op, ver = op_m.group(1) or "", op_m.group(2)
    m = _VER_RE.match(ver)
    if not m:
        raise ValueError(spec)
    raw = [g for g in m.group(1, 2, 3)]
    nums = [int(g) if g and g.isdigit() else None for g in raw]
    major, minor, patch = nums
    given = sum(1 for n in nums if n is not None)
    lower = ".".join(str(n if n is not None else 0) for n in nums)
    if m.group(4):
        lower = f"{lower}-{m.group(4)}"
    if op in (">=", ">"):
        return lower, None
    if op == "=" or (op == "" and given == 3):
        # Exact version: the only admissible release is the version itself.
        return lower, (major, minor or 0, (patch or 0) + 1)
    if op == "^":
        if major > 0 or given == 1:
            return lower, (major + 1, 0, 0)
        if (minor or 0) > 0 or given == 2:
            return lower, (0, (minor or 0) + 1, 0)
        return lower, (0, 0, (patch or 0) + 1)
    if op in ("~", "~>"):
        if ecosystem == "Packagist" and given == 2:
            # Composer ~1.2 == >=1.2 <2.0 (npm ~1.2 == <1.3).
            return lower, (major + 1, 0, 0)
        if given == 1:
            return lower, (major + 1, 0, 0)
        return lower, (major, (minor or 0) + 1, 0)
    # Bare x-range / partial: "1", "1.x", "1.2", "1.2.*".
    if given == 1:
        return lower, (major + 1, 0, 0)
    if given == 2:
        return lower, (major, (minor or 0) + 1, 0)
    raise ValueError(spec)


def fix_within_range(spec: str, fixed_version: Optional[str], ecosystem: str) -> Optional[bool]:
    """True when `fixed_version` satisfies the declared range `spec` (a fresh
    install can resolve to it), False when it does not, None when unknown."""
    if not spec or not fixed_version:
        return None if not spec else False
    try:
        lower, upper = _upper_bound(spec, ecosystem)
    except ValueError:
        return None
    fk = parse_version(fixed_version)
    lk = parse_version(lower or "")
    if fk is None or lk is None:
        return None
    if fk < lk:
        return False
    if upper is None:
        return True
    # Exclusive upper bound on the release triple; a prerelease of the upper
    # release (2.0.0-rc.1) is excluded by npm unless opted in, so compare on
    # the release tuple only.
    return fk[0] < upper


# ---------------------------------------------------------------------------
# Go first-party imports
# ---------------------------------------------------------------------------

_GO_IMPORT_BLOCK = re.compile(r"^import\s*\((.*?)^\)", re.MULTILINE | re.DOTALL)
_GO_IMPORT_LINE = re.compile(r'^import\s+(?:[\w.]+\s+)?"([^"]+)"', re.MULTILINE)
_GO_QUOTED = re.compile(r'"([^"]+)"')
_GO_SKIP_DIRS = {"vendor", ".git", "node_modules", "testdata", "third_party"}


def go_first_party_imports(root: str, max_files: int = 20000) -> Set[str]:
    """Import paths used by the repository's own .go files (vendor/ and
    testdata/ excluded). Bounded; returns what it read so far on overflow."""
    found: Set[str] = set()
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _GO_SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".go"):
                continue
            n += 1
            if n > max_files:
                return found
            try:
                with open(os.path.join(dirpath, fn), "r", encoding="utf-8",
                          errors="ignore") as fh:
                    text = fh.read(200_000)
            except OSError:
                continue
            for block in _GO_IMPORT_BLOCK.findall(text):
                found.update(_GO_QUOTED.findall(block))
            found.update(_GO_IMPORT_LINE.findall(text))
    return found


def imports_affected(affected_imports: Sequence[str], imports: Set[str]) -> Optional[bool]:
    """None when the advisory lists no affected import path (unknown)."""
    if not affected_imports:
        return None
    return any(p in imports for p in affected_imports)


# ---------------------------------------------------------------------------
# Steps 3-5
# ---------------------------------------------------------------------------

def calibrate(base: str, *, all_patched_within_range: bool = False,
              scope: str = "unknown", affected_imported: Optional[bool] = None,
              ) -> Tuple[str, List[str]]:
    """Final shown severity from the advisory base and the context."""
    sev = canonical(base)
    reasons: List[str] = []
    if all_patched_within_range and rank(sev) > rank("Low"):
        sev = "Low"
        reasons.append(REASON_FIX_IN_RANGE)
    if scope == "dev" and rank(sev) > rank("Low"):
        sev = "Low"
        reasons.append(REASON_DEV)
    if scope == "build" and rank(sev) > rank("Low"):
        sev = "Low"
        reasons.append(REASON_BUILD)
    if affected_imported is False and rank(sev) > rank("Low"):
        sev = "Low"
        reasons.append(REASON_NOT_IMPORTED)
    return sev, reasons
