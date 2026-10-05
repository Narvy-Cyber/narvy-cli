"""Command line interface: ``narvy-store-check <file> [--json] [--lang fr]``.

Exit codes: 0 = no blocker found, 1 = at least one blocker (or, with
--fail-on warning, at least one warning), 2 = the file could not be analysed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from typing import List, Optional

from . import __version__
from .analyze import InputError, analyze
from .model import BLOCKER, FAIL, INFO, NOT_APPLICABLE, NOT_DETERMINED, PASS, WARNING, Report

LABELS = {
    "en": {FAIL: {BLOCKER: "BLOCKER", WARNING: "WARNING", INFO: "INFO"}, PASS: "PASS",
           NOT_DETERMINED: "NOT DETERMINED", NOT_APPLICABLE: "N/A",
           "summary": "Summary", "blockers": "blocker(s)", "warnings": "warning(s)", "infos": "info",
           "nd": "not determined", "evidence": "evidence", "doc": "doc", "as_of": "requirements as of",
           "verdict_block": "NOT READY: at least one blocker", "verdict_ok": "No blocker found by these checks",
           "scope": "Deterministic checks only. Not a security scan.", "colon": ": "},
    "fr": {FAIL: {BLOCKER: "BLOQUANT", WARNING: "AVERTISSEMENT", INFO: "INFO"}, PASS: "OK",
           NOT_DETERMINED: "NON DÉTERMINÉ", NOT_APPLICABLE: "N/A",
           "summary": "Résumé", "blockers": "bloquant(s)", "warnings": "avertissement(s)", "infos": "info",
           "nd": "non déterminé(s)", "evidence": "preuve", "doc": "doc", "as_of": "exigences au",
           "verdict_block": "PAS PRÊT : au moins un point bloquant", "verdict_ok": "Aucun point bloquant trouvé par ces contrôles",
           "scope": "Contrôles déterministes uniquement. Ce n'est pas un scan de sécurité.", "colon": " : "},
}


def _label(lang: str, status: str, severity: str) -> str:
    L = LABELS[lang]
    if status == FAIL:
        return L[FAIL][severity]
    return L[status]


def render_text(report: Report, lang: str = "en", verbose: bool = False) -> str:
    L = LABELS[lang]
    a = report.app
    out: List[str] = []
    out.append(f"narvy-store-check {report.tool_version}  |  {report.input_name}  ({report.platform}/{report.container})")
    ident = " ".join(f"{k}={v}" for k, v in a.items() if v not in (None, ""))
    out.append(f"  {ident}")
    out.append(f"  {L['as_of']} {report.as_of}  |  sha256 {report.input_sha256[:16]}...")
    out.append("")
    order = {FAIL: 0, NOT_DETERMINED: 1, PASS: 2, NOT_APPLICABLE: 3}
    sev_order = {BLOCKER: 0, WARNING: 1, INFO: 2}
    for r in sorted(report.results, key=lambda r: (order[r.status], sev_order[r.severity], r.check_id)):
        if r.status == NOT_APPLICABLE and not verbose:
            continue
        out.append(f"[{_label(lang, r.status, r.severity)}] {r.check_id}: {r.title[lang]}")
        out.append(f"    {r.message[lang]}")
        if r.status in (FAIL, NOT_DETERMINED) or verbose:
            shown = r.evidence if verbose else r.evidence[:8]
            for e in shown:
                line = f"    - {L['evidence']}{L['colon']}{e.path}"
                if e.value:
                    line += f" = {e.value}"
                if e.detail:
                    line += f" ({e.detail})"
                out.append(line)
            if len(r.evidence) > len(shown):
                out.append(f"    - ... +{len(r.evidence) - len(shown)} (--verbose / --json)")
            out.append(f"    {L['doc']}{L['colon']}{r.doc_url}")
        out.append("")
    c = report.counts()
    out.append(f"{L['summary']}{L['colon']}{c['blocker']} {L['blockers']}, {c['warning']} {L['warnings']}, "
               f"{c['info']} {L['infos']}, {c['not_determined']} {L['nd']}")
    out.append(L["verdict_block"] if c["blocker"] else L["verdict_ok"])
    for n in report.notes:
        out.append(f"note: {n}")
    out.append(L["scope"])
    return "\n".join(out)


DESCRIPTION = ("Deterministic App Store / Google Play readiness checks for APK, AAB, split-APK sets and IPA. "
               "Offline: no network, no telemetry, nothing written to disk.")


def add_arguments(p: argparse.ArgumentParser) -> None:
    """Options shared by ``narvy-store-check`` and ``narvy store-check``."""
    p.add_argument("file", help="APK, AAB, .apks/.xapk/.apkm or IPA")
    p.add_argument("--json", action="store_true", help="print the JSON report (both languages)")
    p.add_argument("--lang", choices=("en", "fr"), default="en", help="language of the human output")
    p.add_argument("--as-of", metavar="YYYY-MM-DD", help="evaluate store requirements at this date (default: today)")
    p.add_argument("--fail-on", choices=("blocker", "warning"), default="blocker",
                   help="exit 1 when a finding of this severity or higher fails")
    p.add_argument("--verbose", action="store_true", help="show passing evidence and not-applicable checks")


def run(args: argparse.Namespace, parser: argparse.ArgumentParser, input_error_code: int = 2) -> int:
    """Analyse ``args.file`` and print the report. Returns the exit code."""
    as_of = None
    if args.as_of:
        try:
            as_of = dt.date.fromisoformat(args.as_of)
        except ValueError:
            parser.error("--as-of must be YYYY-MM-DD")
    try:
        report = analyze(args.file, as_of=as_of)
    except InputError as exc:
        if args.json:
            print(json.dumps({"tool": "narvy-store-check", "tool_version": __version__, "error": str(exc)}, indent=2))
        else:
            print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return input_error_code
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(render_text(report, args.lang, args.verbose))
    c = report.counts()
    if c["blocker"] or (args.fail_on == "warning" and c["warning"]):
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="narvy-store-check", description=DESCRIPTION, allow_abbrev=False)
    add_arguments(p)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return run(p.parse_args(argv), p)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
