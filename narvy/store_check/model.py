"""Result model shared by every check.

A check never guesses. It returns one of four statuses:

* ``fail``            the rule is violated, with evidence taken from the binary
* ``pass``            the rule was evaluated and is satisfied
* ``not_determined``  the binary does not contain enough information to decide
* ``not_applicable``  the rule does not apply to this binary

``severity`` is only meaningful for ``fail`` (and is kept on other statuses so a
consumer knows how bad a failure of that check would be).

Two texts name a result:

* ``title``        what this run found, worded for its status and citing the
                   value read when it helps ("Target API 33 is below Google
                   Play's requirement (API 36)"). Since engine 0.2.0.
* ``requirement``  the rule itself, the same for every status ("Target API
                   level meets Google Play's current requirement"). Engine
                   0.1.0 put this text in ``title`` for every status, which
                   read as a contradiction on a failure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

BLOCKER = "blocker"
WARNING = "warning"
INFO = "info"
SEVERITIES = (BLOCKER, WARNING, INFO)

FAIL = "fail"
PASS = "pass"
NOT_DETERMINED = "not_determined"
NOT_APPLICABLE = "not_applicable"
STATUSES = (FAIL, PASS, NOT_DETERMINED, NOT_APPLICABLE)


@dataclass
class Evidence:
    """A concrete fact read from the binary: where, and what value."""

    path: str
    value: str = ""
    detail: str = ""

    def to_dict(self) -> Dict[str, str]:
        d = {"path": self.path, "value": self.value}
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class Result:
    check_id: str
    status: str
    severity: str
    title: Dict[str, str]
    message: Dict[str, str]
    doc_url: str
    evidence: List[Evidence] = field(default_factory=list)
    extra_doc_urls: List[str] = field(default_factory=list)
    requirement: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"bad status {self.status!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}")
        for d in (self.title, self.message, self.requirement):
            if not d.get("en") or not d.get("fr"):
                raise ValueError(f"{self.check_id}: EN and FR text are both required")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.check_id,
            "status": self.status,
            "severity": self.severity,
            "title": self.title,
            "requirement": self.requirement,
            "message": self.message,
            "doc_url": self.doc_url,
            "extra_doc_urls": list(self.extra_doc_urls),
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class Report:
    tool_version: str
    input_name: str
    input_sha256: str
    platform: str  # "android" | "ios"
    container: str  # "apk" | "aab" | "apks" | "ipa"
    as_of: str
    app: Dict[str, Optional[str]]
    results: List[Result]
    notes: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        c = {"blocker": 0, "warning": 0, "info": 0, "pass": 0, "not_determined": 0, "not_applicable": 0}
        for r in self.results:
            if r.status == FAIL:
                c[r.severity] += 1
            else:
                c[r.status] += 1
        return c

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "narvy-store-check",
            "tool_version": self.tool_version,
            "input": {"name": self.input_name, "sha256": self.input_sha256},
            "platform": self.platform,
            "container": self.container,
            "as_of": self.as_of,
            "app": self.app,
            "summary": self.counts(),
            "results": [r.to_dict() for r in self.results],
            "notes": list(self.notes),
        }


def make(check_id: str, status: str, severity: str, requirement: Dict[str, str], doc_url: str,
         en: str, fr: str, evidence: Optional[List[Evidence]] = None,
         extra_doc_urls: Optional[List[str]] = None, *, title: Dict[str, str]) -> Result:
    return Result(check_id=check_id, status=status, severity=severity, title=title,
                  message={"en": en, "fr": fr}, doc_url=doc_url,
                  evidence=list(evidence or []), extra_doc_urls=list(extra_doc_urls or []),
                  requirement=requirement)
