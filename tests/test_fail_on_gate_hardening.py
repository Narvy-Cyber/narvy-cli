"""--fail-on: exit 0 clean, 1 threshold hit, 2 when the gate can't be evaluated."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy.main import _exit_on_fail_on  # noqa: E402
from narvy.web.scanner import NucleiScanner  # noqa: E402

ALL_THRESHOLDS = ["critical", "high", "medium", "low", "any"]


def _exit_code(findings, fail_on, **kwargs):
    """Run the gate and return the exit code it would give a CI runner."""
    try:
        _exit_on_fail_on(findings, fail_on, **kwargs)
    except SystemExit as e:
        return e.code
    return 0


@pytest.mark.parametrize("bad_severity", [
    "WARNING",
    "ERROR",
    "UNKNOWN",
    "warn",
    "",
    None,
    9.8,            # a raw CVSS score instead of a bucket
])
@pytest.mark.parametrize("threshold", ALL_THRESHOLDS)
def test_unrankable_severity_fails_closed(bad_severity, threshold):
    findings = [{"severity": bad_severity, "name": "x"}]
    assert _exit_code(findings, threshold) == 1


def test_unrankable_severity_is_silent_without_a_gate():
    """No --fail-on means no gate."""
    assert _exit_code([{"severity": "WARNING"}], None) == 0


def test_known_severities_still_rank_in_both_spellings():
    """SAST emits CRITICAL, web and cloud emit critical. One threshold, both."""
    assert _exit_code([{"severity": "CRITICAL"}], "critical") == 1
    assert _exit_code([{"severity": "critical"}], "critical") == 1
    assert _exit_code([{"severity": "HIGH"}], "critical") == 0
    assert _exit_code([{"severity": "HIGH"}], "high") == 1
    assert _exit_code([{"severity": "LOW"}], "any") == 1
    assert _exit_code([], "any") == 0


def test_surrounding_whitespace_is_not_an_unrankable_severity():
    """' Critical ' is the same severity as 'critical'."""
    assert _exit_code([{"severity": " Critical "}], "critical") == 1


def test_one_unrankable_finding_fails_even_among_ranked_ones():
    findings = [{"severity": "LOW"}, {"severity": "WARNING"}]
    assert _exit_code(findings, "critical") == 1


GAP = ["The deep structural (Semgrep) pass did not run at all."]


@pytest.mark.parametrize("threshold", ALL_THRESHOLDS)
def test_coverage_gap_refuses_to_pass_the_build(threshold):
    assert _exit_code([], threshold, coverage_gaps=GAP) == 2


def test_coverage_gap_does_not_downgrade_a_real_breach():
    """A tripped gate stays exit 1: a real breach outranks a coverage gap."""
    assert _exit_code([{"severity": "HIGH"}], "high", coverage_gaps=GAP) == 1


def test_coverage_gap_below_threshold_is_still_exit_2():
    """A HIGH under --fail-on critical is not a breach, but it is not a pass either."""
    assert _exit_code([{"severity": "HIGH"}], "critical", coverage_gaps=GAP) == 2


def test_coverage_gap_is_inert_without_a_gate():
    """Scanning without --fail-on is unaffected."""
    assert _exit_code([], None, coverage_gaps=GAP) == 0


def test_no_coverage_gap_keeps_the_clean_zero():
    assert _exit_code([], "any", coverage_gaps=[]) == 0
    assert _exit_code([], "any", coverage_gaps=None) == 0


def _probe_with(monkeypatch, side_effect):
    scanner = NucleiScanner.__new__(NucleiScanner)  # no binary resolution needed
    monkeypatch.setattr("narvy.web.ssrf_guard.safe_get", side_effect)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    return scanner._probe_rate_limited("http://target.example")


def test_probe_reports_unreachable_when_every_request_raises(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("connection timed out")
    probe = _probe_with(monkeypatch, boom)
    assert probe["unreachable"] is True
    assert probe["limited"] is False   # no status code ever came back
    assert probe["statuses"] == []


def test_probe_does_not_call_a_throttled_target_unreachable(monkeypatch):
    class Resp:
        status_code = 429
    probe = _probe_with(monkeypatch, lambda *_a, **_k: Resp())
    assert probe["unreachable"] is False
    assert probe["limited"] is True


def test_probe_does_not_call_a_healthy_target_unreachable(monkeypatch):
    class Resp:
        status_code = 200
    probe = _probe_with(monkeypatch, lambda *_a, **_k: Resp())
    assert probe["unreachable"] is False
    assert probe["limited"] is False


def test_rate_limit_floor_cannot_be_escaped_with_a_minus_sign():
    """A negative --rate-limit can't bypass WEB_MAX_RATE_LIMIT."""
    from narvy.main import WEB_MAX_RATE_LIMIT
    for asked, expected in [(-1, 1), (-50, 1), (0, 1), (1, 1),
                            (10, 10), (9999, WEB_MAX_RATE_LIMIT)]:
        assert max(1, min(asked, WEB_MAX_RATE_LIMIT)) == expected
