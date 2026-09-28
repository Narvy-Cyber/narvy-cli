"""semgrep with more than one worker drops taint results at random; taint packs
must run single-worker, and per-file timeouts must be reported."""
import os

from narvy import semgrep_engine
from narvy.web import source_analyzer as sa

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "narvy", "rules", "web")


def test_taint_packs_get_single_worker_groups(monkeypatch):
    monkeypatch.setenv("NARVY_SEMGREP_JOBS", "6")
    cfgs = [os.path.join(RULES, p + ".yml") for p in ("python", "javascript", "secrets")]
    groups = sa._semgrep_groups(cfgs)
    by_cfg = {tuple(os.path.basename(c) for c in g[0]): g[1] for g in groups}
    assert by_cfg[("python.yml",)] == 1
    assert by_cfg[("javascript.yml",)] == 1
    assert by_cfg[("secrets.yml",)] >= 1          # pattern-only pack keeps its own run
    assert all(len(g[0]) == 1 or not any(semgrep_engine.config_has_taint(c) for c in g[0])
               for g in groups)


def test_every_web_pack_with_taint_is_detected():
    for p in ("php", "python", "javascript", "java", "go", "ruby"):
        assert semgrep_engine.config_has_taint(os.path.join(RULES, p + ".yml")), p
    assert not semgrep_engine.config_has_taint(os.path.join(RULES, "secrets.yml"))


def test_timeouts_are_counted():
    data = {"errors": [
        {"type": "Timeout", "path": "/a.php", "message": "Timeout when running r on /a.php"},
        {"type": "Timeout", "message": "Timeout when running r2 on /b.php"},
        {"type": "Timeout", "path": "/a.php", "message": "again"},
        {"type": ["PartialParsing", []], "message": "x"},
    ]}
    assert sa._count_timeout_skipped(data) == 2
    assert sa._count_timeout_skipped({}) == 0
