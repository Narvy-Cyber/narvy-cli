"""semgrep timeout scales with tree size; a timeout is reported as degraded coverage."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy import semgrep_engine  # noqa: E402


def _make_tree(n_files: int) -> str:
    d = tempfile.mkdtemp(prefix="narvy_sgtimeout_")
    sub = os.path.join(d, "sources", "com", "example")
    os.makedirs(sub, exist_ok=True)
    for i in range(n_files):
        with open(os.path.join(sub, f"F{i}.java"), "w") as f:
            f.write("class F%d {}\n" % i)
    return d


class AdaptiveTimeoutTests(unittest.TestCase):

    def test_small_tree_keeps_historical_600s(self):
        d = _make_tree(10)
        self.assertEqual(semgrep_engine.compute_semgrep_timeout(d), 600)

    def test_large_tree_gets_more_budget(self):
        """A big tree must not get the same budget as a toy one."""
        vals = {}
        for n in (10, 3_000, 8_000, 15_000):
            with mock.patch.object(semgrep_engine, "count_source_files",
                                   return_value=n):
                vals[n] = semgrep_engine.compute_semgrep_timeout("/x")
        self.assertEqual(vals[10], 600)
        self.assertGreater(vals[3_000], vals[10])
        self.assertGreater(vals[8_000], vals[3_000])
        self.assertGreater(vals[15_000], vals[8_000])
        self.assertGreaterEqual(vals[15_000], 2 * 600)

    def test_timeout_is_bounded(self):
        """A CI job has to terminate."""
        with mock.patch.object(semgrep_engine, "count_source_files",
                               return_value=10_000_000):
            self.assertEqual(
                semgrep_engine.compute_semgrep_timeout("/nonexistent"),
                semgrep_engine.SEMGREP_MAX_TIMEOUT_SEC,
            )

    def test_never_below_the_old_floor(self):
        for n in (0, 1, 500, 1999):
            with mock.patch.object(semgrep_engine, "count_source_files",
                                   return_value=n):
                self.assertGreaterEqual(
                    semgrep_engine.compute_semgrep_timeout("/x"),
                    semgrep_engine.SEMGREP_BASE_TIMEOUT_SEC)


class DegradedCoverageTests(unittest.TestCase):

    def setUp(self):
        semgrep_engine._record_run('not_run')

    def test_timeout_is_not_reported_as_clean(self):
        d = _make_tree(5)
        with mock.patch.object(semgrep_engine, "is_available",
                               return_value=True), \
             mock.patch("narvy.semgrep_engine.run_tree",
                        side_effect=subprocess.TimeoutExpired(
                            cmd=["semgrep"], timeout=600)):
            out = semgrep_engine.run_semgrep(d, own_roots={"com.example"})
        self.assertEqual(out, [], "hard timeout still yields no findings")
        self.assertEqual(semgrep_engine.LAST_RUN["status"], "timeout")
        self.assertTrue(semgrep_engine.LAST_RUN["degraded"])
        note = semgrep_engine.degraded_coverage_note()
        self.assertIsNotNone(note, "a timeout MUST produce a user warning")
        self.assertIn("--upload", note)
        self.assertIn("hosted engine", note)

    def test_clean_run_raises_no_false_alarm(self):
        d = _make_tree(5)
        with mock.patch.object(semgrep_engine, "is_available",
                               return_value=True), \
             mock.patch("narvy.semgrep_engine.run_tree",
                        return_value=mock.Mock(
                            returncode=0, stdout=json.dumps({"results": []}),
                            stderr="")):
            out = semgrep_engine.run_semgrep(d, own_roots={"com.example"})
        self.assertEqual(out, [])
        self.assertEqual(semgrep_engine.LAST_RUN["status"], "ok")
        self.assertIsNone(semgrep_engine.degraded_coverage_note())

    def test_nonzero_rc_with_no_output_is_degraded(self):
        d = _make_tree(5)
        with mock.patch.object(semgrep_engine, "is_available",
                               return_value=True), \
             mock.patch("narvy.semgrep_engine.run_tree",
                        return_value=mock.Mock(returncode=2, stdout="",
                                               stderr="boom")):
            semgrep_engine.run_semgrep(d, own_roots={"com.example"})
        self.assertEqual(semgrep_engine.LAST_RUN["status"], "error")
        self.assertIsNotNone(semgrep_engine.degraded_coverage_note())

    def test_env_override_still_honoured(self):
        d = _make_tree(5)
        seen = {}

        def fake_run(*a, **kw):
            seen["timeout"] = kw.get("timeout")
            return mock.Mock(returncode=0,
                             stdout=json.dumps({"results": []}), stderr="")

        with mock.patch.dict(os.environ,
                             {"NARVY_SEMGREP_TIMEOUT": "77"}), \
             mock.patch.object(semgrep_engine, "is_available",
                               return_value=True), \
             mock.patch("narvy.semgrep_engine.run_tree",
                        side_effect=fake_run):
            semgrep_engine.run_semgrep(d, own_roots={"com.example"})
        self.assertEqual(seen["timeout"], 77)


class SwiftPathTests(unittest.TestCase):

    def setUp(self):
        semgrep_engine._record_run('not_run')

    def test_swift_timeout_records_degraded(self):
        from narvy.ios import source_analyzer as ios_sa
        d = _make_tree(3)
        with mock.patch.object(semgrep_engine, "is_available",
                               return_value=True), \
             mock.patch(
                 "narvy.ios.source_analyzer.run_tree",
                 side_effect=subprocess.TimeoutExpired(cmd=["semgrep"],
                                                       timeout=600)):
            out = ios_sa._run_swift_semgrep(d)
        self.assertEqual(out, [])
        self.assertEqual(semgrep_engine.LAST_RUN["status"], "timeout")
        self.assertIsNotNone(semgrep_engine.degraded_coverage_note())


if __name__ == "__main__":
    unittest.main()
