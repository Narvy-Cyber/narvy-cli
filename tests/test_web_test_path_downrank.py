"""Findings in test/fixture paths drop to LOW; app findings keep severity."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.web import source_analyzer as web


def _mk(rule_id, path, sev):
    return {"rule_id": rule_id, "file_path": path, "line": 1, "severity": sev, "details": {}}


def test_test_and_fixture_xss_downranked_app_level_survives():
    findings = [
        # framework test suite + fixture app (react-style flood)
        _mk("dom-innerhtml-assign", "packages/react-dom/src/__tests__/ReactDOMComponent-test.js", "CRITICAL"),
        _mk("dom-innerhtml-assign", "fixtures/dom/public/renderer.js", "CRITICAL"),
        _mk("react-dangerously-set-innerhtml", "packages/embeds/embed-core/src/EmbedElement.test.ts", "CRITICAL"),
        # real app-level XSS (cal.com-style) must survive
        _mk("react-dangerously-set-innerhtml", "apps/web/modules/bookings/components/EventMeta.tsx", "CRITICAL"),
        _mk("dom-innerhtml-assign", "packages/emails/src/components/RawHtml.tsx", "CRITICAL"),
    ]
    out = web._downweight_test_findings(findings)
    by_path = {f["file_path"]: f["severity"] for f in out}

    assert by_path["packages/react-dom/src/__tests__/ReactDOMComponent-test.js"] == "LOW"
    assert by_path["fixtures/dom/public/renderer.js"] == "LOW"
    assert by_path["packages/embeds/embed-core/src/EmbedElement.test.ts"] == "LOW"
    # Real app code, not a test path -> untouched.
    assert by_path["apps/web/modules/bookings/components/EventMeta.tsx"] == "CRITICAL"
    assert by_path["packages/emails/src/components/RawHtml.tsx"] == "CRITICAL"
    # Nothing was dropped.
    assert len(out) == len(findings)
    assert web.LAST_RUN_TEST_FINDINGS_DOWNWEIGHTED == 3


def test_framework_internal_non_test_paths_are_not_test():
    # react-dom renderer internals are not under a test/fixture path.
    assert not web._is_test_path("packages/react-dom-bindings/src/client/ReactDOMComponent.js")
    assert not web._is_test_path("packages/react-devtools-core/src/standalone.js")
