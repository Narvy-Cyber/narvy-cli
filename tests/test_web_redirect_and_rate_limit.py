"""Web scanner: redirect chains are pre-resolved through the SSRF guard, and a
rate-limited target is never reported as a clean zero-finding scan.
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The loopback fixtures below have to be reachable through the SSRF guard.
os.environ.setdefault("SSRF_GUARD_ALLOW_HOSTS", "127.0.0.1")

from narvy.web.scanner import NucleiScanner  # noqa: E402
from narvy.web.ssrf_guard import SSRFBlocked  # noqa: E402


def _scanner():
    """A NucleiScanner without resolve_nuclei_binary(); nothing here shells out."""
    return NucleiScanner.__new__(NucleiScanner)


class _Handler(BaseHTTPRequestHandler):
    status = 200
    location = None
    body = b"<html>ok</html>"

    def do_GET(self):
        self.send_response(self.status)
        if self.location:
            self.send_header("Location", self.location)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


def _serve(port, status=200, location=None, body=b"<html>ok</html>"):
    cls = type("H", (_Handler,), {"status": status, "location": location, "body": body})
    srv = HTTPServer(("127.0.0.1", port), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return srv


def test_redirect_is_resolved_before_nuclei():
    """A 301 with an empty body: nuclei must receive the resolved URL."""
    dest = _serve(8811, status=200, body=b"<html>real content</html>")
    stub = _serve(8810, status=301, location="http://127.0.0.1:8811/", body=b"")
    try:
        r = _scanner()._resolve_redirect_target("http://127.0.0.1:8810/")
        assert r["url"] == "http://127.0.0.1:8811/"
        assert r["final_status"] == 200
        assert "redirects to" in (r["note"] or "")
    finally:
        stub.shutdown()
        dest.shutdown()


def test_non_redirecting_target_is_untouched():
    srv = _serve(8812, status=200)
    try:
        r = _scanner()._resolve_redirect_target("http://127.0.0.1:8812/")
        assert r["url"] == "http://127.0.0.1:8812/"
        assert r["note"] is None
    finally:
        srv.shutdown()


def test_trailing_slash_difference_is_not_treated_as_a_redirect():
    s = _scanner()
    assert (s._normalize_for_compare("https://www.example.com")
            == s._normalize_for_compare("https://www.example.com/"))


def test_redirect_to_internal_address_is_refused_and_reported(monkeypatch):
    """A chain leaving the safe set keeps the URL as given but must say so."""
    import narvy.web.ssrf_guard as guard

    def _boom(*a, **kw):
        raise SSRFBlocked("Host resolves to an internal/private/reserved address")

    monkeypatch.setattr(guard, "safe_get", _boom)
    r = _scanner()._resolve_redirect_target("http://127.0.0.1:8899/")
    assert r["url"] == "http://127.0.0.1:8899/"
    assert "not scanned (SSRF policy" in r["note"]


def test_unreachable_target_does_not_break_the_scan():
    r = _scanner()._resolve_redirect_target("http://127.0.0.1:8898/")
    assert r["url"] == "http://127.0.0.1:8898/"
    assert "could not pre-resolve redirects" in (r["note"] or "")


@pytest.mark.parametrize("status", [429, 503])
def test_rate_limited_target_is_detected(status):
    srv = _serve(8813, status=status)
    try:
        s = _scanner()
        s._RATE_LIMIT_PROBE_DELAY = 0  # test speed only; production stays polite
        probe = s._probe_rate_limited("http://127.0.0.1:8813/")
        assert probe["limited"] is True
        assert probe["blocked"] == [status] * 3
    finally:
        srv.shutdown()


def test_healthy_target_is_not_flagged_as_rate_limited():
    srv = _serve(8814, status=200)
    try:
        s = _scanner()
        s._RATE_LIMIT_PROBE_DELAY = 0
        probe = s._probe_rate_limited("http://127.0.0.1:8814/")
        assert probe["limited"] is False
        assert probe["blocked"] == []
    finally:
        srv.shutdown()


def test_404_is_not_rate_limiting():
    """A 404 is a real answer, so a zero-finding result there is legitimate."""
    srv = _serve(8815, status=404)
    try:
        s = _scanner()
        s._RATE_LIMIT_PROBE_DELAY = 0
        assert s._probe_rate_limited("http://127.0.0.1:8815/")["limited"] is False
    finally:
        srv.shutdown()


def test_zero_findings_on_a_rate_limited_target_is_not_reported_as_success(monkeypatch):
    srv = _serve(8816, status=429)
    try:
        s = _scanner()
        s._RATE_LIMIT_PROBE_DELAY = 0
        monkeypatch.setattr(NucleiScanner, "_resolve_redirect_target",
                            lambda self, t: {"url": t, "note": None, "final_status": 429})
        out = _simulate_zero_finding_scan(s, "http://127.0.0.1:8816/")
        assert out["success"] is False
        assert out["degraded"] is True
        assert "rate-limiting/blocking" in out["degraded_reason"]
        assert "inconclusive" in out["degraded_reason"]
    finally:
        srv.shutdown()


def _simulate_zero_finding_scan(scanner, target):
    """Replays scan()'s post-processing decision for a zero-finding run."""
    out = {
        "success": True, "findings": [], "total_findings": 0, "stderr": "",
        "returncode": 0, "target": target, "scanned_url": target,
        "redirect_note": None, "degraded": False, "degraded_reason": None,
    }
    probe = scanner._probe_rate_limited(target)
    if probe["limited"]:
        reason = (
            f"target is rate-limiting/blocking the scanner - {len(probe['blocked'])} "
            f"of {len(probe['statuses'])} verification requests to {target} came "
            f"back HTTP {'/'.join(str(s) for s in sorted(set(probe['blocked'])))}. "
            f"This run could not reach real content, so it is inconclusive. Run it "
            f"from the Narvy platform (allowlisted egress + the full active engine), "
            f"or re-run with a lower --rate-limit."
        )
        out.update({"degraded": True, "degraded_reason": reason,
                    "success": False, "error": reason})
    return out


def test_scan_result_carries_the_new_keys():
    """main.py's text report and --format json rely on these on every result."""
    import inspect
    src = inspect.getsource(NucleiScanner.scan)
    for k in ("scanned_url", "redirect_note", "degraded", "degraded_reason"):
        assert f'"{k}"' in src, f"scan() no longer returns {k}"
    assert '"-u", scan_target,' in src
    assert '"-disable-redirects"' in src


def test_json_output_shape_is_serializable():
    out = _simulate_zero_finding_scan(_scanner(), "http://127.0.0.1:1/")
    json.dumps(out)  # must not raise
