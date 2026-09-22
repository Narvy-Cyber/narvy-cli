"""ssrf_guard.safe_get(): every redirect hop is revalidated, and responses
over MAX_RESPONSE_BYTES are refused (declared and chunked alike).
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy.web.ssrf_guard import (  # noqa: E402
    safe_get,
    SSRFBlocked,
    ResponseTooLarge,
    MAX_RESPONSE_BYTES,
)

_PRIVATE_REDIRECT_TARGET = "http://10.66.77.88/internal-only"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _RedirectingHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", _PRIVATE_REDIRECT_TARGET)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _OKHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _DeclaredHugeHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(MAX_RESPONSE_BYTES * 4))
        self.end_headers()
        # Never send the declared bytes: the declared-header path must reject first.


class _ChunkedOverCapHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        chunk = b"C" * (1024 * 1024)
        hexlen = format(len(chunk), 'x').encode()
        needed_chunks = (MAX_RESPONSE_BYTES // len(chunk)) + 5
        try:
            for _ in range(needed_chunks):
                self.wfile.write(hexlen + b"\r\n" + chunk + b"\r\n")
        except (BrokenPipeError, ConnectionResetError):
            return


def _start_server(handler_cls):
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    return httpd, port


class _AllowlistedServerTestCase(unittest.TestCase):
    """One fixture server per test, allowlisting only the loopback fixture host
    so the redirect-hop and size-cap guards are what gets exercised."""

    def _setup(self, handler_cls):
        self.httpd, self.port = _start_server(handler_cls)
        self._prev = os.environ.get('SSRF_GUARD_ALLOW_HOSTS')
        os.environ['SSRF_GUARD_ALLOW_HOSTS'] = f"127.0.0.1:{self.port}"
        self.addCleanup(self._teardown)

    def _teardown(self):
        if self._prev is None:
            os.environ.pop('SSRF_GUARD_ALLOW_HOSTS', None)
        else:
            os.environ['SSRF_GUARD_ALLOW_HOSTS'] = self._prev
        self.httpd.shutdown()
        self.httpd.server_close()


class TestCLISSRFGuardBlocksRedirectToPrivateIP(_AllowlistedServerTestCase):

    def test_safe_get_blocks_redirect_to_private_ip(self):
        self._setup(_RedirectingHandler)
        with self.assertRaises(SSRFBlocked):
            safe_get(f"http://127.0.0.1:{self.port}/", timeout=5)

    def test_allowlisted_non_redirecting_request_still_works(self):
        self._setup(_OKHandler)
        resp = safe_get(f"http://127.0.0.1:{self.port}/", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "ok")


class TestCLISSRFGuardResponseSizeCap(_AllowlistedServerTestCase):

    def test_declared_content_length_over_cap_rejected_fast(self):
        self._setup(_DeclaredHugeHandler)
        t0 = time.time()
        with self.assertRaises(ResponseTooLarge):
            safe_get(f"http://127.0.0.1:{self.port}/", timeout=15)
        self.assertLess(time.time() - t0, 5.0)

    def test_chunked_body_over_cap_rejected_while_streaming(self):
        self._setup(_ChunkedOverCapHandler)
        with self.assertRaises(ResponseTooLarge):
            safe_get(f"http://127.0.0.1:{self.port}/", timeout=30)

    def test_small_response_unaffected(self):
        self._setup(_OKHandler)
        resp = safe_get(f"http://127.0.0.1:{self.port}/", timeout=10)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "ok")


if __name__ == "__main__":
    unittest.main()
