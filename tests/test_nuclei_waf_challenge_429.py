"""A 429 counts as a WAF challenge, so header checks on it are skipped."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy.web.scanner import NucleiScanner


class TestWafChallenge429(unittest.TestCase):

    def test_429_is_treated_as_waf_challenge(self):
        self.assertTrue(
            NucleiScanner._is_waf_challenge(429, {"Content-Type": "text/html"}, "Too Many Requests")
        )

    def test_429_with_no_body_still_treated_as_challenge(self):
        # Bare edge 429 with a minimal body.
        self.assertTrue(NucleiScanner._is_waf_challenge(429, {"Server": "nginx"}, ""))

    def test_200_is_not_a_waf_challenge(self):
        self.assertFalse(
            NucleiScanner._is_waf_challenge(200, {"Content-Security-Policy": "default-src 'self'"}, "<html></html>")
        )

    def test_existing_403_challenge_detection_unaffected(self):
        self.assertTrue(
            NucleiScanner._is_waf_challenge(403, {"Server": "cloudflare"}, "Attention Required! | Cloudflare")
        )


if __name__ == "__main__":
    unittest.main()
