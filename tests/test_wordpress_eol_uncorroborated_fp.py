"""EOL findings are dropped unless the response confirms the technology."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy.web.scanner import NucleiScanner


def _finding(template_id, response_raw="", evidence=None):
    return {
        "template_id": template_id,
        "title": "WordPress End-of-Life - Detect",
        "description": "Detected WordPress versions that have reached End-of-Life",
        "cve_id": None,
        "evidence": evidence or [],
        "response_raw": response_raw,
        "request_raw": "GET / HTTP/1.1",
    }


class TestUncorroboratedTechEolSuppression(unittest.TestCase):

    def test_wordpress_eol_dropped_with_no_corroborating_evidence(self):
        f = _finding(
            "wordpress-eol",
            response_raw="HTTP/1.1 200 OK\r\n\r\n<html>Built with Foo Version 2.0</html>",
            evidence=["2.0"],
        )
        kept = NucleiScanner._suppress_uncorroborated_tech_eol([f])
        self.assertEqual(kept, [])

    def test_wordpress_eol_kept_when_wp_content_present(self):
        f = _finding(
            "wordpress-eol",
            response_raw="HTTP/1.1 200 OK\r\n\r\n<html><script src='/wp-content/themes/x.js'></script></html>",
            evidence=["2.0"],
        )
        kept = NucleiScanner._suppress_uncorroborated_tech_eol([f])
        self.assertEqual(len(kept), 1)

    def test_wordpress_eol_kept_when_generator_meta_present(self):
        f = _finding(
            "wordpress-eol",
            response_raw='HTTP/1.1 200 OK\r\n\r\n<meta name="generator" content="WordPress 5.2">',
            evidence=["5.2"],
        )
        kept = NucleiScanner._suppress_uncorroborated_tech_eol([f])
        self.assertEqual(len(kept), 1)

    def test_unrelated_template_untouched(self):
        f = _finding("nginx-eol", response_raw="Server: nginx/1.18.0", evidence=["1.18.0"])
        kept = NucleiScanner._suppress_uncorroborated_tech_eol([f])
        self.assertEqual(len(kept), 1)


if __name__ == "__main__":
    unittest.main()
