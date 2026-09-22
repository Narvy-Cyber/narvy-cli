"""Passive-only web scanning: templates that send a body, a non-GET method or
a raw request must not survive the GET-only filter.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narvy.web.scanner import NucleiScanner

TEMPLATES_ROOT = os.path.expanduser('~/nuclei-templates')
_HAS_TEMPLATES = os.path.isdir(TEMPLATES_ROOT)


@unittest.skipUnless(_HAS_TEMPLATES, "local nuclei-templates checkout not present in this environment")
class TestPassiveScanExcludesActivePayloads(unittest.TestCase):

    def test_waf_detect_post_xss_template_is_excluded(self):
        path = os.path.join(TEMPLATES_ROOT, 'http/technologies/waf-detect.yaml')
        if not os.path.isfile(path):
            self.skipTest("waf-detect.yaml not present at expected path in this template checkout")
        self.assertFalse(NucleiScanner._template_is_get_only(path))

    def test_varnish_purge_template_is_excluded(self):
        path = os.path.join(TEMPLATES_ROOT, 'http/misconfiguration/unauthenticated-varnish-cache-purge.yaml')
        if not os.path.isfile(path):
            self.skipTest("template not present at expected path in this template checkout")
        self.assertFalse(NucleiScanner._template_is_get_only(path))

    def test_hadoop_rce_template_is_excluded(self):
        path = os.path.join(TEMPLATES_ROOT, 'http/misconfiguration/hadoop-unauth-rce.yaml')
        if not os.path.isfile(path):
            self.skipTest("template not present at expected path in this template checkout")
        self.assertFalse(NucleiScanner._template_is_get_only(path))

    def test_dlink_lfi_template_is_excluded(self):
        path = os.path.join(TEMPLATES_ROOT, 'http/misconfiguration/d-link-arbitary-fileread.yaml')
        if not os.path.isfile(path):
            self.skipTest("template not present at expected path in this template checkout")
        self.assertFalse(NucleiScanner._template_is_get_only(path))

    def test_genuinely_passive_header_check_is_kept(self):
        path = os.path.join(TEMPLATES_ROOT, 'http/misconfiguration/http-missing-security-headers.yaml')
        if not os.path.isfile(path):
            self.skipTest("template not present at expected path in this template checkout")
        self.assertTrue(NucleiScanner._template_is_get_only(path))

    def test_directory_expansion_end_to_end_excludes_known_bad_files(self):
        rel = 'http/misconfiguration/'
        out = NucleiScanner._filter_get_only_templates([rel])
        out_basenames = {os.path.basename(p) for p in out}
        for bad in ('unauthenticated-varnish-cache-purge.yaml',
                    'hadoop-unauth-rce.yaml',
                    'd-link-arbitary-fileread.yaml'):
            self.assertNotIn(bad, out_basenames, f"{bad} must not survive the passive filter")
        self.assertGreater(len(out), 0, "the filter should not empty out the whole directory")


class TestTemplateIsGetOnlyUnitLevel(unittest.TestCase):

    def _write(self, tmp_path, content):
        with open(tmp_path, 'w') as f:
            f.write(content)
        return tmp_path

    def test_post_method_excluded(self, tmp_path='/tmp/_cli_t_post.yaml'):
        self._write(tmp_path, "http:\n  - method: POST\n    path: ['{{BaseURL}}']\n")
        try:
            self.assertFalse(NucleiScanner._template_is_get_only(tmp_path))
        finally:
            os.unlink(tmp_path)

    def test_get_with_body_excluded(self, tmp_path='/tmp/_cli_t_getbody.yaml'):
        self._write(tmp_path, "http:\n  - method: GET\n    body: 'x=1'\n    path: ['{{BaseURL}}']\n")
        try:
            self.assertFalse(NucleiScanner._template_is_get_only(tmp_path))
        finally:
            os.unlink(tmp_path)

    def test_raw_request_excluded(self, tmp_path='/tmp/_cli_t_raw.yaml'):
        self._write(tmp_path, "http:\n  - raw:\n      - |\n        POST / HTTP/1.1\n")
        try:
            self.assertFalse(NucleiScanner._template_is_get_only(tmp_path))
        finally:
            os.unlink(tmp_path)

    def test_get_no_method_field_kept(self, tmp_path='/tmp/_cli_t_getdefault.yaml'):
        self._write(tmp_path, "http:\n  - path: ['{{BaseURL}}']\n")
        try:
            self.assertTrue(NucleiScanner._template_is_get_only(tmp_path))
        finally:
            os.unlink(tmp_path)

    def test_explicit_get_kept(self, tmp_path='/tmp/_cli_t_get.yaml'):
        self._write(tmp_path, "http:\n  - method: GET\n    path: ['{{BaseURL}}']\n")
        try:
            self.assertTrue(NucleiScanner._template_is_get_only(tmp_path))
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
