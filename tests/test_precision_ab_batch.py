"""Comment filtering, JWT dedupe, trust-all downgrade and Swift cloud-credential rules."""
import os
import tempfile

import yaml

from narvy import comment_filter
from narvy.rule_engine import run_rules_on_file
from narvy.ios import trust_all_context
from narvy.web import source_analyzer as web


# ---- 1. comment filter -----------------------------------------------------

def test_comment_mask_masks_line_and_block_but_not_strings():
    src = 'let a = "http://real.example"\n// let b = "http://commented"\n'
    mask = comment_filter.build_comment_mask(src)
    # the real URL (inside a string) is NOT masked
    assert mask[src.index('http://real')] is False
    # the commented URL IS masked
    assert mask[src.index('http://commented')] is True


def test_comment_mask_slashes_inside_string_are_not_a_comment():
    src = 'let u = "a//b/*c*/d"; let keep = 1\n'
    mask = comment_filter.build_comment_mask(src)
    assert mask[src.index('keep')] is False
    assert mask[src.index('//b')] is False


def test_regex_rule_skips_match_in_comment(tmp_path):
    rules = [{
        "id": "T-HTTP", "name": "cleartext", "severity": "HIGH",
        "pattern": r'"http://[^"]+"', "details": {},
    }]
    f = tmp_path / "Net.java"
    f.write_text(
        'class X {\n'
        '  String a = "http://real.example";      // TRUE positive\n'
        '  // String b = "http://commented.example";\n'
        '  /* String c = "http://block.example"; */\n'
        '}\n'
    )
    findings = run_rules_on_file(str(f), rules)
    lines = sorted(x["line"] for x in findings)
    assert lines == [2], f"expected only the real string hit on line 2, got {lines}"


# ---- 3. trust-all-certs opt-in gate ----------------------------------------

def test_trust_all_flag_detected_when_guarded():
    content = (
        "func urlSession(_ s: URLSession, didReceive c: URLAuthenticationChallenge,\n"
        "  completionHandler h: @escaping (X, URLCredential?) -> Void) {\n"
        "  try validateServer(trust, allowUntrusted: cfg.allowUntrustedCertificate)\n"
        "  h(.useCredential, URLCredential(trust: trust))\n"
        "}\n"
    )
    assert trust_all_context.opt_in_trust_flag(content, 4) == "allowUntrusted"


def test_trust_all_unconditional_returns_none():
    content = (
        "func urlSession(_ s: URLSession, didReceive c: URLAuthenticationChallenge,\n"
        "  completionHandler h: @escaping (X, URLCredential?) -> Void) {\n"
        "  h(.useCredential, URLCredential(trust: c.protectionSpace.serverTrust!))\n"
        "}\n"
    )
    assert trust_all_context.opt_in_trust_flag(content, 3) is None


# ---- 2. web JWT de-dupe + test down-weight ---------------------------------

def _mk(rule_id, path, line, sev):
    return {"rule_id": rule_id, "file_path": path, "line": line,
            "severity": sev, "details": {}}


def test_jwt_alias_dedup_keeps_highest_severity():
    findings = [
        _mk("hardcoded-jwt-sign-secret", "src/auth.js", 6, "CRITICAL"),
        _mk("js-jsonwebtoken-hardcoded-secret", "src/auth.js", 6, "HIGH"),
        # a genuinely different vuln on the same line must survive
        _mk("some-xss-rule", "src/auth.js", 6, "HIGH"),
    ]
    out = web._collapse_jwt_aliases(list(findings))
    ids = sorted(f["rule_id"] for f in out)
    assert ids == ["hardcoded-jwt-sign-secret", "some-xss-rule"]
    assert web.LAST_RUN_JWT_DUPLICATES_DROPPED == 1


def test_test_path_secret_downweighted_not_dropped():
    findings = [
        _mk("narvy.secrets.aws-access-key-id", "test/keys.test.js", 3, "CRITICAL"),
        _mk("narvy.secrets.aws-access-key-id", "src/config.js", 3, "CRITICAL"),
    ]
    out = web._downweight_test_secrets(findings)
    by_path = {f["file_path"]: f["severity"] for f in out}
    assert by_path["test/keys.test.js"] == "LOW"      # downweighted
    assert by_path["src/config.js"] == "CRITICAL"     # prod untouched
    assert len(out) == 2                               # nothing dropped


def test_prod_source_not_classified_as_test():
    for p in ("src/auth.js", "src/latest.js", "lib/contest.js", "src/greatest.ts"):
        assert web._is_test_path(p) is False, p
    for p in ("src/auth.test.js", "pkg/handler_test.go", "__tests__/x.js"):
        assert web._is_test_path(p) is True, p


# ---- 4. iOS Swift cloud-credential rules exist -----------------------------

def test_swift_pack_has_cloud_credential_rules():
    here = os.path.dirname(os.path.dirname(__file__))
    path = os.path.join(here, "narvy", "rules", "ios_swift.yml")
    with open(path) as fh:
        ids = {r["id"] for r in yaml.safe_load(fh)["rules"]}
    for rid in (
        "ios-swift-hardcoded-aws-access-key",
        "ios-swift-hardcoded-google-api-key",
        "ios-swift-hardcoded-private-key",
    ):
        assert rid in ids, f"missing {rid}"
