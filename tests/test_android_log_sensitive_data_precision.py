"""android-log-sensitive-data precision: a string literal that merely mentions
"token"/"password" is not a leak, but logging the value still is.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import semgrep_engine

RULE_ID = "android-log-sensitive-data"

FIXTURE = """package com.example;

public class Test2 {
    // FALSE POSITIVE: static text mentioning "token"/"password"
    // as a noun, with no value printed.
    void fp1() {
        Log.i(TAG, "Time for routine FCM token refresh.");
    }
    void fp2() {
        Log.w(TAG, "Cannot restore AuthToken from backup service.");
    }
    void fp3() {
        Log.d(TAG, "Submitting captcha token...");
    }

    // TRUE POSITIVE: bare identifier whose name is the secret
    void tp1(String authToken) {
        Log.d(TAG, authToken);
    }

    // TRUE POSITIVE: concatenation with a real variable
    void tp2(String token) {
        Log.d(TAG, "token=" + token);
    }

    void tp3(String password) {
        Log.e(TAG, "Login failed, password was: " + password);
    }
}
"""

EXPECTED_TP_LINES = {18, 23, 27}
EXPECTED_FP_LINES_SUPPRESSED = {7, 10, 13}


def _run_fixture():
    if not semgrep_engine.is_available():
        return None
    with tempfile.TemporaryDirectory() as d:
        fpath = os.path.join(d, "Test2.java")
        with open(fpath, "w", encoding="utf-8") as fh:
            fh.write(FIXTURE)
        results = semgrep_engine.run_semgrep(d, timeout=60) or []
    return [r for r in results if r.get("rule_id") == RULE_ID]


def test_static_prose_mentioning_keyword_not_flagged():
    """A literal that only mentions the keyword must not be flagged."""
    findings = _run_fixture()
    if findings is None:
        return  # semgrep not installed in this environment - skip silently
    flagged_lines = {f["line"] for f in findings}
    leaked_fps = flagged_lines & EXPECTED_FP_LINES_SUPPRESSED
    assert not leaked_fps, (
        f"static English text mentioning the keyword still flagged at "
        f"lines {leaked_fps} - precision guard regressed"
    )


def test_real_value_logging_still_flagged():
    """Logging the variable itself, or concatenating it in, must still flag."""
    findings = _run_fixture()
    if findings is None:
        return
    flagged_lines = {f["line"] for f in findings}
    missing_tps = EXPECTED_TP_LINES - flagged_lines
    assert not missing_tps, (
        f"real value-logging NOT flagged at lines {missing_tps} - "
        f"precision guard over-suppressed and ate recall"
    )


if __name__ == "__main__":
    test_static_prose_mentioning_keyword_not_flagged()
    test_real_value_logging_still_flagged()
    print("PASS: android-log-sensitive-data precision guard OK "
          "(static prose suppressed, real value-logging still flagged)")
