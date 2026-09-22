"""android-sql-injection-rawquery precision: concatenation of compile-time
constants is not injection, real tainted concatenation still is.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import semgrep_engine

# SQL-injection-via-concatenation is detected by two sibling rules: rawQuery()
# calls fire `android-sql-injection-rawquery`, execSQL() calls fire
# `android-sql-injection-execsql`. The fixture exercises both APIs, so the
# precision test must count BOTH (it used to name only the rawquery id, from
# before the rule was split, which under-counted the execSQL true positives).
RULE_IDS = {"android-sql-injection-rawquery", "android-sql-injection-execsql"}

FIXTURE = """package com.example;

public class Test {
    // FALSE POSITIVE shape: constant-only concatenation (DB migration)
    void migrate(SQLiteDatabase db) {
        db.execSQL("ALTER TABLE " + Adapter.TABLE_NAME_FEEDS + " ADD COLUMN " + Adapter.KEY_TYPE + " TEXT");
        db.execSQL("UPDATE " + Adapter.TABLE_NAME_FEEDS + " SET " + Adapter.KEY_IMAGE_URL + " = NULL");
        db.execSQL("DROP TABLE " + Adapter.TABLE_NAME_FEED_IMAGES);
    }

    // TRUE POSITIVE shape: real taint
    void findUser(SQLiteDatabase db, String userId) {
        Cursor c = db.rawQuery("SELECT * FROM users WHERE id=" + userId, null);
    }

    void search(SQLiteDatabase db, String q) {
        db.execSQL("DELETE FROM logs WHERE query='" + q + "'");
    }

    // TRUE POSITIVE shape: tainted var mid-chain, not just at the tail
    void findByName(SQLiteDatabase db, String name) {
        Cursor c = db.rawQuery("SELECT * FROM " + Adapter.TABLE_USERS + " WHERE name='" + name + "'", null);
    }

    // TRUE POSITIVE shape: Intent-extra taint source
    void fromIntent(SQLiteDatabase db, android.content.Intent intent) {
        db.execSQL("SELECT * FROM t WHERE x=" + intent.getStringExtra("x"));
    }
}
"""

EXPECTED_TP_LINES = {13, 17, 22, 27}
EXPECTED_FP_LINES_SUPPRESSED = {6, 7, 8}


def _run_fixture():
    if not semgrep_engine.is_available():
        return None
    with tempfile.TemporaryDirectory() as d:
        fpath = os.path.join(d, "Test.java")
        with open(fpath, "w", encoding="utf-8") as fh:
            fh.write(FIXTURE)
        results = semgrep_engine.run_semgrep(d, timeout=60) or []
    return [r for r in results if r.get("rule_id") in RULE_IDS]


def test_constant_only_concatenation_not_flagged():
    """Literals plus UPPER_SNAKE_CASE constants must not be flagged."""
    findings = _run_fixture()
    if findings is None:
        return  # semgrep not installed in this environment - skip silently
    flagged_lines = {f["line"] for f in findings}
    leaked_fps = flagged_lines & EXPECTED_FP_LINES_SUPPRESSED
    assert not leaked_fps, (
        f"constant-only concatenation (DB-migration shape) still flagged "
        f"at lines {leaked_fps} - precision guard regressed"
    )


def test_real_taint_still_flagged():
    """Local var, param, mid-chain and Intent-extra taint must still flag."""
    findings = _run_fixture()
    if findings is None:
        return
    flagged_lines = {f["line"] for f in findings}
    missing_tps = EXPECTED_TP_LINES - flagged_lines
    assert not missing_tps, (
        f"real SQL-injection-shaped concatenation NOT flagged at lines "
        f"{missing_tps} - precision guard over-suppressed and ate recall"
    )


if __name__ == "__main__":
    test_constant_only_concatenation_not_flagged()
    test_real_taint_still_flagged()
    print("PASS: android-sql-injection-rawquery precision guard OK "
          "(constant-only suppressed, real taint still flagged)")
