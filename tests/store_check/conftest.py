import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from narvy.store_check.analyze import analyze  # noqa: E402

AS_OF = dt.date(2026, 10, 4)


def assert_titles(r):
    """Every result fixture in the suite goes through this: the title names
    what was found for this status, the requirement keeps the rule, and the
    two never coincide (engine 0.1.0 printed the requirement as the title of
    a failure, which read as a contradiction)."""
    for d in (r.title, r.requirement):
        for lang in ("en", "fr"):
            assert d.get(lang), (r.check_id, r.status, d)
            assert "\u2014" not in d[lang] and "\u2013" not in d[lang], d[lang]
    assert r.title["en"] != r.requirement["en"], (r.check_id, r.status)
    assert r.title["fr"] != r.requirement["fr"], (r.check_id, r.status)


@pytest.fixture
def run(tmp_path):
    """Write fixture bytes to a temp file, analyse, return {check_id: Result}."""
    counter = {"n": 0}

    def _run(data: bytes, suffix: str = ".apk", as_of=AS_OF):
        counter["n"] += 1
        p = tmp_path / f"fixture{counter['n']}{suffix}"
        p.write_bytes(data)
        rep = analyze(str(p), as_of=as_of)
        for r in rep.results:
            assert_titles(r)
        return {r.check_id: r for r in rep.results}, rep
    return _run


def pytest_configure(config):
    config.addinivalue_line("markers", "real: tests on real binaries found under NARVY_STORE_CHECK_CORPUS (skipped otherwise)")
