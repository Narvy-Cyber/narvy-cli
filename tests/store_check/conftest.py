import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from narvy.store_check.analyze import analyze  # noqa: E402

AS_OF = dt.date(2026, 10, 4)


@pytest.fixture
def run(tmp_path):
    """Write fixture bytes to a temp file, analyse, return {check_id: Result}."""
    counter = {"n": 0}

    def _run(data: bytes, suffix: str = ".apk", as_of=AS_OF):
        counter["n"] += 1
        p = tmp_path / f"fixture{counter['n']}{suffix}"
        p.write_bytes(data)
        rep = analyze(str(p), as_of=as_of)
        return {r.check_id: r for r in rep.results}, rep
    return _run


def pytest_configure(config):
    config.addinivalue_line("markers", "real: tests on real binaries found under NARVY_STORE_CHECK_CORPUS (skipped otherwise)")
