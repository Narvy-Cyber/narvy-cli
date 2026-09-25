import pytest


@pytest.fixture(autouse=True)
def _no_telemetry(monkeypatch):
    """No test may send a usage event; telemetry tests opt back in explicitly."""
    monkeypatch.setenv("NARVY_TELEMETRY", "0")
