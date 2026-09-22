"""The nuclei subprocess budget must scale with --rate-limit, stay capped and
never drop below the default floor.
"""
import pytest

from narvy.web.scanner import (
    SUBPROCESS_TIMEOUT,
    SUBPROCESS_TIMEOUT_CAP,
    compute_subprocess_timeout,
)

# Size of the passive template set after the GET-only filter.
PASSIVE_SET_SIZE = 2415


@pytest.mark.parametrize("rate_limit", [1, 2, 3, 5])
def test_low_rate_limits_are_no_longer_guaranteed_timeouts(rate_limit):
    """The budget must exceed the physical minimum the rate limit imposes."""
    physical_minimum = PASSIVE_SET_SIZE / rate_limit
    budget = compute_subprocess_timeout(PASSIVE_SET_SIZE, rate_limit)
    assert budget > physical_minimum, (
        f"rate-limit {rate_limit}: budget {budget}s <= physical minimum "
        f"{physical_minimum:.0f}s - scan is mathematically guaranteed to fail"
    )


def test_rate_limit_5_was_the_observed_failure():
    """rate-limit 5 needs more than the default floor allows."""
    assert PASSIVE_SET_SIZE / 5 > SUBPROCESS_TIMEOUT
    assert compute_subprocess_timeout(PASSIVE_SET_SIZE, 5) > PASSIVE_SET_SIZE / 5


def test_default_rate_limit_keeps_the_default_floor():
    """At the default --rate-limit 50 the budget stays at the floor."""
    assert compute_subprocess_timeout(PASSIVE_SET_SIZE, 50) == SUBPROCESS_TIMEOUT


def test_budget_covers_the_measured_overhead_ratio():
    """Calibration guard: the budget must cover the measured overhead ratio at
    every rate limit."""
    measured_ratio = 261 / (PASSIVE_SET_SIZE / 20)
    assert measured_ratio == pytest.approx(2.16, abs=0.05)
    for r in (1, 2, 5, 10, 20, 50):
        expected_wall = (PASSIVE_SET_SIZE / r) * measured_ratio
        budget = compute_subprocess_timeout(PASSIVE_SET_SIZE, r)
        if budget == SUBPROCESS_TIMEOUT_CAP:
            continue  # capped on purpose
        assert budget >= expected_wall, (
            f"rate-limit {r}: budget {budget}s < measured-ratio estimate "
            f"{expected_wall:.0f}s"
        )


def test_budget_is_capped():
    """A pathological rate limit must not produce an unbounded wait."""
    assert compute_subprocess_timeout(PASSIVE_SET_SIZE, 1) <= SUBPROCESS_TIMEOUT_CAP
    assert compute_subprocess_timeout(10 ** 9, 1) == SUBPROCESS_TIMEOUT_CAP


def test_never_below_the_default_floor():
    for n in (0, 1, 10, 100, PASSIVE_SET_SIZE):
        for r in (1, 5, 50, 1000):
            assert compute_subprocess_timeout(n, r) >= SUBPROCESS_TIMEOUT


def test_degenerate_inputs_do_not_crash():
    """rate_limit 0 / None must not raise ZeroDivisionError."""
    assert compute_subprocess_timeout(PASSIVE_SET_SIZE, 0) >= SUBPROCESS_TIMEOUT
    assert compute_subprocess_timeout(PASSIVE_SET_SIZE, None) >= SUBPROCESS_TIMEOUT
    assert compute_subprocess_timeout(0, 50) == SUBPROCESS_TIMEOUT
    assert compute_subprocess_timeout(-5, 50) == SUBPROCESS_TIMEOUT


def test_budget_is_monotonic_in_rate_limit():
    """Lower rate limit means the same or more time, never less."""
    budgets = [compute_subprocess_timeout(PASSIVE_SET_SIZE, r)
               for r in (1, 2, 5, 10, 20, 50)]
    assert budgets == sorted(budgets, reverse=True)
