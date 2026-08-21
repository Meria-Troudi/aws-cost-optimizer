"""
Cost Explorer must query exactly the window the user asked for.

An earlier month-level cache rounded the fetch out to whole month
boundaries, so a scan for 2026-06-15 -> 2026-08-17 actually queried
2026-06-01 -> 2026-09-01. Two scans of the identical period reported
June as $295.62 and $555.00 -- a closed month that cannot change --
and validation still passed, because the monthly-totals cross-check was
widened identically and compared two equally-wrong numbers.
"""

from __future__ import annotations

import pytest

from collection.cost import cost_explorer as ce


@pytest.fixture(autouse=True)
def _clear_cache():
    ce._MONTH_CACHE.clear()
    yield
    ce._MONTH_CACHE.clear()


def _recorder(blocks):
    """A fetch_range stub that records the range it was asked for."""

    calls: list[tuple[str, str]] = []

    def fetch(start: str, end: str):
        calls.append((start, end))
        return blocks

    return fetch, calls


PARTIAL_WINDOW_BLOCKS = [
    {"TimePeriod": {"Start": "2026-06-15", "End": "2026-07-01"}},
    {"TimePeriod": {"Start": "2026-07-01", "End": "2026-08-01"}},
    {"TimePeriod": {"Start": "2026-08-01", "End": "2026-08-17"}},
]


def test_fetch_range_is_not_widened_to_month_boundaries():
    fetch, calls = _recorder(PARTIAL_WINDOW_BLOCKS)

    ce._fetch_monthly_with_cache(
        "test",
        fetch,
        "2026-06-15",
        "2026-08-17",
        "eu-west-1",
    )

    assert calls == [("2026-06-15", "2026-08-17")]


def test_partial_month_is_not_served_to_a_full_month_request():
    """
    A cached 15th-to-end-of-June block must never satisfy a later
    request for the whole of June -- that is how the inflated figure
    would reappear through the cache instead of the fetch.
    """

    fetch, calls = _recorder(PARTIAL_WINDOW_BLOCKS)

    ce._fetch_monthly_with_cache(
        "test", fetch, "2026-06-15", "2026-08-17", "eu-west-1"
    )
    calls.clear()

    ce._fetch_monthly_with_cache(
        "test", fetch, "2026-06-01", "2026-07-01", "eu-west-1"
    )

    assert calls == [("2026-06-01", "2026-07-01")]


def test_identical_window_is_served_from_cache():
    """The fix must not cost us the caching it was added for."""

    fetch, calls = _recorder(PARTIAL_WINDOW_BLOCKS)

    ce._fetch_monthly_with_cache(
        "test", fetch, "2026-06-15", "2026-08-17", "eu-west-1"
    )
    assert len(calls) == 1

    ce._fetch_monthly_with_cache(
        "test", fetch, "2026-06-15", "2026-08-17", "eu-west-1"
    )
    assert len(calls) == 1, "second identical request should hit cache"


def test_regions_are_cached_separately():
    fetch, calls = _recorder(PARTIAL_WINDOW_BLOCKS)

    ce._fetch_monthly_with_cache(
        "test", fetch, "2026-06-15", "2026-08-17", "eu-west-1"
    )
    ce._fetch_monthly_with_cache(
        "test", fetch, "2026-06-15", "2026-08-17", "us-east-1"
    )

    assert len(calls) == 2


def test_empty_or_inverted_window_makes_no_request():
    fetch, calls = _recorder(PARTIAL_WINDOW_BLOCKS)

    assert (
        ce._fetch_monthly_with_cache(
            "test", fetch, "2026-08-17", "2026-06-15", None
        )
        == []
    )
    assert (
        ce._fetch_monthly_with_cache(
            "test", fetch, "2026-06-15", "2026-06-15", None
        )
        == []
    )
    assert calls == []


def test_single_partial_month_window():
    blocks = [
        {"TimePeriod": {"Start": "2026-06-10", "End": "2026-06-20"}}
    ]
    fetch, calls = _recorder(blocks)

    result = ce._fetch_monthly_with_cache(
        "test", fetch, "2026-06-10", "2026-06-20", "eu-west-1"
    )

    assert calls == [("2026-06-10", "2026-06-20")]
    assert len(result) == 1
