"""
Contract tests for the dashboard Cost Explorer cache.

The cache was an unbounded module-level dict, read and written by both
request threads and background scan threads with no synchronisation,
and entries for already-closed windows were stored with no expiry at
all -- cached for the lifetime of the process.

Each test here pins one of those three properties.
"""

from __future__ import annotations

import threading
import time
from datetime import date, timedelta

from backend.api.services import dashboard_service as ds


def setup_function() -> None:
    ds._cache_clear()


def test_value_round_trips():
    today = date.today()

    ds._cache_set("k", {"v": 1}, end=today, today=today)

    assert ds._cache_get("k") == {"v": 1}


def test_missing_key_returns_none():
    assert ds._cache_get("absent") is None


def test_closed_window_entries_still_expire():
    """Historical data is stable, not immutable -- Cost Explorer restates it.

    The previous implementation stored these with expires_at=None,
    which in a long-running server meant "never re-read this range
    again".
    """

    today = date.today()
    closed = today - timedelta(days=30)

    ds._cache_set("closed", "v", end=closed, today=today)

    expires_at, _ = ds._QUERY_CACHE["closed"]

    assert expires_at is not None
    assert expires_at > time.time()


def test_expired_entry_is_evicted_on_read():
    today = date.today()

    ds._cache_set("stale", "v", end=today, today=today)
    ds._QUERY_CACHE["stale"] = (time.time() - 1, "v")

    assert ds._cache_get("stale") is None
    assert "stale" not in ds._QUERY_CACHE


def test_cache_is_bounded_and_evicts_least_recently_used():
    today = date.today()

    for index in range(ds.CACHE_MAX_ENTRIES + 25):
        ds._cache_set(f"k{index}", index, end=today, today=today)

    assert len(ds._QUERY_CACHE) <= ds.CACHE_MAX_ENTRIES

    # Oldest keys evicted first; newest retained.
    assert ds._cache_get("k0") is None
    assert ds._cache_get(f"k{ds.CACHE_MAX_ENTRIES + 24}") is not None


def test_reading_an_entry_makes_it_survive_eviction():
    """LRU, not FIFO: a hot key must not be evicted by cold traffic."""

    today = date.today()

    ds._cache_set("hot", "v", end=today, today=today)

    for index in range(ds.CACHE_MAX_ENTRIES - 1):
        ds._cache_set(f"cold{index}", index, end=today, today=today)
        # Keep "hot" recent.
        ds._cache_get("hot")

    for index in range(50):
        ds._cache_set(f"new{index}", index, end=today, today=today)
        ds._cache_get("hot")

    assert ds._cache_get("hot") == "v"


def test_concurrent_access_does_not_corrupt_the_cache():
    """Request threads and scan threads both reach this cache.

    Individual dict ops are atomic under the GIL, but the get/decide/
    evict/set sequences here are not.
    """

    today = date.today()
    errors: list[BaseException] = []

    def worker(offset: int) -> None:
        try:
            for index in range(200):
                key = f"k{(offset + index) % 64}"
                ds._cache_set(key, index, end=today, today=today)
                ds._cache_get(key)
        except BaseException as exc:  # noqa: BLE001 - recorded then asserted
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i * 7,)) for i in range(8)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert len(ds._QUERY_CACHE) <= ds.CACHE_MAX_ENTRIES
