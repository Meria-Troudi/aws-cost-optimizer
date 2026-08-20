"""
AWS Cost Explorer helpers.

This module is responsible only for querying AWS Cost Explorer.

It does NOT:
    - create database records
    - run analyzers
    - generate recommendations
    - manage ScanRun

Those responsibilities belong to higher layers.
"""

from __future__ import annotations

import time
from datetime import date
from typing import Any, Callable

from aws_cost_optimizer.collectors.cost.periods import (
    month_keys_in_period,
)
from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION


# ---------------------------------------------------------------------
# Month-level cache.
#
# Cost Explorer bills per API request ($0.01/request as of AWS's
# published pricing), and every query here is already MONTHLY
# granularity -- a closed month's cost never changes once AWS has
# finalized it, so re-fetching it on every scan is pure waste. A
# request for a CLOSED month is cached indefinitely; the current
# OPEN month gets a short TTL since it updates throughout the day.
# ---------------------------------------------------------------------

CACHE_TTL_SECONDS = 300

#: Cache entries are keyed by the exact day range they cover, not just
#: the month. A whole interior month always produces the same key and so
#: still caches across scans, while a partial boundary month (the first
#: and last month of a user-selected window) gets its own key and can
#: never be served from -- or written as -- a full-month entry.
_MONTH_CACHE: dict[
    tuple[str, str, str, str, str],
    tuple[float | None, dict[str, Any]],
] = {}


def _cache_key(
    namespace: str,
    region: str | None,
    month_key: str,
    range_start: str,
    range_end: str,
) -> tuple[str, str, str, str, str]:

    return (
        namespace,
        region or "*",
        month_key,
        range_start,
        range_end,
    )


def _cache_get(
    key: tuple[str, str, str, str, str],
) -> dict[str, Any] | None:

    entry = _MONTH_CACHE.get(key)

    if entry is None:
        return None

    expires_at, value = entry

    if (
        expires_at is not None
        and time.time() >= expires_at
    ):
        _MONTH_CACHE.pop(key, None)
        return None

    return value


def _cache_set(
    key: tuple[str, str, str, str, str],
    value: dict[str, Any],
    *,
    month_end: str,
) -> None:

    today = date.today().isoformat()

    expires_at = (
        None
        if month_end <= today
        else time.time() + CACHE_TTL_SECONDS
    )

    _MONTH_CACHE[key] = (expires_at, value)


def _month_start_date(month_key: str) -> date:

    year, month = month_key.split("-")

    return date(int(year), int(month), 1)


def _month_end_date_exclusive(month_key: str) -> str:

    start = _month_start_date(month_key)

    if start.month == 12:
        return date(start.year + 1, 1, 1).isoformat()

    return date(start.year, start.month + 1, 1).isoformat()


def _fetch_monthly_with_cache(
    namespace: str,
    fetch_range: Callable[[str, str], list[dict[str, Any]]],
    start: str,
    end: str,
    region: str | None,
) -> list[dict[str, Any]]:
    """
    Serve month blocks from cache where possible, and issue ONE
    request covering only the contiguous span of missing/expired
    months (not one request per missing month).

    The requested window is honoured exactly. An earlier version
    rounded the fetch out to whole month boundaries, so a scan for
    2026-06-15 -> 2026-08-17 actually queried 2026-06-01 -> 2026-09-01
    and silently reported roughly two extra weeks of spend. Validation
    could not catch it because the monthly-totals cross-check was
    widened identically and compared two equally-wrong numbers.

    Each month is therefore clipped to the requested window, and the
    clipped range is part of the cache key: whole interior months keep
    caching across scans, while the partial first/last months are only
    ever served to a request asking for that same day range.
    """

    start_date = date.fromisoformat(start)
    end_date = date.fromisoformat(end)

    if start_date >= end_date:
        return []

    month_keys = month_keys_in_period(
        start_date,
        end_date,
    )

    if not month_keys:
        return []

    # (month_key, clipped_start, clipped_end_exclusive)
    slices: list[tuple[str, str, str]] = []

    for month_key in month_keys:

        month_start = _month_start_date(month_key)

        month_end = date.fromisoformat(
            _month_end_date_exclusive(month_key)
        )

        clipped_start = max(month_start, start_date)
        clipped_end = min(month_end, end_date)

        if clipped_start >= clipped_end:
            continue

        slices.append(
            (
                month_key,
                clipped_start.isoformat(),
                clipped_end.isoformat(),
            )
        )

    if not slices:
        return []

    cached: dict[str, dict[str, Any]] = {}
    missing: list[tuple[str, str, str]] = []

    for month_key, slice_start, slice_end in slices:

        value = _cache_get(
            _cache_key(
                namespace,
                region,
                month_key,
                slice_start,
                slice_end,
            )
        )

        if value is not None:
            cached[month_key] = value
        else:
            missing.append(
                (month_key, slice_start, slice_end)
            )

    if missing:

        # Exactly the missing span -- never widened to month bounds.
        fetch_start = missing[0][1]
        fetch_end = missing[-1][2]

        fetched = fetch_range(
            fetch_start,
            fetch_end,
        )

        slice_by_month = {
            month_key: (slice_start, slice_end)
            for month_key, slice_start, slice_end in missing
        }

        for block in fetched:

            block_start = (
                block.get("TimePeriod", {})
                .get("Start", "")
            )

            block_month = block_start[:7]

            if block_month not in slice_by_month:
                continue

            slice_start, slice_end = slice_by_month[
                block_month
            ]

            _cache_set(
                _cache_key(
                    namespace,
                    region,
                    block_month,
                    slice_start,
                    slice_end,
                ),
                block,
                month_end=slice_end,
            )

            cached[block_month] = block

    return [
        cached[month_key]
        for month_key, _, _ in slices
        if month_key in cached
    ]


def _paginate_cost_and_usage(
    client: Any,
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Retrieve all Cost Explorer pages and merge them by month.

    Cost Explorer pagination can return the same month across
    multiple pages. We therefore merge Groups for each month.
    """

    results_by_period: dict[
        str,
        dict[str, Any],
    ] = {}

    response = client.get_cost_and_usage(
        **params
    )

    _merge_groups_by_period(
        results_by_period,
        response,
    )

    while (
        response.get("NextPageToken")
    ):

        params["NextPageToken"] = (
            response["NextPageToken"]
        )

        response = client.get_cost_and_usage(
            **params
        )

        _merge_groups_by_period(
            results_by_period,
            response,
        )

    return list(
        results_by_period.values()
    )


def _merge_groups_by_period(
    results_by_period: dict[
        str,
        dict[str, Any],
    ],
    response: dict[str, Any],
) -> None:
    """Merge Cost Explorer ResultsByTime blocks by month."""

    for block in response.get(
        "ResultsByTime",
        [],
    ):

        time_period = block[
            "TimePeriod"
        ]

        start = time_period[
            "Start"
        ]

        if start not in results_by_period:

            results_by_period[start] = {
                "TimePeriod": time_period,
                "Estimated": block.get(
                    "Estimated",
                    False,
                ),
                "Groups": [],
                "Total": block.get(
                    "Total",
                    {},
                ),
            }

        results_by_period[
            start
        ]["Groups"].extend(
            block.get(
                "Groups",
                [],
            )
        )


def get_cost_usage(
    start: str,
    end: str,
    region: str | None = None,
) -> list[dict[str, Any]]:
    """
    Get monthly cost grouped by SERVICE and USAGE_TYPE.

    Optionally filter by AWS region.
    Returns the raw normalized Cost Explorer response.

    Closed months are served from the module-level cache instead of
    re-querying Cost Explorer -- see _fetch_monthly_with_cache().
    """

    client = get_client(
        "ce",
        CE_REGION,
    )

    def fetch_range(
        range_start: str,
        range_end: str,
    ) -> list[dict[str, Any]]:

        params: dict[str, Any] = {
            "TimePeriod": {
                "Start": range_start,
                "End": range_end,
            },

            "Granularity": "MONTHLY",

            "Metrics": [
                "UnblendedCost",
                "UsageQuantity",
            ],

            "GroupBy": [
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE",
                },
                {
                    "Type": "DIMENSION",
                    "Key": "USAGE_TYPE",
                },
            ],
        }

        if region:

            params["Filter"] = {
                "Dimensions": {
                    "Key": "REGION",
                    "Values": [region],
                }
            }

        return _paginate_cost_and_usage(
            client,
            params,
        )

    return _fetch_monthly_with_cache(
        "cost_usage",
        fetch_range,
        start,
        end,
        region,
    )


def get_regions_with_costs(
    start: str,
    end: str,
) -> list[str]:
    """Return AWS regions that have non-zero cost during the requested period."""

    client = get_client(
        "ce",
        CE_REGION,
    )

    def fetch_range(
        range_start: str,
        range_end: str,
    ) -> list[dict[str, Any]]:

        params: dict[str, Any] = {
            "TimePeriod": {
                "Start": range_start,
                "End": range_end,
            },

            "Granularity": "MONTHLY",

            "Metrics": [
                "UnblendedCost",
            ],

            "GroupBy": [
                {
                    "Type": "DIMENSION",
                    "Key": "REGION",
                },
            ],
        }

        return _paginate_cost_and_usage(
            client,
            params,
        )

    results = _fetch_monthly_with_cache(
        "regions_with_costs",
        fetch_range,
        start,
        end,
        None,
    )

    regions: set[str] = set()

    for result in results:

        for group in result.get(
            "Groups",
            [],
        ):

            keys = group.get(
                "Keys",
                [],
            )

            if not keys:
                continue

            region = keys[0]

            try:

                amount = float(
                    group.get(
                        "Metrics",
                        {},
                    )
                    .get(
                        "UnblendedCost",
                        {},
                    )
                    .get(
                        "Amount",
                        0.0,
                    )
                )

            except (
                TypeError,
                ValueError,
            ):

                amount = 0.0

            if amount > 0:
                regions.add(region)

    return sorted(regions)


def get_monthly_totals(
    start: str,
    end: str,
    region: str | None = None,
) -> list[dict[str, Any]]:
    """
    Return monthly total cost.

    Unlike get_cost_usage(), this query is NOT grouped.
    Therefore Cost Explorer returns the monthly total
    inside ResultsByTime[*]["Total"].
    """

    client = get_client(
        "ce",
        CE_REGION,
    )

    def fetch_range(
        range_start: str,
        range_end: str,
    ) -> list[dict[str, Any]]:

        params: dict[str, Any] = {
            "TimePeriod": {
                "Start": range_start,
                "End": range_end,
            },

            "Granularity": "MONTHLY",

            "Metrics": [
                "UnblendedCost",
            ],
        }

        if region:

            params["Filter"] = {
                "Dimensions": {
                    "Key": "REGION",
                    "Values": [region],
                }
            }

        return _paginate_cost_and_usage(
            client,
            params,
        )

    return _fetch_monthly_with_cache(
        "monthly_totals",
        fetch_range,
        start,
        end,
        region,
    )


def get_cost_forecast(
    start: str,
    end: str,
    *,
    region: str | None = None,
    service: str | None = None,
    usage_type: str | None = None,
    metric: str = "UNBLENDED_COST",
    prediction_interval_level: int | None = 80,
) -> dict[str, Any]:
    """
    Retrieve an AWS Cost Explorer forecast directly.

    This function does not persist anything to the database.

    Parameters
    ----------
    start:
        Forecast period start date, inclusive.

    end:
        Forecast period end date, exclusive.

    region:
        Optional AWS region filter.

    service:
        Optional AWS service filter.

    usage_type:
        Optional usage type filter.

    metric:
        Cost Explorer forecast metric.

    prediction_interval_level:
        Optional confidence interval requested from AWS.
        Valid range is 51-99.
    """

    if not start or not end:
        raise ValueError(
            "Forecast start and end dates are required."
        )

    if start >= end:
        raise ValueError(
            "Forecast start date must be earlier than end date."
        )

    if metric not in {
        "UNBLENDED_COST",
        "BLENDED_COST",
        "AMORTIZED_COST",
        "NET_UNBLENDED_COST",
        "NET_AMORTIZED_COST",
        "USAGE_QUANTITY",
        "NORMALIZED_USAGE_AMOUNT",
    }:
        raise ValueError(
            f"Unsupported Cost Explorer forecast metric: {metric}"
        )

    if prediction_interval_level is not None:
        if not 51 <= prediction_interval_level <= 99:
            raise ValueError(
                "prediction_interval_level must be between 51 and 99."
            )

    client = get_client(
        "ce",
        CE_REGION,
    )

    params: dict[str, Any] = {
        "TimePeriod": {
            "Start": start,
            "End": end,
        },
        "Granularity": "MONTHLY",
        "Metric": metric,
    }

    filters: list[dict[str, Any]] = []

    if region:
        filters.append(
            {
                "Dimensions": {
                    "Key": "REGION",
                    "Values": [region],
                }
            }
        )

    if service:
        filters.append(
            {
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": [service],
                }
            }
        )

    if usage_type:
        filters.append(
            {
                "Dimensions": {
                    "Key": "USAGE_TYPE",
                    "Values": [usage_type],
                }
            }
        )

    if len(filters) == 1:
        params["Filter"] = filters[0]

    elif len(filters) > 1:
        params["Filter"] = {
            "And": filters,
        }

    if prediction_interval_level is not None:
        params["PredictionIntervalLevel"] = (
            prediction_interval_level
        )

    response = client.get_cost_forecast(
        **params
    )

    total = response.get(
        "Total",
        {},
    )

    try:
        total_amount = float(
            total.get(
                "Amount",
                0.0,
            )
        )
    except (
        TypeError,
        ValueError,
    ):
        total_amount = 0.0

    unit = (
        total.get(
            "Unit"
        )
        or "USD"
    )

    results: list[dict[str, Any]] = []

    for item in response.get(
        "ForecastResultsByTime",
        [],
    ):
        period = item.get(
            "TimePeriod",
            {},
        )

        mean = _safe_float(
            item.get(
                "MeanValue"
            )
        )

        lower = _safe_float(
            item.get(
                "PredictionIntervalLowerBound"
            )
        )

        upper = _safe_float(
            item.get(
                "PredictionIntervalUpperBound"
            )
        )

        results.append(
            {
                "month": (
                    str(
                        period.get(
                            "Start",
                            "",
                        )
                    )[:7]
                ),
                "start_date": period.get(
                    "Start"
                ),
                "end_date": period.get(
                    "End"
                ),
                "forecast": round(
                    mean,
                    2,
                ),
                "lower_bound": (
                    round(
                        lower,
                        2,
                    )
                    if lower is not None
                    else None
                ),
                "upper_bound": (
                    round(
                        upper,
                        2,
                    )
                    if upper is not None
                    else None
                ),
                "currency": unit,
            }
        )

    return {
        "forecast": round(
            total_amount,
            2,
        ),
        "currency": unit,
        "metric": metric,
        "prediction_interval_level": (
            prediction_interval_level
        ),
        "period": {
            "start_date": start,
            "end_date": end,
        },
        "results": results,
        "source": "aws_cost_explorer",
    }


def _safe_float(value: Any) -> float | None:
    if value is None:
        return None

    try:
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return None