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

from typing import Any

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION


# ==============================================================
# INTERNAL PAGINATION
# ==============================================================


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
    """
    Merge Cost Explorer ResultsByTime blocks by month.
    """

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


# ==============================================================
# COST BY SERVICE / USAGE TYPE
# ==============================================================


def get_cost_usage(
    start: str,
    end: str,
    region: str | None = None,
) -> list[dict[str, Any]]:
    """
    Get monthly cost grouped by:

        SERVICE
        USAGE_TYPE

    Optionally filter by AWS region.

    Returns the raw normalized Cost Explorer response.
    """

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


# ==============================================================
# REGIONS WITH COST
# ==============================================================


def get_regions_with_costs(
    start: str,
    end: str,
) -> list[str]:
    """
    Return AWS regions that have non-zero cost
    during the requested period.
    """

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

    results = _paginate_cost_and_usage(
        client,
        params,
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


# ==============================================================
# MONTHLY TOTALS
# ==============================================================


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

    params: dict[str, Any] = {
        "TimePeriod": {
            "Start": start,
            "End": end,
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