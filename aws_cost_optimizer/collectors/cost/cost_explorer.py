#/aws_cost_optimizer/collectors/cost/cost_explorer.py

from __future__ import annotations

from typing import Any

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION


def _paginate_cost_and_usage(
    client: Any,
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    results_by_period: dict[str, dict[str, Any]] = {}

    response = client.get_cost_and_usage(**params)

    _merge_groups_by_period(
        results_by_period,
        response,
    )

    while (
        "NextPageToken" in response
        and response["NextPageToken"]
    ):
        params["NextPageToken"] = response[
            "NextPageToken"
        ]

        response = client.get_cost_and_usage(
            **params
        )

        _merge_groups_by_period(
            results_by_period,
            response,
        )

    return list(results_by_period.values())


def _merge_groups_by_period(
    results_by_period: dict[str, dict[str, Any]],
    response: dict[str, Any],
) -> None:

    for block in response.get(
        "ResultsByTime",
        [],
    ):
        start = block["TimePeriod"]["Start"]

        if start not in results_by_period:
            results_by_period[start] = {
                "TimePeriod": block["TimePeriod"],
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

        results_by_period[start]["Groups"].extend(
            block.get("Groups", [])
        )


def get_cost_usage(
    start: str,
    end: str,
    region: str | None = None,
) -> list[dict[str, Any]]:
    client = get_client("ce", CE_REGION)
    params: dict[str, Any] = {
        "TimePeriod": {
            "Start": start,
            "End": end,
        },
        "Granularity": "MONTHLY",
        "Metrics": ["UnblendedCost"],
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


def get_regions_with_costs(
    start: str,
    end: str,
) -> list[str]:
    client = get_client("ce", CE_REGION)

    params: dict[str, Any] = {
        "TimePeriod": {
            "Start": start,
            "End": end,
        },
        "Granularity": "MONTHLY",
        "Metrics": ["UnblendedCost"],
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

            if amount > 0:
                regions.add(region)

    return list(regions)


def get_monthly_totals(
    start: str,
    end: str,
    region: str | None = None,
) -> list[dict[str, Any]]:


    client = get_client("ce", CE_REGION)

    params: dict[str, Any] = {
        "TimePeriod": {
            "Start": start,
            "End": end,
        },
        "Granularity": "MONTHLY",
        "Metrics": ["UnblendedCost"],
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