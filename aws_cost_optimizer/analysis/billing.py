"""
Billing context utilities.

"""

from __future__ import annotations

from typing import Any


RESOURCE = "resource"
COLLECTION_PLAN = "collection_plan"
SERVICE = "service"
HISTORICAL = "historical"
UNKNOWN = "unknown"


def normalize_billing_context(
    value: Any,
) -> dict[str, Any]:


    if value is None:
        return {}

    if not isinstance(value, dict):

        try:
            return {
                "amount": float(value),
                "attribution_scope": UNKNOWN,
                "resource_cost_attributed": False,
            }

        except (
            TypeError,
            ValueError,
        ):
            return {}

    result: dict[str, Any] = {}

    amount = value.get(
        "amount",
        value.get(
            "value",
            value.get(
                "total",
            ),
        ),
    )

    cost = value.get(
        "cost"
    )

    if isinstance(
        cost,
        dict,
    ):

        nested_value = cost.get(
            "value"
        )

        if nested_value is not None:
            amount = nested_value

        if amount is None:
            amount = cost.get(
                "total"
            )

    if amount is not None:

        try:
            result["amount"] = float(
                amount
            )

        except (
            TypeError,
            ValueError,
        ):
            pass

    for key in (
        "service",
        "usage_type",
        "operation",
        "region",
        "availability_zone",
        "currency",
        "resource_type",
        "account_id",
        "start_date",
        "end_date",
    ):

        if key in value:
            result[key] = value[key]

    result["currency"] = (
        result.get("currency")
        or value.get("currency_id")
        or value.get("currency_code")
        or "USD"
    )

    if "usage_type" not in result:

        for alias in (
            "usageType",
            "usage",
            "billing_usage_type",
        ):

            if alias in value:

                result[
                    "usage_type"
                ] = value[alias]

                break

    attribution_scope = value.get(
        "attribution_scope"
    )

    if attribution_scope not in {
        RESOURCE,
        COLLECTION_PLAN,
        SERVICE,
        HISTORICAL,
        UNKNOWN,
    }:

        attribution_scope = UNKNOWN

    result[
        "attribution_scope"
    ] = attribution_scope

    resource_cost_attributed = value.get(
        "resource_cost_attributed"
    )

    if not isinstance(
        resource_cost_attributed,
        bool,
    ):

        resource_cost_attributed = (
            attribution_scope
            == RESOURCE
        )

    result[
        "resource_cost_attributed"
    ] = resource_cost_attributed

    return result


def billing_from_plan(
    plan: dict[str, Any] | None,
) -> dict[str, Any]:

    if not isinstance(
        plan,
        dict,
    ):
        return {}

    existing = plan.get(
        "billing"
    )

    if isinstance(
        existing,
        dict,
    ) and existing:

        result = normalize_billing_context(
            existing
        )

        if "attribution_scope" not in result:
            result[
                "attribution_scope"
            ] = UNKNOWN

        return result

    cost_context = plan.get(
        "cost_context"
    )

    normalized = normalize_billing_context(
        cost_context
    )

    if normalized:
        return normalized

    result: dict[str, Any] = {}

    amount = plan.get(
        "cost"
    )

    if amount is not None:

        try:
            result[
                "amount"
            ] = float(amount)

        except (
            TypeError,
            ValueError,
        ):
            pass

    for key in (
        "service",
        "usage_type",
        "operation",
        "region",
        "availability_zone",
        "currency",
        "resource_type",
    ):

        if plan.get(key) is not None:
            result[key] = plan.get(key)

    result[
        "attribution_scope"
    ] = COLLECTION_PLAN

    result[
        "resource_cost_attributed"
    ] = False

    return result