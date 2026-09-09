"""
Billing context utilities.

Billing evidence distinguishes between:

    resource
        Cost can legitimately be attributed to this resource.

    collection_plan
        Cost belongs to the collection scope and must not be treated
        as resource cost.

    service
        Cost belongs to the service and must not be treated as resource cost.

    historical
        Historical billing evidence without current resource attribution.

    unknown
        Billing exists but its attribution scope is not established.

Important invariant
-------------------
Only:

    attribution_scope == "resource"
    AND
    resource_cost_attributed == True
    AND
    claimable_resource_cost is numeric

may be used as resource-attributed financial impact.
"""

from __future__ import annotations

import re
from typing import Any

RESOURCE = "resource"
COLLECTION_PLAN = "collection_plan"
SERVICE = "service"
HISTORICAL = "historical"
UNKNOWN = "unknown"


_VALID_SCOPES = {
    RESOURCE,
    COLLECTION_PLAN,
    SERVICE,
    HISTORICAL,
    UNKNOWN,
}


_BILLING_FIELDS = (
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
)


def _safe_float(
    value: Any,
) -> float | None:

    if value is None:
        return None

    if isinstance(
        value,
        bool,
    ):
        return None

    try:
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return None


def _first_present(
    value: dict[str, Any],
    *keys: str,
) -> Any:

    for key in keys:

        candidate = value.get(key)

        if candidate is not None:
            return candidate

    return None


def _normalize_scope(
    value: Any,
) -> str:

    scope = str(value or UNKNOWN).strip().lower()

    if scope not in _VALID_SCOPES:
        return UNKNOWN

    return scope


def normalize_billing_context(
    value: Any,
) -> dict[str, Any]:

    if value is None:
        return {}

    # Legacy/simple numeric billing.
    if not isinstance(
        value,
        dict,
    ):

        amount = _safe_float(value)

        if amount is None:
            return {}

        return {
            "amount": amount,
            "currency": "USD",
            "attribution_scope": UNKNOWN,
            "resource_cost_attributed": False,
            "claimable_resource_cost": None,
        }

    result: dict[str, Any] = {}

    # --------------------------------------------------------------
    # Amount
    # --------------------------------------------------------------

    amount = _first_present(
        value,
        "amount",
        "value",
        "total",
    )

    nested_cost = value.get("cost")

    if isinstance(
        nested_cost,
        dict,
    ):

        nested_amount = _first_present(
            nested_cost,
            "amount",
            "value",
            "total",
        )

        if nested_amount is not None:
            amount = nested_amount

    normalized_amount = _safe_float(
        amount,
    )

    if normalized_amount is not None:
        result["amount"] = normalized_amount

    for key in _BILLING_FIELDS:

        candidate = value.get(key)

        if candidate is not None:
            result[key] = candidate

    usage_type = _first_present(
        value,
        "usageType",
        "usage",
        "billing_usage_type",
    )

    if usage_type is not None:
        result["usage_type"] = usage_type

    operation = _first_present(
        value,
        "operation_name",
        "operation",
    )

    if operation is not None:
        result["operation"] = operation

    currency = _first_present(
        value,
        "currency",
        "currency_id",
        "currency_code",
        "unit",
    )

    result["currency"] = currency or "USD"

    attribution_scope = _normalize_scope(
        value.get("attribution_scope"),
    )

    claimable_resource_cost = _safe_float(
        value.get(
            "claimable_resource_cost",
        )
    )

    resource_cost_attributed = (
        attribution_scope == RESOURCE and claimable_resource_cost is not None
    )

    if not resource_cost_attributed:

        claimable_resource_cost = None

    result["attribution_scope"] = attribution_scope

    result["resource_cost_attributed"] = resource_cost_attributed

    result["claimable_resource_cost"] = claimable_resource_cost

    return result


def billing_usage_types_conflict(
    resource_usage_type: Any,
    plan_usage_type: Any,
) -> bool:

    def _norm(value: Any) -> str:
        if value is None:
            return ""
        return re.sub(r"[^a-z0-9]", "", str(value).lower())

    resource = _norm(resource_usage_type)
    plan = _norm(plan_usage_type)

    if not resource or not plan:
        return False
    if resource in plan or plan in resource:
        return False

    return True


def billing_from_plan(
    plan: dict[str, Any] | None,
) -> dict[str, Any]:

    if not isinstance(
        plan,
        dict,
    ):
        return {}

    existing = plan.get(
        "billing",
    )

    if (
        isinstance(
            existing,
            dict,
        )
        and existing
    ):

        return normalize_billing_context(
            existing,
        )

    cost_context = plan.get(
        "cost_context",
    )

    if (
        isinstance(
            cost_context,
            dict,
        )
        and cost_context
    ):

        normalized = normalize_billing_context(
            cost_context,
        )

        if normalized:
            return normalized

    result: dict[str, Any] = {}

    amount = _first_present(
        plan,
        "cost",
        "amount",
    )

    # Numeric cost_context is the planner's canonical way of carrying
    # the plan's total billing amount.
    if isinstance(plan.get("cost_context"), (int, float)) and not isinstance(
        plan.get("cost_context"), bool
    ):
        amount = plan["cost_context"]

    normalized_amount = _safe_float(
        amount,
    )

    if normalized_amount is not None:
        result["amount"] = normalized_amount

    for key in (
        "service",
        "usage_type",
        "operation",
        "region",
        "availability_zone",
        "currency",
        "resource_type",
        "account_id",
    ):

        candidate = plan.get(key)

        if candidate is not None:
            result[key] = candidate

    if result:

        result["currency"] = result.get("currency") or "USD"

        result["attribution_scope"] = COLLECTION_PLAN

        result["resource_cost_attributed"] = False

        result["claimable_resource_cost"] = None

    return result
