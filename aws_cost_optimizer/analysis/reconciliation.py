"""
Generic billing/resource reconciliation.

Billing identity is evidence.

It is never assumed to be resource identity unless the billing
dimensions provide a reliable comparison.
"""

from __future__ import annotations

import re
from typing import Any

from .billing import (
    COLLECTION_PLAN,
    HISTORICAL,
    RESOURCE,
    UNKNOWN,
    billing_from_plan,
    normalize_billing_context,
)


MATCHED = "matched"
CURRENT = "current"
CURRENT_MISMATCH = "current_mismatch"
HISTORICAL_ONLY = HISTORICAL
NO_COST = "no_cost"
UNKNOWN_STATUS = "unknown"

_UNRELIABLE_RESOURCE_USAGE = {
    "EU-NatGateway-Hours",
    "APN1-NatGateway-Hours",
    "APN3-NatGateway-Hours",
    "NatGateway-Hours",
    "EU-TransitGateway-Hours",
    "EU-VpcEndpoint-Hours",
    "EU-PublicIPv4:InUseAddress",
    "EU-LoadBalancerUsage",
}

_INSTANCE_USAGE_RE = re.compile(
    r"InstanceUsage:(?P<instance_class>[A-Za-z0-9._-]+)$"
)


def reconcile_collection_plan(
    plan: dict[str, Any] | None,
    discovered_resources: list[dict[str, Any]] | None,
) -> dict[str, Any]:

    if not isinstance(
        plan,
        dict,
    ):

        return _empty_result(
            status=UNKNOWN_STATUS,
            reason="collection_plan_missing",
        )

    resources = [
        resource
        for resource in (
            discovered_resources
            or []
        )
        if isinstance(
            resource,
            dict,
        )
    ]

    billing = normalize_billing_context(
        billing_from_plan(plan)
    )

    cost = _plan_amount(
        plan,
        billing,
    )

    service = plan.get(
        "service"
    )

    usage_type = plan.get(
        "usage_type"
    )

    region = plan.get(
        "region"
    )

    resource_type = str(
        plan.get(
            "resource_type"
        )
        or "unknown"
    )

    expected_identity = _infer_billing_identity(
        service=service,
        usage_type=usage_type,
        billing=billing,
    )

    resource_ids = [
        resource_id(resource)
        for resource in resources
        if resource_id(resource) != "unknown"
    ]

    # --------------------------------------------------------------
    # CRITICAL:
    #
    # Most AWS usage types in this project identify a collection
    # class, not an individual resource.
    # --------------------------------------------------------------

    direct_resource_attribution = bool(
        expected_identity
    )

    if usage_type in _UNRELIABLE_RESOURCE_USAGE:
        direct_resource_attribution = False

    if direct_resource_attribution:

        attribution_scope = RESOURCE

    elif cost > 0:

        attribution_scope = COLLECTION_PLAN

    else:

        attribution_scope = UNKNOWN

    normalized_billing = dict(
        billing
    )

    normalized_billing[
        "attribution_scope"
    ] = attribution_scope

    normalized_billing[
        "resource_cost_attributed"
    ] = (
        attribution_scope
        == RESOURCE
    )

    billing_identity = {
        key: value
        for key, value in billing.items()
        if key in {
            "service",
            "usage_type",
            "operation",
            "region",
            "availability_zone",
        }
        and value is not None
    }

    base = {
        "billing":
            normalized_billing,

        # This remains available as collection-plan evidence.
        "cost":
            cost,

        "cost_attribution":
            attribution_scope,

        "resource_cost_attributed":
            (
                attribution_scope
                == RESOURCE
            ),

        "resource_type":
            resource_type,

        "service":
            service,

        "usage_type":
            usage_type,

        "region":
            region,

        "discovered_count":
            len(resources),

        "billing_identity":
            billing_identity,

        "expected_identity":
            expected_identity,
    }

    if cost <= 0:

        return {
            **base,

            "status":
                NO_COST,

            "reason":
                "No positive billing amount was supplied.",

            "resources_for_analysis":
                resources,

            "matched_resources":
                resources,

            "related_resources":
                [],

            "resource_ids":
                resource_ids,

            "matched_resource_ids":
                resource_ids,

            "historical_evidence":
                [],

            "analysis_status":
                (
                    "ready"
                    if resources
                    else "skipped"
                ),

            "recommendation_allowed":
                bool(resources),

            "confidence":
                "high",
        }

    if resources:

        if expected_identity:

            matched_resources = [
                resource
                for resource in resources
                if _resource_matches_identity(
                    resource,
                    expected_identity,
                )
            ]

            matched_ids = [
                resource_id(resource)
                for resource in matched_resources
                if resource_id(resource)
                != "unknown"
            ]

            if not matched_resources:

                return {
                    **base,

                    "status":
                        CURRENT_MISMATCH,

                    "reason":
                        (
                            "Historical billing identifies a "
                            "resource configuration that does "
                            "not match the current discovered "
                            "resource. Billing is retained as "
                            "historical evidence only."
                        ),

                    "resources_for_analysis":
                        resources,

                    "matched_resources":
                        [],

                    "related_resources":
                        resources,

                    "resource_ids":
                        resource_ids,

                    "matched_resource_ids":
                        [],

                    "historical_evidence": [
                        {
                            "billing_identity":
                                expected_identity,

                            "usage_type":
                                usage_type,

                            "amount":
                                cost,

                            "region":
                                region,
                        }
                    ],

                    "analysis_status":
                        "ready",

                    "recommendation_allowed":
                        True,

                    "confidence":
                        "medium",
                }

            return {
                **base,

                "status":
                    CURRENT,

                "reason":
                    (
                        "Current resources were discovered and "
                        "the billing identity is compatible with "
                        "at least one current resource."
                    ),

                "resources_for_analysis":
                    resources,

                "matched_resources":
                    matched_resources,

                "related_resources":
                    [
                        resource
                        for resource in resources
                        if resource
                        not in matched_resources
                    ],

                "resource_ids":
                    resource_ids,

                "matched_resource_ids":
                    matched_ids,

                "historical_evidence":
                    [],

                "analysis_status":
                    "ready",

                "recommendation_allowed":
                    True,

                "confidence":
                    "high",
            }

        # ----------------------------------------------------------
        # No resource identity.
        #
        # Current resources are analyzable, but the billing amount
        # belongs to the collection plan, not to a specific resource.
        # ----------------------------------------------------------

        return {
            **base,

            "status":
                CURRENT,

            "reason":
                (
                    "Current resources were discovered. "
                    "The billing usage type does not provide "
                    "a reliable resource identity, so billing "
                    "remains collection-plan evidence."
                ),

            "resources_for_analysis":
                resources,

            "matched_resources":
                resources,

            "related_resources":
                [],

            "resource_ids":
                resource_ids,

            "matched_resource_ids":
                resource_ids,

            "historical_evidence":
                [],

            "analysis_status":
                "ready",

            "recommendation_allowed":
                True,

            "confidence":
                "high",
        }

    return {
        **base,

        "status":
            HISTORICAL,

        "reason":
            (
                "Historical billing exists without a current "
                "discovered resource."
            ),

        "resources_for_analysis":
            [],

        "matched_resources":
            [],

        "related_resources":
            [],

        "resource_ids":
            [],

        "matched_resource_ids":
            [],

        "historical_evidence":
            [],

        "analysis_status":
            "skipped",

        "recommendation_allowed":
            False,

        "confidence":
            "high",
    }


def reconcile_billing(
    billing: dict[str, Any] | None,
    resources: list[dict[str, Any]],
) -> dict[str, Any]:

    return reconcile_collection_plan(
        {
            "cost_context":
                billing or {},

            "service":
                (
                    billing or {}
                ).get("service"),

            "usage_type":
                (
                    billing or {}
                ).get("usage_type"),

            "region":
                (
                    billing or {}
                ).get("region"),
        },
        resources,
    )


def reconcile_billing_plan(
    plan: dict[str, Any] | None,
    resources: list[dict[str, Any]],
) -> dict[str, Any]:

    return reconcile_collection_plan(
        plan,
        resources,
    )


def reconcile_collection_plans(
    collection_plans: list[dict[str, Any]],
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    results = []

    for plan in (
        collection_plans or []
    ):

        if not isinstance(
            plan,
            dict,
        ):
            continue

        result = reconcile_collection_plan(
            plan,
            resources,
        )

        result["plan"] = {
            "service":
                plan.get("service"),

            "usage_type":
                plan.get("usage_type"),

            "region":
                plan.get("region"),

            "resource_type":
                plan.get("resource_type"),
        }

        results.append(
            result
        )

    return results


def resource_id(
    resource: dict[str, Any],
) -> str:

    configuration = resource.get(
        "configuration",
        {},
    )

    if not isinstance(
        configuration,
        dict,
    ):
        configuration = {}

    identity = resource.get(
        "identity",
        {},
    )

    if not isinstance(
        identity,
        dict,
    ):
        identity = {}

    value = (
        resource.get("resource_id")
        or resource.get("id")
        or configuration.get("id")
        or configuration.get("name")
        or configuration.get(
            "db_instance_identifier"
        )
        or identity.get("resource_id")
        or identity.get("id")
        or identity.get("name")
    )

    return (
        str(value)
        if value
        else "unknown"
    )


def _infer_billing_identity(
    *,
    service: str | None,
    usage_type: str | None,
    billing: dict[str, Any],
) -> dict[str, Any]:

    usage = str(
        usage_type
        or billing.get("usage_type")
        or ""
    )

    match = _INSTANCE_USAGE_RE.search(
        usage
    )

    if match:
        return {
            "instance_class":
                match.group(
                    "instance_class"
                )
        }

    return {}


def _resource_matches_identity(
    resource: dict[str, Any],
    expected_identity: dict[str, Any],
) -> bool:

    configuration = resource.get(
        "configuration",
        {},
    )

    if not isinstance(
        configuration,
        dict,
    ):
        configuration = {}

    identity = resource.get(
        "identity",
        {},
    )

    if not isinstance(
        identity,
        dict,
    ):
        identity = {}

    for key, expected in (
        expected_identity.items()
    ):

        actual = (
            resource.get(key)
            or configuration.get(key)
            or identity.get(key)
        )

        if actual is None:
            return False

        if (
            str(actual).strip().lower()
            !=
            str(expected).strip().lower()
        ):
            return False

    return True


def _plan_amount(
    plan: dict[str, Any],
    billing: dict[str, Any],
) -> float:

    amount = billing.get(
        "amount"
    )

    if amount is not None:

        try:
            return float(amount)

        except (
            TypeError,
            ValueError,
        ):
            pass

    cost_context = plan.get(
        "cost_context"
    )

    if isinstance(
        cost_context,
        dict,
    ):

        nested = cost_context.get(
            "cost"
        )

        if isinstance(
            nested,
            dict,
        ):

            try:
                return float(
                    nested.get(
                        "value"
                    )
                    or 0
                )

            except (
                TypeError,
                ValueError,
            ):
                return 0.0

        try:
            return float(
                cost_context.get(
                    "value"
                )
                or 0
            )

        except (
            TypeError,
            ValueError,
        ):
            return 0.0

    try:
        return float(
            cost_context
            or 0
        )

    except (
        TypeError,
        ValueError,
    ):
        return 0.0


def _empty_result(
    *,
    status: str,
    reason: str,
) -> dict[str, Any]:

    return {
        "status":
            status,

        "reason":
            reason,

        "billing":
            {},

        "cost":
            0.0,

        "cost_attribution":
            UNKNOWN,

        "resource_cost_attributed":
            False,

        "resource_type":
            "unknown",

        "region":
            None,

        "usage_type":
            None,

        "service":
            None,

        "discovered_count":
            0,

        "billing_identity":
            {},

        "expected_identity":
            {},

        "resources_for_analysis":
            [],

        "matched_resources":
            [],

        "related_resources":
            [],

        "resource_ids":
            [],

        "matched_resource_ids":
            [],

        "historical_evidence":
            [],

        "analysis_status":
            "skipped",

        "recommendation_allowed":
            False,

        "confidence":
            "low",
    }