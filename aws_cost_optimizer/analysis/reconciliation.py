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

_INSTANCE_USAGE_RE = re.compile(
    r"InstanceUsage:(?P<instance_class>[A-Za-z0-9._-]+)$"
)


def _resource_scope_attribution(
    *,
    billing: dict[str, Any],
    cost: float,
    matched_ids: list[str],
    collection_complete: bool,
) -> tuple[dict[str, Any], str, bool, float | None]:
    """Decide attribution from match count + collection completeness.

    resource iff exactly one resource matched this billing line AND
    collection for it was not partial (a partial run could be hiding
    an undiscovered sibling that shares the same bill). Otherwise the
    amount is collection-plan (shared) or unknown evidence -- never a
    single resource's claimed cost.
    """

    if (
        len(matched_ids) == 1
        and collection_complete
    ):
        attribution_scope = RESOURCE

    elif cost > 0:
        attribution_scope = COLLECTION_PLAN

    else:
        attribution_scope = UNKNOWN

    resource_cost_attributed = (
        attribution_scope == RESOURCE
    )

    claimable_resource_cost = (
        cost
        if (
            resource_cost_attributed
            and len(matched_ids) == 1
        )
        else None
    )

    normalized_billing = dict(billing)

    normalized_billing[
        "attribution_scope"
    ] = attribution_scope

    normalized_billing[
        "resource_cost_attributed"
    ] = resource_cost_attributed

    normalized_billing[
        "claimable_resource_cost"
    ] = claimable_resource_cost

    return (
        normalized_billing,
        attribution_scope,
        resource_cost_attributed,
        claimable_resource_cost,
    )


def _fixed_scope_attribution(
    *,
    billing: dict[str, Any],
    scope: str,
) -> tuple[dict[str, Any], str, bool, float | None]:
    """Force a scope that is never eligible for resource attribution.

    Used for historical/mismatched billing: no matter how many
    resources exist today, this amount describes a configuration
    that is not the current resource, so it may never be claimed as
    that resource's cost.
    """

    normalized_billing = dict(billing)

    normalized_billing[
        "attribution_scope"
    ] = scope

    normalized_billing[
        "resource_cost_attributed"
    ] = False

    normalized_billing[
        "claimable_resource_cost"
    ] = None

    return normalized_billing, scope, False, None


def reconcile_collection_plan(
    plan: dict[str, Any] | None,
    discovered_resources: list[dict[str, Any]] | None,
    *,
    collection_complete: bool = True,
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

    # NOTE: usage-type reliability no longer gates attribution --
    # that decision now belongs entirely to _resource_scope_attribution's
    # match-count + collection-completeness check, computed per branch
    # below, after matching. Deciding it here (before any matching had
    # even happened) was the bug: every branch inherited whatever
    # scope this produced, including CURRENT_MISMATCH and HISTORICAL,
    # which must never be resource-scoped regardless of match count.

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

        (
            normalized_billing,
            attribution_scope,
            resource_cost_attributed,
            claimable_resource_cost,
        ) = _fixed_scope_attribution(
            billing=billing,
            scope=UNKNOWN,
        )

        return {
            **base,

            "billing":
                normalized_billing,
            "cost":
                cost,
            "cost_attribution":
                attribution_scope,
            "resource_cost_attributed":
                resource_cost_attributed,
            "claimable_resource_cost":
                claimable_resource_cost,

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

                (
                    normalized_billing,
                    attribution_scope,
                    resource_cost_attributed,
                    claimable_resource_cost,
                ) = _fixed_scope_attribution(
                    billing=billing,
                    # This billing amount describes a resource
                    # configuration that does not match anything
                    # discovered today -- it must never be read as
                    # the current resource's cost, no matter how
                    # many (or how few) current resources exist.
                    scope=HISTORICAL,
                )

                return {
                    **base,

                    "billing":
                        normalized_billing,
                    "cost":
                        cost,
                    "cost_attribution":
                        attribution_scope,
                    "resource_cost_attributed":
                        resource_cost_attributed,
                    "claimable_resource_cost":
                        claimable_resource_cost,

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

            (
                normalized_billing,
                attribution_scope,
                resource_cost_attributed,
                claimable_resource_cost,
            ) = _resource_scope_attribution(
                billing=billing,
                cost=cost,
                matched_ids=matched_ids,
                collection_complete=collection_complete,
            )

            return {
                **base,

                "billing":
                    normalized_billing,
                "cost":
                    cost,
                "cost_attribution":
                    attribution_scope,
                "resource_cost_attributed":
                    resource_cost_attributed,
                "claimable_resource_cost":
                    claimable_resource_cost,

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

        # No inferable billing identity to filter by, so every
        # discovered resource is a candidate match for this plan --
        # if that's exactly one resource (and collection was not
        # partial), it genuinely is that resource's cost; if several
        # share this collector run, none may individually claim it.
        (
            normalized_billing,
            attribution_scope,
            resource_cost_attributed,
            claimable_resource_cost,
        ) = _resource_scope_attribution(
            billing=billing,
            cost=cost,
            matched_ids=resource_ids,
            collection_complete=collection_complete,
        )

        return {
            **base,

            "billing":
                normalized_billing,
            "cost":
                cost,
            "cost_attribution":
                attribution_scope,
            "resource_cost_attributed":
                resource_cost_attributed,
            "claimable_resource_cost":
                claimable_resource_cost,

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

    (
        normalized_billing,
        attribution_scope,
        resource_cost_attributed,
        claimable_resource_cost,
    ) = _fixed_scope_attribution(
        billing=billing,
        scope=HISTORICAL,
    )

    return {
        **base,

        "billing":
            normalized_billing,
        "cost":
            cost,
        "cost_attribution":
            attribution_scope,
        "resource_cost_attributed":
            resource_cost_attributed,
        "claimable_resource_cost":
            claimable_resource_cost,

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

        "claimable_resource_cost":
            None,

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