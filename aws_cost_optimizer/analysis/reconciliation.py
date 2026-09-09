"""
Generic billing/resource reconciliation.
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

CURRENT = "current"
CURRENT_MISMATCH = "current_mismatch"
HISTORICAL_ONLY = HISTORICAL
NO_COST = "no_cost"
UNKNOWN_STATUS = "unknown"

_INSTANCE_USAGE_RE = re.compile(r"InstanceUsage:(?P<instance_class>[A-Za-z0-9._-]+)$")

_VPC_ENDPOINT_HOURS_RE = re.compile(r"VpcEndpoint-Hours$", re.IGNORECASE)


def _configuration_and_identity(
    resource: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return resource configuration and identity dictionaries."""

    configuration = resource.get("configuration", {})
    if not isinstance(configuration, dict):
        configuration = {}

    identity = resource.get("identity", {})
    if not isinstance(identity, dict):
        identity = {}

    return configuration, identity


def _build_result(
    base: dict[str, Any],
    *,
    normalized_billing: dict[str, Any],
    cost: float,
    attribution_scope: str,
    resource_cost_attributed: bool,
    claimable_resource_cost: float | None,
    status: str,
    reason: str,
    resources_for_analysis: list[dict[str, Any]],
    matched_resources: list[dict[str, Any]],
    related_resources: list[dict[str, Any]],
    resource_ids: list[str],
    matched_resource_ids: list[str],
    historical_evidence: list[dict[str, Any]],
    analysis_status: str,
    recommendation_allowed: bool,
    confidence: str,
) -> dict[str, Any]:
    """Build a normalized reconciliation result."""

    return {
        **base,
        "billing": normalized_billing,
        "cost": cost,
        "cost_attribution": attribution_scope,
        "resource_cost_attributed": resource_cost_attributed,
        "claimable_resource_cost": claimable_resource_cost,
        "status": status,
        "reason": reason,
        "resources_for_analysis": resources_for_analysis,
        "matched_resources": matched_resources,
        "related_resources": related_resources,
        "resource_ids": resource_ids,
        "matched_resource_ids": matched_resource_ids,
        "historical_evidence": historical_evidence,
        "analysis_status": analysis_status,
        "recommendation_allowed": recommendation_allowed,
        "confidence": confidence,
    }


def _resource_scope_attribution(
    *,
    billing: dict[str, Any],
    cost: float,
    matched_ids: list[str],
    collection_complete: bool,
) -> tuple[dict[str, Any], str, bool, float | None]:
    """Determine whether billing can be attributed to a specific resource."""

    if len(matched_ids) == 1 and collection_complete:
        attribution_scope = RESOURCE

    elif cost > 0:
        attribution_scope = COLLECTION_PLAN

    else:
        attribution_scope = UNKNOWN

    resource_cost_attributed = attribution_scope == RESOURCE

    claimable_resource_cost = (
        cost if (resource_cost_attributed and len(matched_ids) == 1) else None
    )

    normalized_billing = dict(billing)

    normalized_billing["attribution_scope"] = attribution_scope

    normalized_billing["resource_cost_attributed"] = resource_cost_attributed

    normalized_billing["claimable_resource_cost"] = claimable_resource_cost

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
    """Set a non-resource billing attribution scope."""

    normalized_billing = dict(billing)

    normalized_billing["attribution_scope"] = scope

    normalized_billing["resource_cost_attributed"] = False

    normalized_billing["claimable_resource_cost"] = None

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
        for resource in (discovered_resources or [])
        if isinstance(
            resource,
            dict,
        )
    ]

    billing = normalize_billing_context(billing_from_plan(plan))

    cost = _plan_amount(
        plan,
        billing,
    )

    service = plan.get("service")

    usage_type = plan.get("usage_type")

    region = plan.get("region")

    resource_type = str(plan.get("resource_type") or "unknown")

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

    billing_identity = {
        key: value
        for key, value in billing.items()
        if key
        in {
            "service",
            "usage_type",
            "operation",
            "region",
            "availability_zone",
        }
        and value is not None
    }

    base = {
        "resource_type": resource_type,
        "service": service,
        "usage_type": usage_type,
        "region": region,
        "discovered_count": len(resources),
        "billing_identity": billing_identity,
        "expected_identity": expected_identity,
    }

    if cost <= 0:

        (
            normalized_billing,
            attribution_scope,
            resource_cost_attributed,
            claimable_resource_cost,
        ) = _fixed_scope_attribution(billing=billing, scope=UNKNOWN)

        return _build_result(
            base,
            normalized_billing=normalized_billing,
            cost=cost,
            attribution_scope=attribution_scope,
            resource_cost_attributed=resource_cost_attributed,
            claimable_resource_cost=claimable_resource_cost,
            status=NO_COST,
            reason="No positive billing cost was supplied.",
            resources_for_analysis=resources,
            matched_resources=resources,
            related_resources=[],
            resource_ids=resource_ids,
            matched_resource_ids=resource_ids,
            historical_evidence=[],
            analysis_status="ready" if resources else "skipped",
            recommendation_allowed=bool(resources),
            confidence="high",
        )

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
                if resource_id(resource) != "unknown"
            ]

            if not matched_resources:

                (
                    normalized_billing,
                    attribution_scope,
                    resource_cost_attributed,
                    claimable_resource_cost,
                ) = _fixed_scope_attribution(billing=billing, scope=HISTORICAL)

                return _build_result(
                    base,
                    normalized_billing=normalized_billing,
                    cost=cost,
                    attribution_scope=attribution_scope,
                    resource_cost_attributed=resource_cost_attributed,
                    claimable_resource_cost=claimable_resource_cost,
                    status=CURRENT_MISMATCH,
                    # Usage types identify billed configuration, not a resource ID.
                    reason=(
                        "Historical billing exists, but no current "
                        "resource matches the billed configuration."
                    ),
                    resources_for_analysis=resources,
                    matched_resources=[],
                    related_resources=resources,
                    resource_ids=resource_ids,
                    matched_resource_ids=[],
                    historical_evidence=[
                        {
                            "billing_identity": expected_identity,
                            "usage_type": usage_type,
                            "amount": cost,
                            "region": region,
                        }
                    ],
                    analysis_status="ready",
                    recommendation_allowed=True,
                    confidence="medium",
                )

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

            return _build_result(
                base,
                normalized_billing=normalized_billing,
                cost=cost,
                attribution_scope=attribution_scope,
                resource_cost_attributed=resource_cost_attributed,
                claimable_resource_cost=claimable_resource_cost,
                status=CURRENT,
                reason=(
                    "Current resources were discovered and a "
                    "billing-compatible resource was found."
                ),
                resources_for_analysis=resources,
                matched_resources=matched_resources,
                related_resources=[
                    resource
                    for resource in resources
                    if resource not in matched_resources
                ],
                resource_ids=resource_ids,
                matched_resource_ids=matched_ids,
                historical_evidence=[],
                analysis_status="ready",
                recommendation_allowed=True,
                confidence="high",
            )

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

        return _build_result(
            base,
            normalized_billing=normalized_billing,
            cost=cost,
            attribution_scope=attribution_scope,
            resource_cost_attributed=resource_cost_attributed,
            claimable_resource_cost=claimable_resource_cost,
            status=CURRENT,
            reason=(
                "Current resources were discovered, but the billing "
                "usage type cannot identify a specific resource."
            ),
            resources_for_analysis=resources,
            matched_resources=resources,
            related_resources=[],
            resource_ids=resource_ids,
            matched_resource_ids=resource_ids,
            historical_evidence=[],
            analysis_status="ready",
            recommendation_allowed=True,
            confidence="high",
        )

    (
        normalized_billing,
        attribution_scope,
        resource_cost_attributed,
        claimable_resource_cost,
    ) = _fixed_scope_attribution(billing=billing, scope=HISTORICAL)

    return _build_result(
        base,
        normalized_billing=normalized_billing,
        cost=cost,
        attribution_scope=attribution_scope,
        resource_cost_attributed=resource_cost_attributed,
        claimable_resource_cost=claimable_resource_cost,
        status=HISTORICAL,
        reason="Historical billing exists, but no current resource was discovered.",
        resources_for_analysis=[],
        matched_resources=[],
        related_resources=[],
        resource_ids=[],
        matched_resource_ids=[],
        historical_evidence=[],
        analysis_status="skipped",
        recommendation_allowed=False,
        confidence="high",
    )


def resource_id(
    resource: dict[str, Any],
) -> str:
    """Return the best available resource identifier."""

    configuration, identity = _configuration_and_identity(resource)

    value = (
        resource.get("resource_id")
        or resource.get("id")
        or configuration.get("id")
        or configuration.get("name")
        or configuration.get("db_instance_identifier")
        or identity.get("resource_id")
        or identity.get("id")
        or identity.get("name")
    )

    return str(value) if value else "unknown"


def _infer_billing_identity(
    *,
    service: str | None,
    usage_type: str | None,
    billing: dict[str, Any],
) -> dict[str, Any]:
    """Infer resource identity from the billing usage type."""

    usage = str(usage_type or billing.get("usage_type") or "")

    match = _INSTANCE_USAGE_RE.search(usage)

    if match:
        return {"instance_class": match.group("instance_class")}

    if _VPC_ENDPOINT_HOURS_RE.search(usage):
        return {"endpoint_type": "Interface"}

    return {}


def _resource_matches_identity(
    resource: dict[str, Any],
    expected_identity: dict[str, Any],
) -> bool:
    """Check whether a resource matches the expected billing identity."""

    configuration, identity = _configuration_and_identity(resource)

    for key, expected in expected_identity.items():

        actual = resource.get(key) or configuration.get(key) or identity.get(key)

        if actual is None:
            return False

        if str(actual).strip().lower() != str(expected).strip().lower():
            return False

    return True


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or default)
    except (TypeError, ValueError):
        return default


def _plan_amount(
    plan: dict[str, Any],
    billing: dict[str, Any],
) -> float:
    """Return the billing amount from the collection plan."""

    amount = billing.get("amount")

    if amount is not None:

        try:
            return float(amount)
        except (TypeError, ValueError):
            pass

    cost_context = plan.get("cost_context")

    if isinstance(cost_context, dict):

        nested = cost_context.get("cost")

        if isinstance(nested, dict):
            return _as_float(nested.get("value"))

        return _as_float(cost_context.get("value"))

    return _as_float(cost_context)


def _empty_result(
    *,
    status: str,
    reason: str,
) -> dict[str, Any]:
    """Return an empty reconciliation result."""

    return {
        "status": status,
        "reason": reason,
        "billing": {},
        "cost": 0.0,
        "cost_attribution": UNKNOWN,
        "resource_cost_attributed": False,
        "claimable_resource_cost": None,
        "resource_type": "unknown",
        "region": None,
        "usage_type": None,
        "service": None,
        "discovered_count": 0,
        "billing_identity": {},
        "expected_identity": {},
        "resources_for_analysis": [],
        "matched_resources": [],
        "related_resources": [],
        "resource_ids": [],
        "matched_resource_ids": [],
        "historical_evidence": [],
        "analysis_status": "skipped",
        "recommendation_allowed": False,
        "confidence": "low",
    }
