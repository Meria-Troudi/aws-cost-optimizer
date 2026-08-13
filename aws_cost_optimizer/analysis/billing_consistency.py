"""Billing vs resource consistency checks."""

from __future__ import annotations

import re
from typing import Any


def extract_rds_class(
    usage_type: str | None,
) -> str | None:
    """
    Extract the RDS instance class from a billing usage type.

    Examples:
        EU-InstanceUsage:db.r6g.large
        EU-InstanceUsage:db.t3.large
        InstanceUsage:db.t3.micro
        APN1-InstanceUsage:db.r6g.xl

    Returns:
        db.r6g.large
        db.t3.large
        db.t3.micro
        db.r6g.xl
    """

    if not usage_type:
        return None

    match = re.search(
        r"InstanceUsage[:.]([A-Za-z0-9._-]+)$",
        usage_type,
    )

    if match:
        return match.group(1)

    return None


def compare_rds_billing_class(
    resource_class: str | None,
    billing_usage_type: str | None,
) -> dict[str, Any]:

    if not resource_class:
        return {
            "status": "unknown",
            "reason": "resource_instance_class_missing",
        }

    if not billing_usage_type:
        return {
            "status": "unknown",
            "reason": "billing_usage_type_missing",
        }

    billing_class = extract_rds_class(
        billing_usage_type
    )

    if not billing_class:
        return {
            "status": "unknown",
            "reason": "billing_class_not_parsed",
            "billing_usage_type": billing_usage_type,
        }

    if billing_class == resource_class:
        return {
            "status": "match",
            "resource_class": resource_class,
            "billing_class": billing_class,
            "billing_usage_type": billing_usage_type,
        }

    return {
        "status": "different",
        "resource_class": resource_class,
        "billing_class": billing_class,
        "billing_usage_type": billing_usage_type,
        "reason": (
            "Billing usage type refers to a different instance "
            "class. This may represent historical usage after "
            "a previous resize."
        ),
    }


def billing_from_cost_context(
    cost_context: dict[str, Any] | None,
) -> dict[str, Any]:

    if not cost_context:
        return {}

    cost = cost_context.get("cost") or {}

    return {
        "service": cost_context.get("service"),
        "usage_type": cost_context.get("usage_type"),
        "region": cost_context.get("region"),
        "cost": cost.get("value"),
        "currency": cost.get("currency", "USD"),
    }


def _rds_resources(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    rds = []

    for resource in resources or []:

        if not isinstance(resource, dict):
            continue

        resource_type = (
            resource.get("resource_type")
            or resource.get("type")
        )

        if resource_type in (
            "rds_instance",
            "rds",
        ):
            rds.append(resource)

    return rds


def _resource_instance_class(
    resource: dict[str, Any],
) -> str | None:

    configuration = (
        resource.get("configuration") or {}
    )

    if not isinstance(
        configuration,
        dict,
    ):
        return None

    value = configuration.get(
        "instance_class"
    )

    if value:
        return str(value)

    identity = resource.get("identity") or {}
    if isinstance(identity, dict):
        db_class = identity.get("db_instance_class")
        if db_class:
            return str(db_class)

    return None


def should_attach_rds_billing_context(
    resource: dict[str, Any],
    cost_context: dict[str, Any],
) -> bool:
    """
    Attach usage-type billing only to RDS resources whose current
    instance class matches the billed class.
    """
    usage_type = cost_context.get("usage_type")
    billing_class = extract_rds_class(usage_type)
    if not billing_class:
        return True

    resource_type = (resource.get("resource_type") or "").lower()
    if resource_type not in {"rds_instance", "rds"}:
        return True

    resource_class = _resource_instance_class(resource)
    if not resource_class:
        return False

    return resource_class == billing_class


def _resource_id(
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

    return str(
        resource.get("resource_id")
        or resource.get("id")
        or configuration.get(
            "db_instance_identifier",
            "unknown",
        )
    )


def _historical_classes(
    resource: dict[str, Any],
) -> list[str]:

    """
    Return instance classes observed in CloudTrail history.

    Expected collector structure:

        observations:
            cloudtrail:
                instance_class_history:
                    - db.t3.large
                    - db.r6g.large
    """

    observations = resource.get(
        "observations",
        {},
    )

    if not isinstance(
        observations,
        dict,
    ):
        return []

    cloudtrail = observations.get(
        "cloudtrail",
        {},
    )

    if not isinstance(
        cloudtrail,
        dict,
    ):
        return []

    history = cloudtrail.get(
        "instance_class_history",
        [],
    )

    if not isinstance(
        history,
        list,
    ):
        return []

    result = []

    for value in history:

        if value:
            value = str(value)

            if value not in result:
                result.append(value)

    return result


def evaluate_rds_billing_plans(
    collection_plans: list[dict[str, Any]],
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    rds_resources = _rds_resources(
        resources
    )

    rds_by_class: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for resource in rds_resources:

        instance_class = (
            _resource_instance_class(
                resource
            )
        )

        if instance_class:

            rds_by_class.setdefault(
                instance_class,
                [],
            ).append(resource)

    for plan in collection_plans or []:

        if not isinstance(
            plan,
            dict,
        ):
            continue

        service = (
            plan.get("service")
            or ""
        )

        if "rds" not in service.lower():
            continue

        usage_type = plan.get(
            "usage_type"
        )

        billed_class = extract_rds_class(
            usage_type
        )

        if not billed_class:
            continue

        region = (
            plan.get("region")
            or "Unknown"
        )

        cost_context = plan.get(
            "cost_context"
        )

        matched = rds_by_class.get(
            billed_class,
            [],
        )

        if matched:

            for resource in matched:

                resource_class = (
                    _resource_instance_class(
                        resource
                    )
                )

                findings.append(
                    {
                        "finding_type":
                            "rds_billing_resource_match",

                        "severity":
                            "info",

                        "confidence":
                            "high",

                        "resource_type":
                            "rds_instance",

                        "resource_id":
                            _resource_id(resource),

                        "scope":
                            region,

                        "reason":
                            (
                                f"Billing usage {billed_class} "
                                f"matches the currently discovered "
                                f"RDS instance class."
                            ),

                        "metadata":
                            {
                                "billing_instance_class":
                                    billed_class,

                                "actual_instance_class":
                                    resource_class,

                                "region":
                                    region,

                                "usage_type":
                                    usage_type,

                                "billing_cost":
                                    cost_context,
                            },

                        "conditions":
                            [
                                {
                                    "name":
                                        "billing_resource_match",

                                    "expected":
                                        billed_class,

                                    "actual":
                                        resource_class,

                                    "status":
                                        "PASS",
                                }
                            ],

                        "limitations":
                            [],

                        "recommendation_eligible":
                            True,

                        "blocks_optimization":
                            False,
                    }
                )

            continue
        historical_match = False
        historical_resources = []

        for resource in rds_resources:

            history = _historical_classes(
                resource
            )

            if billed_class in history:

                historical_match = True

                historical_resources.append(
                    _resource_id(resource)
                )

        if historical_match:

            findings.append(
                {
                    "finding_type":
                        "rds_historical_billing_class",

                    "severity":
                        "info",

                    "confidence":
                        "high",

                    "resource_type":
                        "rds_instance",

                    "resource_id":
                        historical_resources[0]
                        if len(historical_resources) == 1
                        else None,

                    "scope":
                        region,

                    "reason":
                        (
                            f"Billing contains usage for "
                            f"{billed_class}, but no current "
                            f"{billed_class} RDS instance exists. "
                            f"The class was observed in resource "
                            f"history and may represent usage before "
                            f"a previous instance resize."
                        ),

                    "metadata":
                        {
                            "billing_instance_class":
                                billed_class,

                            "historical_resources":
                                historical_resources,

                            "region":
                                region,

                            "usage_type":
                                usage_type,

                            "billing_cost":
                                cost_context,
                        },

                    "conditions":
                        [
                            {
                                "name":
                                    "historical_class_detected",

                                "expected":
                                    billed_class,

                                "actual":
                                    billed_class,

                                "status":
                                    "PASS",
                            }
                        ],

                    "limitations":
                        [
                            (
                                "Historical attribution is based on "
                                "available CloudTrail events."
                            ),
                            (
                                "Billing usage may span a period "
                                "during which the instance class "
                                "changed."
                            ),
                        ],

                    "recommendation_eligible":
                        True,

                    "blocks_optimization":
                        False,
                }
            )

            continue
        findings.append(
            {
                "finding_type":
                    "rds_unmatched_billing_usage",

                "severity":
                    "medium",

                "confidence":
                    "medium",

                "resource_type":
                    "rds_instance",

                "resource_id":
                    None,

                "scope":
                    region,

                "reason":
                    (
                        f"RDS billing contains usage for "
                        f"{billed_class}, but no current or "
                        f"historically observed RDS instance "
                        f"with this class was discovered."
                    ),

                "metadata":
                    {
                        "billing_instance_class":
                            billed_class,

                        "billing_cost":
                            cost_context,

                        "region":
                            region,

                        "usage_type":
                            usage_type,
                    },

                "conditions":
                    [
                        {
                            "name":
                                "billing_resource_match",

                            "expected":
                                (
                                    f"current or historical "
                                    f"{billed_class} instance"
                                ),

                            "actual":
                                "none discovered",

                            "status":
                                "FAIL",
                        }
                    ],

                "limitations":
                    [
                        (
                            "Billing usage may reference a "
                            "historical resource for which "
                            "CloudTrail history is unavailable."
                        ),
                    ],

                "recommendation_eligible":
                    False,

                "blocks_optimization":
                    True,
            }
        )

    return findings