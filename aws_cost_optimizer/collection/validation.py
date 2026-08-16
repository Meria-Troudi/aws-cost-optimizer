"""
Common post-collection validation and billing reconciliation.
"""

from __future__ import annotations

from typing import Any

from aws_cost_optimizer.analysis.reconciliation import (
    CURRENT,
    CURRENT_MISMATCH,
    HISTORICAL,
    HISTORICAL_ONLY,
    NO_COST,
    UNKNOWN,
    reconcile_collection_plan,
)


def _plan_cost(
    plan: dict[str, Any],
) -> float:
    cost_context = plan.get("cost_context")

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
                    nested.get("value")
                    or 0
                )
            except (TypeError, ValueError):
                return 0.0

        try:
            return float(
                cost_context.get("value")
                or 0
            )
        except (TypeError, ValueError):
            return 0.0

    try:
        return float(
            cost_context
            or 0
        )
    except (TypeError, ValueError):
        return 0.0


def enrich_collection_result(
    plan: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:

    discovered_resources = (
        result.get("resource_data")
        or []
    )

    reconciliation = (
        reconcile_collection_plan(
            plan,
            discovered_resources,
        )
    )

    status = reconciliation.get(
        "status"
    )

    completed = (
        result.get("status")
        == "completed"
    )

    resources_for_analysis = (
        reconciliation.get(
            "resources_for_analysis"
        )
        or []
    )

    analysis_ready = (
        completed
        and bool(
            resources_for_analysis
        )
        and status != HISTORICAL
    )

    return {
        **result,

        "service":
            plan.get("service"),

        "usage_type":
            plan.get("usage_type"),

        "resource_type":
            plan.get("resource_type"),

        "cost":
            _plan_cost(plan),

        "discovered_count":
            len(discovered_resources),

        "resource_count":
            len(resources_for_analysis),

        "resource_ids":
            reconciliation.get(
                "resource_ids"
            )
            or [],

        "matched_resource_data":
            reconciliation.get(
                "matched_resources"
            )
            or [],

        "related_resource_data":
            reconciliation.get(
                "related_resources"
            )
            or [],

        "resources_for_analysis":
            resources_for_analysis,

        "discovered_resource_data":
            discovered_resources,

        "reconciliation_status":
            status,

        "reconciliation":
            reconciliation,

        "match_status":
            status,

        "match_reason":
            reconciliation.get(
                "reason"
            ),

        "expected_instance_class":
            (
                reconciliation.get(
                    "expected_identity"
                )
                or {}
            ).get(
                "instance_class"
            ),

        "matched":
            status == CURRENT,

        "historical_unmatched":
            status == HISTORICAL,

        "recommendation_allowed":
            analysis_ready,

        "analysis_status":
            (
                "ready"
                if analysis_ready
                else "skipped"
            ),

        "billing_context": {
            "service":
                plan.get("service"),
            "usage_type":
                plan.get("usage_type"),
            "region":
                plan.get("region"),
            "cost":
                _plan_cost(plan),
        },
    }


def _build_reconciliation_finding(
    plan: dict[str, Any],
    enriched: dict[str, Any],
) -> dict[str, Any] | None:

    status = enriched.get(
        "reconciliation_status"
    )
    if status in {
        CURRENT,
        NO_COST,
    }:
        return None

    if status == HISTORICAL:

        resource_id = (
            "billing:"
            f"{plan.get('service') or 'unknown'}:"
            f"{plan.get('usage_type') or 'unknown'}:"
            f"{plan.get('region') or 'unknown'}"
        )

        cost = float(
            enriched.get(
                "cost",
                0,
            )
        )

        reason = (
            f"{plan.get('service') or 'Service'} billing "
            f"usage type {plan.get('usage_type') or 'unknown'} "
            f"represents about ${cost:,.2f}, but no current "
            f"{plan.get('resource_type') or 'resource'} was "
            f"discovered in {plan.get('region') or 'the scanned scope'}. "
            "The spend is retained as historical evidence. "
            "No current resource exists for a resource-level "
            "optimization recommendation."
        )

        return {
            "finding_type":
                "historical_unmatched",

            "finding_key":
                "historical_unmatched",

            "category":
                "data_quality",

            "status":
                "informational",

            "title":
                "Historical cost has no current resource",

            "resource_type":
                plan.get(
                    "resource_type"
                )
                or "unknown",

            "resource_id":
                resource_id,

            "resource_ids":
                [],

            "analyzer":
                "billing_reconciliation",

            "analyzer_version":
                "2.0",

            "severity":
                "medium",

            "confidence":
                "high",

            "reason":
                reason,

            "conditions": [
                {
                    "name":
                        "billing_usage",

                    "value": {
                        "service":
                            plan.get("service"),

                        "usage_type":
                            plan.get("usage_type"),

                        "region":
                            plan.get("region"),

                        "cost":
                            cost,
                    },

                    "description":
                        "Historical billing exists for the collection plan.",

                    "source": [
                        "Cost Explorer",
                        "CostRecord",
                    ],
                },

                {
                    "name":
                        "current_resource_count",

                    "value":
                        0,

                    "description":
                        "No current resource was discovered.",

                    "source": [
                        "resource collector",
                    ],
                },
            ],

            "evidence": {
                "metrics": {},
                "configuration": {},
                "topology": {},

                "resource": {
                    "resource_id":
                        resource_id,

                    "resource_type":
                        plan.get(
                            "resource_type"
                        ),

                    "region":
                        plan.get(
                            "region"
                        ),
                },

                "derived": {
                    "reconciliation_status":
                        HISTORICAL,

                    "billing_cost":
                        cost,

                    "billing_usage_type":
                        plan.get(
                            "usage_type"
                        ),

                    "discovered_count":
                        0,
                },

                "data_quality": {
                    "current_resource_available":
                        False,

                    "historical_billing_available":
                        True,
                },
            },

            "observation_period":
                None,

            "limitations": [
                (
                    "Historical billing does not identify a "
                    "currently active resource by itself."
                ),
            ],

            "metadata": {
                "service":
                    plan.get("service"),

                "usage_type":
                    plan.get("usage_type"),

                "region":
                    plan.get("region"),

                "cost":
                    cost,

                "reconciliation_status":
                    HISTORICAL,
            },

            "recommendation_eligible":
                False,

            "aggregation_scope":
                "region",
        }
    if status == CURRENT_MISMATCH:

        resource_ids = (
            enriched.get(
                "resource_ids"
            )
            or []
        )

        expected_identity = (
            enriched.get(
                "reconciliation",
                {},
            ).get(
                "expected_identity",
                {},
            )
            or {}
        )

        discovered_resources = (
            enriched.get(
                "discovered_resource_data"
            )
            or []
        )

        current_classes = []

        for resource in discovered_resources:

            configuration = resource.get(
                "configuration",
                {},
            )

            if not isinstance(
                configuration,
                dict,
            ):
                continue

            value = (
                configuration.get(
                    "instance_class"
                )
                or configuration.get(
                    "db_instance_class"
                )
            )

            if value and value not in current_classes:
                current_classes.append(
                    str(value)
                )

        expected_class = (
            expected_identity.get(
                "instance_class"
            )
        )

        current_label = (
            ", ".join(
                current_classes
            )
            if current_classes
            else "current discovered configuration"
        )

        if expected_class:

            reason = (
                f"Billing usage {plan.get('usage_type')} "
                f"indicates {expected_class}, while the current "
                f"resource is {current_label}. This is a billing/"
                "resource attribution mismatch. The current resource "
                "remains fully eligible for its normal service "
                "optimization analysis."
            )

        else:

            reason = (
                f"Billing usage {plan.get('usage_type')} does not "
                "match the identity of the currently discovered "
                "resource. The current resource remains fully "
                "eligible for normal optimization analysis."
            )

        return {
            "finding_type":
                "billing_resource_mismatch",

            "title":
                "Billing resource mismatch",

            "resource_type":
                plan.get(
                    "resource_type"
                )
                or "unknown",

            "resource_id":
                resource_ids[0]
                if resource_ids
                else "unknown",

            "resource_ids":
                resource_ids,

            "analyzer":
                "billing_reconciliation",

            "analyzer_version":
                "2.0",

            "severity":
                "medium",

            "confidence":
                "high",

            "reason":
                reason,

            "conditions": [
                {
                    "name":
                        "billing_identity",

                    "value": {
                        "usage_type":
                            plan.get(
                                "usage_type"
                            ),

                        "expected_identity":
                            expected_identity,
                    },

                    "description":
                        "Identity inferred from the billing usage type.",

                    "source": [
                        "Cost Explorer",
                        "billing usage type",
                    ],
                },

                {
                    "name":
                        "current_resource",

                    "value": {
                        "resource_ids":
                            resource_ids,

                        "current_instance_classes":
                            current_classes,
                    },

                    "description":
                        "Current resource inventory differs from the billing identity.",

                    "source": [
                        "resource collector",
                    ],
                },
            ],

            "evidence": {
                "metrics": {},

                "configuration":
                    (
                        discovered_resources[0].get(
                            "configuration",
                            {},
                        )
                        if discovered_resources
                        else {}
                    ),

                "topology":
                    (
                        discovered_resources[0].get(
                            "topology",
                            {},
                        )
                        if discovered_resources
                        else {}
                    ),

                "resource": {
                    "resource_id":
                        resource_ids[0]
                        if resource_ids
                        else "unknown",

                    "resource_type":
                        plan.get(
                            "resource_type"
                        ),

                    "region":
                        plan.get(
                            "region"
                        ),
                },

                "derived": {
                    "reconciliation_status":
                        CURRENT_MISMATCH,

                    "billing_cost":
                        enriched.get(
                            "cost",
                            0,
                        ),

                    "expected_identity":
                        expected_identity,

                    "current_instance_classes":
                        current_classes,
                },

                "data_quality": {
                    "current_resource_available":
                        True,

                    "billing_identity_available":
                        bool(expected_identity),
                },
            },

            "observation_period":
                None,

            "limitations": [
                (
                    "Billing usage type represents historical "
                    "billing evidence and does not necessarily "
                    "identify the current resource."
                ),

                (
                    "This mismatch must not block service-specific "
                    "optimization analysis of the current resource."
                ),
            ],

            "metadata": {
                "service":
                    plan.get("service"),

                "usage_type":
                    plan.get("usage_type"),

                "region":
                    plan.get("region"),

                "cost":
                    enriched.get(
                        "cost",
                        0,
                    ),

                "expected_identity":
                    expected_identity,

                "current_resource_ids":
                    resource_ids,
            },
            "recommendation_eligible":
                False,

            "aggregation_scope":
                "resource",
        }

    return None


def validate_collection_results(
    plans: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> dict[str, Any]:

    enriched_results = []

    reconciliation_findings = []

    used_indexes: set[int] = set()

    for plan in plans or []:

        matched_index = None

        for index, result in enumerate(
            results or []
        ):

            if index in used_indexes:
                continue

            if (
                plan.get("collector")
                == result.get("collector")
                and
                plan.get("region")
                == result.get("region")
            ):
                matched_index = index
                break

        if matched_index is None:

            result = {
                "collector":
                    plan.get("collector"),

                "region":
                    plan.get("region"),

                "resource_type":
                    plan.get("resource_type"),

                "status":
                    "failed",

                "resource_data":
                    [],

                "resources":
                    0,

                "metrics":
                    0,

                "topology_resources":
                    0,

                "error":
                    "No collector result was returned.",
            }

        else:

            used_indexes.add(
                matched_index
            )

            result = results[
                matched_index
            ]

        enriched = enrich_collection_result(
            plan,
            result,
        )

        enriched_results.append(
            enriched
        )

        finding = _build_reconciliation_finding(
            plan,
            enriched,
        )

        if finding:
            reconciliation_findings.append(
                finding
            )

    return {
        "results":
            enriched_results,

        "reconciliation_findings":
            reconciliation_findings,

        "not_found_findings":
            reconciliation_findings,

        "not_found_count":
            sum(
                1
                for finding
                in reconciliation_findings
                if finding.get(
                    "finding_type"
                ) == "historical_unmatched"
            ),
    }


def resources_for_analysis(
    enriched_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    resources = []

    for result in enriched_results:

        if result.get(
            "status"
        ) != "completed":
            continue

        if (
            result.get(
                "reconciliation_status"
            )
            == HISTORICAL_ONLY
        ):
            continue

        resources.extend(
            result.get(
                "resources_for_analysis",
                [],
            )
            or []
        )

    return resources


def build_historical_unmatched_finding(
    plan: dict[str, Any],
    reconciliation: dict[str, Any],
) -> dict[str, Any] | None:

    return None


build_not_found_finding = (
    build_historical_unmatched_finding
)