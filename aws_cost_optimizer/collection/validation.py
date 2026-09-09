"""
Common post-collection validation and billing reconciliation.
"""

from __future__ import annotations

from typing import Any

from aws_cost_optimizer.analysis.reconciliation import (
    CURRENT,
    CURRENT_MISMATCH,
    HISTORICAL,
    NO_COST,
    reconcile_collection_plan,
)

# Reconciliation statuses that permit current-resource optimization
# analysis. This is the single authoritative whitelist -- never filter
# with `!= SOME_STATUS`, because a new/renamed status would silently
# fall through to "analysis allowed".
ANALYSIS_ALLOWED_RECONCILIATION_STATUSES = {
    CURRENT,
    CURRENT_MISMATCH,
}


def _plan_cost(
    plan: dict[str, Any],
) -> float:
    cost_context = plan.get("cost_context")

    if isinstance(
        cost_context,
        dict,
    ):

        nested = cost_context.get("cost")

        if isinstance(
            nested,
            dict,
        ):

            try:
                return float(nested.get("value") or 0)
            except (TypeError, ValueError):
                return 0.0

        try:
            return float(cost_context.get("value") or 0)
        except (TypeError, ValueError):
            return 0.0

    try:
        return float(cost_context or 0)
    except (TypeError, ValueError):
        return 0.0


def enrich_collection_result(
    plan: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:

    discovered_resources = result.get("discovered_resource_data")

    # Reconciliation answers the COLLECTION question ("did AWS have
    # this resource?"), so it must run against DISCOVERY evidence --
    # not `resource_data`, which only contains resources that survived
    # persistence. A persistence failure must never look like "the
    # resource does not exist". Fall back to resource_data for older
    # collector results that never populated the discovery field.
    if not isinstance(discovered_resources, list) or not discovered_resources:
        discovered_resources = result.get("resource_data") or []

    collection_status = result.get("status")
    collection_complete = collection_status == "completed"

    analysis_allowed = collection_status in {"completed", "partial"}

    reconciliation = reconcile_collection_plan(
        plan,
        discovered_resources,
        collection_complete=collection_complete,
    )

    status = reconciliation.get("status")

    resources_for_analysis = reconciliation.get("resources_for_analysis") or []
    configuration_incomplete = any(
        isinstance(resource, dict)
        and (
            (resource.get("data_quality") or {}).get("configuration_available") is False
            or (resource.get("configuration") or {}).get("status")
            in {"error", "disabled"}
        )
        for resource in resources_for_analysis
    )

    analysis_ready = (
        analysis_allowed
        and bool(resources_for_analysis)
        and status in ANALYSIS_ALLOWED_RECONCILIATION_STATUSES
    )

    return {
        **result,
        "service": plan.get("service"),
        "usage_type": plan.get("usage_type"),
        "resource_type": plan.get("resource_type"),
        "cost": _plan_cost(plan),
        "discovered_count": len(discovered_resources),
        "resource_count": len(resources_for_analysis),
        "resource_ids": reconciliation.get("resource_ids") or [],
        "matched_resource_data": reconciliation.get("matched_resources") or [],
        "related_resource_data": reconciliation.get("related_resources") or [],
        "resources_for_analysis": resources_for_analysis,
        "discovered_resource_data": discovered_resources,
        "reconciliation_status": status,
        "reconciliation": reconciliation,
        "match_status": status,
        "match_reason": reconciliation.get("reason"),
        "expected_instance_class": (reconciliation.get("expected_identity") or {}).get(
            "instance_class"
        ),
        "matched": status == CURRENT,
        "historical_unmatched": status == HISTORICAL,
        "recommendation_allowed": analysis_ready,
        "analysis_status": ("ready" if analysis_ready else "skipped"),
        "configuration_incomplete": configuration_incomplete,
        "billing_context": {
            "service": plan.get("service"),
            "usage_type": plan.get("usage_type"),
            "region": plan.get("region"),
            "cost": _plan_cost(plan),
        },
    }


def billing_contexts_for_analysis(
    enriched_results: list[dict[str, Any]] | None,
) -> dict[tuple[str, str], dict[str, Any]]:

    contexts: dict[tuple[str, str], dict[str, Any]] = {}

    for enriched in enriched_results or []:

        if not isinstance(enriched, dict):
            continue

        reconciliation = enriched.get("reconciliation") or {}

        status = reconciliation.get("status")

        # CURRENT: billing may be resource-attributed (sole match +
        # complete collection). CURRENT_MISMATCH: cost attribution
        # stays DISABLED, but the billing evidence (usage type, amount)
        # is preserved so analyzers can reason about the mismatch.
        # HISTORICAL / NO_COST / UNKNOWN produce no entry.
        if status not in ANALYSIS_ALLOWED_RECONCILIATION_STATUSES:
            continue

        billing = reconciliation.get("billing") or {}

        claimable = reconciliation.get("claimable_resource_cost")

        attributed = reconciliation.get("resource_cost_attributed") is True

        # CURRENT attaches to identity-MATCHED resources.
        # CURRENT_MISMATCH has no matched resources by definition -- its
        # billing context belongs to the DISCOVERED current resources
        # (the ones analyzers will run against).
        if status == CURRENT:
            members = reconciliation.get("matched_resources") or []
        else:
            members = reconciliation.get("resources_for_analysis") or []

        for resource in members:

            if not isinstance(resource, dict):
                continue

            resource_id = resource.get("resource_id")
            resource_type = resource.get("resource_type")

            if not resource_id or not resource_type:
                continue

            key = (str(resource_type), str(resource_id))

            existing = contexts.get(key)

            # Never let a non-attributed entry overwrite an
            # attributed one for the same resource.
            if (
                existing is not None
                and existing.get("resource_cost_attributed") is True
                and not attributed
            ):
                continue

            contexts[key] = {
                "billing": dict(billing),
                "claimable_resource_cost": (
                    float(claimable) if claimable is not None else None
                ),
                "resource_cost_attributed": attributed,
            }

    return contexts


def _build_reconciliation_finding(
    plan: dict[str, Any],
    enriched: dict[str, Any],
) -> dict[str, Any] | None:

    status = enriched.get("reconciliation_status")
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
            "finding_type": "historical_unmatched",
            "finding_key": "historical_unmatched",
            "category": "data_quality",
            "status": "informational",
            "title": "Historical cost has no current resource",
            "resource_type": plan.get("resource_type") or "unknown",
            "resource_id": resource_id,
            "resource_ids": [],
            "analyzer": "billing_reconciliation",
            "analyzer_version": "2.0",
            # This is a data/reconciliation observation, not an
            # optimization-severity signal.
            "severity": "low",
            "confidence": "high",
            "reason": reason,
            "conditions": [
                {
                    "name": "billing_usage",
                    "value": {
                        "service": plan.get("service"),
                        "usage_type": plan.get("usage_type"),
                        "region": plan.get("region"),
                        "cost": cost,
                    },
                    "description": "Historical billing exists for the collection plan.",
                    "source": [
                        "Cost Explorer",
                        "CostRecord",
                    ],
                },
                {
                    "name": "current_resource_count",
                    "value": 0,
                    "description": "No current resource was discovered.",
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
                    "resource_id": resource_id,
                    "resource_type": plan.get("resource_type"),
                    "region": plan.get("region"),
                },
                "derived": {
                    "reconciliation_status": HISTORICAL,
                    "billing_cost": cost,
                    "billing_usage_type": plan.get("usage_type"),
                    "discovered_count": 0,
                },
                "data_quality": {
                    "current_resource_available": False,
                    "historical_billing_available": True,
                },
            },
            "observation_period": None,
            "limitations": [
                (
                    "Historical billing does not identify a "
                    "currently active resource by itself."
                ),
            ],
            "metadata": {
                "service": plan.get("service"),
                "usage_type": plan.get("usage_type"),
                "region": plan.get("region"),
                "cost": cost,
                "reconciliation_status": HISTORICAL,
            },
            "recommendation_eligible": False,
            "aggregation_scope": "region",
        }
    if status == CURRENT_MISMATCH:

        resource_ids = enriched.get("resource_ids") or []

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

        discovered_resources = enriched.get("discovered_resource_data") or []

        # Evidence must represent the MATCHED resource set, not an
        # arbitrary discovery index -- when several resources share the
        # plan, discovered[0] may not even be a matched one.
        matched_resources = enriched.get("matched_resource_data") or []

        evidence_source = (
            matched_resources[0]
            if matched_resources
            else (discovered_resources[0] if discovered_resources else {})
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

            value = configuration.get("instance_class") or configuration.get(
                "db_instance_class"
            )

            if value and value not in current_classes:
                current_classes.append(str(value))

        expected_class = expected_identity.get("instance_class")

        current_label = (
            ", ".join(current_classes)
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
                f"Historical billing usage {plan.get('usage_type')} "
                "could not be attributed to the currently discovered "
                "resource. The billing record is retained as historical "
                "evidence, so no current resource-level cost attribution "
                "or optimization finding is generated from it."
            )

        return {
            "finding_type": "billing_resource_mismatch",
            "title": "Billing resource mismatch",
            "resource_type": plan.get("resource_type") or "unknown",
            "resource_id": resource_ids[0] if resource_ids else "unknown",
            "resource_ids": resource_ids,
            "analyzer": "billing_reconciliation",
            "analyzer_version": "2.0",
            "severity": "medium",
            "confidence": "high",
            "reason": reason,
            "conditions": [
                {
                    "name": "billing_identity",
                    "value": {
                        "usage_type": plan.get("usage_type"),
                        "expected_identity": expected_identity,
                    },
                    "description": "Identity inferred from the billing usage type.",
                    "source": [
                        "Cost Explorer",
                        "billing usage type",
                    ],
                },
                {
                    "name": "current_resource",
                    "value": {
                        "resource_ids": resource_ids,
                        "current_instance_classes": current_classes,
                    },
                    "description": "Current resource inventory differs from the billing identity.",
                    "source": [
                        "resource collector",
                    ],
                },
            ],
            "evidence": {
                "metrics": {},
                "configuration": (
                    evidence_source.get(
                        "configuration",
                        {},
                    )
                    if isinstance(evidence_source, dict)
                    else {}
                ),
                "topology": (
                    evidence_source.get(
                        "topology",
                        {},
                    )
                    if isinstance(evidence_source, dict)
                    else {}
                ),
                "resource": {
                    "resource_id": resource_ids[0] if resource_ids else "unknown",
                    "resource_type": plan.get("resource_type"),
                    "region": plan.get("region"),
                },
                "derived": {
                    "reconciliation_status": CURRENT_MISMATCH,
                    "billing_cost": enriched.get(
                        "cost",
                        0,
                    ),
                    "expected_identity": expected_identity,
                    "current_instance_classes": current_classes,
                },
                "data_quality": {
                    "current_resource_available": True,
                    "billing_identity_available": bool(expected_identity),
                },
            },
            "observation_period": None,
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
                "service": plan.get("service"),
                "usage_type": plan.get("usage_type"),
                "region": plan.get("region"),
                "cost": enriched.get(
                    "cost",
                    0,
                ),
                "billing_cost": enriched.get(
                    "cost",
                    0,
                ),
                "expected_identity": expected_identity,
                "reconciliation_status": CURRENT_MISMATCH,
                "current_resource_ids": resource_ids,
                # Identity + configuration of the CURRENT discovered
                # resource that the historical billing could NOT be
                # matched to (e.g. endpoint_type/source for a VPC
                # endpoint). Used by the summary presentation to make
                # the non-attribution explicit and defensible.
                "current_resource_id": (
                    resource_ids[0]
                    if resource_ids
                    else "unknown"
                ),
                "current_configuration": (
                    evidence_source.get(
                        "configuration",
                        {},
                    )
                    if isinstance(
                        evidence_source,
                        dict,
                    )
                    and isinstance(
                        evidence_source.get("configuration"),
                        dict,
                    )
                    else {}
                ),
            },
            "recommendation_eligible": False,
            "aggregation_scope": "resource",
        }

    return None


def validate_collection_results(
    plans: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> dict[str, Any]:

    enriched_results = []

    reconciliation_findings = []

    used_indexes: set[int] = set()

    # Primary identity: the collection_plan_id. The manager tags every
    # collector result with the id of the plan it executed, so matching
    # by id is exact even when one collector serves several plans in
    # the same region. The legacy collector+region fallback (with its
    # used_indexes exclusivity) remains only for results that predate
    # plan-id tagging.
    results_by_plan_id: dict[str, int] = {
        str(result.get("collection_plan_id")): index
        for index, result in enumerate(results or [])
        if isinstance(result, dict) and result.get("collection_plan_id") is not None
    }

    for plan in plans or []:

        matched_index = None

        plan_id = plan.get("collection_plan_id", plan.get("id"))

        if plan_id is not None:
            matched_index = results_by_plan_id.get(str(plan_id))

        legacy_fallback = matched_index is None

        if legacy_fallback:

            for index, result in enumerate(results or []):

                if index in used_indexes:
                    continue

                if plan.get("collector") == result.get("collector") and plan.get(
                    "region"
                ) == result.get("region"):
                    matched_index = index
                    break

        if matched_index is None:

            result = {
                "collector": plan.get("collector"),
                "collection_plan_id": plan.get("collection_plan_id", plan.get("id")),
                "region": plan.get("region"),
                "resource_type": plan.get("resource_type"),
                "status": "failed",
                "resource_data": [],
                "discovered_resource_data": [],
                "resources": 0,
                "error": "No collector result was returned.",
            }

        else:

            result = results[matched_index]

            # Only the legacy collector+region fallback is exclusive;
            # plan-id matches are explicit one-to-one associations and
            # must not block other plans from their own results.
            if legacy_fallback:
                used_indexes.add(matched_index)

        enriched = enrich_collection_result(
            plan,
            result,
        )

        enriched_results.append(enriched)

        finding = _build_reconciliation_finding(
            plan,
            enriched,
        )

        if finding:
            reconciliation_findings.append(finding)

    return {
        "results": enriched_results,
        "reconciliation_findings": reconciliation_findings,
        # DEPRECATED alias: reconciliation findings include BOTH
        # historical_unmatched AND billing_resource_mismatch -- the
        # latter is not a "not found" condition. New code must read
        # `reconciliation_findings`. Keep only until downstream
        # consumers (scan_service / dashboards) are migrated.
        "not_found_findings": reconciliation_findings,
        "not_found_count": sum(
            1
            for finding in reconciliation_findings
            if finding.get("finding_type") == "historical_unmatched"
        ),
    }


def resources_for_analysis(
    enriched_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    resources = []

    for result in enriched_results:

        if result.get("status") not in {"completed", "partial"}:
            continue

        # Authoritative whitelist -- see
        # ANALYSIS_ALLOWED_RECONCILIATION_STATUSES.
        if (
            result.get("reconciliation_status")
            not in ANALYSIS_ALLOWED_RECONCILIATION_STATUSES
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


# Removed: build_historical_unmatched_finding() /
# build_not_found_finding() were dead stubs competing with
# _build_reconciliation_finding(), which is the single mechanism that
# builds historical and mismatch findings.
