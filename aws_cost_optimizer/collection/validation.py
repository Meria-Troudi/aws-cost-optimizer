#/aws_cost_optimizer/collection/validation.py
from __future__ import annotations
import uuid
from typing import Any
FINDING_TYPE = "collection_no_matching_resources"
def _resource_ids(resources: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for resource in resources:
        resource_id = resource.get("resource_id")
        if resource_id and str(resource_id) not in ids:
            ids.append(str(resource_id))
    return ids
def _plan_cost(plan: dict[str, Any]) -> float:
    try:
        return float(plan.get("cost_context") or 0)
    except (TypeError, ValueError):
        return 0.0
def _match_plan(
    plan: dict[str, Any],
    result: dict[str, Any],
) -> bool:
    return (
        plan.get("collector") == result.get("collector")
        and plan.get("region") == result.get("region")
        and plan.get("resource_type") == result.get("resource_type")
    )


def enrich_collection_result(
    plan: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    resource_data = result.get("resource_data") or []
    resource_ids = _resource_ids(resource_data)
    resource_count = len(resource_data)
    cost = _plan_cost(plan)
    completed = result.get("status") == "completed"
    not_found = completed and cost > 0 and resource_count == 0

    return {
        **result,
        "service": plan.get("service"),
        "usage_type": plan.get("usage_type"),
        "resource_type": plan.get("resource_type"),
        "cost": cost,
        "resource_count": resource_count,
        "resource_ids": resource_ids,
        "not_found": not_found,
        "recommendation_allowed": completed and not not_found,
    }


def build_not_found_finding(
    enriched: dict[str, Any],
) -> dict[str, Any]:
    resource_type = enriched.get("resource_type") or "unknown"
    region = enriched.get("region") or "unknown"
    service = enriched.get("service") or resource_type
    usage_type = enriched.get("usage_type")
    cost = float(enriched.get("cost") or 0)

    usage_suffix = f" ({usage_type})" if usage_type else ""
    reason = (
        f"${cost:,.2f} of {service} cost was detected for "
        f"{resource_type}{usage_suffix} in {region}, but no matching "
        "resources were found during collection. Recommendation "
        "analysis skipped."
    )

    synthetic_id = (
        f"not-found:{region}:{resource_type}"
    )

    return {
        "finding_id": str(uuid.uuid4()),
        "finding_type": FINDING_TYPE,
        "resource_type": resource_type,
        "resource_id": synthetic_id,
        "analyzer": "collection_validation",
        "analyzer_version": "1.0",
        "severity": "low",
        "confidence": "high",
        "reason": reason,
        "resource_count": 0,
        "resource_ids": [],
        "conditions": [
            {
                "resource_id": None,
                "evidence": [
                    {
                        "name": "resource_discovery",
                        "value": {
                            "expected": "> 0 resources",
                            "actual": 0,
                            "status": "not_found",
                        },
                        "description": (
                            "No matching resources were found during "
                            "the collection scan."
                        ),
                        "source": [
                            "collection_plan.cost_context",
                            "collector.discover",
                        ],
                    }
                ],
            }
        ],
        "evidence": [
            {
                "resource_id": None,
                "evidence": {
                    "billing": {
                        "service": service,
                        "usage_type": usage_type,
                        "region": region,
                        "cost": cost,
                    },
                    "collection": {
                        "resource_count": 0,
                        "resource_ids": [],
                        "not_found": True,
                        "recommendation_allowed": False,
                    },
                },
            }
        ],
        "observation_periods": [],
        "limitations": [
            "This result compares historical billing with the current "
            "AWS inventory at collection time. It does not determine "
            "whether resources existed previously."
        ],
        "metadata": [
            {
                "category": "COLLECTION_VALIDATION",
                "service": service,
                "usage_type": usage_type,
                "region": region,
                "cost": cost,
                "resource_type": resource_type,
                "not_found": True,
                "recommendation_allowed": False,
            }
        ],
        "affected_resources": [],
        "aggregate_evidence": {
            "affected_resource_count": 0,
            "cost": cost,
            "resource_count": 0,
        },
        "scope": region,
        "recommendation_eligible": False,
    }


def validate_collection_results(
    plans: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    enriched_results: list[dict[str, Any]] = []
    not_found_findings: list[dict[str, Any]] = []

    if len(plans) == len(results):
        pairs = zip(plans, results)
    else:
        pairs = []
        used_indexes: set[int] = set()
        for plan in plans:
            match_index = None
            for index, result in enumerate(results):
                if index in used_indexes:
                    continue
                if (
                    plan.get("collector") == result.get("collector")
                    and plan.get("region") == result.get("region")
                ):
                    match_index = index
                    break
            if match_index is None:
                continue
            used_indexes.add(match_index)
            pairs.append((plan, results[match_index]))

    for plan, result in pairs:
        enriched = enrich_collection_result(plan, result)
        enriched_results.append(enriched)
        if enriched.get("not_found"):
            not_found_findings.append(
                build_not_found_finding(enriched)
            )

    return {
        "results": enriched_results,
        "not_found_findings": not_found_findings,
        "not_found_count": len(not_found_findings),
    }


def resources_for_analysis(
    enriched_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []

    for result in enriched_results:
        if result.get("status") != "completed":
            continue
        if result.get("not_found"):
            continue
        resources.extend(result.get("resource_data") or [])

    return resources
