"""
Build the compact evidence payload sent to the LLM explanation layer.

Deliberately excludes topology, raw CloudWatch datapoints, and the
full Evidence object -- only what's needed to explain an already-
decided recommendation, keeping the payload small and the model's
task constrained to explanation, not discovery.

No DB access here: this stays a pure function so `aws_cost_optimizer/`
remains decoupled from `backend/database`, matching the existing
architecture split.
"""

from __future__ import annotations

from typing import Any

from .catalog import get_definition

_SAFE_BILLING_KEYS = {
    "attribution_scope",
    "resource_cost_attributed",
    "claimable_resource_cost",
    "amount",
    "currency",
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _compact_evidence(evidence: Any) -> dict[str, Any]:

    if isinstance(evidence, list):

        records = [item for item in evidence if isinstance(item, dict)]

        if not records:
            return {}

        merged: dict[str, Any] = {}

        for record in records:
            record_compact = _compact_evidence(record)

            for key, value in record_compact.items():
                if isinstance(value, dict):
                    merged.setdefault(key, {}).update(value)
                else:
                    merged[key] = value

        return merged

    evidence = _dict(evidence)

    compact: dict[str, Any] = {}

    derived = evidence.get("derived")

    if isinstance(derived, dict):
        compact["derived"] = derived

    billing = _dict(evidence.get("billing"))

    if billing:
        compact["billing"] = {
            key: value for key, value in billing.items() if key in _SAFE_BILLING_KEYS
        }

    for key in ("evidence_summary", "conditions", "reason"):
        if key in evidence:
            compact[key] = evidence[key]

    return compact


def build_explanation_payload(
    recommendation: dict[str, Any],
    finding: dict[str, Any] | None,
) -> dict[str, Any]:

    recommendation = _dict(recommendation)
    finding = _dict(finding)

    recommendation_key = str(recommendation.get("recommendation_key") or "").strip()

    definition = get_definition(recommendation_key)

    catalog_constraints: dict[str, Any] = {}

    if definition is not None:

        procedure = {
            key: value
            for key, value in dict(definition.procedure).items()
            if key != "aws_operations"
        }
        catalog_constraints = {
            "required_evidence": list(definition.required_evidence),
            "never_invent": list(definition.never_invent),
            "procedure": procedure,
        }

    evidence = finding.get("evidence")

    if not evidence:
        evidence = recommendation.get("evidence")

    financial_impact = dict(
        recommendation.get("financial_impact") or finding.get("impact") or {}
    )

    billing = _dict(evidence).get("billing") if isinstance(evidence, dict) else None
    if not billing and isinstance(evidence, list):
        for record in evidence:
            billing = _dict(record).get("billing")
            if billing:
                break

    financial_impact["cost_scope"] = (
        _dict(billing).get("attribution_scope")
        or financial_impact.get("savings_basis")
        or "unknown"
    )

    return {
        "recommendation": {
            "key": recommendation_key,
            "title": recommendation.get("title"),
            "action": recommendation.get("action"),
            "category": recommendation.get("category"),
            "priority": recommendation.get("priority"),
            "service": recommendation.get("service"),
            "resource_type": recommendation.get("resource_type"),
            "scope": recommendation.get("scope"),
        },
        # Resource identity, so the explanation stays anchored to the
        # specific affected resource instead of generalizing to "the
        # AWS account". Without this the model has nothing concrete
        # to name and drifts to account-level language.
        "resource": {
            "id": finding.get("resource_id"),
            "type": finding.get("resource_type") or recommendation.get("resource_type"),
            "region": finding.get("region") or recommendation.get("region"),
            "state": finding.get("status"),
        },
        "finding": {
            "type": finding.get("finding_type"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "reason": finding.get("reason"),
        },
        "catalog_constraints": catalog_constraints,
        "evidence": _compact_evidence(evidence),
        "financial_impact": financial_impact,
    }
