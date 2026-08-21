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

# Billing evidence keys that are safe to hand to the LLM as context --
# everything else on the billing dict (raw usage-type strings, plan
# identifiers, etc.) stays server-side.
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
    """
    Allowlist-based extraction: only `derived` (already-summarized
    metrics) and a handful of billing fields ever leave the server.
    Raw CloudWatch datapoints, topology, and configuration are never
    included, even if present on the source evidence.
    """

    evidence = _dict(evidence)

    compact: dict[str, Any] = {}

    derived = evidence.get("derived")

    if isinstance(derived, dict):
        compact["derived"] = derived

    billing = _dict(evidence.get("billing"))

    if billing:
        compact["billing"] = {
            key: value
            for key, value in billing.items()
            if key in _SAFE_BILLING_KEYS
        }

    return compact


def build_explanation_payload(
    recommendation: dict[str, Any],
    finding: dict[str, Any] | None,
) -> dict[str, Any]:

    recommendation = _dict(recommendation)
    finding = _dict(finding)

    return {
        "recommendation": {
            "key": recommendation.get("recommendation_key"),
            "title": recommendation.get("title"),
            "action": recommendation.get("action"),
            "category": recommendation.get("category"),
            "priority": recommendation.get("priority"),
            "service": recommendation.get("service"),
            "resource_type": recommendation.get("resource_type"),
            "scope": recommendation.get("scope"),
        },
        "finding": {
            "type": finding.get("finding_type"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "reason": finding.get("reason"),
        },
        "evidence": _compact_evidence(
            finding.get("evidence")
        ),
        "limitations": (
            finding.get("limitations")
            or recommendation.get("limitations")
            or []
        ),
        "financial_impact": (
            recommendation.get("financial_impact")
            or finding.get("impact")
            or {}
        ),
    }
