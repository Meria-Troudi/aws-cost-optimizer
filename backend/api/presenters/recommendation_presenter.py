"""
Present recommendations from DB to frontend.
"""

from __future__ import annotations

from typing import Any

from backend.database.models.recommendation import Recommendation
from backend.api.presenters.utils import parse_json_field


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value

    parsed = parse_json_field(
        value,
        default=[],
    )

    return parsed if isinstance(parsed, list) else []


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    parsed = parse_json_field(
        value,
        default={},
    )

    return parsed if isinstance(parsed, dict) else {}


def present_recommendation(
    rec: Recommendation,
) -> dict[str, Any]:
    affected_resources = _list(
        rec.affected_resources
    )

    limitations = _list(
        rec.limitations
    )

    evidence = _list(
        rec.evidence
    )

    financial_impact = _dict(
        rec.financial_impact
    )

    return {
        "id": rec.id,
        "scan_id": rec.scan_run_id,

        "finding_id": rec.finding_id,

        "recommendation_key": (
            rec.recommendation_key
        ),

        "recommendation_variant": (
            rec.recommendation_variant
        ),

        "recommendation_scope": (
            rec.recommendation_scope
        ),

        "resource_type": rec.resource_type,

        "scope": rec.scope,

        "service": rec.service,


        "title": rec.title,

        "reason": rec.reason,

        "action": rec.action,

        "priority": rec.priority,

        "confidence": rec.confidence,

        "affected_resources": (
            affected_resources
        ),

        "affected_resource_count": len(
            affected_resources
        ),

        "limitations": limitations,

        "evidence": evidence,

        "financial_impact": financial_impact,

        # Kept under this key too (in addition to financial_impact)
        # since ResultsPage's summary totals already read it. 0 (not
        # None) when the evidence's savings_confidence is "low" --
        # see aws_cost_optimizer/analysis/financial.py.
        "estimated_monthly_savings": (
            financial_impact.get(
                "estimated_monthly_savings"
            )
        ),

        "status": rec.status,

        "ai_explanation": parse_json_field(
            rec.ai_explanation,
            default=None,
        ),

        "ai_provider": rec.ai_provider,

        "ai_model": rec.ai_model,

        "ai_generated_at": (
            rec.ai_generated_at.isoformat()
            if rec.ai_generated_at
            else None
        ),

        "created_at": (
            rec.created_at.isoformat()
            if rec.created_at
            else None
        ),
    }


def present_recommendations(
    recommendations: list[Recommendation],
) -> list[dict[str, Any]]:
    """Present recommendation records with the same stable API contract."""
    return [present_recommendation(rec) for rec in recommendations]
