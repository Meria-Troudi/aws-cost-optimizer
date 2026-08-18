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


def _extract_number(
    data: dict[str, Any],
    *keys: str,
) -> float | None:
    for key in keys:
        value = data.get(key)

        if value is None:
            continue

        try:
            return float(value)
        except (TypeError, ValueError):
            continue

    return None


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

        "category": rec.category,

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

        "estimated_monthly_savings": (
            _extract_number(
                financial_impact,
                "monthly_savings",
                "estimated_monthly_savings",
                "estimatedMonthlySavings",
            )
        ),

        "estimated_annual_savings": (
            _extract_number(
                financial_impact,
                "annual_savings",
                "estimated_annual_savings",
                "estimatedAnnualSavings",
            )
        ),

        "status": rec.status,

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
