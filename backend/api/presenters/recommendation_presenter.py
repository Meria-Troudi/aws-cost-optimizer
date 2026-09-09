"""
Present recommendations from DB to frontend.
"""

from __future__ import annotations

from typing import Any

from backend.database.models.recommendation import Recommendation
from backend.api.presenters.utils import parse_json_field
from aws_cost_optimizer.planner.resource_catalog import get_resource_catalog
from aws_cost_optimizer.recommendations.catalog import get_definition
from aws_cost_optimizer.recommendations.plan import build_plan


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


def _normalize_ai_explanation(
    ai_explanation: Any,
    plan: dict[str, Any],
) -> Any:
    """Fill in sections older generated explanations may be missing.

    Explanations produced by prompt versions before 4.1 did not
    include ``what_to_verify`` / ``possible_actions`` (the model simply
    never returned them), so the Recommendation rail renders those
    rows without the "What to verify" / "Possible actions" sections. We do
    NOT regenerate -- the stored text stays cached -- instead we surface
    the deterministic plan's material (the exactly thing the AI was told
    to humanize) as a stable fallback, so every explanation renders
    the same sections regardless of which prompt version produced it.
    """
    if not isinstance(ai_explanation, dict):
        return ai_explanation

    ai_explanation.setdefault("what_to_verify", [])
    ai_explanation.setdefault("possible_actions", [])

    if ai_explanation["what_to_verify"] or ai_explanation["possible_actions"]:
        return ai_explanation

    validation_steps = _list(plan.get("validation_steps"))
    possible_actions = _list(plan.get("possible_actions"))

    if validation_steps:
        ai_explanation["what_to_verify"] = list(validation_steps)

    if possible_actions:
        ai_explanation["possible_actions"] = list(possible_actions)

    if ai_explanation["what_to_verify"] or ai_explanation["possible_actions"]:
        # Tag the fallback so the UI/future code can tell a deterministic
        # fallback from an AI-authored section. We treat these as real
        # content elsewhere, so only record provenance for debugging.
        if not ai_explanation.get("_fallback_plan"):
            ai_explanation["_fallback_plan"] = True

    return ai_explanation


def present_recommendation(
    rec: Recommendation,
) -> dict[str, Any]:
    affected_resources = _list(rec.affected_resources)

    limitations = _list(rec.limitations)

    evidence = _list(rec.evidence)

    financial_impact = _dict(rec.financial_impact)

    plan = _dict(rec.plan)

    # Deterministic plan for the parse fallback: prefer the stored plan,
    # then rebuild from the catalog definition if the key still resolves (the
    # stored plan may predate the current catalog).
    plan_source = plan if plan.get("validation_steps") or plan.get("possible_actions") else {}
    if not plan_source:
        definition = get_definition(str(rec.recommendation_key or "").strip())
        if definition is not None:
            plan_source = build_plan(definition)

    ai_explanation = _normalize_ai_explanation(
        parse_json_field(
            rec.ai_explanation,
            default=None,
        ),
        plan_source or {},
    )

    # Derived purely from the already-stored resource_type against the
    # catalog's domain/subdomain/service taxonomy -- no DB column, no
    # migration, and stays in sync automatically if resource_catalog.yaml
    # changes.
    group = get_resource_catalog().group_for(rec.resource_type)

    return {
        "id": rec.id,
        "scan_id": rec.scan_run_id,
        "finding_id": rec.finding_id,
        "recommendation_key": (rec.recommendation_key),
        "recommendation_variant": (rec.recommendation_variant),
        "recommendation_scope": (rec.recommendation_scope),
        "resource_type": rec.resource_type,
        "domain": group["domain"],
        "subdomain": group["subdomain"],
        "category": rec.category,
        "scope": rec.scope,
        # rec.service is the raw billing service (e.g. "EC2 - Other")
        # -- kept as-is, the frontend's finding<->recommendation
        # matching compares it against Finding.service. resource_service
        # is the resource's actual AWS service (e.g. "Amazon EBS"),
        # used for display/titles instead.
        "service": rec.service,
        "resource_service": group["service"] or rec.service,
        "title": rec.title,
        "reason": rec.reason,
        "action": rec.action,
        # Deterministic validation/action plan -- see
        # aws_cost_optimizer/recommendations/plan.py. Never contains AWS
        # operation names or commands.
        "plan": plan,
        "priority": rec.priority,
        "confidence": rec.confidence,
        "affected_resources": (affected_resources),
        "affected_resource_count": len(affected_resources),
        "limitations": limitations,
        "evidence": evidence,
        "financial_impact": financial_impact,
        # Kept under this key too (in addition to financial_impact)
        # since ResultsPage's summary totals already read it. 0 (not
        # None) when the evidence's savings_confidence is "low" --
        # see aws_cost_optimizer/analysis/financial.py.
        "estimated_monthly_savings": (
            financial_impact.get("estimated_monthly_savings")
        ),
        "status": rec.status,
        "ai_explanation": ai_explanation,
        "ai_provider": rec.ai_provider,
        "ai_model": rec.ai_model,
        "ai_generated_at": (
            rec.ai_generated_at.isoformat() if rec.ai_generated_at else None
        ),
        "created_at": (rec.created_at.isoformat() if rec.created_at else None),
    }


def present_recommendations(
    recommendations: list[Recommendation],
) -> list[dict[str, Any]]:
    """Present recommendation records with the same stable API contract."""
    return [present_recommendation(rec) for rec in recommendations]
