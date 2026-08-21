"""
Recommendation persistence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import case
from sqlalchemy.orm import Session, selectinload

from aws_cost_optimizer.analysis.ranking import (
    SEVERITY_RANK as PRIORITY_RANK,
)
from backend.database.models.finding import Finding
from backend.database.models.recommendation import Recommendation
from backend.database.utils import json_dumps


def _int_list(values: Any) -> list[int]:

    if not isinstance(values, list):
        return []

    result: list[int] = []
    seen: set[int] = set()

    for value in values:

        try:
            number = int(value)
        except (
            TypeError,
            ValueError,
        ):
            continue

        if number in seen:
            continue

        seen.add(number)
        result.append(number)

    return result


def _string_list(values: Any) -> list[str]:

    if not isinstance(values, list):
        return []

    result: list[str] = []
    seen: set[str] = set()

    for value in values:

        if value is None:
            continue

        text = str(value).strip()

        if not text or text in seen:
            continue

        seen.add(text)
        result.append(text)

    return result


def _json_value(
    value: Any,
) -> str | None:

    if value is None:
        return None

    return json_dumps(value)


def save_recommendations(
    db: Session,
    scan_run_id: int,
    recommendations: list[dict[str, Any]],
) -> list[Recommendation]:

    saved: list[Recommendation] = []

    for data in recommendations:

        if not isinstance(data, dict):
            continue

        recommendation_key = str(
            data.get("recommendation_key")
            or ""
        ).strip()

        if not recommendation_key:
            continue

        recommendation_variant = str(
            data.get("recommendation_variant")
            or ""
        ).strip()

        recommendation_scope = str(
            data.get("recommendation_scope")
            or "region"
        ).strip().lower()

        resource_type = str(
            data.get("resource_type")
            or "unknown"
        ).strip()

        scope = str(
            data.get("scope")
            or ""
        ).strip()

        if not scope:
            raise ValueError(
                "Recommendation scope identity is required."
            )

        category = str(
            data.get("category")
            or "cost_optimization"
        ).strip()

        service = str(
            data.get("service")
            or "Unknown service"
        ).strip()

        priority = str(
            data.get("priority")
            or "low"
        ).strip().lower()

        confidence = str(
            data.get("confidence")
            or "low"
        ).strip().lower()

        status = str(
            data.get("status")
            or "requires_validation"
        ).strip().lower()

        finding_ids = _int_list(
            data.get("source_finding_ids")
        )

        if not finding_ids:

            legacy_id = data.get(
                "finding_id"
            )

            if legacy_id is not None:
                finding_ids = _int_list(
                    [legacy_id]
                )

        source_findings: list[Finding] = []

        if finding_ids:

            source_findings = (
                db.query(Finding)
                .filter(
                    Finding.scan_run_id
                    == scan_run_id
                )
                .filter(
                    Finding.id.in_(finding_ids)
                )
                .all()
            )

        finding_by_id = {
            finding.id: finding
            for finding in source_findings
        }

        ordered_findings = [
            finding_by_id[finding_id]
            for finding_id in finding_ids
            if finding_id in finding_by_id
        ]

        if not ordered_findings:
            raise ValueError(
                "Recommendation must reference at least "
                "one persisted finding."
            )

        affected_resources = _string_list(
            data.get("affected_resources")
        )

        source_finding_types = _string_list(
            data.get("source_finding_types")
        )

        primary_finding_id = (
            ordered_findings[0].id
            if ordered_findings
            else None
        )

        recommendation = (
            db.query(Recommendation)
            .filter(
                Recommendation.scan_run_id
                == scan_run_id
            )
            .filter(
                Recommendation.recommendation_key
                == recommendation_key
            )
            .filter(
                Recommendation.recommendation_variant
                == recommendation_variant
            )
            .filter(
                Recommendation.resource_type
                == resource_type
            )
            .filter(
                Recommendation.scope
                == scope
            )
            .one_or_none()
        )

        if recommendation is None:

            recommendation = Recommendation(
                scan_run_id=scan_run_id,

                finding_id=primary_finding_id,

                recommendation_key=(
                    recommendation_key
                ),

                recommendation_variant=(
                    recommendation_variant
                ),

                recommendation_scope=(
                    recommendation_scope
                ),

                resource_type=(
                    resource_type
                ),

                scope=scope,

                category=category,

                service=service,

                title=str(
                    data.get("title")
                    or "Review resource"
                ),

                reason=str(
                    data.get("reason")
                    or ""
                ),

                action=str(
                    data.get("action")
                    or ""
                ),

                priority=priority,

                confidence=confidence,

                affected_resources=_json_value(
                    affected_resources
                ),

                limitations=_json_value(
                    data.get("limitations")
                    or []
                ),

                evidence=_json_value(
                    data.get("evidence")
                    or []
                ),

                financial_impact=_json_value(
                    data.get("financial_impact")
                    or {}
                ),

                status=status,
            )

            db.add(recommendation)

        else:

            recommendation.finding_id = (
                primary_finding_id
            )

            recommendation.recommendation_scope = (
                recommendation_scope
            )

            recommendation.category = category
            recommendation.service = service

            recommendation.title = str(
                data.get("title")
                or recommendation.title
            )

            recommendation.reason = str(
                data.get("reason")
                or recommendation.reason
            )

            recommendation.action = str(
                data.get("action")
                or recommendation.action
            )

            recommendation.priority = priority
            recommendation.confidence = confidence

            recommendation.affected_resources = (
                _json_value(
                    affected_resources
                )
            )

            recommendation.limitations = (
                _json_value(
                    data.get("limitations")
                    or []
                )
            )

            recommendation.evidence = (
                _json_value(
                    data.get("evidence")
                    or []
                )
            )

            recommendation.financial_impact = (
                _json_value(
                    data.get("financial_impact")
                    or {}
                )
            )

            recommendation.status = status

        db.flush()

        recommendation.findings = (
            ordered_findings
        )

        saved.append(
            recommendation
        )

    db.flush()

    return saved


def get_recommendation_by_id(
    db: Session,
    recommendation_id: int,
) -> Recommendation | None:

    return (
        db.query(Recommendation)
        .options(
            selectinload(
                Recommendation.primary_finding
            ),
        )
        .filter(
            Recommendation.id
            == recommendation_id
        )
        .one_or_none()
    )


def save_recommendation_explanation(
    db: Session,
    recommendation_id: int,
    explanation: dict[str, Any],
    *,
    provider: str,
    model: str,
    prompt_version: str,
) -> Recommendation | None:

    recommendation = get_recommendation_by_id(
        db,
        recommendation_id,
    )

    if recommendation is None:
        return None

    recommendation.ai_explanation = (
        _json_value(explanation)
    )

    recommendation.ai_provider = provider
    recommendation.ai_model = model
    recommendation.ai_prompt_version = (
        prompt_version
    )

    recommendation.ai_generated_at = (
        datetime.utcnow()
    )

    db.flush()

    return recommendation


def get_recommendations_by_scan(
    db: Session,
    scan_run_id: int,
) -> list[Recommendation]:

    priority_case = case(
        PRIORITY_RANK,
        value=Recommendation.priority,
        else_=0,
    )

    return (
        db.query(Recommendation)
        .options(
            selectinload(
                Recommendation.findings
            ),
            selectinload(
                Recommendation.primary_finding
            ),
        )
        .filter(
            Recommendation.scan_run_id
            == scan_run_id
        )
        .order_by(
            priority_case.desc(),
            Recommendation.id.asc(),
        )
        .all()
    )


