"""
Recommendation persistence.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.database.utils import json_dumps
from ..models.recommendation import Recommendation


def save_recommendations(
    db: Session,
    scan_run_id: int,
    recommendations: list[dict],
) -> list[Recommendation]:

    saved = []

    for data in recommendations:

        if not isinstance(data, dict):
            continue

        explanation_payload = {
            "reason": data.get("reason") or "",
            "generation": data.get("generation", "deterministic"),
            "affected_resources": data.get("affected_resources") or [],
        }

        rec = Recommendation(
            scan_run_id=scan_run_id,
            finding_id=data.get("finding_id"),
            resource_type=data.get("resource_type"),
            title=data.get("title"),
            action=data.get("action"),
            explanation=json_dumps(explanation_payload),
            priority=data.get("priority", "low"),
            confidence=data.get("confidence", "low"),
            status="requires_validation",
        )

        db.add(rec)
        saved.append(rec)

    db.flush()

    return saved


def get_recommendations_by_scan(
    db: Session,
    scan_run_id: int,
):
    return (
        db.query(Recommendation)
        .filter(Recommendation.scan_run_id == scan_run_id)
        .order_by(Recommendation.priority.desc())
        .all()
    )
