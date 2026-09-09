"""
Per-recommendation API routes.

Endpoints
---------
GET  /api/recommendations/{recommendation_id}
POST /api/recommendations/{recommendation_id}/explain
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.api.presenters.recommendation_presenter import (
    present_recommendation,
)
from backend.api.routes.dependencies import get_db
from backend.api.services.recommendation_explanation_service import (
    RecommendationExplanationService,
)
from backend.database.connection import SessionLocal
from backend.database.repositories.recommendation_repository import (
    get_recommendation_by_id,
    get_recommendations_by_scan,
)

router = APIRouter(
    prefix="/api/recommendations",
    tags=["Recommendations"],
)


@router.post("/scan/{scan_id}/explain-pending")
def explain_pending_for_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Queue background generation of explanations for every
    recommendation of a scan that does not have one yet.

    The LLM call takes tens of seconds per recommendation, so this
    endpoint returns immediately and generates sequentially in a
    background task -- by the time a user opens a recommendation, the
    explanation is usually already persisted and served from cache.
    """

    recommendations = get_recommendations_by_scan(
        db,
        scan_id,
    )

    if not recommendations:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found or has no recommendations.",
        )

    pending_ids = [
        recommendation.id
        for recommendation in recommendations
        if not (
            getattr(recommendation, "ai_explanation", None)
            or ""
        ).strip()
    ]

    if not pending_ids:
        return {
            "scan_id": scan_id,
            "queued": 0,
            "status": "all_explanations_cached",
        }

    background_tasks.add_task(
        _explain_many,
        list(pending_ids),
    )

    return {
        "scan_id": scan_id,
        "queued": len(pending_ids),
        "status": "queued",
    }


def _explain_many(
    recommendation_ids: list[int],
) -> None:
    """
    Background worker: explain each recommendation with its own DB
    session (the request-scoped session must not be reused outside
    the request lifecycle). Failures for one recommendation must not
    stop the rest.
    """

    for recommendation_id in recommendation_ids:

        db = SessionLocal()

        try:
            RecommendationExplanationService(db).explain(
                recommendation_id,
            )
        except Exception as exc:  # noqa: BLE001 - background safety
            print(
                "[explain-pending] recommendation "
                f"{recommendation_id} failed: "
                f"{type(exc).__name__}: {exc}"
            )
        finally:
            db.close()


@router.get("/{recommendation_id}")
def get_recommendation(
    recommendation_id: int,
    db: Session = Depends(get_db),
):

    recommendation = get_recommendation_by_id(
        db,
        recommendation_id,
    )

    if recommendation is None:
        raise HTTPException(
            status_code=404,
            detail="Recommendation not found.",
        )

    return present_recommendation(recommendation)


@router.post("/{recommendation_id}/explain")
def explain_recommendation(
    recommendation_id: int,
    force: bool = False,
    db: Session = Depends(get_db),
):

    result = RecommendationExplanationService(db).explain(
        recommendation_id,
        force=force,
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Recommendation not found.",
        )

    return result
