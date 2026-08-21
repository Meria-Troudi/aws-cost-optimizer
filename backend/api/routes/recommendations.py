"""
Per-recommendation API routes.

Endpoints
---------
GET  /api/recommendations/{recommendation_id}
POST /api/recommendations/{recommendation_id}/explain
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.api.presenters.recommendation_presenter import (
    present_recommendation,
)
from backend.api.routes.dependencies import get_db
from backend.api.services.recommendation_explanation_service import (
    RecommendationExplanationService,
)
from backend.database.repositories.recommendation_repository import (
    get_recommendation_by_id,
)


router = APIRouter(
    prefix="/api/recommendations",
    tags=["Recommendations"],
)


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

    return present_recommendation(
        recommendation
    )


@router.post("/{recommendation_id}/explain")
def explain_recommendation(
    recommendation_id: int,
    force: bool = False,
    db: Session = Depends(get_db),
):

    result = RecommendationExplanationService(
        db
    ).explain(
        recommendation_id,
        force=force,
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Recommendation not found.",
        )

    return result
