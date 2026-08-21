"""
Structured output schema for recommendation explanations.
"""

from __future__ import annotations

from pydantic import BaseModel


class RecommendationExplanation(BaseModel):

    summary: str
    why: str
    action: str
    confidence_note: str
    risk: str
