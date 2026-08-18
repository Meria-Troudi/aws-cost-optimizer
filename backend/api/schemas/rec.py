"""
Recommendation API schemas.

"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RecommendationAction(BaseModel):


    action: str

    target: str | None = None

    resource_id: str | None = None

    parameters: dict[str, Any] = Field(
        default_factory=dict
    )


class RecommendationResponse(BaseModel):

    model_config = ConfigDict(
        from_attributes=True
    )

    id: int | None = None

    scan_id: int | None = None

    finding_id: int | None = None

    resource_id: str | None = None

    resource_type: str | None = None

    service: str | None = None

    region: str | None = None

    category: str | None = None

    code: str | None = None

    title: str

    description: str | None = None

    rationale: str | None = None

    priority: str = "medium"

    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

   

    estimated_annual_savings: float = Field(
        default=0.0,
        ge=0.0,
    )

    currency: str = "USD"

    action: dict[str, Any] | None = None

    evidence: list[dict[str, Any]] = Field(
        default_factory=list
    )

    risks: list[str] = Field(
        default_factory=list
    )

    assumptions: list[str] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    created_at: datetime | None = None


class RecommendationSummary(BaseModel):

    id: int | None = None

    scan_id: int | None = None

    finding_id: int | None = None

    resource_id: str | None = None

    service: str | None = None

    region: str | None = None

    category: str | None = None

    title: str

    priority: str = "medium"

    confidence: float | None = None


    estimated_annual_savings: float = 0.0

    currency: str = "USD"


class RecommendationListResponse(BaseModel):


    items: list[RecommendationResponse] = Field(
        default_factory=list
    )

    total: int = 0


