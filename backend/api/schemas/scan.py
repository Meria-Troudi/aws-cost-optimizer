from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):

    start_date: date

    end_date: date

    region: str | None = None

    cost_threshold: float = Field(
        default=0.0,
        ge=0,
    )


class ScanStartResponse(BaseModel):

    scan_id: int

    status: str

    message: str


class ScanStatusResponse(BaseModel):

    scan_id: int

    status: str

    account_id: str | None = None

    start_date: date | None = None

    end_date: date | None = None

    region: str | None = None

    cost_threshold: float | None = None

    metrics: dict[str, Any] | None = None

    total_spend: float | None = None

    service_costs: list[dict[str, Any]] | None = None

    findings_count: int = 0

    recommendations_count: int = 0

    collection_plans: list[dict[str, Any]] | None = None

    monthly_costs: list[dict[str, Any]] | None = None


class FindingResponse(BaseModel):

    id: int

    resource_type: str

    resource_id: str

    finding_type: str

    analyzer: str

    severity: str

    confidence: str

    reason: str

    recommendation_eligible: bool = False

    conditions: list[Any] | None = None

    evidence: dict[str, Any] | None = None

    limitations: list[Any] | None = None

    # Presentation-ready fields for the UI
    title: str | None = None

    summary: str | None = None

    service: str | None = None

    resource_count: int = 1

    resource_ids: list[str] | None = None

    region: str | None = None

    evidence_items: list[dict[str, Any]] | None = None

    metrics: list[dict[str, Any]] | None = None

    cost_label: str = "Not estimated"

    condition_groups: list[dict[str, Any]] | None = None

    billing_details: dict[str, Any] | None = None

    metadata: dict[str, Any] | None = None

    observation_period: dict[str, Any] | None = None

    category: str | None = None

    blocks_optimization: bool = False


class RecommendationResponse(BaseModel):

    id: int

    finding_id: int | None = None

    resource_type: str

    title: str

    action: str

    explanation: str | None = None

    reason: str | None = None

    priority: str

    confidence: str

    status: str

    meta: str | None = None

 
    affected_resources: list[str] | None = None

    affected_resource_count: int = 0