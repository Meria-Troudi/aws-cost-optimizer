"""
Finding API schemas.

"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingEvidence(BaseModel):


    type: str | None = None

    message: str | None = None

    value: Any | None = None

    unit: str | None = None

    source: str | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )
"""
Frontend-facing Finding API schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FindingResponse(BaseModel):
    id: int | None = None

    scan_id: int | None = None

    finding_type: str | None = None

    finding_key: str | None = None

    resource_type: str | None = None

    resource_id: str | None = None

    analyzer: str | None = None

    severity: str = "info"

    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

    category: str | None = None

    title: str

    reason: str | None = None

    cost: float | None = None

    billing_details: dict[str, Any] | None = None

    impact: dict[str, Any] | None = None

    recommendation_eligible: bool = False

    conditions: list[Any] = Field(
        default_factory=list
    )

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )

    evidence_summary: list[str] = Field(
        default_factory=list
    )

    limitations: list[Any] = Field(
        default_factory=list
    )

    region: str | None = None

    account_id: str | None = None

    status: str = "open"

    observation_period: dict[str, Any] | None = None

    created_at: datetime | None = None


class FindingListResponse(BaseModel):
    items: list[FindingResponse] = Field(
        default_factory=list
    )

    total: int = 0

class FindingSummary(BaseModel):


    id: int | None = None

    scan_id: int | None = None

    resource_id: str | None = None

    service: str | None = None

    region: str | None = None

    analyzer: str | None = None

    title: str

    severity: str = "info"

    category: str | None = None

    confidence: float | None = None


class FindingListResponse(BaseModel):


    items: list[FindingResponse] = Field(
        default_factory=list
    )

    total: int = 0