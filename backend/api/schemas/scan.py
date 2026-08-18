"""
Schemas for scan API requests and responses.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from aws_cost_optimizer.config.settings import (
    DEFAULT_COST_THRESHOLD,
    DEFAULT_END_DATE,
    DEFAULT_START_DATE,
)


class ScanRequest(BaseModel):
    """
    Request used to start an optimization scan.
    """

    region: str | None = None

    start_date: date = Field(
        default_factory=lambda: date.fromisoformat(
            DEFAULT_START_DATE
        )
    )

    end_date: date = Field(
        default_factory=lambda: date.fromisoformat(
            DEFAULT_END_DATE
        )
    )

    cost_threshold: float = Field(
        default=DEFAULT_COST_THRESHOLD,
        ge=0,
    )


class ScanResponse(BaseModel):
    """
    Response returned after starting a scan.
    """

    scan_id: int
    status: str
    result: dict[str, Any]


class ScanSummary(BaseModel):
    """
    Lightweight representation of a stored scan.
    """

    id: int
    account_id: str | None = None
    region: str | None = None
    status: str

    start_date: date | None = None
    end_date: date | None = None

    cost_threshold: float = 0.0

    created_at: datetime | None = None
    finished_at: datetime | None = None

    class Config:
        from_attributes = True