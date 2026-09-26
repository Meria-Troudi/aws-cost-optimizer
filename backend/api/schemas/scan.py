"""
Schemas for scan API requests and responses.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, Field

from aws_cost_optimizer.config.settings import (
    DEFAULT_COST_THRESHOLD,
)


class ScanRequest(BaseModel):

    region: str | None = None

    # No default: the window must always be the caller's actual selection, so an
    # omitted range never silently scans a period the user didn't choose.
    start_date: date

    end_date: date

    cost_threshold: float = Field(
        default=DEFAULT_COST_THRESHOLD,
        ge=0,
    )


class ScanResponse(BaseModel):

    scan_id: int
    status: str
    result: dict[str, Any]
