"""
Metric persistence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from sqlalchemy.orm import Session

from ..models.metric import Metric
from ..utils import json_dumps


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a datetime from various formats."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def save_metric(
    db: Session,
    *,
    resource_id: int,
    scan_run_id: int,
    metric: Dict[str, Any],
) -> Metric | None:
    """Save a single metric."""
    metric_name = metric.get("metric_name")
    if not metric_name:
        return None

    record = Metric(
        resource_id=resource_id,
        scan_run_id=scan_run_id,
        namespace=metric.get("namespace", ""),
        metric_name=metric_name,
        statistic=metric.get("statistic", ""),
        period=metric.get("period", 0),
        value=metric.get("value"),
        unit=metric.get("unit"),
        metric_start=_parse_datetime(
            metric.get("metric_start")
        ),
        metric_end=_parse_datetime(
            metric.get("metric_end")
        ),
        dimensions=json_dumps(
            metric.get("dimensions", None)
        ),
    )

    db.add(record)
    db.flush()
    return record
