"""
Metric persistence with deterministic upsert.

Identity:
resource_id + scan_run_id + namespace + metric_name + statistic
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from ..models.metric import Metric
from ..utils import json_dumps


def _parse_datetime(
    value: Any,
) -> datetime | None:

    if value is None:
        return None

    if isinstance(value, datetime):
        return value

    if isinstance(value, str):

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError:
            return None

    return None


def _find_existing(
    db: Session,
    *,
    resource_id: int,
    scan_run_id: int,
    namespace: str,
    metric_name: str,
    statistic: str,
) -> Metric | None:

    return (
        db.query(Metric)
        .filter(
            Metric.resource_id == resource_id,
            Metric.scan_run_id == scan_run_id,
            Metric.namespace == namespace,
            Metric.metric_name == metric_name,
            Metric.statistic == statistic,
        )
        .one_or_none()
    )


def save_metric(
    db: Session,
    *,
    resource_id: int,
    scan_run_id: int,
    metric: dict[str, Any],
) -> Metric | None:

    metric_name = str(
        metric.get("metric_name") or ""
    ).strip()

    if not metric_name:
        return None

    namespace = str(
        metric.get("namespace") or ""
    ).strip()

    statistic = str(
        metric.get("statistic") or ""
    ).strip()

    record = _find_existing(
        db,
        resource_id=resource_id,
        scan_run_id=scan_run_id,
        namespace=namespace,
        metric_name=metric_name,
        statistic=statistic,
    )

    metric_start = _parse_datetime(
        metric.get("metric_start")
    )

    metric_end = _parse_datetime(
        metric.get("metric_end")
    )

    dimensions = metric.get("dimensions")

    if record is None:

        record = Metric(
            resource_id=resource_id,
            scan_run_id=scan_run_id,
            namespace=namespace,
            metric_name=metric_name,
            statistic=statistic,
            period=int(
                metric.get("period") or 0
            ),
            value=metric.get("value"),
            unit=metric.get("unit"),
            metric_start=metric_start,
            metric_end=metric_end,
            dimensions=(
                json_dumps(dimensions)
                if dimensions is not None
                else None
            ),
        )

        db.add(record)

    else:

        if "period" in metric:
            record.period = int(
                metric.get("period") or 0
            )

        if "value" in metric:
            record.value = metric.get("value")

        if "unit" in metric:
            record.unit = metric.get("unit")

        if metric_start is not None:
            record.metric_start = metric_start

        if metric_end is not None:
            record.metric_end = metric_end

        if dimensions is not None:
            record.dimensions = json_dumps(
                dimensions
            )

    db.flush()

    return record