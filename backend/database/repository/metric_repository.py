"""
Metric persistence with deterministic upsert.

Metric identity: resource_id + scan_run_id + namespace + metric_name + statistic
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from sqlalchemy.orm import Session

from ..models.metric import Metric
from ..utils import json_dumps


def _parse_datetime(value: Any) -> datetime | None:
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
    metric: Dict[str, Any],
) -> Metric | None:
    """Save a single metric using deterministic upsert."""
    metric_name = metric.get("metric_name")
    if not metric_name:
        return None

    namespace = metric.get("namespace", "")
    statistic = metric.get("statistic", "")

    record = _find_existing(
        db,
        resource_id=resource_id,
        scan_run_id=scan_run_id,
        namespace=namespace,
        metric_name=metric_name,
        statistic=statistic,
    )

    if record is None:
        record = Metric(
            resource_id=resource_id,
            scan_run_id=scan_run_id,
            namespace=namespace,
            metric_name=metric_name,
            statistic=statistic,
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
    else:
        record.period = metric.get("period", record.period)
        record.value = metric.get("value", record.value)
        record.unit = metric.get("unit", record.unit)
        record.metric_start = _parse_datetime(
            metric.get("metric_start")
        ) or record.metric_start
        record.metric_end = _parse_datetime(
            metric.get("metric_end")
        ) or record.metric_end
        record.dimensions = json_dumps(
            metric.get("dimensions", None)
        ) or record.dimensions

    db.flush()
    return record