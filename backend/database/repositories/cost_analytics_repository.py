"""Cost analytics queries over CostRecord."""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database.models.cost_record import CostRecord
from backend.database.models.metric import Metric
from backend.database.models.resource import Resource
from backend.database.scan_recovery import month_expression
from backend.database.models.snapshot import ResourceSnapshot

def get_monthly_totals(db: Session, scan_run_id: int) -> list[dict]:
    rows = (
        db.query(
            month_expression(CostRecord.start_date).label("month"),
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .group_by("month")
        .order_by("month")
        .all()
    )
    return [{"month": row.month, "cost": float(row.cost or 0)} for row in rows]


def get_month_totals_by_month_keys(
    db: Session, scan_run_id: int, month_keys: list[str]
) -> dict[str, float]:
    rows = (
        db.query(
            month_expression(CostRecord.start_date).label("month"),
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .group_by("month")
        .all()
    )
    result: dict[str, float] = {}
    for row in rows:
        result[row.month] = float(row.cost or 0)
    return {mk: result.get(mk, 0.0) for mk in month_keys}


def get_service_costs_for_month(
    db: Session, scan_run_id: int, month_key: str, limit: int = 5
) -> list[dict]:
    rows = (
        db.query(
            CostRecord.service,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .filter(month_expression(CostRecord.start_date) == month_key)
        .group_by(CostRecord.service)
        .order_by(func.sum(CostRecord.amount).desc())
        .limit(limit)
        .all()
    )
    total = sum(float(r.cost or 0) for r in rows)
    result = []
    for rank, row in enumerate(rows, 1):
        cost = float(row.cost or 0)
        result.append({
            "service": row.service,
            "cost": round(cost, 2),
            "share_pct": round(cost / total * 100, 1) if total else 0,
            "rank": rank,
        })
    return result


def get_region_costs_for_month(
    db: Session, scan_run_id: int, month_key: str, limit: int = 5
) -> list[dict]:
    rows = (
        db.query(
            CostRecord.region,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .filter(month_expression(CostRecord.start_date) == month_key)
        .filter(CostRecord.region.isnot(None))
        .filter(CostRecord.region != "")
        .group_by(CostRecord.region)
        .order_by(func.sum(CostRecord.amount).desc())
        .limit(limit)
        .all()
    )
    total = sum(float(r.cost or 0) for r in rows)
    result = []
    for rank, row in enumerate(rows, 1):
        cost = float(row.cost or 0)
        region = row.region or "unknown"
        result.append({
            "region": region,
            "cost": round(cost, 2),
            "share_pct": round(cost / total * 100, 1) if total else 0,
            "rank": rank,
        })
    return result


def get_service_count_for_month(db: Session, scan_run_id: int, month_key: str) -> int:
    count = (
        db.query(func.count(func.distinct(CostRecord.service)))
        .filter(CostRecord.scan_run_id == scan_run_id)
        .filter(month_expression(CostRecord.start_date) == month_key)
        .filter(CostRecord.amount > 0)
        .scalar()
    )
    return count or 0


def get_region_count_for_month(db: Session, scan_run_id: int, month_key: str) -> int:
    count = (
        db.query(func.count(func.distinct(CostRecord.region)))
        .filter(CostRecord.scan_run_id == scan_run_id)
        .filter(month_expression(CostRecord.start_date) == month_key)
        .filter(CostRecord.region.isnot(None))
        .filter(CostRecord.region != "")
        .filter(CostRecord.amount > 0)
        .scalar()
    )
    return count or 0


def get_usage_type_costs_for_month(
    db: Session, scan_run_id: int, month_key: str, limit: int = 5
) -> list[dict]:
    rows = (
        db.query(
            CostRecord.usage_type,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .filter(month_expression(CostRecord.start_date) == month_key)
        .filter(CostRecord.usage_type.isnot(None))
        .filter(CostRecord.usage_type != "")
        .group_by(CostRecord.usage_type)
        .order_by(func.sum(CostRecord.amount).desc())
        .limit(limit)
        .all()
    )
    total = sum(float(r.cost or 0) for r in rows)
    result = []
    for rank, row in enumerate(rows, 1):
        cost = float(row.cost or 0)
        result.append({
            "usage_type": row.usage_type,
            "cost": round(cost, 2),
            "share_pct": round(cost / total * 100, 1) if total else 0,
            "rank": rank,
        })
    return result


def get_service_costs_by_month(db: Session, scan_run_id: int) -> list[dict]:
    rows = (
        db.query(
            month_expression(CostRecord.start_date).label("month"),
            CostRecord.service,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .group_by("month", CostRecord.service)
        .order_by("month", func.sum(CostRecord.amount).desc())
        .all()
    )
    return [
        {
            "month": row.month,
            "service": row.service,
            "cost": float(row.cost or 0),
        }
        for row in rows
    ]


def get_region_costs_by_month(db: Session, scan_run_id: int) -> list[dict]:
    rows = (
        db.query(
            month_expression(CostRecord.start_date).label("month"),
            CostRecord.region,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .group_by("month", CostRecord.region)
        .order_by("month", func.sum(CostRecord.amount).desc())
        .all()
    )
    return [
        {
            "month": row.month,
            "region": row.region or "unknown",
            "cost": float(row.cost or 0),
        }
        for row in rows
    ]


def get_service_period_totals(db: Session, scan_run_id: int) -> list[dict]:
    rows = (
        db.query(
            CostRecord.service,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .group_by(CostRecord.service)
        .order_by(func.sum(CostRecord.amount).desc())
        .all()
    )
    return [
        {"service": row.service, "cost": float(row.cost or 0)}
        for row in rows
    ]


def get_region_period_totals(db: Session, scan_run_id: int) -> list[dict]:
    rows = (
        db.query(
            CostRecord.region,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .group_by(CostRecord.region)
        .order_by(func.sum(CostRecord.amount).desc())
        .all()
    )
    return [
        {"region": row.region or "unknown", "cost": float(row.cost or 0)}
        for row in rows
    ]


def get_distinct_regions(db: Session, scan_run_id: int) -> list[str]:
    rows = (
        db.query(CostRecord.region)
        .filter(
            CostRecord.scan_run_id == scan_run_id,
            CostRecord.region.isnot(None),
            CostRecord.region != "",
        )
        .distinct()
        .order_by(CostRecord.region)
        .all()
    )
    return [row.region for row in rows if row.region]


def get_service_region_costs(db: Session, scan_run_id: int) -> list[dict]:
    rows = (
        db.query(
            CostRecord.service,
            CostRecord.region,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_run_id)
        .group_by(CostRecord.service, CostRecord.region)
        .order_by(func.sum(CostRecord.amount).desc())
        .all()
    )
    return [
        {
            "service": row.service,
            "region": row.region or "unknown",
            "cost": float(row.cost or 0),
        }
        for row in rows
    ]

def get_resource_type_counts(
    db: Session,
    scan_run_id: int | None,
) -> dict[str, int]:

    if not scan_run_id:
        return {}

    rows = (
        db.query(
            Resource.resource_type,
            func.count(func.distinct(Resource.id)),
        )
        .join(
            ResourceSnapshot,
            ResourceSnapshot.resource_id == Resource.id,
        )
        .filter(
            ResourceSnapshot.scan_run_id == scan_run_id
        )
        .group_by(Resource.resource_type)
        .all()
    )

    return {
        resource_type: count
        for resource_type, count in rows
    }

def get_collection_counts(
    db: Session,
    cost_scan_id: int,
    analysis_scan_id: int | None,
) -> dict:
    cost_records = (
        db.query(func.count(CostRecord.id))
        .filter(CostRecord.scan_run_id == cost_scan_id)
        .scalar()
        or 0
    )
    services = (
        db.query(func.count(func.distinct(CostRecord.service)))
        .filter(CostRecord.scan_run_id == cost_scan_id)
        .scalar()
        or 0
    )
    regions = (
        db.query(func.count(func.distinct(CostRecord.region)))
        .filter(
            CostRecord.scan_run_id == cost_scan_id,
            CostRecord.region.isnot(None),
            CostRecord.region != "",
        )
        .scalar()
        or 0
    )
    usage_types = (
        db.query(func.count(func.distinct(CostRecord.usage_type)))
        .filter(
            CostRecord.scan_run_id == cost_scan_id,
            CostRecord.usage_type.isnot(None),
            CostRecord.usage_type != "",
        )
        .scalar()
        or 0
    )

    resources = 0
    metrics = 0
    if analysis_scan_id:
        resources = (
            db.query(func.count(func.distinct(Resource.id)))
            .join(
                ResourceSnapshot,
                ResourceSnapshot.resource_id == Resource.id,
            )
            .filter(
                ResourceSnapshot.scan_run_id == analysis_scan_id
            )
            .scalar()
            or 0
        )
        metrics = (
            db.query(func.count(Metric.id))
            .filter(Metric.scan_run_id == analysis_scan_id)
            .scalar()
            or 0
        )

    return {
        "cost_records": cost_records,
        "services": services,
        "regions": regions,
        "usage_types": usage_types,
        "resources": resources,
        "metrics": metrics,
    }
