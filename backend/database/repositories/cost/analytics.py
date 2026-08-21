"""Cost analytics queries over CostRecord."""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database.models.cost_record import CostRecord
from backend.database.utils import month_expression


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
