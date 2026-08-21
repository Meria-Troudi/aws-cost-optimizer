"""
Service cost repository
"""
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.api.services.cost_analytics import build_service_costs_with_changes
from backend.database.models.cost_record import CostRecord
from backend.database.repositories.cost.analytics import get_service_costs_by_month


def get_period_cost_total(db: Session, scan_run_id: int) -> float:
    total = (
        db.query(func.sum(CostRecord.amount))
        .filter(CostRecord.scan_run_id == scan_run_id)
        .scalar()
    )
    return float(total or 0.0)


def get_service_count(db: Session, scan_run_id: int) -> int:
    return (
        db.query(func.count(func.distinct(CostRecord.service)))
        .filter(CostRecord.scan_run_id == scan_run_id)
        .scalar()
        or 0
    )


def get_service_costs_with_rank(
    db: Session,
    scan_run_id: int,
    *,
    limit: int = 10,
):
    service_by_month = get_service_costs_by_month(db, scan_run_id)
    period_totals = {}
    for row in service_by_month:
        period_totals[row["service"]] = period_totals.get(row["service"], 0) + row["cost"]
    total = sum(period_totals.values()) or get_period_cost_total(db, scan_run_id) or 1

    enriched = build_service_costs_with_changes(
        service_by_month,
        total,
        limit=limit,
    )
    return [
        {
            "rank": row["rank"],
            "service": row["service"],
            "cost": row["cost"],
            "share_pct": row["share_pct"],
            "trend": row["trend"],
            "change_percentage": row["change_pct"] or 0.0,
            "change_amount": row["change_amount"],
        }
        for row in enriched
    ]
