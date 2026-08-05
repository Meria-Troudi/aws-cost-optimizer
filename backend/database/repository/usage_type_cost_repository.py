"""
Usage type cost repository - queries CostRecord directly for usage type aggregations.
"""

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database.models.cost_record import CostRecord


def get_usage_types_by_service(db: Session, scan_run_id: int, service: str, limit: int = 3):
    """Return a service's usage types aggregated across all regions."""
    rows = (
        db.query(
            CostRecord.usage_type,
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(
            CostRecord.scan_run_id == scan_run_id,
            CostRecord.service == service,
        )
        .group_by(CostRecord.usage_type)
        .order_by(func.sum(CostRecord.amount).desc())
        .limit(limit)
        .all()
    )
    service_total = (
        db.query(func.sum(CostRecord.amount))
        .filter(
            CostRecord.scan_run_id == scan_run_id,
            CostRecord.service == service,
        )
        .scalar()
        or 0
    )
    service_total = float(service_total)
    return [
        {
            "usage_type": row.usage_type,
            "cost": float(row.cost or 0),
            "percentage": round(float(row.cost or 0) / service_total * 100, 2) if service_total else 0.0,
        }
        for row in rows
    ]
