"""
Service cost repository - queries CostRecord directly for service aggregations.
"""

from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database.models.cost_record import CostRecord


def get_service_costs_with_rank(db: Session, scan_run_id: int):
    """Return one ranked cost row per service, aggregated across regions."""
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

    total = sum(float(row.cost or 0) for row in rows)
    result = []
    for rank, row in enumerate(rows, 1):
        cost = float(row.cost or 0)
        result.append({
            "rank": rank,
            "service": row.service,
            "cost": cost,
            "share_pct": round(cost / total * 100, 2) if total else 0.0,
            "trend": "N/A",
            "change_percentage": 0.0,
        })
    return result
