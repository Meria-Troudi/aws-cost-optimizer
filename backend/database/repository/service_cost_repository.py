"""
Service cost repository
"""
from sqlalchemy.orm import Session

from backend.api.services.cost_analytics import build_service_costs_with_changes
from backend.database.repository.cost_analytics_repository import get_service_costs_by_month


def get_service_costs_with_rank(db: Session, scan_run_id: int):
    service_by_month = get_service_costs_by_month(db, scan_run_id)
    period_totals = {}
    for row in service_by_month:
        period_totals[row["service"]] = period_totals.get(row["service"], 0) + row["cost"]
    total = sum(period_totals.values()) or 1

    enriched = build_service_costs_with_changes(service_by_month, total)
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
