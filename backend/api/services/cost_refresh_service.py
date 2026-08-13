"""Lightweight cost-only collection separate from optimization analysis."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy.orm import Session

from backend.api.services.account_service import discover_current_account
from backend.bootstrap import ensure_project_paths

ensure_project_paths()

from aws_cost_optimizer.collectors.cost.collector import CostCollector

from backend.database.repository.scan_run_repository import (
    complete_scan_run,
    create_scan_run,
)


def default_cost_period() -> tuple[date, date]:
    """Cost Explorer end date is exclusive — use tomorrow to include today."""
    end = date.today() + timedelta(days=1)
    start = end - timedelta(days=91)
    return start, end


class CostRefreshService:
    def refresh(
        self,
        db: Session,
        *,
        start_date: date | None = None,
        end_date: date | None = None,
        region: str | None = None,
    ) -> dict:
        account = discover_current_account()
        if start_date is None or end_date is None:
            start_date, end_date = default_cost_period()

        scan = create_scan_run(
            db,
            account_id=account["account_id"],
            start_date=start_date,
            end_date=end_date,
            region=region,
            cost_threshold=0,
        )
        db.commit()

        collector = CostCollector()
        validation = collector.collect(db, scan)
        complete_scan_run(db, scan.id)
        db.commit()

        return {
            "scan_id": scan.id,
            "account_id": account["account_id"],
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "region": region,
            "validation": validation,
            "status": "completed",
        }
