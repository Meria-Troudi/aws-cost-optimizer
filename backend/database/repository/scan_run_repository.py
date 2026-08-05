"""
Scan run repository
"""

from sqlalchemy.orm import Session
from datetime import datetime

from backend.database.models.scan_run import ScanRun


def create_scan_run(
    db: Session,
    account_id: str = "default",
    start_date: datetime = None,
    end_date: datetime = None,
    region: str = None,
    cost_threshold: float = 100.0,
    tag_filter: dict = None,
    collector_version: str = None,
) -> ScanRun:
    scan_run = ScanRun(
        account_id=account_id,
        status="running",
        start_date=start_date,
        end_date=end_date,
        region=region,
        cost_threshold=cost_threshold,
        tag_filter=tag_filter,
        collector_version=collector_version,
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    return scan_run


def finish_scan_run(
    db: Session,
    scan_run_id: int,
    status: str = "completed",
) -> ScanRun:
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if scan_run:
        scan_run.status = status
        scan_run.finished_at = datetime.utcnow()
        db.commit()
        db.refresh(scan_run)
    return scan_run
