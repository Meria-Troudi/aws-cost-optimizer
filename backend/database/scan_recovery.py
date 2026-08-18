"""
Recover scans left in 'running' after server reload or crash.
"""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database.models.cost_record import CostRecord
from backend.database.models.finding import Finding
from backend.database.models.scan_run import ScanRun
from backend.database.repositories.scan_run_repository import complete_scan_run


def recover_stuck_scans(db: Session) -> int:
    """
    Mark running scans as completed when they already persisted cost data,
    or failed when they have no cost data and cannot have finished normally.
    """
    recovered = 0

    running_scans = (
        db.query(ScanRun)
        .filter(ScanRun.status == "running")
        .order_by(ScanRun.id.asc())
        .all()
    )

    for scan in running_scans:
        cost_count = (
            db.query(func.count(CostRecord.id))
            .filter(CostRecord.scan_run_id == scan.id)
            .scalar()
            or 0
        )

        if cost_count > 0:
            complete_scan_run(db, scan.id)
            recovered += 1
            continue

        findings_count = (
            db.query(func.count(Finding.id))
            .filter(Finding.scan_run_id == scan.id)
            .scalar()
            or 0
        )

        if findings_count > 0:
            complete_scan_run(db, scan.id)
            recovered += 1
            continue

        scan.status = "failed"

    if running_scans:
        db.commit()

    return recovered


def latest_scan_with_costs(db: Session) -> ScanRun | None:
    """
    Best scan for the cost overview dashboard.

    Prefers the newest completed all-regions cost refresh (cost_threshold=0),
    then any newest completed scan that has cost records.
    """
    completed = ("completed", "completed_with_errors")
    cost_scan_ids = db.query(CostRecord.scan_run_id).distinct()

    overview = (
        db.query(ScanRun)
        .filter(ScanRun.id.in_(cost_scan_ids))
        .filter(ScanRun.status.in_(completed))
        .filter(ScanRun.cost_threshold == 0)
        .filter(ScanRun.region.is_(None))
        .order_by(ScanRun.id.desc())
        .first()
    )
    if overview:
        return overview

    return (
        db.query(ScanRun)
        .filter(ScanRun.id.in_(cost_scan_ids))
        .filter(ScanRun.status.in_(completed))
        .order_by(ScanRun.id.desc())
        .first()
    )


def month_expression(start_date_column):
    """SQLite-safe YYYY-MM grouping for date columns."""
    return func.strftime("%Y-%m", start_date_column)
