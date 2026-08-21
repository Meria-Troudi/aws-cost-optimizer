"""
Recover scans left in 'running' after server reload or crash.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database.models.cost_record import CostRecord
from backend.database.models.finding import Finding
from backend.database.models.scan_run import ScanRun


#: Scan states that only a live worker thread can legitimately hold.
INTERRUPTED_STATES = ("pending", "running")


def recover_stuck_scans(db: Session) -> int:
    """
    Close out scans orphaned by a server restart or crash.

    Scans run in daemon threads inside this process, so at startup no
    scan can still be in flight: every row left in 'pending' or
    'running' belongs to a worker that no longer exists. Without this,
    such rows keep their status forever and the UI polls them until it
    times out.

    Interrupted scans are marked **failed**, not completed, even when
    they already persisted cost records or findings. Stage-by-stage
    commits mean partial data proves only that the scan got part-way,
    never that it finished -- promoting those to 'completed' would
    publish a half-collected scan as a whole one.

    Note: this assumes a single worker process. With multiple uvicorn
    workers, a scan running in a sibling process would be wrongly
    failed here.

    Returns the number of scans closed out.
    """

    stuck_scans = (
        db.query(ScanRun)
        .filter(ScanRun.status.in_(INTERRUPTED_STATES))
        .order_by(ScanRun.id.asc())
        .all()
    )

    if not stuck_scans:
        return 0

    for scan in stuck_scans:

        cost_count = (
            db.query(func.count(CostRecord.id))
            .filter(CostRecord.scan_run_id == scan.id)
            .scalar()
            or 0
        )

        findings_count = (
            db.query(func.count(Finding.id))
            .filter(Finding.scan_run_id == scan.id)
            .scalar()
            or 0
        )

        scan.status = "failed"

        if hasattr(scan, "finished_at") and not scan.finished_at:
            scan.finished_at = datetime.utcnow()

        if hasattr(scan, "error_message"):
            scan.error_message = (
                "Scan was interrupted before it finished (server "
                f"restart or crash). Partial data retained: "
                f"{cost_count} cost record(s), "
                f"{findings_count} finding(s)."
            )

    db.commit()

    print(
        f"[startup] Closed out {len(stuck_scans)} interrupted "
        f"scan(s): {[s.id for s in stuck_scans]}"
    )

    return len(stuck_scans)


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
