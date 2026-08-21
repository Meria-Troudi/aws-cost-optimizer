from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from ..models.scan_run import ScanRun


def create_scan_run(
    db: Session,
    account_id: str,
    start_date,
    end_date,
    region: str | None,
    cost_threshold: float,
) -> ScanRun:

    scan = ScanRun(
        account_id=account_id,
        start_date=start_date,
        end_date=end_date,
        region=region,
        cost_threshold=float(cost_threshold),
        progress_percent=0.0,
        status="pending",
    )

    db.add(scan)
    db.flush()

    return scan


def get_scan_run(
    db: Session,
    scan_id: int,
) -> ScanRun | None:

    return db.get(ScanRun, scan_id)


def get_scan_runs(
    db: Session,
    limit: int = 50,
) -> list[ScanRun]:

    return (
        db.query(ScanRun)
        .order_by(
            ScanRun.created_at.desc()
        )
        .limit(limit)
        .all()
    )


def get_latest_scan_run(
    db: Session,
) -> ScanRun | None:

    return (
        db.query(ScanRun)
        .order_by(
            ScanRun.created_at.desc()
        )
        .first()
    )


def mark_scan_running(
    db: Session,
    scan_id: int,
) -> ScanRun | None:

    scan = get_scan_run(db, scan_id)

    if scan is None:
        return None

    scan.status = "running"
    scan.progress_percent = max(
        float(scan.progress_percent or 0),
        0.0,
    )
    scan.error_message = None

    db.flush()

    return scan


def update_scan_progress(
    db: Session,
    scan_id: int,
    progress_percent: float,
) -> ScanRun | None:

    scan = get_scan_run(db, scan_id)

    if scan is None:
        return None

    if scan.status in {"completed", "failed"}:
        return scan

    scan.progress_percent = max(
        0.0,
        min(99.0, float(progress_percent)),
    )

    db.flush()

    return scan


def complete_scan_run(
    db: Session,
    scan_id: int,
    outcome: str | None = None,
) -> ScanRun | None:

    scan = get_scan_run(db, scan_id)

    if scan is None:
        return None

    scan.status = "completed"
    scan.progress_percent = 100.0
    scan.finished_at = datetime.utcnow()
    scan.error_message = None

    if outcome is not None:
        scan.outcome = outcome

    db.flush()

    return scan


def fail_scan_run(
    db: Session,
    scan_id: int,
    error_message: str,
    outcome: str | None = None,
) -> ScanRun | None:

    scan = get_scan_run(db, scan_id)

    if scan is None:
        return None

    scan.status = "failed"
    scan.error_message = str(error_message)
    scan.finished_at = datetime.utcnow()

    if outcome is not None:
        scan.outcome = outcome

    db.flush()

    return scan


def get_scan_summary(
    scan: ScanRun,
) -> dict:

    findings_count = len(
        scan.findings or []
    )

    recommendations_count = len(
        scan.recommendations or []
    )

    return {
        "id": scan.id,
        "account_id": scan.account_id,
        "region": scan.region,
        "status": scan.status,
        "start_date": (
            scan.start_date.isoformat()
            if scan.start_date
            else None
        ),
        "end_date": (
            scan.end_date.isoformat()
            if scan.end_date
            else None
        ),
        "cost_threshold": float(
            scan.cost_threshold or 0.0
        ),
        "progress_percent": float(
            scan.progress_percent or 0.0
        ),
        "findings_count": findings_count,
        "recommendations_count": recommendations_count,
        "error": scan.error_message,
        "outcome": scan.outcome,
        "created_at": (
            scan.created_at.isoformat()
            if scan.created_at
            else None
        ),
        "finished_at": (
            scan.finished_at.isoformat()
            if scan.finished_at
            else None
        ),
    }


def delete_scan_run(
    db: Session,
    scan_id: int,
) -> bool:

    scan = get_scan_run(db, scan_id)

    if scan is None:
        return False

    db.delete(scan)
    db.flush()
    db.commit()

    return True