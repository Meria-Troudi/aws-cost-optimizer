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
        cost_threshold=cost_threshold,
        status="running",
    )

    db.add(scan)
    db.flush()

    return scan


def get_scan_run(
    db: Session,
    scan_id: int,
) -> ScanRun | None:

    return db.get(ScanRun, scan_id)


def complete_scan_run(
    db: Session,
    scan_id: int,
):

    scan = db.get(ScanRun, scan_id)

    if scan is None:
        return None

    scan.status = "completed"
    scan.finished_at = datetime.utcnow()

    db.flush()

    return scan