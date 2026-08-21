"""
Scan lifecycle API routes.

Endpoints
---------
POST   /api/scans
GET    /api/scans
GET    /api/scans/latest
GET    /api/scans/{scan_id}
DELETE /api/scans/{scan_id}

Result-retrieval endpoints (findings, recommendations, cost summary/trend/
drivers, collection summary, full result) live in scan_results.py.
"""

from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION

from backend.api.routes.dependencies import get_db
from backend.api.schemas.scan import (
    ScanRequest,
    ScanResponse,
)
from backend.api.services.scan_service import (
    ScanService,
)

from backend.database.connection import SessionLocal

from backend.database.repositories.scan_run_repository import (
    create_scan_run,
    delete_scan_run,
    get_latest_scan_run,
    get_scan_run,
    get_scan_runs,
    get_scan_summary,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"],
)


def _run_scan_in_background(
    scan_id: int,
) -> None:
    """
    Run a scan using an independent DB session.

    The request session must never be reused by the
    background worker.
    """

    def worker() -> None:
        db: Session = SessionLocal()

        try:
            scan = get_scan_run(
                db,
                scan_id,
            )

            if scan is None:
                logger.error(
                    "Scan %s disappeared before execution.",
                    scan_id,
                )
                return

            ScanService(db).run(scan)

            db.commit()

        except Exception as exc:
            logger.exception(
                "Scan %s failed.",
                scan_id,
            )

            try:
                db.rollback()

                scan = get_scan_run(
                    db,
                    scan_id,
                )

                if scan is not None:
                    scan.status = "failed"

                    # Only set finished_at if the model supports it.
                    if hasattr(scan, "finished_at"):
                        from datetime import datetime, timezone

                        scan.finished_at = datetime.now(
                            timezone.utc
                        )

                    db.commit()

            except Exception:
                logger.exception(
                    "Unable to mark scan %s as failed.",
                    scan_id,
                )

        finally:
            db.close()

    thread = threading.Thread(
        target=worker,
        daemon=True,
        name=f"scan-{scan_id}",
    )

    thread.start()


@router.post(
    "",
    response_model=ScanResponse,
)
def create_scan(
    request: ScanRequest,
    db: Session = Depends(get_db),
):
    if request.start_date >= request.end_date:
        raise HTTPException(
            status_code=400,
            detail=(
                "start_date must be earlier "
                "than end_date."
            ),
        )

    try:
        sts = get_client(
            "sts",
            CE_REGION,
        )

        identity = (
            sts.get_caller_identity()
        )

        account_id = identity.get(
            "Account"
        )

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to identify AWS account: "
                f"{exc}"
            ),
        ) from exc

    if not account_id:
        raise HTTPException(
            status_code=502,
            detail=(
                "AWS account ID could not be determined."
            ),
        )

    try:
        scan = create_scan_run(
            db,
            account_id=account_id,
            start_date=request.start_date,
            end_date=request.end_date,
            region=request.region,
            cost_threshold=request.cost_threshold,
        )

        db.commit()
        db.refresh(scan)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to create scan: "
                f"{exc}"
            ),
        ) from exc

    _run_scan_in_background(
        scan.id
    )

    return ScanResponse(
        scan_id=scan.id,
        status="running",
        result=get_scan_summary(
            scan
        ),
    )


@router.get("")
def list_scans(
    db: Session = Depends(get_db),
):
    scans = get_scan_runs(db)

    return [
        get_scan_summary(scan)
        for scan in scans
    ]


@router.get("/latest")
def get_latest_scan(
    db: Session = Depends(get_db),
):
    scan = get_latest_scan_run(db)

    if scan is None:
        return None

    return get_scan_summary(
        scan
    )


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = get_scan_run(
        db,
        scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Scan {scan_id} not found."
            ),
        )

    return get_scan_summary(
        scan
    )


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = get_scan_run(
        db,
        scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Scan {scan_id} not found."
            ),
        )

    try:
        deleted = delete_scan_run(
            db,
            scan_id,
        )

        if not deleted:
            db.rollback()

            raise HTTPException(
                status_code=404,
                detail=(
                    f"Scan {scan_id} not found."
                ),
            )

        db.commit()

        return {
            "status": "deleted",
            "scan_id": scan_id,
        }

    except HTTPException:
        raise

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to delete scan: "
                f"{exc}"
            ),
        ) from exc
