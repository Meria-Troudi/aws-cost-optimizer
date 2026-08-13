from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.api.services.account_service import discover_current_account
from backend.database.connection import SessionLocal
from backend.database.repository.cost_analytics_repository import get_distinct_regions
from backend.database.scan_recovery import latest_scan_with_costs


router = APIRouter(prefix="/api", tags=["Account & Cost"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class CostRefreshRequest(BaseModel):
    region: str | None = None


@router.get("/account")
def get_account():
    try:
        return discover_current_account()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _execute_cost_refresh(scan_id: int) -> None:
    db = SessionLocal()
    try:
        from backend.database.models.scan_run import ScanRun

        scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not scan:
            return
        from aws_cost_optimizer.collectors.cost.collector import CostCollector
        from backend.database.repository.scan_run_repository import complete_scan_run

        CostCollector().collect(db, scan)
        complete_scan_run(db, scan.id)
        db.commit()
    except Exception as exc:
        print(f"Cost refresh {scan_id} failed: {exc}")
        db.rollback()
    finally:
        db.close()


@router.post("/cost/refresh")
def refresh_costs(
    background_tasks: BackgroundTasks,
    request: CostRefreshRequest | None = None,
    db: Session = Depends(get_db),
):
    from backend.database.repository.scan_run_repository import create_scan_run
    from backend.api.services.cost_refresh_service import default_cost_period

    try:
        account = discover_current_account()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    start_date, end_date = default_cost_period()
    region = request.region if request else None

    scan = create_scan_run(
        db,
        account_id=account["account_id"],
        start_date=start_date,
        end_date=end_date,
        region=region,
        cost_threshold=0,
    )
    db.commit()

    background_tasks.add_task(_execute_cost_refresh, scan.id)
    return {
        "scan_id": scan.id,
        "status": "running",
        "message": "Cost collection started",
        "account_id": account["account_id"],
    }


@router.get("/cost/regions")
def list_cost_regions(db: Session = Depends(get_db)):
    latest = latest_scan_with_costs(db)
    if not latest:
        return {"regions": [], "source": "none"}

    regions = get_distinct_regions(db, latest.id)
    return {
        "regions": regions,
        "scan_id": latest.id,
        "source": "database",
    }
