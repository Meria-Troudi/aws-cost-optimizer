from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from sqlalchemy.orm import Session

from backend.api.routes.dependencies import get_db
from backend.api.services.dashboard_service import (
    DashboardService,
)

from backend.database.models.scan_run import ScanRun
from backend.database.repositories.scan_run_repository import (
    get_scan_summary,
)

router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
)


@router.get("/overview")
def dashboard_overview(
    history_months: int = Query(
        default=6,
        ge=1,
        le=24,
    ),
    region: str | None = None,
    service: str | None = None,
    db: Session = Depends(get_db),
):
    try:
        latest_scan = (
            db.query(ScanRun)
            .order_by(
                ScanRun.created_at.desc()
            )
            .first()
        )

        latest_scan_summary = (
            get_scan_summary(
                latest_scan
            )
            if latest_scan
            else None
        )

        dashboard = DashboardService()

        return dashboard.get_overview(
            history_months=history_months,
            # DashboardService currently aggregates all services itself.
            # Do not forward the UI service filter as an unsupported keyword.
            region=None if region in (None, "", "all") else region,
            latest_scan=latest_scan_summary,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to load dashboard.",
        ) from exc
