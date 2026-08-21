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

from backend.database.repositories.scan_run_repository import (
    get_latest_scan_run,
    get_scan_summary,
)


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
)


def _clean_region(
    value: str | None,
) -> str | None:

    if value in (
        None,
        "",
        "all",
    ):
        return None

    return value


@router.get("/overview")
def dashboard_overview(
    history_months: int = Query(
        default=6,
        ge=3,
        le=12,
    ),
    force_refresh: bool = Query(
        default=False,
    ),
    db: Session = Depends(
        get_db
    ),
):

    try:

        latest_scan = get_latest_scan_run(db)

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
            latest_scan=latest_scan_summary,
            force_refresh=force_refresh,
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail="Unable to load dashboard.",
        ) from exc