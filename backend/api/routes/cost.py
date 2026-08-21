"""
Cost API routes.
"""

from __future__ import annotations

from datetime import date

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from aws_cost_optimizer.config.client import (
    get_client,
)
from aws_cost_optimizer.config.settings import (
    CE_REGION,
)

from backend.api.services.dashboard_service import (
    DashboardService,
)


router = APIRouter(
    prefix="/api/cost",
    tags=["Cost"],
)


@router.get("/regions")
def list_regions():

    try:

        ec2 = get_client(
            "ec2",
            CE_REGION,
        )

        response = ec2.describe_regions()

        regions = [
            region["RegionName"]
            for region in response.get(
                "Regions",
                [],
            )
            if region.get(
                "RegionName"
            )
        ]

        return {
            "regions": sorted(
                regions
            )
        }

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail="Unable to fetch AWS regions.",
        ) from exc


@router.get("/explorer")
def get_cost_explorer(
    dimension: str = Query(
        default="SERVICE",
    ),
    region: str | None = None,
    date_type: str = Query(
        default="current",
    ),
    month: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int = Query(
        default=12,
        ge=1,
        le=30,
    ),
):

    try:

        dashboard = DashboardService()

        return dashboard.get_cost_explorer(
            dimension=dimension,
            region=(
                None
                if region in (
                    None,
                    "",
                    "all",
                )
                else region
            ),
            date_type=date_type,
            month=month,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            today=date.today(),
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to retrieve Cost Explorer data."
            ),
        ) from exc


@router.get("/explorer/service")
def get_cost_explorer_service(
    service: str,
    region: str | None = None,
    date_type: str = Query(
        default="current",
    ),
    month: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int = Query(
        default=10,
        ge=1,
        le=20,
    ),
):

    try:

        dashboard = DashboardService()

        return dashboard.get_cost_explorer_service(
            service=service,
            region=(
                None
                if region in (
                    None,
                    "",
                    "all",
                )
                else region
            ),
            date_type=date_type,
            month=month,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            today=date.today(),
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to retrieve service cost details."
            ),
        ) from exc