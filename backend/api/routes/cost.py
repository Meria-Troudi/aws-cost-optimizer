"""
Cost API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from aws_cost_optimizer.config.client import (
    get_client,
)
from aws_cost_optimizer.config.settings import (
    CE_REGION,
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

        response = (
            ec2.describe_regions()
        )

        regions = [
            region["RegionName"]
            for region
            in response.get(
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
            detail=(
                "Unable to fetch AWS regions."
            ),
        ) from exc


@router.post("/refresh")
def refresh_cost_data():

    raise HTTPException(
        status_code=501,
        detail=(
            "Cost refresh is not implemented. "
            "Use POST /api/scans to create a new "
            "analysis scan."
        ),
    )