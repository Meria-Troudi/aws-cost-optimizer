from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.api.routes.dependencies import get_db
from backend.api.services.scan_service import ScanService

from backend.database.repositories.scan_run_repository import (
    get_scan_run,
)

from backend.database.models.cost_record import CostRecord


router = APIRouter(
    prefix="/api/scans",
    tags=["Scan Results"],
)


@router.get("/{scan_id}")
def get_scan_result(
    scan_id: int,
    db: Session = Depends(get_db),
) -> dict[str, Any]:

    scan = get_scan_run(
        db,
        scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found.",
        )

    cost_records = (
        db.query(CostRecord)
        .filter(
            CostRecord.scan_run_id == scan_id
        )
        .all()
    )

    costs = []

    for record in cost_records:
        costs.append({
            "id": record.id,
            "service": record.service,
            "usage_type": record.usage_type,
            "operation": record.operation,
            "region": record.region,
            "amount": float(
                record.amount or 0
            ),
            "usage_quantity": (
                float(record.usage_quantity)
                if record.usage_quantity is not None
                else None
            ),
            "unit": record.unit,
            "start_date": (
                record.start_date.isoformat()
                if record.start_date
                else None
            ),
            "end_date": (
                record.end_date.isoformat()
                if record.end_date
                else None
            ),
        })

    total_cost = sum(
        item["amount"]
        for item in costs
    )

    return {
        "scan": {
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
                scan.cost_threshold or 0
            ),
            "created_at": (
                scan.created_at.isoformat()
                if getattr(
                    scan,
                    "created_at",
                    None,
                )
                else None
            ),
            "finished_at": (
                scan.finished_at.isoformat()
                if getattr(
                    scan,
                    "finished_at",
                    None,
                )
                else None
            ),
        },

        "summary": {
            "total_cost": round(
                total_cost,
                2,
            ),
            "cost_records": len(costs),
        },

        "cost_records": costs,
    }