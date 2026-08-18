"""
Scan API routes.

Endpoints
---------
POST   /api/scans
GET    /api/scans
GET    /api/scans/latest
GET    /api/scans/{scan_id}
DELETE /api/scans/{scan_id}

GET    /api/scans/{scan_id}/findings
GET    /api/scans/{scan_id}/recommendations
GET    /api/scans/{scan_id}/cost-trend
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION

from backend.api.presenters.finding_presenter import (
    present_findings,
)
from backend.api.presenters.recommendation_presenter import (
    present_recommendations,
)
from backend.api.routes.dependencies import get_db
from backend.api.schemas.scan import (
    ScanRequest,
    ScanResponse,
)
from backend.api.services.scan_service import (
    ScanService,
)

from backend.database.connection import SessionLocal
from backend.database.models.cost_record import CostRecord
from backend.database.models.scan_run import ScanRun

from backend.database.repositories.cost_analytics_repository import (
    get_monthly_totals,
    get_region_period_totals,
    get_service_period_totals,
    get_service_region_costs,
)
from backend.database.repositories.finding_repository import (
    get_findings_by_scan,
)
from backend.database.repositories.recommendation_repository import (
    get_recommendations_by_scan,
)
from backend.database.repositories.scan_run_repository import (
    create_scan_run,
    delete_scan_run,
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


def _aggregate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Aggregate resource-level findings.

    One analyzer may create one Finding row per resource.
    The frontend should normally see one reportable finding
    containing all affected resources.
    """

    groups: dict[
        tuple[str, str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for finding in findings:
        key = (
            str(
                finding.get("finding_key")
                or finding.get("finding_type")
                or "unknown"
            ),
            str(
                finding.get("resource_type")
                or "unknown"
            ),
            str(
                finding.get("region")
                or "unknown"
            ),
        )

        groups[key].append(finding)

    result: list[dict[str, Any]] = []

    for group in groups.values():
        first = group[0]

        resource_ids: list[str] = []
        reasons: list[str] = []
        evidence_summaries: list[str] = []
        limitations: list[str] = []

        total_cost = 0.0
        has_cost = False

        for finding in group:
            resource_id = finding.get(
                "resource_id"
            )

            if (
                resource_id
                and resource_id not in resource_ids
            ):
                resource_ids.append(
                    str(resource_id)
                )

            cost = finding.get("cost")

            if isinstance(cost, (int, float)):
                total_cost += float(cost)
                has_cost = True

            reason = finding.get("reason")

            if (
                reason
                and reason not in reasons
            ):
                reasons.append(
                    str(reason)
                )

            for item in (
                finding.get(
                    "evidence_summary"
                )
                or []
            ):
                if (
                    item
                    and str(item)
                    not in evidence_summaries
                ):
                    evidence_summaries.append(
                        str(item)
                    )

            for item in (
                finding.get(
                    "limitations"
                )
                or []
            ):
                if (
                    item
                    and str(item)
                    not in limitations
                ):
                    limitations.append(
                        str(item)
                    )

        aggregated = dict(first)

        aggregated["resource_ids"] = (
            resource_ids
        )

        aggregated["resource_count"] = (
            len(resource_ids)
        )

        aggregated["cost"] = (
            round(total_cost, 2)
            if has_cost
            else None
        )

        if len(resource_ids) == 1:
            resource_text = (
                "1 affected resource."
            )
        else:
            resource_text = (
                f"{len(resource_ids)} affected resources."
            )

        aggregated["reason"] = (
            resource_text
            + (
                f" {reasons[0]}"
                if reasons
                else ""
            )
        )

        aggregated["evidence_summary"] = (
            evidence_summaries
        )

        aggregated["limitations"] = (
            limitations
        )

        aggregated["aggregation_scope"] = (
            "region"
        )

        result.append(
            aggregated
        )

    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    result.sort(
        key=lambda finding: (
            -severity_order.get(
                str(
                    finding.get(
                        "severity",
                        "info",
                    )
                ).lower(),
                0,
            ),
            str(
                finding.get(
                    "finding_type",
                    "",
                )
            ),
        )
    )

    return result


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
    scan = (
        db.query(ScanRun)
        .order_by(
            ScanRun.created_at.desc()
        )
        .first()
    )

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


@router.get(
    "/{scan_id}/findings"
)
def get_scan_findings(
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

    findings = get_findings_by_scan(
        db,
        scan_id,
    )

    presented = present_findings(
        findings
    )

    return _aggregate_findings(
        presented
    )


@router.get(
    "/{scan_id}/recommendations"
)
def get_scan_recommendations(
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

    recommendations = (
        get_recommendations_by_scan(
            db,
            scan_id,
        )
    )

    return present_recommendations(
        recommendations
    )


@router.get(
    "/{scan_id}/cost-summary"
)
def get_scan_cost_summary(
    scan_id: int,
    db: Session = Depends(get_db),
):
    """Return the cost summary used by the results page."""
    scan = get_scan_run(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    records = (
        db.query(CostRecord)
        .filter(CostRecord.scan_run_id == scan_id)
        .all()
    )
    total_cost = sum(float(record.amount or 0) for record in records)

    return {
        "scan_id": scan_id,
        "period": {
            "start_date": scan.start_date.isoformat() if scan.start_date else None,
            "end_date": scan.end_date.isoformat() if scan.end_date else None,
        },
        "currency": "USD",
        "total_cost": round(total_cost, 2),
        "cost_records": len(records),
        "monthly": get_monthly_totals(db, scan_id),
        "services": get_service_period_totals(db, scan_id),
        "regions": get_region_period_totals(db, scan_id),
        "service_regions": get_service_region_costs(db, scan_id),
    }


@router.get(
    "/{scan_id}/cost-trend"
)
def get_scan_cost_trend(
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

    return get_monthly_totals(
        db,
        scan_id,
    )


@router.get(
    "/{scan_id}/result"
)
def get_scan_result(
    scan_id: int,
    db: Session = Depends(get_db),
):
    """
    Complete frontend result endpoint.

    Keeps scan metadata, cost summary, findings,
    recommendations and cost trend in one response.
    """

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

    cost_records = (
        db.query(CostRecord)
        .filter(
            CostRecord.scan_run_id
            == scan_id
        )
        .all()
    )

    costs = []

    for record in cost_records:
        costs.append(
            {
                "id": record.id,
                "service": record.service,
                "usage_type": record.usage_type,
                "operation": record.operation,
                "region": record.region,
                "amount": round(
                    float(
                        record.amount or 0
                    ),
                    2,
                ),
                "usage_quantity": (
                    float(
                        record.usage_quantity
                    )
                    if record.usage_quantity
                    is not None
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
            }
        )

    total_cost = sum(
        item["amount"]
        for item in costs
    )

    findings = _aggregate_findings(
        present_findings(
            get_findings_by_scan(
                db,
                scan_id,
            )
        )
    )

    recommendations = present_recommendations(
        get_recommendations_by_scan(
            db,
            scan_id,
        )
    )

    return {
        "scan": get_scan_summary(
            scan
        ),

        "summary": {
            "total_cost": round(
                total_cost,
                2,
            ),
            "cost_records": len(
                costs
            ),
            "findings": len(
                findings
            ),
            "recommendations": len(
                recommendations
            ),
        },

        "cost_records": costs,

        "findings": findings,

        "recommendations": recommendations,

        "cost_trend": get_monthly_totals(
            db,
            scan_id,
        ),
    }
