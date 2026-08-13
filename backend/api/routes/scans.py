from __future__ import annotations

import os
import sys
from typing import Any

# Ensure aws_cost_optimizer is importable when this module is loaded
# (including inside FastAPI background tasks / reloaded workers).
_BACKEND_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)
sys.path.insert(0, _BACKEND_ROOT)
sys.path.insert(0, os.path.join(_BACKEND_ROOT, "aws_cost_optimizer"))

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database.connection import SessionLocal
from backend.database.models.scan_run import ScanRun

from backend.api.schemas.scan import (
    FindingResponse,
    RecommendationResponse,
    ScanCreate,
    ScanStartResponse,
    ScanStatusResponse,
)


router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"],
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def execute_scan(scan_id: int) -> None:

    db = SessionLocal()

    try:

        scan = (
            db.query(ScanRun)
            .filter(
                ScanRun.id == scan_id
            )
            .first()
        )

        if not scan:
            return

        from backend.api.services.scan_service import ScanService

        service = ScanService()

        service.run_scan(
            db,
            scan,
        )
    except Exception as exc:

        print(
            f"Scan {scan_id} failed: {exc}"
        )

        db.rollback()

        scan = (
            db.query(ScanRun)
            .filter(ScanRun.id == scan_id)
            .first()
        )

        if scan and scan.status == "running":
            scan.status = "failed"
            db.commit()

    finally:

        db.close()


@router.post(
    "",
    response_model=ScanStartResponse,
)
def start_scan(
    request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    from backend.database.repository.scan_run_repository import (
        create_scan_run,
    )

    from aws_cost_optimizer.config.client import get_client
    from aws_cost_optimizer.config.settings import CE_REGION

    sts = get_client(
        "sts",
        CE_REGION,
    )

    account_id = (
        sts.get_caller_identity()
        .get("Account")
    )

    if not account_id:
        raise HTTPException(
            status_code=500,
            detail="Unable to determine AWS account",
        )

    scan = create_scan_run(
        db,
        account_id=account_id,
        start_date=request.start_date,
        end_date=request.end_date,
        region=request.region,
        cost_threshold=request.cost_threshold,
    )

    db.commit()

    background_tasks.add_task(
        execute_scan,
        scan.id,
    )

    return ScanStartResponse(
        scan_id=scan.id,
        status="running",
        message="Scan started",
    )


@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):

    scan = (
        db.query(ScanRun)
        .filter(
            ScanRun.id == scan_id
        )
        .first()
    )

    if not scan:

        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    from sqlalchemy import func

    from backend.database.models.collection_plan import CollectionPlan
    from backend.database.models.cost_record import CostRecord
    from backend.database.models.finding import Finding
    from backend.database.models.recommendation import Recommendation
    from backend.database.repository.service_cost_repository import (
        get_service_costs_with_rank,
    )
    from backend.database.scan_recovery import month_expression

    total_spend = (
        db.query(func.sum(CostRecord.amount))
        .filter(CostRecord.scan_run_id == scan_id)
        .scalar()
    )

    findings_count = (
        db.query(func.count(Finding.id))
        .filter(Finding.scan_run_id == scan_id)
        .scalar()
        or 0
    )

    recommendations_count = (
        db.query(func.count(Recommendation.id))
        .filter(Recommendation.scan_run_id == scan_id)
        .scalar()
        or 0
    )

    service_costs = []
    if total_spend:
        service_costs = get_service_costs_with_rank(db, scan_id)

    collection_plans = []
    if scan.status in ("running", "completed", "completed_with_errors"):
        plans = (
            db.query(CollectionPlan)
            .filter(CollectionPlan.scan_run_id == scan_id)
            .all()
        )
        collection_plans = [
            {
                "id": p.id,
                "service": p.service,
                "region": p.region,
                "usage_type": p.usage_type,
                "resource_type": p.resource_type,
                "collector": p.collector_name,
                "priority": p.priority,
                "cost_context": float(p.cost_context),
                "status": p.status,
            }
            for p in plans
        ]

    monthly_costs = []
    if total_spend:
        monthly_rows = (
            db.query(
                month_expression(CostRecord.start_date).label("month"),
                func.sum(CostRecord.amount).label("cost"),
            )
            .filter(CostRecord.scan_run_id == scan_id)
            .group_by("month")
            .order_by("month")
            .all()
        )
        monthly_costs = [
            {"month": row.month, "cost": float(row.cost)}
            for row in monthly_rows
        ]

    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        account_id=scan.account_id,
        start_date=scan.start_date,
        end_date=scan.end_date,
        region=scan.region,
        cost_threshold=scan.cost_threshold,
        metrics={
            "findings": findings_count,
            "recommendations": recommendations_count,
        },
        total_spend=float(total_spend) if total_spend else None,
        service_costs=service_costs,
        findings_count=findings_count,
        recommendations_count=recommendations_count,
        collection_plans=collection_plans,
        monthly_costs=monthly_costs,
    )


@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingResponse],
)
def get_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db),
):
    import json

    from backend.database.repository.finding_repository import (
        get_findings_by_scan,
    )

    scan = (
        db.query(ScanRun)
        .filter(ScanRun.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = get_findings_by_scan(db, scan_id)

    from backend.api.services.finding_presentation import present_finding

    def parse_json(value: str | None, fallback):
        if not value:
            return fallback
        try:
            parsed = json.loads(value)
            if isinstance(fallback, dict) and isinstance(parsed, list):
                return {}
            return parsed
        except json.JSONDecodeError:
            return fallback

    responses = []
    for f in findings:
        raw = {
            "id": f.id,
            "resource_type": f.resource_type,
            "resource_id": f.resource_id,
            "finding_type": f.finding_type,
            "analyzer": f.analyzer,
            "severity": f.severity,
            "confidence": f.confidence,
            "reason": f.reason,
            "recommendation_eligible": f.recommendation_eligible,
            "conditions": parse_json(f.conditions, []),
            "evidence": parse_json(f.evidence, {}),
            "limitations": parse_json(f.limitations, []),
        }
        presented = present_finding(raw, region=scan.region)

        responses.append(
            FindingResponse(
                id=f.id,
                resource_type=f.resource_type,
                resource_id=f.resource_id,
                finding_type=f.finding_type,
                analyzer=f.analyzer,
                severity=f.severity,
                confidence=f.confidence,
                reason=presented["reason"],
                recommendation_eligible=f.recommendation_eligible,
                conditions=parse_json(f.conditions, []),
                evidence=parse_json(f.evidence, {}),
                limitations=parse_json(f.limitations, []),
                title=presented["title"],
                summary=presented["summary"],
                service=presented["service"],
                resource_count=presented["resource_count"],
                resource_ids=presented["resource_ids"],
                region=presented["region"],
                evidence_items=presented["evidence_items"],
                metrics=presented["metrics"],
                cost_label=presented["cost_label"],
                condition_groups=presented["condition_groups"],
                billing_details=presented["billing_details"],
                metadata=presented["metadata"],
                observation_period=presented["observation_period"],
                category=presented["category"],
                blocks_optimization=presented["blocks_optimization"],
            )
        )

    return responses


@router.get(
    "/{scan_id}/recommendations",
    response_model=list[RecommendationResponse],
)
def get_scan_recommendations(
    scan_id: int,
    db: Session = Depends(get_db),
):
    import json

    from backend.database.repository.recommendation_repository import (
        get_recommendations_by_scan,
    )

    scan = (
        db.query(ScanRun)
        .filter(ScanRun.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    from backend.api.services.finding_presentation import present_finding
    from backend.api.services.recommendation_presentation import (
        present_recommendation,
    )
    from backend.database.repository.finding_repository import (
        get_findings_by_scan,
    )

    recommendations = get_recommendations_by_scan(
        db,
        scan_id,
    )

    findings = get_findings_by_scan(db, scan_id)

    finding_by_id: dict[int, dict[str, Any]] = {}
    for f in findings:
        presented = present_finding(
            {
                "id": f.id,
                "resource_type": f.resource_type,
                "resource_id": f.resource_id,
                "finding_type": f.finding_type,
                "reason": f.reason,
                "conditions": json.loads(f.conditions) if f.conditions else [],
                "evidence": json.loads(f.evidence) if f.evidence else {},
                "limitations": json.loads(f.limitations) if f.limitations else [],
                "recommendation_eligible": f.recommendation_eligible,
            },
            region=scan.region,
        )
        finding_by_id[f.id] = presented

    responses = []
    for r in recommendations:
        linked = finding_by_id.get(r.finding_id) if r.finding_id else None
        presented = present_recommendation(
            {
                "id": r.id,
                "finding_id": r.finding_id,
                "resource_type": r.resource_type,
                "title": r.title,
                "action": r.action,
                "explanation": r.explanation,
                "priority": r.priority,
                "confidence": r.confidence,
                "status": r.status,
                "affected_resources": linked.get("resource_ids") if linked else [],
            },
            resource_count=linked.get("resource_count") if linked else None,
            affected_resources=linked.get("resource_ids") if linked else None,
        )
        responses.append(
            RecommendationResponse(
                id=r.id,
                finding_id=r.finding_id,
                resource_type=r.resource_type,
                title=r.title,
                action=r.action,
                explanation=presented["explanation"],
                reason=presented["reason"],
                priority=r.priority,
                confidence=r.confidence,
                status=r.status,
                meta=presented["meta"],
                affected_resources=presented["affected_resources"],
                affected_resource_count=presented["affected_resource_count"],
            )
        )

    return responses


@router.get(
    "/{scan_id}/cost-trend",
)
def get_scan_cost_trend(
    scan_id: int,
    db: Session = Depends(get_db),
):

    from sqlalchemy import func

    from backend.database.models.cost_record import CostRecord
    from backend.database.scan_recovery import month_expression

    scan = (
        db.query(ScanRun)
        .filter(ScanRun.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    monthly_rows = (
        db.query(
            month_expression(CostRecord.start_date).label("month"),
            func.sum(CostRecord.amount).label("cost"),
        )
        .filter(CostRecord.scan_run_id == scan_id)
        .group_by("month")
        .order_by("month")
        .all()
    )

    return [
        {
            "month": row.month,
            "cost": float(row.cost),
        }
        for row in monthly_rows
    ]
