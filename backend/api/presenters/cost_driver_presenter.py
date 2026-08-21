"""
Present hierarchical cost-driver (service -> usage type) data and the
per-scan collection summary (scan info, cost-collection reconciliation,
cost analysis, collection plan) to the frontend.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from backend.api.presenters.utils import parse_json_object
from backend.database.repositories.collection_plan_repository import (
    get_collection_plans_for_scan,
)
from backend.database.repositories.cost.service_costs import (
    get_service_costs_with_rank,
)
from backend.database.repositories.cost.usage_types import (
    get_usage_types_by_service,
)
from backend.database.models.scan_run import ScanRun


def present_cost_drivers(
    db: Session,
    scan_run_id: int,
    *,
    limit: int = 8,
    usage_types_per_service: int = 5,
) -> list[dict[str, Any]]:
    services = get_service_costs_with_rank(
        db,
        scan_run_id,
        limit=limit,
    )

    drivers = []

    for row in services:
        usage_types = get_usage_types_by_service(
            db,
            scan_run_id,
            row["service"],
            limit=usage_types_per_service,
        )

        drivers.append(
            {
                "rank": row["rank"],
                "service": row["service"],
                "cost": row["cost"],
                "share_pct": row["share_pct"],
                "trend": row["trend"],
                "change_percentage": row["change_percentage"],
                "change_amount": row["change_amount"],
                "usage_types": usage_types,
            }
        )

    return drivers


def _present_scan_info(scan_run: ScanRun) -> dict[str, Any]:
    return {
        "id": scan_run.id,
        "account_id": scan_run.account_id,
        "start_date": (
            scan_run.start_date.isoformat()
            if scan_run.start_date
            else None
        ),
        "end_date": (
            scan_run.end_date.isoformat()
            if scan_run.end_date
            else None
        ),
        "region": scan_run.region,
        "cost_threshold": scan_run.cost_threshold,
        "status": scan_run.status,
        "created_at": (
            scan_run.created_at.isoformat()
            if scan_run.created_at
            else None
        ),
        "finished_at": (
            scan_run.finished_at.isoformat()
            if scan_run.finished_at
            else None
        ),
    }


def _present_cost_collection(
    scan_run: ScanRun,
) -> dict[str, Any] | None:
    validation = parse_json_object(
        scan_run.cost_validation_json
    )

    if not validation:
        return None

    return {
        "collected_total": validation.get("collected_total"),
        "monthly_total": validation.get("monthly_total"),
        "difference": validation.get("difference"),
        "matches": validation.get("matches"),
    }


def _present_collection_plan(
    db: Session,
    scan_run_id: int,
) -> list[dict[str, Any]]:
    plans = get_collection_plans_for_scan(db, scan_run_id)

    return [
        {
            "resource_type": plan.resource_type,
            "region": plan.region,
            "cost_context": plan.cost_context,
            "priority": plan.priority,
            "service": plan.service,
            "usage_type": plan.usage_type,
            "collector_name": plan.collector_name,
            "status": plan.status,
        }
        for plan in sorted(
            plans,
            key=lambda item: item.cost_context or 0.0,
            reverse=True,
        )
    ]


def present_collection_summary(
    db: Session,
    scan_run: ScanRun,
) -> dict[str, Any]:
    return {
        "scan": _present_scan_info(scan_run),
        "cost_collection": _present_cost_collection(scan_run),
        "cost_analysis": present_cost_drivers(
            db,
            scan_run.id,
        ),
        "collection_plan": _present_collection_plan(
            db,
            scan_run.id,
        ),
    }
