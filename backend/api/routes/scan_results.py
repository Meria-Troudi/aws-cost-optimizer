"""
Scan result-retrieval API routes.

Endpoints
---------
GET /api/scans/{scan_id}/cost-summary
GET /api/scans/{scan_id}/cost-trend
GET /api/scans/{scan_id}/cost-drivers
GET /api/scans/{scan_id}/collection-summary
GET /api/scans/{scan_id}/findings
GET /api/scans/{scan_id}/recommendations
GET /api/scans/{scan_id}/result

The scan's own lifecycle/CRUD endpoints (create/list/latest/bare
GET-by-id/delete) live in scans.py.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from aws_cost_optimizer.analysis.aggregation import FindingAggregator

from backend.api.presenters.cost_driver_presenter import (
    present_cost_drivers,
    present_collection_summary,
)
from backend.api.presenters.finding_presenter import (
    present_findings,
)
from backend.api.presenters.recommendation_presenter import (
    present_recommendations,
)
from backend.api.routes.dependencies import get_db

from backend.database.models.cost_record import CostRecord

from backend.database.repositories.cost.analytics import (
    get_monthly_totals,
    get_region_period_totals,
    get_service_period_totals,
    get_service_region_costs,
)
from backend.database.repositories.finding_repository import (
    SEVERITY_ORDER,
    get_findings_by_scan,
    hydrate_findings,
)
from backend.database.repositories.recommendation_repository import (
    get_recommendations_by_scan,
)
from backend.database.repositories.scan_run_repository import (
    get_scan_run,
    get_scan_summary,
)


router = APIRouter(
    prefix="/api/scans",
    tags=["Scan Results"],
)


def _aggregate_findings(
    presented: list[dict[str, Any]],
    hydrated: list[Any],
) -> list[dict[str, Any]]:
    """
    Aggregate resource-level findings using the canonical
    FindingAggregator (aws_cost_optimizer/analysis/aggregation.py) --
    the same grouping the exporter already uses -- instead of a
    separate, weaker re-implementation. A prior bespoke version keyed
    groups on (finding_key, resource_type, region) with no
    account_id and no string normalization, which could split what
    should have been one group into two (e.g. the same resource
    appearing both inside a ">1 resources" group and again as its own
    singleton row).

    One analyzer may create one Finding row per resource.
    The frontend should normally see one reportable finding
    containing all affected resources.
    """

    presented_by_database_id = {
        finding.get("id"): finding
        for finding in presented
        if finding.get("id") is not None
    }

    aggregator_groups = (
        FindingAggregator().aggregate(
            hydrated
        )
    )

    result: list[dict[str, Any]] = []

    for group in aggregator_groups:

        # group["source_finding_ids"] is only populated by
        # FindingEngine right after a fresh scan persists its raw
        # findings (it needs the stable-id -> DB-id map built at that
        # moment). Reading it back later from hydrated rows leaves it
        # permanently empty, so pull each member's database_id from
        # the group's own affected_resources instead -- hydrate_findings
        # already sets Finding.database_id from the DB row's own id.
        member_ids = [
            resource.get("database_id")
            for resource in (
                group.get(
                    "affected_resources"
                )
                or []
            )
            if resource.get("database_id")
            is not None
        ]

        members = [
            presented_by_database_id[
                member_id
            ]
            for member_id in member_ids
            if member_id
            in presented_by_database_id
        ]

        if not members:
            continue

        first = members[0]

        resource_ids: list[str] = []
        reasons: list[str] = []
        evidence_summaries: list[str] = []
        limitations: list[str] = []

        group_cost: float | None = None

        for finding in members:
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

            # Members grouped together typically share one
            # collection-plan billing figure (see
            # aws_cost_optimizer/analysis/aggregation.py::_aggregate_impact
            # for the full explanation) rather than each having an
            # individually-attributed cost, so this takes the max
            # across the group instead of summing -- summing would
            # multiply-count the same account-level total once per
            # affected resource.
            if isinstance(
                cost,
                (int, float),
            ):
                group_cost = (
                    float(cost)
                    if group_cost is None
                    else max(
                        group_cost,
                        float(cost),
                    )
                )

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
            round(group_cost, 2)
            if group_cost is not None
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
            group.get(
                "aggregation_scope"
            )
            or "region"
        )

        result.append(
            aggregated
        )

    result.sort(
        key=lambda finding: (
            -SEVERITY_ORDER.get(
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


@router.get("/{scan_id}/cost-drivers")
def get_scan_cost_drivers(
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

    return {
        "scan_id": scan_id,
        "drivers": present_cost_drivers(db, scan_id),
    }


@router.get("/{scan_id}/collection-summary")
def get_scan_collection_summary(
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

    return present_collection_summary(db, scan)


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
        presented,
        hydrate_findings(findings),
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

    scan_finding_rows = (
        get_findings_by_scan(
            db,
            scan_id,
        )
    )

    findings = _aggregate_findings(
        present_findings(
            scan_finding_rows
        ),
        hydrate_findings(
            scan_finding_rows
        ),
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
