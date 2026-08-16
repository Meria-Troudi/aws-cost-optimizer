"""
Dashboard routes.

Uses persisted cost records from the database (via CostCollector refresh).
Everything is database-driven — no direct AWS Cost Explorer calls here.
"""

from __future__ import annotations

from calendar import monthrange
from datetime import date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database.connection import SessionLocal
from backend.database.models.cost_record import CostRecord
from backend.database.models.finding import Finding
from backend.database.models.recommendation import Recommendation
from backend.database.models.scan_run import ScanRun
from backend.database.repository.cost_analytics_repository import (
    get_collection_counts,
    get_month_totals_by_month_keys,
    get_monthly_totals,
    get_region_costs_by_month,
    get_region_costs_for_month,
    get_region_count_for_month,
    get_service_costs_by_month,
    get_service_costs_for_month,
    get_service_count_for_month,
    get_service_region_costs,
    get_usage_type_costs_for_month,
)
from backend.database.scan_recovery import (
    latest_scan_with_costs,
    month_expression,
)
from backend.api.services.cost_analytics import (
    build_concentration_stats,
    build_cost_drivers_from_services,
    build_cost_statistics,
    build_previous_month_kpi,
    build_region_costs_with_changes,
    build_region_monthly_matrix,
    build_service_costs_with_changes,
    build_service_changes,
    build_service_monthly_matrix,
    build_service_region_matrix,
    build_three_month_total,
    _short_service,
)


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _month_key(yr: int, mo: int) -> str:
    return f"{yr:04d}-{mo:02d}"


def _add_months(d: date, months: int) -> date:
    month = d.month - 1 + months
    year = d.year + month // 12
    month = month % 12 + 1
    day = min(d.day, monthrange(year, month)[1])
    return date(year, month, day)


def _key_months(today: date | None = None) -> dict[str, str]:
    """Return YYYY-MM keys for current, 3mo-ago, and 6mo-ago months."""
    today = today or date.today()
    current = _month_key(today.year, today.month)
    three_ago = _add_months(today.replace(day=1), -3)
    six_ago = _add_months(today.replace(day=1), -6)
    return {
        "current_month": current,
        "three_months_ago": _month_key(three_ago.year, three_ago.month),
        "six_months_ago": _month_key(six_ago.year, six_ago.month),
    }


def _period_months_list(today: date | None = None, count: int = 6) -> list[str]:
    today = today or date.today()
    months: list[str] = []
    for i in range(count - 1, -1, -1):
        d = _add_months(today.replace(day=1), -i)
        months.append(_month_key(d.year, d.month))
    return months


def _build_period_stats(
    db: Session,
    scan_run_id: int,
    month_key: str,
    label: str,
) -> dict[str, Any]:
    total_rows = get_month_totals_by_month_keys(db, scan_run_id, [month_key])
    total = float(total_rows.get(month_key, 0.0))
    return {
        "month": month_key,
        "label": label,
        "total_spend": round(total, 2),
        "top_services": get_service_costs_for_month(db, scan_run_id, month_key, limit=5),
        "top_regions": get_region_costs_for_month(db, scan_run_id, month_key, limit=5),
        "top_usage_types": get_usage_type_costs_for_month(db, scan_run_id, month_key, limit=5),
        "services_with_spend": get_service_count_for_month(db, scan_run_id, month_key),
        "regions_with_spend": get_region_count_for_month(db, scan_run_id, month_key),
        "currency": "USD",
    }


def _build_period_comparison(
    db: Session,
    scan_run_id: int,
    today: date | None = None,
) -> dict[str, Any]:
    keys = _key_months(today)
    return {
        "current_month": _build_period_stats(
            db, scan_run_id, keys["current_month"], "Current month"
        ),
        "three_months_ago": _build_period_stats(
            db, scan_run_id, keys["three_months_ago"], "3 months ago"
        ),
        "six_months_ago": _build_period_stats(
            db, scan_run_id, keys["six_months_ago"], "6 months ago"
        ),
    }


def _build_mtd_from_monthly(
    monthly_rows: list[dict],
    today: date | None = None,
) -> dict[str, Any]:
    today = today or date.today()
    current_key = _month_key(today.year, today.month)
    prev_date = _add_months(today.replace(day=1), -1)
    prev_key = _month_key(prev_date.year, prev_date.month)

    by_month = {r["month"]: float(r["cost"]) for r in monthly_rows}
    current_amount = by_month.get(current_key, 0.0)
    previous_amount = by_month.get(prev_key, 0.0)

    difference = current_amount - previous_amount
    if previous_amount != 0:
        percentage = (difference / previous_amount) * 100
    else:
        percentage = None

    if difference > 0.01:
        direction = "increased"
    elif difference < -0.01:
        direction = "decreased"
    else:
        direction = "stable"

    month_start = today.replace(day=1)
    comparable_day = min(today.day, monthrange(prev_date.year, prev_date.month)[1])
    prev_end = prev_date + timedelta(days=comparable_day)

    return {
        "current": {
            "start_date": month_start.isoformat(),
            "end_date": today.isoformat(),
            "days_elapsed": today.day,
            "amount": round(current_amount, 2),
            "currency": "USD",
        },
        "previous": {
            "start_date": prev_date.isoformat(),
            "end_date": (prev_end - timedelta(days=1)).isoformat(),
            "days": comparable_day,
            "amount": round(previous_amount, 2),
            "currency": "USD",
        },
        "difference": round(difference, 2),
        "percentage_change": round(percentage, 2) if percentage is not None else None,
        "direction": direction,
    }


def _build_hero(
    monthly_rows: list[dict],
    total_spend: float,
    forecast_amount: float | None,
) -> dict[str, Any]:
    trend_points = []
    sorted_months = sorted(monthly_rows, key=lambda r: r["month"])
    for i, row in enumerate(sorted_months):
        is_current = i == len(sorted_months) - 1
        trend_points.append({
            "month": row["month"],
            "label": row["month"],
            "cost": round(float(row["cost"]), 2),
            "is_current": is_current,
            "is_partial": is_current,
        })

    return {
        "title": "Total Cost",
        "description": "Historical monthly spend with current MTD and projected month-end forecast.",
        "total_spend": round(total_spend, 2),
        "total_label": "Collected spend",
        "trend_points": trend_points,
        "forecast_amount": forecast_amount,
    }


def _build_collection_status(
    scan: ScanRun | None,
    counts: dict[str, Any],
) -> dict[str, Any] | None:
    if not scan:
        return None
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "start_date": scan.start_date.isoformat() if scan.start_date else None,
        "end_date": scan.end_date.isoformat() if scan.end_date else None,
        "region": scan.region,
        "account_id": scan.account_id,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "counts": counts,
    }


def _build_optimization_from_db(
    db: Session,
    latest_cost_scan: ScanRun | None,
) -> dict[str, Any]:
    completed = ("completed", "completed_with_errors")
    analysis_scan = (
        db.query(ScanRun)
        .filter(ScanRun.status.in_(completed))
        .filter(ScanRun.cost_threshold > 0)
        .order_by(ScanRun.id.desc())
        .first()
    )

    if not analysis_scan:
        findings_count = 0
        recommendations_count = 0
        last_scan_id = None
        last_scan_date = None
        status = "not_analyzed"
        message = (
            "Cost monitoring data is available. Run a cost analysis to "
            "identify optimization opportunities."
        )
    else:
        findings_count = (
            db.query(func.count(Finding.id))
            .filter(Finding.scan_run_id == analysis_scan.id)
            .scalar()
            or 0
        )
        recommendations_count = (
            db.query(func.count(Recommendation.id))
            .filter(Recommendation.scan_run_id == analysis_scan.id)
            .scalar()
            or 0
        )
        last_scan_id = analysis_scan.id
        last_scan_date = (
            analysis_scan.finished_at.isoformat()
            if analysis_scan.finished_at
            else analysis_scan.created_at.isoformat()
        )
        status = "analyzed" if findings_count or recommendations_count else "not_analyzed"
        message = (
            f"Cost analysis completed. {findings_count} findings and "
            f"{recommendations_count} recommendations identified."
        )

    findings_preview = []
    if analysis_scan:
        findings_rows = (
            db.query(Finding)
            .filter(Finding.scan_run_id == analysis_scan.id)
            .order_by(Finding.severity.desc())
            .limit(10)
            .all()
        )
        for f in findings_rows:
            findings_preview.append({
                "id": f.id,
                "resource_type": f.resource_type,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "analyzer": f.analyzer,
                "reason": f.reason,
            })

    recs_preview = []
    if analysis_scan:
        recs_rows = (
            db.query(Recommendation)
            .filter(Recommendation.scan_run_id == analysis_scan.id)
            .order_by(Recommendation.priority.desc())
            .limit(10)
            .all()
        )
        for r in recs_rows:
            recs_preview.append({
                "id": r.id,
                "finding_id": r.finding_id,
                "title": r.title,
                "action": r.action,
                "priority": r.priority,
                "status": r.status,
            })

    return {
        "status": status,
        "last_scan_id": last_scan_id,
        "last_scan_date": last_scan_date,
        "findings_count": findings_count,
        "recommendations_count": recommendations_count,
        "message": message,
        "findings_preview": findings_preview,
        "recommendations_preview": recs_preview,
    }


def _project_forecast_from_mtd(
    monthly_rows: list[dict],
    today: date | None = None,
) -> float | None:
    today = today or date.today()
    current_key = _month_key(today.year, today.month)
    by_month = {r["month"]: float(r["cost"]) for r in monthly_rows}
    mtd_amount = by_month.get(current_key, 0.0)
    days_elapsed = today.day
    days_in_month = monthrange(today.year, today.month)[1]
    if days_elapsed < 1:
        return None
    projected = mtd_amount * (days_in_month / days_elapsed)
    return round(projected, 2)


def _build_full_response(
    db: Session,
    today: date | None = None,
) -> dict[str, Any]:
    today = today or date.today()
    cost_scan = latest_scan_with_costs(db)

    if not cost_scan:
        return {
            "cost_available": False,
            "message": "No cost data collected yet. Run 'Refresh data' to collect Cost Explorer data.",
            "period_comparison": {
                "current_month": _build_period_stats(db, 0, _month_key(today.year, today.month), "Current month"),
                "three_months_ago": _build_period_stats(db, 0, _month_key(today.year, today.month), "3 months ago"),
                "six_months_ago": _build_period_stats(db, 0, _month_key(today.year, today.month), "6 months ago"),
            },
            "optimization": _build_optimization_from_db(db, None),
        }

    scan_id = cost_scan.id

    monthly_rows = get_monthly_totals(db, scan_id)
    service_by_month = get_service_costs_by_month(db, scan_id)
    region_by_month = get_region_costs_by_month(db, scan_id)
    service_region_rows = get_service_region_costs(db, scan_id)
    collection_counts = get_collection_counts(db, scan_id, None)

    period_months = _period_months_list(today, count=6)
    for pm in period_months:
        if not any(r["month"] == pm for r in monthly_rows):
            monthly_rows.append({"month": pm, "cost": 0.0})
    monthly_rows.sort(key=lambda r: r["month"])

    total_spend = sum(float(r["cost"]) for r in monthly_rows)

    service_costs = build_service_costs_with_changes(service_by_month, total_spend, limit=15)
    region_costs = build_region_costs_with_changes(region_by_month, total_spend, limit=10)
    service_changes = build_service_changes(service_costs, service_by_month, limit=8)
    service_monthly_matrix = build_service_monthly_matrix(service_by_month, period_months, limit=10)
    region_monthly_matrix = build_region_monthly_matrix(region_by_month, period_months, limit=8)
    service_region_matrix = build_service_region_matrix(service_region_rows, limit_services=8)
    concentration = build_concentration_stats(service_costs, region_costs, total_spend)
    cost_drivers = build_cost_drivers_from_services(service_costs, total_spend, limit=8)
    statistics = build_cost_statistics(monthly_rows, service_costs, service_changes, region_costs)
    previous_completed_month = build_previous_month_kpi(monthly_rows)
    three_month_total = build_three_month_total(monthly_rows)
    mtd = _build_mtd_from_monthly(monthly_rows, today)
    period_comparison = _build_period_comparison(db, scan_id, today)

    forecast_amount = _project_forecast_from_mtd(monthly_rows, today)
    hero = _build_hero(monthly_rows, total_spend, forecast_amount)

    completed_mom = None
    sorted_months = sorted(monthly_rows, key=lambda r: r["month"])
    if len(sorted_months) >= 2:
        cur = sorted_months[-1]
        prev = sorted_months[-2]
        cur_cost = float(cur["cost"])
        prev_cost = float(prev["cost"])
        change_pct = ((cur_cost - prev_cost) / prev_cost * 100) if prev_cost > 0 else None
        completed_mom = {
            "current_label": cur["month"],
            "previous_label": prev["month"],
            "current_cost": round(cur_cost, 2),
            "previous_cost": round(prev_cost, 2),
            "change_abs": round(cur_cost - prev_cost, 2),
            "change_pct": round(change_pct, 1) if change_pct is not None else None,
        }

    last3_period = None
    if three_month_total:
        last3_period = three_month_total
    elif len(sorted_months) >= 3:
        last3 = sorted_months[-3:]
        t = sum(float(r["cost"]) for r in last3)
        last3_period = {
            "months": 3,
            "total_spend": round(t, 2),
            "label": "Last 3 completed months",
        }

    data_freshness = {
        "cost_through": (
            max(r["month"] for r in monthly_rows if float(r["cost"]) > 0)
            if any(float(r["cost"]) > 0 for r in monthly_rows)
            else None
        ),
        "last_collection": (
            cost_scan.finished_at.isoformat()
            if cost_scan.finished_at
            else cost_scan.created_at.isoformat()
        ),
    }

    account = {
        "account_id": cost_scan.account_id,
        "account_id_masked": (
            f"****{cost_scan.account_id[-4:]}"
            if cost_scan.account_id and len(cost_scan.account_id) >= 4
            else None
        ),
        "display_name": (
            f"AWS Account {cost_scan.account_id[-4:]}"
            if cost_scan.account_id
            else None
        ),
        "connection_label": "Connected (database)",
        "region": cost_scan.region,
    }

    optimization = _build_optimization_from_db(db, cost_scan)
    collection_status = _build_collection_status(cost_scan, collection_counts)

    last_updated_dt = cost_scan.finished_at or cost_scan.created_at or datetime.utcnow()
    data_stale = False
    data_stale_message = None
    if last_updated_dt:
        age_days = (datetime.utcnow() - last_updated_dt.replace(tzinfo=None) if last_updated_dt.tzinfo else datetime.utcnow() - last_updated_dt).days
        if age_days > 60:
            data_stale = True
            data_stale_message = (
                f"Cost data is {age_days} days old. Click 'Refresh data' to update."
            )

    hero_trend = [
        {
            "month": p["month"],
            "start_date": f"{p['month']}-01",
            "amount": p["cost"],
            "estimated": p.get("is_partial", False),
            "currency": "USD",
        }
        for p in hero["trend_points"]
    ] if hero.get("trend_points") else []

    return {
        "cost_available": True,
        "period_comparison": period_comparison,
        "account": account,
        "hero": hero,
        "concentration": concentration,
        "collection_status": collection_status,
        "optimization": optimization,
        "data_freshness": data_freshness,
        "last_updated": last_updated_dt.isoformat() if last_updated_dt else None,
        "data_stale": data_stale,
        "data_stale_message": data_stale_message,
        "periods": {
            "current_mtd": {
                "spend": mtd["current"]["amount"],
                "period_start": mtd["current"]["start_date"],
                "period_end": mtd["current"]["end_date"],
                "period_label": (
                    f"{mtd['current']['start_date']} → {mtd['current']['end_date']}"
                ),
                "previous_mtd": mtd["previous"]["amount"],
                "change_vs_previous_mtd_abs": mtd["difference"],
                "change_vs_previous_mtd_pct": mtd["percentage_change"],
                "forecast": forecast_amount,
                "forecast_label": (
                    f"{_month_key(today.year, today.month)} projected"
                    if forecast_amount is not None
                    else None
                ),
                "status": "available",
                "label": "Current MTD",
            },
            "previous_completed_month": previous_completed_month,
            "last_3_completed_months": last3_period,
            "completed_month_mom": completed_mom,
            "trend": hero_trend,
            "cost_through": data_freshness["cost_through"],
        },
        "statistics": statistics,
        "cost_by_service": service_costs,
        "cost_by_region": region_costs,
        "service_changes": service_changes,
        "cost_drivers": cost_drivers,
        "forecast": {
            "month": _month_key(today.year, today.month),
            "forecast": forecast_amount,
            "currency": "USD",
        } if forecast_amount is not None else {
            "month": _month_key(today.year, today.month),
            "forecast": None,
            "currency": "USD",
        },
        "previous_completed_month": previous_completed_month,
        "mtd": mtd,
        "historical": {
            "start_date": f"{period_months[0]}-01",
            "end_date": cost_scan.end_date.isoformat() if cost_scan.end_date else f"{period_months[-1]}-01",
            "total_spend": statistics["total_spend"],
            "average_monthly_spend": statistics["average_monthly_spend"],
            "highest_month": statistics["highest_month"],
            "lowest_month": statistics["lowest_month"],
            "monthly_cost": hero_trend,
        },
        "services": {
            "count": statistics["services_with_spend"],
            "cost": service_costs,
            "monthly": service_by_month,
            "month_over_month": service_changes.get("increased", []) + service_changes.get("decreased", []) + service_changes.get("new", []),
        },
        "regions": {
            "count": statistics["regions_with_spend"],
            "cost": region_costs,
            "monthly": region_by_month,
        },
        "findings": optimization["findings_preview"],
        "recommendations": optimization["recommendations_preview"],
        "current_month": {
            "spend": mtd["current"]["amount"],
            "period_start": mtd["current"]["start_date"],
            "period_end": mtd["current"]["end_date"],
            "period_label": f"{mtd['current']['start_date']} → {mtd['current']['end_date']}",
            "previous_mtd": mtd["previous"]["amount"],
            "change_vs_previous_mtd_abs": mtd["difference"],
            "change_vs_previous_mtd_pct": mtd["percentage_change"],
            "forecast": forecast_amount,
            "forecast_label": f"{_month_key(today.year, today.month)} projected",
            "status": "available",
            "label": "Current MTD",
        },
        "previous_month": previous_completed_month,
        "three_month_total": three_month_total,
        "analysis_period": {
            "start_date": f"{period_months[0]}-01",
            "end_date": cost_scan.end_date.isoformat() if cost_scan.end_date else f"{period_months[-1]}-28",
            "months_count": len(period_months),
            "label": f"{period_months[0]} to {period_months[-1]}",
        },
        "spend_change": completed_mom,
        "service_costs": service_costs,
        "service_monthly_matrix": service_monthly_matrix,
        "region_costs": region_costs,
        "region_monthly_matrix": region_monthly_matrix,
        "service_region_matrix": service_region_matrix,
        "monthly_costs": hero_trend,
        "top_cost_drivers": cost_drivers,
    }


@router.get("")
def get_dashboard_root(db: Session = Depends(get_db)):
    return get_dashboard_overview(db)


@router.get("/overview")
def get_dashboard_overview(db: Session = Depends(get_db)):
    return _build_full_response(db, today=date.today())


@router.get("/monthly")
def get_dashboard_monthly(db: Session = Depends(get_db)):
    cost_scan = latest_scan_with_costs(db)
    if not cost_scan:
        return {"start_date": None, "end_date": None, "months": []}
    today = date.today()
    period_months = _period_months_list(today, count=6)
    monthly_rows = get_monthly_totals(db, cost_scan.id)
    return {
        "start_date": f"{period_months[0]}-01",
        "end_date": cost_scan.end_date.isoformat() if cost_scan.end_date else None,
        "months": [
            {
                "month": r["month"],
                "start_date": f"{r['month']}-01",
                "end_date": None,
                "amount": round(float(r["cost"]), 2),
                "estimated": False,
                "currency": "USD",
            }
            for r in sorted(monthly_rows, key=lambda x: x["month"])
        ],
    }


@router.get("/services")
def get_dashboard_services(db: Session = Depends(get_db)):
    cost_scan = latest_scan_with_costs(db)
    if not cost_scan:
        return {"start_date": None, "end_date": None, "cost": [], "monthly": [], "month_over_month": []}
    today = date.today()
    period_months = _period_months_list(today, count=6)
    service_by_month = get_service_costs_by_month(db, cost_scan.id)
    total = sum(float(r["cost"]) for r in service_by_month)
    service_costs = build_service_costs_with_changes(service_by_month, total, limit=15)
    changes = build_service_changes(service_costs, service_by_month, limit=8)
    return {
        "start_date": f"{period_months[0]}-01",
        "end_date": cost_scan.end_date.isoformat() if cost_scan.end_date else None,
        "cost": service_costs,
        "monthly": service_by_month,
        "month_over_month": changes,
    }


@router.get("/regions")
def get_dashboard_regions(db: Session = Depends(get_db)):
    cost_scan = latest_scan_with_costs(db)
    if not cost_scan:
        return {"start_date": None, "end_date": None, "cost": [], "monthly": []}
    today = date.today()
    period_months = _period_months_list(today, count=6)
    region_by_month = get_region_costs_by_month(db, cost_scan.id)
    total = sum(float(r["cost"]) for r in region_by_month)
    region_costs = build_region_costs_with_changes(region_by_month, total, limit=10)
    return {
        "start_date": f"{period_months[0]}-01",
        "end_date": cost_scan.end_date.isoformat() if cost_scan.end_date else None,
        "cost": region_costs,
        "monthly": region_by_month,
    }


@router.get("/forecast")
def get_dashboard_forecast(db: Session = Depends(get_db)):
    today = date.today()
    cost_scan = latest_scan_with_costs(db)
    if not cost_scan:
        return {
            "month": _month_key(today.year, today.month),
            "forecast": None,
            "currency": "USD",
        }
    monthly_rows = get_monthly_totals(db, cost_scan.id)
    forecast_amount = _project_forecast_from_mtd(monthly_rows, today)
    return {
        "month": _month_key(today.year, today.month),
        "forecast": forecast_amount,
        "currency": "USD",
    }


@router.get("/period-comparison")
def get_dashboard_period_comparison(db: Session = Depends(get_db)):
    cost_scan = latest_scan_with_costs(db)
    scan_id = cost_scan.id if cost_scan else 0
    return _build_period_comparison(db, scan_id, today=date.today())
