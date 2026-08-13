"""
Dashboard routes.

These use DashboardCostService and DashboardForecastService
from the dashboard folder to query Cost Explorer directly.

The dashboard is independent of Optimization Scans.
"""

from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter

from aws_cost_optimizer.collectors.dashboard.cost_service import (
    DashboardCostService,
)
from aws_cost_optimizer.collectors.dashboard.forecast import (
    DashboardForecastService,
)


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
)

# Default history period: 6 completed months before current month
DEFAULT_HISTORY_MONTHS = 6


def _history_period(
    today: date | None = None,
) -> tuple[date, date]:
    """
    Return (history_start, history_end) for the dashboard.

    history_start = first day of (DEFAULT_HISTORY_MONTHS) months ago
    history_end   = first day of current month (exclusive end for CE)

    Cost Explorer end date is exclusive. Passing the first day
    of the current month excludes any partial MTD data from the
    historical period.
    """

    today = today or date.today()
    history_end = today.replace(day=1)
    history_start = history_end - timedelta(
        days=DEFAULT_HISTORY_MONTHS * 31
    )
    history_start = history_start.replace(day=1)
    return history_start, history_end


def _build_legacy_compat(
    overview: dict,
    forecast: dict,
    previous_month: dict,
) -> dict:
    """
    Map the new dashboard structure to the legacy fields
    the frontend still expects.

    This keeps the React dashboard working while the
    backend queries Cost Explorer directly.
    """

    mtd = overview.get("mtd", {})
    current = mtd.get("current", {})
    previous = mtd.get("previous", {})
    historical = overview.get("historical", {})
    services = overview.get("services", {})
    regions = overview.get("regions", {})

    # periods structure
    periods = {
        "current_mtd": {
            "spend": current.get("amount"),
            "period_start": current.get("start_date"),
            "period_end": current.get("end_date"),
            "period_label": (
                f"{current.get('start_date', '')} → "
                f"{current.get('end_date', '')}"
            ),
            "previous_mtd": previous.get("amount"),
            "change_vs_previous_mtd_abs": mtd.get("difference"),
            "change_vs_previous_mtd_pct": mtd.get("percentage_change"),
            "forecast": forecast.get("forecast"),
            "forecast_label": (
                f"{forecast.get('month', '')} projected"
            ),
            "status": "available" if current.get("amount") is not None else "unavailable",
            "label": "Current MTD",
        },
        "previous_completed_month": {
            "month": previous_month.get("month"),
            "spend": previous_month.get("amount"),
            "label": (
                f"{previous_month.get('month', '')} completed"
            ),
        },
        "last_3_completed_months": None,
        "completed_month_mom": None,
        "trend": historical.get("monthly_cost", []),
        "cost_through": (
            historical.get("end_date")
            if historical.get("end_date")
            else None
        ),
    }

    # statistics
    statistics = {
        "total_spend": historical.get("total_spend"),
        "average_monthly_spend": historical.get(
            "average_monthly_spend"
        ),
        "highest_month": historical.get("highest_month"),
        "lowest_month": historical.get("lowest_month"),
        "services_with_spend": services.get("count"),
        "regions_with_spend": regions.get("count"),
    }

    # cost by service / region
    cost_by_service = services.get("cost", [])
    cost_by_region = regions.get("cost", [])

    # service changes
    service_changes = {
        "increased": [],
        "decreased": [],
        "new": [],
    }
    for change in services.get("month_over_month", []):
        trend = change.get("trend")
        if trend == "increased":
            service_changes["increased"].append(change)
        elif trend == "decreased":
            service_changes["decreased"].append(change)
        elif trend == "stable":
            service_changes["stable"] = service_changes.get(
                "stable", []
            )
            service_changes["stable"].append(change)

    # cost drivers
    cost_drivers = overview.get("cost_drivers", [])

    return {
        "cost_available": True,
        "periods": periods,
        "statistics": statistics,
        "cost_by_service": cost_by_service,
        "cost_by_region": cost_by_region,
        "service_changes": service_changes,
        "cost_drivers": cost_drivers,
        "forecast": forecast,
        "previous_completed_month": previous_month,
        "mtd": mtd,
        "historical": historical,
        "services": services,
        "regions": regions,
        "optimization": {
            "status": "not_analyzed",
            "last_scan_id": None,
            "last_scan_date": None,
            "findings_count": 0,
            "recommendations_count": 0,
            "message": (
                "Cost monitoring data is available. Run a cost analysis to "
                "identify optimization opportunities."
            ),
        },
        "data_freshness": {
            "cost_through": historical.get("end_date"),
            "last_collection": None,
        },
        "last_updated": None,
        "data_stale": False,
        "data_stale_message": None,
        "account": None,
        "hero": None,
        "concentration": None,
        "collection_coverage": None,
        "analysis_checklist": [],
        "findings": [],
        "recommendations": [],
        # Legacy aliases
        "current_month": periods["current_mtd"],
        "previous_month": periods["previous_completed_month"],
        "three_month_total": None,
        "analysis_period": None,
        "spend_change": None,
        "service_costs": cost_by_service,
        "service_monthly_matrix": {"months": [], "rows": []},
        "region_costs": cost_by_region,
        "monthly_costs": historical.get("monthly_cost", []),
        "top_cost_drivers": cost_drivers,
        "collection_status": None,
    }


# ------------------------------------------------------------------
# GET /api/dashboard  (root - overview for backward compatibility)
# ------------------------------------------------------------------


@router.get("")
def get_dashboard_root():
    """
    Root dashboard endpoint.

    Returns the same data as /overview for backward
    compatibility with the frontend.
    """

    return get_dashboard_overview()


# ------------------------------------------------------------------
# GET /api/dashboard/overview
# ------------------------------------------------------------------


@router.get("/overview")
def get_dashboard_overview():
    """
    Full dashboard overview:

    - MTD comparison
    - Forecast
    - Previous completed month
    - Monthly history
    - Service costs
    - Regional costs
    - Cost drivers
    """

    cost = DashboardCostService()
    forecast_service = DashboardForecastService()

    today = date.today()
    history_start, history_end = _history_period(today)

    overview = cost.get_dashboard_overview(
        history_start=history_start,
        history_end=history_end,
        today=today,
    )

    forecast = forecast_service.get_current_month_forecast(
        today=today,
    )

    previous_month = cost.get_previous_completed_month(
        today=today,
    )

    legacy = _build_legacy_compat(
        overview,
        forecast,
        previous_month,
    )

    return {
        **overview,
        "forecast": forecast,
        "previous_completed_month": previous_month,
        **legacy,
    }


# ------------------------------------------------------------------
# GET /api/dashboard/monthly
# ------------------------------------------------------------------


@router.get("/monthly")
def get_dashboard_monthly():
    """
    Monthly historical cost.

    Returns a list of monthly totals for the
    default history period.
    """

    service = DashboardCostService()
    history_start, history_end = _history_period()

    monthly = service.get_monthly_cost(
        history_start,
        history_end,
    )

    return {
        "start_date": history_start.isoformat(),
        "end_date": history_end.isoformat(),
        "months": monthly,
    }


# ------------------------------------------------------------------
# GET /api/dashboard/services
# ------------------------------------------------------------------


@router.get("/services")
def get_dashboard_services():
    """
    Service cost breakdown.

    Returns:
        - total cost grouped by service
        - service monthly history
        - month-over-month changes
    """

    service = DashboardCostService()
    history_start, history_end = _history_period()

    cost = service.get_service_cost(
        history_start,
        history_end,
    )

    monthly = service.get_service_monthly_cost(
        history_start,
        history_end,
    )

    changes = service.get_service_month_over_month(
        history_start,
        history_end,
    )

    return {
        "start_date": history_start.isoformat(),
        "end_date": history_end.isoformat(),
        "cost": cost,
        "monthly": monthly,
        "month_over_month": changes,
    }


# ------------------------------------------------------------------
# GET /api/dashboard/regions
# ------------------------------------------------------------------


@router.get("/regions")
def get_dashboard_regions():
    """
    Regional cost breakdown.

    Returns:
        - total cost grouped by region
        - regional monthly history
    """

    service = DashboardCostService()
    history_start, history_end = _history_period()

    cost = service.get_region_cost(
        history_start,
        history_end,
    )

    monthly = service.get_region_monthly_cost(
        history_start,
        history_end,
    )

    return {
        "start_date": history_start.isoformat(),
        "end_date": history_end.isoformat(),
        "cost": cost,
        "monthly": monthly,
    }


# ------------------------------------------------------------------
# GET /api/dashboard/forecast
# ------------------------------------------------------------------


@router.get("/forecast")
def get_dashboard_forecast():
    """
    Return the current month forecast from Cost Explorer.
    """

    service = DashboardForecastService()
    forecast = service.get_current_month_forecast()

    return forecast