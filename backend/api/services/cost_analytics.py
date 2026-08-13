"""Build FinOps cost overview aggregates from repository data."""

from __future__ import annotations

from typing import Any

# Ignore MoM % when prior period spend is below this (avoids divide-by-near-zero)
MIN_PRIOR_COST_FOR_PCT = 5.0


def _short_service(name: str) -> str:
    mapping = {
        "Amazon Relational Database Service": "RDS",
        "Amazon Elastic Compute Cloud - Compute": "EC2",
        "EC2 - Other": "EC2 — Other",
        "Amazon Virtual Private Cloud": "VPC",
        "Amazon Elastic Container Service for Kubernetes": "EKS",
        "Amazon Simple Storage Service": "S3",
    }
    return mapping.get(name, name.replace("Amazon ", "").strip())


def _safe_change_pct(change_amount: float, previous_cost: float) -> float | None:
    if previous_cost < MIN_PRIOR_COST_FOR_PCT:
        return None
    return round((change_amount / previous_cost) * 100, 1)


def build_service_costs_with_changes(
    service_by_month: list[dict],
    period_total: float,
    limit: int = 10,
) -> list[dict]:
    by_service: dict[str, dict[str, float]] = {}
    for row in service_by_month:
        svc = row["service"]
        by_service.setdefault(svc, {})[row["month"]] = row["cost"]

    results = []
    for service, months in by_service.items():
        sorted_months = sorted(months.keys())
        current_cost = months[sorted_months[-1]] if sorted_months else 0.0
        previous_cost = months[sorted_months[-2]] if len(sorted_months) >= 2 else None

        change_amount = None
        change_pct = None
        trend = "stable"
        if previous_cost is not None:
            change_amount = current_cost - previous_cost
            change_pct = _safe_change_pct(change_amount, previous_cost)
            if change_amount > 0.01:
                trend = "increased"
            elif change_amount < -0.01:
                trend = "decreased"

        period_cost = sum(months.values())
        results.append({
            "service": service,
            "service_short": _short_service(service),
            "cost": round(period_cost, 2),
            "current_cost": round(current_cost, 2),
            "previous_cost": round(previous_cost, 2) if previous_cost is not None else None,
            "change_amount": round(change_amount, 2) if change_amount is not None else None,
            "change_pct": change_pct,
            "share_pct": round(period_cost / period_total * 100, 1) if period_total else 0,
            "trend": trend,
        })

    results.sort(key=lambda r: r["cost"], reverse=True)
    for rank, item in enumerate(results[:limit], 1):
        item["rank"] = rank
    return results[:limit]


def build_service_changes(
    service_costs: list[dict],
    service_by_month: list[dict] | None = None,
    limit: int = 5,
) -> dict[str, list[dict]]:
    increased = [
        s for s in service_costs
        if s.get("change_amount") is not None and s["change_amount"] > 0.01
    ]
    decreased = [
        s for s in service_costs
        if s.get("change_amount") is not None and s["change_amount"] < -0.01
    ]

    increased.sort(key=lambda s: s["change_amount"], reverse=True)
    decreased.sort(key=lambda s: s["change_amount"])

    new_services: list[dict] = []
    if service_by_month:
        by_service: dict[str, dict[str, float]] = {}
        for row in service_by_month:
            by_service.setdefault(row["service"], {})[row["month"]] = row["cost"]
        for service, months in by_service.items():
            sorted_months = sorted(months.keys())
            if len(sorted_months) < 2:
                continue
            cur = months[sorted_months[-1]]
            prev = months[sorted_months[-2]]
            if prev < MIN_PRIOR_COST_FOR_PCT and cur >= MIN_PRIOR_COST_FOR_PCT:
                new_services.append({
                    "service": service,
                    "service_short": _short_service(service),
                    "cost": round(cur, 2),
                    "change_amount": round(cur, 2),
                    "change_pct": None,
                    "trend": "new",
                    "note": "New spend this period",
                })
        new_services.sort(key=lambda s: s["cost"], reverse=True)

    return {
        "increased": increased[:limit],
        "decreased": decreased[:limit],
        "new": new_services[:limit],
    }


def build_region_costs_with_changes(
    region_by_month: list[dict],
    period_total: float,
    limit: int = 8,
) -> list[dict]:
    by_region: dict[str, dict[str, float]] = {}
    for row in region_by_month:
        region = row["region"]
        by_region.setdefault(region, {})[row["month"]] = row["cost"]

    results = []
    for region, months in by_region.items():
        sorted_months = sorted(months.keys())
        current_cost = months[sorted_months[-1]] if sorted_months else 0.0
        previous_cost = months[sorted_months[-2]] if len(sorted_months) >= 2 else None

        change_amount = None
        change_pct = None
        if previous_cost is not None:
            change_amount = current_cost - previous_cost
            change_pct = _safe_change_pct(change_amount, previous_cost)

        period_cost = sum(months.values())
        results.append({
            "region": region,
            "cost": round(period_cost, 2),
            "current_cost": round(current_cost, 2),
            "previous_cost": round(previous_cost, 2) if previous_cost is not None else None,
            "change_amount": round(change_amount, 2) if change_amount is not None else None,
            "change_pct": change_pct,
            "share_pct": round(period_cost / period_total * 100, 1) if period_total else 0,
        })

    results.sort(key=lambda r: r["cost"], reverse=True)
    return results[:limit]


def build_service_monthly_matrix(
    service_by_month: list[dict],
    months: list[str],
    limit: int = 8,
) -> dict[str, Any]:
    by_service: dict[str, dict[str, float]] = {}
    for row in service_by_month:
        by_service.setdefault(row["service"], {})[row["month"]] = row["cost"]

    totals = {svc: sum(vals.values()) for svc, vals in by_service.items()}
    top_services = sorted(totals.keys(), key=lambda s: totals[s], reverse=True)[:limit]

    rows = []
    for service in top_services:
        month_costs = {
            m: round(by_service[service].get(m, 0), 2)
            for m in months
        }
        rows.append({
            "service": service,
            "service_short": _short_service(service),
            "months": month_costs,
            "total": round(totals[service], 2),
        })

    return {
        "months": months,
        "rows": rows,
    }


def build_region_monthly_matrix(
    region_by_month: list[dict],
    months: list[str],
    limit: int = 8,
) -> dict[str, Any]:
    by_region: dict[str, dict[str, float]] = {}
    for row in region_by_month:
        by_region.setdefault(row["region"], {})[row["month"]] = row["cost"]

    totals = {r: sum(vals.values()) for r, vals in by_region.items()}
    top_regions = sorted(totals.keys(), key=lambda r: totals[r], reverse=True)[:limit]

    rows = []
    for region in top_regions:
        month_costs = {m: round(by_region[region].get(m, 0), 2) for m in months}
        rows.append({
            "region": region,
            "months": month_costs,
            "total": round(totals[region], 2),
        })

    return {"months": months, "rows": rows}


def build_service_region_matrix(
    service_region_rows: list[dict],
    limit_services: int = 8,
) -> dict[str, Any]:
    by_service: dict[str, dict[str, float]] = {}
    for row in service_region_rows:
        by_service.setdefault(row["service"], {})[row["region"]] = row["cost"]

    totals = {s: sum(v.values()) for s, v in by_service.items()}
    top = sorted(totals.keys(), key=lambda s: totals[s], reverse=True)[:limit_services]
    all_regions = sorted({row["region"] for row in service_region_rows})

    rows = []
    for service in top:
        regions = {
            r: round(by_service[service].get(r, 0), 2)
            for r in all_regions
        }
        rows.append({
            "service": service,
            "service_short": _short_service(service),
            "regions": regions,
            "total": round(totals[service], 2),
        })

    return {"regions": all_regions, "rows": rows}


def build_concentration_stats(
    service_costs: list[dict],
    region_costs: list[dict],
    total_spend: float,
) -> dict[str, Any]:
    if total_spend <= 0:
        return {}

    sorted_services = sorted(service_costs, key=lambda s: s["cost"], reverse=True)
    top3 = sum(s["cost"] for s in sorted_services[:3])
    top5 = sum(s["cost"] for s in sorted_services[:5])
    top_region = region_costs[0] if region_costs else None

    return {
        "top_3_services_pct": round(top3 / total_spend * 100, 1),
        "top_5_services_pct": round(top5 / total_spend * 100, 1),
        "top_region": top_region["region"] if top_region else None,
        "top_region_pct": top_region["share_pct"] if top_region else None,
    }


def build_cost_drivers_from_services(
    service_costs: list[dict],
    total_spend: float,
    limit: int = 6,
) -> list[dict]:
    drivers = []
    for row in service_costs[:limit]:
        drivers.append({
            "service": row["service"],
            "service_short": row["service_short"],
            "cost": row["cost"],
            "share_pct": row["share_pct"],
            "change_pct": row.get("change_pct"),
            "change_amount": row.get("change_amount"),
        })
    return drivers


def build_cost_statistics(
    monthly_rows: list[dict],
    service_costs: list[dict],
    service_changes: dict[str, list[dict]],
    region_costs: list[dict],
) -> dict[str, Any]:
    costs = [float(r["cost"]) for r in monthly_rows]
    avg_monthly = sum(costs) / len(costs) if costs else None

    highest = max(monthly_rows, key=lambda r: r["cost"]) if monthly_rows else None
    lowest = min(monthly_rows, key=lambda r: r["cost"]) if monthly_rows else None

    largest_increase = service_changes["increased"][0] if service_changes["increased"] else None
    largest_decrease = service_changes["decreased"][0] if service_changes["decreased"] else None
    total_spend = sum(float(r["cost"]) for r in monthly_rows) if monthly_rows else 0

    return {
        "total_spend": round(total_spend, 2),
        "average_monthly_spend": round(avg_monthly, 2) if avg_monthly is not None else None,
        "highest_month": (
            {"month": highest["month"], "cost": round(float(highest["cost"]), 2)}
            if highest
            else None
        ),
        "lowest_month": (
            {"month": lowest["month"], "cost": round(float(lowest["cost"]), 2)}
            if lowest
            else None
        ),
        "services_with_spend": len(service_costs),
        "regions_with_spend": len(region_costs),
        "largest_service": service_costs[0] if service_costs else None,
        "largest_increase": largest_increase,
        "largest_decrease": largest_decrease,
    }


def build_previous_month_kpi(monthly_rows: list[dict]) -> dict[str, Any] | None:
    """Latest completed billing month present in collected data."""
    if not monthly_rows:
        return None

    sorted_rows = sorted(monthly_rows, key=lambda r: r["month"])
    latest = sorted_rows[-1]
    return {
        "month": latest["month"],
        "spend": round(float(latest["cost"]), 2),
        "label": "Latest collected month",
    }


def build_three_month_total(monthly_rows: list[dict]) -> dict[str, Any] | None:
    if not monthly_rows:
        return None

    sorted_rows = sorted(monthly_rows, key=lambda r: r["month"])
    recent = sorted_rows[-3:]
    total = sum(float(r["cost"]) for r in recent)
    return {
        "months": len(recent),
        "total_spend": round(total, 2),
        "label": f"Last {len(recent)} month{'s' if len(recent) != 1 else ''}",
    }
