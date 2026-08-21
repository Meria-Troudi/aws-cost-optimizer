"""Build FinOps cost overview aggregates from repository data."""

from __future__ import annotations

from backend.api.services.analytics_constants import (
    MIN_PRIOR_COST_FOR_PERCENTAGE as MIN_PRIOR_COST_FOR_PCT,
)


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
