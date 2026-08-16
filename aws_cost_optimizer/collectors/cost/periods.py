"""Helpers for Cost Explorer date ranges (exclusive end dates)."""

from __future__ import annotations

from datetime import date, timedelta


def inclusive_end(exclusive_end: date) -> date:
    """Cost Explorer ``End`` is exclusive; return the last included day."""
    return exclusive_end - timedelta(days=1)


def period_label(start: date, exclusive_end: date) -> str:
    if exclusive_end <= start:
        return f"{start.isoformat()} → {exclusive_end.isoformat()}"
    return (
        f"{start.isoformat()} → {inclusive_end(exclusive_end).isoformat()} "
        f"(inclusive · CE end {exclusive_end.isoformat()})"
    )


def month_keys_in_period(start: date, exclusive_end: date) -> list[str]:
    """Return YYYY-MM keys for each monthly bucket CE includes."""
    months: list[str] = []
    cursor = date(start.year, start.month, 1)
    while cursor < exclusive_end:
        months.append(f"{cursor.year:04d}-{cursor.month:02d}")
        if cursor.month == 12:
            cursor = date(cursor.year + 1, 1, 1)
        else:
            cursor = date(cursor.year, cursor.month + 1, 1)
    return months


def breakdown_from_ce_monthly(
    monthly_results: list[dict],
) -> list[dict[str, float | str]]:
    rows: list[dict[str, float | str]] = []
    for block in monthly_results:
        period = block.get("TimePeriod") or {}
        month = (period.get("Start") or "")[:7]
        amount = float(
            block.get("Total", {})
            .get("UnblendedCost", {})
            .get("Amount", 0.0)
        )
        if month:
            rows.append({"month": month, "cost": round(amount, 2)})
    return rows
