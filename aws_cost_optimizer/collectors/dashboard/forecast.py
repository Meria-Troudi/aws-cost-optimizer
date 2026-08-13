"""
AWS Cost Explorer forecast service.

Dashboard-only.

Forecast data is deliberately independent from optimization scans.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION


class DashboardForecastService:

    def __init__(self) -> None:
        self.client = get_client(
            "ce",
            CE_REGION,
        )

    def get_current_month_forecast(
        self,
        today: date | None = None,
    ) -> dict[str, Any]:

        today = today or date.today()

        month_start = today.replace(
            day=1
        )

        if today.month == 12:
            next_month = date(
                today.year + 1,
                1,
                1,
            )
        else:
            next_month = date(
                today.year,
                today.month + 1,
                1,
            )

        response = self.client.get_cost_forecast(
            TimePeriod={
                "Start": today.isoformat(),
                "End": next_month.isoformat(),
            },
            Metric="UNBLENDED_COST",
            Granularity="MONTHLY",
        )

        amount = float(
            response["Total"]["Amount"]
        )

        return {
            "month": month_start.isoformat()[:7],
            "forecast": round(
                amount,
                2,
            ),
            "currency": response[
                "Total"
            ].get(
                "Unit",
                "USD",
            ),
        }