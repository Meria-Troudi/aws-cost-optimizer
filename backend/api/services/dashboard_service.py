"""
Live AWS Cost Explorer service for the dashboard.

"""

from __future__ import annotations

from calendar import monthrange
from datetime import date, datetime, timedelta, timezone
from typing import Any

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION


class DashboardService:

    CURRENCY = "USD"
    DEFAULT_HISTORY_MONTHS = 6
    DEFAULT_DIMENSION_LIMIT = 15
    SERVICE_CHANGE_LIMIT = 10
    MIN_CHANGE_AMOUNT = 1.0
    MIN_PRIOR_COST_FOR_PERCENTAGE = 5.0

    def __init__(self) -> None:
        self.client = get_client("ce", CE_REGION)

    @staticmethod
    def _month_start(value: date) -> date:
        return value.replace(day=1)

    @staticmethod
    def _next_month(value: date) -> date:
        if value.month == 12:
            return date(value.year + 1, 1, 1)

        return date(
            value.year,
            value.month + 1,
            1,
        )

    @staticmethod
    def _previous_month(value: date) -> date:
        first = value.replace(day=1)

        if first.month == 1:
            return date(
                first.year - 1,
                12,
                1,
            )

        return date(
            first.year,
            first.month - 1,
            1,
        )

    @staticmethod
    def _month_keys(
        today: date,
        count: int,
    ) -> list[str]:

        if count < 1:
            raise ValueError(
                "history_months must be greater than zero"
            )

        current = today.replace(day=1)

        months: list[str] = []
        cursor = current

        for _ in range(count):
            months.append(cursor.strftime("%Y-%m"))
            cursor = DashboardService._previous_month(cursor)

        months.reverse()
        return months


    def _query(
        self,
        start: date,
        end: date,
        *,
        granularity: str,
        group_by: list[dict[str, str]] | None = None,
        region: str | None = None,
        service: str | None = None,
    ) -> list[dict[str, Any]]:
        if start >= end:
            raise ValueError(
                f"Invalid Cost Explorer period: "
                f"{start.isoformat()} >= {end.isoformat()}"
            )

        params: dict[str, Any] = {
            "TimePeriod": {
                "Start": start.isoformat(),
                "End": end.isoformat(),
            },
            "Granularity": granularity,
            "Metrics": ["UnblendedCost"],
        }

        if group_by:
            params["GroupBy"] = group_by

        filters: list[dict[str, Any]] = []

        if region:
            filters.append(
                {
                    "Dimensions": {
                        "Key": "REGION",
                        "Values": [region],
                    }
                }
            )

        if service:
            filters.append(
                {
                    "Dimensions": {
                        "Key": "SERVICE",
                        "Values": [service],
                    }
                }
            )

        if len(filters) == 1:
            params["Filter"] = filters[0]
        elif len(filters) > 1:
            params["Filter"] = {
                "And": filters,
            }

        results_by_period: dict[str, dict[str, Any]] = {}

        response = self.client.get_cost_and_usage(**params)

        self._merge_response(
            results_by_period,
            response,
        )

        while response.get("NextPageToken"):
            params["NextPageToken"] = response["NextPageToken"]

            response = self.client.get_cost_and_usage(
                **params
            )

            self._merge_response(
                results_by_period,
                response,
            )

        return [
            results_by_period[key]
            for key in sorted(results_by_period)
        ]

    @staticmethod
    def _merge_response(
        destination: dict[str, dict[str, Any]],
        response: dict[str, Any],
    ) -> None:
        """
        Merge paginated Cost Explorer responses.

        Multiple pages can contain different groups for the same
        time period, so groups are accumulated.
        """

        for block in response.get(
            "ResultsByTime",
            [],
        ):
            period = block.get(
                "TimePeriod",
                {},
            )

            period_start = period.get("Start")

            if not period_start:
                continue

            if period_start not in destination:
                destination[period_start] = {
                    "TimePeriod": period,
                    "Estimated": block.get(
                        "Estimated",
                        False,
                    ),
                    "Groups": [],
                    "Total": block.get(
                        "Total",
                        {},
                    ),
                }

            destination[period_start]["Groups"].extend(
                block.get("Groups", [])
            )

    @staticmethod
    def _amount(value: dict[str, Any]) -> float:
        """
        Extract UnblendedCost from either:

        block["Total"]["UnblendedCost"]

        or:

        group["Metrics"]["UnblendedCost"]
        """

        if not isinstance(value, dict):
            return 0.0

        metrics = value.get("Metrics")

        if isinstance(metrics, dict):
            unblended = metrics.get("UnblendedCost")

            if isinstance(unblended, dict):
                try:
                    return float(
                        unblended.get(
                            "Amount",
                            0.0,
                        )
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    return 0.0

        unblended = value.get("UnblendedCost")

        if isinstance(unblended, dict):
            try:
                return float(
                    unblended.get(
                        "Amount",
                        0.0,
                    )
                )
            except (
                TypeError,
                ValueError,
            ):
                return 0.0

        return 0.0

    def get_current_mtd(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> dict[str, Any]:
        today = today or date.today()

        month_start = self._month_start(today)

        # Cost Explorer End is exclusive.
        # tomorrow includes today's complete daily bucket.
        end = today + timedelta(days=1)

        results = self._query(
            month_start,
            end,
            granularity="DAILY",
            region=region,
        )

        amount = sum(
            self._amount(
                block.get(
                    "Total",
                    {},
                )
            )
            for block in results
        )

        estimated = any(
            bool(
                block.get(
                    "Estimated",
                    False,
                )
            )
            for block in results
        )

        data_through = None

        if results:
            data_through = (
                results[-1]
                .get(
                    "TimePeriod",
                    {},
                )
                .get("End")
            )

        return {
            "month": month_start.strftime("%Y-%m"),
            "start_date": month_start.isoformat(),
            "end_date": today.isoformat(),
            "amount": round(amount, 2),
            "currency": self.CURRENCY,
            "calendar_days_elapsed": today.day,
            "data_points": len(results),
            "data_through": data_through,
            "estimated": estimated,
        }

    def get_previous_comparable_mtd(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> dict[str, Any]:
        today = today or date.today()

        previous_month = self._previous_month(today)

        days = min(
            today.day,
            monthrange(
                previous_month.year,
                previous_month.month,
            )[1],
        )

        start = previous_month

        # End is exclusive.
        end = start + timedelta(days=days)

        results = self._query(
            start,
            end,
            granularity="DAILY",
            region=region,
        )

        amount = sum(
            self._amount(
                block.get(
                    "Total",
                    {},
                )
            )
            for block in results
        )

        estimated = any(
            bool(
                block.get(
                    "Estimated",
                    False,
                )
            )
            for block in results
        )

        data_through = None

        if results:
            data_through = (
                results[-1]
                .get(
                    "TimePeriod",
                    {},
                )
                .get("End")
            )

        return {
            "month": previous_month.strftime("%Y-%m"),
            "start_date": start.isoformat(),
            "end_date": (
                end - timedelta(days=1)
            ).isoformat(),
            "days": days,
            "amount": round(amount, 2),
            "currency": self.CURRENCY,
            "data_points": len(results),
            "data_through": data_through,
            "estimated": estimated,
        }

    def get_mtd_comparison(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> dict[str, Any]:
        current = self.get_current_mtd(
            today=today,
            region=region,
        )

        previous = self.get_previous_comparable_mtd(
            today=today,
            region=region,
        )

        difference = (
            current["amount"]
            - previous["amount"]
        )

        previous_amount = previous["amount"]

        percentage = (
            difference
            / previous_amount
            * 100
            if previous_amount > 0
            else None
        )

        if difference > 0.01:
            direction = "increased"
        elif difference < -0.01:
            direction = "decreased"
        else:
            direction = "stable"

        return {
            "current": current,
            "previous": previous,
            "difference": round(
                difference,
                2,
            ),
            "percentage_change": (
                round(
                    percentage,
                    2,
                )
                if percentage is not None
                else None
            ),
            "direction": direction,
        }

    def get_current_month_forecast(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> dict[str, Any]:


        today = today or date.today()

        month_start = self._month_start(today)
        next_month = self._next_month(today)

        current = self.get_current_mtd(
            today=today,
            region=region,
        )

        actual_mtd = float(
            current.get(
                "amount",
                0.0,
            )
            or 0.0
        )

        forecast_start = today

        data_through = current.get(
            "data_through"
        )

        if data_through:
            try:
                data_through_date = date.fromisoformat(
                    str(data_through)[:10]
                )

                if data_through_date > forecast_start:
                    forecast_start = data_through_date

            except ValueError:
                pass

        if forecast_start < month_start:
            forecast_start = month_start

        if forecast_start >= next_month:
            return {
                "month": month_start.strftime("%Y-%m"),
                "forecast": round(
                    actual_mtd,
                    2,
                ),
                "actual_mtd": round(
                    actual_mtd,
                    2,
                ),
                "remaining_forecast": 0.0,
                "forecast_start": forecast_start.isoformat(),
                "forecast_end": (
                    next_month - timedelta(days=1)
                ).isoformat(),
                "currency": self.CURRENCY,
                "source": "aws_cost_explorer",
                "status": "current_period_complete",
            }

        params: dict[str, Any] = {
            "TimePeriod": {
                "Start": forecast_start.isoformat(),
                "End": next_month.isoformat(),
            },
            "Granularity": "MONTHLY",
            "Metric": "UNBLENDED_COST",
        }

        if region:
            params["Filter"] = {
                "Dimensions": {
                    "Key": "REGION",
                    "Values": [region],
                }
            }

        response = self.client.get_cost_forecast(
            **params
        )

        total = response.get(
            "Total",
            {},
        )

        try:
            remaining_forecast = float(
                total.get(
                    "Amount",
                    0.0,
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            remaining_forecast = 0.0

        projected_total = (
            actual_mtd
            + remaining_forecast
        )

        return {
            "month": month_start.strftime("%Y-%m"),
            "forecast": round(
                projected_total,
                2,
            ),
            "actual_mtd": round(
                actual_mtd,
                2,
            ),
            "remaining_forecast": round(
                remaining_forecast,
                2,
            ),
            "forecast_start": forecast_start.isoformat(),
            "forecast_end": (
                next_month - timedelta(days=1)
            ).isoformat(),
            "currency": total.get(
                "Unit",
                self.CURRENCY,
            ),
            "source": "aws_cost_explorer",
            "status": "available",
        }

    def get_monthly_cost(
        self,
        months: int = DEFAULT_HISTORY_MONTHS,
        today: date | None = None,
        region: str | None = None,
    ) -> list[dict[str, Any]]:
        if months < 1:
            raise ValueError(
                "months must be greater than zero"
            )

        today = today or date.today()

        current_month = self._month_start(today)

        start = current_month

        for _ in range(months - 1):
            start = self._previous_month(start)

        end = self._next_month(current_month)

        results = self._query(
            start,
            end,
            granularity="MONTHLY",
            region=region,
        )

        output: list[dict[str, Any]] = []

        for block in results:
            period = block.get(
                "TimePeriod",
                {},
            )

            period_start = period.get("Start")

            if not period_start:
                continue

            output.append(
                {
                    "month": period_start[:7],
                    "start_date": period_start,
                    "end_date": period.get("End"),
                    "amount": round(
                        self._amount(
                            block.get(
                                "Total",
                                {},
                            )
                        ),
                        2,
                    ),
                    "estimated": bool(
                        block.get(
                            "Estimated",
                            False,
                        )
                    ),
                    "currency": self.CURRENCY,
                }
            )

        return sorted(
            output,
            key=lambda item: item["month"],
        )

    def get_monthly_service_cost(
        self,
        months: int = DEFAULT_HISTORY_MONTHS,
        today: date | None = None,
        region: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return monthly cost broken down by service."""
        if months < 1:
            raise ValueError(
                "months must be greater than zero"
            )

        today = today or date.today()
        current_month = self._month_start(today)
        start = current_month

        for _ in range(months - 1):
            start = self._previous_month(start)

        end = self._next_month(current_month)

        results = self._query(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE",
                }
            ],
            region=region,
        )

        by_month: dict[str, dict[str, float]] = {}

        for block in results:
            period = block.get("TimePeriod", {})
            period_start = period.get("Start")

            if not period_start:
                continue

            month_key = period_start[:7]

            if month_key not in by_month:
                by_month[month_key] = {}

            for group in block.get("Groups", []):
                keys = group.get("Keys", [])

                if not keys:
                    continue

                service_name = keys[0]
                amount = self._amount(group)

                if amount <= 0:
                    continue

                by_month[month_key][service_name] = (
                    by_month[month_key].get(
                        service_name, 0.0
                    )
                    + amount
                )

        output: list[dict[str, Any]] = []

        for month_key in sorted(by_month):
            services_list = [
                {
                    "service": name,
                    "amount": round(amount, 2),
                }
                for name, amount in sorted(
                    by_month[month_key].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
            ]

            output.append(
                {
                    "month": month_key,
                    "services": services_list,
                }
            )

        return output

    def get_monthly_region_cost(
        self,
        months: int = DEFAULT_HISTORY_MONTHS,
        today: date | None = None,
        service: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return monthly cost broken down by region."""
        if months < 1:
            raise ValueError(
                "months must be greater than zero"
            )

        today = today or date.today()
        current_month = self._month_start(today)
        start = current_month

        for _ in range(months - 1):
            start = self._previous_month(start)

        end = self._next_month(current_month)

        results = self._query(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "REGION",
                }
            ],
            service=service,
        )

        by_month: dict[str, dict[str, float]] = {}

        for block in results:
            period = block.get("TimePeriod", {})
            period_start = period.get("Start")

            if not period_start:
                continue

            month_key = period_start[:7]

            if month_key not in by_month:
                by_month[month_key] = {}

            for group in block.get("Groups", []):
                keys = group.get("Keys", [])

                if not keys:
                    continue

                region_name = keys[0]
                amount = self._amount(group)

                if amount <= 0:
                    continue

                by_month[month_key][region_name] = (
                    by_month[month_key].get(
                        region_name, 0.0
                    )
                    + amount
                )

        output: list[dict[str, Any]] = []

        for month_key in sorted(by_month):
            regions_list = [
                {
                    "region": name,
                    "amount": round(amount, 2),
                }
                for name, amount in sorted(
                    by_month[month_key].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
            ]

            output.append(
                {
                    "month": month_key,
                    "regions": regions_list,
                }
            )

        return output

    def _get_grouped_cost(
        self,
        start: date,
        end: date,
        *,
        dimension: str,
        region: str | None = None,
        service: str | None = None,
        limit: int | None = DEFAULT_DIMENSION_LIMIT,
    ) -> list[dict[str, Any]]:
        results = self._query(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": dimension,
                }
            ],
            region=region,
            service=service,
        )

        totals: dict[str, float] = {}

        for block in results:
            for group in block.get(
                "Groups",
                [],
            ):
                keys = group.get(
                    "Keys",
                    [],
                )

                if not keys:
                    continue

                name = keys[0]

                amount = self._amount(group)

                if amount <= 0:
                    continue

                totals[name] = (
                    totals.get(
                        name,
                        0.0,
                    )
                    + amount
                )

        total = sum(totals.values())

        output: list[dict[str, Any]] = []

        for name, amount in sorted(
            totals.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            output.append(
                {
                    dimension.lower(): name,
                    "amount": round(
                        amount,
                        2,
                    ),
                    "share_pct": round(
                        amount / total * 100,
                        2,
                    )
                    if total
                    else 0.0,
                    "currency": self.CURRENCY,
                }
            )

        if limit is not None:
            output = output[:limit]

        for index, item in enumerate(
            output,
            start=1,
        ):
            item["rank"] = index

        return output

    def get_service_cost(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> list[dict[str, Any]]:
        today = today or date.today()

        return self._get_grouped_cost(
            self._month_start(today),
            today + timedelta(days=1),
            dimension="SERVICE",
            region=region,
        )

    def _get_grouped_mtd_comparison(
        self,
        *,
        dimension: str,
        today: date | None = None,
        region: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Compare current MTD vs previous MTD for a given dimension.

        The previous period uses the same number of elapsed days as the
        current month (e.g. Aug 01-17 vs Jul 01-17), which makes the
        month-over-month comparison valid for partial months.
        """

        today = today or date.today()

        current_start = self._month_start(today)
        current_end = today + timedelta(days=1)

        previous_start = self._previous_month(today)

        comparable_days = min(
            today.day,
            monthrange(
                previous_start.year,
                previous_start.month,
            )[1],
        )

        previous_end = (
            previous_start
            + timedelta(days=comparable_days)
        )

        current_results = self._query(
            current_start,
            current_end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": dimension,
                }
            ],
            region=region,
        )

        previous_results = self._query(
            previous_start,
            previous_end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": dimension,
                }
            ],
            region=region,
        )

        current_totals = self._group_results(
            current_results
        )

        previous_totals = self._group_results(
            previous_results
        )

        keys = (
            set(current_totals)
            | set(previous_totals)
        )

        total_current = sum(
            current_totals.values()
        )

        output: list[dict[str, Any]] = []

        for key in keys:
            current_amount = current_totals.get(
                key,
                0.0,
            )

            previous_amount = previous_totals.get(
                key,
                0.0,
            )

            change_amount = (
                current_amount
                - previous_amount
            )

            change_pct = (
                change_amount
                / previous_amount
                * 100
                if previous_amount >= self.MIN_PRIOR_COST_FOR_PERCENTAGE
                else None
            )

            output.append(
                {
                    dimension.lower():
                        key,
                    "current_cost": round(
                        current_amount,
                        2,
                    ),
                    "previous_cost": round(
                        previous_amount,
                        2,
                    ),
                    "change_amount": round(
                        change_amount,
                        2,
                    ),
                    "change_pct": (
                        round(
                            change_pct,
                            2,
                        )
                        if change_pct is not None
                        else None
                    ),
                    "share_pct": round(
                        current_amount
                        / total_current
                        * 100,
                        2,
                    )
                    if total_current
                    else 0.0,
                    "currency": self.CURRENCY,
                }
            )

        output.sort(
            key=lambda item: item["current_cost"],
            reverse=True,
        )

        return output

    def get_region_cost(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> list[dict[str, Any]]:
        today = today or date.today()

        return self._get_grouped_cost(
            self._month_start(today),
            today + timedelta(days=1),
            dimension="REGION",
            region=region,
        )

    def get_service_mtd(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._get_grouped_mtd_comparison(
            dimension="SERVICE",
            today=today,
            region=region,
        )

    def get_region_mtd(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._get_grouped_mtd_comparison(
            dimension="REGION",
            today=today,
            region=region,
        )

    def get_usage_type_cost(
        self,
        today: date | None = None,
        region: str | None = None,
        service: str | None = None,
    ) -> list[dict[str, Any]]:
        today = today or date.today()

        return self._get_grouped_cost(
            self._month_start(today),
            today + timedelta(days=1),
            dimension="USAGE_TYPE",
            region=region,
            service=service,
        )

    def get_service_changes(
        self,
        today: date | None = None,
        region: str | None = None,
    ) -> list[dict[str, Any]]:
       

        today = today or date.today()

        current_start = self._month_start(today)
        current_end = today + timedelta(days=1)

        previous_start = self._previous_month(today)

        comparable_days = min(
            today.day,
            monthrange(
                previous_start.year,
                previous_start.month,
            )[1],
        )

        previous_end = (
            previous_start
            + timedelta(days=comparable_days)
        )

        current_results = self._query(
            current_start,
            current_end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE",
                }
            ],
            region=region,
        )

        previous_results = self._query(
            previous_start,
            previous_end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE",
                }
            ],
            region=region,
        )

        current_totals = self._group_results(
            current_results
        )

        previous_totals = self._group_results(
            previous_results
        )

        services = (
            set(current_totals)
            | set(previous_totals)
        )

        output: list[dict[str, Any]] = []

        for service in services:
            current_amount = current_totals.get(
                service,
                0.0,
            )

            previous_amount = previous_totals.get(
                service,
                0.0,
            )

            difference = (
                current_amount
                - previous_amount
            )

            # Ignore tiny movements.
            if abs(difference) < self.MIN_CHANGE_AMOUNT:
                continue

            percentage = (
                difference
                / previous_amount
                * 100
                if previous_amount >= self.MIN_PRIOR_COST_FOR_PERCENTAGE
                else None
            )

            if difference > 0:
                trend = "increased"
            elif difference < 0:
                trend = "decreased"
            else:
                trend = "stable"

            output.append(
                {
                    "service": service,
                    "current_amount": round(
                        current_amount,
                        2,
                    ),
                    "previous_amount": round(
                        previous_amount,
                        2,
                    ),
                    "difference": round(
                        difference,
                        2,
                    ),
                    "percentage_change": (
                        round(
                            percentage,
                            2,
                        )
                        if percentage is not None
                        else None
                    ),
                    "trend": trend,
                }
            )

        output.sort(
            key=lambda item: abs(
                item["difference"]
            ),
            reverse=True,
        )

        return output[: self.SERVICE_CHANGE_LIMIT]

    @staticmethod
    def _group_results(
        results: list[dict[str, Any]],
    ) -> dict[str, float]:
        totals: dict[str, float] = {}

        for block in results:
            for group in block.get(
                "Groups",
                [],
            ):
                keys = group.get(
                    "Keys",
                    [],
                )

                if not keys:
                    continue

                service = keys[0]

                totals[service] = (
                    totals.get(
                        service,
                        0.0,
                    )
                    + DashboardService._amount(group)
                )

        return totals

    def get_overview(
        self,
        *,
        today: date | None = None,
        history_months: int = DEFAULT_HISTORY_MONTHS,
        region: str | None = None,
        latest_scan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        today = today or date.today()

        if history_months < 1:
            raise ValueError(
                "history_months must be greater than zero"
            )

        current_month = self._month_start(today)
        previous_month = self._previous_month(today)

        mtd = self.get_mtd_comparison(
            today=today,
            region=region,
        )

        forecast = self.get_current_month_forecast(
            today=today,
            region=region,
        )

        monthly = self.get_monthly_cost(
            months=history_months,
            today=today,
            region=region,
        )

        services = self.get_service_mtd(
            today=today,
            region=region,
        )

        regions = self.get_region_mtd(
            today=today,
            region=region,
        )

        usage_types = self.get_usage_type_cost(
            today=today,
            region=region,
        )

        service_changes = self.get_service_changes(
            today=today,
            region=region,
        )

        monthly_service_cost = (
            self.get_monthly_service_cost(
                months=history_months,
                today=today,
                region=region,
            )
        )

        monthly_region_cost = (
            self.get_monthly_region_cost(
                months=history_months,
                today=today,
            )
        )

        # --------------------------------------------------------------
        # Completed historical months
        # --------------------------------------------------------------
        #
        # The current month is normally estimated/partial.
        # Do not include it in "completed historical average".

        completed_months = [
            item
            for item in monthly
            if not item.get("estimated", False)
        ]

        completed_total = sum(
            float(item["amount"])
            for item in completed_months
        )

        completed_average = (
            completed_total / len(completed_months)
            if completed_months
            else 0.0
        )
        collected_history_total = sum(
            float(item["amount"])
            for item in monthly
        )

        return {
            "source": "aws_cost_explorer",
            "currency": self.CURRENCY,

            # Dynamic application date.
            "current_date": today.isoformat(),

            # Current/previous calendar period.
            "period": {
                "current_month": current_month.strftime("%Y-%m"),
                "current_start": current_month.isoformat(),
                "previous_month": previous_month.strftime("%Y-%m"),
                "previous_start": previous_month.isoformat(),
                "history_months": history_months,
            },

            "region_filter": region,

            "mtd": mtd,

            "forecast": forecast,

            "monthly_cost": monthly,

            "monthly_service_cost": monthly_service_cost,

            "monthly_region_cost": monthly_region_cost,

            "services": services,

            "regions": regions,

            "usage_types": usage_types,

            "service_changes": service_changes,

            "latest_scan": latest_scan,

            "history": {
                "months": len(monthly),
                "completed_months": len(completed_months),
                "completed_total_spend": round(
                    completed_total,
                    2,
                ),
                "average_completed_monthly_spend": round(
                    completed_average,
                    2,
                ),
                "collected_total_spend": round(
                    collected_history_total,
                    2,
                ),
            },

            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }
