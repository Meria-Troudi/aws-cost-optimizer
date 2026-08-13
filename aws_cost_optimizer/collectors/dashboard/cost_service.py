"""
Cost Explorer service for the Cost Dashboard.

"""

from __future__ import annotations

from calendar import monthrange
from datetime import date, timedelta
from typing import Any

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION


class DashboardCostService:
    """
    Read-only Cost Explorer service used by the dashboard.
    """

    def __init__(self) -> None:
        self.client = get_client("ce", CE_REGION)

    # ------------------------------------------------------------------
    # Generic Cost Explorer helpers
    # ------------------------------------------------------------------

    def _get_cost_and_usage(
        self,
        start: date,
        end: date,
        *,
        granularity: str = "MONTHLY",
        group_by: list[dict[str, str]] | None = None,
        filter_expression: dict[str, Any] | None = None,
        metrics: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute Cost Explorer GetCostAndUsage.

        Handles pagination and merges ResultsByTime blocks.
        """

        params: dict[str, Any] = {
            "TimePeriod": {
                "Start": start.isoformat(),
                "End": end.isoformat(),
            },
            "Granularity": granularity,
            "Metrics": metrics or ["UnblendedCost"],
        }

        if group_by:
            params["GroupBy"] = group_by

        if filter_expression:
            params["Filter"] = filter_expression

        results_by_time: dict[str, dict[str, Any]] = {}

        response = self.client.get_cost_and_usage(**params)

        self._merge_results(
            results_by_time,
            response,
        )

        while response.get("NextPageToken"):
            params["NextPageToken"] = response["NextPageToken"]

            response = self.client.get_cost_and_usage(
                **params
            )

            self._merge_results(
                results_by_time,
                response,
            )

        return list(results_by_time.values())

    @staticmethod
    def _merge_results(
        results_by_time: dict[str, dict[str, Any]],
        response: dict[str, Any],
    ) -> None:
        """
        Merge paginated Cost Explorer responses.
        """

        for block in response.get("ResultsByTime", []):
            period_start = block["TimePeriod"]["Start"]

            if period_start not in results_by_time:
                results_by_time[period_start] = {
                    "TimePeriod": block["TimePeriod"],
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

            results_by_time[period_start]["Groups"].extend(
                block.get("Groups", [])
            )
    def get_previous_completed_month(
        self,
        today: date | None = None,
    ) -> dict[str, Any]:
        today = today or date.today()
        current_month_start = today.replace(
            day=1
        )
        previous_month_end = (
            current_month_start
            - timedelta(days=1)
        )

        previous_month_start = (
            previous_month_end.replace(
                day=1
            )
        )

        results = self._get_cost_and_usage(
            previous_month_start,
            current_month_start,
            granularity="MONTHLY",
        )

        total = sum(
            self._amount(
                block.get("Total", {})
            )
            for block in results
        )

        return {
            "month": previous_month_start.isoformat()[
                :7
            ],
            "start_date": (
                previous_month_start.isoformat()
            ),
            "end_date": (
                previous_month_end.isoformat()
            ),
            "amount": round(
                total,
                2,
            ),
            "currency": "USD",
        }
    @staticmethod
    def _amount(
        block: dict[str, Any],
    ) -> float:
        """
        Safely extract UnblendedCost.

        Handles two Cost Explorer shapes:

            1. {"Metrics": {"UnblendedCost": {"Amount": "..."}}}
               (group objects)

            2. {"UnblendedCost": {"Amount": "...", "Unit": "USD"}}
               (Total objects)
        """

        try:
            if "Metrics" in block:
                return float(
                    block["Metrics"]["UnblendedCost"]["Amount"]
                )
            return float(
                block["UnblendedCost"]["Amount"]
            )
        except (
            KeyError,
            TypeError,
            ValueError,
        ):
            return 0.0

    # ------------------------------------------------------------------
    # Current month / MTD
    # ------------------------------------------------------------------

    def get_mtd(
        self,
        today: date | None = None,
    ) -> dict[str, Any]:
        """
        Return current month-to-date spend.

        Example:

            2026-08-01 -> 2026-08-13

        Cost Explorer's end date is exclusive.
        """

        today = today or date.today()

        month_start = today.replace(day=1)
        tomorrow = today + timedelta(days=1)

        results = self._get_cost_and_usage(
            month_start,
            tomorrow,
            granularity="DAILY",
        )

        total = sum(
            self._amount(
                block.get("Total", {})
            )
            for block in results
        )

        return {
            "start_date": month_start.isoformat(),
            "end_date": today.isoformat(),
            "days_elapsed": today.day,
            "amount": round(total, 2),
            "currency": "USD",
        }

    # ------------------------------------------------------------------
    # Previous month comparable MTD
    # ------------------------------------------------------------------

    def get_previous_month_comparable_mtd(
        self,
        today: date | None = None,
    ) -> dict[str, Any]:
        """
        Compare the same number of elapsed calendar days
        in the previous month.

        Example:

            Current:
                August 1 -> August 13

            Previous:
                July 1 -> July 13

        The end date sent to Cost Explorer is exclusive.
        """

        today = today or date.today()

        current_day = today.day

        previous_month_last_day = (
            today.replace(day=1) - timedelta(days=1)
        )

        previous_month_start = previous_month_last_day.replace(
            day=1
        )

        comparable_day = min(
            current_day,
            previous_month_last_day.day,
        )

        previous_end = previous_month_start + timedelta(
            days=comparable_day
        )

        results = self._get_cost_and_usage(
            previous_month_start,
            previous_end,
            granularity="DAILY",
        )

        total = 0.0

        for block in results:
            total += self._amount(
                block.get("Total", {})
            )

        return {
            "start_date": previous_month_start.isoformat(),
            "end_date": (
                previous_end - timedelta(days=1)
            ).isoformat(),
            "days": comparable_day,
            "amount": round(total, 2),
            "currency": "USD",
        }

    # ------------------------------------------------------------------
    # MTD comparison
    # ------------------------------------------------------------------

    def get_mtd_comparison(
        self,
        today: date | None = None,
    ) -> dict[str, Any]:
        """
        Return MTD and previous comparable MTD together.
        """

        current = self.get_mtd(today)
        previous = self.get_previous_month_comparable_mtd(
            today
        )

        current_amount = current["amount"]
        previous_amount = previous["amount"]

        difference = current_amount - previous_amount

        if previous_amount != 0:
            percentage = (
                difference / previous_amount
            ) * 100
        else:
            percentage = None

        if difference > 0:
            direction = "increased"
        elif difference < 0:
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
                round(percentage, 2)
                if percentage is not None
                else None
            ),
            "direction": direction,
        }

    # ------------------------------------------------------------------
    # Monthly historical cost
    # ------------------------------------------------------------------

    def get_monthly_cost(
        self,
        start: date,
        end: date,
    ) -> list[dict[str, Any]]:
        """
        Return monthly total cost.

        This is the main source for the historical
        cost graph.
        """

        results = self._get_cost_and_usage(
            start,
            end,
            granularity="MONTHLY",
        )

        output: list[dict[str, Any]] = []

        for block in sorted(
            results,
            key=lambda item: item["TimePeriod"]["Start"],
        ):
            output.append(
                {
                    "month": block[
                        "TimePeriod"
                    ]["Start"][:7],
                    "start_date": block[
                        "TimePeriod"
                    ]["Start"],
                    "end_date": block[
                        "TimePeriod"
                    ]["End"],
                    "amount": round(
                        self._amount(
                            block.get(
                                "Total",
                                {},
                            )
                        ),
                        2,
                    ),
                    "estimated": block.get(
                        "Estimated",
                        False,
                    ),
                    "currency": "USD",
                }
            )

        return output

    # ------------------------------------------------------------------
    # Service cost
    # ------------------------------------------------------------------

    def get_service_cost(
        self,
        start: date,
        end: date,
    ) -> list[dict[str, Any]]:
        """
        Return total cost grouped by AWS service.
        """

        results = self._get_cost_and_usage(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE",
                }
            ],
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

                service = keys[0]

                totals[service] = (
                    totals.get(service, 0.0)
                    + self._amount(group)
                )

        return self._rank_costs(
            totals,
            "service",
        )

    # ------------------------------------------------------------------
    # Service monthly history
    # ------------------------------------------------------------------

    def get_service_monthly_cost(
        self,
        start: date,
        end: date,
    ) -> list[dict[str, Any]]:
        """
        Return monthly service costs.

        Useful for:
            - service trend graph
            - MoM service changes
            - service breakdown
        """

        results = self._get_cost_and_usage(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE",
                }
            ],
        )

        output: list[dict[str, Any]] = []

        for block in results:
            month = block[
                "TimePeriod"
            ]["Start"][:7]

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

                output.append(
                    {
                        "month": month,
                        "service": keys[0],
                        "amount": round(
                            self._amount(group),
                            2,
                        ),
                    }
                )

        return output

    # ------------------------------------------------------------------
    # Regional cost
    # ------------------------------------------------------------------

    def get_region_cost(
        self,
        start: date,
        end: date,
    ) -> list[dict[str, Any]]:
        """
        Return total cost grouped by AWS region.
        """

        results = self._get_cost_and_usage(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "REGION",
                }
            ],
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

                region = keys[0]

                totals[region] = (
                    totals.get(region, 0.0)
                    + self._amount(group)
                )

        return self._rank_costs(
            totals,
            "region",
        )

    # ------------------------------------------------------------------
    # Regional monthly history
    # ------------------------------------------------------------------

    def get_region_monthly_cost(
        self,
        start: date,
        end: date,
    ) -> list[dict[str, Any]]:
        """
        Return monthly regional cost.
        """

        results = self._get_cost_and_usage(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "REGION",
                }
            ],
        )

        output: list[dict[str, Any]] = []

        for block in results:
            month = block[
                "TimePeriod"
            ]["Start"][:7]

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

                output.append(
                    {
                        "month": month,
                        "region": keys[0],
                        "amount": round(
                            self._amount(group),
                            2,
                        ),
                    }
                )

        return output

    # ------------------------------------------------------------------
    # Usage type
    # ------------------------------------------------------------------

    def get_usage_type_cost(
        self,
        start: date,
        end: date,
    ) -> list[dict[str, Any]]:
        """
        Return cost grouped by usage type.
        """

        results = self._get_cost_and_usage(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "USAGE_TYPE",
                }
            ],
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

                usage_type = keys[0]

                totals[usage_type] = (
                    totals.get(
                        usage_type,
                        0.0,
                    )
                    + self._amount(group)
                )

        return self._rank_costs(
            totals,
            "usage_type",
        )

    # ------------------------------------------------------------------
    # Service + usage type
    # ------------------------------------------------------------------

    def get_service_usage_type_cost(
        self,
        start: date,
        end: date,
    ) -> list[dict[str, Any]]:
        """
        Return:

            service
                usage type
                    cost

        This is useful for identifying cost drivers.
        """

        results = self._get_cost_and_usage(
            start,
            end,
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE",
                },
                {
                    "Type": "DIMENSION",
                    "Key": "USAGE_TYPE",
                },
            ],
        )

        output: list[dict[str, Any]] = []

        for block in results:
            month = block[
                "TimePeriod"
            ]["Start"][:7]

            for group in block.get(
                "Groups",
                [],
            ):
                keys = group.get(
                    "Keys",
                    [],
                )

                if len(keys) < 2:
                    continue

                output.append(
                    {
                        "month": month,
                        "service": keys[0],
                        "usage_type": keys[1],
                        "amount": round(
                            self._amount(group),
                            2,
                        ),
                    }
                )

        return output

    # ------------------------------------------------------------------
    # Number of services
    # ------------------------------------------------------------------

    def get_service_count(
        self,
        start: date,
        end: date,
    ) -> int:
        """
        Number of services with positive cost.
        """

        services = self.get_service_cost(
            start,
            end,
        )

        return len(
            [
                item
                for item in services
                if item["amount"] > 0
            ]
        )

    # ------------------------------------------------------------------
    # Number of regions
    # ------------------------------------------------------------------

    def get_region_count(
        self,
        start: date,
        end: date,
    ) -> int:
        """
        Number of regions with positive cost.
        """

        regions = self.get_region_cost(
            start,
            end,
        )

        return len(
            [
                item
                for item in regions
                if item["amount"] > 0
            ]
        )

    # ------------------------------------------------------------------
    # Average / highest / lowest
    # ------------------------------------------------------------------

    def get_monthly_statistics(
        self,
        start: date,
        end: date,
    ) -> dict[str, Any]:
        """
        Calculate:

            - total spend
            - average monthly spend
            - highest month
            - lowest month
        """

        months = self.get_monthly_cost(
            start,
            end,
        )

        if not months:
            return {
                "total": 0.0,
                "average": 0.0,
                "highest": None,
                "lowest": None,
                "months": [],
            }

        total = sum(
            item["amount"]
            for item in months
        )

        highest = max(
            months,
            key=lambda item: item["amount"],
        )

        lowest = min(
            months,
            key=lambda item: item["amount"],
        )

        return {
            "total": round(total, 2),
            "average": round(
                total / len(months),
                2,
            ),
            "highest": highest,
            "lowest": lowest,
            "months": months,
        }

    # ------------------------------------------------------------------
    # Month-over-month service changes
    # ------------------------------------------------------------------

    def get_service_month_over_month(
        self,
        start: date,
        end: date,
    ) -> list[dict[str, Any]]:
        """
        Compare each service against its previous month.
        """

        history = self.get_service_monthly_cost(
            start,
            end,
        )

        monthly: dict[
            str,
            dict[str, float],
        ] = {}

        for item in history:
            month = item["month"]
            service = item["service"]

            monthly.setdefault(
                month,
                {},
            )

            monthly[month][service] = item[
                "amount"
            ]

        months = sorted(monthly.keys())

        if len(months) < 2:
            return []

        current_month = months[-1]
        previous_month = months[-2]

        current = monthly[current_month]
        previous = monthly[previous_month]

        services = set(
            current.keys()
        ) | set(
            previous.keys()
        )

        output: list[dict[str, Any]] = []

        for service in services:
            current_amount = current.get(
                service,
                0.0,
            )

            previous_amount = previous.get(
                service,
                0.0,
            )

            difference = (
                current_amount
                - previous_amount
            )

            if previous_amount != 0:
                percentage = (
                    difference
                    / previous_amount
                ) * 100
            else:
                percentage = None

            if difference > 0:
                trend = "increased"
            elif difference < 0:
                trend = "decreased"
            else:
                trend = "stable"

            output.append(
                {
                    "service": service,
                    "current_month": current_month,
                    "previous_month": previous_month,
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

        return output

    # ------------------------------------------------------------------
    # Complete dashboard overview
    # ------------------------------------------------------------------

    def get_dashboard_overview(
        self,
        history_start: date,
        history_end: date,
        today: date | None = None,
    ) -> dict[str, Any]:
        """
        Build the dashboard overview.

        `history_start` and `history_end` belong exclusively
        to the dashboard.

        They have no relationship to an optimization ScanRun.
        """

        monthly_statistics = (
            self.get_monthly_statistics(
                history_start,
                history_end,
            )
        )

        services = self.get_service_cost(
            history_start,
            history_end,
        )

        regions = self.get_region_cost(
            history_start,
            history_end,
        )

        service_history = (
            self.get_service_monthly_cost(
                history_start,
                history_end,
            )
        )

        region_history = (
            self.get_region_monthly_cost(
                history_start,
                history_end,
            )
        )

        service_changes = (
            self.get_service_month_over_month(
                history_start,
                history_end,
            )
        )

        usage_types = (
            self.get_service_usage_type_cost(
                history_start,
                history_end,
            )
        )

        mtd = self.get_mtd_comparison(
            today=today,
        )

        return {
            "mtd": mtd,
            "historical": {
                "start_date": history_start.isoformat(),
                "end_date": history_end.isoformat(),
                "total_spend": monthly_statistics[
                    "total"
                ],
                "average_monthly_spend": (
                    monthly_statistics[
                        "average"
                    ]
                ),
                "highest_month": (
                    monthly_statistics[
                        "highest"
                    ]
                ),
                "lowest_month": (
                    monthly_statistics[
                        "lowest"
                    ]
                ),
                "monthly_cost": (
                    monthly_statistics[
                        "months"
                    ]
                ),
            },
            "services": {
                "count": len(
                    [
                        item
                        for item in services
                        if item["amount"] > 0
                    ]
                ),
                "cost": services,
                "monthly": service_history,
                "month_over_month": service_changes,
            },
            "regions": {
                "count": len(
                    [
                        item
                        for item in regions
                        if item["amount"] > 0
                    ]
                ),
                "cost": regions,
                "monthly": region_history,
            },
            "cost_drivers": usage_types,
        }

    # ------------------------------------------------------------------
    # Ranking
    # ------------------------------------------------------------------

    @staticmethod
    def _rank_costs(
        totals: dict[str, float],
        field_name: str,
    ) -> list[dict[str, Any]]:
        """
        Convert cost dictionary to ranked records.
        """

        total = sum(
            amount
            for amount in totals.values()
            if amount > 0
        )

        output: list[dict[str, Any]] = []

        for name, amount in totals.items():
            if amount <= 0:
                continue

            share = (
                amount / total * 100
                if total
                else 0.0
            )

            output.append(
                {
                    field_name: name,
                    "amount": round(
                        amount,
                        2,
                    ),
                    "share": round(
                        share,
                        2,
                    ),
                    "currency": "USD",
                }
            )

        output.sort(
            key=lambda item: item["amount"],
            reverse=True,
        )

        for index, item in enumerate(
            output,
            start=1,
        ):
            item["rank"] = index

        return output