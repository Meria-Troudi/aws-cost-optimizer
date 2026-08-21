"""
Live AWS Cost Explorer service.

Architecture
------------

The dashboard has two different cost concerns:

1. Live overview
   - current MTD
   - previous month
   - forecast
   - 6-month history
   - top services
   - top regions
   - top usage types
   - service movements

2. Cost Explorer investigation
   - region filter
   - specific date/month/custom range
   - breakdown by service / usage type / region
   - service drill-down into usage type + region

The overview intentionally uses MONTHLY Cost Explorer aggregation.
The explorer also uses MONTHLY aggregation.

This is deliberate:
the dashboard does not need daily line-item data for these views.

Completed ranges are cached indefinitely.
Open/current ranges use a short cache TTL.

Cost Explorer is queried lazily for service drill-downs.
"""

from __future__ import annotations

import hashlib
import json
import time
from calendar import monthrange
from datetime import date, datetime, timedelta, timezone
from typing import Any

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION
from backend.api.services.analytics_constants import (
    MIN_PRIOR_COST_FOR_PERCENTAGE,
)


# ---------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------

_QUERY_CACHE: dict[str, tuple[float | None, Any]] = {}

CACHE_TTL_SECONDS = 300


def _cache_key(*parts: Any) -> str:
    raw = json.dumps(
        parts,
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


def _cache_get(
    key: str,
) -> Any | None:

    entry = _QUERY_CACHE.get(key)

    if entry is None:
        return None

    expires_at, value = entry

    if (
        expires_at is not None
        and time.time() >= expires_at
    ):
        _QUERY_CACHE.pop(
            key,
            None,
        )
        return None

    return value


def _cache_set(
    key: str,
    value: Any,
    *,
    end: date,
    today: date,
) -> None:

    expires_at = (
        None
        if end <= today
        else time.time() + CACHE_TTL_SECONDS
    )

    _QUERY_CACHE[key] = (
        expires_at,
        value,
    )


# ---------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------


class DashboardService:

    CURRENCY = "USD"

    DEFAULT_HISTORY_MONTHS = 6

    MAX_HISTORY_MONTHS = 12

    SERVICE_CHANGE_LIMIT = 10

    DEFAULT_DIMENSION_LIMIT = 15

    MIN_CHANGE_AMOUNT = 1.0

    MIN_PRIOR_COST_FOR_PERCENTAGE = MIN_PRIOR_COST_FOR_PERCENTAGE

    MIN_VISIBLE_COST = 0.01

    PERIOD_TYPES = {
        "rolling",
        "current",
        "previous",
        "month",
        "custom",
    }

    DIMENSIONS = {
        "SERVICE",
        "REGION",
        "USAGE_TYPE",
    }

    def __init__(self) -> None:

        self.client = get_client(
            "ce",
            CE_REGION,
        )

    # ================================================================
    # DATE HELPERS
    # ================================================================

    @staticmethod
    def _month_start(
        value: date,
    ) -> date:

        return value.replace(
            day=1
        )

    @staticmethod
    def _next_month(
        value: date,
    ) -> date:

        if value.month == 12:
            return date(
                value.year + 1,
                1,
                1,
            )

        return date(
            value.year,
            value.month + 1,
            1,
        )

    @staticmethod
    def _previous_month(
        value: date,
    ) -> date:

        first = value.replace(
            day=1
        )

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

        cursor = today.replace(
            day=1
        )

        values = []

        for _ in range(count):
            values.append(
                cursor.strftime("%Y-%m")
            )
            cursor = DashboardService._previous_month(
                cursor
            )

        return list(
            reversed(values)
        )

    # ================================================================
    # COST EXPLORER CORE QUERY
    # ================================================================

    def _query(
        self,
        start: date,
        end: date,
        *,
        granularity: str = "MONTHLY",
        group_by: list[dict[str, str]] | None = None,
        region: str | None = None,
        service: str | None = None,
        force_refresh: bool = False,
    ) -> list[dict[str, Any]]:

        if start >= end:
            raise ValueError(
                f"Invalid Cost Explorer period: "
                f"{start.isoformat()} >= {end.isoformat()}"
            )

        cache_key = _cache_key(
            "cost-query",
            start.isoformat(),
            end.isoformat(),
            granularity,
            group_by,
            region,
            service,
        )

        if not force_refresh:
            cached = _cache_get(
                cache_key
            )

            if cached is not None:
                return cached

        params: dict[str, Any] = {
            "TimePeriod": {
                "Start": start.isoformat(),
                "End": end.isoformat(),
            },
            "Granularity": granularity,
            "Metrics": [
                "UnblendedCost"
            ],
        }

        if group_by:
            params["GroupBy"] = group_by

        filters: list[dict[str, Any]] = []

        if region:
            filters.append(
                {
                    "Dimensions": {
                        "Key": "REGION",
                        "Values": [
                            region
                        ],
                    }
                }
            )

        if service:
            filters.append(
                {
                    "Dimensions": {
                        "Key": "SERVICE",
                        "Values": [
                            service
                        ],
                    }
                }
            )

        if len(filters) == 1:

            params["Filter"] = filters[0]

        elif len(filters) > 1:

            params["Filter"] = {
                "And": filters
            }

        results_by_period: dict[
            str,
            dict[str, Any],
        ] = {}

        response = self.client.get_cost_and_usage(
            **params
        )

        self._merge_response(
            results_by_period,
            response,
        )

        while response.get(
            "NextPageToken"
        ):

            params["NextPageToken"] = (
                response[
                    "NextPageToken"
                ]
            )

            response = (
                self.client.get_cost_and_usage(
                    **params
                )
            )

            self._merge_response(
                results_by_period,
                response,
            )

        result = [
            results_by_period[key]
            for key in sorted(
                results_by_period
            )
        ]

        _cache_set(
            cache_key,
            result,
            end=end,
            today=date.today(),
        )

        return result

    @staticmethod
    def _merge_response(
        destination: dict[
            str,
            dict[str, Any],
        ],
        response: dict[str, Any],
    ) -> None:

        for block in response.get(
            "ResultsByTime",
            [],
        ):

            period = block.get(
                "TimePeriod",
                {},
            )

            start = period.get(
                "Start"
            )

            if not start:
                continue

            if start not in destination:

                destination[start] = {
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

            destination[start][
                "Groups"
            ].extend(
                block.get(
                    "Groups",
                    [],
                )
            )

    # ================================================================
    # SAFE AMOUNT
    # ================================================================

    @staticmethod
    def _amount(
        value: dict[str, Any],
    ) -> float:

        if not isinstance(
            value,
            dict,
        ):
            return 0.0

        metrics = value.get(
            "Metrics"
        )

        if isinstance(
            metrics,
            dict,
        ):

            cost = metrics.get(
                "UnblendedCost"
            )

            if isinstance(
                cost,
                dict,
            ):

                try:
                    return float(
                        cost.get(
                            "Amount",
                            0.0,
                        )
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    return 0.0

        cost = value.get(
            "UnblendedCost"
        )

        if isinstance(
            cost,
            dict,
        ):

            try:
                return float(
                    cost.get(
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

    # ================================================================
    # OVERVIEW
    # ================================================================

    def get_current_mtd(
        self,
        *,
        today: date | None = None,
        region: str | None = None,
    ) -> dict[str, Any]:

        today = today or date.today()

        start = self._month_start(
            today
        )

        end = today + timedelta(
            days=1
        )

        results = self._query(
            start,
            end,
            granularity="MONTHLY",
            region=region,
        )

        amount = sum(
            self._amount(
                item.get(
                    "Total",
                    {},
                )
            )
            for item in results
        )

        estimated = any(
            bool(
                item.get(
                    "Estimated",
                    False,
                )
            )
            for item in results
        )

        return {
            "month": start.strftime(
                "%Y-%m"
            ),
            "start_date": start.isoformat(),
            "end_date": today.isoformat(),
            "amount": round(
                amount,
                2,
            ),
            "currency": self.CURRENCY,
            "estimated": estimated,
        }

    # ================================================================
    # FORECAST
    # ================================================================

    def get_current_month_forecast(
        self,
        today: date | None = None,
        region: str | None = None,
        service: str | None = None,
        *,
        actual_mtd: float | None = None,
        force_refresh: bool = False,
    ) -> dict[str, Any]:

        from aws_cost_optimizer.collection.cost.cost_explorer import (
            get_cost_forecast,
        )

        today = today or date.today()

        month_start = self._month_start(
            today
        )

        next_month = self._next_month(
            today
        )

        if actual_mtd is None:

            actual = self.get_current_mtd(
                today=today,
                region=region,
            )

            actual_mtd = float(
                actual.get(
                    "amount",
                    0.0,
                )
            )

        else:

            actual_mtd = float(
                actual_mtd
            )

        forecast_start = today + timedelta(
            days=1
        )

        if forecast_start >= next_month:

            return {
                "month": month_start.strftime(
                    "%Y-%m"
                ),
                "forecast": round(
                    actual_mtd,
                    2,
                ),
                "actual_mtd": round(
                    actual_mtd,
                    2,
                ),
                "remaining_forecast": 0.0,
                "lower_bound": round(
                    actual_mtd,
                    2,
                ),
                "upper_bound": round(
                    actual_mtd,
                    2,
                ),
                "forecast_start": today.isoformat(),
                "forecast_end": (
                    next_month
                    - timedelta(
                        days=1
                    )
                ).isoformat(),
                "currency": self.CURRENCY,
                "source": "aws_cost_explorer",
                "status": "current_period_complete",
            }

        cache_key = _cache_key(
            "forecast",
            forecast_start.isoformat(),
            next_month.isoformat(),
            region,
            service,
        )

        forecast_data = None

        if not force_refresh:

            forecast_data = _cache_get(
                cache_key
            )

        if forecast_data is None:

            try:

                forecast_data = get_cost_forecast(
                    forecast_start.isoformat(),
                    next_month.isoformat(),
                    region=region,
                    service=service,
                    metric="UNBLENDED_COST",
                    prediction_interval_level=80,
                )

            except Exception as exc:

                return {
                    "month": month_start.strftime(
                        "%Y-%m"
                    ),
                    "forecast": None,
                    "actual_mtd": round(
                        actual_mtd,
                        2,
                    ),
                    "remaining_forecast": None,
                    "lower_bound": None,
                    "upper_bound": None,
                    "source": "aws_cost_explorer",
                    "status": "unavailable",
                    "error": str(exc),
                }

            _cache_set(
                cache_key,
                forecast_data,
                end=next_month,
                today=today,
            )

        remaining = float(
            forecast_data.get(
                "forecast",
                0.0,
            )
            or 0.0
        )

        projected = (
            actual_mtd
            + remaining
        )

        lower_bound = None
        upper_bound = None

        result_rows = forecast_data.get(
            "results",
            [],
        )

        if result_rows:

            lower_values = [
                row["lower_bound"]
                for row in result_rows
                if row.get(
                    "lower_bound"
                )
                is not None
            ]

            upper_values = [
                row["upper_bound"]
                for row in result_rows
                if row.get(
                    "upper_bound"
                )
                is not None
            ]

            if lower_values:
                lower_bound = (
                    actual_mtd
                    + sum(
                        lower_values
                    )
                )

            if upper_values:
                upper_bound = (
                    actual_mtd
                    + sum(
                        upper_values
                    )
                )

        return {
            "month": month_start.strftime(
                "%Y-%m"
            ),
            "forecast": round(
                projected,
                2,
            ),
            "actual_mtd": round(
                actual_mtd,
                2,
            ),
            "remaining_forecast": round(
                remaining,
                2,
            ),
            "lower_bound": (
                round(
                    lower_bound,
                    2,
                )
                if lower_bound is not None
                else None
            ),
            "upper_bound": (
                round(
                    upper_bound,
                    2,
                )
                if upper_bound is not None
                else None
            ),
            "forecast_start": forecast_start.isoformat(),
            "forecast_end": (
                next_month
                - timedelta(
                    days=1
                )
            ).isoformat(),
            "currency": self.CURRENCY,
            "source": "aws_cost_explorer",
            "metric": "UNBLENDED_COST",
            "prediction_interval_level": 80,
            "status": "available",
        }

    # ================================================================
    # GENERIC MONTHLY GROUPING
    # ================================================================

    def _monthly_grouped(
        self,
        start: date,
        end: date,
        *,
        dimension: str,
        region: str | None = None,
        service: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:

        dimension = dimension.upper()

        if dimension not in self.DIMENSIONS:
            raise ValueError(
                f"Unsupported dimension: {dimension}"
            )

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

        totals: dict[
            str,
            float,
        ] = {}

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

                amount = self._amount(
                    group
                )

                if amount < self.MIN_VISIBLE_COST:
                    continue

                name = keys[0]

                totals[name] = (
                    totals.get(
                        name,
                        0.0,
                    )
                    + amount
                )

        total = sum(
            totals.values()
        )

        rows = []

        for name, amount in sorted(
            totals.items(),
            key=lambda item: item[1],
            reverse=True,
        ):

            rows.append(
                {
                    "key": name,
                    "cost": round(
                        amount,
                        2,
                    ),
                    "share_pct": (
                        round(
                            amount
                            / total
                            * 100,
                            2,
                        )
                        if total
                        else 0.0
                    ),
                    "currency": self.CURRENCY,
                }
            )

        if limit is not None:
            rows = rows[:limit]

        for index, row in enumerate(
            rows,
            start=1,
        ):
            row["rank"] = index

        return rows

    # ================================================================
    # SERVICE / REGION / USAGE
    # ================================================================

    def _get_monthly_service_region_usage(
        self,
        start: date,
        end: date,
        *,
        region: str | None = None,
        force_refresh: bool = False,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:

        service_region = self._query(
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
                    "Key": "REGION",
                },
            ],
            region=region,
            force_refresh=force_refresh,
        )

        service_usage = self._query(
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
            region=region,
            force_refresh=force_refresh,
        )

        return (
            service_region,
            service_usage,
        )

    @staticmethod
    def _flatten_groups(
        results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        rows = []

        for block in results:

            month = (
                block
                .get(
                    "TimePeriod",
                    {},
                )
                .get(
                    "Start"
                )
            )

            if not month:
                continue

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

                amount = DashboardService._amount(
                    group
                )

                if (
                    amount
                    < DashboardService.MIN_VISIBLE_COST
                ):
                    continue

                rows.append(
                    {
                        "month": month[
                            :7
                        ],
                        "key1": keys[
                            0
                        ],
                        "key2": keys[
                            1
                        ],
                        "cost": amount,
                    }
                )

        return rows

    @staticmethod
    def _totals_between(
        rows: list[dict[str, Any]],
        start: date,
        end: date,
        key_name: str,
    ) -> dict[str, float]:

        start_key = start.strftime(
            "%Y-%m"
        )

        # `rows` are already at monthly granularity (one row per
        # calendar month), but `end` is a day-precision exclusive
        # bound that often falls *inside* its own month (e.g. "today
        # + 1 day" for the still-open current month). Truncating that
        # to "%Y-%m" and comparing with >= would wrongly exclude the
        # entire current month. Anchor the inclusive upper bound to
        # the last day actually covered by the window instead.
        end_key = (
            end - timedelta(days=1)
        ).strftime("%Y-%m")

        totals: dict[
            str,
            float,
        ] = {}

        for row in rows:

            month = row[
                "month"
            ]

            if month < start_key:
                continue

            if month > end_key:
                continue

            key = row[
                key_name
            ]

            totals[key] = (
                totals.get(
                    key,
                    0.0,
                )
                + row[
                    "cost"
                ]
            )

        return totals

    def _rank_comparison(
        self,
        current: dict[str, float],
        previous: dict[str, float],
        *,
        dimension: str,
        limit: int = 15,
    ) -> list[dict[str, Any]]:

        total_current = sum(
            current.values()
        )

        keys = (
            set(current)
            | set(previous)
        )

        rows = []

        for key in keys:

            current_cost = current.get(
                key,
                0.0,
            )

            previous_cost = previous.get(
                key,
                0.0,
            )

            change = (
                current_cost
                - previous_cost
            )

            change_pct = (
                change
                / previous_cost
                * 100
                if previous_cost
                >= self.MIN_PRIOR_COST_FOR_PERCENTAGE
                else None
            )

            rows.append(
                {
                    dimension: key,
                    "cost": round(
                        current_cost,
                        2,
                    ),
                    "current_cost": round(
                        current_cost,
                        2,
                    ),
                    "previous_cost": round(
                        previous_cost,
                        2,
                    ),
                    "change_amount": round(
                        change,
                        2,
                    ),
                    "change_pct": (
                        round(
                            change_pct,
                            2,
                        )
                        if change_pct
                        is not None
                        else None
                    ),
                    "share_pct": (
                        round(
                            current_cost
                            / total_current
                            * 100,
                            2,
                        )
                        if total_current
                        else 0.0
                    ),
                    "currency": self.CURRENCY,
                }
            )

        rows.sort(
            key=lambda row: row[
                "cost"
            ],
            reverse=True,
        )

        rows = rows[:limit]

        for index, row in enumerate(
            rows,
            start=1,
        ):
            row["rank"] = index

        return rows

    # ================================================================
    # OVERVIEW
    # ================================================================

    def get_overview(
        self,
        *,
        today: date | None = None,
        history_months: int = DEFAULT_HISTORY_MONTHS,
        region: str | None = None,
        latest_scan: dict[str, Any] | None = None,
        force_refresh: bool = False,
        **_: Any,
    ) -> dict[str, Any]:

        today = today or date.today()

        history_months = max(
            3,
            min(
                history_months,
                self.MAX_HISTORY_MONTHS,
            ),
        )

        current_start = self._month_start(
            today
        )

        current_end = today + timedelta(
            days=1
        )

        previous_start = self._previous_month(
            today
        )

        previous_end = current_start

        current_month_key = current_start.strftime(
            "%Y-%m"
        )

        previous_month_key = previous_start.strftime(
            "%Y-%m"
        )

        # Anchor the shared fetch window directly from
        # history_months instead of a separate get_monthly_cost()
        # call — the SERVICE+REGION dataset below already covers
        # every month this needs, so the monthly trend, current MTD,
        # and previous-month total are all derived from it rather
        # than three more Cost Explorer round trips.
        fetch_start_date = current_start

        for _ in range(
            history_months - 1
        ):
            fetch_start_date = self._previous_month(
                fetch_start_date
            )

        fetch_end = self._next_month(
            current_start
        )

        service_region_raw, service_usage_raw = (
            self._get_monthly_service_region_usage(
                fetch_start_date,
                fetch_end,
                region=region,
                force_refresh=force_refresh,
            )
        )

        sr_rows = self._flatten_groups(
            service_region_raw
        )

        su_rows = self._flatten_groups(
            service_usage_raw
        )

        monthly_totals: dict[
            str,
            float,
        ] = {}

        for row in sr_rows:

            monthly_totals[
                row["month"]
            ] = (
                monthly_totals.get(
                    row["month"],
                    0.0,
                )
                + row["cost"]
            )

        history = []

        cursor = fetch_start_date

        for _ in range(
            history_months
        ):

            month_key = cursor.strftime(
                "%Y-%m"
            )

            is_current = (
                month_key
                == current_month_key
            )

            month_end_exclusive = self._next_month(
                cursor
            )

            history.append(
                {
                    "month": month_key,
                    "start_date": cursor.isoformat(),
                    "end_date": (
                        today
                        if is_current
                        else month_end_exclusive
                        - timedelta(
                            days=1
                        )
                    ).isoformat(),
                    "amount": round(
                        monthly_totals.get(
                            month_key,
                            0.0,
                        ),
                        2,
                    ),
                    "estimated": is_current,
                    "currency": self.CURRENCY,
                }
            )

            cursor = self._next_month(
                cursor
            )

        current_total = round(
            monthly_totals.get(
                current_month_key,
                0.0,
            ),
            2,
        )

        previous_total = round(
            monthly_totals.get(
                previous_month_key,
                0.0,
            ),
            2,
        )

        current_mtd = {
            "month": current_month_key,
            "start_date": current_start.isoformat(),
            "end_date": today.isoformat(),
            "amount": current_total,
            "currency": self.CURRENCY,
            "estimated": True,
        }

        previous_month = {
            "month": previous_month_key,
            "start_date": previous_start.isoformat(),
            "end_date": (
                previous_end
                - timedelta(days=1)
            ).isoformat(),
            "amount": previous_total,
            "currency": self.CURRENCY,
        }

        difference = (
            current_total
            - previous_total
        )

        percentage_change = (
            difference
            / previous_total
            * 100
            if previous_total > 0
            else None
        )

        if difference > self.MIN_CHANGE_AMOUNT:
            direction = "increased"
        elif difference < -self.MIN_CHANGE_AMOUNT:
            direction = "decreased"
        else:
            direction = "stable"

        current_services = self._totals_between(
            sr_rows,
            current_start,
            current_end,
            "key1",
        )

        previous_services = self._totals_between(
            sr_rows,
            previous_start,
            previous_end,
            "key1",
        )

        services = self._rank_comparison(
            current_services,
            previous_services,
            dimension="service",
            limit=15,
        )

        current_regions = self._totals_between(
            sr_rows,
            current_start,
            current_end,
            "key2",
        )

        previous_regions = self._totals_between(
            sr_rows,
            previous_start,
            previous_end,
            "key2",
        )

        regions = self._rank_comparison(
            current_regions,
            previous_regions,
            dimension="region",
            limit=15,
        )

        current_usage = self._totals_between(
            su_rows,
            current_start,
            current_end,
            "key2",
        )

        usage_types = sorted(
            (
                {
                    "usage_type": key,
                    "cost": round(
                        value,
                        2,
                    ),
                    "share_pct": (
                        round(
                            value
                            / current_total
                            * 100,
                            2,
                        )
                        if current_total
                        else 0.0
                    ),
                    "currency": self.CURRENCY,
                }
                for key, value
                in current_usage.items()
                if value
                >= self.MIN_VISIBLE_COST
            ),
            key=lambda row: row[
                "cost"
            ],
            reverse=True,
        )[
            : self.DEFAULT_DIMENSION_LIMIT
        ]

        service_changes = [
            row
            for row in services
            if abs(
                row.get(
                    "change_amount",
                    0.0,
                )
            ) >= self.MIN_CHANGE_AMOUNT
        ]

        service_changes.sort(
            key=lambda row: abs(
                row[
                    "change_amount"
                ]
            ),
            reverse=True,
        )

        monthly_service_map: dict[
            str,
            dict[str, float],
        ] = {}

        monthly_region_map: dict[
            str,
            dict[str, float],
        ] = {}

        for row in sr_rows:

            monthly_service_map.setdefault(
                row["month"],
                {},
            )

            monthly_service_map[
                row["month"]
            ][
                row["key1"]
            ] = (
                monthly_service_map[
                    row["month"]
                ].get(
                    row["key1"],
                    0.0,
                )
                + row["cost"]
            )

            monthly_region_map.setdefault(
                row["month"],
                {},
            )

            monthly_region_map[
                row["month"]
            ][
                row["key2"]
            ] = (
                monthly_region_map[
                    row["month"]
                ].get(
                    row["key2"],
                    0.0,
                )
                + row["cost"]
            )

        monthly_service_cost = []

        for month_key in sorted(
            monthly_service_map
        ):

            monthly_service_cost.append(
                {
                    "month": month_key,
                    "services": [
                        {
                            "service": name,
                            "amount": round(
                                amount,
                                2,
                            ),
                        }
                        for name, amount
                        in sorted(
                            monthly_service_map[
                                month_key
                            ].items(),
                            key=lambda item: item[
                                1
                            ],
                            reverse=True,
                        )
                    ],
                }
            )

        monthly_region_cost = []

        for month_key in sorted(
            monthly_region_map
        ):

            monthly_region_cost.append(
                {
                    "month": month_key,
                    "regions": [
                        {
                            "region": name,
                            "amount": round(
                                amount,
                                2,
                            ),
                        }
                        for name, amount
                        in sorted(
                            monthly_region_map[
                                month_key
                            ].items(),
                            key=lambda item: item[
                                1
                            ],
                            reverse=True,
                        )
                    ],
                }
            )

        completed_months = [
            row
            for row in history
            if not row.get(
                "estimated",
                False,
            )
        ]

        completed_total = sum(
            float(
                row["amount"]
            )
            for row in completed_months
        )

        completed_average = (
            completed_total
            / len(
                completed_months
            )
            if completed_months
            else 0.0
        )

        forecast = self.get_current_month_forecast(
            today=today,
            region=region,
            actual_mtd=current_total,
            force_refresh=force_refresh,
        )

        return {
            "source": "aws_cost_explorer",
            "currency": self.CURRENCY,
            "current_date": today.isoformat(),

            "period": {
                "mode": "live",
                "label": "Live dashboard",
                "supports_forecast": True,
                "current_month": current_start.strftime(
                    "%Y-%m"
                ),
                "previous_month": previous_start.strftime(
                    "%Y-%m"
                ),
                "history_months": history_months,
            },

            "region_filter": region,

            "mtd": {
                "current": current_mtd,
                "previous": previous_month,
                "difference": round(
                    difference,
                    2,
                ),
                "percentage_change": (
                    round(
                        percentage_change,
                        2,
                    )
                    if percentage_change
                    is not None
                    else None
                ),
                "direction": direction,
            },

            "forecast": forecast,

            "monthly_cost": history,

            "monthly_service_cost": monthly_service_cost,

            "monthly_region_cost": monthly_region_cost,

            "services": services,

            "regions": regions,

            "usage_types": usage_types,

            "service_changes": service_changes[
                : self.SERVICE_CHANGE_LIMIT
            ],

            "latest_scan": latest_scan,

            "history": {
                "months": len(
                    history
                ),
                "completed_months": len(
                    completed_months
                ),
                "completed_total_spend": round(
                    completed_total,
                    2,
                ),
                "average_completed_monthly_spend": round(
                    completed_average,
                    2,
                ),
                "collected_total_spend": round(
                    sum(
                        float(
                            row["amount"]
                        )
                        for row in history
                    ),
                    2,
                ),
            },

            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

    # ================================================================
    # COST EXPLORER DATE SCOPE
    # ================================================================

    def resolve_explorer_scope(
        self,
        *,
        date_type: str = "current",
        month: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        today: date | None = None,
    ) -> dict[str, Any]:

        today = today or date.today()

        date_type = (
            date_type
            or "current"
        ).lower()

        if date_type == "current":

            start = self._month_start(
                today
            )

            end = today + timedelta(
                days=1
            )

            return {
                "type": "current",
                "start": start,
                "end": end,
                "label": "Current month",
            }

        if date_type == "previous":

            start = self._previous_month(
                today
            )

            end = self._month_start(
                today
            )

            return {
                "type": "previous",
                "start": start,
                "end": end,
                "label": start.strftime(
                    "%B %Y"
                ),
            }

        if date_type == "three_months":

            target = self._previous_month(
                self._previous_month(
                    today
                )
            )

            start = target
            end = self._next_month(
                target
            )

            return {
                "type": "three_months",
                "start": start,
                "end": end,
                "label": start.strftime(
                    "%B %Y"
                ),
            }

        if date_type == "six_months":

            target = self._previous_month(
                self._previous_month(
                    self._previous_month(
                        self._previous_month(
                            self._previous_month(
                                today
                            )
                        )
                    )
                )
            )

            start = target
            end = self._next_month(
                target
            )

            return {
                "type": "six_months",
                "start": start,
                "end": end,
                "label": start.strftime(
                    "%B %Y"
                ),
            }

        if date_type == "month":

            if not month:
                raise ValueError(
                    "month is required"
                )

            try:
                year, month_number = (
                    month.split("-")
                )

                target = date(
                    int(year),
                    int(month_number),
                    1,
                )

            except Exception as exc:
                raise ValueError(
                    "month must use YYYY-MM"
                ) from exc

            if target == self._month_start(
                today
            ):

                end = today + timedelta(
                    days=1
                )

            else:

                end = self._next_month(
                    target
                )

            return {
                "type": "month",
                "start": target,
                "end": end,
                "label": target.strftime(
                    "%B %Y"
                ),
            }

        if date_type == "custom":

            if not start_date or not end_date:
                raise ValueError(
                    "start_date and end_date are required"
                )

            if start_date > end_date:
                raise ValueError(
                    "start_date must not be after end_date"
                )

            return {
                "type": "custom",
                "start": start_date,
                "end": end_date + timedelta(
                    days=1
                ),
                "label": (
                    f"{start_date.isoformat()} "
                    f"→ "
                    f"{end_date.isoformat()}"
                ),
            }

        raise ValueError(
            f"Unknown date_type: {date_type}"
        )

    # ================================================================
    # COST EXPLORER MAIN
    # ================================================================

    def get_cost_explorer(
        self,
        *,
        dimension: str = "SERVICE",
        region: str | None = None,
        date_type: str = "current",
        month: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        limit: int = 12,
        today: date | None = None,
    ) -> dict[str, Any]:

        dimension = dimension.upper()

        if dimension not in self.DIMENSIONS:
            raise ValueError(
                "dimension must be SERVICE, REGION or USAGE_TYPE"
            )

        scope = self.resolve_explorer_scope(
            date_type=date_type,
            month=month,
            start_date=start_date,
            end_date=end_date,
            today=today,
        )

        rows = self._monthly_grouped(
            scope["start"],
            scope["end"],
            dimension=dimension,
            region=region,
            limit=limit,
        )

        total = sum(
            row["cost"]
            for row in rows
        )

        return {
            "source": "aws_cost_explorer",
            "currency": self.CURRENCY,
            "dimension": dimension.lower(),
            "region": region,
            "date": {
                "type": scope["type"],
                "start": scope[
                    "start"
                ].isoformat(),
                "end": (
                    scope["end"]
                    - timedelta(
                        days=1
                    )
                ).isoformat(),
                "label": scope[
                    "label"
                ],
            },
            "total_cost": round(
                total,
                2,
            ),
            "items": rows,
        }

    # ================================================================
    # SERVICE DRILL-DOWN
    # ================================================================

    def get_cost_explorer_service(
        self,
        *,
        service: str,
        region: str | None = None,
        date_type: str = "current",
        month: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        today: date | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:

        if not service:
            raise ValueError(
                "service is required"
            )

        scope = self.resolve_explorer_scope(
            date_type=date_type,
            month=month,
            start_date=start_date,
            end_date=end_date,
            today=today,
        )

        usage_results = self._query(
            scope["start"],
            scope["end"],
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
            region=region,
            service=service,
        )

        region_results = self._query(
            scope["start"],
            scope["end"],
            granularity="MONTHLY",
            group_by=[
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE",
                },
                {
                    "Type": "DIMENSION",
                    "Key": "REGION",
                },
            ],
            region=region,
            service=service,
        )

        usage_totals: dict[
            str,
            float,
        ] = {}

        region_totals: dict[
            str,
            float,
        ] = {}

        monthly_totals: dict[
            str,
            float,
        ] = {}

        for block in usage_results:

            period = block.get(
                "TimePeriod",
                {},
            )

            month_key = (
                period.get(
                    "Start"
                )
                or ""
            )[:7]

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

                amount = self._amount(
                    group
                )

                if amount < self.MIN_VISIBLE_COST:
                    continue

                usage = keys[1]

                usage_totals[
                    usage
                ] = (
                    usage_totals.get(
                        usage,
                        0.0,
                    )
                    + amount
                )

                monthly_totals[
                    month_key
                ] = (
                    monthly_totals.get(
                        month_key,
                        0.0,
                    )
                    + amount
                )

        for block in region_results:

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

                amount = self._amount(
                    group
                )

                if amount < self.MIN_VISIBLE_COST:
                    continue

                region_name = keys[
                    1
                ]

                region_totals[
                    region_name
                ] = (
                    region_totals.get(
                        region_name,
                        0.0,
                    )
                    + amount
                )

        usage_total = sum(
            usage_totals.values()
        )

        region_total = sum(
            region_totals.values()
        )

        usage_types = [
            {
                "key": key,
                "cost": round(
                    amount,
                    2,
                ),
                "share_pct": (
                    round(
                        amount
                        / usage_total
                        * 100,
                        2,
                    )
                    if usage_total
                    else 0.0
                ),
            }
            for key, amount
            in sorted(
                usage_totals.items(),
                key=lambda item: item[
                    1
                ],
                reverse=True,
            )[
                :limit
            ]
        ]

        regions = [
            {
                "key": key,
                "cost": round(
                    amount,
                    2,
                ),
                "share_pct": (
                    round(
                        amount
                        / region_total
                        * 100,
                        2,
                    )
                    if region_total
                    else 0.0
                ),
            }
            for key, amount
            in sorted(
                region_totals.items(),
                key=lambda item: item[
                    1
                ],
                reverse=True,
            )[
                :limit
            ]
        ]

        monthly = [
            {
                "month": month_key,
                "cost": round(
                    amount,
                    2,
                ),
            }
            for month_key, amount
            in sorted(
                monthly_totals.items()
            )
        ]

        return {
            "source": "aws_cost_explorer",
            "currency": self.CURRENCY,
            "service": service,
            "region": region,
            "date": {
                "type": scope["type"],
                "start": scope[
                    "start"
                ].isoformat(),
                "end": (
                    scope["end"]
                    - timedelta(
                        days=1
                    )
                ).isoformat(),
                "label": scope[
                    "label"
                ],
            },
            "total_cost": round(
                usage_total,
                2,
            ),
            "usage_types": usage_types,
            "regions": regions,
            "monthly": monthly,
        }