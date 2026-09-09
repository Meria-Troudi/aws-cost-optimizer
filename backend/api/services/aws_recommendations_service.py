"""
Live AWS-native cost recommendations.

Sources
-------
1. AWS Cost Explorer Savings Plans purchase recommendations
2. AWS Cost Explorer Reserved Instance purchase recommendations
3. AWS Cost Explorer EC2 rightsizing recommendations
4. AWS Compute Optimizer EC2 instance recommendations

Design
------
This service is read-only.

It does NOT:
- create Savings Plans
- purchase Reserved Instances
- resize EC2 instances
- terminate instances
- modify Compute Optimizer preferences
- calculate its own savings model
- replace the application's deterministic analyzer/recommendation engine

Each AWS recommendation engine is queried independently.

A failure in one engine does not invalidate the others.

Important
---------
Savings opportunities from different AWS engines can overlap.

Therefore:
    total_estimated_monthly_savings

is NOT calculated by summing all engines together.

Instead, totals are exposed per engine.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION
from backend.api.services.dashboard_service import (
    _cache_get,
    _cache_key,
    _cache_set,
)


RESERVATION_SERVICES = [
    (
        "Amazon Relational Database Service",
        "Amazon RDS",
    ),
    (
        "Amazon Redshift",
        "Amazon Redshift",
    ),
    (
        "Amazon ElastiCache",
        "Amazon ElastiCache",
    ),
    (
        "Amazon OpenSearch Service",
        "Amazon OpenSearch Service",
    ),
]

SAVINGS_PLANS_TYPES = [
    "COMPUTE_SP",
    "SAGEMAKER_SP",
]


class AwsRecommendationsService:

    CURRENCY = "USD"

    CACHE_KEY = "aws-native-recommendations"

    COMPUTE_OPTIMIZER_PAGE_SIZE = 1000

    def __init__(self) -> None:
        self.client = get_client(
            "ce",
            CE_REGION,
        )

        self.compute_optimizer = get_client(
            "compute-optimizer",
            CE_REGION,
        )

    # ================================================================
    # GENERIC HELPERS
    # ================================================================

    @staticmethod
    def _float(
        value: Any,
        default: float | None = 0.0,
    ) -> float | None:

        if isinstance(value, bool):
            return default

        try:
            return float(value)

        except (
            TypeError,
            ValueError,
        ):
            return default

    @staticmethod
    def _safe_int(
        value: Any,
        default: int = 0,
    ) -> int:

        if isinstance(value, bool):
            return default

        try:
            return int(value)

        except (
            TypeError,
            ValueError,
        ):
            return default

    @staticmethod
    def _money_value(
        value: Any,
    ) -> float | None:

        if not isinstance(value, dict):
            return None

        return AwsRecommendationsService._float(
            value.get("value"),
            None,
        )

    @staticmethod
    def _money_currency(
        value: Any,
        default: str = "USD",
    ) -> str:

        if not isinstance(value, dict):
            return default

        currency = value.get("currency")

        return (
            str(currency)
            if currency
            else default
        )

    @staticmethod
    def _sum_savings(
        rows: list[dict[str, Any]],
        field: str = "estimated_monthly_savings",
    ) -> float:

        total = 0.0

        for row in rows:

            value = AwsRecommendationsService._float(
                row.get(field),
                None,
            )

            if value is not None and value > 0:
                total += value

        return round(
            total,
            2,
        )

    @staticmethod
    def _error_text(
        exc: Exception,
    ) -> str:

        response = getattr(
            exc,
            "response",
            None,
        )

        if isinstance(
            response,
            dict,
        ):

            error = response.get(
                "Error",
                {},
            )

            if isinstance(
                error,
                dict,
            ):

                code = error.get(
                    "Code"
                )

                message = error.get(
                    "Message"
                )

                if code and message:
                    return f"{code}: {message}"

                if code:
                    return str(code)

        return str(exc)

    # ================================================================
    # SAVINGS PLANS
    # ================================================================

    def _savings_plans(
        self,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:

        results: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        for sp_type in SAVINGS_PLANS_TYPES:

            try:

                response = (
                    self.client
                    .get_savings_plans_purchase_recommendation(
                        LookbackPeriodInDays="THIRTY_DAYS",
                        TermInYears="ONE_YEAR",
                        PaymentOption="NO_UPFRONT",
                        SavingsPlansType=sp_type,
                    )
                )

            except Exception as exc:

                errors.append(
                    {
                        "engine": "savings_plans",
                        "type": sp_type,
                        "error": self._error_text(exc),
                    }
                )

                continue

            recommendation = (
                response.get(
                    "SavingsPlansPurchaseRecommendation",
                    {},
                )
                or {}
            )

            summary = (
                recommendation.get(
                    "SavingsPlansPurchaseRecommendationSummary",
                    {},
                )
                or {}
            )

            savings = self._float(
                summary.get(
                    "EstimatedMonthlySavingsAmount"
                ),
                None,
            )

            if savings is None or savings <= 0:
                continue

            results.append(
                {
                    "plan_type": sp_type,

                    "hourly_commitment": self._float(
                        summary.get(
                            "EstimatedHourlyCommitment"
                        ),
                        None,
                    ),

                    "estimated_monthly_savings": round(
                        savings,
                        2,
                    ),

                    "estimated_savings_pct": self._float(
                        summary.get(
                            "EstimatedSavingsPercentage"
                        ),
                        None,
                    ),

                    "currency": self.CURRENCY,

                    "lookback_period_days": 30,

                    "term_years": 1,

                    "payment_option": "NO_UPFRONT",

                    "source": "AWS Cost Explorer",
                }
            )

        results.sort(
            key=lambda row: row[
                "estimated_monthly_savings"
            ],
            reverse=True,
        )

        return results, errors

    # ================================================================
    # RESERVATIONS
    # ================================================================

    @staticmethod
    def _reservation_resource_type(
        instance_details: dict[str, Any],
    ) -> str:

        for key in (
            "RDSInstanceDetails",
            "RedshiftInstanceDetails",
            "ElastiCacheInstanceDetails",
            "ESInstanceDetails",
            "DBInstanceDetails",
            "NodeDetails",
        ):

            details = instance_details.get(
                key
            )

            if not isinstance(
                details,
                dict,
            ):
                continue

            resource_type = (
                details.get("InstanceType")
                or details.get("NodeType")
                or details.get("InstanceClass")
            )

            if resource_type:
                return str(resource_type)

        return "Unknown"

    def _reservations(
        self,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:

        results: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        for service_id, display_name in RESERVATION_SERVICES:

            try:

                response = (
                    self.client
                    .get_reservation_purchase_recommendation(
                        Service=service_id,
                        LookbackPeriodInDays="THIRTY_DAYS",
                        TermInYears="ONE_YEAR",
                        PaymentOption="NO_UPFRONT",
                    )
                )

            except Exception as exc:

                errors.append(
                    {
                        "engine": "reservations",
                        "service": display_name,
                        "error": self._error_text(exc),
                    }
                )

                continue

            recommendations = (
                response.get(
                    "Recommendations",
                    [],
                )
                or []
            )

            for recommendation in recommendations:

                details_list = (
                    recommendation.get(
                        "RecommendationDetails",
                        [],
                    )
                    or []
                )

                for detail in details_list:

                    if not isinstance(
                        detail,
                        dict,
                    ):
                        continue

                    savings = self._float(
                        detail.get(
                            "EstimatedMonthlySavingsAmount"
                        ),
                        None,
                    )

                    if savings is None or savings <= 0:
                        continue

                    instance_details = (
                        detail.get(
                            "InstanceDetails"
                        )
                        or {}
                    )

                    quantity = self._safe_int(
                        detail.get(
                            "RecommendedNumberOfInstances"
                        ),
                        0,
                    )

                    results.append(
                        {
                            "service": display_name,

                            "resource_type": (
                                self._reservation_resource_type(
                                    instance_details
                                )
                            ),

                            "recommended_quantity": quantity,

                            "estimated_monthly_savings": round(
                                savings,
                                2,
                            ),

                            "currency": self.CURRENCY,

                            "lookback_period_days": 30,

                            "term_years": 1,

                            "payment_option": "NO_UPFRONT",

                            "source": "AWS Cost Explorer",
                        }
                    )

        results.sort(
            key=lambda row: row[
                "estimated_monthly_savings"
            ],
            reverse=True,
        )

        return results, errors

    # ================================================================
    # COST EXPLORER RIGHTSIZING
    # ================================================================

    def _rightsizing(
        self,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:

        try:

            response = (
                self.client
                .get_rightsizing_recommendation(
                    Service="AmazonEC2",
                    Configuration={
                        "RecommendationTarget": (
                            "SAME_INSTANCE_FAMILY"
                        ),
                        "BenefitsConsidered": True,
                    },
                )
            )

        except Exception as exc:

            return [], [
                {
                    "engine": "cost_explorer_rightsizing",
                    "error": self._error_text(exc),
                }
            ]

        results: list[dict[str, Any]] = []

        recommendations = (
            response.get(
                "RightsizingRecommendations",
                [],
            )
            or []
        )

        for recommendation in recommendations:

            if not isinstance(
                recommendation,
                dict,
            ):
                continue

            current = (
                recommendation.get(
                    "CurrentInstance"
                )
                or {}
            )

            current_details = (
                current.get(
                    "ResourceDetails"
                )
                or {}
            ).get(
                "EC2ResourceDetails",
                {},
            ) or {}

            utilization = (
                current.get(
                    "ResourceUtilization"
                )
                or {}
            ).get(
                "EC2ResourceUtilization",
                {},
            ) or {}

            raw_action = recommendation.get(
                "RightsizingType"
            )

            if raw_action == "Terminate":
                action = "Terminate"

                detail = (
                    recommendation.get(
                        "TerminateRecommendationDetail"
                    )
                    or {}
                )

                savings = self._float(
                    detail.get(
                        "EstimatedMonthlySavings"
                    ),
                    None,
                )

                target_type = None

            else:
                action = "Resize"

                modify_detail = (
                    recommendation.get(
                        "ModifyRecommendationDetail"
                    )
                    or {}
                )

                targets = (
                    modify_detail.get(
                        "TargetInstances"
                    )
                    or []
                )

                target = next(
                    (
                        item
                        for item in targets
                        if isinstance(item, dict)
                        and item.get(
                            "DefaultTargetInstance"
                        )
                    ),
                    (
                        targets[0]
                        if targets
                        and isinstance(
                            targets[0],
                            dict,
                        )
                        else {}
                    ),
                )

                target_details = (
                    target.get(
                        "ResourceDetails"
                    )
                    or {}
                ).get(
                    "EC2ResourceDetails",
                    {},
                ) or {}

                target_type = target_details.get(
                    "InstanceType"
                )

                savings = self._float(
                    target.get(
                        "EstimatedMonthlySavings"
                    ),
                    None,
                )

            if savings is None or savings <= 0:
                continue

            results.append(
                {
                    "resource_id": current.get(
                        "ResourceId"
                    ),

                    "resource_name": current.get(
                        "InstanceName"
                    ),

                    "region": current_details.get(
                        "Region"
                    ),

                    "action": action,

                    "current_instance_type": (
                        current_details.get(
                            "InstanceType"
                        )
                    ),

                    "target_instance_type": target_type,

                    "current_monthly_cost": self._float(
                        current.get(
                            "MonthlyCost"
                        ),
                        None,
                    ),

                    "estimated_monthly_savings": round(
                        savings,
                        2,
                    ),

                    "max_cpu_utilization_pct": self._float(
                        utilization.get(
                            "MaxCpuUtilizationPercentage"
                        ),
                        None,
                    ),

                    "currency": self.CURRENCY,

                    "source": "AWS Cost Explorer",
                }
            )

        results.sort(
            key=lambda row: row[
                "estimated_monthly_savings"
            ],
            reverse=True,
        )

        return results, []

    # ================================================================
    # COMPUTE OPTIMIZER
    # ================================================================

    @staticmethod
    def _compute_optimizer_metric(
        metrics: Any,
        name: str,
        statistic: str | None = None,
    ) -> float | None:

        if not isinstance(
            metrics,
            list,
        ):
            return None

        for metric in metrics:

            if not isinstance(
                metric,
                dict,
            ):
                continue

            if metric.get("name") != name:
                continue

            if (
                statistic is not None
                and metric.get("statistic") != statistic
            ):
                continue

            value = metric.get(
                "value"
            )

            if isinstance(
                value,
                (int, float),
            ) and not isinstance(
                value,
                bool,
            ):
                return float(value)

        return None

    def _compute_optimizer(
        self,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:

        results: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        next_token: str | None = None

        while True:

            request: dict[str, Any] = {
                "maxResults": (
                    self.COMPUTE_OPTIMIZER_PAGE_SIZE
                )
            }

            if next_token:
                request["nextToken"] = next_token

            try:

                response = (
                    self.compute_optimizer
                    .get_ec2_instance_recommendations(
                        **request
                    )
                )

            except Exception as exc:

                errors.append(
                    {
                        "engine": "compute_optimizer",
                        "error": self._error_text(exc),
                    }
                )

                break

            recommendations = (
                response.get(
                    "instanceRecommendations",
                    [],
                )
                or []
            )

            for recommendation in recommendations:

                if not isinstance(
                    recommendation,
                    dict,
                ):
                    continue

                finding = recommendation.get(
                    "finding"
                )

                # Compute Optimizer returns Optimized resources too.
                # They are not cost opportunities and should not be
                # displayed as savings recommendations.
                if finding in {
                    "Optimized",
                }:
                    continue

                options = (
                    recommendation.get(
                        "recommendationOptions",
                        [],
                    )
                    or []
                )

                if not options:
                    continue

                # Rank 1 is the preferred/top recommendation.
                valid_options = [
                    option
                    for option in options
                    if isinstance(option, dict)
                ]

                if not valid_options:
                    continue

                top_option = next(
                    (
                        option
                        for option in valid_options
                        if self._safe_int(
                            option.get("rank"),
                            0,
                        ) == 1
                    ),
                    valid_options[0],
                )

                savings = (
                    top_option.get(
                        "savingsOpportunity"
                    )
                    or {}
                )

                savings_after_discounts = (
                    top_option.get(
                        "savingsOpportunityAfterDiscounts"
                    )
                    or {}
                )

                on_demand_savings = (
                    self._money_value(
                        savings.get(
                            "estimatedMonthlySavings"
                        )
                    )
                )

                discounted_savings = (
                    self._money_value(
                        savings_after_discounts.get(
                            "estimatedMonthlySavings"
                        )
                    )
                )

                # Prefer the after-discount value when AWS provides it.
                effective_savings = (
                    discounted_savings
                    if discounted_savings is not None
                    else on_demand_savings
                )

                if (
                    effective_savings is None
                    or effective_savings <= 0
                ):
                    continue

                projected_metrics = (
                    top_option.get(
                        "projectedUtilizationMetrics",
                        [],
                    )
                    or []
                )

                current_metrics = (
                    recommendation.get(
                        "utilizationMetrics",
                        [],
                    )
                    or []
                )

                results.append(
                    {
                        "resource_id": recommendation.get(
                            "instanceArn"
                        ),

                        "resource_name": recommendation.get(
                            "instanceName"
                        ),

                        "finding": finding,

                        "finding_reason_codes": (
                            recommendation.get(
                                "findingReasonCodes",
                                [],
                            )
                            or []
                        ),

                        "current_instance_type": (
                            recommendation.get(
                                "currentInstanceType"
                            )
                        ),

                        "recommended_instance_type": (
                            top_option.get(
                                "instanceType"
                            )
                        ),

                        "rank": self._safe_int(
                            top_option.get(
                                "rank"
                            ),
                            1,
                        ),

                        "migration_effort": (
                            top_option.get(
                                "migrationEffort"
                            )
                        ),

                        "current_performance_risk": (
                            self._float(
                                recommendation.get(
                                    "currentPerformanceRisk"
                                ),
                                None,
                            )
                        ),

                        "recommended_performance_risk": (
                            self._float(
                                top_option.get(
                                    "performanceRisk"
                                ),
                                None,
                            )
                        ),

                        "lookback_period_days": (
                            self._float(
                                recommendation.get(
                                    "lookBackPeriodInDays"
                                ),
                                None,
                            )
                        ),

                        "max_cpu_utilization_pct": (
                            self._compute_optimizer_metric(
                                current_metrics,
                                "CPU",
                                "Maximum",
                            )
                        ),

                        "avg_cpu_utilization_pct": (
                            self._compute_optimizer_metric(
                                current_metrics,
                                "CPU",
                                "Average",
                            )
                        ),

                        "projected_cpu_utilization_pct": (
                            self._compute_optimizer_metric(
                                projected_metrics,
                                "CPU",
                                "Maximum",
                            )
                        ),

                        "estimated_monthly_savings": round(
                            effective_savings,
                            2,
                        ),

                        "on_demand_estimated_monthly_savings": (
                            round(
                                on_demand_savings,
                                2,
                            )
                            if on_demand_savings is not None
                            else None
                        ),

                        "after_discounts_estimated_monthly_savings": (
                            round(
                                discounted_savings,
                                2,
                            )
                            if discounted_savings is not None
                            else None
                        ),

                        "estimated_savings_pct": (
                            self._float(
                                savings_after_discounts.get(
                                    "savingsOpportunityPercentage"
                                ),
                                None,
                            )
                            if discounted_savings is not None
                            else self._float(
                                savings.get(
                                    "savingsOpportunityPercentage"
                                ),
                                None,
                            )
                        ),

                        "currency": (
                            self._money_currency(
                                (
                                    savings_after_discounts.get(
                                        "estimatedMonthlySavings"
                                    )
                                    if discounted_savings is not None
                                    else savings.get(
                                        "estimatedMonthlySavings"
                                    )
                                ),
                                self.CURRENCY,
                            )
                        ),

                        "last_refresh_timestamp": (
                            recommendation.get(
                                "lastRefreshTimestamp"
                            ).isoformat()
                            if isinstance(
                                recommendation.get(
                                    "lastRefreshTimestamp"
                                ),
                                datetime,
                            )
                            else recommendation.get(
                                "lastRefreshTimestamp"
                            )
                        ),

                        "source": "AWS Compute Optimizer",
                    }
                )

            next_token = response.get(
                "nextToken"
            )

            if not next_token:
                break

        results.sort(
            key=lambda row: row[
                "estimated_monthly_savings"
            ],
            reverse=True,
        )

        return results, errors

    # ================================================================
    # OVERVIEW
    # ================================================================

    def get_overview(
        self,
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:

        cache_key = _cache_key(
            self.CACHE_KEY
        )

        if not force_refresh:

            cached = _cache_get(
                cache_key
            )

            if cached is not None:
                return cached

        savings_plans, savings_plan_errors = (
            self._savings_plans()
        )

        reservations, reservation_errors = (
            self._reservations()
        )

        rightsizing, rightsizing_errors = (
            self._rightsizing()
        )

        compute_optimizer, compute_optimizer_errors = (
            self._compute_optimizer()
        )

        result = {
            "source": "aws_native_recommendations",

            "currency": self.CURRENCY,

            "savings_plans": savings_plans,

            "reservations": reservations,

            "rightsizing": rightsizing,

            "compute_optimizer": compute_optimizer,

            # IMPORTANT:
            # Do not sum all engines together because their
            # savings opportunities may overlap.
            "estimated_monthly_savings": {
                "savings_plans": self._sum_savings(
                    savings_plans
                ),

                "reservations": self._sum_savings(
                    reservations
                ),

                "cost_explorer_rightsizing": (
                    self._sum_savings(
                        rightsizing
                    )
                ),

                "compute_optimizer": (
                    self._sum_savings(
                        compute_optimizer
                    )
                ),
            },

            "errors": (
                savings_plan_errors
                + reservation_errors
                + rightsizing_errors
                + compute_optimizer_errors
            ),

            "engine_status": {
                "savings_plans": (
                    "error"
                    if savings_plan_errors
                    and not savings_plans
                    else "ok"
                ),

                "reservations": (
                    "error"
                    if reservation_errors
                    and not reservations
                    else "ok"
                ),

                "cost_explorer_rightsizing": (
                    "error"
                    if rightsizing_errors
                    and not rightsizing
                    else "ok"
                ),

                "compute_optimizer": (
                    "error"
                    if compute_optimizer_errors
                    and not compute_optimizer
                    else "ok"
                ),
            },

            "retrieved_at": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),
        }

        today = date.today()

        _cache_set(
            cache_key,
            result,
            end=today,
            today=today,
        )

        return result