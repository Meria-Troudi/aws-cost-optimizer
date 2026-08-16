"""
Analysis context.

Provides a stable interface for analyzers to consume collector
output without knowing the internal resource document layout.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .billing import (
    normalize_billing_context,
)

from .metrics import (
    metric_datapoint_count,
    metric_has_observed_data,
    metric_is_zero,
    metric_numeric_value,
    metric_status,
    metric_summary,
)


@dataclass(slots=True)
class AnalysisContext:

    resource: dict[str, Any]

    scan_id: int | str | None = None

    account_id: str | None = None

    observation_period: (
        dict[str, Any] | None
    ) = None

    cost_context: (
        dict[str, Any] | None
    ) = None

    # ==============================================================
    # IDENTITY
    # ==============================================================

    @property
    def resource_id(
        self,
    ) -> str | None:

        value = self.resource.get(
            "resource_id"
        )

        if value is None:
            return None

        return str(value)

    @property
    def resource_type(
        self,
    ) -> str | None:

        value = self.resource.get(
            "resource_type"
        )

        if value is None:
            return None

        return str(value)

    @property
    def region(
        self,
    ) -> str | None:

        value = self.resource.get(
            "region"
        )

        if value is None:
            return None

        return str(value)

    # ==============================================================
    # COLLECTOR DATA
    # ==============================================================

    def observations(
        self,
    ) -> dict[str, Any]:

        value = self.resource.get(
            "observations",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def cloudwatch(
        self,
    ) -> dict[str, Any]:

        value = (
            self.observations().get(
                "cloudwatch",
                {},
            )
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def metrics(
        self,
    ) -> dict[str, Any]:

        value = (
            self.cloudwatch().get(
                "metrics",
                {},
            )
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def derived(
        self,
    ) -> dict[str, Any]:

        value = (
            self.observations().get(
                "derived",
                {},
            )
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def topology(
        self,
    ) -> dict[str, Any]:

        value = self.resource.get(
            "topology",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def configuration(
        self,
    ) -> dict[str, Any]:

        value = self.resource.get(
            "configuration",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def identity(
        self,
    ) -> dict[str, Any]:

        value = self.resource.get(
            "identity",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    # ==============================================================
    # BILLING
    # ==============================================================

    def billing(
        self,
    ) -> dict[str, Any]:

        value = (
            self.cost_context
            or self.resource.get(
                "cost_context"
            )
        )

        return normalize_billing_context(
            value
        )

    def billing_amount(
        self,
    ) -> float | None:

        billing = self.billing()

        value = billing.get(
            "amount"
        )

        if isinstance(
            value,
            (int, float),
        ):
            return float(value)

        return None

    # ==============================================================
    # OBSERVATION PERIOD
    # ==============================================================

    def period(
        self,
    ) -> dict[str, Any]:

        if isinstance(
            self.observation_period,
            dict,
        ):

            return dict(
                self.observation_period
            )

        value = self.resource.get(
            "observation_period",
            {},
        )

        return (
            dict(value)
            if isinstance(value, dict)
            else {}
        )

    # ==============================================================
    # METRICS
    # ==============================================================

    def metric(
        self,
        name: str,
    ) -> dict[str, Any]:

        value = self.metrics().get(
            name
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def metric_value(
        self,
        name: str,
    ) -> float | None:

        return metric_numeric_value(
            self.metric(name)
        )

    def metric_available(
        self,
        name: str,
    ) -> bool:

        return metric_has_observed_data(
            self.metric(name)
        )

    def metric_is_zero(
        self,
        name: str,
    ) -> bool:

        return metric_is_zero(
            self.metric(name)
        )

    def metric_has_numeric_value(
        self,
        name: str,
    ) -> bool:

        return (
            self.metric_value(name)
            is not None
        )

    def metric_summary(
        self,
        name: str,
    ) -> dict[str, Any]:

        return metric_summary(
            self.metric(name)
        )

    def metric_datapoints(
        self,
        name: str,
    ) -> int:

        return metric_datapoint_count(
            self.metric(name)
        )

    def metric_status(
        self,
        name: str,
    ) -> str:

        return metric_status(
            self.metric(name)
        )

    # ==============================================================
    # DATA QUALITY
    # ==============================================================

    def collector_data_quality(
        self,
    ) -> dict[str, Any]:

        value = self.observations().get(
            "data_quality",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def data_quality(
        self,
    ) -> dict[str, Any]:

        return self.collector_data_quality()

    # ==============================================================
    # OPTIMIZATION EVIDENCE
    # ==============================================================

    def optimization_evidence(
        self,
    ) -> dict[str, Any]:

        value = self.resource.get(
            "optimization_evidence"
        )

        if isinstance(value, dict):
            return value

        relationships = (
            self.resource.get(
                "relationships",
                {},
            )
        )

        if isinstance(
            relationships,
            dict,
        ):

            nested = relationships.get(
                "optimization_evidence"
            )

            if isinstance(
                nested,
                dict,
            ):
                return nested

        return {}

    # ==============================================================
    # COMPATIBILITY
    # ==============================================================

    def rds_billing_match(
        self,
    ) -> dict[str, Any]:

        value = self.resource.get(
            "rds_billing_match",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )