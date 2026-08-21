"""
DynamoDB cost optimization analyzer.

Rules
-----
1. Provisioned capacity is strongly underutilized.
2. Provisioned table has no Auto Scaling evidence.
3. Provisioned GSI is strongly underutilized.
4. Table has no observed read/write activity.
5. On-demand table may warrant a provisioned-vs-on-demand review.
6. Global Table replica configuration should be reviewed.
7. Throttling is reported as an operational warning only -- never a
   cost-saving recommendation.

The analyzer consumes the collector's already rate-normalized
utilization evidence (`context.derived()`); it does not re-derive
attribution, invent RCU/WCU values, or invent savings. Billing is
read only via `context.billing()` and passed through untouched --
reconciliation is the sole cost-attribution authority.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ...base import Analyzer
from ...condition import EvidenceStatement
from ...context import AnalysisContext
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
from ...registry import register


DEFAULT_POLICY = {
    "utilization": {
        "enabled": True,
        "minimum_coverage": 0.80,
        "low_read_percent": 20.0,
        "low_write_percent": 20.0,
    },
    "autoscaling": {
        "enabled": True,
    },
    "unused": {
        "enabled": True,
        "minimum_observation_days": 30.0,
    },
    "on_demand": {
        "enabled": True,
        "minimum_observation_days": 30.0,
    },
    "global_table": {
        "enabled": True,
    },
    "gsi": {
        "enabled": True,
        "minimum_coverage": 0.80,
        "low_read_percent": 20.0,
        "low_write_percent": 20.0,
    },
    "throttling": {
        "enabled": True,
    },
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float | None:

    if value is None or isinstance(value, bool):
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class _H:
    """Small namespace of context-reading helpers (kept local to
    this module rather than exported, mirroring the pattern used by
    the NAT/TGW analyzer modules)."""

    @staticmethod
    def configuration(context: AnalysisContext) -> dict[str, Any]:
        return _dict(context.configuration())

    @staticmethod
    def capacity(context: AnalysisContext) -> dict[str, Any]:
        return _dict(_H.configuration(context).get("capacity"))

    @staticmethod
    def billing_mode(context: AnalysisContext) -> str:
        return str(
            _H.capacity(context).get("billing_mode") or "UNKNOWN"
        ).upper()

    @staticmethod
    def global_table(context: AnalysisContext) -> dict[str, Any]:
        return _dict(
            _dict(context.resource.get("relationships")).get(
                "global_table"
            )
        )

    @staticmethod
    def cloudwatch(context: AnalysisContext) -> dict[str, Any]:
        return _dict(context.cloudwatch())

    @staticmethod
    def derived(context: AnalysisContext) -> dict[str, Any]:
        return _dict(context.derived())

    @staticmethod
    def table_metrics(context: AnalysisContext) -> dict[str, Any]:
        return _dict(
            _dict(_H.cloudwatch(context).get("table")).get(
                "metrics"
            )
        )

    @staticmethod
    def metric(
        context: AnalysisContext,
        name: str,
    ) -> dict[str, Any]:
        value = _H.table_metrics(context).get(name)
        return value if isinstance(value, dict) else {}

    @staticmethod
    def metric_value(
        metric: dict[str, Any],
        field: str = "value",
    ) -> float | None:

        if metric.get("has_data") is not True:
            return None

        return _number(metric.get(field))

    @staticmethod
    def coverage(metric: dict[str, Any]) -> float:

        ratio = _number(metric.get("coverage_ratio"))

        if ratio is not None:
            return ratio / 100.0 if ratio > 1 else ratio

        percent = _number(metric.get("coverage_percent"))

        return percent / 100.0 if percent is not None else 0.0

    @staticmethod
    def ready(metric: dict[str, Any], minimum: float) -> bool:

        return (
            metric.get("has_data") is True
            and _H.metric_value(metric) is not None
            and _H.coverage(metric) >= minimum
        )

    @staticmethod
    def observation_days(context: AnalysisContext) -> float | None:

        period = context.observation_period

        if isinstance(period, dict):

            duration = _number(period.get("duration_seconds"))

            if duration is not None:
                return duration / 86400.0

            start = period.get("start")
            end = period.get("end")

        else:

            cloudwatch = _H.cloudwatch(context)
            duration = _number(cloudwatch.get("duration_seconds"))

            if duration is not None:
                return duration / 86400.0

            start = cloudwatch.get("analysis_start")
            end = cloudwatch.get("analysis_end")

        if not start or not end:
            return None

        try:

            start_dt = (
                start
                if isinstance(start, datetime)
                else datetime.fromisoformat(
                    str(start).replace("Z", "+00:00")
                )
            )

            end_dt = (
                end
                if isinstance(end, datetime)
                else datetime.fromisoformat(
                    str(end).replace("Z", "+00:00")
                )
            )

            return (end_dt - start_dt).total_seconds() / 86400.0

        except (TypeError, ValueError):
            return None

    @staticmethod
    def policy(context: AnalysisContext) -> dict[str, Any]:

        result = {
            key: (dict(value) if isinstance(value, dict) else value)
            for key, value in DEFAULT_POLICY.items()
        }

        for root_name in (
            "analyzer_config",
            "analysis_config",
            "config",
        ):

            root = context.resource.get(root_name)

            if not isinstance(root, dict):
                continue

            configured = root.get("dynamodb")

            if not isinstance(configured, dict):
                continue

            for category, values in configured.items():

                if isinstance(values, dict):

                    current = result.get(category, {})

                    if not isinstance(current, dict):
                        current = {}

                    result[category] = {**current, **values}

                else:

                    result[category] = values

            break

        return result


@register
class DynamoDBAnalyzer(Analyzer):

    name = "dynamodb"
    version = "1.0"

    SUPPORTED_RESOURCE_TYPES = {"dynamodb_table", "dynamodb"}

    def supports(self, context: AnalysisContext) -> bool:
        return context.resource_type in self.SUPPORTED_RESOURCE_TYPES

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        checks = (
            self._check_underutilized_provisioned,
            self._check_missing_autoscaling,
            self._check_unused_table,
            self._check_on_demand_review,
            self._check_global_table,
            self._check_gsi_underutilization,
            self._check_throttling,
        )

        findings: list[Finding] = []

        for check in checks:

            finding = check(context)

            if finding is not None:
                findings.append(finding)

        return findings

    # ==================================================================
    # RULE 1 -- PROVISIONED UNDERUTILIZATION
    # ==================================================================

    def _check_underutilized_provisioned(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _H.policy(context).get("utilization", {})

        if not policy.get("enabled", True):
            return None

        if _H.billing_mode(context) != "PROVISIONED":
            return None

        minimum = float(policy.get("minimum_coverage", 0.80))

        consumed_read = _H.metric(
            context, "ConsumedReadCapacityUnits"
        )
        consumed_write = _H.metric(
            context, "ConsumedWriteCapacityUnits"
        )
        provisioned_read = _H.metric(
            context, "ProvisionedReadCapacityUnits"
        )
        provisioned_write = _H.metric(
            context, "ProvisionedWriteCapacityUnits"
        )

        required = (
            consumed_read,
            consumed_write,
            provisioned_read,
            provisioned_write,
        )

        if not all(_H.ready(metric, minimum) for metric in required):
            return None

        table_derived = _dict(_H.derived(context).get("table"))

        read_utilization = _number(
            table_derived.get("read_utilization_percent")
        )
        write_utilization = _number(
            table_derived.get("write_utilization_percent")
        )

        if read_utilization is None or write_utilization is None:
            return None

        read_limit = float(policy.get("low_read_percent", 20.0))
        write_limit = float(policy.get("low_write_percent", 20.0))

        if (
            read_utilization > read_limit
            or write_utilization > write_limit
        ):
            return None

        return self._finding(
            context=context,
            finding_type="dynamodb_provisioned_capacity_underutilized",
            title=(
                "DynamoDB provisioned capacity is strongly "
                "underutilized"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "Observed consumed read and write capacity remain "
                "well below provisioned capacity during the "
                "analysis period."
            ),
            statements=[
                self._metric_statement(
                    context, "ConsumedReadCapacityUnits"
                ),
                self._metric_statement(
                    context, "ProvisionedReadCapacityUnits"
                ),
                self._metric_statement(
                    context, "ConsumedWriteCapacityUnits"
                ),
                self._metric_statement(
                    context, "ProvisionedWriteCapacityUnits"
                ),
            ],
            metadata={
                "category": "capacity_optimization",
                "billing_mode": "PROVISIONED",
                "read_utilization_percent": read_utilization,
                "write_utilization_percent": write_utilization,
            },
            recommendation_eligible=True,
            limitations=[
                "Average utilization can hide short traffic spikes.",
                (
                    "Capacity must not be reduced below workload "
                    "requirements."
                ),
                (
                    "The analyzer does not prescribe a new RCU or "
                    "WCU value."
                ),
            ],
        )

    # ==================================================================
    # RULE 2 -- AUTOSCALING
    # ==================================================================

    def _check_missing_autoscaling(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _H.policy(context).get("autoscaling", {})

        if not policy.get("enabled", True):
            return None

        if _H.billing_mode(context) != "PROVISIONED":
            return None

        autoscaling = _H.configuration(context).get("autoscaling")

        if not isinstance(autoscaling, dict):
            return None

        table = _dict(autoscaling.get("table"))
        read = _dict(table.get("read"))
        write = _dict(table.get("write"))

        read_enabled = read.get("enabled") is True
        write_enabled = write.get("enabled") is True

        if read_enabled and write_enabled:
            return None

        return self._finding(
            context=context,
            finding_type="dynamodb_provisioned_autoscaling_review",
            title="Review DynamoDB Auto Scaling",
            severity="low",
            confidence="high",
            reason=(
                "The table uses provisioned capacity but one or "
                "both read/write capacity dimensions have no "
                "observed Application Auto Scaling configuration."
            ),
            statements=[
                self._statement(
                    name="autoscaling",
                    value={"read": read, "write": write},
                    description=(
                        "Application Auto Scaling evidence for "
                        "provisioned table capacity."
                    ),
                    source=["Application Auto Scaling"],
                    observed=True,
                )
            ],
            metadata={
                "category": "autoscaling",
                "read_autoscaling_enabled": read_enabled,
                "write_autoscaling_enabled": write_enabled,
            },
            recommendation_eligible=True,
            limitations=[
                (
                    "A table may intentionally use fixed capacity "
                    "for predictable workloads."
                ),
            ],
        )

    # ==================================================================
    # RULE 3 -- UNUSED TABLE
    # ==================================================================

    def _check_unused_table(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _H.policy(context).get("unused", {})

        if not policy.get("enabled", True):
            return None

        required_days = float(
            policy.get("minimum_observation_days", 30.0)
        )
        observed_days = _H.observation_days(context)

        if observed_days is None or observed_days < required_days:
            return None

        read = _H.metric(context, "ConsumedReadCapacityUnits")
        write = _H.metric(context, "ConsumedWriteCapacityUnits")

        minimum = 0.80

        if not (
            _H.ready(read, minimum) and _H.ready(write, minimum)
        ):
            return None

        table_derived = _dict(_H.derived(context).get("table"))

        read_rate = _number(
            table_derived.get("consumed_read_units_per_second")
        )
        write_rate = _number(
            table_derived.get("consumed_write_units_per_second")
        )

        if read_rate is None or write_rate is None:
            return None

        if read_rate > 0 or write_rate > 0:
            return None

        return self._finding(
            context=context,
            finding_type="dynamodb_no_observed_activity",
            title="DynamoDB table has no observed read/write activity",
            severity="medium",
            confidence="high",
            reason=(
                "No consumed read or write capacity was observed "
                f"during approximately {observed_days:.0f} days of "
                "complete capacity observations."
            ),
            statements=[
                self._metric_statement(
                    context, "ConsumedReadCapacityUnits"
                ),
                self._metric_statement(
                    context, "ConsumedWriteCapacityUnits"
                ),
                self._statement(
                    name="observation_days",
                    value=observed_days,
                    description="Duration of the CloudWatch observation window.",
                    source=["CloudWatch"],
                    unit="days",
                    observed=True,
                ),
            ],
            metadata={
                "category": "unused_resource",
                "observed_days": observed_days,
            },
            recommendation_eligible=True,
            limitations=[
                (
                    "A table with no observed requests may still be "
                    "retained intentionally."
                ),
                (
                    "Review application references, backups, "
                    "streams, exports and infrastructure "
                    "definitions before deletion."
                ),
            ],
        )

    # ==================================================================
    # RULE 4 -- ON-DEMAND REVIEW
    # ==================================================================

    def _check_on_demand_review(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _H.policy(context).get("on_demand", {})

        if not policy.get("enabled", True):
            return None

        if _H.billing_mode(context) != "PAY_PER_REQUEST":
            return None

        minimum_days = float(
            policy.get("minimum_observation_days", 30.0)
        )
        observed_days = _H.observation_days(context)

        if observed_days is None or observed_days < minimum_days:
            return None

        read = _H.metric(context, "ConsumedReadCapacityUnits")
        write = _H.metric(context, "ConsumedWriteCapacityUnits")

        minimum = 0.80

        if not (
            _H.ready(read, minimum) and _H.ready(write, minimum)
        ):
            return None

        # On-demand mode has no provisioned baseline to compute a
        # utilization percentage against -- this stays a review
        # signal only. It does not assert that provisioned mode
        # would be cheaper.
        return self._finding(
            context=context,
            finding_type="dynamodb_on_demand_billing_mode_review",
            title="Review DynamoDB on-demand billing mode",
            severity="info",
            confidence="medium",
            reason=(
                "The table uses on-demand billing and has "
                "sufficiently long observed traffic history. For "
                "stable high-volume workloads, compare on-demand "
                "pricing with an appropriately provisioned and "
                "autoscaled configuration."
            ),
            statements=[
                self._metric_statement(
                    context, "ConsumedReadCapacityUnits"
                ),
                self._metric_statement(
                    context, "ConsumedWriteCapacityUnits"
                ),
            ],
            metadata={
                "category": "billing_mode_review",
                "billing_mode": "PAY_PER_REQUEST",
                "observed_days": observed_days,
            },
            recommendation_eligible=True,
            limitations=[
                (
                    "On-demand vs provisioned economics require "
                    "current pricing and workload shape."
                ),
                (
                    "This analyzer does not calculate the "
                    "alternative billing cost."
                ),
            ],
        )

    # ==================================================================
    # RULE 5 -- GLOBAL TABLE
    # ==================================================================

    def _check_global_table(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _H.policy(context).get("global_table", {})

        if not policy.get("enabled", True):
            return None

        global_table = _H.global_table(context)

        if not global_table.get("is_global_table"):
            return None

        return self._finding(
            context=context,
            finding_type="dynamodb_global_table_replica_review",
            title="DynamoDB Global Table replicas should be reviewed",
            severity="low",
            confidence="high",
            reason=(
                "The table is replicated across "
                f"{global_table.get('replica_count', 0)} Region(s). "
                "Review whether every replica is still required."
            ),
            statements=[
                self._statement(
                    name="global_table",
                    value=global_table,
                    description=(
                        "Global Table replica configuration "
                        "collected from DynamoDB."
                    ),
                    source=["DynamoDB.DescribeTable"],
                    observed=True,
                )
            ],
            metadata={
                "category": "global_table",
                "replica_count": global_table.get("replica_count"),
                "replica_regions": global_table.get(
                    "replica_regions"
                ),
            },
            recommendation_eligible=True,
            limitations=[
                (
                    "Replicas may be required for disaster "
                    "recovery, latency, or regional availability."
                ),
                (
                    "Replica utilization is not proven by replica "
                    "inventory alone."
                ),
            ],
        )

    # ==================================================================
    # RULE 6 -- GSI UNDERUTILIZATION
    # ==================================================================

    def _check_gsi_underutilization(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _H.policy(context).get("gsi", {})

        if not policy.get("enabled", True):
            return None

        if _H.billing_mode(context) != "PROVISIONED":
            return None

        indexes = _H.configuration(context).get("indexes", [])

        if not isinstance(indexes, list) or not indexes:
            return None

        gsi_metrics = _dict(_H.cloudwatch(context).get("gsis"))
        gsi_derived = _dict(_H.derived(context).get("gsis"))

        minimum = float(policy.get("minimum_coverage", 0.80))
        read_limit = float(policy.get("low_read_percent", 20.0))
        write_limit = float(policy.get("low_write_percent", 20.0))

        candidates = []

        for index in indexes:

            if not isinstance(index, dict):
                continue

            index_name = index.get("index_name")

            if not index_name:
                continue

            scoped = gsi_metrics.get(str(index_name))

            if not isinstance(scoped, dict):
                continue

            metrics = scoped.get("metrics", {})

            if not isinstance(metrics, dict):
                continue

            required = (
                metrics.get("ConsumedReadCapacityUnits"),
                metrics.get("ConsumedWriteCapacityUnits"),
                metrics.get("ProvisionedReadCapacityUnits"),
                metrics.get("ProvisionedWriteCapacityUnits"),
            )

            if not all(
                isinstance(metric, dict)
                and _H.ready(metric, minimum)
                for metric in required
            ):
                continue

            derived = _dict(gsi_derived.get(str(index_name)))

            read_utilization = _number(
                derived.get("read_utilization_percent")
            )
            write_utilization = _number(
                derived.get("write_utilization_percent")
            )

            if read_utilization is None or write_utilization is None:
                continue

            if (
                read_utilization > read_limit
                or write_utilization > write_limit
            ):
                continue

            candidates.append(
                {
                    "index_name": index_name,
                    "read_utilization_percent": read_utilization,
                    "write_utilization_percent": write_utilization,
                }
            )

        if not candidates:
            return None

        return self._finding(
            context=context,
            finding_type="dynamodb_gsi_underutilized",
            title=(
                "DynamoDB global secondary index capacity is "
                "strongly underutilized"
            ),
            severity="medium",
            confidence="high",
            reason=(
                f"{len(candidates)} GSI(s) show low read and write "
                "capacity utilization during the observation period."
            ),
            statements=[
                self._statement(
                    name="underutilized_gsis",
                    value=candidates,
                    description=(
                        "Global secondary indexes with strongly "
                        "underutilized provisioned capacity."
                    ),
                    source=[
                        "CloudWatch.AWS/DynamoDB",
                        "DynamoDB.DescribeTable",
                    ],
                    observed=True,
                )
            ],
            metadata={
                "category": "gsi_capacity",
                "candidate_count": len(candidates),
                "gsis": candidates,
            },
            recommendation_eligible=True,
            limitations=[
                (
                    "A GSI may exist for application access "
                    "patterns that are not continuously active."
                ),
                (
                    "The analyzer does not recommend deleting an "
                    "index without dependency validation."
                ),
            ],
        )

    # ==================================================================
    # RULE 7 -- THROTTLING
    # ==================================================================

    def _check_throttling(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _H.policy(context).get("throttling", {})

        if not policy.get("enabled", True):
            return None

        read = _H.metric(context, "ReadThrottleEvents")
        write = _H.metric(context, "WriteThrottleEvents")

        read_value = _H.metric_value(read)
        write_value = _H.metric_value(write)

        if read_value is None and write_value is None:
            return None

        if (read_value or 0) <= 0 and (write_value or 0) <= 0:
            return None

        return self._finding(
            context=context,
            finding_type="dynamodb_throttling_observed",
            title="DynamoDB throttling was observed",
            severity="medium",
            confidence="high",
            reason=(
                "DynamoDB read or write throttle events were "
                "observed during the analysis period. Capacity "
                "should not be reduced until the throttling "
                "condition is understood."
            ),
            statements=[
                self._metric_statement(
                    context, "ReadThrottleEvents"
                ),
                self._metric_statement(
                    context, "WriteThrottleEvents"
                ),
            ],
            metadata={
                "category": "operational_capacity",
                "read_throttle_events": read_value,
                "write_throttle_events": write_value,
            },
            # Throttling is an operational signal, never a cost
            # recommendation -- always ineligible regardless of
            # policy overrides.
            recommendation_eligible=False,
            limitations=[
                (
                    "Throttling is an operational capacity signal, "
                    "not evidence of cost waste."
                ),
                (
                    "The analyzer does not automatically increase "
                    "provisioned capacity."
                ),
            ],
        )

    # ==================================================================
    # FINDING / EVIDENCE
    # ==================================================================

    def _finding(
        self,
        *,
        context: AnalysisContext,
        finding_type: str,
        title: str,
        severity: str,
        confidence: str,
        reason: str,
        statements: list[EvidenceStatement],
        metadata: dict[str, Any],
        recommendation_eligible: bool,
        limitations: list[str],
    ) -> Finding:

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=(
                context.resource_type or "dynamodb_table"
            ),
            resource_id=context.resource_id or "unknown",
            analyzer=self.name,
            analyzer_version=self.version,
            severity=severity.lower(),
            confidence=confidence.lower(),
            reason=reason,
            conditions=statements,
            evidence=self._build_evidence(context, metadata),
            observation_period=self._observation_period(context),
            limitations=list(limitations),
            metadata=dict(metadata),
            recommendation_eligible=recommendation_eligible,
            aggregation_scope="resource",
        )

    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: dict[str, Any],
    ) -> Evidence:

        cloudwatch = _H.cloudwatch(context)
        configuration = _H.configuration(context)

        return Evidence(
            metrics=_H.table_metrics(context),
            configuration=dict(configuration),
            topology=dict(context.topology() or {}),
            billing=dict(context.billing() or {}),
            resource={
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "region": context.region,
                "billing_mode": _H.billing_mode(context),
            },
            derived={
                **metadata,
                "cloudwatch": _H.derived(context),
            },
            data_quality={
                **(context.collector_data_quality() or {}),
                "cloudwatch": cloudwatch.get("data_quality", {}),
            },
        )

    @staticmethod
    def _metric_statement(
        context: AnalysisContext,
        name: str,
    ) -> EvidenceStatement:

        metric = _H.metric(context, name)

        return EvidenceStatement(
            name=name,
            value=metric,
            description=f"Observed DynamoDB {name} metric.",
            source=["CloudWatch.AWS/DynamoDB"],
            evidence_keys=[
                f"observations.cloudwatch.table.metrics.{name}"
            ],
            observed=metric.get("has_data") is True,
        )

    @staticmethod
    def _statement(
        *,
        name: str,
        value: Any,
        description: str,
        source: list[str],
        observed: bool | None = None,
        unit: str | None = None,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=list(source),
            unit=unit,
            observed=observed,
        )

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        observation = context.observation_period

        if isinstance(observation, dict):

            return ObservationPeriod(
                start=observation.get("start"),
                end=observation.get("end"),
                duration_seconds=observation.get(
                    "duration_seconds"
                ),
            )

        cloudwatch = _H.cloudwatch(context)

        start = cloudwatch.get("analysis_start")
        end = cloudwatch.get("analysis_end")

        if not start and not end:
            return None

        return ObservationPeriod(
            start=start,
            end=end,
            duration_seconds=cloudwatch.get("duration_seconds"),
        )
