"""
RDS cost optimization analyzer.

Principles
----------
- Uses collected evidence only.
- Does not assume a single metric value represents peak workload.
- Uses configurable analysis policy instead of embedding business policy
  throughout the analyzer.
- Separates strong optimization findings from informational context.
- Does not invent a replacement instance class without sizing/pricing
  evidence.
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


RDS_CONFIGURATION_FIELDS = (
    "instance_class",
    "engine",
    "engine_version",
    "multi_az",
    "availability_zone",
    "backup_retention_days",
    "publicly_accessible",
    "performance_insights_enabled",
    "storage_type",
    "allocated_storage_gib",
    "storage_throughput",
    "db_cluster_identifier",
    "promotion_tier",
    "status",
    "storage_throughput",
)
DEFAULT_POLICY = {
    # Rightsizing
    "rightsizing": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "average_cpu_max_percent": 15.0,
        "maximum_cpu_max_percent": 70.0,
        "connections_max": 2.0,
        "read_iops_max": 10.0,
        "write_iops_max": 10.0,
        "cloudtrail": {
            "enabled": True,
            "required": True,
            "minimum_stable_days": 14,
            "suppress_if_recent_resize": True,
            "suppress_if_multiple_resizes": True,
            "max_resizes_in_window": 1,
            "require_class_stability": True,
        },
    },

    # Idle detection is intentionally stricter.
    "idle": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "average_cpu_max_percent": 5.0,
        "maximum_cpu_max_percent": 25.0,
        "connections_max": 0.0,
        "read_iops_max": 1.0,
        "write_iops_max": 1.0,
    },

    # A stopped instance still incurs storage and backup cost.
    "stopped": {
        "enabled": True,
    },

    # Policy/configuration checks.
    "multi_az": {
        "enabled": True,
    },

    "backup_retention": {
        "enabled": True,
        "minimum_days": 14,
    },

    "performance_insights": {
        "enabled": True,
    },

    # Operational context.
    "old_generation": {
        "enabled": True,
    },

    "aurora": {
        "enabled": True,
    },

    "read_replica": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "connections_max": 2.0,
        "network_bytes_per_second_max": 1024.0,
    },

    # Security finding, not automatically a cost recommendation.
    "public_accessibility": {
        "enabled": True,
    },

    # Capacity signal, not automatically a cost recommendation.
    "io_pressure": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "high_iops": 1000.0,
    },
}


OLD_INSTANCE_FAMILIES = (
    "db.t2.",
    "db.m3.",
    "db.m4.",
    "db.r3.",
    "db.r4.",
)


@register
class RDSAnalyzer(Analyzer):

    name = "rds"
    version = "3.0"

    resource_type = "rds_instance"

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:
        return context.resource_type in {
            "rds_instance",
            "rds",
        }

    # ==================================================================
    # PUBLIC
    # ==================================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        if not self._is_rds_resource(
            context.resource
        ):
            return []

        findings: list[Finding] = []

        # Strong cost findings.
        if self._rightsizing_eligible(
            context
        ):
            finding = self._check_idle_instance(
                context
            )
            if finding:
                findings.append(finding)

            finding = self._check_oversized_instance(
                context
            )
            if finding:
                findings.append(finding)

            finding = self._check_read_replica(
                context
            )
            if finding:
                findings.append(finding)

        # A stopped instance is excluded from rightsizing (see
        # _rightsizing_eligible), so nothing above reports it -- but it
        # still incurs storage and backup cost, which is a cost finding
        # in its own right.
        finding = self._check_stopped_instance(
            context
        )
        if finding:
            findings.append(finding)

        # Configuration/context findings.
        finding = self._check_multi_az(
            context
        )
        if finding:
            findings.append(finding)

        finding = self._check_backup_retention(
            context
        )
        if finding:
            findings.append(finding)

        finding = self._check_performance_insights(
            context
        )
        if finding:
            findings.append(finding)

        finding = self._check_old_generation(
            context
        )
        if finding:
            findings.append(finding)

        finding = self._check_aurora_context(
            context
        )
        if finding:
            findings.append(finding)

        finding = self._check_public_accessibility(
            context
        )
        if finding:
            findings.append(finding)

        finding = self._check_io_pressure(
            context
        )
        if finding:
            findings.append(finding)

        return findings

    # ==================================================================
    # POLICY
    # ==================================================================

    @staticmethod
    def _policy(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        policy = DEFAULT_POLICY.copy()

        resource_policy = (
            context.resource.get(
                "analysis_policy",
                {},
            )
        )

        if not isinstance(
            resource_policy,
            dict,
        ):
            return policy

        rds_policy = resource_policy.get(
            "rds",
            {},
        )

        if not isinstance(
            rds_policy,
            dict,
        ):
            return policy

        for category, values in rds_policy.items():

            if not isinstance(
                values,
                dict,
            ):
                policy[category] = values
                continue

            default_category = policy.get(
                category,
                {},
            )

            if not isinstance(
                default_category,
                dict,
            ):
                default_category = {}

            policy[category] = {
                **default_category,
                **values,
            }

        return policy

    # ==================================================================
    # RESOURCE HELPERS
    # ==================================================================

    @classmethod
    def _is_rds_resource(
        cls,
        resource: dict[str, Any],
    ) -> bool:

        return resource.get(
            "resource_type"
        ) in {
            "rds_instance",
            "rds",
        } or resource.get(
            "type"
        ) == "rds_instance"

    @staticmethod
    def _configuration(
        resource: dict[str, Any],
    ) -> dict[str, Any]:

        value = resource.get(
            "configuration",
            {},
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _resource_id(
        context: AnalysisContext,
    ) -> str:

        return (
            context.resource_id
            or "unknown"
        )

    @classmethod
    def _instance_status(
        cls,
        context: AnalysisContext,
    ) -> str:

        configuration = cls._configuration(
            context.resource
        )

        value = (
            configuration.get(
                "status"
            )
            or context.resource.get(
                "status"
            )
            or context.resource.get(
                "DBInstanceStatus"
            )
            or ""
        )

        return str(value).strip().lower()

    @classmethod
    def _rightsizing_eligible(
        cls,
        context: AnalysisContext,
    ) -> bool:

        status = cls._instance_status(
            context
        )

        return status in {
            "available",
            "backing-up",
            "storage-optimization",
        }

    @staticmethod
    def _cloudtrail(context: AnalysisContext) -> dict[str, Any]:
        observations = context.observations()
        value = observations.get("cloudtrail", {})
        return value if isinstance(value, dict) else {}

    @classmethod
    def _rightsizing_history(cls, context: AnalysisContext) -> dict[str, Any]:
        policy = cls._policy(context).get("rightsizing", {})
        cloudtrail_policy = policy.get("cloudtrail", {})
        if not isinstance(cloudtrail_policy, dict):
            cloudtrail_policy = {}

        history = cls._cloudtrail(context)
        enabled = cloudtrail_policy.get("enabled", True)
        required = cloudtrail_policy.get("required", True)

        if not enabled:
            return {
                "allowed": True,
                "status": "disabled_by_policy",
                "reason": None,
                "history": history,
            }

        status = str(history.get("status", "missing")).lower()
        if status != "ok":
            if required:
                return {
                    "allowed": False,
                    "status": status,
                    "reason": "CloudTrail resize history is unavailable; conservative rightsizing is suppressed.",
                    "history": history,
                }
            return {
                "allowed": True,
                "status": status,
                "reason": "CloudTrail resize history is unavailable; rightsizing continues without historical change evidence.",
                "history": history,
            }

        change_count = int(history.get("change_count", history.get("event_count", 0)) or 0)
        max_changes = int(cloudtrail_policy.get("max_resizes_in_window", 1))
        suppress_multiple = bool(
            cloudtrail_policy.get("suppress_if_multiple_resizes", True)
        )

        if suppress_multiple and change_count > max_changes:
            return {
                "allowed": False,
                "status": status,
                "reason": (
                    f"CloudTrail recorded {change_count} instance-class changes in the observation window; "
                    "CloudWatch metrics may represent multiple configurations."
                ),
                "history": history,
            }

        minimum_stable_days = float(
            cloudtrail_policy.get("minimum_stable_days", 14)
        )
        days_since_last_change = history.get("days_since_last_change")
        suppress_recent = bool(
            cloudtrail_policy.get("suppress_if_recent_resize", True)
        )

        if (
            suppress_recent
            and days_since_last_change is not None
            and float(days_since_last_change) < minimum_stable_days
        ):
            return {
                "allowed": False,
                "status": status,
                "reason": (
                    f"The instance class changed {float(days_since_last_change):.1f} days ago; "
                    f"wait at least {minimum_stable_days:.0f} days of stable workload data before rightsizing."
                ),
                "history": history,
            }

        current_class = cls._configuration(context.resource).get("instance_class")
        last_changed_to_class = history.get("last_changed_to_class")
        require_stable_class = bool(
            cloudtrail_policy.get("require_class_stability", True)
        )

        if (
            require_stable_class
            and current_class
            and last_changed_to_class
            and str(current_class) != str(last_changed_to_class)
        ):
            return {
                "allowed": False,
                "status": status,
                "reason": (
                    "CloudTrail's latest recorded target class differs from the current RDS class; "
                    "historical evidence is inconsistent and rightsizing is suppressed."
                ),
                "history": history,
            }

        return {
            "allowed": True,
            "status": status,
            "reason": None,
            "history": history,
        }

    @classmethod
    def _rightsizing_history_statement(
        cls,
        context: AnalysisContext,
    ) -> EvidenceStatement:
        guard = cls._rightsizing_history(context)
        history = guard.get("history", {})
        return cls._statement(
            "cloudtrail_resize_history",
            {
                "status": guard.get("status"),
                "change_count": history.get("change_count", history.get("event_count", 0)),
                "last_change_at": history.get("last_change_at"),
                "last_changed_to_class": history.get("last_changed_to_class"),
                "days_since_last_change": history.get("days_since_last_change"),
                "class_changed_during_observation": history.get(
                    "class_changed_during_observation", False
                ),
            },
            "CloudTrail was checked for RDS instance-class changes so utilization is evaluated against a stable configuration.",
            ["CloudTrail.ModifyDBInstance"],
        )

    # ==================================================================
    # METRICS
    # ==================================================================

    @staticmethod
    def _metric(
        context: AnalysisContext,
        name: str,
    ) -> dict[str, Any]:

        return context.metric_summary(
            name
        )

    @staticmethod
    def _metric_observed(
        metric: dict[str, Any],
    ) -> bool:

        return (
            isinstance(
                metric,
                dict,
            )
            and metric.get(
                "observed"
            ) is True
            and isinstance(
                metric.get(
                    "value"
                ),
                (int, float),
            )
        )

    @staticmethod
    def _metric_value(
        metric: dict[str, Any],
    ) -> float | None:

        if not RDSAnalyzer._metric_observed(
            metric
        ):
            return None

        return float(
            metric["value"]
        )

    @staticmethod
    def _metric_average(
        metric: dict[str, Any],
    ) -> float | None:

        if not RDSAnalyzer._metric_observed(
            metric
        ):
            return None

        value = metric.get(
            "value"
        )

        return (
            float(value)
            if isinstance(
                value,
                (int, float),
            )
            else None
        )

    @staticmethod
    def _metric_maximum(
        metric: dict[str, Any],
    ) -> float | None:

        if not isinstance(
            metric,
            dict,
        ):
            return None

        value = metric.get(
            "maximum"
        )

        if isinstance(
            value,
            (int, float),
        ):
            return float(value)

        return None

    @staticmethod
    def _metric_datapoints(
        metric: dict[str, Any],
    ) -> int:

        if not isinstance(
            metric,
            dict,
        ):
            return 0

        value = metric.get(
            "datapoints",
            0,
        )

        return (
            int(value)
            if isinstance(
                value,
                int,
            )
            else 0
        )

    @staticmethod
    def _metric_coverage(
        metric: dict[str, Any],
    ) -> float:

        if not isinstance(
            metric,
            dict,
        ):
            return 0.0

        value = metric.get(
            "coverage_ratio",
            0.0,
        )

        try:
            return float(value)
        except (
            TypeError,
            ValueError,
        ):
            return 0.0

    @classmethod
    def _usable_metric_set(
        cls,
        context: AnalysisContext,
        names: tuple[str, ...],
        minimum_coverage: float,
    ) -> bool:

        for name in names:

            metric = cls._metric(
                context,
                name,
            )

            if not cls._metric_observed(
                metric
            ):
                return False

            if (
                cls._metric_coverage(metric)
                < minimum_coverage
            ):
                return False

        return True

    # ==================================================================
    # IDLE INSTANCE
    # ==================================================================

    @classmethod
    def _check_idle_instance(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "idle",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        history_guard = cls._rightsizing_history(context)
        if not history_guard["allowed"]:
            return None

        minimum_coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        metric_names = (
            "CPUUtilization",
            "DatabaseConnections",
            "ReadIOPS",
            "WriteIOPS",
        )

        if not cls._usable_metric_set(
            context,
            metric_names,
            minimum_coverage,
        ):
            return None

        cpu = cls._metric(
            context,
            "CPUUtilization",
        )

        connections = cls._metric(
            context,
            "DatabaseConnections",
        )

        read_iops = cls._metric(
            context,
            "ReadIOPS",
        )

        write_iops = cls._metric(
            context,
            "WriteIOPS",
        )

        cpu_average = cls._metric_average(
            cpu
        )
        cpu_maximum = cls._metric_maximum(
            cpu
        )
        connection_value = cls._metric_value(
            connections
        )
        read_value = cls._metric_value(
            read_iops
        )
        write_value = cls._metric_value(
            write_iops
        )

        if (
            cpu_average is None
            or cpu_maximum is None
            or connection_value is None
            or read_value is None
            or write_value is None
        ):
            return None

        conditions = (
            cpu_average
            <= float(
                policy.get(
                    "average_cpu_max_percent",
                    5.0,
                )
            )
            and cpu_maximum
            <= float(
                policy.get(
                    "maximum_cpu_max_percent",
                    25.0,
                )
            )
            and connection_value
            <= float(
                policy.get(
                    "connections_max",
                    0.0,
                )
            )
            and read_value
            <= float(
                policy.get(
                    "read_iops_max",
                    1.0,
                )
            )
            and write_value
            <= float(
                policy.get(
                    "write_iops_max",
                    1.0,
                )
            )
        )

        if not conditions:
            return None

        statements = [
            cls._rightsizing_history_statement(context),
            cls._statement(
                "cpu",
                {
                    "average_percent":
                        round(cpu_average, 2),
                    "maximum_percent":
                        round(cpu_maximum, 2),
                },
                (
                    "CPU remained very low across "
                    "the observation period."
                ),
                ["CloudWatch.CPUUtilization"],
            ),
            cls._statement(
                "connections",
                connection_value,
                "No database connections were observed.",
                ["CloudWatch.DatabaseConnections"],
            ),
            cls._statement(
                "io",
                {
                    "read_iops":
                        round(read_value, 2),
                    "write_iops":
                        round(write_value, 2),
                },
                "Read and write I/O remained very low.",
                [
                    "CloudWatch.ReadIOPS",
                    "CloudWatch.WriteIOPS",
                ],
            ),
        ]

        reason = (
            "The instance shows sustained low utilization "
            "across CPU, connections and I/O."
        )

        return cls._build_finding(
            context=context,
            finding_type="rds_no_activity",
            title="RDS instance with very low utilization",
            severity="medium",
            confidence="high",
            reason=reason,
            statements=statements,
            metadata={
                "category":
                    "rightsizing",
                "cloudtrail_resize_change_count":
                    cls._cloudtrail(context).get("change_count", 0),
                "cloudtrail_last_change_at":
                    cls._cloudtrail(context).get("last_change_at"),
                "cloudtrail_days_since_last_change":
                    cls._cloudtrail(context).get("days_since_last_change"),
                "instance_class":
                    cls._configuration(
                        context.resource
                    ).get(
                        "instance_class"
                    ),
                "cpu_average_percent":
                    cpu_average,
                "cpu_maximum_percent":
                    cpu_maximum,
                "database_connections":
                    connection_value,
                "read_iops":
                    read_value,
                "write_iops":
                    write_value,
            },
            recommendation_eligible=True,
            limitations=[
                "Validate workload requirements and HA expectations before changing the instance size."
            ],
        )

    @classmethod
    def _check_oversized_instance(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "rightsizing",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        history_guard = cls._rightsizing_history(context)
        if not history_guard["allowed"]:
            return None

        minimum_coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        metric_names = (
            "CPUUtilization",
            "DatabaseConnections",
            "ReadIOPS",
            "WriteIOPS",
        )

        if not cls._usable_metric_set(
            context,
            metric_names,
            minimum_coverage,
        ):
            return None

        cpu = cls._metric(
            context,
            "CPUUtilization",
        )

        connections = cls._metric(
            context,
            "DatabaseConnections",
        )

        read_iops = cls._metric(
            context,
            "ReadIOPS",
        )

        write_iops = cls._metric(
            context,
            "WriteIOPS",
        )

        cpu_average = cls._metric_average(
            cpu
        )
        cpu_maximum = cls._metric_maximum(
            cpu
        )
        connection_value = cls._metric_value(
            connections
        )
        read_value = cls._metric_value(
            read_iops
        )
        write_value = cls._metric_value(
            write_iops
        )

        if (
            cpu_average is None
            or cpu_maximum is None
            or connection_value is None
            or read_value is None
            or write_value is None
        ):
            return None

        # Idle is handled by the stronger idle finding.
        if (
            cpu_average
            <= float(
                DEFAULT_POLICY["idle"][
                    "average_cpu_max_percent"
                ]
            )
            and cpu_maximum
            <= float(
                DEFAULT_POLICY["idle"][
                    "maximum_cpu_max_percent"
                ]
            )
            and connection_value
            <= float(
                DEFAULT_POLICY["idle"][
                    "connections_max"
                ]
            )
            and read_value
            <= float(
                DEFAULT_POLICY["idle"][
                    "read_iops_max"
                ]
            )
            and write_value
            <= float(
                DEFAULT_POLICY["idle"][
                    "write_iops_max"
                ]
            )
        ):
            return None

        low_cpu = (
            cpu_average
            <= float(
                policy.get(
                    "average_cpu_max_percent",
                    15.0,
                )
            )
        )

        safe_peak = (
            cpu_maximum
            <= float(
                policy.get(
                    "maximum_cpu_max_percent",
                    70.0,
                )
            )
        )

        low_connections = (
            connection_value
            <= float(
                policy.get(
                    "connections_max",
                    2.0,
                )
            )
        )

        low_io = (
            read_value
            <= float(
                policy.get(
                    "read_iops_max",
                    10.0,
                )
            )
            and write_value
            <= float(
                policy.get(
                    "write_iops_max",
                    10.0,
                )
            )
        )

        if not (
            low_cpu
            and safe_peak
            and low_connections
            and low_io
        ):
            return None

        configuration = cls._configuration(
            context.resource
        )

        instance_class = (
            configuration.get(
                "instance_class"
            )
            or "current instance"
        )

        statements = [
            cls._rightsizing_history_statement(context),
            cls._statement(
                "cpu",
                {
                    "average_percent":
                        round(cpu_average, 2),
                    "maximum_percent":
                        round(cpu_maximum, 2),
                },
                "CPU utilization remained low and peak CPU stayed below the review limit.",
                ["CloudWatch.CPUUtilization"],
            ),
            cls._statement(
                "connections",
                round(
                    connection_value,
                    2,
                ),
                "Database connections remained low.",
                ["CloudWatch.DatabaseConnections"],
            ),
            cls._statement(
                "io",
                {
                    "read_iops":
                        round(read_value, 2),
                    "write_iops":
                        round(write_value, 2),
                },
                "Read and write I/O remained low.",
                [
                    "CloudWatch.ReadIOPS",
                    "CloudWatch.WriteIOPS",
                ],
            ),
        ]

        # We deliberately do NOT name a smaller class here.
        # That requires a rightsizing/catalog/pricing source.
        reason = (
            f"{instance_class} shows sustained low resource "
            "utilization. A smaller compatible class should be "
            "evaluated against workload and availability requirements."
        )

        return cls._build_finding(
            context=context,
            finding_type=(
                "rds_instance_possible_oversized"
            ),
            title="RDS instance may be oversized",
            severity="medium",
            confidence="medium",
            reason=reason,
            statements=statements,
            metadata={
                "category":
                    "rightsizing",
                "cloudtrail_resize_change_count":
                    cls._cloudtrail(context).get("change_count", 0),
                "cloudtrail_last_change_at":
                    cls._cloudtrail(context).get("last_change_at"),
                "cloudtrail_days_since_last_change":
                    cls._cloudtrail(context).get("days_since_last_change"),
                "instance_class":
                    instance_class,
                "cpu_average_percent":
                    cpu_average,
                "cpu_maximum_percent":
                    cpu_maximum,
                "database_connections":
                    connection_value,
                "read_iops":
                    read_value,
                "write_iops":
                    write_value,
            },
            recommendation_eligible=True,
            limitations=[
                "A replacement class cannot be selected safely without workload, compatibility and pricing evidence."
            ],
        )

    @classmethod
    def _check_read_replica(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "read_replica",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        configuration = cls._configuration(
            context.resource
        )

        replica_source = (
            configuration.get(
                "read_replica_source"
            )
            or configuration.get(
                "replica_source_identifier"
            )
        )

        if not replica_source:
            return None

        minimum_coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        metric_names = (
            "DatabaseConnections",
            "NetworkReceiveThroughput",
            "NetworkTransmitThroughput",
        )

        if not cls._usable_metric_set(
            context,
            metric_names,
            minimum_coverage,
        ):
            return None

        connections = cls._metric_value(
            cls._metric(
                context,
                "DatabaseConnections",
            )
        )

        network_rx = cls._metric_value(
            cls._metric(
                context,
                "NetworkReceiveThroughput",
            )
        )

        network_tx = cls._metric_value(
            cls._metric(
                context,
                "NetworkTransmitThroughput",
            )
        )

        if (
            connections is None
            or network_rx is None
            or network_tx is None
        ):
            return None

        connection_limit = float(
            policy.get(
                "connections_max",
                2.0,
            )
        )

        network_limit = float(
            policy.get(
                "network_bytes_per_second_max",
                1024.0,
            )
        )

        if not (
            connections
            <= connection_limit
            and network_rx
            <= network_limit
            and network_tx
            <= network_limit
        ):
            return None

        statements = [
            cls._statement(
                "connections",
                round(
                    connections,
                    2,
                ),
                "Observed connections remained low.",
                ["CloudWatch.DatabaseConnections"],
            ),
            cls._statement(
                "network",
                {
                    "receive_bytes_per_second":
                        round(network_rx, 2),
                    "transmit_bytes_per_second":
                        round(network_tx, 2),
                },
                "Observed network activity remained low.",
                [
                    "CloudWatch.NetworkReceiveThroughput",
                    "CloudWatch.NetworkTransmitThroughput",
                ],
            ),
        ]

        return cls._build_finding(
            context=context,
            finding_type="rds_underused_read_replica",
            title="RDS read replica is lightly used",
            severity="medium",
            confidence="medium",
            reason=(
                "The read replica shows sustained low "
                "connection and network activity."
            ),
            statements=statements,
            metadata={
                "category":
                    "replica_utilization",
                "replica_source":
                    replica_source,
                "database_connections":
                    connections,
                "network_receive_bytes_per_second":
                    network_rx,
                "network_transmit_bytes_per_second":
                    network_tx,
            },
            recommendation_eligible=True,
            limitations=[
                "Confirm reporting, failover and read-scaling requirements before changing the replica topology."
            ],
        )

    # ==================================================================
    # STOPPED INSTANCE
    # ==================================================================

    @classmethod
    def _check_stopped_instance(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:
        """
        A stopped RDS instance still incurs storage and backup charges
        while delivering no compute value.

        This is deliberately independent of rightsizing:
        _rightsizing_eligible() excludes stopped instances, so without
        this detector a stopped instance produces no cost finding at
        all. The finding does not claim the instance should be deleted,
        only that its retention should be reviewed.
        """

        policy = cls._policy(
            context
        ).get(
            "stopped",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        status = cls._instance_status(
            context
        )

        if status != "stopped":
            return None

        configuration = cls._configuration(
            context.resource
        )

        engine = configuration.get("engine")
        instance_class = configuration.get(
            "instance_class"
        )
        cluster_identifier = (
            configuration.get(
                "db_cluster_identifier"
            )
            or configuration.get(
                "db_cluster_id"
            )
        )

        statements = [
            cls._statement(
                "status",
                status,
                "The instance is in a stopped state.",
                ["RDS configuration"],
            ),
            cls._statement(
                "engine",
                engine,
                "Database engine.",
                ["RDS configuration"],
            ),
            cls._statement(
                "instance_class",
                instance_class,
                "Configured instance class.",
                ["RDS configuration"],
            ),
        ]

        if cluster_identifier:
            statements.append(
                cls._statement(
                    "db_cluster_identifier",
                    cluster_identifier,
                    "Parent cluster identifier.",
                    ["RDS configuration"],
                )
            )

        return cls._build_finding(
            context=context,
            finding_type=(
                "rds_stopped_instance"
            ),
            title="RDS instance is stopped",
            severity="medium",
            confidence="high",
            reason=(
                "The RDS instance is currently stopped. "
                "Review whether it is still required before "
                "removing or retaining it."
            ),
            statements=statements,
            metadata={
                "category": "unused_resource",
                "status": status,
                "engine": engine,
                "instance_class": instance_class,
                "db_cluster_identifier": cluster_identifier,
            },
            recommendation_eligible=True,
            limitations=[
                "A stopped instance still incurs storage and "
                "backup charges; compute charges do not apply.",
                "AWS automatically restarts an instance stopped "
                "for more than seven days, so the stopped state "
                "may be temporary.",
                "Confirm recovery, backup and application "
                "requirements before removal.",
            ],
        )

    @classmethod
    def _check_multi_az(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "multi_az",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        configuration = cls._configuration(
            context.resource
        )

        if configuration.get(
            "multi_az"
        ) is not True:
            return None

        return cls._build_finding(
            context=context,
            finding_type="rds_multi_az_cost_review",
            title="RDS Multi-AZ configuration",
            severity="info",
            confidence="high",
            reason=(
                "Multi-AZ is enabled. Review whether the "
                "current availability requirement justifies "
                "the additional deployment cost."
            ),
            statements=[
                cls._statement(
                    "multi_az",
                    True,
                    "Multi-AZ is enabled on the instance.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category":
                    "configuration_review",
                "multi_az":
                    True,
            },
            recommendation_eligible=False,
            limitations=[
                "Cost optimization must not reduce required availability."
            ],
        )

    @classmethod
    def _check_backup_retention(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "backup_retention",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        retention = cls._configuration(
            context.resource
        ).get(
            "backup_retention_days"
        )

        if retention is None:
            return None

        try:
            retention = int(
                retention
            )
        except (
            TypeError,
            ValueError,
        ):
            return None

        minimum_days = int(
            policy.get(
                "minimum_days",
                14,
            )
        )

        if retention <= minimum_days:
            return None

        return cls._build_finding(
            context=context,
            finding_type=(
                "rds_backup_retention_review"
            ),
            title="RDS backup retention is high",
            severity="low",
            confidence="medium",
            reason=(
                f"Backup retention is {retention} days. "
                "Review whether the recovery policy requires "
                "the full retention period."
            ),
            statements=[
                cls._statement(
                    "backup_retention",
                    {
                        "days":
                            retention,
                        "review_threshold_days":
                            minimum_days,
                    },
                    "Configured backup retention exceeds the review threshold.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category":
                    "backup_configuration",
                "backup_retention_days":
                    retention,
            },
            recommendation_eligible=False,
            limitations=[
                "Retention should only be reduced when recovery requirements allow it."
            ],
        )

    @classmethod
    def _check_performance_insights(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "performance_insights",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        enabled = cls._configuration(
            context.resource
        ).get(
            "performance_insights_enabled"
        )

        if enabled is not True:
            return None

        return cls._build_finding(
            context=context,
            finding_type=(
                "rds_performance_insights_review"
            ),
            title="RDS Performance Insights enabled",
            severity="info",
            confidence="high",
            reason=(
                "Performance Insights is enabled. "
                "Review whether its monitoring capability "
                "is still required."
            ),
            statements=[
                cls._statement(
                    "performance_insights",
                    True,
                    "Performance Insights is enabled.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category":
                    "configuration_review",
                "performance_insights_enabled":
                    True,
            },
            recommendation_eligible=False,
        )

    @classmethod
    def _check_old_generation(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "old_generation",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        instance_class = cls._configuration(
            context.resource
        ).get(
            "instance_class"
        )

        if not instance_class:
            return None

        if not any(
            str(instance_class).startswith(
                family
            )
            for family in OLD_INSTANCE_FAMILIES
        ):
            return None

        return cls._build_finding(
            context=context,
            finding_type=(
                "rds_old_instance_generation"
            ),
            title="RDS uses an older instance generation",
            severity="low",
            confidence="high",
            reason=(
                f"{instance_class} is from an older instance "
                "generation. Review newer compatible generations "
                "for price/performance improvements."
            ),
            statements=[
                cls._statement(
                    "instance_generation",
                    instance_class,
                    "The configured instance belongs to a legacy family.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category":
                    "generation_review",
                "instance_class":
                    instance_class,
            },
            recommendation_eligible=False,
            limitations=[
                "A savings recommendation requires current pricing and compatible instance options."
            ],
        )

    @classmethod
    def _check_aurora_context(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "aurora",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        configuration = cls._configuration(
            context.resource
        )

        engine = str(
            configuration.get(
                "engine",
                "",
            )
        ).lower()

        if not engine.startswith(
            "aurora"
        ):
            return None

        cluster_id = (
            configuration.get(
                "db_cluster_identifier"
            )
            or configuration.get(
                "db_cluster_id"
            )
        )

        value = {
            "engine":
                engine,
        }

        if cluster_id:
            value["cluster_identifier"] = (
                cluster_id
            )

        return cls._build_finding(
            context=context,
            finding_type=(
                "rds_aurora_cluster_context"
            ),
            title="Aurora cluster context",
            severity="info",
            confidence="high",
            reason=(
                "This instance belongs to an Aurora cluster. "
                "Rightsizing should consider writer/reader roles "
                "and cluster availability together."
            ),
            statements=[
                cls._statement(
                    "aurora",
                    value,
                    "Aurora engine detected.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category":
                    "optimization_context",
                **value,
            },
            recommendation_eligible=False,
        )

    @classmethod
    def _check_public_accessibility(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "public_accessibility",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        publicly_accessible = cls._configuration(
            context.resource
        ).get(
            "publicly_accessible"
        )

        if publicly_accessible is not True:
            return None

        return cls._build_finding(
            context=context,
            finding_type=(
                "rds_public_accessibility"
            ),
            title="RDS instance is publicly accessible",
            severity="low",
            confidence="high",
            reason=(
                "The RDS instance is publicly accessible. "
                "Review whether public access is required."
            ),
            statements=[
                cls._statement(
                    "public_access",
                    True,
                    "Public accessibility is enabled.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category":
                    "security_review",
                "publicly_accessible":
                    True,
            },
            recommendation_eligible=False,
        )

    # ==================================================================
    # I/O PRESSURE
    # ==================================================================

    @classmethod
    def _check_io_pressure(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = cls._policy(
            context
        ).get(
            "io_pressure",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        minimum_coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        metric_names = (
            "ReadIOPS",
            "WriteIOPS",
        )

        if not cls._usable_metric_set(
            context,
            metric_names,
            minimum_coverage,
        ):
            return None

        read_value = cls._metric_value(
            cls._metric(
                context,
                "ReadIOPS",
            )
        )

        write_value = cls._metric_value(
            cls._metric(
                context,
                "WriteIOPS",
            )
        )

        if (
            read_value is None
            or write_value is None
        ):
            return None

        total_iops = read_value + write_value

        iops_threshold = float(
            policy.get(
                "high_iops",
                1000.0,
            )
        )

        if total_iops < iops_threshold:
            return None

        return cls._build_finding(
            context=context,
            finding_type=(
                "rds_io_pressure"
            ),
            title="RDS I/O pressure",
            severity="medium",
            confidence="medium",
            reason=(
                "Observed I/O activity indicates that storage "
                "performance should be reviewed before reducing "
                "capacity."
            ),
            statements=[
                cls._statement(
                    "io",
                    {
                        "read_iops":
                            round(read_value, 2),
                        "write_iops":
                            round(write_value, 2),
                        "total_iops":
                            round(total_iops, 2),
                    },
                    "Sustained I/O throughput indicates the "
                    "instance is under IOPS pressure.",
                    [
                        "CloudWatch.ReadIOPS",
                        "CloudWatch.WriteIOPS",
                    ],
                )
            ],
            metadata={
                "category":
                    "capacity_review",
                "read_iops":
                    read_value,
                "write_iops":
                    write_value,
                "total_iops":
                    total_iops,
                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )

    @staticmethod
    def _statement(
        name: str,
        value: Any,
        description: str,
        source: list[str],
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=source,
        )

    @classmethod
    def _build_finding(
        cls,
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
        limitations: list[str] | None = None,
    ) -> Finding:

        metrics = context.metrics()

        metric_evidence = {
            name:
                context.metric_summary(name)
            for name in metrics
            if isinstance(
                metrics.get(name),
                dict,
            )
        }

        configuration = cls._configuration(
            context.resource
        )

        filtered_configuration = {
            key:
                configuration.get(key)
            for key in RDS_CONFIGURATION_FIELDS
            if key in configuration
        }

        derived = context.derived()

        if not isinstance(
            derived,
            dict,
        ):
            derived = {}

        billing = context.billing()

        if not isinstance(
            billing,
            dict,
        ):
            billing = {}

        evidence = Evidence(
            metrics=metric_evidence,

            configuration=filtered_configuration,

            topology=context.topology(),

            billing=dict(billing),

            resource={
                "resource_id":
                    context.resource_id,
                "resource_type":
                    context.resource_type,
                "region":
                    context.region,
                "instance_class":
                    configuration.get(
                        "instance_class"
                    ),
                "engine":
                    configuration.get(
                        "engine"
                    ),
            },

            derived={
                **derived,
                "cloudtrail_resize_history": cls._cloudtrail(context),
                "analysis_category":
                    metadata.get(
                        "category"
                    ),
            },

            data_quality={
                **context.collector_data_quality(),
                "metric_count":
                    len(metric_evidence),
            },
        )

        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or cls.resource_type
            ),

            resource_id=(
                context.resource_id
                or "unknown"
            ),

            analyzer=cls.name,

            analyzer_version=cls.version,

            severity=severity.lower(),

            confidence=confidence.lower(),

            reason=reason,

            conditions=statements,

            evidence=evidence,

            observation_period=(
                cls._observation_period(
                    context
                )
            ),

            limitations=(
                limitations
                or []
            ),

            metadata=metadata,

            recommendation_eligible=(
                recommendation_eligible
            ),

            aggregation_scope="resource",
        )

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        observation = (
            context.observation_period
        )

        if isinstance(
            observation,
            dict,
        ):
            return ObservationPeriod(
                start=observation.get(
                    "start"
                ),
                end=observation.get(
                    "end"
                ),
                duration_seconds=observation.get(
                    "duration_seconds"
                ),
            )

        cloudwatch = context.cloudwatch()

        if not isinstance(
            cloudwatch,
            dict,
        ):
            return None

        start = (
            cloudwatch.get("start")
            or cloudwatch.get("metric_start")
        )

        end = (
            cloudwatch.get("end")
            or cloudwatch.get("metric_end")
        )

        if not start and not end:
            return None

        return ObservationPeriod(
            start=start,
            end=end,
        )