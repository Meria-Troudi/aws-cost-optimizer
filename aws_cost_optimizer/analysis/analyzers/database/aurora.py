"""
Aurora cost optimization analyzer.

Purpose
-------
Generate evidence-based AWS Aurora findings.

Analyzer responsibilities
-------------------------
This analyzer evaluates:

1. Stopped Aurora clusters
2. Aurora Serverless v2 suitability
3. Aurora Reader Auto Scaling suitability
4. Aurora reader underutilization
5. Aurora reader topology
6. Very-low-activity Aurora clusters
7. Aurora Serverless v2 capacity pressure
8. Aurora backup retention
9. Aurora Global Database configuration
10. Aurora Serverless v1 configuration
11. Aurora I/O-Optimized storage suitability

Design principles
-----------------
- Collectors provide evidence; analyzers interpret evidence.
- Do not infer cost attribution from workload evidence.
- Historical/service-level billing must never be presented as
  current-resource cost.
- Do not produce savings estimates without defensible
  resource-attributed cost.
- Missing or failed telemetry must not be interpreted as zero usage.
- Lifecycle state is authoritative where available.
- Recommendations are intentionally kept separate from findings.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ...base import Analyzer
from ...condition import EvidenceStatement
from ...context import AnalysisContext
from ...evidence import Evidence
from ...financial import calculate_savings
from ...finding import Finding, ObservationPeriod
from ...registry import register

# DEFAULT POLICY

DEFAULT_POLICY: dict[str, dict[str, Any]] = {
    "serverless_v2": {
        "enabled": True,
        "minimum_observation_days": 14.0,
        "low_cpu_average_percent": 25.0,
        "low_cpu_maximum_percent": 70.0,
        "low_connections_average": 10.0,
        "recommendation_eligible": True,
    },
    "reader_autoscaling": {
        "enabled": True,
        "minimum_readers": 1,
        "reader_cpu_average_min_percent": 20.0,
        "reader_cpu_maximum_min_percent": 50.0,
        "reader_connections_average_min": 5.0,
        "minimum_observation_days": 14.0,
        "recommendation_eligible": True,
    },
    "reader_utilization": {
        "enabled": True,
        "connections_max": 2.0,
        "cpu_average_max_percent": 15.0,
        "cpu_maximum_max_percent": 50.0,
        "network_receive_bytes_per_second_max": 1024.0,
        "network_transmit_bytes_per_second_max": 1024.0,
        "minimum_observation_days": 14.0,
        "recommendation_eligible": False,
    },
    "reader_count": {
        "enabled": True,
        "minimum_readers": 1,
        "recommendation_eligible": False,
    },
    "idle": {
        "enabled": True,
        "minimum_observation_days": 14.0,
        "cpu_average_max_percent": 5.0,
        "cpu_maximum_max_percent": 25.0,
        "connections_max": 0.0,
        "read_iops_max": 1.0,
        "write_iops_max": 1.0,
        "recommendation_eligible": False,
    },
    "serverless_capacity": {
        "enabled": True,
        "high_capacity_utilization_percent": 80.0,
        "recommendation_eligible": False,
    },
    "backup_retention": {
        "enabled": True,
        "review_threshold_days": 14,
        "recommendation_eligible": False,
    },
    "global_database": {
        "enabled": True,
        "recommendation_eligible": False,
    },
    "serverless_v1": {
        "enabled": True,
        "recommendation_eligible": False,
    },
    "io_optimized_review": {
        "enabled": True,
        "minimum_observation_days": 14.0,
        "minimum_read_write_iops": 1000.0,
        "recommendation_eligible": False,
    },
    "stopped_cluster": {
        "enabled": True,
        "recommendation_eligible": True,
    },
}


# FINDING TITLES

TITLES: dict[str, str] = {
    "aurora_serverless_v2_cost_opportunity": "Provisioned Aurora Cluster With Sustained Low Workload",
    "aurora_reader_autoscaling_cost_opportunity": "Aurora Reader With Sustained Workload Without Auto Scaling",
    "aurora_io_optimized_high_io": "Aurora Standard Storage With High I/O Activity",
    "aurora_no_observed_activity": "Aurora Cluster With Very Low Activity",
    "aurora_reader_underutilized": "Lightly Utilized Aurora Reader",
    "aurora_reader_capacity_excess": "Aurora Cluster Has Additional Reader Capacity",
    "aurora_serverless_capacity_pressure": "Aurora Serverless v2 With High ACU Utilization",
    "aurora_backup_retention_excess": "Aurora Backup Retention Exceeds Configured Threshold",
    "aurora_global_database": "Aurora Cluster Is Part of a Global Database",
    "aurora_serverless_v1_detected": "Aurora Cluster Uses Serverless v1",
    "aurora_stopped_cluster": "Stopped Aurora Cluster — Amazon RDS",
}


# GENERIC HELPERS


def _dict(value: Any) -> dict[str, Any]:
    """Return value when it is a dictionary, otherwise an empty dictionary."""
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    """Return value when it is a list, otherwise an empty list."""
    return value if isinstance(value, list) else []


def _number(value: Any) -> float | None:
    """Safely convert a value to float."""
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _boolean(value: Any) -> bool | None:
    """Safely normalize boolean-like values."""
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {"true", "yes", "1", "enabled"}:
            return True

        if normalized in {"false", "no", "0", "disabled"}:
            return False

    return None


# ANALYZER


@register
class AuroraAnalyzer(Analyzer):

    name = "aurora"
    version = "4.0"

    SUPPORTED_RESOURCE_TYPES = {
        "aurora_cluster",
        "aurora",
    }

    _dict = staticmethod(_dict)

    # SUPPORT

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:
        return context.resource_type in self.SUPPORTED_RESOURCE_TYPES

    # ANALYZE

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        checks = (
            # Lifecycle must be checked first.
            self._check_stopped_cluster,
            # Primary optimization opportunities.
            self._check_serverless_v2_cost_opportunity,
            self._check_reader_autoscaling_cost_opportunity,
            # Diagnostic / review findings.
            self._check_reader_underutilization,
            self._check_reader_count_review,
            self._check_idle_cluster,
            self._check_serverless_capacity_pressure,
            self._check_io_optimized_storage,
            self._check_backup_retention,
            self._check_global_database,
            self._check_serverless_v1,
        )

        findings: list[Finding] = []

        for check in checks:
            try:
                finding = check(context)

            except Exception as exc:
                print(
                    "[ERROR] Aurora detector "
                    f"{check.__name__} failed for "
                    f"{context.resource_id}: {exc}"
                )
                continue

            if finding is not None:
                findings.append(finding)

        return findings

    # POLICY

    @classmethod
    def _policy(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        policy: dict[str, Any] = {
            name: dict(value) if isinstance(value, dict) else value
            for name, value in DEFAULT_POLICY.items()
        }

        configuration_roots = (
            "analyzer_config",
            "analysis_config",
            "config",
            "optimization_profile",
            "analysis_profile",
        )

        for root_name in configuration_roots:

            root = context.resource.get(root_name)

            if not isinstance(root, dict):
                continue

            configured = root.get("aurora")

            if not isinstance(configured, dict):
                continue

            for category, values in configured.items():

                if isinstance(values, dict):

                    current = policy.get(category, {})

                    if not isinstance(current, dict):
                        current = {}

                    policy[category] = {
                        **current,
                        **values,
                    }

                else:
                    policy[category] = values

            break

        return policy

    # CONFIGURATION

    @classmethod
    def _configuration(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return cls._dict(context.configuration())

    @classmethod
    def _cluster(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return cls._dict(cls._configuration(context).get("cluster"))

    @classmethod
    def _backup(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return cls._dict(cls._configuration(context).get("backup"))

    @classmethod
    def _serverless_v2(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return cls._dict(cls._configuration(context).get("serverless_v2"))

    @classmethod
    def _serverless_v1(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return cls._dict(cls._configuration(context).get("serverless_v1"))

    # RELATIONSHIPS

    @classmethod
    def _relationships(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return cls._dict(context.resource.get("relationships"))

    @classmethod
    def _reader_instances(
        cls,
        context: AnalysisContext,
    ) -> list[str]:

        return [
            str(value)
            for value in _list(cls._relationships(context).get("reader_instances"))
            if value
        ]

    @classmethod
    def _reader_count(
        cls,
        context: AnalysisContext,
    ) -> int:

        relationships = cls._relationships(context)

        explicit = _number(relationships.get("reader_count"))

        if explicit is not None:
            return max(0, int(explicit))

        return len(cls._reader_instances(context))

    # CLOUDWATCH

    @classmethod
    def _cloudwatch(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return cls._dict(context.cloudwatch())

    @classmethod
    def _group(
        cls,
        context: AnalysisContext,
        name: str,
    ) -> dict[str, Any]:

        return cls._dict(cls._cloudwatch(context).get(name))

    @classmethod
    def _metrics(
        cls,
        context: AnalysisContext,
        group: str,
    ) -> dict[str, Any]:

        return cls._dict(
            cls._group(
                context,
                group,
            ).get("metrics")
        )

    @classmethod
    def _metric(
        cls,
        context: AnalysisContext,
        group: str,
        name: str,
    ) -> dict[str, Any]:

        metric = cls._metrics(
            context,
            group,
        ).get(name)

        return metric if isinstance(metric, dict) else {}

    # METRIC VALIDATION

    @staticmethod
    def _metric_observed(
        metric: dict[str, Any],
    ) -> bool:

        if not isinstance(metric, dict):
            return False

        if metric.get("has_data") is not True:
            return False

        status = str(metric.get("status") or "ok").strip().lower()

        if status == "error":
            return False

        return metric.get("average") is not None or metric.get("value") is not None

    @classmethod
    def _metric_value(
        cls,
        metric: dict[str, Any],
        field: str = "average",
    ) -> float | None:

        if not cls._metric_observed(metric):
            return None

        return _number(metric.get(field))

    @classmethod
    def _metric_ready(
        cls,
        context: AnalysisContext,
        group: str,
        name: str,
        *,
        require_maximum: bool = False,
    ) -> bool:

        metric = cls._metric(
            context,
            group,
            name,
        )

        if not cls._metric_observed(metric):
            return False

        if cls._metric_value(metric) is None:
            return False

        if require_maximum:
            if (
                cls._metric_value(
                    metric,
                    "maximum",
                )
                is None
            ):
                return False

        return True

    # INSTANCE METRICS

    @classmethod
    def _instance_metric(
        cls,
        context: AnalysisContext,
        instance_id: str,
        name: str,
    ) -> dict[str, Any]:

        instances = cls._dict(cls._cloudwatch(context).get("instances"))

        instance = cls._dict(instances.get(instance_id))

        metrics = cls._dict(instance.get("metrics"))

        return cls._dict(metrics.get(name))

    # OBSERVATION PERIOD

    @classmethod
    def _observation_period_data(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = context.observation_period

        if isinstance(value, dict):
            return value

        cloudwatch = cls._cloudwatch(context)

        return {
            "start": (cloudwatch.get("analysis_start") or cloudwatch.get("start")),
            "end": (cloudwatch.get("analysis_end") or cloudwatch.get("end")),
        }

    @classmethod
    def _observation_days(
        cls,
        context: AnalysisContext,
    ) -> float | None:

        value = cls._observation_period_data(context)

        start = value.get("start")
        end = value.get("end")

        if not start or not end:
            return None

        try:
            start_dt = (
                start
                if isinstance(start, datetime)
                else datetime.fromisoformat(
                    str(start).replace(
                        "Z",
                        "+00:00",
                    )
                )
            )

            end_dt = (
                end
                if isinstance(end, datetime)
                else datetime.fromisoformat(
                    str(end).replace(
                        "Z",
                        "+00:00",
                    )
                )
            )

            duration = (end_dt - start_dt).total_seconds()

            if duration < 0:
                return None

            return duration / 86400.0

        except (
            TypeError,
            ValueError,
        ):
            return None

    @classmethod
    def _minimum_observation_days(
        cls,
        context: AnalysisContext,
        category: str,
        default: float = 14.0,
    ) -> float:

        policy = cls._policy(context).get(
            category,
            {},
        )

        if not isinstance(policy, dict):
            return default

        value = _number(
            policy.get(
                "minimum_observation_days",
                default,
            )
        )

        if value is None:
            return default

        return max(0.0, value)

    @classmethod
    def _observation_ready(
        cls,
        context: AnalysisContext,
        category: str,
        default: float = 14.0,
    ) -> tuple[bool, float | None]:

        days = cls._observation_days(context)

        if days is None:
            return False, None

        minimum = cls._minimum_observation_days(
            context,
            category,
            default,
        )

        return days >= minimum, days

    # BILLING

    @classmethod
    def _billing(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return _dict(context.billing())

    @classmethod
    def _billing_status(
        cls,
        context: AnalysisContext,
    ) -> str:

        billing = cls._billing(context)

        scope = str(billing.get("attribution_scope") or "").strip().lower()

        if scope == "resource":
            return "resource_attributed"

        if scope in {
            "historical",
            "historical_resource",
        }:
            return "historical"

        if scope in {
            "service",
            "service_level",
        }:
            return "service_level"

        if scope in {
            "collection_plan",
            "plan",
        }:
            return "collection_plan"

        return "unavailable"

    @classmethod
    def _current_resource_cost(
        cls,
        context: AnalysisContext,
    ) -> float | None:
        """
        Return current cost only when billing explicitly attributes
        the amount to the current resource.

        Historical, service-level, and collection-plan costs are
        intentionally rejected.
        """

        billing = cls._billing(context)

        if not billing:
            return None

        scope = str(billing.get("attribution_scope") or "").strip().lower()

        resource_attributed = billing.get("resource_cost_attributed")

        claimable = _number(billing.get("claimable_resource_cost"))

        amount = _number(billing.get("amount"))

        if (
            scope == "resource"
            and resource_attributed is True
            and claimable is not None
            and claimable >= 0
        ):
            return claimable

        if (
            scope == "resource"
            and resource_attributed is True
            and amount is not None
            and amount >= 0
        ):
            return amount

        return None

    # STOPPED CLUSTER

    def _check_stopped_cluster(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "stopped_cluster",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        cluster = self._cluster(context)

        status = str(cluster.get("status") or "").strip().lower()

        if status != "stopped":
            return None

        configuration = self._configuration(context)
        backup = self._backup(context)
        observations = self._observations(context)
        relationships = self._relationships(context)

        backup_obs = _dict(observations.get("backup"))

        automated_backup_obs = _dict(observations.get("automated_backup"))

        lifecycle = _dict(observations.get("lifecycle"))

        manual_snapshot_count = _number(backup_obs.get("manual_count"))

        automated_snapshot_count = _number(backup_obs.get("automated_count"))

        automated_backup_resource_count = _number(
            automated_backup_obs.get("backup_count")
        )

        retention_days = _number(backup.get("backup_retention_days"))

        deletion_protection = configuration.get("deletion_protection")

        writer_count = _number(relationships.get("writer_count")) or 0.0

        reader_count = _number(relationships.get("reader_count")) or 0.0

        member_count = writer_count + reader_count

        events = _list(lifecycle.get("events"))

        stop_events = [
            event
            for event in events
            if (isinstance(event, dict) and event.get("event_name") == "StopDBCluster")
        ]

        start_events = [
            event
            for event in events
            if (isinstance(event, dict) and event.get("event_name") == "StartDBCluster")
        ]

        last_stop = stop_events[-1] if stop_events else None

        last_start = start_events[-1] if start_events else None

        statements: list[EvidenceStatement] = [
            self._statement(
                name="cluster_identifier",
                value=cluster.get("identifier"),
                description="Aurora DB cluster identifier.",
                source=["RDS.DescribeDBClusters"],
                observed=(cluster.get("identifier") is not None),
            ),
            self._statement(
                name="cluster_status",
                value="stopped",
                description=("Current Aurora DB cluster lifecycle state."),
                source=["RDS.DescribeDBClusters"],
                observed=True,
            ),
        ]

        if retention_days is not None:
            statements.append(
                self._statement(
                    name="backup_retention_days",
                    value=int(retention_days),
                    description=(
                        "Configured Aurora automated " "backup retention period."
                    ),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                    unit="days",
                )
            )

        if manual_snapshot_count is not None:
            statements.append(
                self._statement(
                    name="manual_snapshot_count",
                    value=int(manual_snapshot_count),
                    description=("Current manual Aurora cluster " "snapshot count."),
                    source=["RDS.DescribeDBClusterSnapshots"],
                    observed=True,
                    unit="snapshots",
                )
            )

        if automated_snapshot_count is not None:
            statements.append(
                self._statement(
                    name="automated_snapshot_count",
                    value=int(automated_snapshot_count),
                    description=("Current automated Aurora cluster " "snapshot count."),
                    source=["RDS.DescribeDBClusterSnapshots"],
                    observed=True,
                    unit="snapshots",
                )
            )

        if automated_backup_resource_count is not None:
            statements.append(
                self._statement(
                    name="automated_backup_resource_count",
                    value=int(automated_backup_resource_count),
                    description=(
                        "Automated backup resources retained " "for this cluster."
                    ),
                    source=["RDS.DescribeDBClusterAutomatedBackups"],
                    observed=True,
                    unit="backups",
                )
            )

        statements.append(
            self._statement(
                name="deletion_protection",
                value=deletion_protection,
                description=(
                    "Whether deletion protection is enabled " "for the Aurora cluster."
                ),
                source=["RDS.DescribeDBClusters"],
                observed=(deletion_protection is not None),
            )
        )

        statements.append(
            self._statement(
                name="member_count",
                value=int(member_count),
                description=(
                    "Number of DB instances currently " "associated with the cluster."
                ),
                source=["RDS.DescribeDBClusters"],
                observed=True,
                unit="instances",
            )
        )

        return self._finding(
            context=context,
            finding_type="aurora_stopped_cluster",
            title=TITLES["aurora_stopped_cluster"],
            severity="medium",
            confidence="high",
            reason=(
                "The Aurora DB cluster is currently stopped. "
                "DB instance-hour charges are not incurred "
                "while the cluster is stopped, but storage "
                "and backup-related charges can continue. "
                "Review whether the cluster is still required "
                "or should be retired instead of repeatedly "
                "stopped and restarted."
            ),
            statements=statements,
            metadata={
                "category": "lifecycle_optimization",
                "cluster_status": "stopped",
                "backup_retention_days": retention_days,
                "manual_snapshot_count": (manual_snapshot_count),
                "automated_snapshot_count": (automated_snapshot_count),
                "automated_backup_resource_count": (automated_backup_resource_count),
                "deletion_protection": deletion_protection,
                "member_count": member_count,
                "last_stop_event": last_stop,
                "last_start_event": last_start,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
            cost_optimization_type="review",
        )

    # SERVERLESS V2

    def _check_serverless_v2_cost_opportunity(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "serverless_v2",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        cluster = self._cluster(context)

        if str(cluster.get("status") or "").lower() != "available":
            return None

        serverless = self._serverless_v2(context)

        enabled = _boolean(serverless.get("enabled"))

        if enabled is True:
            return None

        ready, observation_days = self._observation_ready(
            context,
            "serverless_v2",
        )

        if not ready or observation_days is None:
            return None

        if not self._metric_ready(
            context,
            "cluster",
            "CPUUtilization",
            require_maximum=True,
        ):
            return None

        if not self._metric_ready(
            context,
            "cluster",
            "DatabaseConnections",
        ):
            return None

        cpu = self._metric(
            context,
            "cluster",
            "CPUUtilization",
        )

        connections = self._metric(
            context,
            "cluster",
            "DatabaseConnections",
        )

        cpu_average = self._metric_value(cpu)
        cpu_maximum = self._metric_value(
            cpu,
            "maximum",
        )
        connections_average = self._metric_value(connections)

        if any(
            value is None
            for value in (
                cpu_average,
                cpu_maximum,
                connections_average,
            )
        ):
            return None

        if cpu_average > float(
            policy.get(
                "low_cpu_average_percent",
                25.0,
            )
        ):
            return None

        if cpu_maximum > float(
            policy.get(
                "low_cpu_maximum_percent",
                70.0,
            )
        ):
            return None

        if connections_average > float(
            policy.get(
                "low_connections_average",
                10.0,
            )
        ):
            return None

        return self._finding(
            context=context,
            finding_type=("aurora_serverless_v2_cost_opportunity"),
            title=TITLES["aurora_serverless_v2_cost_opportunity"],
            severity="medium",
            confidence="high",
            reason=(
                f"The provisioned Aurora cluster shows "
                f"sustained low workload over "
                f"{observation_days:.0f} days "
                f"(CPU average {cpu_average:.1f}%, "
                f"CPU maximum {cpu_maximum:.1f}%, "
                f"database connections average "
                f"{connections_average:.1f}). "
                "Aurora Serverless v2 should be evaluated "
                "as a potentially more elastic capacity model."
            ),
            statements=[
                self._metric_statement(
                    context,
                    "cluster",
                    "CPUUtilization",
                ),
                self._metric_statement(
                    context,
                    "cluster",
                    "DatabaseConnections",
                ),
                self._statement(
                    name="current_capacity_model",
                    value="provisioned",
                    description=("Current Aurora capacity model."),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                ),
                self._statement(
                    name="serverless_v2_enabled",
                    value=False,
                    description=(
                        "Aurora Serverless v2 is not currently " "configured."
                    ),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                ),
            ],
            metadata={
                "category": "capacity_optimization",
                "optimization": ("evaluate_aurora_serverless_v2"),
                "billing_status": (self._billing_status(context)),
                "billing_is_not_resource_attributed": (
                    self._current_resource_cost(context) is None
                ),
                "observation_days": observation_days,
                "cpu_average_percent": cpu_average,
                "cpu_maximum_percent": cpu_maximum,
                "connections_average": connections_average,
                "current_model": "provisioned",
                "candidate_model": "aurora_serverless_v2",
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
        )

    # READER AUTO SCALING

    def _check_reader_autoscaling_cost_opportunity(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "reader_autoscaling",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        cluster = self._cluster(context)

        if str(cluster.get("status") or "").lower() != "available":
            return None

        reader_count = self._reader_count(context)

        minimum_readers = int(
            _number(
                policy.get(
                    "minimum_readers",
                    1,
                )
            )
            or 1
        )

        if reader_count < minimum_readers:
            return None

        ready, observation_days = self._observation_ready(
            context,
            "reader_autoscaling",
        )

        if not ready or observation_days is None:
            return None

        relationships = self._relationships(context)

        autoscaling = _dict(relationships.get("reader_autoscaling"))

        if autoscaling.get("status") == "error":
            return None

        configured = _boolean(autoscaling.get("configured"))

        if configured is not False:
            return None

        if not self._metric_ready(
            context,
            "reader",
            "CPUUtilization",
            require_maximum=True,
        ):
            return None

        if not self._metric_ready(
            context,
            "reader",
            "DatabaseConnections",
        ):
            return None

        cpu = self._metric(
            context,
            "reader",
            "CPUUtilization",
        )

        connections = self._metric(
            context,
            "reader",
            "DatabaseConnections",
        )

        cpu_average = self._metric_value(cpu)
        cpu_maximum = self._metric_value(
            cpu,
            "maximum",
        )
        connection_average = self._metric_value(connections)

        if any(
            value is None
            for value in (
                cpu_average,
                cpu_maximum,
                connection_average,
            )
        ):
            return None

        average_cpu_trigger = cpu_average >= float(
            policy.get(
                "reader_cpu_average_min_percent",
                20.0,
            )
        )

        peak_cpu_trigger = cpu_maximum >= float(
            policy.get(
                "reader_cpu_maximum_min_percent",
                50.0,
            )
        )

        connections_trigger = connection_average >= float(
            policy.get(
                "reader_connections_average_min",
                5.0,
            )
        )

        sustained_demand = average_cpu_trigger and connections_trigger

        peak_plus_connections = peak_cpu_trigger and connections_trigger

        if not (sustained_demand or peak_plus_connections):
            return None

        return self._finding(
            context=context,
            finding_type=("aurora_reader_autoscaling_cost_opportunity"),
            title=TITLES["aurora_reader_autoscaling_cost_opportunity"],
            severity="medium",
            confidence="high",
            reason=(
                f"The Aurora cluster has {reader_count} "
                f"reader(s) with observed reader workload, "
                f"including {cpu_average:.1f}% average CPU, "
                f"{cpu_maximum:.1f}% maximum CPU, and "
                f"{connection_average:.1f} average connections. "
                "Aurora Reader Auto Scaling should be evaluated "
                "so reader capacity can respond to workload."
            ),
            statements=[
                self._statement(
                    name="reader_count",
                    value=reader_count,
                    description=("Current Aurora reader count."),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                    unit="readers",
                ),
                self._metric_statement(
                    context,
                    "reader",
                    "CPUUtilization",
                ),
                self._metric_statement(
                    context,
                    "reader",
                    "DatabaseConnections",
                ),
                self._statement(
                    name="reader_autoscaling_configured",
                    value=False,
                    description=(
                        "Aurora Reader Auto Scaling is not " "currently configured."
                    ),
                    source=["Application Auto Scaling"],
                    observed=True,
                ),
            ],
            metadata={
                "category": "reader_capacity_optimization",
                "optimization": ("enable_aurora_reader_autoscaling"),
                "billing_status": (self._billing_status(context)),
                "observation_days": observation_days,
                "reader_count": reader_count,
                "cpu_average_percent": cpu_average,
                "cpu_maximum_percent": cpu_maximum,
                "connections_average": connection_average,
                "autoscaling_configured": False,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
        )

    # READER UNDERUTILIZATION

    def _check_reader_underutilization(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "reader_utilization",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        ready, observation_days = self._observation_ready(
            context,
            "reader_utilization",
        )

        if not ready:
            return None

        readers = self._reader_instances(context)

        if not readers:
            return None

        candidates: list[dict[str, Any]] = []

        for reader_id in readers:

            cpu = self._instance_metric(
                context,
                reader_id,
                "CPUUtilization",
            )

            connections = self._instance_metric(
                context,
                reader_id,
                "DatabaseConnections",
            )

            rx = self._instance_metric(
                context,
                reader_id,
                "NetworkReceiveThroughput",
            )

            tx = self._instance_metric(
                context,
                reader_id,
                "NetworkTransmitThroughput",
            )

            if not (
                self._metric_observed(cpu)
                and self._metric_observed(connections)
                and self._metric_observed(rx)
                and self._metric_observed(tx)
            ):
                continue

            cpu_average = self._metric_value(cpu)
            cpu_maximum = self._metric_value(
                cpu,
                "maximum",
            )
            connection_average = self._metric_value(connections)
            rx_average = self._metric_value(rx)
            tx_average = self._metric_value(tx)

            if any(
                value is None
                for value in (
                    cpu_average,
                    cpu_maximum,
                    connection_average,
                    rx_average,
                    tx_average,
                )
            ):
                continue

            if rx_average > float(
                policy.get(
                    "network_receive_bytes_per_second_max",
                    1024.0,
                )
            ):
                continue

            if tx_average > float(
                policy.get(
                    "network_transmit_bytes_per_second_max",
                    1024.0,
                )
            ):
                continue

            if cpu_average > float(
                policy.get(
                    "cpu_average_max_percent",
                    15.0,
                )
            ):
                continue

            if cpu_maximum > float(
                policy.get(
                    "cpu_maximum_max_percent",
                    50.0,
                )
            ):
                continue

            if connection_average > float(
                policy.get(
                    "connections_max",
                    2.0,
                )
            ):
                continue

            candidates.append(
                {
                    "reader_instance": reader_id,
                    "cpu_average_percent": cpu_average,
                    "cpu_maximum_percent": cpu_maximum,
                    "connections_average": connection_average,
                    "network_receive_bytes_per_second": rx_average,
                    "network_transmit_bytes_per_second": tx_average,
                }
            )

        if not candidates:
            return None

        return self._finding(
            context=context,
            finding_type="aurora_reader_underutilized",
            title=TITLES["aurora_reader_underutilized"],
            severity="low",
            confidence="high",
            reason=(
                f"{len(candidates)} Aurora reader(s) "
                f"show sustained low observed workload "
                f"over approximately "
                f"{observation_days:.0f} days."
            ),
            statements=[
                self._statement(
                    name="underutilized_readers",
                    value=candidates,
                    description=("Aurora readers with low observed workload."),
                    source=[
                        "RDS",
                        "CloudWatch",
                    ],
                    observed=True,
                )
            ],
            metadata={
                "category": "reader_utilization",
                "observation_days": observation_days,
                "candidate_count": len(candidates),
                "readers": candidates,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
        )

    # READER COUNT

    def _check_reader_count_review(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "reader_count",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        relationships = self._relationships(context)

        # Do not infer topology from an absent relationship object.
        if not relationships:
            return None

        reader_instances = self._reader_instances(context)

        explicit_count = _number(relationships.get("reader_count"))

        if explicit_count is None and not reader_instances:
            return None

        reader_count = self._reader_count(context)

        minimum = int(
            _number(
                policy.get(
                    "minimum_readers",
                    1,
                )
            )
            or 1
        )

        if reader_count < minimum:
            return None

        return self._finding(
            context=context,
            finding_type="aurora_reader_capacity_excess",
            title=TITLES["aurora_reader_capacity_excess"],
            severity="low",
            confidence="high",
            reason=(
                f"The cluster currently has {reader_count} "
                "reader(s). Review whether the current reader "
                "topology remains justified by workload, "
                "availability, and read-scaling requirements."
            ),
            statements=[
                self._statement(
                    name="reader_count",
                    value=reader_count,
                    description=("Current Aurora reader count."),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                    unit="readers",
                )
            ],
            metadata={
                "category": "reader_capacity",
                "reader_count": reader_count,
                "reader_instances": reader_instances,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
        )

    # IDLE CLUSTER

    def _check_idle_cluster(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "idle",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        if not self._available_cluster(context):
            return None

        ready, observation_days = self._observation_ready(
            context,
            "idle",
        )

        if not ready or observation_days is None:
            return None

        required = (
            "CPUUtilization",
            "DatabaseConnections",
            "VolumeReadIOPs",
            "VolumeWriteIOPs",
        )

        metrics: dict[str, dict[str, Any]] = {}

        for name in required:

            if not self._metric_ready(
                context,
                "cluster",
                name,
                require_maximum=(name == "CPUUtilization"),
            ):
                return None

            metrics[name] = self._metric(
                context,
                "cluster",
                name,
            )

        cpu_average = self._metric_value(metrics["CPUUtilization"])

        cpu_maximum = self._metric_value(
            metrics["CPUUtilization"],
            "maximum",
        )

        connections = self._metric_value(metrics["DatabaseConnections"])

        read_iops = self._metric_value(metrics["VolumeReadIOPs"])

        write_iops = self._metric_value(metrics["VolumeWriteIOPs"])

        if any(
            value is None
            for value in (
                cpu_average,
                cpu_maximum,
                connections,
                read_iops,
                write_iops,
            )
        ):
            return None

        if cpu_average > float(
            policy.get(
                "cpu_average_max_percent",
                5.0,
            )
        ):
            return None

        if cpu_maximum > float(
            policy.get(
                "cpu_maximum_max_percent",
                25.0,
            )
        ):
            return None

        if connections > float(
            policy.get(
                "connections_max",
                0.0,
            )
        ):
            return None

        if read_iops > float(
            policy.get(
                "read_iops_max",
                1.0,
            )
        ):
            return None

        if write_iops > float(
            policy.get(
                "write_iops_max",
                1.0,
            )
        ):
            return None

        return self._finding(
            context=context,
            finding_type="aurora_no_observed_activity",
            title=TITLES["aurora_no_observed_activity"],
            severity="medium",
            confidence="high",
            reason=(
                "Aurora CPU, connection, and I/O metrics "
                "indicate very low observed activity over "
                f"approximately {observation_days:.0f} days."
            ),
            statements=[
                self._metric_statement(
                    context,
                    "cluster",
                    "CPUUtilization",
                ),
                self._metric_statement(
                    context,
                    "cluster",
                    "DatabaseConnections",
                ),
                self._metric_statement(
                    context,
                    "cluster",
                    "VolumeReadIOPs",
                ),
                self._metric_statement(
                    context,
                    "cluster",
                    "VolumeWriteIOPs",
                ),
            ],
            metadata={
                "category": "unused_resource",
                "observation_days": observation_days,
                "cpu_average_percent": cpu_average,
                "cpu_maximum_percent": cpu_maximum,
                "connections": connections,
                "read_iops": read_iops,
                "write_iops": write_iops,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
        )

    # SERVERLESS CAPACITY

    def _check_serverless_capacity_pressure(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "serverless_capacity",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        serverless = self._serverless_v2(context)

        if _boolean(serverless.get("enabled")) is not True:
            return None

        metric = self._metric(
            context,
            "cluster",
            "ACUUtilization",
        )

        if not self._metric_observed(metric):
            return None

        utilization = self._metric_value(metric)

        if utilization is None:
            return None

        threshold = float(
            policy.get(
                "high_capacity_utilization_percent",
                80.0,
            )
        )

        if utilization < threshold:
            return None

        return self._finding(
            context=context,
            finding_type=("aurora_serverless_capacity_pressure"),
            title=TITLES["aurora_serverless_capacity_pressure"],
            severity="medium",
            confidence="high",
            reason=(
                "Aurora Serverless v2 shows high observed "
                f"ACU utilization at approximately "
                f"{utilization:.1f}%."
            ),
            statements=[
                self._metric_statement(
                    context,
                    "cluster",
                    "ACUUtilization",
                )
            ],
            metadata={
                "category": "serverless_capacity",
                "acu_utilization_percent": utilization,
                "min_capacity": (serverless.get("min_capacity")),
                "max_capacity": (serverless.get("max_capacity")),
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
        )

    # I/O OPTIMIZED

    def _check_io_optimized_storage(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(self._policy(context).get("io_optimized_review"))

        if not policy.get("enabled", True):
            return None

        ready, observation_days = self._observation_ready(
            context,
            "io_optimized_review",
        )

        if not ready or observation_days is None:
            return None

        if not self._available_cluster(context):
            return None

        storage = _dict(self._configuration(context).get("storage"))

        storage_type = str(storage.get("storage_type") or "").strip().lower()

        if storage_type != "aurora":
            return None

        if not self._metric_ready(
            context,
            "cluster",
            "VolumeReadIOPs",
        ):
            return None

        if not self._metric_ready(
            context,
            "cluster",
            "VolumeWriteIOPs",
        ):
            return None

        read_iops = self._metric_value(
            self._metric(
                context,
                "cluster",
                "VolumeReadIOPs",
            )
        )

        write_iops = self._metric_value(
            self._metric(
                context,
                "cluster",
                "VolumeWriteIOPs",
            )
        )

        if read_iops is None or write_iops is None:
            return None

        total_iops = read_iops + write_iops

        threshold = float(
            policy.get(
                "minimum_read_write_iops",
                1000.0,
            )
        )

        if total_iops < threshold:
            return None

        return self._finding(
            context=context,
            finding_type=("aurora_io_optimized_high_io"),
            title=TITLES["aurora_io_optimized_high_io"],
            severity="low",
            confidence="medium",
            reason=(
                "The Aurora cluster uses standard Aurora "
                "storage and observed combined read/write "
                f"I/O is approximately {total_iops:.1f} IOPS "
                f"over {observation_days:.0f} days. Review "
                "whether Aurora I/O-Optimized economics are "
                "appropriate for this workload."
            ),
            statements=[
                self._metric_statement(
                    context,
                    "cluster",
                    "VolumeReadIOPs",
                ),
                self._metric_statement(
                    context,
                    "cluster",
                    "VolumeWriteIOPs",
                ),
                self._statement(
                    name="storage_type",
                    value=storage_type,
                    description=("Current Aurora storage configuration."),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                ),
            ],
            metadata={
                "category": "storage_cost_review",
                "optimization": ("evaluate_aurora_io_optimized"),
                "storage_type": storage_type,
                "observation_days": observation_days,
                "read_iops": read_iops,
                "write_iops": write_iops,
                "total_iops": total_iops,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
        )

    # BACKUP RETENTION

    def _check_backup_retention(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "backup_retention",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        retention = _number(self._backup(context).get("backup_retention_days"))

        if retention is None:
            return None

        threshold = int(
            _number(
                policy.get(
                    "review_threshold_days",
                    14,
                )
            )
            or 14
        )

        if retention <= threshold:
            return None

        return self._finding(
            context=context,
            finding_type=("aurora_backup_retention_excess"),
            title=TITLES["aurora_backup_retention_excess"],
            severity="low",
            confidence="high",
            reason=(
                f"Aurora backup retention is configured "
                f"for {int(retention)} days, which exceeds "
                f"the configured review threshold of "
                f"{threshold} days."
            ),
            statements=[
                self._statement(
                    name="backup_retention_days",
                    value=int(retention),
                    description=("Configured Aurora backup retention."),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                    unit="days",
                )
            ],
            metadata={
                "category": "backup_configuration",
                "backup_retention_days": int(retention),
                "review_threshold_days": threshold,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
        )

    # GLOBAL DATABASE

    def _check_global_database(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "global_database",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        identifier = self._relationships(context).get("global_cluster_identifier")

        if not identifier:
            return None

        return self._finding(
            context=context,
            finding_type=("aurora_global_database"),
            title=TITLES["aurora_global_database"],
            severity="info",
            confidence="high",
            reason=(
                "The Aurora cluster participates in an "
                "Aurora Global Database. Review whether "
                "cross-Region replicas and replication "
                "capacity remain necessary for the workload."
            ),
            statements=[
                self._statement(
                    name="global_cluster_identifier",
                    value=identifier,
                    description=("Aurora Global Database identifier."),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                )
            ],
            metadata={
                "category": "global_database",
                "global_cluster_identifier": identifier,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
        )

    # SERVERLESS V1

    def _check_serverless_v1(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "serverless_v1",
            {},
        )

        if not isinstance(policy, dict):
            policy = {}

        if not policy.get("enabled", True):
            return None

        configuration = self._serverless_v1(context)

        if _boolean(configuration.get("enabled")) is not True:
            return None

        return self._finding(
            context=context,
            finding_type=("aurora_serverless_v1_detected"),
            title=TITLES["aurora_serverless_v1_detected"],
            severity="low",
            confidence="high",
            reason=(
                "The Aurora cluster uses Serverless v1. "
                "Review the current architecture and "
                "available migration options."
            ),
            statements=[
                self._statement(
                    name="serverless_v1",
                    value=configuration,
                    description=("Aurora Serverless v1 configuration."),
                    source=["RDS.DescribeDBClusters"],
                    observed=True,
                )
            ],
            metadata={
                "category": "architecture_review",
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
        )

    # OBSERVATIONS

    @classmethod
    def _observations(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:
        return cls._dict(context.observations())

    # EVIDENCE

    @classmethod
    def _metric_statement(
        cls,
        context: AnalysisContext,
        group: str,
        name: str,
    ) -> EvidenceStatement:

        metric = cls._metric(
            context,
            group,
            name,
        )

        return cls._statement(
            name=name,
            value=metric,
            description=(f"Observed Aurora {name} metric."),
            source=["CloudWatch.AWS/RDS"],
            evidence_keys=["observations.cloudwatch." f"{group}.metrics.{name}"],
            observed=(cls._metric_observed(metric)),
        )

    @staticmethod
    def _statement(
        *,
        name: str,
        value: Any,
        description: str,
        source: list[str],
        evidence_keys: list[str] | None = None,
        unit: str | None = None,
        observed: bool | None = None,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=list(source),
            evidence_keys=list(evidence_keys or []),
            unit=unit,
            observed=observed,
        )

    # FINDING BUILDER

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
        cost_optimization_type: str = "review",
    ) -> Finding:

        # Add current resource-attributed cost only when it is
        # defensible. This keeps the financial layer consistent
        # across every detector.
        resource_cost = self._current_resource_cost(context)

        enriched_metadata = dict(metadata)

        if resource_cost is not None:
            enriched_metadata["current_monthly_resource_cost"] = resource_cost

        enriched_metadata["billing_status"] = self._billing_status(context)

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=(context.resource_type or "aurora_cluster"),
            resource_id=(context.resource_id or "unknown"),
            analyzer=self.name,
            analyzer_version=self.version,
            severity=str(severity).lower(),
            confidence=str(confidence).lower(),
            reason=reason,
            conditions=statements,
            evidence=self._build_evidence(
                context,
                enriched_metadata,
            ),
            observation_period=(self._observation_period(context)),
            metadata={
                **enriched_metadata,
                "region": context.region,
                "recommendation_eligible": (recommendation_eligible),
            },
            recommendation_eligible=(recommendation_eligible),
            impact=self._build_impact(
                context,
                enriched_metadata,
                cost_optimization_type,
            ),
            cost_optimization_type=(cost_optimization_type),
            aggregation_scope="resource",
        )

    # FINANCIAL IMPACT

    @classmethod
    def _build_impact(
        cls,
        context: AnalysisContext,
        metadata: dict[str, Any],
        cost_optimization_type: str = "review",
    ) -> dict[str, Any]:

        cost = _number(metadata.get("current_monthly_resource_cost"))

        billing = cls._billing(context)

        scope = str(billing.get("attribution_scope") or "").strip().lower()

        # No defensible resource attribution:
        # do not invent a savings amount.
        if cost is None or scope != "resource":
            return {
                "currency": "USD",
                "amount": None,
                "monthly_savings": None,
                "annual_savings": None,
                "confidence": None,
                "attribution_scope": (scope or None),
                "savings_available": False,
            }

        calculated = calculate_savings(
            cost,
            confidence=None,
            attribution_scope=scope,
            full_elimination=(cost_optimization_type == "elimination"),
        )

        return {
            **calculated,
            "currency": "USD",
            "attribution_scope": scope,
            "savings_available": True,
        }

    # EVIDENCE OBJECT

    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: dict[str, Any],
    ) -> Evidence:

        cloudwatch = self._cloudwatch(context)

        configuration = self._configuration(context)

        relationships = self._relationships(context)

        return Evidence(
            metrics=self._metrics(
                context,
                "cluster",
            ),
            configuration=dict(configuration),
            topology=dict(context.topology() or {}),
            billing=dict(context.billing() or {}),
            resource={
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "region": context.region,
                "cluster_identifier": (self._cluster(context).get("identifier")),
                "engine": (self._cluster(context).get("engine")),
            },
            derived={
                "relationships": relationships,
                "cloudwatch": cloudwatch,
                **metadata,
            },
            data_quality={
                "cloudwatch_status": (cloudwatch.get("status")),
                "cloudwatch_data_quality": (
                    cloudwatch.get(
                        "data_quality",
                        {},
                    )
                ),
                "billing_status": (self._billing_status(context)),
            },
        )

    # OBSERVATION PERIOD OBJECT

    @classmethod
    def _observation_period(
        cls,
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        value = context.observation_period

        if isinstance(value, dict):

            return ObservationPeriod(
                start=value.get("start"),
                end=value.get("end"),
                duration_seconds=value.get("duration_seconds"),
            )

        cloudwatch = cls._cloudwatch(context)

        start = cloudwatch.get("analysis_start") or cloudwatch.get("start")

        end = cloudwatch.get("analysis_end") or cloudwatch.get("end")

        if not start and not end:
            return None

        duration_seconds = None

        if start and end:
            try:
                start_dt = (
                    start
                    if isinstance(
                        start,
                        datetime,
                    )
                    else datetime.fromisoformat(
                        str(start).replace(
                            "Z",
                            "+00:00",
                        )
                    )
                )

                end_dt = (
                    end
                    if isinstance(
                        end,
                        datetime,
                    )
                    else datetime.fromisoformat(
                        str(end).replace(
                            "Z",
                            "+00:00",
                        )
                    )
                )

                duration_seconds = max(
                    0.0,
                    (end_dt - start_dt).total_seconds(),
                )

            except (
                TypeError,
                ValueError,
            ):
                duration_seconds = None

        return ObservationPeriod(
            start=start,
            end=end,
            duration_seconds=duration_seconds,
        )

    # CLUSTER STATE

    @classmethod
    def _available_cluster(
        cls,
        context: AnalysisContext,
    ) -> bool:

        return (
            str(cls._cluster(context).get("status") or "").strip().lower()
            == "available"
        )
