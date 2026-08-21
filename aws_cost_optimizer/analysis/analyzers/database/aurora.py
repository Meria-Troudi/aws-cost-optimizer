"""
Aurora cost optimization analyzer.

Rules
-----
1. Provisioned Aurora cluster may be suitable for Serverless v2 review.
2. Aurora reader is lightly utilized.
3. Aurora has more readers than observed workload appears to require.
4. Aurora cluster has no observed activity.
5. Aurora Serverless v2 capacity range may be too restrictive.
6. Aurora backup retention review.
7. Aurora Global Database cost review.
8. Aurora legacy Serverless v1 review.

Design
------
The analyzer evaluates evidence collected by AuroraClusterCollector.

It does not:
- invent a Serverless v2 capacity range
- invent a replacement DB instance class
- estimate savings without billing/pricing evidence
- automatically recommend deleting a reader
- assume that low CPU alone makes Serverless v2 cheaper
- assume that zero observed traffic proves the cluster can be deleted
"""

from __future__ import annotations

from typing import Any

from ....base import Analyzer
from ....condition import EvidenceStatement
from ....context import AnalysisContext
from ....evidence import Evidence
from ....finding import Finding, ObservationPeriod
from ....registry import register


# ======================================================================
# DEFAULT POLICY
# ======================================================================

DEFAULT_POLICY = {
    "serverless_v2": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,

        "minimum_observation_days": 14.0,

        "low_cpu_average_percent": 20.0,
        "low_cpu_maximum_percent": 60.0,

        "low_connections_average": 5.0,

        "minimum_reader_count": 0,

        "recommendation_eligible": True,
    },

    "reader_utilization": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,

        "connections_max": 2.0,

        "cpu_average_max_percent": 15.0,
        "cpu_maximum_max_percent": 50.0,

        "network_receive_bytes_per_second_max": 1024.0,
        "network_transmit_bytes_per_second_max": 1024.0,

        "recommendation_eligible": True,
    },

    "reader_count": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,

        "minimum_readers": 1,

        "recommendation_eligible": True,
    },

    "idle": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,

        "cpu_average_max_percent": 5.0,
        "cpu_maximum_max_percent": 25.0,

        "connections_max": 0.0,
        "read_iops_max": 1.0,
        "write_iops_max": 1.0,

        "recommendation_eligible": True,
    },

    "serverless_capacity": {
        "enabled": True,

        "minimum_metric_coverage": 0.80,

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
}


@register
class AuroraAnalyzer(Analyzer):

    name = "aurora"
    version = "1.0"

    SUPPORTED_RESOURCE_TYPES = {
        "aurora_cluster",
        "aurora",
    }

    # ==================================================================
    # SUPPORT
    # ==================================================================

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            in self.SUPPORTED_RESOURCE_TYPES
        )

    # ==================================================================
    # ANALYZE
    # ==================================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        if not self._cluster_eligible(context):
            return []

        checks = (
            self._check_serverless_v2_suitability,
            self._check_reader_underutilization,
            self._check_reader_count_review,
            self._check_idle_cluster,
            self._check_serverless_capacity_pressure,
            self._check_backup_retention,
            self._check_global_database,
            self._check_serverless_v1,
        )

        findings: list[Finding] = []

        for check in checks:

            finding = check(context)

            if finding is not None:
                findings.append(finding)

        return findings

    # ==================================================================
    # POLICY
    # ==================================================================

    @classmethod
    def _policy(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        policy = {
            category:
                dict(values)
                if isinstance(values, dict)
                else values
            for category, values
            in DEFAULT_POLICY.items()
        }

        for root_name in (
            "analyzer_config",
            "analysis_config",
            "config",
            "optimization_profile",
            "analysis_profile",
        ):

            root = context.resource.get(
                root_name
            )

            if not isinstance(root, dict):
                continue

            configured = root.get(
                "aurora"
            )

            if not isinstance(configured, dict):
                continue

            for category, values in configured.items():

                if isinstance(values, dict):

                    current = policy.get(
                        category,
                        {},
                    )

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

    # ==================================================================
    # RESOURCE HELPERS
    # ==================================================================

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    @staticmethod
    def _list(
        value: Any,
    ) -> list[Any]:

        return (
            value
            if isinstance(value, list)
            else []
        )

    @staticmethod
    def _number(
        value: Any,
    ) -> float | None:

        if value is None:
            return None

        if isinstance(value, bool):
            return float(int(value))

        try:
            return float(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

    @classmethod
    def _configuration(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            context.configuration()
        )

    @classmethod
    def _cluster(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            cls._configuration(context).get(
                "cluster"
            )
        )

    @classmethod
    def _storage(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            cls._configuration(context).get(
                "storage"
            )
        )

    @classmethod
    def _backup(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            cls._configuration(context).get(
                "backup"
            )
        )

    @classmethod
    def _serverless_v2(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            cls._configuration(context).get(
                "serverless_v2"
            )
        )

    @classmethod
    def _serverless_v1(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            cls._configuration(context).get(
                "serverless_v1"
            )
        )

    @classmethod
    def _relationships(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            context.resource.get(
                "relationships"
            )
        )

    @classmethod
    def _members(
        cls,
        context: AnalysisContext,
    ) -> list[dict[str, Any]]:

        return [
            value
            for value in cls._list(
                cls._relationships(context).get(
                    "members"
                )
            )
            if isinstance(value, dict)
        ]

    @classmethod
    def _reader_instances(
        cls,
        context: AnalysisContext,
    ) -> list[str]:

        return [
            str(value)
            for value in cls._list(
                cls._relationships(context).get(
                    "reader_instances"
                )
            )
            if value
        ]

    @classmethod
    def _reader_count(
        cls,
        context: AnalysisContext,
    ) -> int:

        explicit = cls._relationships(
            context
        ).get("reader_count")

        parsed = cls._number(explicit)

        if parsed is not None:
            return int(parsed)

        return len(
            cls._reader_instances(context)
        )

    @classmethod
    def _writer_count(
        cls,
        context: AnalysisContext,
    ) -> int:

        explicit = cls._relationships(
            context
        ).get("writer_count")

        parsed = cls._number(explicit)

        if parsed is not None:
            return int(parsed)

        return sum(
            1
            for member
            in cls._members(context)
            if member.get("is_writer")
        )

    # ==================================================================
    # CLOUDWATCH
    # ==================================================================

    @classmethod
    def _cloudwatch(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            context.cloudwatch()
        )

    @classmethod
    def _cloudwatch_group(
        cls,
        context: AnalysisContext,
        group: str,
    ) -> dict[str, Any]:

        return cls._dict(
            cls._cloudwatch(context).get(
                group
            )
        )

    @classmethod
    def _metrics(
        cls,
        context: AnalysisContext,
        group: str,
    ) -> dict[str, Any]:

        return cls._dict(
            cls._cloudwatch_group(
                context,
                group,
            ).get(
                "metrics"
            )
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

        return (
            metric
            if isinstance(metric, dict)
            else {}
        )

    @classmethod
    def _metric_observed(
        cls,
        metric: dict[str, Any],
    ) -> bool:

        return (
            metric.get("has_data") is True
            and
            (
                metric.get("status")
                in {"ok", "partial", None}
            )
        )

    @classmethod
    def _metric_value(
        cls,
        metric: dict[str, Any],
        field: str = "average",
    ) -> float | None:

        if not cls._metric_observed(metric):
            return None

        return cls._number(
            metric.get(field)
        )

    @classmethod
    def _coverage(
        cls,
        metric: dict[str, Any],
    ) -> float:

        value = cls._number(
            metric.get(
                "coverage_ratio"
            )
        )

        if value is not None:

            if value > 1:
                return value / 100.0

            return value

        value = cls._number(
            metric.get(
                "coverage_percent"
            )
        )

        if value is not None:
            return value / 100.0

        return 0.0

    @classmethod
    def _metric_ready(
        cls,
        context: AnalysisContext,
        group: str,
        name: str,
        minimum_coverage: float,
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

        if cls._metric_value(
            metric,
            "average",
        ) is None:
            return False

        if (
            require_maximum
            and
            cls._metric_value(
                metric,
                "maximum",
            ) is None
        ):
            return False

        return (
            cls._coverage(metric)
            >= minimum_coverage
        )

    # ==================================================================
    # OBSERVATION PERIOD
    # ==================================================================

    @classmethod
    def _observation_days(
        cls,
        context: AnalysisContext,
    ) -> float | None:

        observation = context.observation_period

        if not isinstance(
            observation,
            dict,
        ):
            cloudwatch = cls._cloudwatch(
                context
            )

            observation = {
                "start":
                    cloudwatch.get(
                        "analysis_start"
                    )
                    or cloudwatch.get(
                        "start"
                    ),

                "end":
                    cloudwatch.get(
                        "analysis_end"
                    )
                    or cloudwatch.get(
                        "end"
                    ),
            }

        start = observation.get("start")
        end = observation.get("end")

        if not start or not end:
            return None

        try:

            from datetime import datetime

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

            return (
                end_dt - start_dt
            ).total_seconds() / 86400.0

        except (
            TypeError,
            ValueError,
        ):
            return None

    # ==================================================================
    # ELIGIBILITY
    # ==================================================================

    @classmethod
    def _cluster_eligible(
        cls,
        context: AnalysisContext,
    ) -> bool:

        status = str(
            cls._cluster(context).get(
                "status"
            )
            or ""
        ).lower()

        return status in {
            "available",
        }

    @classmethod
    def _minimum_observation_met(
        cls,
        context: AnalysisContext,
        policy: dict[str, Any],
    ) -> bool:

        required = float(
            policy.get(
                "minimum_observation_days",
                14.0,
            )
        )

        observed = cls._observation_days(
            context
        )

        return (
            observed is not None
            and
            observed >= required
        )

    # ==================================================================
    # RULE 1 — SERVERLESS V2 SUITABILITY
    # ==================================================================

    def _check_serverless_v2_suitability(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(
            context
        ).get(
            "serverless_v2",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        serverless = self._serverless_v2(
            context
        )

        if serverless.get(
            "enabled"
        ):
            return None

        if not self._minimum_observation_met(
            context,
            policy,
        ):
            return None

        minimum_coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

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

        if not (
            self._metric_ready(
                context,
                "cluster",
                "CPUUtilization",
                minimum_coverage,
                require_maximum=True,
            )
            and
            self._metric_ready(
                context,
                "cluster",
                "DatabaseConnections",
                minimum_coverage,
            )
        ):
            return None

        cpu_average = self._metric_value(
            cpu,
            "average",
        )

        cpu_maximum = self._metric_value(
            cpu,
            "maximum",
        )

        connections_average = (
            self._metric_value(
                connections,
                "average",
            )
        )

        if (
            cpu_average is None
            or cpu_maximum is None
            or connections_average is None
        ):
            return None

        if (
            cpu_average
            >
            float(
                policy.get(
                    "low_cpu_average_percent",
                    20.0,
                )
            )
        ):
            return None

        if (
            cpu_maximum
            >
            float(
                policy.get(
                    "low_cpu_maximum_percent",
                    60.0,
                )
            )
        ):
            return None

        if (
            connections_average
            >
            float(
                policy.get(
                    "low_connections_average",
                    5.0,
                )
            )
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "aurora_serverless_v2_suitability_review"
            ),
            title=(
                "Aurora provisioned cluster may suit "
                "a Serverless v2 review"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "The Aurora cluster is provisioned and "
                "shows sustained low resource activity. "
                "Aurora Serverless v2 should be evaluated "
                "against the workload's scaling pattern, "
                "capacity requirements, reader topology, "
                "and current pricing."
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
                    name="serverless_v2_currently_enabled",
                    value=False,
                    description=(
                        "Serverless v2 is not currently "
                        "configured for the cluster."
                    ),
                    source=[
                        "RDS.DescribeDBClusters"
                    ],
                    observed=True,
                ),
            ],
            metadata={
                "category":
                    "architecture_review",

                "current_model":
                    "provisioned",

                "candidate_model":
                    "aurora_serverless_v2",

                "cpu_average_percent":
                    cpu_average,

                "cpu_maximum_percent":
                    cpu_maximum,

                "connections_average":
                    connections_average,

                "reader_count":
                    self._reader_count(
                        context
                    ),
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
            limitations=[
                (
                    "Low utilization does not by itself prove "
                    "that Serverless v2 is cheaper."
                ),
                (
                    "Compatibility, minimum/maximum ACU requirements, "
                    "reader count, workload latency, and pricing "
                    "must be evaluated."
                ),
                (
                    "The analyzer does not select ACU limits."
                ),
            ],
        )

    # ==================================================================
    # RULE 2 — READER UNDERUTILIZATION
    # ==================================================================

    def _check_reader_underutilization(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(
            context
        ).get(
            "reader_utilization",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        readers = self._reader_instances(
            context
        )

        if not readers:
            return None

        minimum_coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        candidates = []

        for reader_id in readers:

            cpu = self._metric(
                context,
                f"instances",
                "CPUUtilization",
            )

            # Instance-level metrics are stored below the
            # instance identifier in this collector. The
            # normal path is handled by _instance_metric().
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
                self._metric_ready_instance(
                    cpu,
                    minimum_coverage,
                    require_maximum=True,
                )
                and
                self._metric_ready_instance(
                    connections,
                    minimum_coverage,
                )
            ):
                continue

            cpu_average = self._metric_value(
                cpu
            )

            cpu_maximum = self._metric_value(
                cpu,
                "maximum",
            )

            connection_average = self._metric_value(
                connections
            )

            rx_average = self._metric_value(
                rx
            )

            tx_average = self._metric_value(
                tx
            )

            if (
                cpu_average is None
                or cpu_maximum is None
                or connection_average is None
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

            if (
                rx_average is not None
                and
                rx_average
                >
                float(
                    policy.get(
                        "network_receive_bytes_per_second_max",
                        1024.0,
                    )
                )
            ):
                continue

            if (
                tx_average is not None
                and
                tx_average
                >
                float(
                    policy.get(
                        "network_transmit_bytes_per_second_max",
                        1024.0,
                    )
                )
            ):
                continue

            candidates.append(
                {
                    "reader_instance":
                        reader_id,

                    "cpu_average_percent":
                        cpu_average,

                    "cpu_maximum_percent":
                        cpu_maximum,

                    "connections_average":
                        connection_average,

                    "network_receive_bytes_per_second":
                        rx_average,

                    "network_transmit_bytes_per_second":
                        tx_average,
                }
            )

        if not candidates:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "aurora_reader_underutilized"
            ),
            title=(
                "Aurora reader is lightly utilized"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                f"{len(candidates)} Aurora reader(s) "
                "show sustained low CPU, connection, "
                "and network activity."
            ),
            statements=[
                self._statement(
                    name="underutilized_readers",
                    value=candidates,
                    description=(
                        "Aurora reader instances with "
                        "low observed workload."
                    ),
                    source=[
                        "RDS",
                        "CloudWatch"
                    ],
                    observed=True,
                )
            ],
            metadata={
                "category":
                    "reader_utilization",

                "candidate_count":
                    len(candidates),

                "readers":
                    candidates,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
            limitations=[
                (
                    "A lightly used reader may be required "
                    "for failover, reporting, latency, or "
                    "future workload growth."
                ),
                (
                    "The finding does not instruct the system "
                    "to delete a reader."
                ),
            ],
        )

    # ==================================================================
    # RULE 3 — READER COUNT REVIEW
    # ==================================================================

    def _check_reader_count_review(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(
            context
        ).get(
            "reader_count",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        reader_count = self._reader_count(
            context
        )

        minimum = int(
            self._number(
                policy.get(
                    "minimum_readers",
                    1,
                )
            )
            or 1
        )

        if reader_count < minimum:
            return None

        underutilized_readers = []

        # Reader utilization may already have produced a stronger
        # finding. Here we only provide topology-level context.
        readers = self._reader_instances(
            context
        )

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

            cpu_avg = self._metric_value(
                cpu
            )

            conn_avg = self._metric_value(
                connections
            )

            if (
                cpu_avg is not None
                and conn_avg is not None
                and cpu_avg <= 15.0
                and conn_avg <= 2.0
            ):
                underutilized_readers.append(
                    reader_id
                )

        if not underutilized_readers:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "aurora_reader_count_review"
            ),
            title=(
                "Aurora reader capacity should be reviewed"
            ),
            severity="low",
            confidence="medium",
            reason=(
                f"The cluster has {reader_count} reader(s), "
                "and one or more readers show low observed "
                "workload. Review whether all reader capacity "
                "is still required."
            ),
            statements=[
                self._statement(
                    name="reader_count",
                    value=reader_count,
                    description=(
                        "Current Aurora reader count."
                    ),
                    source=[
                        "RDS.DescribeDBClusters"
                    ],
                    observed=True,
                ),
                self._statement(
                    name="lightly_used_readers",
                    value=underutilized_readers,
                    description=(
                        "Readers with low observed utilization."
                    ),
                    source=[
                        "CloudWatch"
                    ],
                    observed=True,
                ),
            ],
            metadata={
                "category":
                    "reader_capacity",

                "reader_count":
                    reader_count,

                "lightly_used_readers":
                    underutilized_readers,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
            limitations=[
                (
                    "Reader redundancy may be required for "
                    "availability and failover."
                ),
                (
                    "The analyzer does not choose how many "
                    "readers to remove."
                ),
            ],
        )

    # ==================================================================
    # RULE 4 — IDLE CLUSTER
    # ==================================================================

    def _check_idle_cluster(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(
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

        minimum_coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        required = (
            "CPUUtilization",
            "DatabaseConnections",
            "ReadIOPS",
            "WriteIOPS",
        )

        metrics = {}

        for name in required:

            if not self._metric_ready(
                context,
                "cluster",
                name,
                minimum_coverage,
                require_maximum=(
                    name == "CPUUtilization"
                ),
            ):
                return None

            metrics[name] = self._metric(
                context,
                "cluster",
                name,
            )

        cpu_average = self._metric_value(
            metrics["CPUUtilization"]
        )

        cpu_maximum = self._metric_value(
            metrics["CPUUtilization"],
            "maximum",
        )

        connections = self._metric_value(
            metrics["DatabaseConnections"]
        )

        read_iops = self._metric_value(
            metrics["ReadIOPS"]
        )

        write_iops = self._metric_value(
            metrics["WriteIOPS"]
        )

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
            title="Aurora cluster has very low observed activity",
            severity="medium",
            confidence="high",
            reason=(
                "Aurora CPU, connection, and I/O metrics "
                "all indicate very low observed activity "
                "during the analysis period."
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
                    "ReadIOPS",
                ),
                self._metric_statement(
                    context,
                    "cluster",
                    "WriteIOPS",
                ),
            ],
            metadata={
                "category":
                    "unused_resource",

                "cpu_average_percent":
                    cpu_average,

                "cpu_maximum_percent":
                    cpu_maximum,

                "connections":
                    connections,

                "read_iops":
                    read_iops,

                "write_iops":
                    write_iops,

                "reader_count":
                    self._reader_count(
                        context
                    ),
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
            limitations=[
                (
                    "Low observed activity does not prove "
                    "that the cluster can be deleted."
                ),
                (
                    "Scheduled workloads and failover "
                    "dependencies may not appear in the window."
                ),
            ],
        )

    # ==================================================================
    # RULE 5 — SERVERLESS CAPACITY PRESSURE
    # ==================================================================

    def _check_serverless_capacity_pressure(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(
            context
        ).get(
            "serverless_capacity",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        serverless = self._serverless_v2(
            context
        )

        if not serverless.get(
            "enabled"
        ):
            return None

        metric = self._metric(
            context,
            "cluster",
            "ACUUtilization",
        )

        if not self._metric_observed(
            metric
        ):
            return None

        utilization = self._metric_value(
            metric
        )

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
            finding_type=(
                "aurora_serverless_capacity_pressure"
            ),
            title=(
                "Aurora Serverless v2 capacity is frequently high"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                f"Observed Aurora Serverless capacity "
                f"utilization is approximately "
                f"{utilization:.1f}%, exceeding the "
                "configured review threshold."
            ),
            statements=[
                self._metric_statement(
                    context,
                    "cluster",
                    "ACUUtilization",
                ),
            ],
            metadata={
                "category":
                    "serverless_capacity",

                "acu_utilization_percent":
                    utilization,

                "threshold_percent":
                    threshold,

                "min_capacity":
                    serverless.get(
                        "min_capacity"
                    ),

                "max_capacity":
                    serverless.get(
                        "max_capacity"
                    ),
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
            limitations=[
                (
                    "High ACU utilization does not prove that "
                    "the cluster needs a different architecture."
                ),
                (
                    "The analyzer does not automatically change "
                    "the maximum ACU."
                ),
            ],
        )

    # ==================================================================
    # RULE 6 — BACKUP RETENTION
    # ==================================================================

    def _check_backup_retention(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(
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

        retention = self._number(
            self._backup(context).get(
                "backup_retention_days"
            )
        )

        if retention is None:
            return None

        threshold = int(
            self._number(
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
            finding_type=(
                "aurora_backup_retention_review"
            ),
            title="Aurora backup retention is high",
            severity="low",
            confidence="medium",
            reason=(
                f"Aurora backup retention is configured "
                f"for {int(retention)} days, above the "
                "configured review threshold."
            ),
            statements=[
                self._statement(
                    name="backup_retention_days",
                    value=int(retention),
                    description=(
                        "Configured Aurora backup retention."
                    ),
                    source=[
                        "RDS.DescribeDBClusters"
                    ],
                    observed=True,
                )
            ],
            metadata={
                "category":
                    "backup_configuration",

                "backup_retention_days":
                    int(retention),

                "review_threshold_days":
                    threshold,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
            limitations=[
                (
                    "Retention may be required by recovery "
                    "and compliance policy."
                ),
            ],
        )

    # ==================================================================
    # RULE 7 — GLOBAL DATABASE
    # ==================================================================

    def _check_global_database(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(
            context
        ).get(
            "global_database",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        relationships = self._relationships(
            context
        )

        global_cluster = (
            relationships.get(
                "global_cluster_identifier"
            )
        )

        if not global_cluster:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "aurora_global_database_cost_review"
            ),
            title="Aurora Global Database configuration",
            severity="info",
            confidence="high",
            reason=(
                "The Aurora cluster participates in an "
                "Aurora Global Database. Review whether "
                "all cross-Region replicas and replication "
                "capacity are still required."
            ),
            statements=[
                self._statement(
                    name="global_cluster_identifier",
                    value=global_cluster,
                    description=(
                        "Aurora Global Database identifier."
                    ),
                    source=[
                        "RDS.DescribeDBClusters"
                    ],
                    observed=True,
                )
            ],
            metadata={
                "category":
                    "global_database",

                "global_cluster_identifier":
                    global_cluster,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
            limitations=[
                (
                    "Global Database replicas may be required "
                    "for disaster recovery or cross-Region reads."
                ),
                (
                    "The collector does not currently establish "
                    "whether a secondary Region is unused."
                ),
            ],
        )

    # ==================================================================
    # RULE 8 — SERVERLESS V1
    # ==================================================================

    def _check_serverless_v1(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(
            context
        ).get(
            "serverless_v1",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        configuration = self._serverless_v1(
            context
        )

        if not configuration.get(
            "enabled"
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "aurora_serverless_v1_review"
            ),
            title="Aurora Serverless v1 configuration",
            severity="low",
            confidence="high",
            reason=(
                "The cluster uses Aurora Serverless v1. "
                "Review the current Aurora architecture and "
                "supported migration options."
            ),
            statements=[
                self._statement(
                    name="serverless_v1",
                    value=configuration,
                    description=(
                        "Aurora Serverless v1 configuration."
                    ),
                    source=[
                        "RDS.DescribeDBClusters"
                    ],
                    observed=True,
                )
            ],
            metadata={
                "category":
                    "architecture_review",

                "serverless_v1":
                    configuration,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    False,
                )
            ),
            limitations=[
                (
                    "The analyzer does not invent a migration "
                    "target or migration plan."
                ),
            ],
        )

    # ==================================================================
    # INSTANCE METRIC HELPERS
    # ==================================================================

    @classmethod
    def _instance_metric(
        cls,
        context: AnalysisContext,
        instance_id: str,
        metric_name: str,
    ) -> dict[str, Any]:

        instances = cls._dict(
            cls._cloudwatch(context).get(
                "instances"
            )
        )

        instance = cls._dict(
            instances.get(
                instance_id
            )
        )

        metrics = cls._dict(
            instance.get(
                "metrics"
            )
        )

        metric = metrics.get(
            metric_name
        )

        return (
            metric
            if isinstance(metric, dict)
            else {}
        )

    @classmethod
    def _metric_ready_instance(
        cls,
        metric: dict[str, Any],
        minimum_coverage: float,
        *,
        require_maximum: bool = False,
    ) -> bool:

        if not cls._metric_observed(
            metric
        ):
            return False

        if cls._metric_value(
            metric
        ) is None:
            return False

        if (
            require_maximum
            and
            cls._metric_value(
                metric,
                "maximum",
            ) is None
        ):
            return False

        return (
            cls._coverage(metric)
            >= minimum_coverage
        )

    # ==================================================================
    # EVIDENCE
    # ==================================================================

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
            description=(
                f"Observed Aurora {name} metric."
            ),
            source=[
                "CloudWatch.AWS/RDS"
            ],
            evidence_keys=[
                (
                    f"observations.cloudwatch."
                    f"{group}.metrics.{name}"
                )
            ],
            observed=(
                cls._metric_observed(metric)
            ),
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
            evidence_keys=list(
                evidence_keys or []
            ),
            unit=unit,
            observed=observed,
        )

    # ==================================================================
    # FINDING
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
                context.resource_type
                or "aurora_cluster"
            ),

            resource_id=(
                context.resource_id
                or "unknown"
            ),

            analyzer=self.name,

            analyzer_version=self.version,

            severity=severity.lower(),

            confidence=confidence.lower(),

            reason=reason,

            conditions=statements,

            evidence=self._build_evidence(
                context,
                metadata,
            ),

            observation_period=(
                self._observation_period(
                    context
                )
            ),

            limitations=list(
                limitations
            ),

            metadata=dict(
                metadata
            ),

            recommendation_eligible=(
                recommendation_eligible
            ),

            aggregation_scope="resource",
        )

    # ==================================================================
    # EVIDENCE
    # ==================================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: dict[str, Any],
    ) -> Evidence:

        cloudwatch = self._cloudwatch(
            context
        )

        configuration = self._configuration(
            context
        )

        relationships = self._relationships(
            context
        )

        return Evidence(
            metrics={
                key:
                    value
                for key, value
                in self._dict(
                    cloudwatch.get(
                        "cluster"
                    )
                ).get(
                    "metrics",
                    {}
                ).items()
            }
            if isinstance(
                self._dict(
                    cloudwatch.get(
                        "cluster"
                    )
                ).get(
                    "metrics"
                ),
                dict,
            )
            else {},

            configuration=dict(
                configuration
            ),

            topology=dict(
                context.topology()
                or {}
            ),

            billing=dict(
                context.billing()
                or {}
            ),

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,

                "cluster_identifier":
                    self._cluster(context).get(
                        "identifier"
                    ),

                "engine":
                    self._cluster(context).get(
                        "engine"
                    ),
            },

            derived={
                "relationships":
                    relationships,

                **metadata,
            },

            data_quality={
                **(
                    context.collector_data_quality()
                    if hasattr(
                        context,
                        "collector_data_quality",
                    )
                    else {}
                ),

                "cloudwatch_status":
                    cloudwatch.get(
                        "status"
                    ),

                "cloudwatch_data_quality":
                    cloudwatch.get(
                        "data_quality",
                        {},
                    ),
            },
        )

    # ==================================================================
    # OBSERVATION PERIOD
    # ==================================================================

    @classmethod
    def _observation_period(
        cls,
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        value = context.observation_period

        if isinstance(
            value,
            dict,
        ):

            return ObservationPeriod(
                start=value.get("start"),
                end=value.get("end"),
                duration_seconds=value.get(
                    "duration_seconds"
                ),
            )

        cloudwatch = cls._cloudwatch(
            context
        )

        start = (
            cloudwatch.get(
                "analysis_start"
            )
            or cloudwatch.get(
                "start"
            )
        )

        end = (
            cloudwatch.get(
                "analysis_end"
            )
            or cloudwatch.get(
                "end"
            )
        )

        if not start and not end:
            return None

        return ObservationPeriod(
            start=start,
            end=end,
        )