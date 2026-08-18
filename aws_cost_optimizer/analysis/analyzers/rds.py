"""
RDS cost and performance optimization analyzer.

"""

from __future__ import annotations

from typing import Any

from ..base import Analyzer
from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from ..metrics import (
    metric_has_observed_data,
    metric_summary,
)
from ..registry import register


# ======================================================================
# DEFAULT CONFIGURATION
# ======================================================================

DEFAULT_IDLE_CPU_PERCENT = 5.0
DEFAULT_LOW_CPU_PERCENT = 15.0

DEFAULT_IDLE_CONNECTIONS = 0.0
DEFAULT_LOW_CONNECTIONS = 2.0

DEFAULT_IDLE_IOPS = 1.0
DEFAULT_LOW_IOPS = 10.0

DEFAULT_IDLE_NETWORK_BYTES_PER_SECOND = 1_024.0

# CloudWatch RDS ReadLatency / WriteLatency are reported in seconds.
# 20 ms = 0.020 seconds.
DEFAULT_HIGH_LATENCY_MS = 20.0

DEFAULT_STORAGE_PRESSURE_RATIO = 0.80

DEFAULT_IOPS_UNDERUSE_RATIO = 0.20

DEFAULT_HIGH_FREE_MEMORY_PRESSURE = 0.15

DEFAULT_HIGH_BACKUP_RETENTION_DAYS = 14

DEFAULT_MIN_HISTORY_EVENTS = 2


# ======================================================================
# METRIC NAMES
# ======================================================================

CPU_METRIC = "CPUUtilization"
CONNECTION_METRIC = "DatabaseConnections"

READ_IOPS_METRIC = "ReadIOPS"
WRITE_IOPS_METRIC = "WriteIOPS"

READ_LATENCY_METRIC = "ReadLatency"
WRITE_LATENCY_METRIC = "WriteLatency"

NETWORK_RX_METRIC = "NetworkReceiveThroughput"
NETWORK_TX_METRIC = "NetworkTransmitThroughput"

FREEABLE_MEMORY_METRIC = "FreeableMemory"
FREE_STORAGE_METRIC = "FreeStorageSpace"

QUEUE_DEPTH_METRIC = "DiskQueueDepth"
REPLICA_LAG_METRIC = "ReplicaLag"


# ======================================================================
# EXPECTED CLOUDWATCH STATISTICS
# ======================================================================

EXPECTED_STATISTICS = {
    CPU_METRIC: "Average",
    CONNECTION_METRIC: "Average",
    READ_IOPS_METRIC: "Average",
    WRITE_IOPS_METRIC: "Average",
    READ_LATENCY_METRIC: "Average",
    WRITE_LATENCY_METRIC: "Average",
    NETWORK_RX_METRIC: "Average",
    NETWORK_TX_METRIC: "Average",
    FREEABLE_MEMORY_METRIC: "Average",
    FREE_STORAGE_METRIC: "Average",
    QUEUE_DEPTH_METRIC: "Average",
    REPLICA_LAG_METRIC: "Average",
}


# ======================================================================
# CONFIGURATION
# ======================================================================


def _analyzer_config(
    context: AnalysisContext,
) -> dict[str, Any]:

    resource = context.resource

    for root_name in (
        "analyzer_config",
        "analysis_config",
        "config",
    ):

        root = resource.get(
            root_name
        )

        if not isinstance(
            root,
            dict,
        ):
            continue

        value = root.get(
            "rds"
        )

        if isinstance(
            value,
            dict,
        ):
            return value

    return {}


def _threshold(
    context: AnalysisContext,
    key: str,
    default: float | int | None,
) -> float | None:

    value = _analyzer_config(context).get(
        key
    )

    if value is None:

        return (
            float(default)
            if default is not None
            else None
        )

    try:

        result = float(
            value
        )

        if result < 0:
            return (
                float(default)
                if default is not None
                else None
            )

        return result

    except (
        TypeError,
        ValueError,
    ):

        return (
            float(default)
            if default is not None
            else None
        )


# ======================================================================
# GENERIC HELPERS
# ======================================================================


def _as_number(
    value: Any,
) -> float | None:

    if value is None:
        return None

    try:

        return float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return None


def _configuration(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = context.configuration()

    return (
        value
        if isinstance(value, dict)
        else {}
    )


def _is_aurora(
    context: AnalysisContext,
) -> bool:

    engine = str(
        _configuration(context).get(
            "engine",
            "",
        )
    ).lower()

    return engine.startswith(
        "aurora"
    )


def _metrics(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = context.metrics()

    return (
        value
        if isinstance(value, dict)
        else {}
    )


def _metric_value(
    context: AnalysisContext,
    name: str,
) -> float | None:

    return context.metric_value(
        name
    )


def _metric_ready(
    context: AnalysisContext,
    name: str,
) -> bool:

    metric = context.metric(
        name
    )

    if not metric_has_observed_data(
        metric
    ):
        return False

    summary = metric_summary(
        metric
    )

    expected = EXPECTED_STATISTICS.get(
        name
    )

    if expected is None:
        return True

    actual = summary.get(
        "statistic"
    )

    return (
        str(actual).strip().lower()
        == expected.lower()
    )


def _all_metrics_ready(
    context: AnalysisContext,
    names: tuple[str, ...],
) -> bool:

    return all(
        _metric_ready(
            context,
            name,
        )
        for name in names
    )


def _any_metric_ready(
    context: AnalysisContext,
    names: tuple[str, ...],
) -> bool:

    return any(
        _metric_ready(
            context,
            name,
        )
        for name in names
    )


def _instance_status(
    context: AnalysisContext,
) -> str:

    configuration = _configuration(
        context
    )

    value = (
        configuration.get(
            "status"
        )
        or context.resource.get(
            "status"
        )
        or ""
    )

    return str(
        value
    ).strip().lower()


def _is_stopped(
    context: AnalysisContext,
) -> bool:

    return (
        _instance_status(context)
        == "stopped"
    )


def _rightsizing_eligible(
    context: AnalysisContext,
) -> bool:

    return _instance_status(
        context
    ) in {
        "available",
        "backing-up",
        "storage-optimization",
    }


def _metric_analysis_allowed(
    context: AnalysisContext,
) -> bool:

    return not _is_stopped(
        context
    )


def _observation_period(
    context: AnalysisContext,
) -> ObservationPeriod | None:

    value = context.observation_period

    if isinstance(
        value,
        dict,
    ):

        return ObservationPeriod(
            start=value.get(
                "start"
            ),
            end=value.get(
                "end"
            ),
            duration_seconds=value.get(
                "duration_seconds"
            ),
        )

    cloudwatch = context.cloudwatch()

    start = (
        cloudwatch.get(
            "start"
        )
        or cloudwatch.get(
            "metric_start"
        )
    )

    end = (
        cloudwatch.get(
            "end"
        )
        or cloudwatch.get(
            "metric_end"
        )
    )

    if not start and not end:
        return None

    return ObservationPeriod(
        start=start,
        end=end,
    )


def _statement(
    *,
    name: str,
    value: Any,
    description: str,
    source: list[str],
) -> EvidenceStatement:

    return EvidenceStatement(
        name=name,
        value=value,
        description=description,
        source=list(
            source
        ),
    )


def _metric_evidence(
    context: AnalysisContext,
    name: str,
    label: str | None = None,
) -> EvidenceStatement:

    return _statement(
        name=name,
        value=context.metric_summary(
            name
        ),
        description=(
            label
            or f"{name} observation"
        ),
        source=[
            f"CloudWatch.{name}"
        ],
    )


# ======================================================================
# ANALYZER
# ======================================================================


@register
class RDSAnalyzer(Analyzer):

    name = "rds"
    version = "4.0"

    SUPPORTED_RESOURCE_TYPES = {
        "rds_instance",
        "rds",
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

        if not self.supports(
            context
        ):
            return []

        findings: list[
            Finding
        ] = []

        # --------------------------------------------------------------
        # Current resource state
        # --------------------------------------------------------------

        stopped_finding = (
            self._check_stopped_instance(
                context
            )
        )

        if stopped_finding is not None:
            findings.append(
                stopped_finding
            )

        # --------------------------------------------------------------
        # Configuration findings
        # --------------------------------------------------------------

        backup_finding = (
            self._check_backup_retention(
                context
            )
        )

        if backup_finding is not None:
            findings.append(
                backup_finding
            )

        history_finding = (
            self._check_class_change_history(
                context
            )
        )

        if history_finding is not None:
            findings.append(
                history_finding
            )

        # --------------------------------------------------------------
        # Workload findings
        #
        # Never interpret metrics from a stopped instance as workload
        # activity.
        # --------------------------------------------------------------

        if _metric_analysis_allowed(
            context
        ):

            checks = (
                self._check_idle_instance,
                self._check_low_utilization,
                self._check_memory_pressure,
                self._check_io_pressure,
                self._check_io_latency,
                self._check_storage_pressure,
                self._check_iops_underuse,
                self._check_underused_read_replica,
            )

            for check in checks:

                finding = check(
                    context
                )

                if finding is not None:
                    findings.append(
                        finding
                    )

        return findings

    # ==================================================================
    # RULE 1 — STOPPED
    # ==================================================================

    def _check_stopped_instance(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _is_stopped(
            context
        ):
            return None

        configuration = _configuration(
            context
        )

        engine = configuration.get(
            "engine"
        )

        instance_class = (
            configuration.get(
                "instance_class"
            )
            or configuration.get(
                "db_instance_class"
            )
        )

        cluster_id = configuration.get(
            "db_cluster_identifier"
        )

        statements = [
            self._configuration_evidence(
                context,
                "status",
                "stopped",
            )
        ]

        if engine:

            statements.append(
                self._configuration_evidence(
                    context,
                    "engine",
                    engine,
                )
            )

        if instance_class:

            statements.append(
                self._configuration_evidence(
                    context,
                    "instance_class",
                    instance_class,
                )
            )

        if cluster_id:

            statements.append(
                self._configuration_evidence(
                    context,
                    "db_cluster_identifier",
                    cluster_id,
                )
            )

        billing_context = (
            context.rds_billing_match()
        )

        if billing_context:

            statements.append(
                _statement(
                    name="billing_reconciliation",
                    value=billing_context,
                    description=(
                        "Historical billing/resource "
                        "reconciliation context."
                    ),
                    source=[
                        "Billing/resource reconciliation"
                    ],
                )
            )

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_stopped_instance"
            ),
            title=(
                "RDS instance is stopped"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "The current RDS instance is stopped. "
                "Review whether it is intentionally retained "
                "and whether storage, backup, recovery, scheduled "
                "restart, application, or cluster requirements "
                "justify keeping it."
            ),
            statements=statements,
            metadata={
                "status":
                    "stopped",

                "engine":
                    engine,

                "instance_class":
                    instance_class,

                "db_cluster_identifier":
                    cluster_id,

                "billing_reconciliation":
                    billing_context,

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )

    # ==================================================================
    # RULE 2 — IDLE
    # ==================================================================

    def _check_idle_instance(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _rightsizing_eligible(
            context
        ):
            return None

        required = (
            CPU_METRIC,
            CONNECTION_METRIC,
            READ_IOPS_METRIC,
            WRITE_IOPS_METRIC,
        )

        if not _all_metrics_ready(
            context,
            required,
        ):
            return None

        cpu = _metric_value(
            context,
            CPU_METRIC,
        )

        connections = _metric_value(
            context,
            CONNECTION_METRIC,
        )

        read_iops = _metric_value(
            context,
            READ_IOPS_METRIC,
        )

        write_iops = _metric_value(
            context,
            WRITE_IOPS_METRIC,
        )

        if any(
            value is None
            for value in (
                cpu,
                connections,
                read_iops,
                write_iops,
            )
        ):
            return None

        idle_cpu_threshold = (
            _threshold(
                context,
                "idle_cpu_percent",
                DEFAULT_IDLE_CPU_PERCENT,
            )
        )

        idle_connection_threshold = (
            _threshold(
                context,
                "idle_connections",
                DEFAULT_IDLE_CONNECTIONS,
            )
        )

        idle_iops_threshold = (
            _threshold(
                context,
                "idle_iops",
                DEFAULT_IDLE_IOPS,
            )
        )

        if any(
            value is None
            for value in (
                idle_cpu_threshold,
                idle_connection_threshold,
                idle_iops_threshold,
            )
        ):
            return None

        if not (
            cpu <= idle_cpu_threshold
            and connections <= idle_connection_threshold
            and read_iops <= idle_iops_threshold
            and write_iops <= idle_iops_threshold
        ):
            return None

        network_rx = _metric_value(
            context,
            NETWORK_RX_METRIC,
        )

        network_tx = _metric_value(
            context,
            NETWORK_TX_METRIC,
        )

        network_threshold = _threshold(
            context,
            "idle_network_bytes_per_second",
            DEFAULT_IDLE_NETWORK_BYTES_PER_SECOND,
        )

        if (
            network_rx is not None
            and network_tx is not None
            and network_threshold is not None
            and (
                network_rx > network_threshold
                or network_tx > network_threshold
            )
        ):
            return None

        statements = [
            _metric_evidence(
                context,
                CPU_METRIC,
                "CPU utilization is very low.",
            ),
            _metric_evidence(
                context,
                CONNECTION_METRIC,
                "Database connections are negligible.",
            ),
            _metric_evidence(
                context,
                READ_IOPS_METRIC,
                "Read I/O is negligible.",
            ),
            _metric_evidence(
                context,
                WRITE_IOPS_METRIC,
                "Write I/O is negligible.",
            ),
        ]

        if (
            _metric_ready(
                context,
                NETWORK_RX_METRIC,
            )
            and _metric_ready(
                context,
                NETWORK_TX_METRIC,
            )
        ):

            statements.extend(
                [
                    _metric_evidence(
                        context,
                        NETWORK_RX_METRIC,
                    ),
                    _metric_evidence(
                        context,
                        NETWORK_TX_METRIC,
                    ),
                ]
            )

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_idle_instance"
            ),
            title=(
                "RDS instance appears idle"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Very low CPU, database connections and "
                "I/O were observed using complete and "
                "semantically compatible CloudWatch metrics "
                "during the analysis period."
            ),
            statements=statements,
            metadata={
                "cpu_percent":
                    cpu,

                "database_connections":
                    connections,

                "read_iops":
                    read_iops,

                "write_iops":
                    write_iops,

                "network_receive":
                    network_rx,

                "network_transmit":
                    network_tx,

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )

    # ==================================================================
    # RULE 3 — LOW UTILIZATION
    # ==================================================================

    def _check_low_utilization(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _rightsizing_eligible(
            context
        ):
            return None

        required = (
            CPU_METRIC,
            CONNECTION_METRIC,
            READ_IOPS_METRIC,
            WRITE_IOPS_METRIC,
        )

        if not _all_metrics_ready(
            context,
            required,
        ):
            return None

        cpu = _metric_value(
            context,
            CPU_METRIC,
        )

        connections = _metric_value(
            context,
            CONNECTION_METRIC,
        )

        read_iops = _metric_value(
            context,
            READ_IOPS_METRIC,
        )

        write_iops = _metric_value(
            context,
            WRITE_IOPS_METRIC,
        )

        if any(
            value is None
            for value in (
                cpu,
                connections,
                read_iops,
                write_iops,
            )
        ):
            return None

        idle_cpu = (
            cpu
            <= (
                _threshold(
                    context,
                    "idle_cpu_percent",
                    DEFAULT_IDLE_CPU_PERCENT,
                )
                or 0
            )
        )

        idle_connections = (
            connections
            <= (
                _threshold(
                    context,
                    "idle_connections",
                    DEFAULT_IDLE_CONNECTIONS,
                )
                or 0
            )
        )

        idle_iops = (
            read_iops
            <= (
                _threshold(
                    context,
                    "idle_iops",
                    DEFAULT_IDLE_IOPS,
                )
                or 0
            )
            and write_iops
            <= (
                _threshold(
                    context,
                    "idle_iops",
                    DEFAULT_IDLE_IOPS,
                )
                or 0
            )
        )

        # Idle already owns the stronger state.
        if (
            idle_cpu
            and idle_connections
            and idle_iops
        ):
            return None

        low_cpu_threshold = (
            _threshold(
                context,
                "low_cpu_percent",
                DEFAULT_LOW_CPU_PERCENT,
            )
        )

        low_connections_threshold = (
            _threshold(
                context,
                "low_connections",
                DEFAULT_LOW_CONNECTIONS,
            )
        )

        low_iops_threshold = (
            _threshold(
                context,
                "low_iops",
                DEFAULT_LOW_IOPS,
            )
        )

        if any(
            value is None
            for value in (
                low_cpu_threshold,
                low_connections_threshold,
                low_iops_threshold,
            )
        ):
            return None

        if not (
            cpu <= low_cpu_threshold
            and connections <= low_connections_threshold
            and read_iops <= low_iops_threshold
            and write_iops <= low_iops_threshold
        ):
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_low_utilization"
            ),
            title=(
                "RDS instance has low utilization"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "CPU, database connections and I/O remain "
                "low during the analysis period. Review whether "
                "the current instance capacity exceeds workload "
                "requirements."
            ),
            statements=[
                _metric_evidence(
                    context,
                    CPU_METRIC,
                ),
                _metric_evidence(
                    context,
                    CONNECTION_METRIC,
                ),
                _metric_evidence(
                    context,
                    READ_IOPS_METRIC,
                ),
                _metric_evidence(
                    context,
                    WRITE_IOPS_METRIC,
                ),
            ],
            metadata={
                "instance_class":
                    _configuration(
                        context
                    ).get(
                        "instance_class"
                    ),

                "cpu_percent":
                    cpu,

                "database_connections":
                    connections,

                "read_iops":
                    read_iops,

                "write_iops":
                    write_iops,

                "thresholds": {
                    "cpu_percent":
                        low_cpu_threshold,

                    "connections":
                        low_connections_threshold,

                    "iops":
                        low_iops_threshold,
                },

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )

    # ==================================================================
    # RULE 4 — MEMORY PRESSURE
    # ==================================================================

    def _check_memory_pressure(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _metric_ready(
            context,
            FREEABLE_MEMORY_METRIC,
        ):
            return None

        free_memory = _metric_value(
            context,
            FREEABLE_MEMORY_METRIC,
        )

        if free_memory is None:
            return None

        configuration = _configuration(
            context
        )

        allocated_memory = _as_number(
            configuration.get(
                "instance_memory_bytes"
            )
        )

        if allocated_memory is None:

            allocated_memory = _as_number(
                configuration.get(
                    "memory_bytes"
                )
            )

        # Do not guess instance memory.
        if (
            allocated_memory is None
            or allocated_memory <= 0
        ):
            return None

        free_ratio = (
            free_memory
            / allocated_memory
        )

        threshold = _threshold(
            context,
            "low_free_memory_ratio",
            DEFAULT_HIGH_FREE_MEMORY_PRESSURE,
        )

        if (
            threshold is None
            or free_ratio >= threshold
        ):
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_memory_pressure"
            ),
            title=(
                "RDS memory pressure"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Observed freeable memory is low relative "
                "to the available instance memory."
            ),
            statements=[
                _metric_evidence(
                    context,
                    FREEABLE_MEMORY_METRIC,
                ),
                self._configuration_evidence(
                    context,
                    "instance_memory_bytes",
                    allocated_memory,
                ),
            ],
            metadata={
                "freeable_memory_bytes":
                    free_memory,

                "instance_memory_bytes":
                    allocated_memory,

                "free_memory_ratio":
                    round(
                        free_ratio,
                        4,
                    ),

                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )

    # ==================================================================
    # RULE 5 — I/O PRESSURE
    # ==================================================================

    def _check_io_pressure(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        read_ready = _metric_ready(
            context,
            READ_IOPS_METRIC,
        )

        write_ready = _metric_ready(
            context,
            WRITE_IOPS_METRIC,
        )

        queue_ready = _metric_ready(
            context,
            QUEUE_DEPTH_METRIC,
        )

        if not (
            read_ready
            or write_ready
            or queue_ready
        ):
            return None

        read_iops = (
            _metric_value(
                context,
                READ_IOPS_METRIC,
            )
            if read_ready
            else None
        )

        write_iops = (
            _metric_value(
                context,
                WRITE_IOPS_METRIC,
            )
            if write_ready
            else None
        )

        queue_depth = (
            _metric_value(
                context,
                QUEUE_DEPTH_METRIC,
            )
            if queue_ready
            else None
        )

        queue_threshold = _threshold(
            context,
            "high_disk_queue_depth",
            1.0,
        )

        queue_pressure = (
            queue_depth is not None
            and queue_threshold is not None
            and queue_depth >= queue_threshold
        )

        total_iops = None

        # Sum only when BOTH directions are available.
        if (
            read_iops is not None
            and write_iops is not None
        ):
            total_iops = (
                read_iops
                + write_iops
            )

        iops_threshold = _threshold(
            context,
            "high_iops",
            None,
        )

        iops_pressure = (
            total_iops is not None
            and iops_threshold is not None
            and total_iops >= iops_threshold
        )

        if not (
            queue_pressure
            or iops_pressure
        ):
            return None

        statements: list[
            EvidenceStatement
        ] = []

        if read_ready:
            statements.append(
                _metric_evidence(
                    context,
                    READ_IOPS_METRIC,
                )
            )

        if write_ready:
            statements.append(
                _metric_evidence(
                    context,
                    WRITE_IOPS_METRIC,
                )
            )

        if queue_ready:
            statements.append(
                _metric_evidence(
                    context,
                    QUEUE_DEPTH_METRIC,
                )
            )

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_io_pressure"
            ),
            title=(
                "RDS I/O pressure"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Observed I/O activity or queue depth "
                "indicates that storage performance should "
                "be reviewed before reducing capacity."
            ),
            statements=statements,
            metadata={
                "read_iops":
                    read_iops,

                "write_iops":
                    write_iops,

                "queue_depth":
                    queue_depth,

                "total_iops":
                    total_iops,

                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )

    # ==================================================================
    # RULE 6 — I/O LATENCY
    # ==================================================================

    def _check_io_latency(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        read_ready = _metric_ready(
            context,
            READ_LATENCY_METRIC,
        )

        write_ready = _metric_ready(
            context,
            WRITE_LATENCY_METRIC,
        )

        if not (
            read_ready
            or write_ready
        ):
            return None

        read_latency_seconds = (
            _metric_value(
                context,
                READ_LATENCY_METRIC,
            )
            if read_ready
            else None
        )

        write_latency_seconds = (
            _metric_value(
                context,
                WRITE_LATENCY_METRIC,
            )
            if write_ready
            else None
        )

        threshold_ms = _threshold(
            context,
            "high_latency_ms",
            DEFAULT_HIGH_LATENCY_MS,
        )

        if threshold_ms is None:
            return None

        read_latency_ms = (
            read_latency_seconds * 1000.0
            if read_latency_seconds is not None
            else None
        )

        write_latency_ms = (
            write_latency_seconds * 1000.0
            if write_latency_seconds is not None
            else None
        )

        high_read = (
            read_latency_ms is not None
            and read_latency_ms >= threshold_ms
        )

        high_write = (
            write_latency_ms is not None
            and write_latency_ms >= threshold_ms
        )

        if not (
            high_read
            or high_write
        ):
            return None

        statements: list[
            EvidenceStatement
        ] = []

        if read_ready:
            statements.append(
                _metric_evidence(
                    context,
                    READ_LATENCY_METRIC,
                    (
                        "CloudWatch reports the raw "
                        "latency value in seconds."
                    ),
                )
            )

        if write_ready:
            statements.append(
                _metric_evidence(
                    context,
                    WRITE_LATENCY_METRIC,
                    (
                        "CloudWatch reports the raw "
                        "latency value in seconds."
                    ),
                )
            )

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_io_latency"
            ),
            title=(
                "RDS I/O latency"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Observed read or write latency is above "
                f"the configured review threshold of "
                f"{threshold_ms:.2f} ms."
            ),
            statements=statements,
            metadata={
                "read_latency_seconds":
                    read_latency_seconds,

                "write_latency_seconds":
                    write_latency_seconds,

                "read_latency_ms":
                    read_latency_ms,

                "write_latency_ms":
                    write_latency_ms,

                "threshold_ms":
                    threshold_ms,

                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )

    # ==================================================================
    # RULE 7 — STORAGE PRESSURE
    # ==================================================================

    def _check_storage_pressure(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        configuration = _configuration(
            context
        )

        engine = str(
            configuration.get(
                "engine",
                "",
            )
        ).lower()

        # Aurora storage is managed at cluster/storage-layer level;
        # do not treat allocated instance storage as an Aurora
        # instance capacity signal.
        if engine.startswith(
            "aurora"
        ):
            return None

        if not _metric_ready(
            context,
            FREE_STORAGE_METRIC,
        ):
            return None

        free_storage_bytes = _metric_value(
            context,
            FREE_STORAGE_METRIC,
        )

        if free_storage_bytes is None:
            return None

        allocated_gib = _as_number(
            configuration.get(
                "allocated_storage_gib"
            )
        )

        if (
            allocated_gib is None
            or allocated_gib <= 0
        ):
            return None

        allocated_bytes = (
            allocated_gib
            * (1024 ** 3)
        )

        if allocated_bytes <= 0:
            return None

        # Impossible/invalid telemetry should not create a finding.
        if free_storage_bytes < 0:
            return None

        if free_storage_bytes > allocated_bytes:
            return None

        used_ratio = (
            1.0
            - (
                free_storage_bytes
                / allocated_bytes
            )
        )

        threshold = _threshold(
            context,
            "storage_pressure_ratio",
            DEFAULT_STORAGE_PRESSURE_RATIO,
        )

        if (
            threshold is None
            or threshold <= 0
            or threshold > 1
        ):
            return None

        if used_ratio < threshold:
            return None

        free_gib = (
            free_storage_bytes
            / (1024 ** 3)
        )

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_storage_pressure"
            ),
            title=(
                "RDS storage is highly utilized"
            ),
            severity="medium",
            confidence="high",
            reason=(
                f"Observed FreeStorageSpace indicates "
                f"approximately {used_ratio * 100:.1f}% "
                f"of allocated storage is in use, above "
                f"the configured pressure threshold of "
                f"{threshold * 100:.1f}%."
            ),
            statements=[
                _metric_evidence(
                    context,
                    FREE_STORAGE_METRIC,
                ),
                self._configuration_evidence(
                    context,
                    "allocated_storage_gib",
                    allocated_gib,
                ),
            ],
            metadata={
                "allocated_storage_gib":
                    allocated_gib,

                "free_storage_bytes":
                    free_storage_bytes,

                "free_storage_gib":
                    free_gib,

                "used_ratio":
                    round(
                        used_ratio,
                        4,
                    ),

                "pressure_threshold":
                    threshold,

                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )
    def _check_iops_underuse(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if _is_aurora(
            context
        ):
            return None

        configuration = _configuration(
            context
        )

        provisioned_iops = _as_number(
            configuration.get(
                "iops"
            )
        )

        if (
            provisioned_iops is None
            or provisioned_iops <= 0
        ):
            return None

        required = (
            READ_IOPS_METRIC,
            WRITE_IOPS_METRIC,
        )

        if not _all_metrics_ready(
            context,
            required,
        ):
            return None

        read_iops = _metric_value(
            context,
            READ_IOPS_METRIC,
        )

        write_iops = _metric_value(
            context,
            WRITE_IOPS_METRIC,
        )

        if (
            read_iops is None
            or write_iops is None
        ):
            return None

        observed_iops = (
            read_iops
            + write_iops
        )

        ratio = (
            observed_iops
            / provisioned_iops
        )

        threshold = _threshold(
            context,
            "iops_underuse_ratio",
            DEFAULT_IOPS_UNDERUSE_RATIO,
        )

        if (
            threshold is None
            or threshold <= 0
            or threshold >= 1
        ):
            return None

        if ratio > threshold:
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_provisioned_iops_underuse"
            ),
            title=(
                "Provisioned RDS IOPS appears underused"
            ),
            severity="low",
            confidence="medium",
            reason=(
                f"Observed average read/write IOPS total "
                f"about {ratio * 100:.1f}% of provisioned "
                f"IOPS during the analysis period."
            ),
            statements=[
                self._configuration_evidence(
                    context,
                    "iops",
                    provisioned_iops,
                ),
                _metric_evidence(
                    context,
                    READ_IOPS_METRIC,
                ),
                _metric_evidence(
                    context,
                    WRITE_IOPS_METRIC,
                ),
            ],
            metadata={
                "provisioned_iops":
                    provisioned_iops,

                "read_iops":
                    read_iops,

                "write_iops":
                    write_iops,

                "observed_iops":
                    observed_iops,

                "utilization_ratio":
                    round(
                        ratio,
                        4,
                    ),

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )

    def _check_underused_read_replica(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        configuration = _configuration(
            context
        )

        source = configuration.get(
            "read_replica_source"
        )

        if not source:
            return None

        required = (
            CONNECTION_METRIC,
            NETWORK_RX_METRIC,
            NETWORK_TX_METRIC,
        )

        if not _all_metrics_ready(
            context,
            required,
        ):
            return None

        connections = _metric_value(
            context,
            CONNECTION_METRIC,
        )

        network_rx = _metric_value(
            context,
            NETWORK_RX_METRIC,
        )

        network_tx = _metric_value(
            context,
            NETWORK_TX_METRIC,
        )

        if any(
            value is None
            for value in (
                connections,
                network_rx,
                network_tx,
            )
        ):
            return None

        connection_threshold = _threshold(
            context,
            "replica_low_connections",
            DEFAULT_LOW_CONNECTIONS,
        )

        network_threshold = _threshold(
            context,
            "replica_low_network_bytes_per_second",
            DEFAULT_IDLE_NETWORK_BYTES_PER_SECOND,
        )

        if (
            connection_threshold is None
            or network_threshold is None
        ):
            return None

        if not (
            connections <= connection_threshold
            and network_rx <= network_threshold
            and network_tx <= network_threshold
        ):
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_underused_read_replica"
            ),
            title=(
                "RDS read replica is lightly used"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "The read replica shows low observed "
                "connections and network activity. "
                "Review whether it is still required "
                "for availability, failover, reporting, "
                "or read-scaling purposes."
            ),
            statements=[
                _metric_evidence(
                    context,
                    CONNECTION_METRIC,
                ),
                _metric_evidence(
                    context,
                    NETWORK_RX_METRIC,
                ),
                _metric_evidence(
                    context,
                    NETWORK_TX_METRIC,
                ),
                self._configuration_evidence(
                    context,
                    "read_replica_source",
                    source,
                ),
            ],
            metadata={
                "source":
                    source,

                "connections":
                    connections,

                "network_receive":
                    network_rx,

                "network_transmit":
                    network_tx,

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )

    # ==================================================================
    # RULE 10 — BACKUP RETENTION
    # ==================================================================

    def _check_backup_retention(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        retention = _as_number(
            _configuration(
                context
            ).get(
                "backup_retention_days"
            )
        )

        if retention is None:
            return None

        threshold = _threshold(
            context,
            "high_backup_retention_days",
            DEFAULT_HIGH_BACKUP_RETENTION_DAYS,
        )

        if (
            threshold is None
            or retention <= threshold
        ):
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_backup_retention_review"
            ),
            title=(
                "RDS backup retention review"
            ),
            severity="low",
            confidence="medium",
            reason=(
                f"Backup retention is {int(retention)} days. "
                "Review whether the recovery requirement "
                "justifies the current retention period."
            ),
            statements=[
                self._configuration_evidence(
                    context,
                    "backup_retention_days",
                    int(retention),
                )
            ],
            metadata={
                "backup_retention_days":
                    int(retention),

                "review_threshold_days":
                    int(threshold),

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )

    # ==================================================================
    # RULE 11 — CLASS HISTORY
    # ==================================================================

    def _check_class_change_history(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        observations = context.observations()

        cloudtrail = observations.get(
            "cloudtrail",
            {},
        )

        if not isinstance(
            cloudtrail,
            dict,
        ):
            return None

        history = cloudtrail.get(
            "instance_class_history",
            [],
        )

        events = cloudtrail.get(
            "events",
            [],
        )

        if not isinstance(
            history,
            list,
        ):
            history = []

        if not isinstance(
            events,
            list,
        ):
            events = []

        classes: list[str] = []

        for value in history:

            if value is None:
                continue

            text = str(
                value
            ).strip()

            if (
                text
                and text not in classes
            ):
                classes.append(
                    text
                )

        minimum_events = int(
            _threshold(
                context,
                "minimum_class_change_events",
                DEFAULT_MIN_HISTORY_EVENTS,
            )
            or DEFAULT_MIN_HISTORY_EVENTS
        )

        if (
            len(events)
            < minimum_events
        ):
            return None

        if len(classes) < 2:
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "rds_instance_class_changes"
            ),
            title=(
                "RDS sizing changed repeatedly"
            ),
            severity="low",
            confidence="high",
            reason=(
                "CloudTrail shows multiple instance-class "
                "changes during the analysis period. Review "
                "workload sizing against observed demand before "
                "making another change."
            ),
            statements=[
                self._cloudtrail_history_evidence(
                    classes,
                    events,
                )
            ],
            metadata={
                "instance_classes":
                    classes,

                "change_event_count":
                    len(events),

                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )

    # ==================================================================
    # FINDING BUILDER
    # ==================================================================

    def _build_finding(
        self,
        *,
        context: AnalysisContext,
        finding_type: str,
        title: str,
        severity: str,
        confidence: str,
        reason: str,
        statements: list[
            EvidenceStatement
        ],
        metadata: dict[str, Any],
        recommendation_eligible: bool,
    ) -> Finding:

    
        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or "rds_instance"
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
                _observation_period(
                    context
                )
            ),

            limitations=[
                (
                    "Workload findings use the CloudWatch "
                    "statistics and observation window collected "
                    "for this scan; they do not prove that future "
                    "or intermittent workload behavior will remain "
                    "the same."
                )
                for finding_type_value in (
                    "rds_idle_instance",
                    "rds_low_utilization",
                    "rds_provisioned_iops_underuse",
                    "rds_underused_read_replica",
                )
                if finding_type == finding_type_value
            ],

            metadata=dict(
                metadata
            ),

            recommendation_eligible=(
                recommendation_eligible
            ),
        )

    # ==================================================================
    # EVIDENCE
    # ==================================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: dict[str, Any],
    ) -> Evidence:

        configuration = _configuration(
            context
        )

        metrics = {
            name:
                context.metric_summary(
                    name
                )
            for name in _metrics(
                context
            )
        }

        allowed_fields = (
            "instance_class",
            "db_instance_class",
            "engine",
            "engine_version",
            "status",
            "multi_az",
            "availability_zone",
            "backup_retention_days",
            "publicly_accessible",
            "performance_insights_enabled",
            "storage_type",
            "allocated_storage_gib",
            "max_allocated_storage_gib",
            "iops",
            "storage_throughput",
            "storage_encrypted",
            "db_cluster_identifier",
            "db_subnet_group",
            "vpc_id",
            "read_replica_source",
            "read_replicas",
            "monitoring_interval",
            "promotion_tier",
            "deletion_protection",
            "instance_memory_bytes",
            "memory_bytes",
        )

        selected_configuration = {
            key:
                configuration[key]
            for key in allowed_fields
            if key in configuration
        }

        return Evidence(
            metrics=metrics,

            configuration=(
                selected_configuration
            ),

            topology=(
                context.topology()
            ),

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,
            },

            derived=dict(
                metadata
            ),

            data_quality={
                **context.data_quality(),

                "cloudwatch_metrics":
                    len(metrics),

                "observation_period_available":
                    (
                        _observation_period(
                            context
                        )
                        is not None
                    ),

                "billing_reconciliation_available":
                    bool(
                        context.rds_billing_match()
                    ),

                "required_statistics": {
                    key:
                        EXPECTED_STATISTICS[key]
                    for key in EXPECTED_STATISTICS
                    if key in metrics
                },
            },
        )

    # ==================================================================
    # EVIDENCE HELPERS
    # ==================================================================

    @staticmethod
    def _configuration_evidence(
        context: AnalysisContext,
        name: str,
        value: Any,
    ) -> EvidenceStatement:

        return _statement(
            name=name,

            value=value,

            description=(
                "Current RDS configuration: "
                f"{name}={value}."
            ),

            source=[
                "RDS configuration"
            ],
        )

    @staticmethod
    def _cloudtrail_history_evidence(
        classes: list[str],
        events: list[Any],
    ) -> EvidenceStatement:

        return _statement(
            name="instance_class_history",

            value={
                "classes":
                    classes,

                "event_count":
                    len(events),
            },

            description=(
                "CloudTrail records multiple "
                "instance-class changes during "
                "the analysis period."
            ),

            source=[
                "CloudTrail.ModifyDBInstance"
            ],
        )