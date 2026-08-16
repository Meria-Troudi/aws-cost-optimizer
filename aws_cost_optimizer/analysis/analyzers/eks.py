"""
Amazon EKS cost and operational optimization analyzer.

Resource-oriented and evidence-first.

The analyzer evaluates one EKS cluster at a time.

It detects:
- confirmed absence of active worker capacity
- low EC2 worker utilization
- excessive per-nodegroup scaling headroom
- failed worker nodes
- high resource reservation relative to observed utilization

It does NOT:
- aggregate findings
- decide recommendation scope
- invent savings
- select instance types
- recommend Spot automatically
- delete clusters or workloads

Safety rules
------------
- Missing telemetry never becomes zero.
- Partial inventory never becomes "empty cluster".
- A Fargate profile is not treated as proof of running workload.
- A nodegroup with desired=0 is not the same thing as a deleted nodegroup.
- Scaling headroom is evaluated per nodegroup.
- Metric values are accepted only when their expected statistic
  is actually present.
- Low utilization requires complete worker telemetry.
- Failed-node detection is operational evidence, not direct cost-saving
  proof.
- No aggregation scope is assigned by the analyzer.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

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

DEFAULT_LOW_CPU_PERCENT = 20.0
DEFAULT_LOW_MEMORY_PERCENT = 30.0

DEFAULT_HIGH_RESERVED_PERCENT = 80.0

DEFAULT_MAX_TO_DESIRED_RATIO = 2.0

DEFAULT_MIN_NODE_COUNT_FOR_UTILIZATION = 1


# ======================================================================
# METRIC KEYS
# ======================================================================

CPU_UTILIZATION = "node_cpu_utilization"
MEMORY_UTILIZATION = "node_memory_utilization"

CPU_RESERVED = "node_cpu_reserved_capacity"
MEMORY_RESERVED = "node_memory_reserved_capacity"

RUNNING_PODS = "running_pods"
NODE_COUNT = "cluster_node_count"
FAILED_NODE_COUNT = "failed_node_count"

NETWORK = "node_network_total_bytes"


# ======================================================================
# EXPECTED CLOUDWATCH STATISTICS
# ======================================================================

EXPECTED_STATISTICS = {
    CPU_UTILIZATION: "Average",
    MEMORY_UTILIZATION: "Average",
    CPU_RESERVED: "Average",
    MEMORY_RESERVED: "Average",
    RUNNING_PODS: "Average",
    NODE_COUNT: "Average",
    FAILED_NODE_COUNT: "Average",
    NETWORK: "Average",
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
            "eks"
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

    value = _analyzer_config(
        context
    ).get(key)

    if value is None:

        return (
            float(default)
            if default is not None
            else None
        )

    try:

        parsed = float(value)

    except (
        TypeError,
        ValueError,
    ):

        return (
            float(default)
            if default is not None
            else None
        )

    if parsed < 0:
        return (
            float(default)
            if default is not None
            else None
        )

    return parsed


# ======================================================================
# ANALYZER
# ======================================================================


@register
class EKSAnalyzer(Analyzer):

    name = "eks"
    version = "3.0"

    SUPPORTED_RESOURCE_TYPES = {
        "eks_cluster",
        "eks",
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
    # MAIN
    # ==================================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(
            context
        ):
            return []

        data = self._collect_data(
            context
        )

        findings: list[
            Finding
        ] = []

        checks = (
            self._check_no_worker_capacity,
            self._check_low_utilization,
            self._check_scaling_headroom,
            self._check_failed_nodes,
            self._check_reserved_capacity,
        )

        for check in checks:

            finding = check(
                context,
                data,
            )

            if finding is not None:

                findings.append(
                    finding
                )

        return findings

    # ==================================================================
    # DATA
    # ==================================================================

    @classmethod
    def _collect_data(
        cls,
        context: AnalysisContext,
    ) -> Dict[str, Any]:

        configuration = context.configuration()

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        compute = configuration.get(
            "compute",
            {},
        )

        if not isinstance(
            compute,
            dict,
        ):
            compute = {}

        summary = compute.get(
            "summary",
            {},
        )

        if not isinstance(
            summary,
            dict,
        ):
            summary = {}

        nodegroups = compute.get(
            "nodegroups",
            [],
        )

        if not isinstance(
            nodegroups,
            list,
        ):
            nodegroups = []

        fargate_profiles = compute.get(
            "fargate_profiles",
            [],
        )

        if not isinstance(
            fargate_profiles,
            list,
        ):
            fargate_profiles = []

        ec2_instances = compute.get(
            "ec2_instances",
            [],
        )

        if not isinstance(
            ec2_instances,
            list,
        ):
            ec2_instances = []

        inventory_status = str(
            compute.get(
                "inventory_status",
                "unknown",
            )
        ).lower()

        inventory_complete = (
            inventory_status
            == "complete"
        )

        metric_data = {
            key:
                cls._metric_info(
                    context,
                    key,
                )
            for key in (
                CPU_UTILIZATION,
                MEMORY_UTILIZATION,
                CPU_RESERVED,
                MEMORY_RESERVED,
                RUNNING_PODS,
                NODE_COUNT,
                FAILED_NODE_COUNT,
                NETWORK,
            )
        }

        active_managed_nodes = sum(
            1
            for nodegroup in nodegroups
            if (
                isinstance(
                    nodegroup,
                    dict,
                )
                and cls._number(
                    nodegroup.get(
                        "scaling",
                        {},
                    ).get(
                        "desired_size"
                    )
                )
                and cls._number(
                    nodegroup.get(
                        "scaling",
                        {},
                    ).get(
                        "desired_size"
                    )
                ) > 0
            )
        )

        desired_nodes = cls._number(
            summary.get(
                "desired_node_count"
            )
        )

        minimum_nodes = cls._number(
            summary.get(
                "minimum_node_count"
            )
        )

        maximum_nodes = cls._number(
            summary.get(
                "maximum_node_count"
            )
        )

        observed_node_count = (
            metric_data[NODE_COUNT]["value"]
        )

        confirmed_no_ec2_capacity = (
            inventory_complete
            and not ec2_instances
            and (
                desired_nodes is None
                or desired_nodes <= 0
            )
        )

        confirmed_no_worker_capacity = (
            inventory_complete
            and not ec2_instances
            and (
                desired_nodes is None
                or desired_nodes <= 0
            )
            and (
                observed_node_count is None
                or observed_node_count <= 0
            )
            and cls._fargate_running_evidence(
                compute
            ) is not True
        )

        return {
            "configuration":
                configuration,

            "compute":
                compute,

            "summary":
                summary,

            "nodegroups":
                nodegroups,

            "fargate_profiles":
                fargate_profiles,

            "ec2_instances":
                ec2_instances,

            "nodegroup_count":
                len(nodegroups),

            "fargate_profile_count":
                len(fargate_profiles),

            "ec2_instance_count":
                len(ec2_instances),

            "inventory_status":
                inventory_status,

            "inventory_complete":
                inventory_complete,

            "active_managed_nodes":
                active_managed_nodes,

            "desired_nodes":
                desired_nodes,

            "minimum_nodes":
                minimum_nodes,

            "maximum_nodes":
                maximum_nodes,

            "observed_node_count":
                observed_node_count,

            "confirmed_no_worker_capacity":
                confirmed_no_worker_capacity,

            "confirmed_no_ec2_capacity":
                confirmed_no_ec2_capacity,

            "fargate_running":
                cls._fargate_running_evidence(
                    compute
                ),

            "metrics":
                metric_data,

            "cpu_utilization":
                metric_data[
                    CPU_UTILIZATION
                ]["value"],

            "memory_utilization":
                metric_data[
                    MEMORY_UTILIZATION
                ]["value"],

            "cpu_reserved":
                metric_data[
                    CPU_RESERVED
                ]["value"],

            "memory_reserved":
                metric_data[
                    MEMORY_RESERVED
                ]["value"],

            "running_pods":
                metric_data[
                    RUNNING_PODS
                ]["value"],

            "node_count":
                metric_data[
                    NODE_COUNT
                ]["value"],

            "failed_node_count":
                metric_data[
                    FAILED_NODE_COUNT
                ]["value"],

            "network_bytes":
                metric_data[
                    NETWORK
                ]["value"],
        }

    # ==================================================================
    # RULE 1 — NO WORKER CAPACITY
    # ==================================================================

    def _check_no_worker_capacity(
        self,
        context: AnalysisContext,
        data: Dict[str, Any],
    ) -> Finding | None:

        if not data[
            "confirmed_no_worker_capacity"
        ]:
            return None

        cluster_status = (
            self._cluster_status(
                context
            )
        )

        if cluster_status not in {
            "active",
            "creating",
            "updating",
            "unknown",
        }:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_no_worker_capacity"
            ),
            title=(
                "EKS cluster has no active worker capacity"
            ),
            severity="info",
            confidence="high",
            reason=(
                "Current inventory and workload telemetry "
                "do not show active EC2 worker capacity or "
                "running Fargate capacity for the cluster. "
                "The control plane may still incur EKS charges."
            ),
            statements=[
                EvidenceStatement(
                    name="worker_capacity",
                    value={
                        "nodegroups":
                            data[
                                "nodegroup_count"
                            ],

                        "desired_nodes":
                            data[
                                "desired_nodes"
                            ],

                        "ec2_instances":
                            data[
                                "ec2_instance_count"
                            ],

                        "observed_node_count":
                            data[
                                "observed_node_count"
                            ],

                        "fargate_profiles":
                            data[
                                "fargate_profile_count"
                            ],

                        "fargate_running":
                            data[
                                "fargate_running"
                            ],
                    },
                    description=(
                        "Collected EKS worker-capacity evidence."
                    ),
                    source=[
                        "EKS nodegroups",
                        "EC2 worker inventory",
                        "Container Insights node count",
                        "Fargate workload evidence",
                    ],
                )
            ],
            metadata={
                "nodegroup_count":
                    data[
                        "nodegroup_count"
                    ],

                "desired_nodes":
                    data[
                        "desired_nodes"
                    ],

                "ec2_instance_count":
                    data[
                        "ec2_instance_count"
                    ],

                "observed_node_count":
                    data[
                        "observed_node_count"
                    ],

                "fargate_profile_count":
                    data[
                        "fargate_profile_count"
                    ],

                "fargate_running":
                    data[
                        "fargate_running"
                    ],

                "cluster_status":
                    cluster_status,

                "region":
                    context.region,
            },
            limitations=[
                (
                    "An intentionally scaled-to-zero cluster may "
                    "still be required for future workloads."
                ),
                (
                    "A Fargate profile by itself is not treated "
                    "as proof of active workload capacity."
                ),
            ],
        )

    # ==================================================================
    # RULE 2 — LOW UTILIZATION
    # ==================================================================

    def _check_low_utilization(
        self,
        context: AnalysisContext,
        data: Dict[str, Any],
    ) -> Finding | None:

        # This rule is specifically for EC2 worker capacity.
        if not data[
            "ec2_instance_count"
        ]:
            return None

        if not data[
            "inventory_complete"
        ]:
            return None

        required = (
            CPU_UTILIZATION,
            MEMORY_UTILIZATION,
            NODE_COUNT,
        )

        if not self._metrics_ready(
            data,
            required,
        ):
            return None

        cpu = data[
            "cpu_utilization"
        ]

        memory = data[
            "memory_utilization"
        ]

        node_count = data[
            "node_count"
        ]

        if any(
            value is None
            for value in (
                cpu,
                memory,
                node_count,
            )
        ):
            return None

        if (
            node_count
            < 1
        ):
            return None

        low_cpu = _threshold(
            context,
            "low_cpu_percent",
            DEFAULT_LOW_CPU_PERCENT,
        )

        low_memory = _threshold(
            context,
            "low_memory_percent",
            DEFAULT_LOW_MEMORY_PERCENT,
        )

        if (
            low_cpu is None
            or low_memory is None
        ):
            return None

        if (
            cpu > low_cpu
            or memory > low_memory
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_low_worker_utilization"
            ),
            title=(
                "EKS worker capacity is underutilized"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Observed worker CPU and memory utilization "
                "are both below the configured review thresholds. "
                "Review node capacity, pod requests, placement, "
                "and scaling behavior before reducing workers."
            ),
            statements=[
                self._metric_evidence(
                    context,
                    CPU_UTILIZATION,
                ),
                self._metric_evidence(
                    context,
                    MEMORY_UTILIZATION,
                ),
                self._metric_evidence(
                    context,
                    NODE_COUNT,
                ),
            ],
            metadata={
                "cpu_utilization":
                    cpu,

                "memory_utilization":
                    memory,

                "node_count":
                    node_count,

                "ec2_instance_count":
                    data[
                        "ec2_instance_count"
                    ],

                "thresholds": {
                    "cpu_percent":
                        low_cpu,

                    "memory_percent":
                        low_memory,
                },

                "region":
                    context.region,
            },
            limitations=[
                (
                    "Cluster-level utilization averages do not "
                    "capture short peaks, pod-level scheduling "
                    "constraints, daemonsets, disruption budgets, "
                    "or workloads requiring dedicated nodes."
                ),
            ],
        )

    # ==================================================================
    # RULE 3 — SCALING HEADROOM
    # ==================================================================

    def _check_scaling_headroom(
        self,
        context: AnalysisContext,
        data: Dict[str, Any],
    ) -> Finding | None:

        if not data[
            "inventory_complete"
        ]:
            return None

        threshold = _threshold(
            context,
            "max_to_desired_ratio",
            DEFAULT_MAX_TO_DESIRED_RATIO,
        )

        if (
            threshold is None
            or threshold <= 1
        ):
            return None

        affected = []

        for nodegroup in data[
            "nodegroups"
        ]:

            if not isinstance(
                nodegroup,
                dict,
            ):
                continue

            name = nodegroup.get(
                "name"
            )

            scaling = nodegroup.get(
                "scaling",
                {},
            )

            if not isinstance(
                scaling,
                dict,
            ):
                continue

            desired = self._number(
                scaling.get(
                    "desired_size"
                )
            )

            maximum = self._number(
                scaling.get(
                    "max_size"
                )
            )

            minimum = self._number(
                scaling.get(
                    "min_size"
                )
            )

            if (
                desired is None
                or maximum is None
            ):
                continue

            # desired=0 does not mean max/desired is infinite.
            # It represents a scale-to-zero configuration and
            # requires a separate scaling review.
            if desired <= 0:
                if maximum > 0:
                    affected.append(
                        {
                            "name":
                                name,

                            "minimum":
                                minimum,

                            "desired":
                                desired,

                            "maximum":
                                maximum,

                            "ratio":
                                None,

                            "scale_to_zero":
                                True,
                        }
                    )

                continue

            ratio = (
                maximum
                / desired
            )

            if ratio <= threshold:
                continue

            affected.append(
                {
                    "name":
                        name,

                    "minimum":
                        minimum,

                    "desired":
                        desired,

                    "maximum":
                        maximum,

                    "ratio":
                        round(
                            ratio,
                            2,
                        ),

                    "scale_to_zero":
                        False,
                }
            )

        if not affected:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_excessive_scaling_headroom"
            ),
            title=(
                "EKS nodegroups have large scaling headroom"
            ),
            severity="low",
            confidence="high",
            recommendation_eligible=False,
            reason=(
                "One or more nodegroups have scaling "
                "configuration substantially above their "
                "current desired capacity. Review whether "
                "the configured range matches expected workload "
                "demand and autoscaling behavior."
            ),
            statements=[
                EvidenceStatement(
                    name="affected_nodegroups",
                    value=affected,
                    description=(
                        "Nodegroups whose maximum capacity "
                        "is substantially above desired capacity."
                    ),
                    source=[
                        "EKS nodegroup scaling configuration",
                    ],
                )
            ],
            metadata={
                "threshold_ratio":
                    threshold,

                "affected_nodegroups":
                    affected,

                "region":
                    context.region,
            },
            limitations=[
                (
                    "Configured maximum capacity creates "
                    "headroom; it does not itself create a cost."
                ),
                (
                    "Scale-to-zero configurations require "
                    "workload and autoscaler review before "
                    "changing the maximum."
                ),
            ],
        )

    # ==================================================================
    # RULE 4 — FAILED NODES
    # ==================================================================

    def _check_failed_nodes(
        self,
        context: AnalysisContext,
        data: Dict[str, Any],
    ) -> Finding | None:

        failed_nodes = data[
            "failed_node_count"
        ]

        if not self._metric_ready(
            data,
            FAILED_NODE_COUNT,
        ):
            return None

        if failed_nodes is None:
            return None

        if failed_nodes <= 0:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_failed_worker_nodes"
            ),
            title=(
                "EKS failed worker nodes detected"
            ),
            severity="medium",
            recommendation_eligible=False,
            confidence="high",
            reason=(
                f"{self._format_number(failed_nodes)} "
                "failed worker-node observations were recorded. "
                "Investigate node health and infrastructure "
                "conditions before changing worker capacity."
            ),
            statements=[
                self._metric_evidence(
                    context,
                    FAILED_NODE_COUNT,
                )
            ],
            metadata={
                "failed_node_count":
                    failed_nodes,

                "region":
                    context.region,
            },
            limitations=[
                (
                    "This is an operational signal and does "
                    "not by itself demonstrate a cost-saving action."
                ),
            ],
        )

    # ==================================================================
    # RULE 5 — HIGH RESERVED CAPACITY
    # ==================================================================

    def _check_reserved_capacity(
        self,
        context: AnalysisContext,
        data: Dict[str, Any],
    ) -> Finding | None:

        cpu_reserved = data[
            "cpu_reserved"
        ]

        memory_reserved = data[
            "memory_reserved"
        ]

        if not (
            self._metric_ready(
                data,
                CPU_RESERVED,
            )
            or
            self._metric_ready(
                data,
                MEMORY_RESERVED,
            )
        ):
            return None

        high_reserved = _threshold(
            context,
            "high_reserved_percent",
            DEFAULT_HIGH_RESERVED_PERCENT,
        )

        if (
            high_reserved is None
            or high_reserved <= 0
            or high_reserved > 100
        ):
            return None

        cpu_high = (
            cpu_reserved is not None
            and cpu_reserved >= high_reserved
        )

        memory_high = (
            memory_reserved is not None
            and memory_reserved >= high_reserved
        )

        if not (
            cpu_high
            or memory_high
        ):
            return None

        cpu_utilization = data[
            "cpu_utilization"
        ]

        memory_utilization = data[
            "memory_utilization"
        ]

        cpu_gap = (
            cpu_reserved is not None
            and cpu_utilization is not None
            and cpu_reserved > cpu_utilization
        )

        memory_gap = (
            memory_reserved is not None
            and memory_utilization is not None
            and memory_reserved > memory_utilization
        )

        # If utilization evidence exists, require an actual gap.
        if (
            cpu_utilization is not None
            or memory_utilization is not None
        ):

            if not (
                cpu_gap
                or memory_gap
            ):
                return None

        statements = []

        if self._metric_ready(
            data,
            CPU_RESERVED,
        ):

            statements.append(
                self._metric_evidence(
                    context,
                    CPU_RESERVED,
                )
            )

        if self._metric_ready(
            data,
            MEMORY_RESERVED,
        ):

            statements.append(
                self._metric_evidence(
                    context,
                    MEMORY_RESERVED,
                )
            )

        if self._metric_ready(
            data,
            CPU_UTILIZATION,
        ):

            statements.append(
                self._metric_evidence(
                    context,
                    CPU_UTILIZATION,
                )
            )

        if self._metric_ready(
            data,
            MEMORY_UTILIZATION,
        ):

            statements.append(
                self._metric_evidence(
                    context,
                    MEMORY_UTILIZATION,
                )
            )

        return self._finding(
            context=context,
            finding_type=(
                "eks_high_reserved_capacity"
            ),
            title=(
                "EKS reserved capacity is high"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Worker CPU or memory reservation is high "
                "relative to available capacity and observed "
                "utilization. Review pod requests, limits, "
                "placement, and node sizing before changing "
                "capacity."
            ),
            statements=statements,
            metadata={
                "cpu_reserved_percent":
                    cpu_reserved,

                "memory_reserved_percent":
                    memory_reserved,

                "cpu_utilization_percent":
                    cpu_utilization,

                "memory_utilization_percent":
                    memory_utilization,

                "reserved_threshold_percent":
                    high_reserved,

                "region":
                    context.region,
            },
            recommendation_eligible=False,
            limitations=[
                (
                    "High reservation can be intentional for "
                    "availability, scheduling guarantees, or "
                    "bursty workloads."
                ),
                (
                    "Reservation alone does not establish that "
                    "worker capacity can safely be reduced."
                ),
            ],
        )

    # ==================================================================
    # FINDING BUILDER
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
        statements: list[
            EvidenceStatement
        ],
        metadata: dict[str, Any],
        limitations: list[str],
        recommendation_eligible: bool = True,
    ) -> Finding:

        # Analyzer does not own aggregation scope.

        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or "eks_cluster"
            ),

            resource_id=(
                context.resource_id
                or "unknown"
            ),

            analyzer=self.name,

            analyzer_version=self.version,

            severity=str(
                severity
            ).lower(),

            confidence=str(
                confidence
            ).lower(),

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
        )

    # ==================================================================
    # EVIDENCE
    # ==================================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: Dict[str, Any],
    ) -> Evidence:

        configuration = context.configuration()

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        selected_configuration = {
            "cluster":
                configuration.get(
                    "cluster"
                ),

            "compute":
                configuration.get(
                    "compute"
                ),

            "network":
                configuration.get(
                    "network"
                ),
        }

        metrics = {}

        for key in (
            CPU_UTILIZATION,
            MEMORY_UTILIZATION,
            CPU_RESERVED,
            MEMORY_RESERVED,
            RUNNING_PODS,
            NODE_COUNT,
            FAILED_NODE_COUNT,
            NETWORK,
        ):

            summary = self._metric_summary_from_context(
                context,
                key,
            )

            if summary:
                metrics[key] = summary

        return Evidence(
            metrics=metrics,

            configuration=(
                selected_configuration
            ),

            topology=context.topology(),

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
                "cloudwatch_available":
                    bool(
                        context.metrics()
                    ),

                "collector_data_quality":
                    context.collector_data_quality(),

                "metrics_with_observed_data":
                    sum(
                        1
                        for metric in metrics.values()
                        if metric.get(
                            "has_data"
                        ) is True
                    ),
            },
        )

    # ==================================================================
    # METRIC HELPERS
    # ==================================================================

    @classmethod
    def _metric_info(
        cls,
        context: AnalysisContext,
        key: str,
    ) -> dict[str, Any]:

        metric = context.metric(
            key
        )

        # Support collector aliases.
        if not isinstance(
            metric,
            dict,
        ):

            aliases = {
                RUNNING_PODS:
                    "node_number_of_running_pods",

                FAILED_NODE_COUNT:
                    "cluster_failed_node_count",

                NETWORK:
                    "node_network_total_bytes",
            }

            alias = aliases.get(
                key
            )

            if alias:
                metric = context.metric(
                    alias
                )

        if not isinstance(
            metric,
            dict,
        ):

            return {
                "status":
                    "missing",

                "has_data":
                    False,

                "statistic":
                    None,

                "value":
                    None,
            }

        has_data = (
            metric_has_observed_data(
                metric
            )
        )

        statistic = (
            metric.get(
                "statistic"
            )
        )

        expected = (
            EXPECTED_STATISTICS.get(
                key
            )
        )

        statistic_valid = (
            expected is None
            or (
                statistic is not None
                and str(
                    statistic
                ).lower()
                == expected.lower()
            )
        )

        value = None

        if (
            has_data
            and statistic_valid
        ):

            for field in (
                "average",
                "value",
                "maximum",
            ):

                candidate = metric.get(
                    field
                )

                if isinstance(
                    candidate,
                    (int, float),
                ):

                    value = float(
                        candidate
                    )

                    break

        return {
            "status":
                metric.get(
                    "status"
                ),

            "has_data":
                has_data,

            "statistic":
                statistic,

            "statistic_valid":
                statistic_valid,

            "value":
                value,

            "datapoints":
                metric.get(
                    "datapoints"
                ),

            "coverage_ratio":
                metric.get(
                    "coverage_ratio"
                ),

            "coverage_percent":
                metric.get(
                    "coverage_percent"
                ),
        }

    @classmethod
    def _metric_summary_from_context(
        cls,
        context: AnalysisContext,
        key: str,
    ) -> dict[str, Any]:

        info = cls._metric_info(
            context,
            key,
        )

        if (
            info["status"] == "missing"
            and not info["has_data"]
        ):
            return {}

        return info

    @staticmethod
    def _metric_ready(
        data: Dict[str, Any],
        key: str,
    ) -> bool:

        metric = data[
            "metrics"
        ].get(
            key,
            {},
        )

        return (
            isinstance(
                metric,
                dict,
            )
            and metric.get(
                "has_data"
            ) is True
            and metric.get(
                "statistic_valid"
            ) is True
            and metric.get(
                "value"
            ) is not None
        )

    @classmethod
    def _metrics_ready(
        cls,
        data: Dict[str, Any],
        keys: tuple[str, ...],
    ) -> bool:

        return all(
            cls._metric_ready(
                data,
                key,
            )
            for key in keys
        )

    @classmethod
    def _metric_evidence(
        cls,
        context: AnalysisContext,
        key: str,
    ) -> EvidenceStatement:

        info = cls._metric_info(
            context,
            key,
        )

        return EvidenceStatement(
            name=key,
            value=info,
            description=(
                f"Observed {key} CloudWatch metric."
            ),
            source=[
                f"CloudWatch.ContainerInsights.{key}"
            ],
            observed=(
                info.get(
                    "value"
                ) is not None
            ),
        )

    # ==================================================================
    # FARGATE
    # ==================================================================

    @staticmethod
    def _fargate_running_evidence(
        compute: Dict[str, Any],
    ) -> bool | None:

        value = compute.get(
            "fargate_running"
        )

        if isinstance(
            value,
            bool,
        ):
            return value

        running_tasks = compute.get(
            "running_fargate_tasks"
        )

        if isinstance(
            running_tasks,
            (int, float),
        ):
            return (
                running_tasks > 0
            )

        return None

    # ==================================================================
    # HELPERS
    # ==================================================================

    @staticmethod
    def _number(
        value: Any,
    ) -> Optional[float]:

        if value is None:
            return None

        if isinstance(
            value,
            bool,
        ):
            return float(
                int(value)
            )

        try:

            return float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

    @staticmethod
    def _cluster_status(
        context: AnalysisContext,
    ) -> str:

        configuration = (
            context.configuration()
        )

        if not isinstance(
            configuration,
            dict,
        ):
            return "unknown"

        cluster = configuration.get(
            "cluster",
            {},
        )

        if not isinstance(
            cluster,
            dict,
        ):
            return "unknown"

        status = cluster.get(
            "status"
        )

        if not status:
            return "unknown"

        return str(
            status
        ).strip().lower()

    @staticmethod
    def _format_number(
        value: float,
    ) -> str:

        if float(
            value
        ).is_integer():

            return str(
                int(value)
            )

        return f"{value:.2f}"

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        cloudwatch = context.cloudwatch()

        if not isinstance(
            cloudwatch,
            dict,
        ):
            cloudwatch = {}

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

        if start or end:

            return ObservationPeriod(
                start=start,
                end=end,
            )

        value = context.observation_period

        if not isinstance(
            value,
            dict,
        ):
            return None

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