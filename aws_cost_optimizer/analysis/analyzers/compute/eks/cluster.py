"""
Amazon EKS cost optimization analyzer.

Rules
-----
1. EKS worker underutilization
2. EKS node-group underutilization
3. EKS minimum-capacity review
4. Pod CPU reservation overprovisioning
5. Pod memory reservation overprovisioning
6. GPU underutilization
7. EKS cluster with no observed worker capacity
8. EKS Kubernetes-version support review

Design
------
The analyzer detects cost-optimization opportunities.

It does NOT invent:

- replacement instance types
- exact node counts to remove
- savings amounts
- Spot eligibility
- autoscaler configuration
- Kubernetes upgrade targets
- Fargate-to-EC2 migrations
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, Optional

from ....base import Analyzer
from ....condition import EvidenceStatement
from ....context import AnalysisContext
from ....evidence import Evidence
from ....finding import (
    Finding,
    ObservationPeriod,
)
from ....registry import register


# ======================================================================
# DEFAULT THRESHOLDS
# ======================================================================

DEFAULT_LOW_CPU_AVERAGE_PERCENT = 20.0
DEFAULT_LOW_CPU_MAXIMUM_PERCENT = 50.0

DEFAULT_LOW_MEMORY_AVERAGE_PERCENT = 30.0
DEFAULT_LOW_MEMORY_MAXIMUM_PERCENT = 60.0

DEFAULT_MIN_COVERAGE_PERCENT = 80.0
DEFAULT_MIN_OBSERVATION_DAYS = 14.0

DEFAULT_HIGH_NODE_CPU_RESERVED_PERCENT = 70.0
DEFAULT_HIGH_NODE_MEMORY_RESERVED_PERCENT = 70.0

DEFAULT_HIGH_POD_CPU_RESERVED_PERCENT = 70.0
DEFAULT_HIGH_POD_MEMORY_RESERVED_PERCENT = 70.0

DEFAULT_LOW_GPU_UTILIZATION_PERCENT = 20.0

DEFAULT_MIN_NODEGROUP_INSTANCES = 1


# ======================================================================
# METRIC NAMES
# ======================================================================

CPU_UTILIZATION = "node_cpu_utilization"
CPU_LIMIT = "node_cpu_limit"
CPU_RESERVED = "node_cpu_reserved_capacity"
CPU_USAGE = "node_cpu_usage_total"

MEMORY_UTILIZATION = "node_memory_utilization"
MEMORY_LIMIT = "node_memory_limit"
MEMORY_RESERVED = "node_memory_reserved_capacity"
MEMORY_WORKING_SET = "node_memory_working_set"

NODE_COUNT = "cluster_node_count"
FAILED_NODE_COUNT = "cluster_failed_node_count"

NODE_PODS = "node_number_of_running_pods"
NODE_CONTAINERS = "node_number_of_running_containers"

GPU_LIMIT = "node_gpu_limit"
GPU_USAGE = "node_gpu_usage_total"
GPU_RESERVED = "node_gpu_reserved_capacity"
GPU_UTILIZATION = "node_gpu_utilization"

POD_CPU_UTILIZATION = "pod_cpu_utilization"
POD_CPU_OVER_LIMIT = (
    "pod_cpu_utilization_over_pod_limit"
)
POD_CPU_RESERVED = "pod_cpu_reserved_capacity"

POD_MEMORY_UTILIZATION = "pod_memory_utilization"
POD_MEMORY_OVER_LIMIT = (
    "pod_memory_utilization_over_pod_limit"
)
POD_MEMORY_RESERVED = (
    "pod_memory_reserved_capacity"
)

POD_GPU_LIMIT = "pod_gpu_limit"
POD_GPU_USAGE = "pod_gpu_usage_total"
POD_GPU_RESERVED = "pod_gpu_reserved_capacity"
POD_GPU_UTILIZATION = "pod_gpu_utilization"


# ======================================================================
# HELPERS
# ======================================================================

def _dict(
    value: Any,
) -> dict[str, Any]:

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def _list(
    value: Any,
) -> list[Any]:

    return (
        value
        if isinstance(
            value,
            list,
        )
        else []
    )


def _number(
    value: Any,
) -> float | None:

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
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return None


def _number_or_zero(
    value: Any,
) -> float:

    value = _number(
        value
    )

    return (
        value
        if value is not None
        else 0.0
    )


def _coverage_percent(
    metric: dict[str, Any],
) -> float | None:

    value = _number(
        metric.get(
            "coverage_percent"
        )
    )

    if value is not None:
        return value

    ratio = _number(
        metric.get(
            "coverage_ratio"
        )
    )

    if ratio is None:
        return None

    return (
        ratio * 100.0
    )


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
            evidence_keys
            or []
        ),
        unit=unit,
        observed=observed,
    )


# ======================================================================
# CONFIGURATION
# ======================================================================

def _config(
    context: AnalysisContext,
) -> dict[str, Any]:

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

        if not isinstance(
            root,
            dict,
        ):
            continue

        value = root.get(
            "eks",
            root,
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
    default: float,
) -> float:

    value = _config(
        context
    ).get(
        key
    )

    parsed = _number(
        value
    )

    if (
        parsed is None
        or parsed < 0
    ):
        return default

    return parsed


# ======================================================================
# RESOURCE DATA
# ======================================================================

def _configuration(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        context.configuration()
    )


def _compute(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        _configuration(
            context
        ).get(
            "compute"
        )
    )


def _cluster(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        _configuration(
            context
        ).get(
            "cluster"
        )
    )


def _cluster_status(
    context: AnalysisContext,
) -> str:

    return str(
        _cluster(context).get(
            "status"
        )
        or "unknown"
    ).strip().lower()


def _nodegroups(
    context: AnalysisContext,
) -> list[dict[str, Any]]:

    return [
        value
        for value in _list(
            _compute(context).get(
                "nodegroups"
            )
        )
        if isinstance(
            value,
            dict,
        )
    ]


def _ec2_instances(
    context: AnalysisContext,
) -> list[dict[str, Any]]:

    return [
        value
        for value in _list(
            _compute(context).get(
                "ec2_instances"
            )
        )
        if isinstance(
            value,
            dict,
        )
    ]


# ======================================================================
# CLOUDWATCH GROUPS
# ======================================================================

def _cloudwatch_group(
    context: AnalysisContext,
    group: str,
) -> dict[str, Any]:

    return _dict(
        context.cloudwatch().get(
            group
        )
    )


def _metric_aggregate(
    context: AnalysisContext,
    name: str,
    group: str,
) -> dict[str, Any]:

    metrics = _dict(
        _cloudwatch_group(
            context,
            group,
        ).get(
            "metrics"
        )
    )

    metric = metrics.get(
        name
    )

    return (
        metric
        if isinstance(
            metric,
            dict,
        )
        else {
            "status":
                "missing",

            "has_data":
                False,

            "average":
                None,

            "minimum":
                None,

            "maximum":
                None,

            "coverage_percent":
                None,
        }
    )


def _metric_ready(
    context: AnalysisContext,
    name: str,
    group: str,
    *,
    require_maximum: bool = False,
) -> bool:

    metric = _metric_aggregate(
        context,
        name,
        group,
    )

    if (
        metric.get(
            "has_data"
        )
        is not True
    ):
        return False

    if (
        metric.get(
            "average"
        )
        is None
    ):
        return False

    if require_maximum and (
        metric.get(
            "maximum"
        )
        is None
    ):
        return False

    coverage = _coverage_percent(
        metric
    )

    if coverage is None:
        return False

    return True


# ======================================================================
# NODE SERIES
# ======================================================================

def _node_series(
    context: AnalysisContext,
    metric_name: str,
) -> list[dict[str, Any]]:

    group = _cloudwatch_group(
        context,
        "nodes",
    )

    series = _dict(
        group.get(
            "series"
        )
    ).get(
        metric_name,
        []
    )

    return [
        value
        for value in _list(
            series
        )
        if isinstance(
            value,
            dict,
        )
    ]


def _series_dimensions(
    metric: dict[str, Any],
) -> dict[str, str]:

    dimensions = metric.get(
        "dimensions",
        [],
    )

    result = {}

    for dimension in _list(
        dimensions
    ):

        if not isinstance(
            dimension,
            dict,
        ):
            continue

        name = dimension.get(
            "Name"
        )

        value = dimension.get(
            "Value"
        )

        if name and value is not None:
            result[
                str(name)
            ] = str(value)

    return result


def _node_series_index(
    context: AnalysisContext,
) -> dict[
    str,
    dict[str, list[dict[str, Any]]]
]:

    result: dict[
        str,
        dict[str, list[dict[str, Any]]]
    ] = defaultdict(
        lambda: defaultdict(list)
    )

    metric_names = (
        CPU_UTILIZATION,
        MEMORY_UTILIZATION,
        CPU_RESERVED,
        MEMORY_RESERVED,
        CPU_LIMIT,
        MEMORY_LIMIT,
        GPU_LIMIT,
        GPU_USAGE,
        GPU_RESERVED,
        GPU_UTILIZATION,
        NODE_PODS,
        NODE_CONTAINERS,
    )

    for metric_name in metric_names:

        for series in _node_series(
            context,
            metric_name,
        ):

            dimensions = _series_dimensions(
                series
            )

            instance_id = (
                dimensions.get(
                    "InstanceId"
                )
            )

            if not instance_id:
                continue

            result[
                instance_id
            ][
                metric_name
            ].append(
                series
            )

    return result


# ======================================================================
# POD SERIES
# ======================================================================

def _pod_series(
    context: AnalysisContext,
    metric_name: str,
) -> list[dict[str, Any]]:

    group = _cloudwatch_group(
        context,
        "pods",
    )

    series = _dict(
        group.get(
            "series"
        )
    ).get(
        metric_name,
        []
    )

    return [
        value
        for value in _list(
            series
        )
        if isinstance(
            value,
            dict,
        )
    ]


# ======================================================================
# SERIES VALUE HELPERS
# ======================================================================

def _series_average(
    series: dict[str, Any],
) -> float | None:

    summary = _dict(
        series.get(
            "summary"
        )
    )

    return _number(
        summary.get(
            "average",
            series.get(
                "average"
            ),
        )
    )


def _series_maximum(
    series: dict[str, Any],
) -> float | None:

    summary = _dict(
        series.get(
            "summary"
        )
    )

    return _number(
        summary.get(
            "maximum",
            series.get(
                "maximum"
            ),
        )
    )


def _series_coverage(
    series: dict[str, Any],
) -> float | None:

    value = _number(
        series.get(
            "coverage_percent"
        )
    )

    if value is not None:
        return value

    return _coverage_percent(
        series
    )


def _series_has_data(
    series: dict[str, Any],
) -> bool:

    return (
        series.get(
            "status"
        )
        == "ok"
        and series.get(
            "has_data"
        )
        is True
    )


# ======================================================================
# NODEGROUP UTILIZATION
# ======================================================================

def _instance_to_nodegroup(
    context: AnalysisContext,
) -> dict[str, str]:

    return {
        str(instance.get("instance_id")):
            str(instance.get("nodegroup"))
        for instance
        in _ec2_instances(context)
        if (
            instance.get("instance_id")
            and instance.get("nodegroup")
        )
    }


def _nodegroup_metrics(
    context: AnalysisContext,
) -> dict[
    str,
    dict[str, Any]
]:

    instance_to_nodegroup = (
        _instance_to_nodegroup(
            context
        )
    )

    node_index = (
        _node_series_index(
            context
        )
    )

    result: dict[
        str,
        dict[str, Any]
    ] = {}

    for instance_id, metrics in (
        node_index.items()
    ):

        nodegroup = (
            instance_to_nodegroup.get(
                instance_id
            )
        )

        if not nodegroup:
            continue

        entry = result.setdefault(
            nodegroup,
            {
                "instance_ids": [],
                "cpu": [],
                "memory": [],
                "cpu_max": [],
                "memory_max": [],
            }
        )

        entry[
            "instance_ids"
        ].append(
            instance_id
        )

        cpu_values = [
            _series_average(
                value
            )
            for value
            in metrics.get(
                CPU_UTILIZATION,
                [],
            )
        ]

        memory_values = [
            _series_average(
                value
            )
            for value
            in metrics.get(
                MEMORY_UTILIZATION,
                [],
            )
        ]

        cpu_max_values = [
            _series_maximum(
                value
            )
            for value
            in metrics.get(
                CPU_UTILIZATION,
                [],
            )
        ]

        memory_max_values = [
            _series_maximum(
                value
            )
            for value
            in metrics.get(
                MEMORY_UTILIZATION,
                [],
            )
        ]

        entry["cpu"].extend(
            value
            for value
            in cpu_values
            if value is not None
        )

        entry["memory"].extend(
            value
            for value
            in memory_values
            if value is not None
        )

        entry["cpu_max"].extend(
            value
            for value
            in cpu_max_values
            if value is not None
        )

        entry["memory_max"].extend(
            value
            for value
            in memory_max_values
            if value is not None
        )

    return result


def _mean(
    values: Iterable[float],
) -> float | None:

    values = list(
        values
    )

    if not values:
        return None

    return (
        sum(values)
        / len(values)
    )


# ======================================================================
# OBSERVATION PERIOD
# ======================================================================

def _observation_period(
    context: AnalysisContext,
) -> ObservationPeriod | None:

    cloudwatch = context.cloudwatch()

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

    value = (
        context.observation_period
    )

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


def _observation_days(
    context: AnalysisContext,
) -> float | None:

    period = _observation_period(
        context
    )

    if period is None:
        return None

    start = getattr(period, "start", None)
    end = getattr(period, "end", None)

    if not start or not end:
        return None

    try:

        from datetime import datetime

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

        return (
            (end_dt - start_dt).total_seconds()
            / 86400.0
        )

    except (TypeError, ValueError):
        return None


def _minimum_observation_period_met(
    context: AnalysisContext,
) -> bool:

    required = _threshold(
        context,
        "min_observation_days",
        DEFAULT_MIN_OBSERVATION_DAYS,
    )

    observed = _observation_days(
        context
    )

    if observed is None:
        return False

    return observed >= required


# ======================================================================
# ANALYZER
# ======================================================================

@register
class EKSAnalyzer(Analyzer):

    name = "eks"
    version = "8.0"

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

        if (
            _cluster_status(context)
            != "active"
        ):
            return []

        findings: list[Finding] = []

        detectors = (
            self._check_extended_support,
            self._check_no_observed_worker_capacity,
            self._check_low_cluster_utilization,
            self._check_nodegroup_underutilization,
            self._check_minimum_capacity_review,
            self._check_pod_cpu_overprovisioning,
            self._check_pod_memory_overprovisioning,
            self._check_gpu_underutilization,
        )

        for detector in detectors:

            finding = detector(
                context
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    # ==================================================================
    # RULE 1: VERSION SUPPORT
    # ==================================================================

    def _check_extended_support(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        config = _config(
            context
        )

        versions = config.get(
            "extended_support_versions",
            [],
        )

        if not isinstance(
            versions,
            list,
        ):
            return None

        version = (
            _cluster(context).get(
                "version"
            )
        )

        if not version:
            return None

        if str(version) not in {
            str(value)
            for value in versions
        }:
            return None

        return self._finding(
            context=context,
            finding_type="eks_extended_support_review",
            title=(
                "Review EKS Kubernetes version support"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "The cluster Kubernetes version is explicitly "
                "configured in the analysis profile as being in "
                "extended-support coverage. Extended support can "
                "increase EKS control-plane cost."
            ),
            statements=[
                _statement(
                    name="kubernetes_version",
                    value=version,
                    description=(
                        "Kubernetes version reported by EKS."
                    ),
                    source=[
                        "EKS.DescribeCluster"
                    ],
                    evidence_keys=[
                        "configuration.cluster.version"
                    ],
                    observed=True,
                )
            ],
            metadata={
                "rule":
                    "extended_support_version",

                "kubernetes_version":
                    version,

                "configured_extended_support_versions":
                    versions,

                "region":
                    context.region,
            },
            limitations=[
                (
                    "The analyzer does not invent an upgrade target."
                ),
                (
                    "The finding depends on the configured "
                    "version-support catalog being current."
                ),
                (
                    "Upgrade compatibility and operational risk "
                    "must be reviewed before changing the version."
                ),
            ],
            recommendation_eligible=False,
        )

    # ==================================================================
    # RULE 2: NO OBSERVED WORKER CAPACITY
    # ==================================================================

    def _check_no_observed_worker_capacity(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        compute = _compute(
            context
        )

        inventory_status = str(
            compute.get(
                "inventory_status",
                "unknown",
            )
        ).lower()

        if inventory_status != "complete":
            return None

        node_count = (
            _metric_aggregate(
                context,
                NODE_COUNT,
                "cluster",
            )
        )

        if not _metric_ready(
            context,
            NODE_COUNT,
            "cluster",
        ):
            return None

        observed_node_count = (
            _number(
                node_count.get(
                    "average"
                )
            )
        )

        if (
            observed_node_count is None
            or observed_node_count > 0
        ):
            return None

        nodegroups = _nodegroups(
            context
        )

        fargate_profiles = _list(
            compute.get(
                "fargate_profiles"
            )
        )

        if nodegroups or fargate_profiles:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_no_observed_worker_capacity"
            ),
            title=(
                "EKS cluster has no observed worker capacity"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Container Insights reports zero observed "
                "worker nodes during the analysis period and "
                "the collector did not discover managed "
                "nodegroups or Fargate profiles."
            ),
            statements=[
                self._metric_statement(
                    context,
                    NODE_COUNT,
                    "cluster",
                ),
                _statement(
                    name="managed_nodegroup_count",
                    value=len(
                        nodegroups
                    ),
                    description=(
                        "Managed EKS nodegroups discovered."
                    ),
                    source=[
                        "EKS.ListNodegroups"
                    ],
                    evidence_keys=[
                        "configuration.compute.nodegroups"
                    ],
                    observed=True,
                ),
            ],
            metadata={
                "rule":
                    "no_observed_worker_capacity",

                "observed_node_count":
                    observed_node_count,

                "managed_nodegroup_count":
                    len(nodegroups),

                "fargate_profile_count":
                    len(fargate_profiles),
            },
            limitations=[
                (
                    "No observed worker capacity does not prove "
                    "that the cluster is unused."
                ),
                (
                    "The environment may use a compute path not "
                    "represented by managed nodegroups."
                ),
                (
                    "Scheduled or intermittent workloads may not "
                    "appear in the selected observation period."
                ),
            ],
            recommendation_eligible=False,
        )

    # ==================================================================
    # RULE 3: CLUSTER WORKER UNDERUTILIZATION
    # ==================================================================

    def _check_low_cluster_utilization(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _ec2_instances(
            context
        ):
            return None

        if not _minimum_observation_period_met(
            context
        ):
            return None

        required = (
            CPU_UTILIZATION,
            MEMORY_UTILIZATION,
            NODE_COUNT,
        )

        for metric_name in required:

            if not _metric_ready(
                context,
                metric_name,
                "cluster",
                require_maximum=(
                    metric_name
                    != NODE_COUNT
                ),
            ):
                return None

        cpu = _metric_aggregate(
            context,
            CPU_UTILIZATION,
            "cluster",
        )

        memory = _metric_aggregate(
            context,
            MEMORY_UTILIZATION,
            "cluster",
        )

        node_count = _metric_aggregate(
            context,
            NODE_COUNT,
            "cluster",
        )

        low_cpu_average = _threshold(
            context,
            "low_cpu_average_percent",
            DEFAULT_LOW_CPU_AVERAGE_PERCENT,
        )

        low_cpu_maximum = _threshold(
            context,
            "low_cpu_maximum_percent",
            DEFAULT_LOW_CPU_MAXIMUM_PERCENT,
        )

        low_memory_average = _threshold(
            context,
            "low_memory_average_percent",
            DEFAULT_LOW_MEMORY_AVERAGE_PERCENT,
        )

        low_memory_maximum = _threshold(
            context,
            "low_memory_maximum_percent",
            DEFAULT_LOW_MEMORY_MAXIMUM_PERCENT,
        )

        minimum_coverage = _threshold(
            context,
            "min_coverage_percent",
            DEFAULT_MIN_COVERAGE_PERCENT,
        )

        minimum_days = _threshold(
            context,
            "min_observation_days",
            DEFAULT_MIN_OBSERVATION_DAYS,
        )

        if (
            _number(
                cpu.get(
                    "average"
                )
            ) is None
            or _number(
                cpu.get(
                    "maximum"
                )
            ) is None
            or _number(
                memory.get(
                    "average"
                )
            ) is None
            or _number(
                memory.get(
                    "maximum"
                )
            ) is None
        ):
            return None

        if (
            _number(
                cpu.get(
                    "average"
                )
            )
            > low_cpu_average
        ):
            return None

        if (
            _number(
                memory.get(
                    "average"
                )
            )
            > low_memory_average
        ):
            return None

        if (
            _number(
                cpu.get(
                    "maximum"
                )
            )
            > low_cpu_maximum
        ):
            return None

        if (
            _number(
                memory.get(
                    "maximum"
                )
            )
            > low_memory_maximum
        ):
            return None

        for metric in (
            cpu,
            memory,
            node_count,
        ):

            coverage = _coverage_percent(
                metric
            )

            if (
                coverage is None
                or coverage < minimum_coverage
            ):
                return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_low_worker_utilization"
            ),
            title=(
                "EKS worker capacity is strongly underutilized"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "EC2-backed EKS worker capacity shows sustained "
                "low CPU and memory utilization, including "
                "observed peaks, over a sufficiently covered "
                "observation period."
            ),
            statements=[
                self._metric_statement(
                    context,
                    CPU_UTILIZATION,
                    "cluster",
                ),
                self._metric_statement(
                    context,
                    MEMORY_UTILIZATION,
                    "cluster",
                ),
                self._metric_statement(
                    context,
                    NODE_COUNT,
                    "cluster",
                ),
                self._worker_inventory_statement(
                    context
                ),
            ],
            metadata={
                "rule":
                    "cluster_worker_underutilization",

                "cpu":
                    cpu,

                "memory":
                    memory,

                "node_count":
                    node_count,
            },
            limitations=[
                (
                    "Cluster-level utilization identifies an "
                    "environment-wide signal but not the exact "
                    "nodegroup or instance to change."
                ),
                (
                    "The finding does not select a replacement "
                    "instance type."
                ),
                (
                    "The finding does not estimate savings."
                ),
            ],
            recommendation_eligible=True,
        )

    # ==================================================================
    # RULE 4: NODEGROUP UNDERUTILIZATION
    # ==================================================================

    def _check_nodegroup_underutilization(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        nodegroups = _nodegroups(
            context
        )

        if not nodegroups:
            return None

        group_metrics = _nodegroup_metrics(
            context
        )

        if not group_metrics:
            return None

        low_cpu_average = _threshold(
            context,
            "low_cpu_average_percent",
            DEFAULT_LOW_CPU_AVERAGE_PERCENT,
        )

        low_cpu_maximum = _threshold(
            context,
            "low_cpu_maximum_percent",
            DEFAULT_LOW_CPU_MAXIMUM_PERCENT,
        )

        low_memory_average = _threshold(
            context,
            "low_memory_average_percent",
            DEFAULT_LOW_MEMORY_AVERAGE_PERCENT,
        )

        low_memory_maximum = _threshold(
            context,
            "low_memory_maximum_percent",
            DEFAULT_LOW_MEMORY_MAXIMUM_PERCENT,
        )

        minimum_instances = int(
            _threshold(
                context,
                "min_nodegroup_instances",
                DEFAULT_MIN_NODEGROUP_INSTANCES,
            )
        )

        candidates = []

        for nodegroup in nodegroups:

            name = nodegroup.get(
                "name"
            )

            if not name:
                continue

            metrics = group_metrics.get(
                str(name)
            )

            if not metrics:
                continue

            instance_count = len(
                metrics.get(
                    "instance_ids",
                    [],
                )
            )

            if instance_count < minimum_instances:
                continue

            cpu_avg = _mean(
                metrics.get(
                    "cpu",
                    [],
                )
            )

            memory_avg = _mean(
                metrics.get(
                    "memory",
                    [],
                )
            )

            cpu_max = (
                max(
                    metrics.get(
                        "cpu_max",
                        [],
                    )
                )
                if metrics.get(
                    "cpu_max"
                )
                else None
            )

            memory_max = (
                max(
                    metrics.get(
                        "memory_max",
                        [],
                    )
                )
                if metrics.get(
                    "memory_max"
                )
                else None
            )

            if (
                cpu_avg is None
                or memory_avg is None
                or cpu_max is None
                or memory_max is None
            ):
                continue

            if cpu_avg > low_cpu_average:
                continue

            if memory_avg > low_memory_average:
                continue

            if cpu_max > low_cpu_maximum:
                continue

            if memory_max > low_memory_maximum:
                continue

            candidates.append(
                {
                    "nodegroup":
                        name,

                    "instance_count":
                        instance_count,

                    "instance_ids":
                        metrics.get(
                            "instance_ids",
                            [],
                        ),

                    "cpu_average":
                        cpu_avg,

                    "cpu_maximum":
                        cpu_max,

                    "memory_average":
                        memory_avg,

                    "memory_maximum":
                        memory_max,
                }
            )

        if not candidates:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_nodegroup_underutilization"
            ),
            title=(
                "EKS node group shows sustained underutilization"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                f"{len(candidates)} managed node group(s) show "
                "low observed CPU and memory utilization across "
                "their identified EC2 workers."
            ),
            statements=[
                _statement(
                    name="underutilized_nodegroups",
                    value=candidates,
                    description=(
                        "Managed node groups whose identified "
                        "worker instances show sustained low "
                        "utilization."
                    ),
                    source=[
                        "EKS",
                        "EC2",
                        "CloudWatch.ContainerInsights",
                    ],
                    evidence_keys=[
                        "configuration.compute.nodegroups",
                        "configuration.compute.ec2_instances",
                        "observations.cloudwatch.nodes",
                    ],
                    observed=True,
                )
            ],
            metadata={
                "rule":
                    "nodegroup_underutilization",

                "nodegroups":
                    candidates,
            },
            limitations=[
                (
                    "Metrics may not cover every node in the "
                    "node group."
                ),
                (
                    "Cluster/nodegroup peaks outside the "
                    "observation window are not represented."
                ),
                (
                    "The finding does not specify an exact "
                    "node count to remove."
                ),
            ],
            recommendation_eligible=False,
        )

    # ==================================================================
    # RULE 5: MINIMUM CAPACITY REVIEW
    # ==================================================================

    def _check_minimum_capacity_review(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        candidates = []

        for nodegroup in _nodegroups(
            context
        ):

            scaling = _dict(
                nodegroup.get(
                    "scaling"
                )
            )

            minimum = _number(
                scaling.get(
                    "min_size"
                )
            )

            desired = _number(
                scaling.get(
                    "desired_size"
                )
            )

            maximum = _number(
                scaling.get(
                    "max_size"
                )
            )

            if (
                minimum is None
                or desired is None
            ):
                continue

            if minimum <= 0:
                continue

            if desired != minimum:
                continue

            candidates.append(
                {
                    "nodegroup":
                        nodegroup.get(
                            "name"
                        ),

                    "minimum_size":
                        minimum,

                    "desired_size":
                        desired,

                    "maximum_size":
                        maximum,

                    "capacity_type":
                        nodegroup.get(
                            "capacity_type"
                        ),
                }
            )

        if not candidates:
            return None

        # Only issue this as a review signal. A min size equal to
        # desired is not itself waste.
        low_utilization = (
            self._cluster_low_utilization_available(
                context
            )
        )

        if not low_utilization:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_minimum_capacity_review"
            ),
            title=(
                "Review EKS node-group minimum capacity"
            ),
            severity="low",
            confidence="medium",
            reason=(
                "One or more node groups are operating at their "
                "configured minimum capacity while the cluster "
                "also shows sustained low resource utilization."
            ),
            statements=[
                _statement(
                    name="nodegroups_at_minimum_capacity",
                    value=candidates,
                    description=(
                        "Managed node groups whose desired "
                        "capacity equals minimum capacity."
                    ),
                    source=[
                        "EKS.DescribeNodegroup"
                    ],
                    evidence_keys=[
                        "configuration.compute.nodegroups"
                    ],
                    observed=True,
                ),
                self._metric_statement(
                    context,
                    CPU_UTILIZATION,
                    "cluster",
                ),
                self._metric_statement(
                    context,
                    MEMORY_UTILIZATION,
                    "cluster",
                ),
            ],
            metadata={
                "rule":
                    "minimum_capacity_review",

                "nodegroups":
                    candidates,
            },
            limitations=[
                (
                    "A configured minimum may be required for "
                    "availability, latency, resilience, or "
                    "scheduled workloads."
                ),
                (
                    "The analyzer does not prescribe a new "
                    "minimum size."
                ),
            ],
            recommendation_eligible=False,
        )

    # ==================================================================
    # RULE 6: POD CPU
    # ==================================================================

    def _check_pod_cpu_overprovisioning(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _minimum_observation_period_met(
            context
        ):
            return None

        reserved = _metric_aggregate(
            context,
            POD_CPU_RESERVED,
            "pods",
        )

        utilization = _metric_aggregate(
            context,
            POD_CPU_UTILIZATION,
            "pods",
        )

        if not self._metric_pair_ready(
            reserved,
            utilization,
        ):
            return None

        threshold = _threshold(
            context,
            "high_pod_cpu_reserved_percent",
            DEFAULT_HIGH_POD_CPU_RESERVED_PERCENT,
        )

        reserved_average = _number(
            reserved.get(
                "average"
            )
        )

        utilization_average = _number(
            utilization.get(
                "average"
            )
        )

        if (
            reserved_average is None
            or utilization_average is None
        ):
            return None

        if reserved_average < threshold:
            return None

        if (
            utilization_average
            >= reserved_average * 0.70
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_pod_cpu_request_overprovisioning"
            ),
            title=(
                "EKS pod CPU reservations are substantially "
                "higher than observed usage"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Observed pod CPU reservation is high while "
                "actual pod CPU utilization is substantially "
                "lower across the collected pod series."
            ),
            statements=[
                self._metric_statement(
                    context,
                    POD_CPU_RESERVED,
                    "pods",
                ),
                self._metric_statement(
                    context,
                    POD_CPU_UTILIZATION,
                    "pods",
                ),
            ],
            metadata={
                "rule":
                    "pod_cpu_request_overprovisioning",

                "reserved":
                    reserved,

                "utilization":
                    utilization,

                "threshold_percent":
                    threshold,
            },
            limitations=[
                (
                    "Pod reservation can be intentionally high "
                    "to guarantee scheduling capacity."
                ),
                (
                    "The finding does not prescribe a CPU request."
                ),
                (
                    "Peak workload behavior must be reviewed."
                ),
            ],
            recommendation_eligible=True,
        )

    # ==================================================================
    # RULE 7: POD MEMORY
    # ==================================================================

    def _check_pod_memory_overprovisioning(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _minimum_observation_period_met(
            context
        ):
            return None

        reserved = _metric_aggregate(
            context,
            POD_MEMORY_RESERVED,
            "pods",
        )

        utilization = _metric_aggregate(
            context,
            POD_MEMORY_UTILIZATION,
            "pods",
        )

        if not self._metric_pair_ready(
            reserved,
            utilization,
        ):
            return None

        threshold = _threshold(
            context,
            "high_pod_memory_reserved_percent",
            DEFAULT_HIGH_POD_MEMORY_RESERVED_PERCENT,
        )

        reserved_average = _number(
            reserved.get(
                "average"
            )
        )

        utilization_average = _number(
            utilization.get(
                "average"
            )
        )

        if (
            reserved_average is None
            or utilization_average is None
        ):
            return None

        if reserved_average < threshold:
            return None

        if (
            utilization_average
            >= reserved_average * 0.70
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_pod_memory_request_overprovisioning"
            ),
            title=(
                "EKS pod memory reservations are substantially "
                "higher than observed usage"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "Observed pod memory reservation is high while "
                "actual pod memory utilization is substantially "
                "lower across the collected pod series."
            ),
            statements=[
                self._metric_statement(
                    context,
                    POD_MEMORY_RESERVED,
                    "pods",
                ),
                self._metric_statement(
                    context,
                    POD_MEMORY_UTILIZATION,
                    "pods",
                ),
            ],
            metadata={
                "rule":
                    "pod_memory_request_overprovisioning",

                "reserved":
                    reserved,

                "utilization":
                    utilization,

                "threshold_percent":
                    threshold,
            },
            limitations=[
                (
                    "Memory requests may intentionally include "
                    "headroom for application stability."
                ),
                (
                    "The finding does not prescribe a memory request."
                ),
                (
                    "Memory peaks and application behavior "
                    "must be validated."
                ),
            ],
            recommendation_eligible=True,
        )

    # ==================================================================
    # RULE 8: GPU
    # ==================================================================

    def _check_gpu_underutilization(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _minimum_observation_period_met(
            context
        ):
            return None

        direct_utilization = _metric_aggregate(
            context,
            GPU_UTILIZATION,
            "nodes",
        )

        gpu_limit = _metric_aggregate(
            context,
            GPU_LIMIT,
            "nodes",
        )

        gpu_usage = _metric_aggregate(
            context,
            GPU_USAGE,
            "nodes",
        )

        minimum_coverage = _threshold(
            context,
            "min_coverage_percent",
            DEFAULT_MIN_COVERAGE_PERCENT,
        )

        utilization = None
        method = "direct"
        metrics_used: tuple[dict[str, Any], ...] = ()

        if (
            direct_utilization.get(
                "has_data"
            )
            is True
        ):

            utilization = _number(
                direct_utilization.get(
                    "average"
                )
            )

            if utilization is not None:
                metrics_used = (
                    direct_utilization,
                )

        if utilization is None:

            if (
                gpu_limit.get(
                    "has_data"
                )
                is not True
                or gpu_usage.get(
                    "has_data"
                )
                is not True
            ):
                return None

            limit = _number(
                gpu_limit.get(
                    "average"
                )
            )

            usage = _number(
                gpu_usage.get(
                    "average"
                )
            )

            if (
                limit is None
                or usage is None
                or limit <= 0
            ):
                return None

            utilization = (
                usage
                / limit
                * 100.0
            )

            method = "usage_divided_by_limit"
            metrics_used = (
                gpu_limit,
                gpu_usage,
            )

        for metric in metrics_used:

            coverage = _coverage_percent(
                metric
            )

            if (
                coverage is None
                or coverage
                < minimum_coverage
            ):
                return None

        threshold = _threshold(
            context,
            "low_gpu_utilization_percent",
            DEFAULT_LOW_GPU_UTILIZATION_PERCENT,
        )

        if utilization > threshold:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "eks_gpu_underutilization"
            ),
            title=(
                "EKS GPU worker capacity appears underutilized"
            ),
            severity="high",
            confidence="medium",
            reason=(
                f"Observed GPU utilization is approximately "
                f"{utilization:.2f}%, below the configured "
                f"threshold of {threshold:.2f}%."
            ),
            statements=[
                self._metric_statement(
                    context,
                    GPU_LIMIT,
                    "nodes",
                ),
                self._metric_statement(
                    context,
                    GPU_USAGE,
                    "nodes",
                ),
                self._metric_statement(
                    context,
                    GPU_UTILIZATION,
                    "nodes",
                ),
            ],
            metadata={
                "rule":
                    "gpu_underutilization",

                "utilization_percent":
                    utilization,

                "threshold_percent":
                    threshold,

                "calculation_method":
                    method,
            },
            limitations=[
                (
                    "GPU utilization does not determine whether "
                    "a smaller or different GPU instance is compatible."
                ),
                (
                    "Scheduling constraints and workload requirements "
                    "must be reviewed."
                ),
                (
                    "No replacement GPU instance is selected."
                ),
            ],
            recommendation_eligible=True,
        )

    # ==================================================================
    # COMMON CHECKS
    # ==================================================================

    @staticmethod
    def _metric_pair_ready(
        first: dict[str, Any],
        second: dict[str, Any],
    ) -> bool:

        for metric in (
            first,
            second,
        ):

            if (
                metric.get(
                    "has_data"
                )
                is not True
            ):
                return False

            if (
                _number(
                    metric.get(
                        "average"
                    )
                )
                is None
            ):
                return False

            coverage = _coverage_percent(
                metric
            )

            if coverage is None:
                return False

        return True

    def _cluster_low_utilization_available(
        self,
        context: AnalysisContext,
    ) -> bool:

        cpu = _metric_aggregate(
            context,
            CPU_UTILIZATION,
            "cluster",
        )

        memory = _metric_aggregate(
            context,
            MEMORY_UTILIZATION,
            "cluster",
        )

        if not self._metric_pair_ready(
            cpu,
            memory,
        ):
            return False

        cpu_avg = _number(
            cpu.get(
                "average"
            )
        )

        memory_avg = _number(
            memory.get(
                "average"
            )
        )

        if (
            cpu_avg is None
            or memory_avg is None
        ):
            return False

        return (
            cpu_avg
            <= _threshold(
                context,
                "low_cpu_average_percent",
                DEFAULT_LOW_CPU_AVERAGE_PERCENT,
            )
            and
            memory_avg
            <= _threshold(
                context,
                "low_memory_average_percent",
                DEFAULT_LOW_MEMORY_AVERAGE_PERCENT,
            )
        )

    # ==================================================================
    # EVIDENCE
    # ==================================================================

    @staticmethod
    def _metric_statement(
        context: AnalysisContext,
        name: str,
        group: str,
    ) -> EvidenceStatement:

        metric = _metric_aggregate(
            context,
            name,
            group,
        )

        return _statement(
            name=name,
            value=metric,
            description=(
                f"Observed Container Insights "
                f"{name} metric."
            ),
            source=[
                "CloudWatch.ContainerInsights"
            ],
            evidence_keys=[
                (
                    f"observations.cloudwatch."
                    f"{group}.metrics.{name}"
                )
            ],
            observed=(
                metric.get(
                    "has_data"
                )
                is True
            ),
        )

    @staticmethod
    def _worker_inventory_statement(
        context: AnalysisContext,
    ) -> EvidenceStatement:

        compute = _compute(
            context
        )

        return _statement(
            name="worker_inventory",
            value={
                "ec2_instance_count":
                    len(
                        _ec2_instances(
                            context
                        )
                    ),

                "nodegroup_count":
                    len(
                        _nodegroups(
                            context
                        )
                    ),

                "desired_nodes":
                    _dict(
                        compute.get(
                            "summary"
                        )
                    ).get(
                        "desired_node_count"
                    ),
            },
            description=(
                "Current EC2-backed EKS worker inventory."
            ),
            source=[
                "EKS",
                "EC2",
            ],
            evidence_keys=[
                "configuration.compute.nodegroups",
                "configuration.compute.ec2_instances",
            ],
            observed=True,
        )

    # ==================================================================
    # FINDING CREATION
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
        limitations: list[str],
        recommendation_eligible: bool = False,
    ) -> Finding:

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
                _observation_period(
                    context
                )
            ),

            limitations=list(
                limitations
            ),

            metadata=dict(
                metadata
            ),

            recommendation_eligible=recommendation_eligible,
        )

    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: dict[str, Any],
    ) -> Evidence:

        cloudwatch = context.cloudwatch()

        return Evidence(
            metrics={
                "cluster":
                    _cloudwatch_group(
                        context,
                        "cluster",
                    ).get(
                        "metrics",
                        {},
                    ),

                "nodes":
                    _cloudwatch_group(
                        context,
                        "nodes",
                    ).get(
                        "metrics",
                        {},
                    ),

                "pods":
                    _cloudwatch_group(
                        context,
                        "pods",
                    ).get(
                        "metrics",
                        {},
                    ),
            },

            configuration=dict(
                context.configuration()
                or {}
            ),

            topology=dict(
                context.topology()
                or {}
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

            billing=dict(
                context.billing()
                or {}
            ),

            data_quality={
                "cloudwatch":
                    cloudwatch.get(
                        "data_quality",
                        {},
                    ),

                "collector":
                    context.collector_data_quality(),
            },
        )