from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...base import Analyzer
from ...condition import EvidenceStatement
from ...context import AnalysisContext
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
from ...registry import register

SUPPORTED_RESOURCE_TYPES = frozenset(
    {
        "ec2_instance",
    }
)


# ---------------------------------------------------------------------------
# CPU thresholds
# ---------------------------------------------------------------------------

CPU_VERY_LOW = 10.0
CPU_LOW = 20.0

CPU_HIGH = 80.0
CPU_CRITICAL = 90.0

CPU_PEAK_MODERATE = 60.0
CPU_PEAK_HIGH = 80.0
CPU_PEAK_CRITICAL = 90.0


# ---------------------------------------------------------------------------
# Memory thresholds
# ---------------------------------------------------------------------------

MEMORY_LOW = 30.0
MEMORY_HIGH = 80.0
MEMORY_CRITICAL = 90.0


# ---------------------------------------------------------------------------
# Network / EBS activity thresholds
# ---------------------------------------------------------------------------

NETWORK_VERY_LOW_BYTES_PER_SECOND = 1024.0
NETWORK_LOW_BYTES_PER_SECOND = 10240.0

EBS_VERY_LOW_IOPS = 1.0
EBS_LOW_IOPS = 10.0


# ---------------------------------------------------------------------------
# Runtime / pricing thresholds
# ---------------------------------------------------------------------------

LONG_RUNNING_DAYS = 30

# Pricing-model findings are deliberately conservative.
# A running instance for >30 days is only evidence for REVIEW,
# not proof that Savings Plans / RI should be purchased.
PRICING_REVIEW_DAYS = 30


# ---------------------------------------------------------------------------
# EBS configuration
# ---------------------------------------------------------------------------

EBS_GP2_REVIEW_SIZE_GIB = 100.0


# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------

STOPPED_STATES = frozenset(
    {
        "stopped",
        "stopping",
        "hibernated",
    }
)

RUNNING_STATE = "running"


# ---------------------------------------------------------------------------
# Instance-family sizing information
#
# This is intentionally conservative.
# It is used only to prevent invalid "downsize" findings.
#
# We do NOT select a replacement instance here.
# A recommendation engine / pricing layer should do that.
# ---------------------------------------------------------------------------

STANDARD_FAMILY_SIZES: dict[str, tuple[str, ...]] = {
    "t2": (
        "nano",
        "micro",
        "small",
        "medium",
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "16xlarge",
    ),
    "t3": (
        "nano",
        "micro",
        "small",
        "medium",
        "large",
        "xlarge",
        "2xlarge",
    ),
    "t3a": (
        "nano",
        "micro",
        "small",
        "medium",
        "large",
        "xlarge",
        "2xlarge",
    ),
    "m5": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
    ),
    "m5a": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
    ),
    "m6i": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
        "32xlarge",
    ),
    "m6a": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
        "32xlarge",
    ),
    "c5": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "9xlarge",
        "12xlarge",
        "18xlarge",
        "24xlarge",
    ),
    "c5a": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
        "48xlarge",
    ),
    "c6i": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
        "32xlarge",
    ),
    "r5": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
    ),
    "r6i": (
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
        "32xlarge",
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalise_tag_value(
    tags: dict[str, Any],
    *names: str,
) -> str | None:
    for name in names:
        value = tags.get(name)

        if value is not None:
            value = str(value).strip()

            if value:
                return value

    return None


def _normalise_text(value: Any) -> str | None:
    if value is None:
        return None

    value = str(value).strip().lower()

    return value or None


@register
class EC2Analyzer(Analyzer):

    name = "ec2"
    version = "12.0"

    # =======================================================================
    # PUBLIC API
    # =======================================================================

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:
        return context.resource_type in SUPPORTED_RESOURCE_TYPES

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        data = self._extract_evidence(context)

        if not data["configuration_available"]:
            return []

        findings: list[Finding] = []

        # -------------------------------------------------------------------
        # 1. STOPPED
        # -------------------------------------------------------------------

        stopped = self._stopped_instance(
            context,
            data,
        )

        if stopped:
            findings.append(stopped)

        # A non-running instance must not receive running-utilization
        # findings.
        if data["state"] != RUNNING_STATE:
            return findings

        # -------------------------------------------------------------------
        # 2. MEMORY PRESSURE
        #
        # This must happen before rightsizing so CPU-only analysis cannot
        # incorrectly recommend downsizing a memory-constrained instance.
        # -------------------------------------------------------------------

        memory_pressure = self._memory_pressure(
            context,
            data,
        )

        if memory_pressure:
            findings.append(memory_pressure)

        # -------------------------------------------------------------------
        # 3. VERY LOW ACTIVITY
        # -------------------------------------------------------------------

        idle = self._idle_instance(
            context,
            data,
        )

        if idle:
            findings.append(idle)

        # -------------------------------------------------------------------
        # 4. OVERLOAD / UNDERSIZING
        # -------------------------------------------------------------------

        overload = self._overload_review(
            context,
            data,
        )

        if overload:
            findings.append(overload)

        # -------------------------------------------------------------------
        # 5. RIGHTSIZING
        #
        # Do not emit a generic rightsizing finding when:
        # - the instance is already an idle candidate
        # - memory pressure exists
        # - the workload shows significant peaks
        # - there is no smaller compatible size
        # -------------------------------------------------------------------

        if not idle and not memory_pressure and not overload:
            rightsizing = self._rightsizing(
                context,
                data,
            )

            if rightsizing:
                findings.append(rightsizing)

        # -------------------------------------------------------------------
        # 6. AUTO SCALING
        # -------------------------------------------------------------------

        autoscaling = self._autoscaling_review(
            context,
            data,
        )

        if autoscaling:
            findings.append(autoscaling)

        # -------------------------------------------------------------------
        # 7. SCHEDULING
        # -------------------------------------------------------------------

        scheduling = self._scheduling_review(
            context,
            data,
        )

        if scheduling:
            findings.append(scheduling)

        # -------------------------------------------------------------------
        # 8. PRICING MODEL
        # -------------------------------------------------------------------

        pricing = self._pricing_model_review(
            context,
            data,
        )

        if pricing:
            findings.append(pricing)

        # -------------------------------------------------------------------
        # 9. EBS
        # -------------------------------------------------------------------

        findings.extend(
            self._ebs_configuration_review(
                context,
                data,
            )
        )

        return findings

    # =======================================================================
    # EVIDENCE EXTRACTION
    # =======================================================================

    @staticmethod
    def _extract_evidence(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        configuration = _dict(context.configuration())

        observations = _dict(context.observations())

        topology = _dict(context.topology())

        cloudwatch = _dict(observations.get("cloudwatch"))

        metrics = _dict(cloudwatch.get("metrics"))

        activity = _dict(cloudwatch.get("activity"))

        autoscaling = _dict(topology.get("autoscaling"))

        tags = configuration.get("tags")

        if not isinstance(tags, dict):
            tags = {}

        volumes = configuration.get("volumes")

        if not isinstance(volumes, list):
            volumes = configuration.get("ebs_volumes")

        if not isinstance(volumes, list):
            volumes = topology.get("volumes")

        if not isinstance(volumes, list):
            volumes = []

        # -------------------------------------------------------------------
        # Metrics
        # -------------------------------------------------------------------

        cpu_average = EC2Analyzer._metric_value(
            metrics,
            "cpu_utilization",
        )

        cpu_max = EC2Analyzer._metric_value(
            metrics,
            "cpu_utilization_max",
        )

        network_in = EC2Analyzer._metric_value(
            metrics,
            "network_in",
        )

        network_out = EC2Analyzer._metric_value(
            metrics,
            "network_out",
        )

        ebs_read_ops = EC2Analyzer._metric_value(
            metrics,
            "ebs_read_ops",
        )

        ebs_write_ops = EC2Analyzer._metric_value(
            metrics,
            "ebs_write_ops",
        )

        memory_average = EC2Analyzer._metric_value(
            metrics,
            "mem_used_percent",
        )

        memory_max = EC2Analyzer._metric_value(
            metrics,
            "mem_used_percent_max",
        )

        # -------------------------------------------------------------------
        # Derived activity
        # -------------------------------------------------------------------

        network_bytes_per_second = _number(
            activity.get("average_network_bytes_per_second")
        )

        ebs_iops = _number(activity.get("ebs_iops"))

        # -------------------------------------------------------------------
        # Tags
        # -------------------------------------------------------------------

        environment = _normalise_tag_value(
            tags,
            "Environment",
            "environment",
            "Env",
            "env",
        )

        role = _normalise_tag_value(
            tags,
            "Role",
            "role",
            "ApplicationRole",
            "application_role",
        )

        workload = _normalise_tag_value(
            tags,
            "Workload",
            "workload",
            "WorkloadType",
            "workload_type",
        )

        name = _normalise_tag_value(
            tags,
            "Name",
            "name",
        )

        # -------------------------------------------------------------------
        # Availability
        # -------------------------------------------------------------------

        cpu_available = EC2Analyzer._metric_available(
            metrics,
            "cpu_utilization",
        )

        cpu_max_available = EC2Analyzer._metric_available(
            metrics,
            "cpu_utilization_max",
        )

        memory_available = EC2Analyzer._metric_available(
            metrics,
            "mem_used_percent",
        )

        memory_max_available = EC2Analyzer._metric_available(
            metrics,
            "mem_used_percent_max",
        )

        network_available = EC2Analyzer._metric_available(
            metrics,
            "network_in",
        ) and EC2Analyzer._metric_available(
            metrics,
            "network_out",
        )

        ebs_activity_available = EC2Analyzer._metric_available(
            metrics,
            "ebs_read_ops",
        ) and EC2Analyzer._metric_available(
            metrics,
            "ebs_write_ops",
        )

        launch_time = configuration.get("launch_time")

        runtime_days = EC2Analyzer._runtime_days(launch_time)

        return {
            # Configuration
            "configuration_available": bool(configuration),
            "instance_id": configuration.get("instance_id"),
            "instance_type": configuration.get("instance_type"),
            "state": (str(configuration.get("state") or "").strip().lower() or None),
            "launch_time": launch_time,
            "runtime_days": runtime_days,
            "name": name,
            "image_id": configuration.get("image_id"),
            "architecture": configuration.get("architecture"),
            "platform": configuration.get("platform"),
            "platform_details": configuration.get("platform_details"),
            "instance_lifecycle": configuration.get("instance_lifecycle"),
            "tenancy": configuration.get("tenancy"),
            "availability_zone": configuration.get("availability_zone"),
            "monitoring": configuration.get("monitoring"),
            "tags": tags,
            # Classification
            "environment": environment,
            "role": role,
            "workload": workload,
            # Metrics
            "metrics": metrics,
            "cpu_average": cpu_average,
            "cpu_max": cpu_max,
            "network_in": network_in,
            "network_out": network_out,
            "ebs_read_ops": ebs_read_ops,
            "ebs_write_ops": ebs_write_ops,
            "memory_average": memory_average,
            "memory_max": memory_max,
            # Derived activity
            "network_bytes_per_second": (network_bytes_per_second),
            "ebs_iops": ebs_iops,
            "traffic_observed": activity.get("traffic_observed"),
            "storage_activity_observed": activity.get("storage_activity_observed"),
            # Auto Scaling
            "autoscaling_managed": (autoscaling.get("managed") is True),
            "autoscaling_group_name": autoscaling.get("autoscaling_group_name"),
            "autoscaling_min_size": _number(autoscaling.get("min_size")),
            "autoscaling_max_size": _number(autoscaling.get("max_size")),
            "autoscaling_desired_capacity": _number(
                autoscaling.get("desired_capacity")
            ),
            # EBS
            "volumes": volumes,
            "ebs_volume_count": len(volumes),
            "ebs_evidence_available": bool(volumes),
            # Network dependencies (what this instance is attached to /
            # associated with -- required for finding types whose catalog
            # route declares a "dependencies" evidence requirement).
            "vpc_id": configuration.get("vpc_id"),
            "subnet_id": configuration.get("subnet_id"),
            "security_group_ids": configuration.get("security_group_ids"),
            "security_group_count": configuration.get("security_group_count"),
            "network_interface_count": configuration.get("network_interface_count"),
            # Evidence quality
            "cpu_evidence_available": cpu_available,
            "cpu_max_evidence_available": cpu_max_available,
            "memory_evidence_available": memory_available,
            "memory_max_evidence_available": memory_max_available,
            "network_evidence_available": network_available,
            "ebs_activity_evidence_available": (ebs_activity_available),
            "standard_metrics_available": (cpu_available or cpu_max_available),
            "cloudwatch_status": cloudwatch.get("status"),
            "observation_period": _dict(observations.get("period")),
        }

    # =======================================================================
    # FINDING 1 — STOPPED
    # =======================================================================

    def _stopped_instance(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] not in STOPPED_STATES:
            return None

        if not data["instance_id"]:
            return None

        return self._finding(
            context=context,
            finding_type="ec2_instance_stopped",
            title="Stopped EC2 instance should be reviewed",
            severity="medium",
            confidence="high",
            reason=(
                "The EC2 instance is currently stopped. A stopped "
                "instance does not normally incur EC2 instance "
                "compute charges, but attached EBS volumes, Elastic "
                "IP addresses, and other associated resources may "
                "continue to generate cost."
            ),
            statements=[
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "EC2 instance identifier.",
                ),
                self._statement(
                    "instance_type",
                    data["instance_type"],
                    "configuration.instance_type",
                    "Configured EC2 instance type.",
                ),
                self._statement(
                    "state",
                    data["state"],
                    "configuration.state",
                    "Current EC2 instance state.",
                ),
            ],
            metadata={
                "optimization_action": ("classify_stopped_instance"),
                "recommendation_category": ("elimination_or_scheduling"),
                "decision": (
                    "Determine whether the instance is still "
                    "required and review attached resources."
                ),
                "region": context.region,
                "evidence_quality": "high",
            },
            data=data,
            cost_optimization_type="elimination",
        )

    # =======================================================================
    # FINDING 2 — VERY LOW ACTIVITY
    # =======================================================================

    def _idle_instance(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != RUNNING_STATE:
            return None

        cpu = data["cpu_average"]

        if cpu is None:
            return None

        if cpu > CPU_VERY_LOW:
            return None

        cpu_peak = data["cpu_max"]

        if cpu_peak is not None and cpu_peak > CPU_PEAK_MODERATE:
            return None

        supporting_signals = 0

        network_low = False
        ebs_low = False
        memory_low = False

        if data["network_bytes_per_second"] is not None:
            network_low = (
                data["network_bytes_per_second"] <= NETWORK_VERY_LOW_BYTES_PER_SECOND
            )

            if network_low:
                supporting_signals += 1

        if data["ebs_iops"] is not None:
            ebs_low = data["ebs_iops"] <= EBS_VERY_LOW_IOPS

            if ebs_low:
                supporting_signals += 1

        if data["memory_average"] is not None:
            memory_low = data["memory_average"] <= MEMORY_LOW

            if memory_low:
                supporting_signals += 1

        # CPU alone is not sufficient for an idle finding.
        if supporting_signals == 0:
            return None

        confidence = "medium"

        if supporting_signals >= 2:
            confidence = "high"

        return self._finding(
            context=context,
            finding_type="ec2_instance_very_low_activity",
            title="EC2 instance has very low observed activity",
            severity="medium",
            confidence=confidence,
            reason=(
                "The running EC2 instance shows very low average "
                "CPU utilization together with independent low-"
                "activity evidence. This supports investigating "
                "whether the instance is required continuously, "
                "should be scheduled, or can be removed."
            ),
            statements=[
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "EC2 instance identifier.",
                ),
                self._statement(
                    "instance_type",
                    data["instance_type"],
                    "configuration.instance_type",
                    "Current EC2 instance type.",
                ),
                self._statement(
                    "cpu_average",
                    data["cpu_average"],
                    "observations.cloudwatch.metrics.cpu_utilization",
                    "Observed average CPU utilization in percent.",
                ),
                self._statement(
                    "cpu_max",
                    data["cpu_max"],
                    "observations.cloudwatch.metrics.cpu_utilization_max",
                    "Observed maximum CPU utilization in percent.",
                ),
                self._statement(
                    "network_bytes_per_second",
                    data["network_bytes_per_second"],
                    "observations.cloudwatch.activity.average_network_bytes_per_second",
                    "Observed average network traffic in bytes per second.",
                ),
                self._statement(
                    "ebs_iops",
                    data["ebs_iops"],
                    "observations.cloudwatch.activity.ebs_iops",
                    "Observed average EBS operations per second.",
                ),
                self._statement(
                    "memory_average",
                    data["memory_average"],
                    "observations.cloudwatch.metrics.mem_used_percent",
                    "Observed average memory utilization in percent when available.",
                ),
                self._statement(
                    "network_interface_count",
                    data["network_interface_count"],
                    "configuration.network_interface_count",
                    "Number of network interfaces attached to the instance.",
                ),
                self._statement(
                    "subnet_id",
                    data["subnet_id"],
                    "configuration.subnet_id",
                    "VPC subnet the instance is associated with.",
                ),
            ],
            metadata={
                "optimization_action": ("investigate_instance_utilization"),
                "recommendation_category": ("elimination_or_scheduling"),
                "supporting_signal_count": supporting_signals,
                "network_low": network_low,
                "ebs_low": ebs_low,
                "memory_low": memory_low,
                "decision": (
                    "First determine whether the workload is "
                    "required. If it is periodic, evaluate scheduling. "
                    "If it is obsolete, evaluate termination. "
                    "Only consider rightsizing if continuous operation "
                    "is confirmed."
                ),
                "region": context.region,
                "evidence_quality": confidence,
            },
            data=data,
        )

    # =======================================================================
    # FINDING 3 — OVERLOAD / UNDERSIZING
    # =======================================================================

    def _overload_review(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != RUNNING_STATE:
            return None

        cpu = data["cpu_average"]
        cpu_max = data["cpu_max"]

        memory = data["memory_average"]
        memory_max = data["memory_max"]

        cpu_pressure = cpu is not None and cpu >= CPU_HIGH

        cpu_peak_pressure = cpu_max is not None and cpu_max >= CPU_PEAK_CRITICAL

        memory_pressure = memory is not None and memory >= MEMORY_HIGH

        memory_peak_pressure = memory_max is not None and memory_max >= MEMORY_CRITICAL

        if not any(
            [
                cpu_pressure,
                cpu_peak_pressure,
                memory_pressure,
                memory_peak_pressure,
            ]
        ):
            return None

        signals = sum(
            [
                cpu_pressure,
                cpu_peak_pressure,
                memory_pressure,
                memory_peak_pressure,
            ]
        )

        confidence = "medium"

        if signals >= 2:
            confidence = "high"

        return self._finding(
            context=context,
            finding_type="ec2_instance_undersizing_candidate",
            title="EC2 instance shows capacity pressure",
            severity="medium",
            confidence=confidence,
            reason=(
                "Observed CPU or memory utilization indicates "
                "potential capacity pressure. The instance should "
                "be reviewed for rightsizing toward a larger or "
                "more appropriate instance configuration. This "
                "finding does not select a replacement instance."
            ),
            statements=[
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "EC2 instance identifier.",
                ),
                self._statement(
                    "instance_type",
                    data["instance_type"],
                    "configuration.instance_type",
                    "Current EC2 instance type.",
                ),
                self._statement(
                    "cpu_average",
                    cpu,
                    "observations.cloudwatch.metrics.cpu_utilization",
                    "Observed average CPU utilization in percent.",
                ),
                self._statement(
                    "cpu_max",
                    cpu_max,
                    "observations.cloudwatch.metrics.cpu_utilization_max",
                    "Observed maximum CPU utilization in percent.",
                ),
                self._statement(
                    "memory_average",
                    memory,
                    "observations.cloudwatch.metrics.mem_used_percent",
                    "Observed average memory utilization in percent.",
                ),
                self._statement(
                    "memory_max",
                    memory_max,
                    "observations.cloudwatch.metrics.mem_used_percent_max",
                    "Observed maximum memory utilization in percent.",
                ),
            ],
            metadata={
                "optimization_action": ("review_instance_capacity"),
                "recommendation_category": "rightsizing",
                "direction": "increase_capacity",
                "pressure_signal_count": signals,
                "decision": (
                    "Review CPU, memory, workload requirements, "
                    "and peak behavior before selecting a larger "
                    "or different instance family."
                ),
                "region": context.region,
            },
            data=data,
            cost_optimization_type="rightsizing",
        )

    # =======================================================================
    # FINDING 4 — RIGHTSIZING
    # =======================================================================

    def _rightsizing(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != RUNNING_STATE:
            return None

        cpu = data["cpu_average"]

        if cpu is None:
            return None

        cpu_peak = data["cpu_max"]

        if cpu > CPU_LOW:
            return None

        if cpu_peak is not None and cpu_peak > CPU_PEAK_MODERATE:
            return None

        memory = data["memory_average"]
        memory_peak = data["memory_max"]

        # Never issue CPU-only downsizing when memory pressure exists.
        if memory is not None and memory >= MEMORY_HIGH:
            return None

        if memory_peak is not None and memory_peak >= MEMORY_CRITICAL:
            return None

        instance_type = str(data["instance_type"] or "").strip().lower()

        family, size = self._split_instance_type(instance_type)

        # Critical fix:
        # t3.micro, for example, cannot be downsized within T3.
        smaller_size_exists = self._has_smaller_size(
            family,
            size,
        )

        if not smaller_size_exists:
            return None

        # A generic low CPU signal is not enough when memory is unknown
        # unless the network/storage evidence also supports low activity.
        supporting_signals = 0

        if cpu <= CPU_VERY_LOW:
            supporting_signals += 1

        if (
            data["network_bytes_per_second"] is not None
            and data["network_bytes_per_second"] <= NETWORK_LOW_BYTES_PER_SECOND
        ):
            supporting_signals += 1

        if data["ebs_iops"] is not None and data["ebs_iops"] <= EBS_LOW_IOPS:
            supporting_signals += 1

        if memory is not None and memory <= MEMORY_LOW:
            supporting_signals += 1

        if supporting_signals < 2:
            return None

        confidence = "medium"

        if supporting_signals >= 3 and data["cpu_max_evidence_available"]:
            confidence = "high"

        severity = "medium" if cpu <= CPU_VERY_LOW else "low"

        memory_guidance = (
            "Memory evidence is unavailable. Memory requirements "
            "must be validated before selecting a smaller instance."
        )

        if memory is not None:
            if memory <= MEMORY_LOW:
                memory_guidance = (
                    "Observed memory utilization is low and provides "
                    "additional support for a smaller-capacity review."
                )
            elif memory <= 60.0:
                memory_guidance = (
                    "Observed memory utilization is moderate. "
                    "Instance-family selection must preserve adequate "
                    "memory capacity."
                )
            else:
                memory_guidance = (
                    "Memory utilization is relatively high. "
                    "CPU-only downsizing should be avoided."
                )

        return self._finding(
            context=context,
            finding_type="ec2_rightsizing_candidate",
            title="EC2 instance is a rightsizing review candidate",
            severity=severity,
            confidence=confidence,
            reason=(
                "The instance shows sustained low resource activity "
                "and a smaller compatible size exists within the "
                "current instance family. The finding identifies a "
                "rightsizing review candidate; it does not assert "
                "that a specific replacement is safe."
            ),
            statements=[
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "EC2 instance identifier.",
                ),
                self._statement(
                    "instance_type",
                    data["instance_type"],
                    "configuration.instance_type",
                    "Current EC2 instance type.",
                ),
                self._statement(
                    "cpu_average",
                    cpu,
                    "observations.cloudwatch.metrics.cpu_utilization",
                    "Observed average CPU utilization in percent.",
                ),
                self._statement(
                    "cpu_max",
                    cpu_peak,
                    "observations.cloudwatch.metrics.cpu_utilization_max",
                    "Observed maximum CPU utilization in percent.",
                ),
                self._statement(
                    "memory_average",
                    memory,
                    "observations.cloudwatch.metrics.mem_used_percent",
                    memory_guidance,
                ),
                self._statement(
                    "memory_max",
                    memory_peak,
                    "observations.cloudwatch.metrics.mem_used_percent_max",
                    "Observed maximum memory utilization in percent.",
                ),
                self._statement(
                    "network_bytes_per_second",
                    data["network_bytes_per_second"],
                    "observations.cloudwatch.activity.average_network_bytes_per_second",
                    "Observed average network traffic in bytes per second.",
                ),
                self._statement(
                    "ebs_iops",
                    data["ebs_iops"],
                    "observations.cloudwatch.activity.ebs_iops",
                    "Observed average EBS operations per second.",
                ),
            ],
            metadata={
                "optimization_action": ("review_instance_rightsizing"),
                "recommendation_category": "rightsizing",
                "direction": "decrease_capacity",
                "current_instance_type": instance_type,
                "instance_family": family,
                "current_size": size,
                "smaller_size_exists": smaller_size_exists,
                "cpu_average": cpu,
                "cpu_max": cpu_peak,
                "memory_average": memory,
                "memory_max": memory_peak,
                "supporting_signal_count": supporting_signals,
                "memory_guidance": memory_guidance,
                "decision": (
                    "Compare workload requirements and peak behavior "
                    "against smaller compatible instance options. "
                    "Do not select a replacement using average CPU alone."
                ),
                "region": context.region,
            },
            data=data,
            cost_optimization_type="rightsizing",
        )

    # =======================================================================
    # FINDING 5 — MEMORY
    # =======================================================================

    def _memory_pressure(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != RUNNING_STATE:
            return None

        memory = data["memory_average"]
        memory_max = data["memory_max"]

        if memory is None:
            return None

        high_average = memory >= MEMORY_HIGH

        critical_peak = memory_max is not None and memory_max >= MEMORY_CRITICAL

        if not high_average and not critical_peak:
            return None

        confidence = "high" if memory_max is not None else "medium"

        return self._finding(
            context=context,
            finding_type="ec2_memory_pressure",
            title="EC2 instance shows high memory utilization",
            severity="medium",
            confidence=confidence,
            reason=(
                "CloudWatch Agent evidence shows high memory "
                "utilization. CPU-only rightsizing could select "
                "an instance with insufficient memory."
            ),
            statements=[
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "EC2 instance identifier.",
                ),
                self._statement(
                    "instance_type",
                    data["instance_type"],
                    "configuration.instance_type",
                    "Current EC2 instance type.",
                ),
                self._statement(
                    "memory_average",
                    memory,
                    "observations.cloudwatch.metrics.mem_used_percent",
                    "Observed average memory utilization in percent.",
                ),
                self._statement(
                    "memory_max",
                    memory_max,
                    "observations.cloudwatch.metrics.mem_used_percent_max",
                    "Observed maximum memory utilization in percent.",
                ),
                self._statement(
                    "cpu_average",
                    data["cpu_average"],
                    "observations.cloudwatch.metrics.cpu_utilization",
                    "Observed CPU utilization for context.",
                ),
            ],
            metadata={
                "optimization_action": ("protect_memory_capacity"),
                "recommendation_category": ("rightsizing_constraint"),
                "decision": (
                    "Do not perform CPU-only downsizing. "
                    "Preserve adequate memory capacity."
                ),
                "region": context.region,
            },
            data=data,
            cost_optimization_type="rightsizing",
        )

    # =======================================================================
    # FINDING 6 — AUTO SCALING
    # =======================================================================

    def _autoscaling_review(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data["autoscaling_managed"]:
            return None

        desired = data["autoscaling_desired_capacity"]
        minimum = data["autoscaling_min_size"]

        if desired is None or minimum is None:
            return None

        if desired <= minimum:
            return None

        cpu = data["cpu_average"]

        if cpu is None or cpu > CPU_VERY_LOW:
            return None

        capacity_gap = desired - minimum

        return self._finding(
            context=context,
            finding_type="ec2_autoscaling_capacity_review",
            title="Auto Scaling capacity may warrant review",
            severity="low",
            confidence="medium",
            reason=(
                "The instance belongs to an Auto Scaling group whose "
                "desired capacity is above its minimum while the "
                "observed instance CPU utilization is very low. "
                "This does not prove that capacity is excessive."
            ),
            statements=[
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "EC2 instance identifier.",
                ),
                self._statement(
                    "autoscaling_group_name",
                    data["autoscaling_group_name"],
                    "topology.autoscaling.autoscaling_group_name",
                    "Auto Scaling group managing the instance.",
                ),
                self._statement(
                    "minimum_size",
                    minimum,
                    "topology.autoscaling.min_size",
                    "Auto Scaling group minimum capacity.",
                ),
                self._statement(
                    "desired_capacity",
                    desired,
                    "topology.autoscaling.desired_capacity",
                    "Auto Scaling group desired capacity.",
                ),
                self._statement(
                    "maximum_size",
                    data["autoscaling_max_size"],
                    "topology.autoscaling.max_size",
                    "Auto Scaling group maximum capacity.",
                ),
                self._statement(
                    "cpu_average",
                    cpu,
                    "observations.cloudwatch.metrics.cpu_utilization",
                    "Observed average CPU utilization in percent.",
                ),
            ],
            metadata={
                "optimization_action": ("review_autoscaling_capacity"),
                "recommendation_category": ("autoscaling_optimization"),
                "capacity_gap_above_minimum": capacity_gap,
                "decision": (
                    "Review scaling policies and historical demand "
                    "before reducing minimum or desired capacity."
                ),
                "region": context.region,
            },
            data=data,
        )

    # =======================================================================
    # FINDING 7 — SCHEDULING
    # =======================================================================

    def _scheduling_review(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != RUNNING_STATE:
            return None

        if data["autoscaling_managed"]:
            return None

        cpu = data["cpu_average"]

        if cpu is None or cpu > CPU_VERY_LOW:
            return None

        cpu_peak = data["cpu_max"]

        if cpu_peak is not None and cpu_peak > CPU_PEAK_MODERATE:
            return None

        runtime_days = data["runtime_days"]

        if runtime_days is None:
            return None

        if runtime_days < PRICING_REVIEW_DAYS:
            return None

        environment = _normalise_text(data["environment"])

        # Do not automatically suggest stopping production instances.
        if environment in {
            "production",
            "prod",
            "live",
        }:
            return None

        return self._finding(
            context=context,
            finding_type="ec2_schedule_review",
            title="EC2 instance may be suitable for scheduled operation",
            severity="low",
            confidence="medium",
            reason=(
                "The instance has been running for at least "
                f"{LONG_RUNNING_DAYS} days, is not Auto Scaling "
                "managed, and shows very low observed CPU activity "
                "without a significant observed CPU peak. If the "
                "workload is not required 24/7, scheduled operation "
                "may reduce unnecessary runtime."
            ),
            statements=[
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "EC2 instance identifier.",
                ),
                self._statement(
                    "instance_type",
                    data["instance_type"],
                    "configuration.instance_type",
                    "Current EC2 instance type.",
                ),
                self._statement(
                    "launch_time",
                    data["launch_time"],
                    "configuration.launch_time",
                    "EC2 instance launch time.",
                ),
                self._statement(
                    "runtime_days",
                    data["runtime_days"],
                    "derived.runtime_days",
                    "Approximate number of days since launch.",
                ),
                self._statement(
                    "cpu_average",
                    cpu,
                    "observations.cloudwatch.metrics.cpu_utilization",
                    "Observed average CPU utilization in percent.",
                ),
                self._statement(
                    "cpu_max",
                    cpu_peak,
                    "observations.cloudwatch.metrics.cpu_utilization_max",
                    "Observed maximum CPU utilization in percent.",
                ),
                self._statement(
                    "environment",
                    data["environment"],
                    "configuration.tags.Environment",
                    "Environment classification when available.",
                ),
                self._statement(
                    "observation_period",
                    data["observation_period"],
                    "observations.period",
                    "CloudWatch metric observation window used to establish this activity pattern.",
                ),
            ],
            metadata={
                "optimization_action": ("review_start_stop_schedule"),
                "recommendation_category": "scheduling",
                "runtime_days": runtime_days,
                "decision": (
                    "Confirm workload operating hours. If continuous "
                    "operation is unnecessary, implement a controlled "
                    "start/stop schedule."
                ),
                "region": context.region,
            },
            data=data,
        )

    # =======================================================================
    # FINDING 8 — PRICING MODEL
    # =======================================================================

    def _pricing_model_review(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != RUNNING_STATE:
            return None

        runtime_days = data["runtime_days"]

        if runtime_days is None:
            return None

        if runtime_days < PRICING_REVIEW_DAYS:
            return None

        # Spot is only appropriate when workload interruptibility is known.
        # We do not infer this from low CPU.
        workload = _normalise_text(data["workload"])

        spot_indicators = {
            "batch",
            "batch-processing",
            "batch_processing",
            "worker",
            "workers",
            "fault-tolerant",
            "fault_tolerant",
            "interruptible",
            "stateless-worker",
            "stateless_worker",
        }

        is_spot_candidate = workload in spot_indicators

        cpu = data["cpu_average"]

        environment = _normalise_text(data["environment"])

        # A production/live instance with long runtime is a better
        # commitment review candidate, but this still does not prove
        # that a Savings Plan or RI is economically optimal.
        stable_baseline_candidate = (
            environment
            in {
                "production",
                "prod",
                "live",
            }
            and cpu is not None
            and cpu <= CPU_HIGH
        )

        if not stable_baseline_candidate and not is_spot_candidate:
            return None

        if is_spot_candidate:
            pricing_direction = "spot_review"
            recommendation_category = "spot"
            decision = (
                "The workload classification suggests possible "
                "interruptibility. Validate checkpointing, retry "
                "behavior, availability requirements, and workload "
                "recovery before considering Spot."
            )
        else:
            pricing_direction = "commitment_review"
            recommendation_category = "savings_plan_or_reserved_instance"
            decision = (
                "The instance has a long runtime and appears to be "
                "part of a continuously running workload. Validate "
                "historical usage and spend across a longer period "
                "before selecting a Savings Plan or Reserved Instance."
            )

        return self._finding(
            context=context,
            finding_type="ec2_pricing_model_review",
            title="EC2 pricing model should be reviewed",
            severity="low",
            confidence="medium",
            reason=(
                "The EC2 instance has been running for at least "
                f"{LONG_RUNNING_DAYS} days. Long-running workloads "
                "may justify evaluation of commitment-based pricing, "
                "while explicitly classified interruptible workloads "
                "may justify Spot evaluation. Runtime alone is not "
                "sufficient to purchase a commitment."
            ),
            statements=[
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "EC2 instance identifier.",
                ),
                self._statement(
                    "instance_type",
                    data["instance_type"],
                    "configuration.instance_type",
                    "Current EC2 instance type.",
                ),
                self._statement(
                    "launch_time",
                    data["launch_time"],
                    "configuration.launch_time",
                    "EC2 instance launch time.",
                ),
                self._statement(
                    "runtime_days",
                    runtime_days,
                    "derived.runtime_days",
                    "Approximate runtime in days.",
                ),
                self._statement(
                    "environment",
                    data["environment"],
                    "configuration.tags.Environment",
                    "Environment classification when available.",
                ),
                self._statement(
                    "workload",
                    data["workload"],
                    "configuration.tags.Workload",
                    "Workload classification when available.",
                ),
                self._statement(
                    "cpu_average",
                    cpu,
                    "observations.cloudwatch.metrics.cpu_utilization",
                    "Observed average CPU utilization in percent.",
                ),
            ],
            metadata={
                "optimization_action": ("review_ec2_pricing_model"),
                "recommendation_category": (recommendation_category),
                "pricing_direction": pricing_direction,
                "runtime_days": runtime_days,
                "spot_candidate": is_spot_candidate,
                "commitment_candidate": (stable_baseline_candidate),
                "decision": decision,
                "important_note": (
                    "Cost Explorer historical usage and billing "
                    "history should be used before recommending "
                    "a commitment quantity."
                ),
                "region": context.region,
            },
            data=data,
            cost_optimization_type="pricing",
        )

    # =======================================================================
    # FINDING 9 — EBS
    # =======================================================================

    def _ebs_configuration_review(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> list[Finding]:

        findings: list[Finding] = []

        volumes = data["volumes"]

        if not volumes:
            return findings

        observed_iops = data["ebs_iops"]

        for index, volume in enumerate(volumes):

            if not isinstance(volume, dict):
                continue

            volume_id = volume.get("volume_id") or volume.get("id")

            volume_type = str(
                volume.get("volume_type") or volume.get("type") or ""
            ).lower()

            size_gib = _number(
                volume.get("size_gib")
                if volume.get("size_gib") is not None
                else volume.get("size")
            )

            provisioned_iops = _number(volume.get("iops"))

            delete_on_termination = volume.get("delete_on_termination")

            # ---------------------------------------------------------------
            # gp2
            # ---------------------------------------------------------------

            if volume_type == "gp2":

                findings.append(
                    self._finding(
                        context=context,
                        finding_type="ec2_ebs_gp2_review",
                        title="EC2 attached EBS volume uses gp2",
                        severity="low",
                        confidence="high",
                        reason=(
                            "The attached EBS volume uses gp2. "
                            "The volume should be reviewed for "
                            "migration to gp3 or another appropriate "
                            "configuration based on workload "
                            "performance requirements."
                        ),
                        statements=[
                            self._statement(
                                "volume_id",
                                volume_id,
                                f"configuration.volumes[{index}].volume_id",
                                "EBS volume identifier.",
                            ),
                            self._statement(
                                "volume_type",
                                volume_type,
                                f"configuration.volumes[{index}].volume_type",
                                "Configured EBS volume type.",
                            ),
                            self._statement(
                                "size_gib",
                                size_gib,
                                f"configuration.volumes[{index}].size_gib",
                                "Configured EBS volume size in GiB.",
                            ),
                        ],
                        metadata={
                            "optimization_action": ("review_ebs_volume_type"),
                            "recommendation_category": ("ebs_optimization"),
                            "volume_id": volume_id,
                            "current_volume_type": volume_type,
                            "decision": (
                                "Review migration to gp3 or another "
                                "appropriate volume type based on "
                                "IOPS and throughput requirements."
                            ),
                            "region": context.region,
                        },
                        data=data,
                    )
                )

            # ---------------------------------------------------------------
            # Provisioned IOPS
            #
            # Only evaluate if observed EBS activity is available.
            # ---------------------------------------------------------------

            if (
                provisioned_iops is not None
                and observed_iops is not None
                and provisioned_iops > 100
                and observed_iops < provisioned_iops * 0.10
            ):

                findings.append(
                    self._finding(
                        context=context,
                        finding_type=("ec2_ebs_provisioned_iops_review"),
                        title=(
                            "EBS volume has substantially higher "
                            "provisioned IOPS than observed activity"
                        ),
                        severity="low",
                        confidence="medium",
                        reason=(
                            "The EBS volume has provisioned IOPS "
                            "substantially above the observed average "
                            "EBS activity. Review whether the "
                            "provisioned performance level is required."
                        ),
                        statements=[
                            self._statement(
                                "volume_id",
                                volume_id,
                                f"configuration.volumes[{index}].volume_id",
                                "EBS volume identifier.",
                            ),
                            self._statement(
                                "provisioned_iops",
                                provisioned_iops,
                                f"configuration.volumes[{index}].iops",
                                "Provisioned EBS IOPS.",
                            ),
                            self._statement(
                                "observed_iops",
                                observed_iops,
                                "observations.cloudwatch.activity.ebs_iops",
                                "Observed average EBS operations per second.",
                            ),
                        ],
                        metadata={
                            "optimization_action": (
                                "review_ebs_performance_configuration"
                            ),
                            "recommendation_category": ("ebs_optimization"),
                            "volume_id": volume_id,
                            "provisioned_iops": provisioned_iops,
                            "observed_iops": observed_iops,
                            "decision": (
                                "Validate workload peak IOPS before "
                                "reducing provisioned performance."
                            ),
                            "region": context.region,
                        },
                        data=data,
                    )
                )

            # ---------------------------------------------------------------
            # Retained EBS
            # ---------------------------------------------------------------

            if delete_on_termination is False:

                findings.append(
                    self._finding(
                        context=context,
                        finding_type=("ec2_ebs_delete_on_termination_review"),
                        title=(
                            "Attached EBS volume is retained when " "EC2 terminates"
                        ),
                        severity="low",
                        confidence="high",
                        reason=(
                            "The attached EBS volume is configured "
                            "not to delete when the EC2 instance "
                            "terminates. This may be intentional, "
                            "but retained volumes should have an "
                            "explicit lifecycle owner."
                        ),
                        statements=[
                            self._statement(
                                "volume_id",
                                volume_id,
                                f"configuration.volumes[{index}].volume_id",
                                "EBS volume identifier.",
                            ),
                            self._statement(
                                "delete_on_termination",
                                delete_on_termination,
                                (
                                    f"configuration.volumes[{index}]"
                                    ".delete_on_termination"
                                ),
                                (
                                    "Whether the EBS volume is deleted "
                                    "when the EC2 instance terminates."
                                ),
                            ),
                        ],
                        metadata={
                            "optimization_action": ("review_ebs_lifecycle"),
                            "recommendation_category": ("ebs_lifecycle"),
                            "volume_id": volume_id,
                            "decision": (
                                "Confirm that retained storage is "
                                "intentional and has an owner/lifecycle."
                            ),
                            "region": context.region,
                        },
                        data=data,
                    )
                )

        return findings

    # =======================================================================
    # FINDING BUILDER
    # =======================================================================

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
        data: dict[str, Any],
        cost_optimization_type: str = "review",
    ) -> Finding:

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=(context.resource_type or "ec2_instance"),
            resource_id=(context.resource_id or data.get("instance_id") or "unknown"),
            analyzer=self.name,
            analyzer_version=self.version,
            severity=severity,
            confidence=confidence,
            reason=reason,
            conditions=statements,
            evidence=self._evidence(
                context,
                data,
            ),
            observation_period=(self._observation_period(context)),
            metadata=dict(metadata),
            recommendation_eligible=True,
            cost_optimization_type=cost_optimization_type,
        )

    # =======================================================================
    # EVIDENCE
    # =======================================================================

    def _evidence(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Evidence:

        configuration = dict(context.configuration() or {})

        topology = dict(context.topology() or {})

        return Evidence(
            metrics=dict(data.get("metrics", {}) or {}),
            configuration=configuration,
            topology=topology,
            resource={
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "region": context.region,
            },
            derived={
                "instance_id": data.get("instance_id"),
                "instance_type": data.get("instance_type"),
                "state": data.get("state"),
                "launch_time": data.get("launch_time"),
                "runtime_days": data.get("runtime_days"),
                "environment": data.get("environment"),
                "role": data.get("role"),
                "workload": data.get("workload"),
                "cpu_average": data.get("cpu_average"),
                "cpu_max": data.get("cpu_max"),
                "memory_average": data.get("memory_average"),
                "memory_max": data.get("memory_max"),
                "network_in": data.get("network_in"),
                "network_out": data.get("network_out"),
                "network_bytes_per_second": data.get("network_bytes_per_second"),
                "ebs_read_ops": data.get("ebs_read_ops"),
                "ebs_write_ops": data.get("ebs_write_ops"),
                "ebs_iops": data.get("ebs_iops"),
                "ebs_volume_count": data.get("ebs_volume_count"),
                "traffic_observed": data.get("traffic_observed"),
                "storage_activity_observed": data.get("storage_activity_observed"),
                "autoscaling_managed": data.get("autoscaling_managed"),
                "autoscaling_group_name": data.get("autoscaling_group_name"),
                "autoscaling_min_size": data.get("autoscaling_min_size"),
                "autoscaling_max_size": data.get("autoscaling_max_size"),
                "autoscaling_desired_capacity": data.get(
                    "autoscaling_desired_capacity"
                ),
            },
            data_quality={
                "configuration_available": (data["configuration_available"]),
                "cpu_evidence_available": (data["cpu_evidence_available"]),
                "cpu_max_evidence_available": (data["cpu_max_evidence_available"]),
                "memory_evidence_available": (data["memory_evidence_available"]),
                "memory_max_evidence_available": (
                    data["memory_max_evidence_available"]
                ),
                "network_evidence_available": (data["network_evidence_available"]),
                "ebs_activity_evidence_available": (
                    data["ebs_activity_evidence_available"]
                ),
                "ebs_configuration_available": (data["ebs_evidence_available"]),
                "cloudwatch_status": (data["cloudwatch_status"]),
                "standard_metrics_available": (data["standard_metrics_available"]),
                "observation_period": (data["observation_period"]),
            },
        )

    # =======================================================================
    # EVIDENCE STATEMENT
    # =======================================================================

    @staticmethod
    def _statement(
        name: str,
        value: Any,
        path: str,
        description: str,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=[
                "AWS EC2 API",
                "Amazon CloudWatch",
                "collector-derived evidence",
            ],
            evidence_keys=([path] if path else []),
            observed=(value is not None),
        )

    # =======================================================================
    # METRIC HELPERS
    # =======================================================================

    @staticmethod
    def _metric_available(
        metrics: dict[str, Any],
        name: str,
    ) -> bool:

        metric = metrics.get(name)

        if not isinstance(metric, dict):
            return False

        if metric.get("status") != "ok":
            return False

        if metric.get("has_data") is not True:
            return False

        value = metric.get("value")

        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @classmethod
    def _metric_value(
        cls,
        metrics: dict[str, Any],
        name: str,
    ) -> float | None:

        if not cls._metric_available(
            metrics,
            name,
        ):
            return None

        value = metrics[name].get("value")

        if value is None:
            return None

        return float(value)

    # =======================================================================
    # INSTANCE SIZE HELPERS
    # =======================================================================

    @staticmethod
    def _split_instance_type(
        instance_type: str,
    ) -> tuple[str | None, str | None]:

        if not instance_type or "." not in instance_type:
            return None, None

        family, size = instance_type.split(
            ".",
            1,
        )

        return family, size

    @staticmethod
    def _has_smaller_size(
        family: str | None,
        size: str | None,
    ) -> bool:

        if not family or not size:
            return False

        sizes = STANDARD_FAMILY_SIZES.get(family)

        if not sizes:
            return False

        try:
            index = sizes.index(size)
        except ValueError:
            return False

        return index > 0

    # =======================================================================
    # RUNTIME
    # =======================================================================

    @staticmethod
    def _runtime_days(
        launch_time: Any,
    ) -> float | None:

        if launch_time is None:
            return None

        dt: datetime | None = None

        if isinstance(launch_time, datetime):
            dt = launch_time

        elif isinstance(launch_time, str):

            value = launch_time.strip()

            if value.endswith("Z"):
                value = value[:-1] + "+00:00"

            try:
                dt = datetime.fromisoformat(value)
            except ValueError:
                return None

        if dt is None:
            return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        now = datetime.now(timezone.utc)

        seconds = (now - dt).total_seconds()

        if seconds < 0:
            return 0.0

        return seconds / 86400.0

    # =======================================================================
    # OBSERVATION PERIOD
    # =======================================================================

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        period = context.period()

        if not period:
            return None

        return ObservationPeriod(
            start=period.get("start"),
            end=period.get("end"),
            duration_seconds=period.get("duration_seconds"),
        )
