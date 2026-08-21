"""
EC2 optimization analyzer.

The analyzer does NOT determine EC2 cost. It reads
AnalysisContext.billing() and passes it straight through to
Evidence.billing (same pattern as the NAT Gateway and Transit
Gateway analyzers) -- reconciliation is the single attribution
authority; no analyzer independently decides cost_attribution or
claimable_resource_cost.

Findings produced here are independent of each other:

    - ec2_idle_instance
    - ec2_instance_underutilized
    - ec2_capacity_pressure
    - ec2_spot_candidate
    - ec2_stable_long_running
    - ec2_autoscaling_opportunity
    - ec2_nonproduction_scheduling
    - ec2_old_generation
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from analysis.base import Analyzer
from analysis.condition import EvidenceStatement
from analysis.context import AnalysisContext
from analysis.evidence import Evidence
from analysis.finding import Finding, ObservationPeriod
from analysis.metrics import metric_has_observed_data, metric_numeric_value
from analysis.registry import register


@register
class EC2Analyzer(Analyzer):

    name = "ec2_optimization"
    version = "1.0"

    DEFAULT_MIN_COVERAGE = 0.80

    UNDERUTILIZED_CPU_AVERAGE = 20.0
    UNDERUTILIZED_CPU_MAX = 50.0

    OVERUTILIZED_CPU_AVERAGE = 70.0
    OVERUTILIZED_CPU_MAX = 90.0

    IDLE_CPU_AVERAGE = 5.0
    IDLE_CPU_MAX = 15.0

    IDLE_NETWORK_BYTES_PER_SECOND = 100 * 1024
    IDLE_EBS_IOPS = 1.0

    AUTOSCALING_PEAK_TO_AVERAGE = 3.0
    AUTOSCALING_CPU_RANGE = 50.0

    MIN_STABLE_RUNTIME_DAYS = 30.0
    MIN_AUTOSCALING_OBSERVATION_DAYS = 14.0

    # Maintained review list, not an attempt to encode every AWS
    # generation -- deliberately conservative.
    OLD_GENERATION_PREFIXES = frozenset({
        "t2", "m1", "m2", "m3", "m4", "c1", "c3", "c4",
        "r3", "r4", "x1", "x1e", "i2", "i3",
    })

    def supports(self, context: AnalysisContext) -> bool:
        return context.resource_type == "ec2_instance"

    def analyze(self, context: AnalysisContext) -> list[Finding]:

        findings: list[Finding] = []

        configuration = context.configuration()
        identity = context.identity()
        relationships = context.resource.get("relationships", {})

        if not isinstance(relationships, dict):
            relationships = {}

        metrics = context.metrics()
        if not isinstance(metrics, dict):
            metrics = {}

        tags = identity.get("tags", {})
        if not isinstance(tags, dict):
            tags = {}

        required_metrics = [
            "CPUUtilization", "CPUUtilization_max",
            "NetworkIn", "NetworkOut",
            "EBSReadOps", "EBSWriteOps",
        ]

        coverage = self._coverage(metrics, required_metrics)

        for builder in (
            self._analyze_idle,
            self._analyze_underutilization,
            self._analyze_overutilization,
        ):
            finding = builder(
                context=context,
                configuration=configuration,
                metrics=metrics,
                coverage=coverage,
            )
            if finding is not None:
                findings.append(finding)

        spot_finding = self._analyze_spot_candidate(
            context=context,
            configuration=configuration,
            identity=identity,
            tags=tags,
            metrics=metrics,
            coverage=coverage,
        )
        if spot_finding is not None:
            findings.append(spot_finding)

        commitment_finding = self._analyze_stable_long_running(
            context=context,
            configuration=configuration,
            identity=identity,
            metrics=metrics,
            coverage=coverage,
        )
        if commitment_finding is not None:
            findings.append(commitment_finding)

        autoscaling_finding = self._analyze_autoscaling(
            context=context,
            configuration=configuration,
            relationships=relationships,
            metrics=metrics,
            coverage=coverage,
        )
        if autoscaling_finding is not None:
            findings.append(autoscaling_finding)

        scheduling_finding = self._analyze_scheduling(
            context=context,
            configuration=configuration,
            tags=tags,
            metrics=metrics,
        )
        if scheduling_finding is not None:
            findings.append(scheduling_finding)

        old_generation_finding = self._analyze_old_generation(
            context=context,
            configuration=configuration,
        )
        if old_generation_finding is not None:
            findings.append(old_generation_finding)

        return findings

    # --------------------------------------------------------------
    # Idle
    # --------------------------------------------------------------

    def _analyze_idle(
        self, *, context, configuration, metrics, coverage,
    ) -> Finding | None:

        if coverage < self._threshold(context, "minimum_metric_coverage", self.DEFAULT_MIN_COVERAGE):
            return None

        cpu_average = self._value(metrics, "CPUUtilization")
        cpu_max = self._value(metrics, "CPUUtilization_max")

        if cpu_average is None or cpu_max is None:
            return None

        duration = self._duration_seconds(context.period())

        network_bps = self._total_per_second(
            self._value(metrics, "NetworkIn"),
            self._value(metrics, "NetworkOut"),
            duration,
        )

        ebs_iops = self._total_per_second(
            self._value(metrics, "EBSReadOps"),
            self._value(metrics, "EBSWriteOps"),
            duration,
        )

        cpu_ok = (
            cpu_average <= self._threshold(context, "idle_average_cpu_max_percent", self.IDLE_CPU_AVERAGE)
            and cpu_max <= self._threshold(context, "idle_maximum_cpu_max_percent", self.IDLE_CPU_MAX)
        )

        network_ok = (
            network_bps is None
            or network_bps <= self._threshold(context, "idle_network_bytes_per_second_max", self.IDLE_NETWORK_BYTES_PER_SECOND)
        )

        io_ok = (
            ebs_iops is None
            or ebs_iops <= self._threshold(context, "idle_ebs_iops_max", self.IDLE_EBS_IOPS)
        )

        if not (cpu_ok and network_ok and io_ok):
            return None

        return self._finding(
            context=context,
            finding_type="ec2_idle_instance",
            title="EC2 instance is idle or nearly idle",
            severity="medium",
            confidence="high",
            reason=(
                "The EC2 instance shows very low CPU, network, and EBS "
                "activity over the observation period."
            ),
            conditions=[
                self._statement("average CPU utilization", cpu_average, "Percent", True),
                self._statement("maximum CPU utilization", cpu_max, "Percent", True),
                self._statement("network throughput", network_bps, "Bytes/Second", network_bps is not None),
                self._statement("EBS IOPS", ebs_iops, "IOPS", ebs_iops is not None),
            ],
            metrics=metrics,
            configuration=configuration,
            metadata={"analysis_role": "idle_detection"},
            limitations=self._common_limitations(context, memory_required=False),
        )

    # --------------------------------------------------------------
    # Underutilization
    # --------------------------------------------------------------

    def _analyze_underutilization(
        self, *, context, configuration, metrics, coverage,
    ) -> Finding | None:

        if coverage < self._threshold(context, "minimum_metric_coverage", self.DEFAULT_MIN_COVERAGE):
            return None

        cpu_average = self._value(metrics, "CPUUtilization")
        cpu_max = self._value(metrics, "CPUUtilization_max")

        if cpu_average is None or cpu_max is None:
            return None

        if cpu_average > self._threshold(context, "average_cpu_max_percent", self.UNDERUTILIZED_CPU_AVERAGE):
            return None

        if cpu_max > self._threshold(context, "maximum_cpu_max_percent", self.UNDERUTILIZED_CPU_MAX):
            return None

        memory = self._value(metrics, "mem_used_percent")
        memory_available = memory is not None

        # Memory pressure, when known, overrides CPU-only evidence.
        if memory_available and memory > 80.0:
            return None

        duration = self._duration_seconds(context.period())

        network_bps = self._total_per_second(
            self._value(metrics, "NetworkIn"),
            self._value(metrics, "NetworkOut"),
            duration,
        )

        ebs_iops = self._total_per_second(
            self._value(metrics, "EBSReadOps"),
            self._value(metrics, "EBSWriteOps"),
            duration,
        )

        return self._finding(
            context=context,
            finding_type="ec2_instance_underutilized",
            title="EC2 instance may be oversized",
            severity="medium",
            confidence="high" if memory_available else "medium",
            reason=(
                "CPU demand remains below the rightsizing threshold and "
                "peak CPU demand is also limited."
            ),
            conditions=[
                self._statement("average CPU utilization", cpu_average, "Percent", True),
                self._statement("maximum CPU utilization", cpu_max, "Percent", True),
                self._statement("memory utilization", memory, "Percent", memory_available),
                self._statement("network activity", network_bps, "Bytes/Second", network_bps is not None),
                self._statement("EBS IOPS", ebs_iops, "IOPS", ebs_iops is not None),
            ],
            metrics=metrics,
            configuration=configuration,
            metadata={"analysis_role": "rightsizing"},
            limitations=self._common_limitations(context, memory_required=True),
        )

    # --------------------------------------------------------------
    # Overutilization / capacity pressure
    # --------------------------------------------------------------

    def _analyze_overutilization(
        self, *, context, configuration, metrics, coverage,
    ) -> Finding | None:

        if coverage < self._threshold(context, "minimum_metric_coverage", self.DEFAULT_MIN_COVERAGE):
            return None

        cpu_average = self._value(metrics, "CPUUtilization")
        cpu_max = self._value(metrics, "CPUUtilization_max")

        if cpu_average is None or cpu_max is None:
            return None

        average_threshold = self._threshold(context, "overutilized_average_cpu_percent", self.OVERUTILIZED_CPU_AVERAGE)
        max_threshold = self._threshold(context, "overutilized_maximum_cpu_percent", self.OVERUTILIZED_CPU_MAX)

        if not (cpu_average >= average_threshold or cpu_max >= max_threshold):
            return None

        memory = self._value(metrics, "mem_used_percent")

        severity = "high" if (
            cpu_average >= 85.0 or cpu_max >= 95.0 or (memory is not None and memory >= 90.0)
        ) else "medium"

        return self._finding(
            context=context,
            finding_type="ec2_capacity_pressure",
            title="EC2 instance may need more capacity",
            severity=severity,
            confidence="high",
            reason="Observed CPU demand reaches or exceeds the capacity-review threshold.",
            conditions=[
                self._statement("average CPU utilization", cpu_average, "Percent", True),
                self._statement("maximum CPU utilization", cpu_max, "Percent", True),
                self._statement("memory utilization", memory, "Percent", memory is not None),
            ],
            metrics=metrics,
            configuration=configuration,
            metadata={"analysis_role": "capacity_review"},
            limitations=self._common_limitations(context, memory_required=False),
        )

    # --------------------------------------------------------------
    # Spot
    # --------------------------------------------------------------

    def _analyze_spot_candidate(
        self, *, context, configuration, identity, tags, metrics, coverage,
    ) -> Finding | None:

        lifecycle = str(identity.get("instance_lifecycle") or "").lower()
        if lifecycle == "spot":
            return None

        if coverage < 0.80:
            return None

        workload = self._classify_workload(tags)
        environment = self._classify_environment(tags)

        if workload != "batch_or_interruptible":
            return None

        if environment == "production":
            return None

        if str(configuration.get("state") or "").lower() != "running":
            return None

        cpu_average = self._value(metrics, "CPUUtilization")
        cpu_max = self._value(metrics, "CPUUtilization_max")

        return self._finding(
            context=context,
            finding_type="ec2_spot_candidate",
            title="EC2 workload may be suitable for Spot capacity",
            severity="low",
            confidence="medium",
            reason=(
                "The instance is classified by its tags as a batch or "
                "interruption-tolerant workload and is not currently "
                "running as Spot capacity."
            ),
            conditions=[
                self._statement("workload classification", workload, None, True),
                self._statement("environment", environment, None, True),
                self._statement("CPU average", cpu_average, "Percent", cpu_average is not None),
                self._statement("CPU maximum", cpu_max, "Percent", cpu_max is not None),
            ],
            metrics=metrics,
            configuration=configuration,
            metadata={"analysis_role": "pricing_model", "workload_type": workload},
            limitations=[
                "Spot suitability cannot be proven from utilization alone; "
                "the workload must tolerate interruption and recovery.",
                "This finding is based on workload classification from resource tags.",
            ],
        )

    # --------------------------------------------------------------
    # Savings Plan / Reserved Instance (stable long-running)
    # --------------------------------------------------------------

    def _analyze_stable_long_running(
        self, *, context, configuration, identity, metrics, coverage,
    ) -> Finding | None:

        if coverage < 0.80:
            return None

        if str(identity.get("instance_lifecycle") or "").lower() == "spot":
            return None

        launch_time = self._parse_datetime(configuration.get("launch_time"))
        if launch_time is None:
            return None

        runtime_days = (datetime.now(timezone.utc) - launch_time).total_seconds() / 86400.0

        if runtime_days < self._threshold(context, "minimum_runtime_days", self.MIN_STABLE_RUNTIME_DAYS):
            return None

        if str(configuration.get("state") or "").lower() != "running":
            return None

        cpu_average = self._value(metrics, "CPUUtilization")
        if cpu_average is None:
            return None

        variation = self._cpu_variation(context)

        if (
            variation.get("available")
            and variation.get("peak_to_average_ratio") is not None
            and variation["peak_to_average_ratio"] > 4.0
        ):
            return None

        return self._finding(
            context=context,
            finding_type="ec2_stable_long_running",
            title="EC2 instance has a stable long-running workload",
            severity="low",
            confidence="medium",
            reason=(
                f"The EC2 instance has been running for about "
                f"{runtime_days:.0f} days with no strong evidence of "
                f"highly variable CPU demand."
            ),
            conditions=[
                self._statement("runtime", round(runtime_days, 1), "days", True),
                self._statement("average CPU utilization", cpu_average, "Percent", True),
            ],
            metrics=metrics,
            configuration=configuration,
            metadata={"analysis_role": "pricing_model", "runtime_days": round(runtime_days, 1)},
            limitations=[
                "Stable runtime does not by itself prove a Savings Plan or "
                "Reserved Instance will be economically beneficial.",
                "Commitment analysis should also account for existing "
                "commitments and expected future demand.",
            ],
        )

    # --------------------------------------------------------------
    # Auto Scaling
    # --------------------------------------------------------------

    def _analyze_autoscaling(
        self, *, context, configuration, relationships, metrics, coverage,
    ) -> Finding | None:

        asg = relationships.get("autoscaling", {})
        if not isinstance(asg, dict):
            asg = {}

        if asg.get("managed") is True:
            return None

        if coverage < 0.80:
            return None

        duration_days = self._duration_seconds(context.period()) / 86400.0

        if duration_days < self._threshold(context, "minimum_observation_days", self.MIN_AUTOSCALING_OBSERVATION_DAYS):
            return None

        variation = self._cpu_variation(context)
        if not variation.get("available"):
            return None

        peak_to_average = variation.get("peak_to_average_ratio")
        cpu_range = variation.get("range")

        if peak_to_average is None or cpu_range is None:
            return None

        if not (
            peak_to_average >= self._threshold(context, "peak_to_average_ratio", self.AUTOSCALING_PEAK_TO_AVERAGE)
            and cpu_range >= self._threshold(context, "cpu_range_percent", self.AUTOSCALING_CPU_RANGE)
        ):
            return None

        return self._finding(
            context=context,
            finding_type="ec2_autoscaling_opportunity",
            title="EC2 workload may benefit from Auto Scaling",
            severity="low",
            confidence="medium",
            reason=(
                "CPU demand varies substantially across the observation "
                "period while the instance is not currently managed by an "
                "Auto Scaling Group."
            ),
            conditions=[
                self._statement("CPU peak-to-average ratio", peak_to_average, None, True),
                self._statement("CPU range", cpu_range, "Percentage points", True),
                self._statement("Auto Scaling management", False, None, True),
            ],
            metrics=metrics,
            configuration=configuration,
            metadata={"analysis_role": "autoscaling"},
            limitations=[
                "CPU variability alone does not prove Auto Scaling is "
                "appropriate; workload architecture, statefulness, scaling "
                "time and availability requirements must be reviewed.",
            ],
        )

    # --------------------------------------------------------------
    # Scheduling
    # --------------------------------------------------------------

    def _analyze_scheduling(
        self, *, context, configuration, tags, metrics,
    ) -> Finding | None:

        environment = self._classify_environment(tags)
        if environment != "non_production":
            return None

        if str(configuration.get("state") or "").lower() != "running":
            return None

        values = self._cpu_values(context)
        if not values:
            return None

        low_ratio = sum(1 for value in values if value <= 5.0) / len(values)
        if low_ratio < 0.50:
            return None

        return self._finding(
            context=context,
            finding_type="ec2_nonproduction_scheduling",
            title="Non-production EC2 instance may be schedulable",
            severity="low",
            confidence="medium",
            reason=(
                "The instance is classified as non-production and spends "
                "a substantial portion of the observation period at very "
                "low CPU activity."
            ),
            conditions=[
                self._statement("environment", environment, None, True),
                self._statement("low CPU observation ratio", round(low_ratio * 100.0, 2), "Percent", True),
            ],
            metrics=metrics,
            configuration=configuration,
            metadata={"analysis_role": "scheduling", "environment": environment},
            limitations=[
                "Observed low activity does not establish the business "
                "operating schedule.",
                "Scheduled stop/start should only be proposed after "
                "confirming application, maintenance, backup and "
                "operational requirements.",
            ],
        )

    # --------------------------------------------------------------
    # Old generation
    # --------------------------------------------------------------

    def _analyze_old_generation(self, *, context, configuration) -> Finding | None:

        instance_type = str(configuration.get("instance_type") or "").lower()
        if not instance_type:
            return None

        family = instance_type.split(".", 1)[0]
        if family not in self.OLD_GENERATION_PREFIXES:
            return None

        return self._finding(
            context=context,
            finding_type="ec2_old_generation",
            title="EC2 instance uses an older instance family",
            severity="low",
            confidence="medium",
            reason=(
                f"The instance uses the {family} family, which should be "
                "reviewed against currently supported generation "
                "alternatives."
            ),
            conditions=[
                self._statement("instance type", instance_type, None, True),
            ],
            metrics={},
            configuration=configuration,
            metadata={"analysis_role": "generation_review", "instance_family": family},
            limitations=[
                "This finding identifies a generation-review candidate; "
                "the analyzer does not assume a specific replacement "
                "instance type.",
            ],
        )

    # --------------------------------------------------------------
    # Finding builder
    # --------------------------------------------------------------

    def _finding(
        self,
        *,
        context: AnalysisContext,
        finding_type: str,
        title: str,
        severity: str,
        confidence: str,
        reason: str,
        conditions: list[EvidenceStatement],
        metrics: dict[str, Any],
        configuration: dict[str, Any],
        metadata: dict[str, Any],
        limitations: list[str],
    ) -> Finding:

        period = context.period()
        start = period.get("start")
        end = period.get("end")

        observation_period = (
            ObservationPeriod(
                start=str(start) if start is not None else None,
                end=str(end) if end is not None else None,
                duration_seconds=period.get("duration_seconds"),
            )
            if start or end
            else None
        )

        resource_id = context.resource_id or "unknown"
        resource_type = context.resource_type or "ec2_instance"

        evidence = Evidence(
            metrics=metrics,
            configuration=configuration,
            topology=context.topology(),
            resource={
                "resource_id": resource_id,
                "resource_type": resource_type,
                "region": context.region,
                "account_id": context.account_id,
                "instance_type": configuration.get("instance_type"),
            },
            derived={"analysis_role": metadata.get("analysis_role")},
            billing=context.billing(),
            data_quality=context.collector_data_quality(),
        )

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=resource_type,
            resource_id=resource_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity=severity,
            confidence=confidence,
            reason=reason,
            conditions=conditions,
            evidence=evidence,
            observation_period=observation_period,
            limitations=limitations,
            metadata={**metadata, "region": context.region, "account_id": context.account_id},
            recommendation_eligible=True,
            aggregation_scope="resource",
            category="optimization",
            status="active",
        )

    # --------------------------------------------------------------
    # Coverage / metric helpers
    # --------------------------------------------------------------

    @classmethod
    def _coverage(cls, metrics: dict[str, Any], names: list[str]) -> float:
        if not names:
            return 0.0
        observed = sum(1 for name in names if metric_has_observed_data(metrics.get(name)))
        return observed / len(names)

    @staticmethod
    def _value(metrics: dict[str, Any], name: str) -> float | None:
        return metric_numeric_value(metrics.get(name))

    @staticmethod
    def _duration_seconds(period: dict[str, Any]) -> float:
        try:
            return max(float(period.get("duration_seconds")), 1.0)
        except (TypeError, ValueError):
            return 1.0

    @staticmethod
    def _total_per_second(first, second, duration_seconds: float) -> float | None:
        if first is None and second is None:
            return None
        return ((first or 0.0) + (second or 0.0)) / max(duration_seconds, 1.0)

    @staticmethod
    def _statement(name, value, unit, observed) -> EvidenceStatement:
        return EvidenceStatement(name=name, value=value, unit=unit, observed=observed)

    def _cpu_values(self, context: AnalysisContext) -> list[float]:
        metric = context.metric("CPUUtilization")
        raw = metric.get("raw_datapoints", []) if isinstance(metric, dict) else []
        return [
            float(point["value"])
            for point in raw
            if isinstance(point, dict) and isinstance(point.get("value"), (int, float))
        ]

    def _cpu_variation(self, context: AnalysisContext) -> dict[str, Any]:
        values = self._cpu_values(context)
        if not values:
            return {"available": False}

        average = sum(values) / len(values)
        maximum = max(values)
        minimum = min(values)

        return {
            "available": True,
            "average": average,
            "maximum": maximum,
            "minimum": minimum,
            "range": maximum - minimum,
            "peak_to_average_ratio": (maximum / average) if average > 0 else None,
        }

    # --------------------------------------------------------------
    # Thresholds
    #
    # AnalysisContext does not currently expose the collector profile
    # or a per-resource-type analyzer_config section -- there is no
    # wiring from collection_profiles.yaml to the analysis layer today.
    # This method is the single place that would read such config if
    # it existed; until that plumbing is added, it returns the
    # class-level defaults.
    # --------------------------------------------------------------

    @staticmethod
    def _threshold(context: AnalysisContext, key: str, default: float) -> float:
        _ = context, key
        return float(default)

    # --------------------------------------------------------------
    # Classification
    # --------------------------------------------------------------

    @staticmethod
    def _classify_environment(tags: dict[str, Any]) -> str:
        values = " ".join(f"{k} {v}".lower() for k, v in tags.items())

        if any(m in values for m in ("production", "prod")):
            return "production"

        if any(m in values for m in ("development", "dev", "testing", "test", "staging", "stage", "qa")):
            return "non_production"

        return "unknown"

    @staticmethod
    def _classify_workload(tags: dict[str, Any]) -> str:
        values = " ".join(f"{k} {v}".lower() for k, v in tags.items())

        if any(m in values for m in ("batch", "worker", "ci", "cd", "cicd", "build", "etl", "ml")):
            return "batch_or_interruptible"

        if any(m in values for m in ("database", "db", "payment", "critical")):
            return "critical"

        return "unknown"

    # --------------------------------------------------------------
    # Limitations
    # --------------------------------------------------------------

    @staticmethod
    def _common_limitations(context: AnalysisContext, *, memory_required: bool) -> list[str]:

        limitations = [
            "CloudWatch utilization evidence describes observed workload "
            "behaviour; it does not prove business criticality or future "
            "demand.",
        ]

        if memory_required:
            quality = context.collector_data_quality()
            if not quality.get("memory_metrics_available"):
                limitations.append(
                    "Guest memory metrics were unavailable. Memory "
                    "pressure could not be fully evaluated."
                )

        return limitations

    # --------------------------------------------------------------
    # Datetime
    # --------------------------------------------------------------

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:

        if value is None:
            return None

        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

        text = str(value).strip()
        if not text:
            return None

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None

        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
