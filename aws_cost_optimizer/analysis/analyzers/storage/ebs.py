"""
EBS optimization analyzer.

Detects evidence-backed EBS optimization opportunities.

Supported findings:

    1. Unattached EBS volume
    2. gp2 volume eligible for gp3 migration
    3. Provisioned IOPS with insufficient observed utilization
    4. Provisioned throughput with insufficient observed utilization


"""

from __future__ import annotations

from typing import Any

from ...base import Analyzer
from ...context import AnalysisContext
from ...condition import EvidenceStatement
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
from ...metrics import metric_statistic
from ...registry import register


@register
class EBSAnalyzer(Analyzer):

    name = "ebs_optimization"
    version = "1.0"

    # Conservative thresholds.
    #
    # These are intentionally not aggressive because a short
    # observation window can produce misleading utilization signals.
    MIN_OBSERVATION_DATAPOINTS = 12

    LOW_IOPS_UTILIZATION = 0.20
    LOW_THROUGHPUT_UTILIZATION = 0.20

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        resource_type = (context.resource_type or "").lower()

        return resource_type in {
            "ebs",
            "ebs_volume",
            "volume",
            "ec2_volume",
        }

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        volume = self._volume(context)

        if not volume:
            return []

        volume_id = context.resource_id or volume.get("volume_id")

        if not volume_id:
            return []

        findings: list[Finding] = []

        # 1. Unattached volume

        unattached = self._is_unattached(volume)

        if unattached:

            finding = self._unattached_volume_finding(
                context,
                volume,
                str(volume_id),
            )

            if finding:
                findings.append(finding)

        # 2. gp2 -> gp3

        if self._is_gp2(volume):

            finding = self._gp2_to_gp3_finding(
                context,
                volume,
                str(volume_id),
            )

            if finding:
                findings.append(finding)

        # 3. IOPS utilization

        finding = self._iops_finding(
            context,
            volume,
            str(volume_id),
        )

        if finding:
            findings.append(finding)

        # 4. Throughput utilization

        finding = self._throughput_finding(
            context,
            volume,
            str(volume_id),
        )

        if finding:
            findings.append(finding)

        return findings

    # Volume extraction

    @staticmethod
    def _volume(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        configuration = context.configuration()

        if not configuration:
            return {}

        # Direct normalized collector document.
        if configuration.get("volume_id"):
            return configuration

        # Some collection flows wrap the resource.
        volume = configuration.get("volume")

        if isinstance(
            volume,
            dict,
        ):
            return volume

        # Some collectors expose a single-item list.
        volumes = configuration.get("volumes")

        if (
            isinstance(
                volumes,
                list,
            )
            and volumes
        ):

            first = volumes[0]

            if isinstance(
                first,
                dict,
            ):
                return first

        return {}

    # Unattached volume

    def _unattached_volume_finding(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        volume_id: str,
    ) -> Finding | None:

        size = volume.get("size_gib")

        state = volume.get("state")

        conditions = [
            EvidenceStatement(
                name="volume attached",
                value=False,
                description=("The EBS volume has no current " "EC2 attachment."),
                source=["EC2 DescribeVolumes"],
                evidence_keys=["configuration.attached"],
                observed=True,
            ),
            EvidenceStatement(
                name="volume state",
                value=state,
                description=("Current EBS volume state."),
                source=["EC2 DescribeVolumes"],
                evidence_keys=["configuration.state"],
                observed=state is not None,
            ),
        ]

        evidence = self._evidence(
            context,
            volume,
            extra={
                "condition": {
                    "attached": False,
                }
            },
        )

        return Finding(
            finding_type="unattached_ebs_volume",
            title="Unattached EBS volume",
            resource_type=(context.resource_type or "ebs_volume"),
            resource_id=volume_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="medium",
            confidence="high",
            reason=(
                f"EBS volume {volume_id} is not currently "
                f"attached to an EC2 instance"
                + (f" and has {size} GiB provisioned." if size is not None else ".")
            ),
            conditions=conditions,
            evidence=evidence,
            observation_period=(self._observation_period(context)),
            metadata={
                "region": context.region,
                "volume_type": volume.get("volume_type"),
                "size_gib": size,
                "encrypted": volume.get("encrypted"),
                "snapshot_id": volume.get("snapshot_id"),
            },
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type="elimination",
            category="cost_optimization",
            status="active",
            impact={},
            account_id=context.account_id,
        )

    # gp2 -> gp3

    def _gp2_to_gp3_finding(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        volume_id: str,
    ) -> Finding | None:

        volume_type = str(volume.get("volume_type") or "").lower()

        if volume_type != "gp2":
            return None

        size = volume.get("size_gib")

        conditions = [
            EvidenceStatement(
                name="volume type",
                value="gp2",
                description=("The EBS volume is using the gp2 " "volume type."),
                source=["EC2 DescribeVolumes"],
                evidence_keys=["configuration.volume_type"],
                observed=True,
            ),
            EvidenceStatement(
                name="gp3 availability",
                value=True,
                description=(
                    "gp3 is the recommended general-purpose "
                    "SSD generation for a migration review."
                ),
                source=["AWS EBS configuration"],
                evidence_keys=[],
                observed=True,
            ),
        ]

        evidence = self._evidence(
            context,
            volume,
        )

        return Finding(
            finding_type="ebs_gp2_to_gp3",
            title="gp2 EBS volume eligible for gp3 migration",
            resource_type=(context.resource_type or "ebs_volume"),
            resource_id=volume_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="low",
            confidence="high",
            reason=(
                f"EBS volume {volume_id} uses gp2"
                + (f" with {size} GiB provisioned." if size is not None else ".")
                + (
                    " Review migration to gp3 for "
                    "potential storage-cost and flexibility "
                    "benefits."
                )
            ),
            conditions=conditions,
            evidence=evidence,
            observation_period=(self._observation_period(context)),
            metadata={
                "region": context.region,
                "current_volume_type": "gp2",
                "recommended_volume_type": "gp3",
                "size_gib": size,
            },
            recommendation_eligible=True,
            aggregation_scope="resource",
            category="cost_optimization",
            status="active",
            impact={},
            account_id=context.account_id,
        )

    # IOPS

    def _iops_finding(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        volume_id: str,
    ) -> Finding | None:

        provisioned = self._numeric(volume.get("iops"))

        if provisioned is None:
            return None

        volume_type = str(volume.get("volume_type") or "").lower()

        # Avoid applying provisioned-IOPS logic to volume
        # classes where IOPS is not an independently meaningful
        # optimization dimension.
        if volume_type not in {
            "io1",
            "io2",
            "gp3",
        }:
            return None

        # CloudWatch operation-count metrics are collected with
        # statistic Sum: "value" is the raw operation TOTAL across all
        # datapoints in the query window, NOT an operations-per-second
        # rate. Provisioned IOPS is operations per SECOND, so the
        # utilization ratio requires an explicit period conversion:
        #
        #   (read ops + write ops) / period_seconds  -> avg IOPS
        #   avg IOPS / provisioned IOPS              -> utilization
        #
        # Read-only evidence would silently understate total IOPS
        # utilization, so BOTH directions are required.
        read_metric = "VolumeReadOps"
        write_metric = "VolumeWriteOps"

        totals_bundle = self._sum_metric_totals(
            context,
            (read_metric, write_metric),
        )

        if totals_bundle is None:
            return None

        period_seconds, datapoints, totals = totals_bundle

        read_operations = totals.get(read_metric, 0.0)

        write_operations = totals.get(write_metric, 0.0)

        observed_operations = read_operations + write_operations

        observed_iops = observed_operations / period_seconds

        utilization = observed_iops / provisioned if provisioned > 0 else None

        if utilization is None:
            return None

        if utilization >= self.LOW_IOPS_UTILIZATION:
            return None

        conditions = [
            EvidenceStatement(
                name="provisioned IOPS",
                value=provisioned,
                description=("IOPS provisioned for the EBS volume."),
                source=["EC2 DescribeVolumes"],
                evidence_keys=["configuration.iops"],
                unit="IOPS",
                observed=True,
            ),
            EvidenceStatement(
                name="observed read operations",
                value=read_operations,
                description=(
                    "Sum of VolumeReadOps over the observation "
                    "window (CloudWatch statistic Sum)."
                ),
                source=["CloudWatch"],
                evidence_keys=[f"observations.cloudwatch.metrics.{read_metric}"],
                unit="operations",
                observed=True,
            ),
            EvidenceStatement(
                name="observed write operations",
                value=write_operations,
                description=(
                    "Sum of VolumeWriteOps over the observation "
                    "window (CloudWatch statistic Sum)."
                ),
                source=["CloudWatch"],
                evidence_keys=[f"observations.cloudwatch.metrics.{write_metric}"],
                unit="operations",
                observed=True,
            ),
            EvidenceStatement(
                name="metric period seconds",
                value=period_seconds,
                description=(
                    "CloudWatch datapoint period used to convert "
                    "summed operations into operations per second."
                ),
                source=["CloudWatch", "derived"],
                evidence_keys=["observations.derived.metric_period_seconds"],
                unit="seconds",
                observed=True,
            ),
            EvidenceStatement(
                name="estimated IOPS utilization",
                value=utilization,
                description=(
                    "Average observed IOPS (combined read and write "
                    "operations per second) divided by provisioned "
                    "IOPS."
                ),
                source=["CloudWatch", "derived"],
                evidence_keys=["observations.derived.iops_utilization"],
                unit="ratio",
                observed=True,
            ),
        ]

        evidence = self._evidence(
            context,
            volume,
            extra={
                "derived": {
                    "iops_utilization": utilization,
                    "provisioned_iops": provisioned,
                    "observed_read_operations": read_operations,
                    "observed_write_operations": write_operations,
                    "observed_operations_total": observed_operations,
                    "observed_iops": observed_iops,
                    "metric_period_seconds": period_seconds,
                    "statistic": "Sum",
                    "datapoints": datapoints,
                }
            },
        )

        return Finding(
            finding_type="ebs_low_iops_utilization",
            title="Provisioned EBS IOPS",
            resource_type=(context.resource_type or "ebs_volume"),
            resource_id=volume_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="medium",
            confidence="medium",
            reason=(
                f"EBS volume {volume_id} has "
                f"{provisioned:,.0f} provisioned IOPS while the "
                f"combined read and write workload averages "
                f"approximately {observed_iops:,.1f} operations per "
                f"second over the observation window, about "
                f"{utilization:.1%} utilization."
            ),
            conditions=conditions,
            evidence=evidence,
            observation_period=(self._observation_period(context)),
            metadata={
                "region": context.region,
                "volume_type": volume_type,
                "provisioned_iops": provisioned,
                "observed_iops": observed_iops,
                "utilization": utilization,
            },
            recommendation_eligible=True,
            aggregation_scope="resource",
            category="cost_optimization",
            status="active",
            impact={},
            account_id=context.account_id,
        )

    # Throughput

    def _throughput_finding(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        volume_id: str,
    ) -> Finding | None:

        provisioned = self._numeric(volume.get("throughput_mibps"))

        if provisioned is None:
            return None

        if provisioned <= 0:
            return None

        volume_type = str(volume.get("volume_type") or "").lower()

        if volume_type != "gp3":
            return None

        # Byte metrics are collected with statistic Sum: "value" is
        # the total bytes transferred across the query window, not a
        # rate. Provisioned throughput is MiB per SECOND, so both
        # read AND write byte totals are required and must be
        # normalized by the metric period:
        #
        #   (read bytes + write bytes) / period_seconds / MiB
        #
        # Write-only evidence would understate total throughput, so
        # the finding is explicitly TOTAL throughput utilization.
        read_metric = "VolumeReadBytes"
        write_metric = "VolumeWriteBytes"

        totals_bundle = self._sum_metric_totals(
            context,
            (read_metric, write_metric),
        )

        if totals_bundle is None:
            return None

        period_seconds, datapoints, totals = totals_bundle

        read_bytes = totals.get(read_metric, 0.0)

        write_bytes = totals.get(write_metric, 0.0)

        observed_bytes = read_bytes + write_bytes

        observed_mibps = observed_bytes / period_seconds / 1024 / 1024

        utilization = observed_mibps / provisioned

        if utilization >= (self.LOW_THROUGHPUT_UTILIZATION):
            return None

        conditions = [
            EvidenceStatement(
                name="provisioned throughput",
                value=provisioned,
                description=("Throughput provisioned for the gp3 volume."),
                source=["EC2 DescribeVolumes"],
                evidence_keys=["configuration.throughput_mibps"],
                unit="MiB/s",
                observed=True,
            ),
            EvidenceStatement(
                name="observed read bytes",
                value=read_bytes,
                description=(
                    "Sum of VolumeReadBytes over the observation "
                    "window (CloudWatch statistic Sum)."
                ),
                source=["CloudWatch"],
                evidence_keys=[f"observations.cloudwatch.metrics.{read_metric}"],
                unit="bytes",
                observed=True,
            ),
            EvidenceStatement(
                name="observed write bytes",
                value=write_bytes,
                description=(
                    "Sum of VolumeWriteBytes over the observation "
                    "window (CloudWatch statistic Sum)."
                ),
                source=["CloudWatch"],
                evidence_keys=[f"observations.cloudwatch.metrics.{write_metric}"],
                unit="bytes",
                observed=True,
            ),
            EvidenceStatement(
                name="metric period seconds",
                value=period_seconds,
                description=(
                    "CloudWatch datapoint period used to convert "
                    "summed bytes into bytes per second."
                ),
                source=["CloudWatch", "derived"],
                evidence_keys=["observations.derived.metric_period_seconds"],
                unit="seconds",
                observed=True,
            ),
            EvidenceStatement(
                name="estimated total throughput utilization",
                value=utilization,
                description=(
                    "Average total throughput (combined read and "
                    "write bytes per second) divided by provisioned "
                    "throughput."
                ),
                source=["CloudWatch", "derived"],
                evidence_keys=["observations.derived.throughput_utilization"],
                unit="ratio",
                observed=True,
            ),
        ]

        evidence = self._evidence(
            context,
            volume,
            extra={
                "derived": {
                    "throughput_utilization": utilization,
                    "provisioned_throughput_mibps": provisioned,
                    "observed_read_bytes": read_bytes,
                    "observed_write_bytes": write_bytes,
                    "observed_bytes_total": observed_bytes,
                    "observed_throughput_mibps": observed_mibps,
                    "metric_period_seconds": period_seconds,
                    "statistic": "Sum",
                    "datapoints": datapoints,
                }
            },
        )

        return Finding(
            finding_type="ebs_low_throughput_utilization",
            title="Provisioned EBS throughput",
            resource_type=(context.resource_type or "ebs_volume"),
            resource_id=volume_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="medium",
            confidence="medium",
            reason=(
                f"EBS volume {volume_id} has "
                f"{provisioned:,.2f} MiB/s provisioned "
                f"throughput while the combined read and write "
                f"workload averages approximately "
                f"{observed_mibps:,.4f} MiB/s over the observation "
                f"window, about {utilization:.1%} total throughput "
                f"utilization."
            ),
            conditions=conditions,
            evidence=evidence,
            observation_period=(self._observation_period(context)),
            metadata={
                "region": context.region,
                "volume_type": volume_type,
                "provisioned_throughput_mibps": provisioned,
                "observed_throughput_mibps": observed_mibps,
                "utilization": utilization,
            },
            recommendation_eligible=True,
            aggregation_scope="resource",
            category="cost_optimization",
            status="active",
            impact={},
            account_id=context.account_id,
        )

    # Evidence

    def _evidence(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        *,
        extra: dict[str, Any] | None = None,
    ) -> Evidence:

        resource = {
            "resource_id": context.resource_id,
            "resource_type": context.resource_type or "ebs_volume",
            "region": context.region,
            "account_id": context.account_id,
            "configuration": dict(volume),
            "data_quality": context.data_quality(),
            "observation_period": context.period(),
        }

        if extra:

            resource.update(extra)

        return Evidence(billing=dict(context.billing() or {}), resource=resource)

    # Helpers

    @staticmethod
    def _is_unattached(
        volume: dict[str, Any],
    ) -> bool:

        attached = volume.get("attached")

        if attached is not None:
            return attached is False

        attachments = volume.get("attachments")

        if isinstance(
            attachments,
            list,
        ):
            return len(attachments) == 0

        state = str(volume.get("state") or "").lower()

        return state == "available"

    @staticmethod
    def _is_gp2(
        volume: dict[str, Any],
    ) -> bool:

        return str(volume.get("volume_type") or "").lower() == "gp2"

    @staticmethod
    def _numeric(
        value: Any,
    ) -> float | None:

        if isinstance(
            value,
            bool,
        ):
            return None

        if isinstance(
            value,
            (int, float),
        ):
            return float(value)

        try:

            if value is None:
                return None

            return float(str(value).strip())

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _metric_period_seconds(
        metric: dict[str, Any],
    ) -> float | None:

        for key in (
            "period_seconds",
            "period",
        ):

            value = metric.get(key)

            if (
                isinstance(
                    value,
                    (int, float),
                )
                and value > 0
            ):

                return float(value)

        summary = metric.get("summary")

        if isinstance(
            summary,
            dict,
        ):

            value = summary.get("period_seconds")

            if (
                isinstance(
                    value,
                    (int, float),
                )
                and value > 0
            ):

                return float(value)

        return None

    def _sum_metric_totals(
        self,
        context: AnalysisContext,
        metric_names: tuple[str, str],
    ) -> tuple[float, int, dict[str, float]] | None:
        """
        Fail-closed Sum-metric reader.

        Returns (period_seconds, min_datapoints, {name: total}) only
        when EVERY requested metric is observed, was collected with
        statistic Sum, carries at least MIN_OBSERVATION_DATAPOINTS
        datapoints, and records an explicit period. Anything else
        returns None -- a utilization ratio computed from unknown
        statistic/period semantics is worse than no finding.
        """

        totals: dict[str, float] = {}

        min_datapoints: int | None = None

        period_seconds: float | None = None

        for name in metric_names:

            metric = context.metric(name)

            if not metric:
                return None

            if metric_statistic(metric) != "Sum":
                return None

            datapoints = context.metric_datapoints(name)

            if datapoints < self.MIN_OBSERVATION_DATAPOINTS:
                return None

            value = context.metric_value(name)

            if value is None:
                return None

            metric_period = self._metric_period_seconds(metric)

            if metric_period is None or metric_period <= 0:
                return None

            # All metrics in one profile share one period; require
            # agreement rather than assuming it.
            if period_seconds is not None and period_seconds != metric_period:
                return None

            period_seconds = metric_period

            if min_datapoints is None or datapoints < min_datapoints:
                min_datapoints = datapoints

            totals[name] = float(value)

        if period_seconds is None or min_datapoints is None:
            return None

        return period_seconds, min_datapoints, totals

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        period = context.period()

        if not period:
            return None

        return ObservationPeriod(
            start=(period.get("start")),
            end=(period.get("end")),
            duration_seconds=(period.get("duration_seconds")),
        )
