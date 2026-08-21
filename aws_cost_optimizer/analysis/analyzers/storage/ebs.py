"""
EBS optimization analyzer.

Detects evidence-backed EBS optimization opportunities.

Supported findings:

    1. Unattached EBS volume
    2. gp2 volume eligible for gp3 migration
    3. Provisioned IOPS with insufficient observed utilization
    4. Provisioned throughput with insufficient observed utilization
    5. EBS volume with incomplete utilization evidence

Important:

    This analyzer does NOT attribute Cost Explorer service-level
    EBS charges to individual volumes.

    A billing amount in AnalysisContext is treated as contextual
    evidence only. It is never presented as the cost of the
    individual EBS volume.
"""

from __future__ import annotations

from typing import Any

from ...base import Analyzer
from ...context import AnalysisContext
from ...condition import EvidenceStatement
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
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

        resource_type = (
            context.resource_type
            or ""
        ).lower()

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

        volume = self._volume(
            context
        )

        if not volume:
            return []

        volume_id = (
            context.resource_id
            or volume.get("volume_id")
        )

        if not volume_id:
            return []

        findings: list[Finding] = []

        # ---------------------------------------------------------
        # 1. Unattached volume
        # ---------------------------------------------------------

        unattached = self._is_unattached(
            volume
        )

        if unattached:

            finding = (
                self._unattached_volume_finding(
                    context,
                    volume,
                    str(volume_id),
                )
            )

            if finding:
                findings.append(
                    finding
                )

        # ---------------------------------------------------------
        # 2. gp2 -> gp3
        # ---------------------------------------------------------

        if self._is_gp2(
            volume
        ):

            finding = (
                self._gp2_to_gp3_finding(
                    context,
                    volume,
                    str(volume_id),
                )
            )

            if finding:
                findings.append(
                    finding
                )

        # ---------------------------------------------------------
        # 3. IOPS utilization
        # ---------------------------------------------------------

        finding = (
            self._iops_finding(
                context,
                volume,
                str(volume_id),
            )
        )

        if finding:
            findings.append(
                finding
            )

        # ---------------------------------------------------------
        # 4. Throughput utilization
        # ---------------------------------------------------------

        finding = (
            self._throughput_finding(
                context,
                volume,
                str(volume_id),
            )
        )

        if finding:
            findings.append(
                finding
            )

        return findings

    # =============================================================
    # Volume extraction
    # =============================================================

    @staticmethod
    def _volume(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        configuration = (
            context.configuration()
        )

        if not configuration:
            return {}

        # Direct normalized collector document.
        if configuration.get(
            "volume_id"
        ):
            return configuration

        # Some collection flows wrap the resource.
        volume = configuration.get(
            "volume"
        )

        if isinstance(
            volume,
            dict,
        ):
            return volume

        # Some collectors expose a single-item list.
        volumes = configuration.get(
            "volumes"
        )

        if isinstance(
            volumes,
            list,
        ) and volumes:

            first = volumes[0]

            if isinstance(
                first,
                dict,
            ):
                return first

        return {}

    # =============================================================
    # Unattached volume
    # =============================================================

    def _unattached_volume_finding(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        volume_id: str,
    ) -> Finding | None:

        size = volume.get(
            "size_gib"
        )

        state = volume.get(
            "state"
        )

        conditions = [
            EvidenceStatement(
                name="volume attached",
                value=False,
                description=(
                    "The EBS volume has no current "
                    "EC2 attachment."
                ),
                source=[
                    "EC2 DescribeVolumes"
                ],
                evidence_keys=[
                    "configuration.attached"
                ],
                observed=True,
            ),
            EvidenceStatement(
                name="volume state",
                value=state,
                description=(
                    "Current EBS volume state."
                ),
                source=[
                    "EC2 DescribeVolumes"
                ],
                evidence_keys=[
                    "configuration.state"
                ],
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
            title="Review unattached EBS volume",
            resource_type=(
                context.resource_type
                or "ebs_volume"
            ),
            resource_id=volume_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="medium",
            confidence="high",
            reason=(
                f"EBS volume {volume_id} is not currently "
                f"attached to an EC2 instance"
                + (
                    f" and has {size} GiB provisioned."
                    if size is not None
                    else "."
                )
            ),
            conditions=conditions,
            evidence=evidence,
            observation_period=(
                self._observation_period(
                    context
                )
            ),
            limitations=[
                (
                    "Unattached state alone does not prove "
                    "the volume is safe to delete."
                ),
                (
                    "The volume may be intentionally retained "
                    "for backup, recovery, migration, or "
                    "operational purposes."
                ),
                (
                    "Business ownership and retention requirements "
                    "must be confirmed before deletion."
                ),
            ],
            metadata={
                "region":
                    context.region,
                "volume_type":
                    volume.get(
                        "volume_type"
                    ),
                "size_gib":
                    size,
                "encrypted":
                    volume.get(
                        "encrypted"
                    ),
                "snapshot_id":
                    volume.get(
                        "snapshot_id"
                    ),
            },
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type="elimination",
            category="cost_optimization",
            status="active",
            impact={},
            account_id=context.account_id,
        )

    # =============================================================
    # gp2 -> gp3
    # =============================================================

    def _gp2_to_gp3_finding(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        volume_id: str,
    ) -> Finding | None:

        volume_type = str(
            volume.get(
                "volume_type"
            )
            or ""
        ).lower()

        if volume_type != "gp2":
            return None

        size = volume.get(
            "size_gib"
        )

        conditions = [
            EvidenceStatement(
                name="volume type",
                value="gp2",
                description=(
                    "The EBS volume is using the gp2 "
                    "volume type."
                ),
                source=[
                    "EC2 DescribeVolumes"
                ],
                evidence_keys=[
                    "configuration.volume_type"
                ],
                observed=True,
            ),
            EvidenceStatement(
                name="gp3 availability",
                value=True,
                description=(
                    "gp3 is the recommended general-purpose "
                    "SSD generation for a migration review."
                ),
                source=[
                    "AWS EBS configuration"
                ],
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
            title="Review gp2 EBS volume for gp3 migration",
            resource_type=(
                context.resource_type
                or "ebs_volume"
            ),
            resource_id=volume_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="low",
            confidence="high",
            reason=(
                f"EBS volume {volume_id} uses gp2"
                + (
                    f" with {size} GiB provisioned."
                    if size is not None
                    else "."
                )
                + (
                    " Review migration to gp3 for "
                    "potential storage-cost and flexibility "
                    "benefits."
                )
            ),
            conditions=conditions,
            evidence=evidence,
            observation_period=(
                self._observation_period(
                    context
                )
            ),
            limitations=[
                (
                    "Migration suitability depends on the "
                    "volume's IOPS, throughput, workload, "
                    "and application requirements."
                ),
                (
                    "This finding does not claim a specific "
                    "savings amount."
                ),
                (
                    "Actual pricing depends on region and "
                    "provisioned gp3 configuration."
                ),
            ],
            metadata={
                "region":
                    context.region,
                "current_volume_type":
                    "gp2",
                "recommended_volume_type":
                    "gp3",
                "size_gib":
                    size,
            },
            recommendation_eligible=True,
            aggregation_scope="resource",
            category="cost_optimization",
            status="active",
            impact={},
            account_id=context.account_id,
        )

    # =============================================================
    # IOPS
    # =============================================================

    def _iops_finding(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        volume_id: str,
    ) -> Finding | None:

        provisioned = self._numeric(
            volume.get(
                "iops"
            )
        )

        if provisioned is None:
            return None

        volume_type = str(
            volume.get(
                "volume_type"
            )
            or ""
        ).lower()

        # Avoid applying provisioned-IOPS logic to volume
        # classes where IOPS is not an independently meaningful
        # optimization dimension.
        if volume_type not in {
            "io1",
            "io2",
            "gp3",
        }:
            return None

        metric_name = (
            "VolumeReadOps"
        )

        metric = context.metric(
            metric_name
        )

        if not metric:
            return None

        datapoints = (
            context.metric_datapoints(
                metric_name
            )
        )

        if datapoints < self.MIN_OBSERVATION_DATAPOINTS:
            return None

        observed = (
            context.metric_value(
                metric_name
            )
        )

        if observed is None:
            return None

        utilization = (
            observed / provisioned
            if provisioned > 0
            else None
        )

        if utilization is None:
            return None

        if utilization >= self.LOW_IOPS_UTILIZATION:
            return None

        conditions = [
            EvidenceStatement(
                name="provisioned IOPS",
                value=provisioned,
                description=(
                    "IOPS provisioned for the EBS volume."
                ),
                source=[
                    "EC2 DescribeVolumes"
                ],
                evidence_keys=[
                    "configuration.iops"
                ],
                unit="IOPS",
                observed=True,
            ),
            EvidenceStatement(
                name="observed read operations",
                value=observed,
                description=(
                    "Observed CloudWatch read-operation "
                    "value used as utilization evidence."
                ),
                source=[
                    "CloudWatch"
                ],
                evidence_keys=[
                    f"observations.cloudwatch.metrics."
                    f"{metric_name}"
                ],
                unit="operations",
                observed=True,
            ),
            EvidenceStatement(
                name="estimated IOPS utilization",
                value=utilization,
                description=(
                    "Observed operations divided by "
                    "provisioned IOPS. This is an approximation "
                    "and depends on the metric period."
                ),
                source=[
                    "CloudWatch",
                    "derived"
                ],
                evidence_keys=[
                    "observations.derived.iops_utilization"
                ],
                unit="ratio",
                observed=True,
            ),
        ]

        evidence = self._evidence(
            context,
            volume,
            extra={
                "derived": {
                    "iops_utilization":
                        utilization,
                    "provisioned_iops":
                        provisioned,
                    "observed_operations":
                        observed,
                    "metric":
                        metric_name,
                    "datapoints":
                        datapoints,
                }
            },
        )

        return Finding(
            finding_type="ebs_low_iops_utilization",
            title="Review provisioned EBS IOPS",
            resource_type=(
                context.resource_type
                or "ebs_volume"
            ),
            resource_id=volume_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="medium",
            confidence="medium",
            reason=(
                f"EBS volume {volume_id} has "
                f"{provisioned:,.0f} provisioned IOPS while "
                f"the observed metric indicates approximately "
                f"{utilization:.1%} utilization."
            ),
            conditions=conditions,
            evidence=evidence,
            observation_period=(
                self._observation_period(
                    context
                )
            ),
            limitations=[
                (
                    "The utilization calculation is an "
                    "approximation based on the available "
                    "CloudWatch metric and its period."
                ),
                (
                    "Read operations alone do not represent "
                    "total I/O demand."
                ),
                (
                    "Peak workload requirements must be "
                    "considered before changing provisioned IOPS."
                ),
            ],
            metadata={
                "region":
                    context.region,
                "volume_type":
                    volume_type,
                "provisioned_iops":
                    provisioned,
                "observed_metric":
                    metric_name,
                "observed_value":
                    observed,
                "utilization":
                    utilization,
            },
            recommendation_eligible=True,
            aggregation_scope="resource",
            category="cost_optimization",
            status="active",
            impact={},
            account_id=context.account_id,
        )

    # =============================================================
    # Throughput
    # =============================================================

    def _throughput_finding(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        volume_id: str,
    ) -> Finding | None:

        provisioned = self._numeric(
            volume.get(
                "throughput_mibps"
            )
        )

        if provisioned is None:
            return None

        if provisioned <= 0:
            return None

        volume_type = str(
            volume.get(
                "volume_type"
            )
            or ""
        ).lower()

        if volume_type != "gp3":
            return None

        metric_name = (
            "VolumeWriteBytes"
        )

        metric = context.metric(
            metric_name
        )

        if not metric:
            return None

        datapoints = (
            context.metric_datapoints(
                metric_name
            )
        )

        if datapoints < self.MIN_OBSERVATION_DATAPOINTS:
            return None

        observed = context.metric_value(
            metric_name
        )

        if observed is None:
            return None

        # CloudWatch byte metrics need a period conversion
        # before they can be compared to MiB/s.
        period_seconds = (
            self._metric_period_seconds(
                metric
            )
        )

        if period_seconds is None:
            return None

        observed_mibps = (
            observed
            / period_seconds
            / 1024
            / 1024
        )

        utilization = (
            observed_mibps
            / provisioned
        )

        if utilization >= (
            self.LOW_THROUGHPUT_UTILIZATION
        ):
            return None

        conditions = [
            EvidenceStatement(
                name="provisioned throughput",
                value=provisioned,
                description=(
                    "Throughput provisioned for the gp3 volume."
                ),
                source=[
                    "EC2 DescribeVolumes"
                ],
                evidence_keys=[
                    "configuration.throughput_mibps"
                ],
                unit="MiB/s",
                observed=True,
            ),
            EvidenceStatement(
                name="observed write bytes",
                value=observed,
                description=(
                    "Observed CloudWatch write-byte value."
                ),
                source=[
                    "CloudWatch"
                ],
                evidence_keys=[
                    f"observations.cloudwatch.metrics."
                    f"{metric_name}"
                ],
                unit="bytes",
                observed=True,
            ),
            EvidenceStatement(
                name="estimated throughput utilization",
                value=utilization,
                description=(
                    "Observed throughput divided by "
                    "provisioned throughput."
                ),
                source=[
                    "CloudWatch",
                    "derived"
                ],
                evidence_keys=[
                    "observations.derived.throughput_utilization"
                ],
                unit="ratio",
                observed=True,
            ),
        ]

        evidence = self._evidence(
            context,
            volume,
            extra={
                "derived": {
                    "throughput_utilization":
                        utilization,
                    "provisioned_throughput_mibps":
                        provisioned,
                    "observed_write_bytes":
                        observed,
                    "observed_throughput_mibps":
                        observed_mibps,
                    "metric_period_seconds":
                        period_seconds,
                    "metric":
                        metric_name,
                    "datapoints":
                        datapoints,
                }
            },
        )

        return Finding(
            finding_type="ebs_low_throughput_utilization",
            title="Review provisioned EBS throughput",
            resource_type=(
                context.resource_type
                or "ebs_volume"
            ),
            resource_id=volume_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="medium",
            confidence="medium",
            reason=(
                f"EBS volume {volume_id} has "
                f"{provisioned:,.2f} MiB/s provisioned "
                f"throughput while the observed metric "
                f"indicates approximately "
                f"{utilization:.1%} utilization."
            ),
            conditions=conditions,
            evidence=evidence,
            observation_period=(
                self._observation_period(
                    context
                )
            ),
            limitations=[
                (
                    "The calculation depends on the "
                    "CloudWatch metric period."
                ),
                (
                    "Write throughput alone does not "
                    "represent total workload throughput."
                ),
                (
                    "Peak workload requirements must be "
                    "considered before reducing throughput."
                ),
            ],
            metadata={
                "region":
                    context.region,
                "volume_type":
                    volume_type,
                "provisioned_throughput_mibps":
                    provisioned,
                "observed_throughput_mibps":
                    observed_mibps,
                "utilization":
                    utilization,
            },
            recommendation_eligible=True,
            aggregation_scope="resource",
            category="cost_optimization",
            status="active",
            impact={},
            account_id=context.account_id,
        )

    # =============================================================
    # Evidence
    # =============================================================

    def _evidence(
        self,
        context: AnalysisContext,
        volume: dict[str, Any],
        *,
        extra: dict[str, Any] | None = None,
    ) -> Evidence:

        resource = {
            "resource_id":
                context.resource_id,

            "resource_type":
                context.resource_type
                or "ebs_volume",

            "region":
                context.region,

            "account_id":
                context.account_id,

            "configuration":
                dict(volume),

            "data_quality":
                context.data_quality(),

            "observation_period":
                context.period(),
        }

        if extra:

            resource.update(
                extra
            )

        return Evidence(
            billing=dict(
                context.billing()
                or {}
            ),
            resource=resource
        )

    # =============================================================
    # Helpers
    # =============================================================

    @staticmethod
    def _is_unattached(
        volume: dict[str, Any],
    ) -> bool:

        attached = volume.get(
            "attached"
        )

        if attached is not None:
            return attached is False

        attachments = volume.get(
            "attachments"
        )

        if isinstance(
            attachments,
            list,
        ):
            return len(
                attachments
            ) == 0

        state = str(
            volume.get(
                "state"
            )
            or ""
        ).lower()

        return state == "available"

    @staticmethod
    def _is_gp2(
        volume: dict[str, Any],
    ) -> bool:

        return (
            str(
                volume.get(
                    "volume_type"
                )
                or ""
            ).lower()
            == "gp2"
        )

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

            return float(
                str(value).strip()
            )

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

            value = metric.get(
                key
            )

            if isinstance(
                value,
                (int, float),
            ) and value > 0:

                return float(value)

        summary = metric.get(
            "summary"
        )

        if isinstance(
            summary,
            dict,
        ):

            value = summary.get(
                "period_seconds"
            )

            if isinstance(
                value,
                (int, float),
            ) and value > 0:

                return float(value)

        return None

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        period = context.period()

        if not period:
            return None

        return ObservationPeriod(
            start=(
                period.get(
                    "start"
                )
            ),
            end=(
                period.get(
                    "end"
                )
            ),
            duration_seconds=(
                period.get(
                    "duration_seconds"
                )
            ),
        )