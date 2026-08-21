"""
NAT Gateway cost optimization analyzer.

Purpose
-------
Generate concise, evidence-based NAT Gateway cost findings.

Findings
--------
1. nat_gateway_idle
2. nat_gateway_no_route_dependency
3. nat_gateway_low_traffic
4. nat_gateway_cross_az
5. nat_gateway_endpoint_opportunity
6. nat_gateway_high_data_processing
7. nat_gateway_multiple_az

Important
---------
This analyzer does not invent NAT Gateway cost.

CloudWatch traffic is operational evidence.

Billing attribution remains the responsibility of the billing/
reconciliation layer.

The analyzer also does not claim that observed NAT traffic is:
    - S3 traffic
    - DynamoDB traffic
    - cross-Region traffic
    - internet egress

Those require additional attribution evidence.
"""

from __future__ import annotations

from typing import Any, Optional

from ....base import Analyzer
from ....condition import EvidenceStatement
from ....context import AnalysisContext
from ....evidence import Evidence
from ....finding import Finding, ObservationPeriod
from ....registry import register


DEFAULT_LOW_TRAFFIC_GIB = 1.0
DEFAULT_HIGH_TRAFFIC_GIB = 100.0


TITLES = {
    "nat_gateway_idle":
        "NAT Gateway is idle",

    "nat_gateway_no_route_dependency":
        "NAT Gateway has no route dependency",

    "nat_gateway_low_traffic":
        "NAT Gateway has low observed traffic",

    "nat_gateway_cross_az":
        "NAT Gateway serves cross-AZ traffic paths",

    "nat_gateway_endpoint_opportunity":
        "NAT Gateway may have endpoint opportunity",

    "nat_gateway_high_data_processing":
        "NAT Gateway has high observed traffic",

    "nat_gateway_multiple_az":
        "NAT Gateway architecture warrants review",
}


LIMITATIONS = {
    "nat_gateway_idle": [
        "Applies only to the collected observation period.",
        "Missing telemetry is not treated as zero.",
        "Confirm workload and recovery requirements before removal.",
    ],

    "nat_gateway_no_route_dependency": [
        "Based on the discovered route tables.",
        "Future or non-discovered dependencies may still exist.",
        "No resource-level billing amount is claimed.",
    ],

    "nat_gateway_low_traffic": [
        "Traffic is an operational indicator, not a resource billing amount.",
        "Low traffic does not prove that the gateway is unnecessary.",
    ],

    "nat_gateway_cross_az": [
        "The finding identifies topology, not cross-AZ transfer cost.",
        "The collector does not attribute traffic volume to each subnet.",
        "Review availability and resilience requirements before changing routing.",
    ],

    "nat_gateway_endpoint_opportunity": [
        "Observed NAT traffic is not identified by destination service.",
        "No conclusion is made that the traffic is S3, DynamoDB, ECR, or another endpoint-eligible service.",
        "No savings amount is estimated.",
    ],

    "nat_gateway_high_data_processing": [
        "The traffic value is an operational indicator, not billing-attributed NAT usage.",
        "High traffic does not prove that the traffic is unnecessary.",
        "Review traffic sources and architecture before claiming savings.",
    ],

    "nat_gateway_multiple_az": [
        "Multiple NAT gateways may be intentional for availability or isolation.",
        "The finding identifies architecture for review, not guaranteed savings.",
        "No consolidation action should be taken without validating HA requirements.",
    ],
}


def _dict(
    value: Any,
) -> dict[str, Any]:

    return (
        value
        if isinstance(value, dict)
        else {}
    )


def _list(
    value: Any,
) -> list[Any]:

    return (
        value
        if isinstance(value, list)
        else []
    )


def _number(
    value: Any,
) -> Optional[float]:

    if value is None:
        return None

    if isinstance(
        value,
        bool,
    ):
        return None

    try:
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return None


def _statement(
    *,
    name: str,
    value: Any,
    description: str,
    source: list[str],
    unit: str | None = None,
) -> EvidenceStatement:

    return EvidenceStatement(
        name=name,
        value=value,
        description=description,
        source=list(source),
        unit=unit,
    )


@register
class NatGatewayAnalyzer(Analyzer):

    name = "nat_gateway"
    version = "3.0"

    SUPPORTED_RESOURCE_TYPES = {
        "nat_gateway",
    }

    # ==============================================================
    # SUPPORT
    # ==============================================================

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            in self.SUPPORTED_RESOURCE_TYPES
        )

    # ==============================================================
    # ENTRY POINT
    # ==============================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        evidence = _dict(
            context.optimization_evidence()
        )

        if not evidence:
            return []

        resource = _dict(
            evidence.get("resource")
        )

        if resource.get(
            "state_category"
        ) != "operational":

            return []

        if not self._usable(
            evidence
        ):
            return []

        detectors = (
            self._detect_idle,
            self._detect_no_route_dependency,
            self._detect_low_traffic,
            self._detect_cross_az,
            self._detect_endpoint_opportunity,
            self._detect_high_data_processing,
            self._detect_multiple_az,
        )

        findings: list[Finding] = []

        for detector in detectors:

            try:

                finding = detector(
                    context,
                    evidence,
                )

            except Exception as exc:

                # One detector must not destroy the complete
                # analyzer result.
                print(
                    "[ERROR] NAT Gateway detector "
                    f"{detector.__name__} failed for "
                    f"{context.resource_id}: {exc}"
                )

                continue

            if finding:
                findings.append(
                    finding
                )

        return findings

    # ==============================================================
    # EVIDENCE ACCESS
    # ==============================================================

    @staticmethod
    def _activity(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "activity"
            )
        )

    @staticmethod
    def _network(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "network"
            )
        )

    @staticmethod
    def _fleet(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "fleet"
            )
        )

    @staticmethod
    def _configuration(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "configuration"
            )
        )

    @staticmethod
    def _quality(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "data_quality"
            )
        )

    # ==============================================================
    # QUALITY
    # ==============================================================

    @staticmethod
    def _usable(
        evidence: dict[str, Any],
    ) -> bool:

        quality = _dict(
            evidence.get(
                "data_quality"
            )
        )

        return (
            quality.get(
                "topology_available"
            ) is True
            or
            quality.get(
                "traffic_available"
            ) is True
        )

    @staticmethod
    def _traffic_complete(
        evidence: dict[str, Any],
    ) -> bool:

        quality = _dict(
            evidence.get(
                "data_quality"
            )
        )

        return (
            quality.get(
                "traffic_available"
            ) is True
            and
            quality.get(
                "traffic_complete"
            ) is True
            and
            quality.get(
                "traffic_semantics_valid"
            ) is True
        )

    @staticmethod
    def _connection_complete(
        evidence: dict[str, Any],
    ) -> bool:

        quality = _dict(
            evidence.get(
                "data_quality"
            )
        )

        return (
            quality.get(
                "connection_data_available"
            ) is True
            and
            quality.get(
                "connection_data_complete"
            ) is True
        )

    # ==============================================================
    # 1. IDLE
    # ==============================================================

    def _detect_idle(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        activity = self._activity(
            evidence
        )
        network = self._network(
            evidence
        )

        if not self._traffic_complete(
            evidence
        ):
            return None

        if not self._connection_complete(
            evidence
        ):
            return None

        if activity.get(
            "traffic_zero"
        ) is not True:

            return None

        if activity.get(
            "connections_zero"
        ) is not True:

            return None

        route_count = _number(
            network.get(
                "nat_route_count"
            )
        )

        route_count = (
            route_count
            if route_count is not None
            else 0.0
        )

        severity = (
            "high"
            if route_count == 0
            else "medium"
        )

        confidence = (
            "high"
            if route_count == 0
            else "medium"
        )

        reason = (
            "No NAT traffic or connections were observed "
            "during the complete collection period."
        )

        statements = [
            _statement(
                name="traffic",
                value=0,
                description=(
                    "Observed NAT traffic indicator."
                ),
                source=["CloudWatch"],
                unit="bytes",
            ),
            _statement(
                name="connections",
                value=0,
                description=(
                    "Observed NAT connections."
                ),
                source=["CloudWatch"],
                unit="count",
            ),
        ]

        if route_count == 0:

            statements.append(
                _statement(
                    name="nat_route_count",
                    value=0,
                    description=(
                        "No discovered route references "
                        "this NAT Gateway."
                    ),
                    source=["Topology"],
                    unit="routes",
                )
            )

            reason += (
                " No discovered route depends on the gateway."
            )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_idle",
            severity=severity,
            confidence=confidence,
            reason=reason,
            statements=statements,
            limitations=LIMITATIONS[
                "nat_gateway_idle"
            ],
            metadata={
                "traffic_zero": True,
                "connections_zero": True,
                "nat_route_count": route_count,
            },
        )

    # ==============================================================
    # 2. NO ROUTE DEPENDENCY
    # ==============================================================

    def _detect_no_route_dependency(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        network = self._network(
            evidence
        )

        quality = self._quality(
            evidence
        )

        if quality.get(
            "topology_available"
        ) is not True:

            return None

        route_count = _number(
            network.get(
                "nat_route_count"
            )
        )

        if route_count is None:
            return None

        if route_count != 0:
            return None

        # Avoid duplicating the stronger idle finding.
        activity = self._activity(
            evidence
        )

        if (
            activity.get(
                "traffic_zero"
            ) is True
            and
            activity.get(
                "connections_zero"
            ) is True
        ):
            return None

        subnet_count = _number(
            network.get(
                "route_dependent_subnet_count"
            )
        ) or 0.0

        route_table_count = _number(
            network.get(
                "route_dependent_route_table_count"
            )
        ) or 0.0

        reason = (
            "No discovered route table currently references "
            "this NAT Gateway."
        )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_no_route_dependency",
            severity="high",
            confidence="high",
            reason=reason,
            statements=[
                _statement(
                    name="nat_route_count",
                    value=0,
                    description=(
                        "Routes targeting the NAT Gateway."
                    ),
                    source=["Topology"],
                    unit="routes",
                ),
                _statement(
                    name="dependent_subnets",
                    value=subnet_count,
                    description=(
                        "Subnets using routes that target "
                        "the NAT Gateway."
                    ),
                    source=["Topology"],
                    unit="subnets",
                ),
                _statement(
                    name="dependent_route_tables",
                    value=route_table_count,
                    description=(
                        "Route tables using the NAT Gateway."
                    ),
                    source=["Topology"],
                    unit="route tables",
                ),
            ],
            limitations=LIMITATIONS[
                "nat_gateway_no_route_dependency"
            ],
            metadata={
                "nat_route_count": 0,
                "route_dependent_subnet_count":
                    subnet_count,
                "route_dependent_route_table_count":
                    route_table_count,
            },
        )

    # ==============================================================
    # 3. LOW TRAFFIC
    # ==============================================================

    def _detect_low_traffic(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if not self._traffic_complete(
            evidence
        ):
            return None

        activity = self._activity(
            evidence
        )

        if activity.get(
            "traffic_observed"
        ) is not True:

            return None

        traffic_gib = _number(
            activity.get(
                "directional_traffic_gib"
            )
        )

        if traffic_gib is None:
            return None

        threshold = (
            self._threshold(
                context,
                "low_traffic_gib",
                DEFAULT_LOW_TRAFFIC_GIB,
            )
        )

        if traffic_gib <= 0:
            return None

        if traffic_gib > threshold:
            return None

        reason = (
            f"Observed NAT traffic was approximately "
            f"{traffic_gib:.3f} GiB, below the "
            f"{threshold:.3f} GiB review threshold."
        )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_low_traffic",
            severity="low",
            confidence="medium",
            reason=reason,
            statements=[
                _statement(
                    name="directional_traffic",
                    value=round(
                        traffic_gib,
                        3,
                    ),
                    description=(
                        "Observed directional traffic "
                        "indicator."
                    ),
                    source=["CloudWatch"],
                    unit="GiB",
                ),
                _statement(
                    name="threshold",
                    value=threshold,
                    description=(
                        "Configured low-traffic threshold."
                    ),
                    source=["Analysis profile"],
                    unit="GiB",
                ),
            ],
            limitations=LIMITATIONS[
                "nat_gateway_low_traffic"
            ],
            metadata={
                "directional_traffic_gib":
                    traffic_gib,
                "threshold_gib":
                    threshold,
            },
        )

    # ==============================================================
    # 4. CROSS-AZ
    # ==============================================================

    def _detect_cross_az(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(
            evidence
        )

        network = self._network(
            evidence
        )

        quality = self._quality(
            evidence
        )

        if quality.get(
            "topology_available"
        ) is not True:

            return None

        if quality.get(
            "traffic_available"
        ) is not True:

            return None

        # ----------------------------------------------------------
        # Important:
        #
        # A regional NAT is specifically designed to support
        # multiple AZs, so a subnet in another AZ is not sufficient
        # evidence of the classic cross-AZ NAT architecture issue.
        # ----------------------------------------------------------

        if configuration.get(
            "availability_mode"
        ) == "regional":

            return None

        if (
            network.get(
                "has_cross_az_route_dependency"
            )
            is not True
        ):
            return None

        activity = self._activity(
            evidence
        )

        if activity.get(
            "traffic_observed"
        ) is not True:

            return None

        cross_az_count = _number(
            network.get(
                "cross_az_subnet_count"
            )
        ) or 0.0

        same_az_count = _number(
            network.get(
                "same_az_subnet_count"
            )
        ) or 0.0

        if cross_az_count <= 0:
            return None

        reason = (
            f"{cross_az_count:g} dependent subnet(s) are "
            "in a different Availability Zone from the "
            "zonal NAT Gateway, while NAT traffic was observed."
        )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_cross_az",
            severity="medium",
            confidence="high",
            reason=reason,
            statements=[
                _statement(
                    name="cross_az_subnets",
                    value=cross_az_count,
                    description=(
                        "Dependent subnets in another "
                        "Availability Zone."
                    ),
                    source=["Topology"],
                    unit="subnets",
                ),
                _statement(
                    name="same_az_subnets",
                    value=same_az_count,
                    description=(
                        "Dependent subnets in the gateway's "
                        "Availability Zone."
                    ),
                    source=["Topology"],
                    unit="subnets",
                ),
                _statement(
                    name="nat_availability_zone",
                    value=configuration.get(
                        "availability_zone"
                    ),
                    description=(
                        "Availability Zone of the NAT Gateway."
                    ),
                    source=["Configuration"],
                ),
            ],
            limitations=LIMITATIONS[
                "nat_gateway_cross_az"
            ],
            metadata={
                "cross_az_subnet_count":
                    cross_az_count,
                "same_az_subnet_count":
                    same_az_count,
                "nat_availability_zone":
                    configuration.get(
                        "availability_zone"
                    ),
            },
        )

    # ==============================================================
    # 5. ENDPOINT OPPORTUNITY
    # ==============================================================

    def _detect_endpoint_opportunity(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        network = self._network(
            evidence
        )

        quality = self._quality(
            evidence
        )

        activity = self._activity(
            evidence
        )

        if quality.get(
            "topology_available"
        ) is not True:

            return None

        if quality.get(
            "traffic_available"
        ) is not True:

            return None

        if activity.get(
            "traffic_observed"
        ) is not True:

            return None

        subnet_count = _number(
            network.get(
                "route_dependent_subnet_count"
            )
        ) or 0.0

        route_table_count = _number(
            network.get(
                "route_dependent_route_table_count"
            )
        ) or 0.0

        endpoint_count = _number(
            network.get(
                "relevant_endpoint_count"
            )
        ) or 0.0

        if (
            subnet_count <= 0
            and route_table_count <= 0
        ):
            return None

        if endpoint_count > 0:
            return None

        # Do not pretend we know the destination service.
        candidate_services = _list(
            network.get(
                "relevant_endpoint_services"
            )
        )

        reason = (
            "The NAT Gateway carries observed traffic from "
            f"{subnet_count:g} dependent subnet(s), but no "
            "relevant VPC endpoint relationship was discovered "
            "on the dependent network paths."
        )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_endpoint_opportunity",
            severity="low",
            confidence="low",
            reason=reason,
            statements=[
                _statement(
                    name="dependent_subnets",
                    value=subnet_count,
                    description=(
                        "Subnets whose routes use the NAT Gateway."
                    ),
                    source=["Topology"],
                    unit="subnets",
                ),
                _statement(
                    name="relevant_endpoints",
                    value=endpoint_count,
                    description=(
                        "Relevant VPC endpoints already covering "
                        "the dependent paths."
                    ),
                    source=["Topology"],
                    unit="endpoints",
                ),
            ],
            limitations=LIMITATIONS[
                "nat_gateway_endpoint_opportunity"
            ],
            metadata={
                "route_dependent_subnet_count":
                    subnet_count,
                "route_dependent_route_table_count":
                    route_table_count,
                "relevant_endpoint_count":
                    endpoint_count,
                "candidate_services":
                    candidate_services,
                "traffic_service_attribution_available":
                    False,
            },
        )

    # ==============================================================
    # 6. HIGH TRAFFIC
    # ==============================================================

    def _detect_high_data_processing(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if not self._traffic_complete(
            evidence
        ):
            return None

        activity = self._activity(
            evidence
        )

        if activity.get(
            "traffic_observed"
        ) is not True:

            return None

        traffic_gib = _number(
            activity.get(
                "directional_traffic_gib"
            )
        )

        if traffic_gib is None:
            return None

        threshold = (
            self._threshold(
                context,
                "high_traffic_gib",
                DEFAULT_HIGH_TRAFFIC_GIB,
            )
        )

        if traffic_gib <= threshold:
            return None

        reason = (
            f"Observed NAT traffic was approximately "
            f"{traffic_gib:.3f} GiB, above the "
            f"{threshold:.3f} GiB review threshold."
        )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_high_data_processing",
            severity="medium",
            confidence="medium",
            reason=reason,
            statements=[
                _statement(
                    name="directional_traffic",
                    value=round(
                        traffic_gib,
                        3,
                    ),
                    description=(
                        "Observed directional traffic "
                        "indicator."
                    ),
                    source=["CloudWatch"],
                    unit="GiB",
                ),
                _statement(
                    name="threshold",
                    value=threshold,
                    description=(
                        "Configured high-traffic threshold."
                    ),
                    source=["Analysis profile"],
                    unit="GiB",
                ),
            ],
            limitations=LIMITATIONS[
                "nat_gateway_high_data_processing"
            ],
            metadata={
                "directional_traffic_gib":
                    traffic_gib,
                "threshold_gib":
                    threshold,
            },
        )

    # ==============================================================
    # 7. MULTIPLE NAT ARCHITECTURE
    # ==============================================================

    def _detect_multiple_az(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        fleet = self._fleet(
            evidence
        )

        quality = self._quality(
            evidence
        )

        if quality.get(
            "topology_available"
        ) is not True:

            return None

        if fleet.get(
            "has_multiple_nats_in_same_az"
        ) is not True:

            return None

        same_az_ids = _list(
            fleet.get(
                "same_az_alternative_nat_ids"
            )
        )

        # If there is no concrete alternative for this resource,
        # do not report an architecture finding.
        if not same_az_ids:
            return None

        current_az = fleet.get(
            "current_nat_availability_zone"
        )

        reason = (
            "Multiple operational NAT Gateways were discovered "
            f"in Availability Zone {current_az or 'unknown'} "
            "within the same VPC."
        )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_multiple_az",
            severity="medium",
            confidence="medium",
            reason=reason,
            statements=[
                _statement(
                    name="same_az_nat_gateways",
                    value=len(
                        same_az_ids
                    ),
                    description=(
                        "Other operational NAT Gateways "
                        "in the same Availability Zone."
                    ),
                    source=["Topology"],
                    unit="gateways",
                ),
                _statement(
                    name="same_vpc_nat_count",
                    value=fleet.get(
                        "nat_gateway_count"
                    ),
                    description=(
                        "NAT Gateways discovered in the VPC."
                    ),
                    source=["Topology"],
                    unit="gateways",
                ),
                _statement(
                    name="same_az_alternatives",
                    value=same_az_ids,
                    description=(
                        "Alternative NAT Gateway IDs in the "
                        "same Availability Zone."
                    ),
                    source=["Topology"],
                ),
            ],
            limitations=LIMITATIONS[
                "nat_gateway_multiple_az"
            ],
            metadata={
                "availability_zone":
                    current_az,

                "same_az_alternative_nat_ids":
                    same_az_ids,

                "same_az_alternative_nat_count":
                    len(
                        same_az_ids
                    ),

                "same_vpc_nat_count":
                    fleet.get(
                        "nat_gateway_count"
                    ),

                "operational_nat_count":
                    fleet.get(
                        "operational_nat_gateway_count"
                    ),
            },
        )

    # ==============================================================
    # THRESHOLDS
    # ==============================================================

    @staticmethod
    def _threshold(
        context: AnalysisContext,
        name: str,
        default: float,
    ) -> float:

        # Optional resource-level override.
        #
        # This keeps the analyzer usable even if the collection
        # profile is not copied into AnalysisContext.
        candidates = (
            context.resource.get(
                "analysis_profile"
            ),

            context.resource.get(
                "optimization_profile"
            ),

            context.resource.get(
                "analyzer_config"
            ),
        )

        for candidate in candidates:

            if not isinstance(
                candidate,
                dict,
            ):
                continue

            value = _number(
                candidate.get(
                    name
                )
            )

            if (
                value is not None
                and value >= 0
            ):

                return value

        return default

    # ==============================================================
    # FINDING BUILDER
    # ==============================================================

    def _finding(
        self,
        *,
        context: AnalysisContext,
        evidence: dict[str, Any],
        finding_type: str,
        severity: str,
        confidence: str,
        reason: str,
        statements: list[EvidenceStatement],
        limitations: list[str],
        metadata: dict[str, Any],
    ) -> Finding:

        final_metadata = {
            "region":
                context.region,

            **metadata,
        }

        return Finding(
            finding_type=
                finding_type,

            title=
                TITLES.get(
                    finding_type,
                    finding_type,
                ),

            resource_type=(
                context.resource_type
                or "nat_gateway"
            ),

            resource_id=(
                context.resource_id
                or "unknown"
            ),

            analyzer=
                self.name,

            analyzer_version=
                self.version,

            severity=
                str(
                    severity
                ).lower(),

            confidence=
                str(
                    confidence
                ).lower(),

            reason=
                reason,

            conditions=
                statements,

            evidence=
                self._build_evidence(
                    context,
                    evidence,
                ),

            observation_period=
                self._observation_period(
                    context
                ),

            limitations=
                list(
                    limitations
                ),

            metadata=
                final_metadata,

            # This analyzer only produces cost-oriented findings.
            recommendation_eligible=
                True,

            impact={},
        )

    # ==============================================================
    # STRUCTURED EVIDENCE
    # ==============================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
        optimization_evidence: dict[str, Any],
    ) -> Evidence:

        metrics = {
            name:
                context.metric_summary(
                    name
                )
            for name
            in _dict(
                context.metrics()
            )
        }

        configuration = {
            key:
                value
            for key, value
            in _dict(
                context.configuration()
            ).items()
            if key != "tags"
        }

        network = self._network(
            optimization_evidence
        )

        activity = self._activity(
            optimization_evidence
        )

        fleet = self._fleet(
            optimization_evidence
        )

        return Evidence(
            metrics=
                metrics,

            configuration=
                configuration,

            topology=
                _dict(
                    context.topology()
                ),

            resource=
                _dict(
                    optimization_evidence.get(
                        "resource"
                    )
                ),

            derived={
                "activity":
                    activity,

                "network":
                    network,

                "fleet":
                    fleet,
            },

            billing=
                _dict(
                    context.billing()
                ),

            data_quality=
                self._quality(
                    optimization_evidence
                ),
        )

    # ==============================================================
    # OBSERVATION PERIOD
    # ==============================================================

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        cloudwatch = _dict(
            context.cloudwatch()
        )

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