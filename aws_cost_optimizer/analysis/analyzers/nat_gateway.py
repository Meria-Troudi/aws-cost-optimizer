"""
NAT Gateway cost optimization analyzer.
"""

from __future__ import annotations

from typing import Any

from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from ..metrics import (
    all_metrics_observed,
    all_metrics_zero,
    any_metric_observed,
    metric_is_detected,
    metric_sum_value,
    metric_summary,
    sum_sum_metrics,
)
from .base import Analyzer
from .registry import register


TRAFFIC_METRICS = (
    "BytesOutToDestination",
    "BytesOutToSource",
)

CONNECTION_METRICS = (
    "ActiveConnectionCount",
    "ConnectionAttemptCount",
    "ConnectionEstablishedCount",
)


def has_nat_activity_data(
    context: AnalysisContext,
) -> bool:
    metrics = context.metrics()
    return (
        all_metrics_observed(
            metrics,
            list(TRAFFIC_METRICS),
        )
        and all_metrics_observed(
            metrics,
            list(CONNECTION_METRICS),
        )
    )


def nat_has_zero_activity(
    context: AnalysisContext,
) -> bool:
    if not has_nat_activity_data(context):
        return False

    metrics = context.metrics()
    return (
        all_metrics_zero(
            metrics,
            list(TRAFFIC_METRICS),
        )
        and all_metrics_zero(
            metrics,
            list(CONNECTION_METRICS),
        )
    )


def _metric_activity_observed(
    metrics: dict[str, Any],
    names: tuple[str, ...],
) -> bool | None:
    if any(
        metric_is_detected(metrics.get(name))
        for name in names
    ):
        return True

    if any_metric_observed(metrics, list(names)):
        return False

    return None


NAT_CONFIGURATION_FIELDS = (
    "nat_gateway_id",
    "vpc_id",
    "subnet_id",
    "availability_zone",
    "connectivity_type",
    "availability_mode",
    "state",
    "public_ip",
    "private_ip",
    "elastic_ip_allocation_id",
    "network_interface_id",
    "address_count",
)


@register
class NatGatewayAnalyzer(Analyzer):

    name = "nat_gateway"
    version = "10.0"

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return context.resource_type == "nat_gateway"  
    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        data = self._collect_data(context)

        findings: list[Finding] = []

        finding = self._detect_no_activity(
            context,
            data,
        )

        if finding:
            findings.append(finding)

        finding = self._detect_low_traffic(
            context,
            data,
        )

        if finding:
            findings.append(finding)

        finding = self._detect_aws_service_traffic(
            context,
            data,
        )

        if finding:
            findings.append(finding)

        finding = self._detect_cross_az(
            context,
            data,
        )

        if finding:
            findings.append(finding)

        finding = self._detect_endpoint_opportunity(
            context,
            data,
        )

        if finding:
            findings.append(finding)

        return findings

  
    def _collect_data(
        self,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        metrics = context.metrics()
        configuration = context.configuration()
        topology = context.topology()
        derived = context.derived()
        outbound = metric_sum_value(
            context.metric("BytesOutToDestination")
        )
        inbound = metric_sum_value(
            context.metric("BytesOutToSource")
        )

        if all_metrics_observed(metrics, list(TRAFFIC_METRICS)):
            traffic_bytes = sum_sum_metrics(
                metrics,
                list(TRAFFIC_METRICS),
            )
        elif outbound is not None and inbound is not None:
            traffic_bytes = outbound + inbound
        elif outbound is not None:
            traffic_bytes = outbound
        elif inbound is not None:
            traffic_bytes = inbound
        else:
            traffic_bytes = None

        traffic_gib = (
            traffic_bytes / (1024 ** 3)
            if traffic_bytes is not None
            else None
        )

        traffic_observed = _metric_activity_observed(
            metrics,
            TRAFFIC_METRICS,
        )

        connection_observed = _metric_activity_observed(
            metrics,
            CONNECTION_METRICS,
        )

        activity_data_complete = has_nat_activity_data(context)
        zero_activity = nat_has_zero_activity(context)

        aws_services = derived.get(
            "aws_service_destinations",
            [],
        )

        if not isinstance(
            aws_services,
            list,
        ):
            aws_services = []

        aws_services = [
            str(service)
            for service in aws_services
            if service
        ]


        endpoint_services = (
            self._extract_endpoint_services(
                topology
            )
        )
        summary = topology.get(
            "summary",
            {},
        )

        if not isinstance(summary, dict):
            summary = {}

        route_count = self._integer(
            summary.get(
                "nat_route_count"
            )
        )

        route_dependent_subnets = self._integer(
            summary.get(
                "route_dependent_subnet_count"
            )
        )

        route_dependent_route_tables = self._integer(
            summary.get(
                "route_dependent_route_table_count"
            )
        )

        cross_az = bool(
            summary.get(
                "has_cross_az_route_dependency"
            )
            or
            derived.get(
                "cross_az",
                False,
            )
        )

        has_s3_endpoint = bool(
            summary.get(
                "has_s3_endpoint_on_route_dependent_tables"
            )
        )

        has_dynamodb_endpoint = bool(
            summary.get(
                "has_dynamodb_endpoint_on_route_dependent_tables"
            )
        )

        has_ecr_endpoint = bool(
            summary.get(
                "has_ecr_endpoint_on_route_dependent_tables"
            )
        )

        has_blackhole_routes = bool(
            summary.get(
                "has_blackhole_routes"
            )
        )

        state = configuration.get(
            "state"
        )

        if state is None:
            nat_state = "unknown"
        else:
            nat_state = str(state).lower()

        recommendation_eligible = (
            nat_state in ("available", "unknown")
        )


        metric_summaries = {
            name: metric_summary(
                context.metric(name)
            )
            for name in (
                *TRAFFIC_METRICS,
                *CONNECTION_METRICS,
            )
        }

        return {
            "metrics": metric_summaries,

            "outbound_bytes": outbound,

            "return_bytes": inbound,

            "traffic_bytes": traffic_bytes,

            "traffic_gib": traffic_gib,

            "traffic_available": activity_data_complete,

            "traffic_observed": traffic_observed,

            "connection_observed": connection_observed,

            "connection_metrics_available": (
                all_metrics_observed(
                    metrics,
                    list(CONNECTION_METRICS),
                )
            ),

            "has_nat_activity_data": activity_data_complete,

            "nat_has_zero_activity": zero_activity,

            "recommendation_eligible": recommendation_eligible,

            "aws_services":
                aws_services,

            "endpoint_services":
                endpoint_services,

            "cross_az":
                cross_az,

            "route_count":
                route_count,

            "route_dependent_subnet_count":
                route_dependent_subnets,

            "route_dependent_route_table_count":
                route_dependent_route_tables,

            "has_route_dependency":
                route_count > 0,

            "has_s3_endpoint":
                has_s3_endpoint,

            "has_dynamodb_endpoint":
                has_dynamodb_endpoint,

            "has_ecr_endpoint":
                has_ecr_endpoint,

            "has_blackhole_routes":
                has_blackhole_routes,

            "state":
                state,

            "configuration":
                configuration,

            "topology":
                topology,

            "derived":
                derived,
        }  
    def _detect_no_activity(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data.get("recommendation_eligible", True):
            return None

        if not nat_has_zero_activity(context):
            return None

        metric_summaries = data["metrics"]

        statements = [
            EvidenceStatement(
                name="traffic",
                value={
                    "expected": "> 0 bytes",
                    "actual": "0 bytes",
                    "status": metric_summaries[
                        "BytesOutToDestination"
                    ]["status"],
                },
                description=(
                    "All NAT traffic metrics returned "
                    "confirmed zero values during the "
                    "CloudWatch observation period."
                ),
                source=[
                    "CloudWatch.BytesOutToDestination",
                    "CloudWatch.BytesOutToSource",
                ],
            ),
            EvidenceStatement(
                name="connections",
                value={
                    "expected": "> 0",
                    "actual": "0",
                    "status": metric_summaries[
                        "ActiveConnectionCount"
                    ]["status"],
                },
                description=(
                    "All NAT connection metrics returned "
                    "confirmed zero values during the "
                    "CloudWatch observation period."
                ),
                source=list(CONNECTION_METRICS),
            ),
        ]

        route_count = data[
            "route_count"
        ]

        if route_count > 0:

            statements.append(
                EvidenceStatement(
                    name="network_dependency",
                    value={
                        "expected": "0 route references",
                        "actual": (
                            f"{route_count} route references"
                        ),
                        "status": "INFO",
                    },
                    description=(
                        f"{route_count} route entries "
                        "still reference this NAT Gateway."
                    ),
                    source=[
                        "VPC route table topology"
                    ],
                )
            )

        reason = (
            "The NAT Gateway has no observed "
            "traffic or connection activity during "
            "the analysis period."
        )

        if route_count > 0:

            reason += (
                f" It is still referenced by "
                f"{route_count} route entries, so "
                "the network dependency should be "
                "reviewed before removal."
            )

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_no_activity"
            ),

            severity="medium",

            confidence="high",

            reason=reason,

            statements=statements,

            metadata={
                "traffic_gib": data["traffic_gib"],
                "has_nat_activity_data": True,
                "nat_has_zero_activity": True,
                "route_count": route_count,

                "route_dependent_subnet_count":
                    data[
                        "route_dependent_subnet_count"
                    ],

                "route_dependent_route_table_count":
                    data[
                        "route_dependent_route_table_count"
                    ],
            },

            data=data,
        )

  
    def _detect_low_traffic(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        traffic_gib = data[
            "traffic_gib"
        ]

        if traffic_gib is None:
            return None

        if traffic_gib <= 0:
            return None
        if traffic_gib > 1:
            return None

        statements = [
            EvidenceStatement(
                name="traffic_volume",
                value={
                    "gib": round(
                        traffic_gib,
                        6,
                    )
                },
                description=(
                    "The NAT Gateway processed a "
                    "small amount of traffic during "
                    "the observation period."
                ),
                source=[
                    "CloudWatch.BytesOutToDestination",
                    "CloudWatch.BytesOutToSource",
                ],
            )
        ]

        if data["route_count"] > 0:

            statements.append(
                EvidenceStatement(
                    name="network_dependency",
                    value={
                        "routes":
                            data["route_count"],
                        "subnets":
                            data[
                                "route_dependent_subnet_count"
                            ],
                    },
                    description=(
                        "The NAT Gateway remains "
                        "referenced by the network."
                    ),
                    source=[
                        "VPC route table topology"
                    ],
                )
            )

        reason = (
            f"The NAT Gateway processed "
            f"approximately {traffic_gib:.4f} GiB "
            "during the observation period."
        )

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_low_traffic"
            ),

            severity="low",

            confidence="medium",

            reason=reason,

            statements=statements,

            metadata={
                "traffic_gib":
                    round(
                        traffic_gib,
                        6,
                    )
            },

            data=data,
        )
  
    def _detect_aws_service_traffic(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        services = data[
            "aws_services"
        ]

        if not services:
            return None

        statements = [
            EvidenceStatement(
                name="aws_service_destinations",
                value=services,
                description=(
                    "Collector evidence identifies "
                    "AWS service destinations associated "
                    "with NAT Gateway traffic."
                ),
                source=[
                    "collector-derived AWS service destinations"
                ],
            )
        ]

        existing_endpoints = data[
            "endpoint_services"
        ]

        if existing_endpoints:

            statements.append(
                EvidenceStatement(
                    name="existing_vpc_endpoints",
                    value=existing_endpoints,
                    description=(
                        "VPC endpoints are already "
                        "present in the network."
                    ),
                    source=[
                        "VPC endpoint collector",
                        "network topology",
                    ],
                )
            )

        reason = (
            "AWS service traffic is associated "
            "with this NAT Gateway. Eligible traffic "
            "should be evaluated for direct VPC "
            "endpoint access."
        )

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_aws_service_traffic"
            ),

            severity="medium",

            confidence="medium",

            reason=reason,

            statements=statements,

            metadata={
                "services":
                    services,

                "existing_endpoint_services":
                    existing_endpoints,
            },

            data=data,
        )

      # FINDING: CROSS-AZ
  
    def _detect_cross_az(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data[
            "cross_az"
        ]:
            return None

        statements = [
            EvidenceStatement(
                name="cross_availability_zone",
                value=True,
                description=(
                    "Network topology identifies "
                    "NAT traffic crossing Availability "
                    "Zone boundaries."
                ),
                source=[
                    "VPC network topology"
                ],
            )
        ]

        if data["route_count"] > 0:

            statements.append(
                EvidenceStatement(
                    name="route_dependency",
                    value=data["route_count"],
                    description=(
                        "Routes reference the NAT "
                        "Gateway from the analyzed "
                        "network topology."
                    ),
                    source=[
                        "VPC route table topology"
                    ],
                )
            )

        reason = (
            "The NAT Gateway is associated with "
            "cross-Availability-Zone network routing. "
            "The NAT placement and dependent workloads "
            "should be reviewed for a more local "
            "network path."
        )

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_cross_az"
            ),

            severity="medium",

            confidence="medium",

            reason=reason,

            statements=statements,

            metadata={
                "cross_az": True,

                "route_count":
                    data["route_count"],
            },

            data=data,
        )

      # FINDING: ENDPOINT OPPORTUNITY
  
    def _detect_endpoint_opportunity(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        services = data[
            "aws_services"
        ]

        if not services:
            return None

        endpoint_services = set(
            data[
                "endpoint_services"
            ]
        )

        candidate_services = [
            service
            for service in services
            if service not in endpoint_services
        ]

        if not candidate_services:
            return None

        statements = [
            EvidenceStatement(
                name="candidate_services",
                value=candidate_services,
                description=(
                    "AWS services associated with "
                    "NAT traffic do not have a matching "
                    "VPC endpoint in the collected "
                    "network topology."
                ),
                source=[
                    "collector-derived AWS service destinations",
                    "VPC endpoint collector",
                ],
            )
        ]

        reason = (
            "Some AWS service traffic associated "
            "with this NAT Gateway has no matching "
            "VPC endpoint in the collected topology. "
            "Evaluate endpoint-based access for "
            "eligible services."
        )

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_endpoint_opportunity"
            ),

            severity="medium",

            confidence="medium",

            reason=reason,

            statements=statements,

            metadata={
                "candidate_services":
                    candidate_services
            },

            data=data,
        )

      # FINDING BUILDER
  
    def _finding(
        self,
        *,
        context: AnalysisContext,
        finding_type: str,
        severity: str,
        confidence: str,
        reason: str,
        statements: list[EvidenceStatement],
        metadata: dict[str, Any],
        data: dict[str, Any],
    ) -> Finding:

        return Finding(

            finding_type=finding_type,

            resource_type="nat_gateway",

            resource_id=(
                context.resource_id
                or "unknown"

            ),

            analyzer=self.name,

            analyzer_version=self.version,

            severity=severity,

            confidence=confidence,

            reason=reason,

            conditions=statements,

            evidence=self._build_evidence(
                context,
                data,
            ),

            observation_period=(
                self._observation_period(
                    context
                )
            ),

        
            limitations=[],

            metadata=metadata,

            recommendation_eligible=True,
        )

      # EVIDENCE
  
    def _build_evidence(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Evidence:

        configuration = data[
            "configuration"
        ]

        filtered_config = {
            key: configuration.get(key)
            for key in NAT_CONFIGURATION_FIELDS
            if key in configuration
        }

        return Evidence(

            metrics=data[
                "metrics"
            ],

            configuration=filtered_config,

            topology=data[
                "topology"
            ],

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,
            },

            derived={

                "outbound_bytes":
                    data["outbound_bytes"],

                "return_bytes":
                    data["return_bytes"],

                "traffic_bytes":
                    data["traffic_bytes"],

                "traffic_gib": (
                    round(
                        data["traffic_gib"],
                        6,
                    )
                    if data["traffic_gib"] is not None
                    else None
                ),

                "traffic_available":
                    data["traffic_available"],

                "has_nat_activity_data":
                    data["has_nat_activity_data"],

                "nat_has_zero_activity":
                    data["nat_has_zero_activity"],

                "traffic_observed":
                    data["traffic_observed"],

                "connection_observed":
                    data["connection_observed"],

                "connection_metrics_available":
                    data[
                        "connection_metrics_available"
                    ],

                "aws_service_destinations":
                    data["aws_services"],

                "existing_vpc_endpoint_services":
                    data[
                        "endpoint_services"
                    ],

                "route_count":
                    data["route_count"],

                "route_dependent_subnet_count":
                    data[
                        "route_dependent_subnet_count"
                    ],

                "route_dependent_route_table_count":
                    data[
                        "route_dependent_route_table_count"
                    ],

                "cross_az":
                    data["cross_az"],

                "has_s3_endpoint":
                    data["has_s3_endpoint"],

                "has_dynamodb_endpoint":
                    data[
                        "has_dynamodb_endpoint"
                    ],

                "has_ecr_endpoint":
                    data["has_ecr_endpoint"],

                "has_blackhole_routes":
                    data["has_blackhole_routes"],
            },

            data_quality={
                "traffic_available":
                    data["traffic_available"],

                "connection_metrics_available":
                    data[
                        "connection_metrics_available"
                    ],

                "collector_data_quality":
                    context.collector_data_quality(),
            },
        )

    @staticmethod
    def _extract_endpoint_services(
        topology: dict[str, Any],
    ) -> list[str]:

        values = topology.get(
            "vpc_endpoints"
        )

        if not isinstance(
            values,
            list,
        ):
            return []

        result: list[str] = []

        for value in values:

            service = None

            if isinstance(
                value,
                str,
            ):
                service = value

            elif isinstance(
                value,
                dict,
            ):
                service = (
                    value.get(
                        "service_name"
                    )
                    or value.get(
                        "service"
                    )
                    or value.get(
                        "name"
                    )
                )

            if service:

                service = str(
                    service
                )

                if service not in result:
                    result.append(
                        service
                    )

        return result

    @staticmethod
    def _integer(
        value: Any,
    ) -> int:

        if isinstance(
            value,
            bool,
        ):
            return int(value)

        if isinstance(
            value,
            (int, float),
        ):
            return int(value)

        return 0

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        value = (
            context.observation_period
        )

        if not value:
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