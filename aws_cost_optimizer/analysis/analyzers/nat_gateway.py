"""
NAT Gateway cost and operational optimization analyzer.

"""

from __future__ import annotations

from typing import Any

from sqlalchemy import values

from ..base import Analyzer
from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from ..metrics import (
    metric_has_observed_data,
    metric_is_sum,
    metric_numeric_value,
    metric_sum_value,
    metric_summary,
)
from ..registry import register


# ======================================================================
# METRIC GROUPS
# ======================================================================

TRAFFIC_METRICS = (
    "BytesOutToDestination",
    "BytesOutToSource",
    "BytesInFromSource",
    "BytesInFromDestination",
)

CONNECTION_METRICS = (
    "ActiveConnectionCount",
    "ConnectionAttemptCount",
    "ConnectionEstablishedCount",
)

ERROR_METRICS = (
    "PacketsDropCount",
    "ErrorPortAllocation",
    "IdleTimeoutCount",
)

ACTIVITY_METRICS = (
    *TRAFFIC_METRICS,
    *CONNECTION_METRICS,
)


DEFAULT_LOW_TRAFFIC_GIB = 1.0
DEFAULT_TRAFFIC_IMBALANCE_RATIO = 10.0


def _config(
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
            "nat_gateway"
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
    default: float | None,
) -> float | None:

    value = _config(
        context
    ).get(
        key
    )

    if value is None:
        return default

    try:
        number = float(value)
    except (
        TypeError,
        ValueError,
    ):
        return default

    if number < 0:
        return default

    return number


# ======================================================================
# ANALYZER
# ======================================================================

@register
class NatGatewayAnalyzer(Analyzer):

    name = "nat_gateway"
    version = "15.0"

    # ==============================================================
    # SUPPORT
    # ==============================================================

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            == "nat_gateway"
        )

    # ==============================================================
    # MAIN
    # ==============================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        data = self._collect_data(
            context
        )

        findings: list[Finding] = []

        checks = (
            self._detect_non_operational,
            self._detect_idle,
            self._detect_low_traffic,
            self._detect_cross_az,
            self._detect_aws_service_traffic,
            self._detect_endpoint_opportunity,
            self._detect_packet_drops,
            self._detect_port_allocation_errors,
            self._detect_idle_timeouts,
            self._detect_traffic_imbalance,
        )

        for detector in checks:

            finding = detector(
                context,
                data,
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    # ==============================================================
    # DATA COLLECTION / NORMALIZATION
    # ==============================================================

    def _collect_data(
        self,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        configuration = context.configuration()
        topology = context.topology()
        derived = context.derived()

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        if not isinstance(
            topology,
            dict,
        ):
            topology = {}

        if not isinstance(
            derived,
            dict,
        ):
            derived = {}

        traffic = self._dict(
            derived.get(
                "traffic"
            )
        )

        connections = self._dict(
            derived.get(
                "connections"
            )
        )

        errors = self._dict(
            derived.get(
                "errors"
            )
        )

        summary = self._dict(
            topology.get(
                "summary"
            )
        )

        route_summary = self._dict(
            topology.get(
                "route_summary"
            )
        )

        # ----------------------------------------------------------
        # Metric availability
        # ----------------------------------------------------------

        traffic_metric_status = {
            name:
                metric_has_observed_data(
                    context.metric(name)
                )
            for name in TRAFFIC_METRICS
        }

        connection_metric_status = {
            name:
                metric_has_observed_data(
                    context.metric(name)
                )
            for name in CONNECTION_METRICS
        }

        error_metric_status = {
            name:
                metric_has_observed_data(
                    context.metric(name)
                )
            for name in ERROR_METRICS
        }

        traffic_available = any(
            traffic_metric_status.values()
        )

        traffic_complete = all(
            traffic_metric_status.values()
        )

        connection_available = any(
            connection_metric_status.values()
        )

        connection_complete = all(
            connection_metric_status.values()
        )

        activity_available = (
            traffic_available
            or connection_available
        )

        activity_complete = (
            traffic_complete
            and connection_complete
        )

        # ----------------------------------------------------------
        # Validate traffic metric semantics.
        #
        # A traffic metric must actually be a Sum metric before it
        # can participate in byte-volume calculations.
        # ----------------------------------------------------------

        traffic_semantics_valid = all(
            not traffic_metric_status[name]
            or metric_is_sum(
                context.metric(name)
            )
            for name in TRAFFIC_METRICS
        )

        # ----------------------------------------------------------
        # Traffic
        # ----------------------------------------------------------

        traffic_bytes = self._traffic_bytes(
            context=context,
            derived_traffic=traffic,
            traffic_complete=(
                traffic_complete
                and traffic_semantics_valid
            ),
        )

        traffic_gib = (
            traffic_bytes / (1024 ** 3)
            if traffic_bytes is not None
            else None
        )

        traffic_observed = (
            traffic_bytes > 0
            if traffic_bytes is not None
            else None
        )

        # IMPORTANT:
        # This key is explicitly stored here.
        #
        # The previous implementation used data["traffic_observed"]
        # in _detect_cross_az(), but never inserted it into data,
        # causing a KeyError and silently suppressing that finding.
        # ----------------------------------------------------------

        # ----------------------------------------------------------
        # Connections
        # ----------------------------------------------------------

        connection_observed = (
            self._connection_observed(
                context=context,
                derived_connections=connections,
                connection_complete=connection_complete,
            )
        )

        # ----------------------------------------------------------
        # Zero activity
        #
        # Only true when ALL required activity metrics were observed
        # and every value is zero.
        # ----------------------------------------------------------

        zero_activity = (
            self._is_zero_activity(
                context=context,
                activity_complete=activity_complete,
            )
        )

        # ----------------------------------------------------------
        # State
        # ----------------------------------------------------------

        raw_state = configuration.get(
            "state"
        )

        state = (
            str(
                raw_state
            ).strip().lower()
            if raw_state is not None
            else "unknown"
        )

        # ----------------------------------------------------------
        # Routes
        # ----------------------------------------------------------

        route_details = (
            self._route_dependency_details(
                topology=topology,
                route_summary=route_summary,
            )
        )

        route_count = (
            route_details[
                "route_count"
            ]
        )

        same_az_subnet_count = (
            route_details[
                "same_az_subnet_count"
            ]
        )

        cross_az_subnet_count = (
            route_details[
                "cross_az_subnet_count"
            ]
        )

        cross_az = (
            cross_az_subnet_count is not None
            and cross_az_subnet_count > 0
        )

        # ----------------------------------------------------------
        # Explicit AWS-service traffic evidence
        #
        # IMPORTANT:
        # A list by itself is not evidence.
        #
        # Every accepted item must explicitly say observed=True.
        # ----------------------------------------------------------

        aws_service_traffic = (
            self._aws_service_traffic(
                derived
            )
        )

        aws_service_traffic_observed = bool(
            aws_service_traffic
        )

        observed_aws_services = sorted(
            {
                item["service"]
                for item
                in aws_service_traffic
                if item.get(
                    "service"
                )
            }
        )

        # ----------------------------------------------------------
        # Existing endpoint topology
        # ----------------------------------------------------------

        endpoint_summary = self._dict(
            topology.get(
                "endpoint_summary"
            )
        )

        endpoint_services = (
            endpoint_summary.get(
                "services",
                [],
            )
        )

        if not isinstance(
            endpoint_services,
            list,
        ):
            endpoint_services = []

        endpoint_services = self._unique(
            endpoint_services
        )

        endpoint_service_set = {
            service.lower()
            for service
            in endpoint_services
        }

        candidate_endpoint_services = [
            service
            for service
            in observed_aws_services
            if service.lower()
            not in endpoint_service_set
        ]

        # ----------------------------------------------------------
        # Error metrics
        # ----------------------------------------------------------

        packet_drops = (
            self._observed_metric_sum(
                context,
                "PacketsDropCount",
            )
        )

        port_allocation_errors = (
            self._observed_metric_sum(
                context,
                "ErrorPortAllocation",
            )
        )

        idle_timeouts = (
            self._observed_metric_sum(
                context,
                "IdleTimeoutCount",
            )
        )

        # ----------------------------------------------------------
        # Metric summaries
        # ----------------------------------------------------------

        metrics = {
            metric_name:
                metric_summary(
                    context.metric(
                        metric_name
                    )
                )
            for metric_name in (
                *TRAFFIC_METRICS,
                *CONNECTION_METRICS,
                *ERROR_METRICS,
            )
        }

        return {
            "configuration":
                configuration,

            "topology":
                topology,

            "derived":
                derived,

            "metrics":
                metrics,

            "traffic_bytes":
                traffic_bytes,

            "traffic_gib":
                traffic_gib,

            "traffic_available":
                traffic_available,

            "traffic_complete":
                traffic_complete,

            "traffic_semantics_valid":
                traffic_semantics_valid,

            "traffic_metric_status":
                traffic_metric_status,

            "traffic_observed":
                traffic_observed,

            "connection_available":
                connection_available,

            "connection_complete":
                connection_complete,

            "connection_metric_status":
                connection_metric_status,

            "connection_observed":
                connection_observed,

            "activity_available":
                activity_available,

            "activity_complete":
                activity_complete,

            "zero_activity":
                zero_activity,

            "state":
                state,

            "route_count":
                route_count,

            "route_details":
                route_details,

            "same_az_subnet_count":
                same_az_subnet_count,

            "cross_az_subnet_count":
                cross_az_subnet_count,

            "cross_az":
                cross_az,

            "aws_service_traffic":
                aws_service_traffic,

            "aws_service_traffic_observed":
                aws_service_traffic_observed,

            "aws_services":
                observed_aws_services,

            "endpoint_services":
                endpoint_services,

            "candidate_endpoint_services":
                candidate_endpoint_services,

            "packet_drops":
                packet_drops,

            "port_allocation_errors":
                port_allocation_errors,

            "idle_timeouts":
                idle_timeouts,

            "error_metric_status":
                error_metric_status,

            "has_blackhole_routes":
                bool(
                    route_summary.get(
                        "has_blackhole_routes"
                    )
                ),

            "blackhole_route_count":
                self._optional_int(
                    route_summary.get(
                        "blackhole_route_count"
                    )
                ),
        }

    # ==============================================================
    # RULE 1 — NON-OPERATIONAL
    # ==============================================================

    def _detect_non_operational(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        state = data[
            "state"
        ]

        if state == "unknown":
            return None

        if state == "available":
            return None

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_non_operational"
            ),

            title=(
                "NAT Gateway is not operational"
            ),

            severity="medium",

            confidence="high",

            reason=(
                f"The NAT Gateway is in "
                f"'{state}' state."
            ),

            statements=[
                self._statement(
                    name="state",
                    value=state,
                    path="configuration.state",
                    description=(
                        "Current NAT Gateway state."
                    ),
                    source=[
                        "NAT Gateway configuration"
                    ],
                    observed=True,
                )
            ],

            data=data,

            metadata={
                "state":
                    state,

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 2 — IDLE
    # ==============================================================

    def _detect_idle(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != "available":
            return None

        if not data["activity_complete"]:
            return None

        if not data["traffic_semantics_valid"]:
            return None

        if not data["zero_activity"]:
            return None

        statements = (
            self._zero_activity_statements(
                context
            )
        )

        route_details = data[
            "route_details"
        ]

        route_count = data[
            "route_count"
        ]

        statements.append(
            self._statement(
                name="network_dependencies",
                value={
                    "route_count":
                        route_count,

                    "route_table_ids":
                        route_details.get(
                            "route_table_ids",
                            [],
                        ),

                    "subnet_ids":
                        route_details.get(
                            "subnet_ids",
                            [],
                        ),

                    "availability_zones":
                        route_details.get(
                            "availability_zones",
                            [],
                        ),
                },
                path="topology.route_summary",
                description=(
                    "Routes and dependent network resources "
                    "that still reference this NAT Gateway."
                ),
                source=[
                    "VPC route topology"
                ],
                observed=True,
            )
        )

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_idle"
            ),

            title=(
                "NAT Gateway with no observed activity"
            ),

            severity="medium",

            confidence="high",

            recommendation_eligible=True,

            reason=(
                "All required NAT traffic and connection "
                "metrics were observed and were zero during "
                "the analysis period."
                + (
                    " VPC routes still reference the gateway, "
                    "so dependency validation is required."
                    if (
                        route_count is not None
                        and route_count > 0
                    )
                    else ""
                )
            ),

            statements=statements,

            data=data,

            metadata={
                "traffic_gib":
                    data["traffic_gib"],

                "traffic_available":
                    data["traffic_available"],

                "traffic_complete":
                    data["traffic_complete"],

                "traffic_semantics_valid":
                    data["traffic_semantics_valid"],

                "connection_available":
                    data["connection_available"],

                "connection_complete":
                    data["connection_complete"],

                "activity_complete":
                    data["activity_complete"],

                "zero_activity":
                    data["zero_activity"],

                "route_count":
                    route_count,

                "route_table_ids":
                    route_details.get(
                        "route_table_ids",
                        [],
                    ),

                "dependent_subnet_ids":
                    route_details.get(
                        "subnet_ids",
                        [],
                    ),

                "dependent_availability_zones":
                    route_details.get(
                        "availability_zones",
                        [],
                    ),

                "network_dependency_review_required":
                    (
                        route_count is not None
                        and route_count > 0
                    ),

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 3 — LOW TRAFFIC
    # ==============================================================

    def _detect_low_traffic(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data[
            "traffic_complete"
        ]:
            return None

        if not data[
            "traffic_semantics_valid"
        ]:
            return None

        traffic_gib = data[
            "traffic_gib"
        ]

        if (
            traffic_gib is None
            or traffic_gib <= 0
        ):
            return None

        threshold = _threshold(
            context,
            "low_traffic_gib",
            DEFAULT_LOW_TRAFFIC_GIB,
        )

        if (
            threshold is None
            or traffic_gib >= threshold
        ):
            return None

        route_details = data[
            "route_details"
        ]

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_low_traffic"
            ),

            title=(
                "NAT Gateway with low traffic"
            ),

            severity="low",

            confidence="high",

            reason=(
                f"Complete NAT traffic telemetry shows "
                f"{traffic_gib:.4f} GiB during the analysis "
                f"period, below the configured review "
                f"threshold of {threshold:.4f} GiB."
            ),

            statements=[
                self._statement(
                    name="traffic_gib",
                    value=traffic_gib,
                    path="derived.traffic.activity_total_gib",
                    description=(
                        "Observed NAT activity volume."
                    ),
                    source=[
                        "CloudWatch NAT traffic metrics"
                    ],
                    unit="GiB",
                    observed=True,
                ),

                self._statement(
                    name="threshold_gib",
                    value=threshold,
                    path="",
                    description=(
                        "Configured low-traffic review threshold."
                    ),
                    source=[
                        "Analyzer configuration"
                    ],
                    unit="GiB",
                    observed=True,
                ),

                self._statement(
                    name="network_dependencies",
                    value={
                        "route_count":
                            data["route_count"],

                        "route_table_ids":
                            route_details.get(
                                "route_table_ids",
                                [],
                            ),

                        "subnet_ids":
                            route_details.get(
                                "subnet_ids",
                                [],
                            ),
                    },
                    path="topology.route_summary",
                    description=(
                        "Current network dependencies "
                        "of the NAT Gateway."
                    ),
                    source=[
                        "VPC route topology"
                    ],
                    observed=True,
                ),
            ],

            data=data,

            metadata={
                "traffic_gib":
                    traffic_gib,

                "threshold_gib":
                    threshold,

                "traffic_complete":
                    True,

                "traffic_semantics_valid":
                    True,

                "route_count":
                    data["route_count"],

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 4 — CROSS AZ
    # ==============================================================

    def _detect_cross_az(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data[
            "cross_az"
        ]:
            return None

        # There must be actual observed NAT traffic.
        if data[
            "traffic_observed"
        ] is not True:
            return None

        if not data[
            "traffic_semantics_valid"
        ]:
            return None

        route_details = data[
            "route_details"
        ]

        cross_az_subnet_ids = route_details.get(
            "cross_az_subnet_ids",
            [],
        )

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_cross_az"
            ),

            title=(
                "Cross-AZ NAT routing"
            ),

            severity="medium",

            # IMPORTANT:
            #
            # Current topology proves a cross-AZ dependency.
            # Current NAT traffic proves that the gateway is being used.
            #
            # It does NOT prove that the observed bytes originated
            # from the cross-AZ dependent subnets.
            #
            # Therefore high confidence was too strong.
            confidence="medium",

            reason=(
                "The NAT Gateway is receiving observed traffic "
                "and current route topology shows dependent "
                "subnets in another Availability Zone. "
                "The collected evidence does not prove that "
                "the observed traffic originated from those "
                "cross-AZ subnets."
            ),

            statements=[
                self._statement(
                    name="cross_az_dependency",
                    value={
                        "subnet_count":
                            data[
                                "cross_az_subnet_count"
                            ],

                        "subnet_ids":
                            cross_az_subnet_ids,

                        "availability_zones":
                            route_details.get(
                                "availability_zones",
                                [],
                            ),
                    },
                    path="topology.route_summary",
                    description=(
                        "Dependent subnets located outside "
                        "the NAT Gateway Availability Zone."
                    ),
                    source=[
                        "VPC route topology"
                    ],
                    observed=True,
                ),

                self._statement(
                    name="traffic_gib",
                    value=data[
                        "traffic_gib"
                    ],
                    path="derived.traffic.activity_total_gib",
                    description=(
                        "Observed NAT activity volume."
                    ),
                    source=[
                        "CloudWatch NAT traffic metrics"
                    ],
                    unit="GiB",
                    observed=True,
                ),
            ],

            data=data,

            metadata={
                "cross_az_subnet_count":
                    data[
                        "cross_az_subnet_count"
                    ],

                "cross_az_subnet_ids":
                    cross_az_subnet_ids,

                "traffic_gib":
                    data[
                        "traffic_gib"
                    ],

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 5 — AWS SERVICE TRAFFIC
    # ==============================================================

    def _detect_aws_service_traffic(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data[
            "aws_service_traffic_observed"
        ]:
            return None

        if data[
            "traffic_observed"
        ] is not True:
            return None

        service_traffic = data[
            "aws_service_traffic"
        ]

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_aws_service_traffic"
            ),

            title=(
                "Observed AWS service traffic via NAT"
            ),

            severity="medium",

            confidence="medium",

            reason=(
                "Collector evidence explicitly identifies "
                "observed AWS service traffic traversing this "
                "NAT Gateway."
            ),

            statements=[
                self._statement(
                    name="aws_service_traffic",
                    value=service_traffic,
                    path=(
                        "derived.aws_service_traffic"
                    ),
                    description=(
                        "Explicitly observed AWS service traffic "
                        "associated with this NAT path."
                    ),
                    source=[
                        "Collector-derived service traffic evidence"
                    ],
                    observed=True,
                ),
            ],

            data=data,

            metadata={
                "services":
                    data[
                        "aws_services"
                    ],

                "endpoint_services":
                    data[
                        "endpoint_services"
                    ],

                "traffic_gib":
                    data[
                        "traffic_gib"
                    ],

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 6 — ENDPOINT OPPORTUNITY
    # ==============================================================

    def _detect_endpoint_opportunity(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        candidates = data[
            "candidate_endpoint_services"
        ]

        if not candidates:
            return None

        if not data[
            "aws_service_traffic_observed"
        ]:
            return None

        if data[
            "traffic_observed"
        ] is not True:
            return None

        endpoint_services = data[
            "endpoint_services"
        ]

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_endpoint_opportunity"
            ),

            title=(
                "VPC endpoint opportunity"
            ),

            severity="medium",

            confidence="medium",

            recommendation_eligible=True,

            reason=(
                "Observed AWS service traffic traverses the "
                "NAT Gateway, while no matching VPC endpoint "
                "coverage was collected for the affected "
                "service(s)."
            ),

            statements=[
                self._statement(
                    name="observed_service_traffic",
                    value=data[
                        "aws_service_traffic"
                    ],
                    path=(
                        "derived.aws_service_traffic"
                    ),
                    description=(
                        "Observed AWS service traffic through NAT."
                    ),
                    source=[
                        "Collector-derived service traffic evidence"
                    ],
                    observed=True,
                ),

                self._statement(
                    name="candidate_services",
                    value=candidates,
                    path="derived.aws_service_traffic",
                    description=(
                        "Observed AWS services without matching "
                        "endpoint coverage."
                    ),
                    source=[
                        "Observed service traffic",
                        "VPC endpoint topology",
                    ],
                    observed=True,
                ),

                self._statement(
                    name="existing_endpoint_services",
                    value=endpoint_services,
                    path=(
                        "topology.endpoint_summary.services"
                    ),
                    description=(
                        "Existing VPC endpoint service coverage."
                    ),
                    source=[
                        "VPC endpoint topology"
                    ],
                    observed=True,
                ),
            ],

            data=data,

            metadata={
                "candidate_services":
                    candidates,

                "existing_endpoint_services":
                    endpoint_services,

                "traffic_gib":
                    data[
                        "traffic_gib"
                    ],

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 7 — PACKET DROPS
    # ==============================================================

    def _detect_packet_drops(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        value = data[
            "packet_drops"
        ]

        if value is None or value <= 0:
            return None

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_packet_drops"
            ),

            title=(
                "NAT Gateway packet drops"
            ),

            severity="medium",

            confidence="high",

            reason=(
                f"{value:,.0f} dropped packets were "
                "observed by CloudWatch."
            ),

            statements=[
                self._statement(
                    name="packet_drops",
                    value=value,
                    path=(
                        "metrics.PacketsDropCount.value"
                    ),
                    description=(
                        "Observed NAT Gateway packet drops."
                    ),
                    source=[
                        "CloudWatch.PacketsDropCount"
                    ],
                    unit="Count",
                    observed=True,
                )
            ],

            data=data,

            metadata={
                "packet_drops":
                    value,

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 8 — PORT ALLOCATION
    # ==============================================================

    def _detect_port_allocation_errors(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        value = data[
            "port_allocation_errors"
        ]

        if value is None or value <= 0:
            return None

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_port_allocation_errors"
            ),

            title=(
                "NAT port allocation pressure"
            ),

            severity="medium",

            confidence="high",

            reason=(
                f"{value:,.0f} port allocation errors "
                "were observed."
            ),

            statements=[
                self._statement(
                    name="port_allocation_errors",
                    value=value,
                    path=(
                        "metrics.ErrorPortAllocation.value"
                    ),
                    description=(
                        "Observed NAT port allocation errors."
                    ),
                    source=[
                        "CloudWatch.ErrorPortAllocation"
                    ],
                    unit="Count",
                    observed=True,
                )
            ],

            data=data,

            metadata={
                "port_allocation_errors":
                    value,

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 9 — IDLE TIMEOUTS
    # ==============================================================

    def _detect_idle_timeouts(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        value = data[
            "idle_timeouts"
        ]

        if value is None or value <= 0:
            return None

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_idle_timeouts"
            ),

            title=(
                "NAT idle connection timeouts"
            ),

            severity="low",

            confidence="high",

            reason=(
                f"{value:,.0f} idle connection "
                "timeouts were observed."
            ),

            statements=[
                self._statement(
                    name="idle_timeouts",
                    value=value,
                    path=(
                        "metrics.IdleTimeoutCount.value"
                    ),
                    description=(
                        "Observed NAT idle connection timeouts."
                    ),
                    source=[
                        "CloudWatch.IdleTimeoutCount"
                    ],
                    unit="Count",
                    observed=True,
                )
            ],

            data=data,

            metadata={
                "idle_timeouts":
                    value,

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # RULE 10 — TRAFFIC IMBALANCE
    # ==============================================================

    def _detect_traffic_imbalance(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data[
            "traffic_complete"
        ]:
            return None

        if not data[
            "traffic_semantics_valid"
        ]:
            return None

        values: dict[str, float] = {}

        for name in TRAFFIC_METRICS:

            value = metric_sum_value(
                context.metric(name)
            )

            if value is None:
                return None

            values[name] = float(
                value
            )

        forward = max(
            values[
                "BytesInFromSource"
            ],
            values[
                "BytesOutToDestination"
            ],
        )

        reverse = max(
            values[
                "BytesOutToSource"
            ],
            values[
                "BytesInFromDestination"
            ],
        )

        if (
            forward <= 0
            or reverse <= 0
        ):
            return None

        ratio = (
            max(
                forward,
                reverse,
            )
            /
            min(
                forward,
                reverse,
            )
        )

        threshold = _threshold(
            context,
            "traffic_imbalance_ratio",
            DEFAULT_TRAFFIC_IMBALANCE_RATIO,
        )

        if (
            threshold is None
            or ratio < threshold
        ):
            return None

        return self._finding(
            context=context,

            finding_type=(
                "nat_gateway_traffic_imbalance"
            ),

            title=(
                "NAT traffic imbalance"
            ),

            severity="low",

            confidence="high",

            reason=(
                f"Complete directional traffic telemetry "
                f"shows approximately a {ratio:.1f}× "
                "difference between the dominant and "
                "opposite traffic direction."
            ),

            statements=[
                self._statement(
                    name="forward_bytes",
                    value=forward,
                    path="",
                    description=(
                        "Higher observed traffic direction."
                    ),
                    source=[
                        "CloudWatch NAT traffic metrics"
                    ],
                    unit="Bytes",
                    observed=True,
                ),

                self._statement(
                    name="reverse_bytes",
                    value=reverse,
                    path="",
                    description=(
                        "Lower observed traffic direction."
                    ),
                    source=[
                        "CloudWatch NAT traffic metrics"
                    ],
                    unit="Bytes",
                    observed=True,
                ),

                self._statement(
                    name="imbalance_ratio",
                    value=ratio,
                    path="",
                    description=(
                        "Ratio between dominant and "
                        "opposite traffic directions."
                    ),
                    source=[
                        "Derived from CloudWatch metrics"
                    ],
                    unit="x",
                    observed=True,
                ),
            ],

            data=data,

            metadata={
                "forward_bytes":
                    forward,

                "reverse_bytes":
                    reverse,

                "ratio":
                    round(
                        ratio,
                        2,
                    ),

                "region":
                    context.region,
            },
        )

    # ==============================================================
    # FINDING BUILDER
    # ==============================================================

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
        data: dict[str, Any],
        metadata: dict[str, Any],
        recommendation_eligible: bool = False,
    ) -> Finding:

        limitations = (
            self._limitations(
                finding_type,
                data,
            )
        )

        # ----------------------------------------------------------
        # IMPORTANT:
        #
        # No aggregation_scope.
        # No recommendation scope.
        # No recommendation grouping.
        #
        # Recommendation eligibility is explicit and per-rule.
        # The catalog must not override analyzer eligibility.
        #
        # This object represents only a raw resource finding.
        # ----------------------------------------------------------

        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or "nat_gateway"
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
                data,
            ),

            observation_period=(
                self._observation_period(
                    context
                )
            ),

            limitations=limitations,

            metadata=metadata,

            recommendation_eligible=(
                recommendation_eligible
            ),
        )

    # ==============================================================
    # EVIDENCE
    # ==============================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Evidence:

        return Evidence(
            metrics=data[
                "metrics"
            ],

            configuration=dict(
                data[
                    "configuration"
                ]
            ),

            topology=dict(
                data[
                    "topology"
                ]
            ),

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,
            },

            derived={
                **data[
                    "derived"
                ],

                "analysis": {
                    "traffic_bytes":
                        data[
                            "traffic_bytes"
                        ],

                    "traffic_gib":
                        data[
                            "traffic_gib"
                        ],

                    "traffic_available":
                        data[
                            "traffic_available"
                        ],

                    "traffic_complete":
                        data[
                            "traffic_complete"
                        ],

                    "traffic_semantics_valid":
                        data[
                            "traffic_semantics_valid"
                        ],

                    "traffic_observed":
                        data[
                            "traffic_observed"
                        ],

                    "connection_available":
                        data[
                            "connection_available"
                        ],

                    "connection_complete":
                        data[
                            "connection_complete"
                        ],

                    "activity_available":
                        data[
                            "activity_available"
                        ],

                    "activity_complete":
                        data[
                            "activity_complete"
                        ],

                    "zero_activity":
                        data[
                            "zero_activity"
                        ],

                    "route_count":
                        data[
                            "route_count"
                        ],

                    "route_details":
                        data[
                            "route_details"
                        ],

                    "aws_service_traffic_observed":
                        data[
                            "aws_service_traffic_observed"
                        ],
                },
            },

            data_quality={
                "activity_data_available":
                    data[
                        "activity_available"
                    ],

                "activity_data_complete":
                    data[
                        "activity_complete"
                    ],

                "traffic_available":
                    data[
                        "traffic_available"
                    ],

                "traffic_complete":
                    data[
                        "traffic_complete"
                    ],

                "traffic_semantics_valid":
                    data[
                        "traffic_semantics_valid"
                    ],

                "connection_available":
                    data[
                        "connection_available"
                    ],

                "connection_metric_status":
                    data[
                        "connection_metric_status"
                    ],

                "traffic_metric_status":
                    data[
                        "traffic_metric_status"
                    ],

                "error_metric_status":
                    data[
                        "error_metric_status"
                    ],

                "topology_available":
                    bool(
                        data[
                            "topology"
                        ]
                    ),

                "route_dependency_data_available":
                    bool(
                        data[
                            "route_details"
                        ]
                    ),

                "aws_service_traffic_evidence_available":
                    data[
                        "aws_service_traffic_observed"
                    ],

                "collector_data_quality":
                    context.collector_data_quality(),
            },
        )

    # ==============================================================
    # LIMITATIONS
    # ==============================================================

    @staticmethod
    def _limitations(
        finding_type: str,
        data: dict[str, Any],
    ) -> list[str]:

        limitations: list[str] = []

        if not data[
            "traffic_complete"
        ]:

            limitations.append(
                "Traffic telemetry is incomplete; "
                "traffic-based decisions are therefore "
                "suppressed where complete telemetry is required."
            )

        if not data[
            "traffic_semantics_valid"
        ]:

            limitations.append(
                "One or more NAT traffic metrics do not have "
                "the expected Sum statistic, so byte-volume "
                "analysis is suppressed."
            )

        if not data[
            "connection_complete"
        ]:

            limitations.append(
                "Connection telemetry is incomplete; "
                "an idle NAT Gateway cannot be established "
                "from partial connection metrics."
            )

        if finding_type in {
            "nat_gateway_idle",
            "nat_gateway_low_traffic",
            "nat_gateway_cross_az",
        }:

            limitations.append(
                "The finding describes observed activity "
                "during the analysis window and does not "
                "exclude scheduled, intermittent, or failover traffic."
            )

        if finding_type == (
            "nat_gateway_endpoint_opportunity"
        ):

            limitations.append(
                "Endpoint opportunity requires explicit "
                "observed AWS service traffic; topology alone "
                "is not sufficient to establish a replacement path."
            )

        if finding_type == (
            "nat_gateway_cross_az"
        ):

            limitations.append(
                "Cross-AZ topology does not prove that the "
                "observed NAT traffic originated from the "
                "cross-AZ dependent subnets."
            )

        return limitations

    # ==============================================================
    # ZERO ACTIVITY STATEMENTS
    # ==============================================================

    def _zero_activity_statements(
        self,
        context: AnalysisContext,
    ) -> list[EvidenceStatement]:

        statements: list[
            EvidenceStatement
        ] = []

        for name in ACTIVITY_METRICS:

            metric = context.metric(
                name
            )

            if not metric_has_observed_data(
                metric
            ):
                continue

            value = metric_numeric_value(
                metric
            )

            statements.append(
                self._statement(
                    name=name,

                    value=value,

                    path=(
                        f"metrics.{name}.value"
                    ),

                    description=(
                        f"Observed {name} value from CloudWatch."
                    ),

                    source=[
                        f"CloudWatch.{name}"
                    ],

                    unit=(
                        "Bytes"
                        if name.startswith(
                            "Bytes"
                        )
                        else "Count"
                    ),

                    observed=(
                        value is not None
                    ),
                )
            )

        return statements

    # ==============================================================
    # ACTIVITY HELPERS
    # ==============================================================

    @staticmethod
    def _is_zero_activity(
        context: AnalysisContext,
        activity_complete: bool,
    ) -> bool:

        if not activity_complete:
            return False

        observed_values: list[
            float
        ] = []

        for name in ACTIVITY_METRICS:

            metric = context.metric(
                name
            )

            if not metric_has_observed_data(
                metric
            ):
                return False

            value = metric_numeric_value(
                metric
            )

            if value is None:
                return False

            observed_values.append(
                float(value)
            )

        return all(
            value == 0.0
            for value in observed_values
        )

    @staticmethod
    def _traffic_bytes(
        context: AnalysisContext,
        derived_traffic: dict[str, Any],
        traffic_complete: bool,
    ) -> float | None:

        if not traffic_complete:
            return None

        # The collector defines this as an observed directional
        # activity indicator, not a billing-volume sum.
        indicator = derived_traffic.get(
            "activity_bytes_indicator"
        )

        if isinstance(
            indicator,
            (int, float),
        ):
            return float(indicator)

        # Fallback: use the largest observed directional metric.
        values: list[float] = []

        for name in TRAFFIC_METRICS:

            metric = context.metric(name)

            if not metric_has_observed_data(metric):
                return None

            value = metric_sum_value(metric)

            if value is None:
                return None

            values.append(
                float(value)
            )

        if not values:
            return None

        return max(values)
    @staticmethod
    def _connection_observed(
        context: AnalysisContext,
        derived_connections: dict[str, Any],
        connection_complete: bool,
    ) -> bool | None:

        if not connection_complete:
            return None

        value = derived_connections.get(
            "observed"
        )

        if isinstance(
            value,
            bool,
        ):
            return value

        values: list[
            float
        ] = []

        for name in CONNECTION_METRICS:

            metric = context.metric(
                name
            )

            if not metric_has_observed_data(
                metric
            ):
                return None

            number = metric_numeric_value(
                metric
            )

            if number is None:
                return None

            values.append(
                float(number)
            )

        return any(
            number > 0
            for number in values
        )

    # ==============================================================
    # ERROR METRICS
    # ==============================================================

    @staticmethod
    def _observed_metric_sum(
        context: AnalysisContext,
        name: str,
    ) -> float | None:

        metric = context.metric(
            name
        )

        if not metric_has_observed_data(
            metric
        ):
            return None

        value = metric_sum_value(
            metric
        )

        if value is None:
            return None

        return float(
            value
        )

    # ==============================================================
    # ROUTE DEPENDENCIES
    # ==============================================================

    @classmethod
    def _route_dependency_details(
        cls,
        *,
        topology: dict[str, Any],
        route_summary: dict[str, Any],
    ) -> dict[str, Any]:

        route_count = cls._first_optional_int(
            (
                route_summary.get(
                    "nat_route_count"
                ),
                route_summary.get(
                    "route_count"
                ),
                topology.get(
                    "nat_route_count"
                ),
                topology.get(
                    "route_count"
                ),
            )
        )

        route_table_ids = cls._string_list(
            cls._first_list(
                (
                    route_summary.get(
                        "nat_route_table_ids"
                    ),
                    route_summary.get(
                        "route_table_ids"
                    ),
                    topology.get(
                        "nat_route_table_ids"
                    ),
                )
            )
        )

        subnet_ids = cls._string_list(
            cls._first_list(
                (
                    route_summary.get(
                        "nat_subnet_ids"
                    ),
                    route_summary.get(
                        "dependent_subnet_ids"
                    ),
                    topology.get(
                        "nat_subnet_ids"
                    ),
                    topology.get(
                        "dependent_subnet_ids"
                    ),
                )
            )
        )

        availability_zones = cls._string_list(
            cls._first_list(
                (
                    route_summary.get(
                        "availability_zones"
                    ),
                    route_summary.get(
                        "dependent_availability_zones"
                    ),
                    topology.get(
                        "dependent_availability_zones"
                    ),
                )
            )
        )

        same_az_subnet_count = (
            cls._first_optional_int(
                (
                    route_summary.get(
                        "same_az_subnet_count"
                    ),
                    topology.get(
                        "same_az_subnet_count"
                    ),
                )
            )
        )

        cross_az_subnet_count = (
            cls._first_optional_int(
                (
                    route_summary.get(
                        "cross_az_subnet_count"
                    ),
                    topology.get(
                        "cross_az_subnet_count"
                    ),
                )
            )
        )

        cross_az_subnet_ids = cls._string_list(
            cls._first_list(
                (
                    route_summary.get(
                        "cross_az_subnet_ids"
                    ),
                    route_summary.get(
                        "cross_availability_zone_subnet_ids"
                    ),
                    topology.get(
                        "cross_az_subnet_ids"
                    ),
                )
            )
        )

        same_az_subnet_ids = cls._string_list(
            cls._first_list(
                (
                    route_summary.get(
                        "same_az_subnet_ids"
                    ),
                    topology.get(
                        "same_az_subnet_ids"
                    ),
                )
            )
        )

        routes = cls._first_list(
            (
                route_summary.get(
                    "routes"
                ),
                topology.get(
                    "nat_routes"
                ),
                topology.get(
                    "routes"
                ),
            )
        )

        # ----------------------------------------------------------
        # Raw route fallback
        # ----------------------------------------------------------

        if routes:

            extracted_route_tables: list[str] = []
            extracted_subnets: list[str] = []
            extracted_azs: list[str] = []

            for route in routes:

                if not isinstance(
                    route,
                    dict,
                ):
                    continue

                route_table_id = (
                    route.get(
                        "route_table_id"
                    )
                    or route.get(
                        "route_table"
                    )
                )

                subnet_id = route.get(
                    "subnet_id"
                )

                availability_zone = route.get(
                    "availability_zone"
                )

                if route_table_id:

                    extracted_route_tables.append(
                        str(
                            route_table_id
                        )
                    )

                if subnet_id:

                    extracted_subnets.append(
                        str(
                            subnet_id
                        )
                    )

                if availability_zone:

                    extracted_azs.append(
                        str(
                            availability_zone
                        )
                    )

            if not route_table_ids:

                route_table_ids = cls._unique(
                    extracted_route_tables
                )

            if not subnet_ids:

                subnet_ids = cls._unique(
                    extracted_subnets
                )

            if not availability_zones:

                availability_zones = cls._unique(
                    extracted_azs
                )

            if route_count is None:

                route_count = len(
                    routes
                )

        return {
            "route_count":
                route_count,

            "route_table_ids":
                route_table_ids,

            "subnet_ids":
                subnet_ids,

            "availability_zones":
                availability_zones,

            "same_az_subnet_count":
                same_az_subnet_count,

            "same_az_subnet_ids":
                same_az_subnet_ids,

            "cross_az_subnet_count":
                cross_az_subnet_count,

            "cross_az_subnet_ids":
                cross_az_subnet_ids,

            "routes":
                routes,

            "data_available":
                bool(
                    route_count is not None
                    or route_table_ids
                    or subnet_ids
                    or routes
                ),
        }

    # ==============================================================
    # EXPLICIT AWS SERVICE TRAFFIC
    # ==============================================================

    @staticmethod
    def _aws_service_traffic(
        derived: dict[str, Any],
    ) -> list[dict[str, Any]]:

        value = derived.get(
            "aws_service_traffic"
        )

        result: list[
            dict[str, Any]
        ] = []

        if not isinstance(
            value,
            list,
        ):
            return result

        for item in value:

            if not isinstance(
                item,
                dict,
            ):
                continue

            service = (
                item.get(
                    "service"
                )
                or item.get(
                    "service_name"
                )
            )

            # Explicit observation flag is mandatory.
            if item.get(
                "observed"
            ) is not True:
                continue

            if not service:
                continue

            result.append(
                {
                    **item,

                    "service":
                        str(
                            service
                        ).strip(),

                    "observed":
                        True,
                }
            )

        return result

    # ==============================================================
    # GENERIC HELPERS
    # ==============================================================

    @staticmethod
    def _statement(
        *,
        name: str,
        value: Any,
        path: str,
        description: str,
        source: list[str],
        unit: str | None = None,
        observed: bool | None = None,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=list(source),
            evidence_keys=(
                [path]
                if path
                else []
            ),
            unit=unit,
            observed=observed,
        )

    @staticmethod
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

    @staticmethod
    def _unique(
        values: list[Any],
    ) -> list[str]:

        result: list[str] = []
        seen: set[str] = set()

        for value in values:

            if value is None:
                continue

            text = str(
                value
            ).strip()

            if (
                not text
                or text in seen
            ):
                continue

            seen.add(
                text
            )

            result.append(
                text
            )

        return result

    @classmethod
    def _string_list(
        cls,
        value: Any,
    ) -> list[str]:

        if not isinstance(
            value,
            list,
        ):
            return []

        return cls._unique(
            value
        )

    @staticmethod
    def _first_list(
        values: tuple[Any, ...],
    ) -> list[Any]:

        for value in values:

            if isinstance(
                value,
                list,
            ):
                return value

        return []

    @staticmethod
    def _optional_int(
        value: Any,
    ) -> int | None:

        if value is None:
            return None

        try:

            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

    @classmethod
    def _first_optional_int(
        cls,
        values: tuple[Any, ...],
    ) -> int | None:

        for value in values:

            parsed = cls._optional_int(
                value
            )

            if parsed is not None:
                return parsed

        return None

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        value = context.period()

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