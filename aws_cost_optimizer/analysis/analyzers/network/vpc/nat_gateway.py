"""
AWS NAT Gateway cost optimization analyzer.

Purpose
-------
Generate evidence-based NAT Gateway findings.

Core optimization findings
---------------------------
1. nat_gateway_idle
2. nat_gateway_no_route_dependency
3. nat_gateway_low_traffic
4. nat_gateway_cross_az
5. nat_gateway_endpoint_opportunity
6. nat_gateway_multiple_az

Diagnostic findings
-------------------
7. nat_gateway_blackhole_route_dependency
8. nat_gateway_high_data_processing
9. nat_gateway_port_allocation_pressure
10. nat_gateway_idle_timeout_activity
11. nat_gateway_packet_drop_activity

Important semantics
-------------------
- Missing telemetry is never treated as zero.
- Optional diagnostic metrics do not invalidate core traffic analysis.
- ActiveConnectionCount is the only metric used for current active
  connection state.
- ConnectionAttemptCount is historical/event evidence.
- ConnectionEstablishedCount is historical/event evidence.
- IdleTimeoutCount is diagnostic event evidence.
- ErrorPortAllocation is diagnostic capacity/error evidence.
- PacketsDropCount is diagnostic network evidence.
- Diagnostic counters never make a NAT Gateway active.
- CloudWatch byte counters are operational traffic evidence.
- Traffic volume is NOT treated as an exact billing value.
- NAT service traffic is never inferred from byte counters alone.
- Topology evidence is not the same thing as observed traffic attribution.
- Incomplete topology is never interpreted as no dependency.
- Incomplete dependency evidence is never interpreted as no dependency.
- The analyzer does not calculate savings.
- The analyzer does not automatically delete or consolidate NAT gateways.

Traffic semantics
-----------------
For the directional NAT byte metrics:

    BytesInFromSource
    BytesOutToDestination
    BytesInFromDestination
    BytesOutToSource

the analyzer derives an operational processed-traffic estimate as:

    BytesInFromSource + BytesInFromDestination

This follows the directional meaning of the AWS NAT Gateway metrics and
avoids double-counting the same direction by adding both ingress and
egress counters.

This value is an operational traffic indicator only. It is not treated
as an exact billing-equivalent quantity.

Idle semantics
--------------
A NAT Gateway is considered idle only when:

1. all four core byte metrics are complete,
2. all four core byte metrics are zero,
3. ActiveConnectionCount is complete,
4. maximum ActiveConnectionCount is zero.

Diagnostic counters such as IdleTimeoutCount do not invalidate idle state.

Endpoint-opportunity semantics
-------------------------------
An endpoint opportunity requires BOTH:

1. Explicit evidence that NAT traffic is attributable to one or more
   endpoint-compatible AWS services.
2. Explicit evidence that the relevant endpoint path is absent or
   incomplete.

The following are NOT sufficient by themselves:

- NAT has traffic.
- No endpoint exists.
- A subnet uses a NAT route.
- A service name is guessed from a destination.
- NAT byte metrics alone.

Cross-AZ semantics
------------------
A cross-AZ route dependency is not equivalent to observed cross-AZ
traffic.

A cost-oriented cross-AZ finding therefore requires:

1. complete topology/dependency evidence,
2. explicit cross-AZ route dependency,
3. explicit evidence that traffic is attributed to the cross-AZ path.

If traffic attribution is unavailable, the analyzer does not claim
that cross-AZ traffic was observed.

Multiple-NAT semantics
----------------------
Multiple NAT Gateways in the same AZ are not inherently wasteful.

A finding requires explicit evidence of overlapping dependency/path
coverage.

Regional NAT gateways
---------------------
Regional NAT gateways are intentionally multi-AZ.

Cross-AZ route findings and same-AZ NAT consolidation logic therefore
do not apply to a regional NAT Gateway.
"""

from __future__ import annotations

from typing import Any, Optional

from ....base import Analyzer
from ....condition import EvidenceStatement
from ....context import AnalysisContext
from ....evidence import Evidence
from ....finding import Finding, ObservationPeriod
from ....registry import register

# THRESHOLDS

DEFAULT_LOW_TRAFFIC_GIB = 1.0
DEFAULT_HIGH_TRAFFIC_GIB = 100.0

DEFAULT_PORT_ALLOCATION_ERRORS = 1.0
DEFAULT_IDLE_TIMEOUTS = 1.0
DEFAULT_PACKET_DROPS = 1.0

# AWS documentation uses 0.01% as the packet-drop investigation threshold.
DEFAULT_PACKET_DROP_PERCENT = 0.01


# CORE METRICS

CORE_TRAFFIC_METRICS = (
    "BytesInFromSource",
    "BytesOutToDestination",
    "BytesInFromDestination",
    "BytesOutToSource",
)

CORE_CONNECTION_METRIC = "ActiveConnectionCount"


# PACKET METRICS

PACKET_TRAFFIC_METRICS = (
    "PacketsInFromSource",
    "PacketsInFromDestination",
)


# DIAGNOSTIC METRICS

DIAGNOSTIC_METRICS = (
    "ConnectionAttemptCount",
    "ConnectionEstablishedCount",
    "ErrorPortAllocation",
    "IdleTimeoutCount",
    "PacketsDropCount",
)


# TITLES

TITLES = {
    "nat_gateway_idle": "NAT Gateway is idle",
    "nat_gateway_no_route_dependency": "NAT Gateway has no route dependency",
    "nat_gateway_low_traffic": "NAT Gateway has low observed traffic",
    "nat_gateway_cross_az": "NAT Gateway has cross-AZ traffic exposure",
    "nat_gateway_endpoint_opportunity": (
        "NAT Gateway has an evidence-backed endpoint opportunity"
    ),
    "nat_gateway_multiple_az": (
        "Multiple NAT Gateways have overlapping coverage in the same "
        "Availability Zone"
    ),
    "nat_gateway_blackhole_route_dependency": (
        "NAT Gateway has blackhole route references"
    ),
    "nat_gateway_high_data_processing": "NAT Gateway has high observed traffic",
    "nat_gateway_port_allocation_pressure": (
        "NAT Gateway shows port allocation pressure"
    ),
    "nat_gateway_idle_timeout_activity": ("NAT Gateway shows idle timeout activity"),
    "nat_gateway_packet_drop_activity": ("NAT Gateway shows packet drop activity"),
}


# GENERAL HELPERS


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {"true", "yes", "1"}:
            return True

        if normalized in {"false", "no", "0"}:
            return False

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


# ANALYZER


@register
class NatGatewayAnalyzer(Analyzer):

    name = "nat_gateway"
    version = "9.0"

    SUPPORTED_RESOURCE_TYPES = {
        "nat_gateway",
    }

    # SUPPORT

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return context.resource_type in self.SUPPORTED_RESOURCE_TYPES

    # MAIN ANALYSIS

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        evidence = _dict(context.optimization_evidence())

        if not evidence:
            return []

        resource = self._resource(evidence)

        state_category = str(resource.get("state_category") or "").strip().lower()

        if state_category != "operational":
            return []

        detectors = (
            self._detect_idle,
            self._detect_no_route_dependency,
            self._detect_blackhole_routes,
            self._detect_low_traffic,
            self._detect_cross_az,
            self._detect_endpoint_opportunity,
            self._detect_high_data_processing,
            self._detect_multiple_az,
            self._detect_port_allocation_pressure,
            self._detect_idle_timeout_activity,
            self._detect_packet_drop_activity,
        )

        findings: list[Finding] = []

        for detector in detectors:

            try:
                finding = detector(
                    context,
                    evidence,
                )

            except Exception as exc:

                print(
                    "[ERROR] NAT Gateway detector "
                    f"{detector.__name__} failed for "
                    f"{context.resource_id}: {exc}"
                )

                continue

            if finding is not None:
                findings.append(finding)

        return findings

    # EVIDENCE ACCESS

    @staticmethod
    def _resource(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("resource"))

    @staticmethod
    def _activity(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("activity"))

    @staticmethod
    def _network(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("network"))

    @staticmethod
    def _network_detail(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("topology_detail"))

    @staticmethod
    def _fleet(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("fleet"))

    @staticmethod
    def _configuration(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("configuration"))

    @staticmethod
    def _quality(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("data_quality"))

    @staticmethod
    def _semantics(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("semantics"))

    # METRIC ACCESS

    @staticmethod
    def _metric(
        context: AnalysisContext,
        name: str,
    ) -> dict[str, Any]:

        try:
            value = context.metric_summary(name)
        except Exception:
            return {}

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _metric_has_data(
        metric: dict[str, Any],
    ) -> bool:

        if not isinstance(metric, dict):
            return False

        for key in (
            "has_data",
            "observed",
            "available",
        ):
            if metric.get(key) is True:
                return True

        return False

    @staticmethod
    def _metric_number(
        metric: dict[str, Any],
        *,
        preferred: tuple[str, ...],
    ) -> Optional[float]:

        if not isinstance(metric, dict):
            return None

        for key in preferred:

            value = _number(metric.get(key))

            if value is not None:
                return value

        return None

    @classmethod
    def _metric_sum_value(
        cls,
        metric: dict[str, Any],
    ) -> Optional[float]:

        if not cls._metric_has_data(metric):
            return None

        statistic = cls._metric_statistic(metric)

        if statistic is not None and statistic.lower() != "sum":
            return None

        # IMPORTANT:
        # Do not fall back to "average" for a counter that must use Sum.
        return cls._metric_number(
            metric,
            preferred=(
                "total",
                "sum",
                "value",
            ),
        )

    @classmethod
    def _metric_max_value(
        cls,
        metric: dict[str, Any],
    ) -> Optional[float]:

        if not cls._metric_has_data(metric):
            return None

        statistic = cls._metric_statistic(metric)

        if statistic is not None and statistic.lower() != "maximum":
            return None

        return cls._metric_number(
            metric,
            preferred=(
                "maximum",
                "max",
                "value",
            ),
        )

    @staticmethod
    def _metric_statistic(
        metric: dict[str, Any],
    ) -> Optional[str]:

        if not isinstance(metric, dict):
            return None

        statistic = metric.get("statistic")

        if statistic is None:
            statistic = metric.get("Statistic")

        if statistic is None:
            return None

        return str(statistic).strip()

    # NAT MODE

    @classmethod
    def _availability_mode(
        cls,
        evidence: dict[str, Any],
    ) -> str:

        configuration = cls._configuration(evidence)

        return str(configuration.get("availability_mode") or "").strip().lower()

    @classmethod
    def _is_regional(
        cls,
        evidence: dict[str, Any],
    ) -> bool:

        return cls._availability_mode(evidence) == "regional"

    # CORE TRAFFIC

    @classmethod
    def _core_traffic_metrics(
        cls,
        context: AnalysisContext,
    ) -> dict[str, dict[str, Any]]:

        return {name: cls._metric(context, name) for name in CORE_TRAFFIC_METRICS}

    @classmethod
    def _core_traffic_complete(
        cls,
        context: AnalysisContext,
    ) -> bool:

        metrics = cls._core_traffic_metrics(context)

        for name in CORE_TRAFFIC_METRICS:

            metric = metrics.get(name, {})

            if not cls._metric_has_data(metric):
                return False

            value = cls._metric_sum_value(metric)

            if value is None:
                return False

        return True

    @classmethod
    def _core_traffic_values(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Optional[float]]:

        metrics = cls._core_traffic_metrics(context)

        return {
            name: cls._metric_sum_value(metrics.get(name, {}))
            for name in CORE_TRAFFIC_METRICS
        }

    @classmethod
    def _core_traffic_zero(
        cls,
        context: AnalysisContext,
    ) -> Optional[bool]:

        if not cls._core_traffic_complete(context):
            return None

        values = cls._core_traffic_values(context)

        if any(value is None for value in values.values()):
            return None

        return all(value == 0 for value in values.values())

    @classmethod
    def _core_traffic_positive(
        cls,
        context: AnalysisContext,
    ) -> Optional[bool]:

        if not cls._core_traffic_complete(context):
            return None

        values = cls._core_traffic_values(context)

        if any(value is None for value in values.values()):
            return None

        return any(value > 0 for value in values.values())

    @classmethod
    def _core_traffic_processed_bytes(
        cls,
        context: AnalysisContext,
    ) -> Optional[float]:
        """
        Operational estimate of bytes processed through the NAT Gateway.

        We use:

            BytesInFromSource + BytesInFromDestination

        rather than summing all four directional counters, because the
        corresponding outbound counters represent the other side of the
        same directional flows.

        This is NOT a billing calculation.
        """

        if not cls._core_traffic_complete(context):
            return None

        values = cls._core_traffic_values(context)

        source_bytes = values.get("BytesInFromSource")

        destination_bytes = values.get("BytesInFromDestination")

        if source_bytes is None or destination_bytes is None:
            return None

        return source_bytes + destination_bytes

    @classmethod
    def _core_traffic_gib(
        cls,
        context: AnalysisContext,
    ) -> Optional[float]:

        processed_bytes = cls._core_traffic_processed_bytes(context)

        if processed_bytes is None:
            return None

        return processed_bytes / (1024.0**3)

    # ACTIVE CONNECTION STATE

    @classmethod
    def _active_connections_complete(
        cls,
        context: AnalysisContext,
    ) -> bool:

        metric = cls._metric(
            context,
            CORE_CONNECTION_METRIC,
        )

        if not cls._metric_has_data(metric):
            return False

        if cls._metric_max_value(metric) is None:
            return False

        return True

    @classmethod
    def _active_connections_value(
        cls,
        context: AnalysisContext,
    ) -> Optional[float]:

        if not cls._active_connections_complete(context):
            return None

        return cls._metric_max_value(
            cls._metric(
                context,
                CORE_CONNECTION_METRIC,
            )
        )

    # DIAGNOSTIC METRICS

    @classmethod
    def _diagnostic_metric_value(
        cls,
        context: AnalysisContext,
        metric_name: str,
    ) -> Optional[float]:

        metric = cls._metric(
            context,
            metric_name,
        )

        if not cls._metric_has_data(metric):
            return None

        value = cls._metric_sum_value(metric)

        if value is None:
            return None

        return value

    @classmethod
    def _diagnostic_activity(
        cls,
        context: AnalysisContext,
    ) -> Optional[bool]:

        values = [
            cls._diagnostic_metric_value(
                context,
                metric_name,
            )
            for metric_name in DIAGNOSTIC_METRICS
        ]

        observed = [value for value in values if value is not None]

        if not observed:
            return None

        return any(value > 0 for value in observed)

    # PACKET METRICS

    @classmethod
    def _packet_traffic_values(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Optional[float]]:

        return {
            name: cls._metric_sum_value(cls._metric(context, name))
            for name in PACKET_TRAFFIC_METRICS
        }

    @classmethod
    def _packet_traffic_complete(
        cls,
        context: AnalysisContext,
    ) -> bool:

        values = cls._packet_traffic_values(context)

        return all(value is not None for value in values.values())

    @classmethod
    def _packet_drop_percentage(
        cls,
        context: AnalysisContext,
    ) -> Optional[float]:

        packet_values = cls._packet_traffic_values(context)

        dropped = cls._diagnostic_metric_value(
            context,
            "PacketsDropCount",
        )

        if dropped is None:
            return None

        packets_in = [value for value in packet_values.values() if value is not None]

        if len(packets_in) != len(PACKET_TRAFFIC_METRICS):
            return None

        total_packets = sum(packets_in)

        if total_packets <= 0:
            return None

        return dropped / total_packets * 100.0

    # DATA QUALITY

    @classmethod
    def _topology_complete(
        cls,
        evidence: dict[str, Any],
    ) -> bool:

        return cls._quality(evidence).get("topology_complete") is True

    @classmethod
    def _dependency_complete(
        cls,
        evidence: dict[str, Any],
    ) -> bool:

        return cls._quality(evidence).get("dependency_evidence_complete") is True

    # IDLE

    def _detect_idle(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if not self._core_traffic_complete(context):
            return None

        if not self._active_connections_complete(context):
            return None

        if self._core_traffic_zero(context) is not True:
            return None

        active_connections = self._active_connections_value(context)

        if active_connections != 0:
            return None

        network = self._network(evidence)

        route_count = _number(network.get("nat_route_count"))

        dependency_complete = self._dependency_complete(evidence)

        timeout_value = self._diagnostic_metric_value(
            context,
            "IdleTimeoutCount",
        )

        timeout_activity = timeout_value is not None and timeout_value > 0

        if route_count == 0 and dependency_complete:
            severity = "high"
            confidence = "high"

        else:
            severity = "medium"
            confidence = "high"

        reason = (
            "No core NAT traffic and no active NAT connections "
            "were observed during the complete observation period."
        )

        if route_count == 0 and dependency_complete:

            reason += (
                " Complete dependency evidence also shows no "
                "effective route targeting this NAT Gateway."
            )

        elif route_count is not None and route_count > 0:

            reason += (
                f" However, {route_count:g} route reference(s) "
                "still target the NAT Gateway and should be "
                "reviewed before removal."
            )

        else:

            reason += (
                " Route dependency evidence is not complete, "
                "so removal cannot be inferred from traffic alone."
            )

        if timeout_activity:

            reason += (
                " Idle timeout events were observed, but those "
                "historical diagnostic events do not establish "
                "current activity."
            )

        statements = [
            _statement(
                name="core_traffic_zero",
                value=True,
                description=("All four core NAT byte metrics reported zero."),
                source=["CloudWatch"],
            ),
            _statement(
                name="active_connections",
                value=0,
                description=("Maximum observed ActiveConnectionCount " "was zero."),
                source=["CloudWatch.ActiveConnectionCount"],
                unit="count",
            ),
        ]

        if route_count is not None:

            statements.append(
                _statement(
                    name="nat_route_count",
                    value=route_count,
                    description=(
                        "Discovered effective route references " "to this NAT Gateway."
                    ),
                    source=["VPC Topology"],
                    unit="routes",
                )
            )

        if timeout_activity:

            statements.append(
                _statement(
                    name="idle_timeout_count",
                    value=timeout_value,
                    description=(
                        "Historical idle-timeout events. These "
                        "do not define current active state."
                    ),
                    source=["CloudWatch.IdleTimeoutCount"],
                    unit="events",
                )
            )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_idle",
            severity=severity,
            confidence=confidence,
            reason=reason,
            statements=statements,
            metadata={
                "category": "unused_resource",
                "core_traffic_zero": True,
                "active_connections": 0,
                "nat_route_count": route_count,
                "dependency_evidence_complete": (dependency_complete),
                "diagnostic_timeout_activity": (timeout_activity),
                "diagnostics_do_not_define_activity": True,
            },
            recommendation_eligible=True,
            cost_optimization_type="elimination",
        )

    # NO ROUTE DEPENDENCY

    def _detect_no_route_dependency(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if not self._topology_complete(evidence):
            return None

        if not self._dependency_complete(evidence):
            return None

        network = self._network(evidence)

        route_count = _number(network.get("nat_route_count"))

        if route_count is None or route_count != 0:
            return None

        subnet_count = _number(network.get("route_dependent_subnet_count"))

        route_table_count = _number(network.get("route_dependent_route_table_count"))

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type=("nat_gateway_no_route_dependency"),
            severity="high",
            confidence="high",
            reason=(
                "Complete VPC topology and dependency evidence "
                "show that no effective route currently targets "
                "this NAT Gateway."
            ),
            statements=[
                _statement(
                    name="nat_route_count",
                    value=0,
                    description=("Effective routes targeting this " "NAT Gateway."),
                    source=["VPC Topology"],
                    unit="routes",
                ),
                _statement(
                    name="dependent_subnets",
                    value=(subnet_count if subnet_count is not None else 0),
                    description=(
                        "Subnets whose effective routes depend " "on this NAT Gateway."
                    ),
                    source=["VPC Topology"],
                    unit="subnets",
                ),
                _statement(
                    name="dependent_route_tables",
                    value=(route_table_count if route_table_count is not None else 0),
                    description=(
                        "Route tables containing effective "
                        "routes to this NAT Gateway."
                    ),
                    source=["VPC Topology"],
                    unit="route tables",
                ),
            ],
            metadata={
                "category": "unused_resource",
                "nat_route_count": 0,
                "route_dependent_subnet_count": (
                    subnet_count if subnet_count is not None else 0
                ),
                "route_dependent_route_table_count": (
                    route_table_count if route_table_count is not None else 0
                ),
                "topology_complete": True,
                "dependency_evidence_complete": True,
            },
            recommendation_eligible=True,
            cost_optimization_type="elimination",
        )

    # BLACKHOLE ROUTES

    def _detect_blackhole_routes(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if not self._topology_complete(evidence):
            return None

        if not self._dependency_complete(evidence):
            return None

        network = self._network(evidence)

        blackhole_count = _number(network.get("blackhole_nat_route_count"))

        if blackhole_count is None or blackhole_count <= 0:
            return None

        detail = self._network_detail(evidence)

        blackhole_routes = _list(detail.get("blackhole_nat_routes"))

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type=("nat_gateway_blackhole_route_dependency"),
            severity="low",
            confidence="high",
            reason=(
                f"{blackhole_count:g} route(s) reference this "
                "NAT Gateway with blackhole state. These are "
                "stale route references and should be reviewed."
            ),
            statements=[
                _statement(
                    name="blackhole_route_count",
                    value=blackhole_count,
                    description=(
                        "Routes targeting this NAT Gateway "
                        "that are in blackhole state."
                    ),
                    source=["VPC Topology"],
                    unit="routes",
                ),
                _statement(
                    name="blackhole_routes",
                    value=blackhole_routes,
                    description=("Collected blackhole route evidence."),
                    source=["VPC Topology"],
                ),
            ],
            metadata={
                "category": "network_cleanup",
                "blackhole_route_count": blackhole_count,
                "blackhole_routes": blackhole_routes,
            },
            recommendation_eligible=False,
            cost_optimization_type="review",
        )

    # LOW TRAFFIC

    def _detect_low_traffic(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if not self._core_traffic_complete(context):
            return None

        traffic_gib = self._core_traffic_gib(context)

        if traffic_gib is None or traffic_gib <= 0:
            return None

        threshold = self._threshold(
            context,
            "low_traffic_gib",
            DEFAULT_LOW_TRAFFIC_GIB,
        )

        if traffic_gib > threshold:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_low_traffic",
            severity="low",
            confidence="medium",
            reason=(
                f"Observed NAT traffic was approximately "
                f"{traffic_gib:.3f} GiB during the complete "
                f"observation period, below the "
                f"{threshold:.3f} GiB review threshold. "
                "This is an operational traffic estimate and "
                "does not represent a billing amount."
            ),
            statements=[
                _statement(
                    name="observed_traffic_gib",
                    value=round(
                        traffic_gib,
                        3,
                    ),
                    description=(
                        "Operational NAT processed-traffic "
                        "estimate derived from CloudWatch "
                        "directional byte metrics."
                    ),
                    source=["CloudWatch"],
                    unit="GiB",
                ),
                _statement(
                    name="traffic_calculation",
                    value=("BytesInFromSource + " "BytesInFromDestination"),
                    description=(
                        "Directional byte metrics used for the "
                        "operational traffic estimate."
                    ),
                    source=["AWS/NATGateway"],
                ),
                _statement(
                    name="threshold_gib",
                    value=threshold,
                    description=("Configured low-traffic review threshold."),
                    source=["Analysis profile"],
                    unit="GiB",
                ),
            ],
            metadata={
                "category": "traffic_optimization",
                "directional_traffic_gib": traffic_gib,
                "threshold_gib": threshold,
                "billing_equivalent": False,
            },
            recommendation_eligible=True,
            cost_optimization_type="review",
        )

    # CROSS-AZ

    @staticmethod
    def _cross_az_traffic_attributed(
        network: dict[str, Any],
    ) -> bool:

        candidates = (
            network.get("cross_az_traffic_attributed"),
            network.get("cross_az_traffic_observed"),
            network.get("cross_az_bytes_attributed"),
        )

        for value in candidates:

            if _bool(value) is True:
                return True

        return False

    def _detect_cross_az(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if self._is_regional(evidence):
            return None

        if not self._topology_complete(evidence):
            return None

        if not self._dependency_complete(evidence):
            return None

        network = self._network(evidence)

        if network.get("has_cross_az_route_dependency") is not True:
            return None

        cross_az_count = _number(network.get("cross_az_subnet_count"))

        if cross_az_count is None or cross_az_count <= 0:
            return None

        # IMPORTANT:
        #
        # A cross-AZ route alone does not prove traffic used the
        # cross-AZ path. Require explicit traffic attribution.
        if not self._cross_az_traffic_attributed(network):
            return None

        traffic_gib = self._core_traffic_gib(context)

        if traffic_gib is None or traffic_gib <= 0:
            return None

        configuration = self._configuration(evidence)

        same_az_count = _number(network.get("same_az_subnet_count"))

        if same_az_count is None:
            same_az_count = 0.0

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="nat_gateway_cross_az",
            severity="medium",
            confidence="high",
            reason=(
                f"{cross_az_count:g} dependent subnet(s) are "
                "in a different Availability Zone from this "
                "zonal NAT Gateway, and explicit evidence "
                "attributes observed traffic to the cross-AZ "
                "path. This indicates cross-AZ traffic exposure; "
                "the analyzer does not estimate cross-AZ bytes "
                "or savings."
            ),
            statements=[
                _statement(
                    name="cross_az_subnets",
                    value=cross_az_count,
                    description=(
                        "Dependent subnets in an AZ different " "from the NAT Gateway."
                    ),
                    source=["VPC Topology"],
                    unit="subnets",
                ),
                _statement(
                    name="same_az_subnets",
                    value=same_az_count,
                    description=(
                        "Dependent subnets in the NAT Gateway's " "Availability Zone."
                    ),
                    source=["VPC Topology"],
                    unit="subnets",
                ),
                _statement(
                    name="cross_az_traffic_attributed",
                    value=True,
                    description=(
                        "Explicit evidence attributes observed "
                        "traffic to the cross-AZ dependency path."
                    ),
                    source=["Network traffic attribution"],
                ),
                _statement(
                    name="nat_availability_zone",
                    value=configuration.get("availability_zone"),
                    description=(
                        "Availability Zone associated with " "the zonal NAT Gateway."
                    ),
                    source=["NAT configuration"],
                ),
                _statement(
                    name="observed_traffic_gib",
                    value=round(
                        traffic_gib,
                        3,
                    ),
                    description=(
                        "Observed NAT processed-traffic estimate. "
                        "It does not measure cross-AZ bytes."
                    ),
                    source=["CloudWatch"],
                    unit="GiB",
                ),
            ],
            metadata={
                "category": "network_optimization",
                "cross_az_subnet_count": cross_az_count,
                "same_az_subnet_count": same_az_count,
                "nat_availability_zone": (configuration.get("availability_zone")),
                "observed_traffic_gib": traffic_gib,
                "cross_az_traffic_attributed": True,
                "cross_az_bytes_measured": False,
                "zonal_nat_gateway": True,
            },
            recommendation_eligible=True,
            cost_optimization_type="architecture",
        )

    # ENDPOINT OPPORTUNITY

    @staticmethod
    def _endpoint_opportunity_data(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        network = _dict(evidence.get("network"))

        return _dict(network.get("endpoint_opportunity"))

    @staticmethod
    def _endpoint_candidate_services(
        endpoint_data: dict[str, Any],
    ) -> list[Any]:

        services = endpoint_data.get("candidate_services")

        if not isinstance(services, list):
            services = endpoint_data.get("services")

        if not isinstance(services, list):
            return []

        return services

    @staticmethod
    def _endpoint_traffic_attributed(
        endpoint_data: dict[str, Any],
    ) -> bool:

        for key in (
            "traffic_attribution_available",
            "service_traffic_attributed",
        ):

            if _bool(endpoint_data.get(key)) is True:
                return True

        return False

    @staticmethod
    def _endpoint_path_incomplete(
        endpoint_data: dict[str, Any],
    ) -> bool:

        # Explicit collector evidence is preferred.
        for key in (
            "endpoint_path_missing",
            "endpoint_path_incomplete",
            "endpoint_required_but_absent",
            "relevant_endpoint_missing",
        ):

            value = _bool(endpoint_data.get(key))

            if value is True:
                return True

        endpoint_count = _number(endpoint_data.get("relevant_endpoint_count"))

        if endpoint_count is not None:
            return endpoint_count <= 0

        return False

    def _detect_endpoint_opportunity(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if not self._topology_complete(evidence):
            return None

        if not self._dependency_complete(evidence):
            return None

        endpoint_data = self._endpoint_opportunity_data(evidence)

        if not endpoint_data:
            return None

        if _bool(endpoint_data.get("evidence_complete")) is not True:
            return None

        if not self._endpoint_traffic_attributed(endpoint_data):
            return None

        candidate_services = self._endpoint_candidate_services(endpoint_data)

        if not candidate_services:
            return None

        compatible_path_count = _number(endpoint_data.get("compatible_path_count"))

        if compatible_path_count is None or compatible_path_count <= 0:
            return None

        # Explicit absence/incompleteness is mandatory.
        if not self._endpoint_path_incomplete(endpoint_data):
            return None

        traffic_gib = self._core_traffic_gib(context)

        if traffic_gib is None or traffic_gib <= 0:
            return None

        endpoint_count = _number(endpoint_data.get("relevant_endpoint_count"))

        if endpoint_count is None:
            endpoint_count = _number(
                self._network(evidence).get("relevant_endpoint_count")
            )

        if endpoint_count is None:
            endpoint_count = 0.0

        services = []

        for item in candidate_services:

            if isinstance(item, dict):
                services.append(item)

            else:
                services.append({"service": str(item)})

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type=("nat_gateway_endpoint_opportunity"),
            severity="medium",
            confidence="high",
            reason=(
                "Complete topology, dependency, and explicit "
                "service-attribution evidence identify NAT traffic "
                "associated with endpoint-compatible AWS services. "
                f"{compatible_path_count:g} compatible network "
                "path(s) were identified, and explicit evidence "
                "shows that the relevant endpoint path is absent "
                "or incomplete. Endpoint replacement must still "
                "be validated against application requirements "
                "and endpoint routing behavior."
            ),
            statements=[
                _statement(
                    name="candidate_services",
                    value=services,
                    description=(
                        "AWS services explicitly attributed to "
                        "NAT-dependent traffic and identified as "
                        "endpoint-compatible."
                    ),
                    source=[
                        "Service traffic evidence",
                        "VPC Topology",
                    ],
                ),
                _statement(
                    name="compatible_path_count",
                    value=compatible_path_count,
                    description=(
                        "Network paths for which endpoint-compatible "
                        "traffic evidence was established."
                    ),
                    source=[
                        "VPC Topology",
                        "Endpoint analysis",
                    ],
                    unit="paths",
                ),
                _statement(
                    name="relevant_endpoint_count",
                    value=endpoint_count,
                    description=(
                        "Relevant VPC endpoints currently "
                        "covering the analyzed paths."
                    ),
                    source=["VPC Topology"],
                    unit="endpoints",
                ),
                _statement(
                    name="endpoint_path_incomplete",
                    value=True,
                    description=(
                        "Explicit evidence shows that the relevant "
                        "endpoint path is absent or incomplete."
                    ),
                    source=[
                        "Endpoint analysis",
                        "VPC Topology",
                    ],
                ),
                _statement(
                    name="observed_traffic_gib",
                    value=round(
                        traffic_gib,
                        3,
                    ),
                    description=(
                        "Operational NAT traffic estimate. "
                        "It is not used to infer AWS service identity."
                    ),
                    source=["CloudWatch"],
                    unit="GiB",
                ),
                _statement(
                    name="traffic_attribution_available",
                    value=True,
                    description=(
                        "Explicit service-level traffic attribution "
                        "was supplied by the collector/evidence layer."
                    ),
                    source=["Service traffic evidence"],
                ),
            ],
            metadata={
                "category": "network_optimization",
                "candidate_services": services,
                "compatible_path_count": (compatible_path_count),
                "relevant_endpoint_count": (endpoint_count),
                "observed_traffic_gib": traffic_gib,
                "traffic_attribution_available": True,
                "endpoint_evidence_complete": True,
                "endpoint_path_incomplete": True,
                "service_attribution_from_bytes_alone": False,
                "requires_validation": True,
            },
            recommendation_eligible=True,
            cost_optimization_type="architecture",
        )

    # HIGH DATA PROCESSING

    def _detect_high_data_processing(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if not self._core_traffic_complete(context):
            return None

        traffic_gib = self._core_traffic_gib(context)

        if traffic_gib is None:
            return None

        threshold = self._threshold(
            context,
            "high_traffic_gib",
            DEFAULT_HIGH_TRAFFIC_GIB,
        )

        if traffic_gib <= threshold:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type=("nat_gateway_high_data_processing"),
            severity="medium",
            confidence="medium",
            reason=(
                f"Observed NAT traffic was approximately "
                f"{traffic_gib:.3f} GiB during the complete "
                f"observation period, above the "
                f"{threshold:.3f} GiB review threshold. "
                "This identifies substantial NAT traffic exposure "
                "but does not calculate a billing amount or savings."
            ),
            statements=[
                _statement(
                    name="observed_traffic_gib",
                    value=round(
                        traffic_gib,
                        3,
                    ),
                    description=("Operational NAT processed-traffic estimate."),
                    source=["CloudWatch"],
                    unit="GiB",
                ),
                _statement(
                    name="threshold_gib",
                    value=threshold,
                    description=("Configured high-traffic review threshold."),
                    source=["Analysis profile"],
                    unit="GiB",
                ),
                _statement(
                    name="billing_equivalent",
                    value=False,
                    description=(
                        "The observed traffic value is not treated "
                        "as an exact billing quantity."
                    ),
                    source=["Analyzer semantics"],
                ),
            ],
            metadata={
                "category": "traffic_review",
                "directional_traffic_gib": traffic_gib,
                "threshold_gib": threshold,
                "billing_equivalent": False,
            },
            recommendation_eligible=False,
            cost_optimization_type="review",
        )

    # MULTIPLE NAT GATEWAYS IN SAME AZ

    def _detect_multiple_az(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        if self._is_regional(evidence):
            return None

        if not self._topology_complete(evidence):
            return None

        if not self._dependency_complete(evidence):
            return None

        fleet = self._fleet(evidence)

        if fleet.get("has_multiple_nats_in_same_az") is not True:
            return None

        overlap_flag = _bool(fleet.get("same_az_dependency_overlap"))

        overlap_count = _number(fleet.get("same_az_route_overlap_count"))

        shared_subnet_count = _number(fleet.get("same_az_shared_subnet_count"))

        explicit_overlap = (
            overlap_flag is True
            or (overlap_count is not None and overlap_count > 0)
            or (shared_subnet_count is not None and shared_subnet_count > 0)
        )

        if not explicit_overlap:
            return None

        same_az_ids = _list(fleet.get("same_az_alternative_nat_ids"))

        if not same_az_ids:
            return None

        current_az = fleet.get("current_nat_availability_zone")

        total_same_az = len(same_az_ids) + 1

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type=("nat_gateway_multiple_az"),
            severity="medium",
            confidence="high",
            reason=(
                f"{total_same_az} operational NAT Gateway(s) "
                f"were discovered in Availability Zone "
                f"{current_az or 'unknown'}, with explicit "
                "overlapping dependency evidence. This may "
                "represent redundant routing coverage and "
                "requires architecture validation before "
                "any consolidation."
            ),
            statements=[
                _statement(
                    name="same_az_nat_count",
                    value=total_same_az,
                    description=(
                        "Operational NAT gateways in the " "same Availability Zone."
                    ),
                    source=[
                        "NAT Gateway inventory",
                        "VPC Topology",
                    ],
                    unit="gateways",
                ),
                _statement(
                    name="same_az_alternatives",
                    value=same_az_ids,
                    description=(
                        "Other operational NAT Gateway IDs "
                        "in the same Availability Zone."
                    ),
                    source=["NAT Gateway inventory"],
                ),
                _statement(
                    name="same_az_route_overlap_count",
                    value=overlap_count,
                    description=(
                        "Explicitly observed overlapping route "
                        "coverage between NAT gateways."
                    ),
                    source=["VPC Topology"],
                    unit="routes",
                ),
                _statement(
                    name="same_az_shared_subnet_count",
                    value=shared_subnet_count,
                    description=(
                        "Dependent subnets with overlapping " "same-AZ NAT coverage."
                    ),
                    source=["VPC Topology"],
                    unit="subnets",
                ),
            ],
            metadata={
                "category": "network_optimization",
                "availability_zone": current_az,
                "same_az_alternative_nat_ids": (same_az_ids),
                "same_az_nat_count": total_same_az,
                "same_az_dependency_overlap": True,
                "same_az_route_overlap_count": (overlap_count),
                "same_az_shared_subnet_count": (shared_subnet_count),
                "same_vpc_nat_count": fleet.get("nat_gateway_count"),
                "operational_nat_count": fleet.get("operational_nat_gateway_count"),
            },
            recommendation_eligible=True,
            cost_optimization_type="architecture",
        )

    # PORT ALLOCATION PRESSURE

    def _detect_port_allocation_pressure(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        value = self._diagnostic_metric_value(
            context,
            "ErrorPortAllocation",
        )

        if value is None:
            return None

        threshold = self._threshold(
            context,
            "port_allocation_errors",
            DEFAULT_PORT_ALLOCATION_ERRORS,
        )

        if value < threshold:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type=("nat_gateway_port_allocation_pressure"),
            severity="medium",
            confidence="high",
            reason=(
                f"NAT Gateway port allocation errors were "
                f"observed ({value:.0f}), reaching the "
                f"configured threshold of {threshold:.0f}. "
                "This is a capacity diagnostic and does not "
                "establish current active connections."
            ),
            statements=[
                _statement(
                    name="error_port_allocation",
                    value=value,
                    description=("Observed NAT Gateway port allocation " "errors."),
                    source=["CloudWatch.ErrorPortAllocation"],
                    unit="events",
                ),
            ],
            metadata={
                "category": "capacity_review",
                "error_port_allocation": value,
                "threshold": threshold,
                "diagnostic_only": True,
                "does_not_define_active_state": True,
            },
            recommendation_eligible=False,
            cost_optimization_type="review",
        )

    # IDLE TIMEOUT

    def _detect_idle_timeout_activity(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        value = self._diagnostic_metric_value(
            context,
            "IdleTimeoutCount",
        )

        if value is None:
            return None

        threshold = self._threshold(
            context,
            "idle_timeouts",
            DEFAULT_IDLE_TIMEOUTS,
        )

        if value < threshold:
            return None

        active_connections = self._active_connections_value(context)

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type=("nat_gateway_idle_timeout_activity"),
            severity="low",
            confidence="medium",
            reason=(
                f"NAT Gateway idle-timeout activity was "
                f"observed ({value:.0f}). This is historical "
                "diagnostic activity and does not mean that "
                "the gateway currently has active connections."
            ),
            statements=[
                _statement(
                    name="idle_timeouts",
                    value=value,
                    description=("Observed NAT Gateway idle-timeout events."),
                    source=["CloudWatch.IdleTimeoutCount"],
                    unit="events",
                ),
                _statement(
                    name="active_connections",
                    value=active_connections,
                    description=(
                        "Maximum observed active connection "
                        "state, evaluated separately."
                    ),
                    source=["CloudWatch.ActiveConnectionCount"],
                    unit="count",
                ),
            ],
            metadata={
                "category": "connection_review",
                "idle_timeouts": value,
                "threshold": threshold,
                "diagnostic_only": True,
                "does_not_indicate_active_connections": True,
                "active_connections": active_connections,
            },
            recommendation_eligible=False,
            cost_optimization_type="review",
        )

    # PACKET DROP

    def _detect_packet_drop_activity(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        value = self._diagnostic_metric_value(
            context,
            "PacketsDropCount",
        )

        if value is None:
            return None

        threshold = self._threshold(
            context,
            "packet_drops",
            DEFAULT_PACKET_DROPS,
        )

        if value < threshold:
            return None

        drop_percentage = self._packet_drop_percentage(context)

        percentage_threshold = self._threshold(
            context,
            "packet_drop_percent",
            DEFAULT_PACKET_DROP_PERCENT,
        )

        if drop_percentage is not None and drop_percentage <= percentage_threshold:

            severity = "low"

            reason = (
                f"{value:.0f} dropped packet(s) were observed, "
                f"but the calculated packet-drop ratio was "
                f"{drop_percentage:.5f}%, which is at or below "
                "the configured investigation threshold."
            )

        elif drop_percentage is not None:

            severity = "medium"

            reason = (
                f"{value:.0f} dropped packet(s) were observed. "
                f"The calculated packet-drop ratio was "
                f"{drop_percentage:.5f}%, exceeding the "
                "configured investigation threshold."
            )

        else:

            severity = "low"

            reason = (
                f"{value:.0f} dropped packet(s) were observed. "
                "Packet-drop percentage could not be calculated "
                "because the required packet-input telemetry "
                "was incomplete."
            )

        statements = [
            _statement(
                name="packets_dropped",
                value=value,
                description=("Observed NAT Gateway packet-drop activity."),
                source=["CloudWatch.PacketsDropCount"],
                unit="packets",
            )
        ]

        if drop_percentage is not None:

            statements.append(
                _statement(
                    name="packet_drop_percentage",
                    value=round(
                        drop_percentage,
                        6,
                    ),
                    description=(
                        "Dropped packets as a percentage of "
                        "PacketsInFromSource plus "
                        "PacketsInFromDestination."
                    ),
                    source=["CloudWatch NAT packet metrics"],
                    unit="percent",
                )
            )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type=("nat_gateway_packet_drop_activity"),
            severity=severity,
            confidence=("high" if drop_percentage is not None else "medium"),
            reason=reason,
            statements=statements,
            metadata={
                "category": "network_capacity_review",
                "packets_dropped": value,
                "threshold": threshold,
                "packet_drop_percentage": (drop_percentage),
                "packet_drop_percentage_threshold": (percentage_threshold),
                "diagnostic_only": True,
                "does_not_define_active_state": True,
            },
            recommendation_eligible=False,
            cost_optimization_type="review",
        )

    # THRESHOLDS

    @staticmethod
    def _threshold(
        context: AnalysisContext,
        name: str,
        default: float,
    ) -> float:

        candidates = (
            context.resource.get("analysis_profile"),
            context.resource.get("optimization_profile"),
            context.resource.get("analyzer_config"),
        )

        for candidate in candidates:

            if not isinstance(
                candidate,
                dict,
            ):
                continue

            value = _number(candidate.get(name))

            if value is not None and value >= 0:
                return value

        return default

    # FINDING BUILDER

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
        metadata: dict[str, Any],
        recommendation_eligible: bool,
        cost_optimization_type: str = "review",
    ) -> Finding:

        final_metadata = {
            "region": context.region,
            **metadata,
        }

        return Finding(
            finding_type=finding_type,
            title=TITLES.get(
                finding_type,
                finding_type,
            ),
            resource_type=(context.resource_type or "nat_gateway"),
            resource_id=(context.resource_id or "unknown"),
            analyzer=self.name,
            analyzer_version=self.version,
            severity=str(severity).lower(),
            confidence=str(confidence).lower(),
            reason=reason,
            conditions=statements,
            evidence=self._build_evidence(
                context,
                evidence,
            ),
            observation_period=(self._observation_period(context)),
            metadata=final_metadata,
            recommendation_eligible=(recommendation_eligible),
            cost_optimization_type=(cost_optimization_type),
            impact={},
        )

    # STRUCTURED EVIDENCE

    def _build_evidence(
        self,
        context: AnalysisContext,
        optimization_evidence: dict[str, Any],
    ) -> Evidence:

        metrics_source = context.metrics()

        metrics: dict[str, Any] = {}

        if isinstance(
            metrics_source,
            dict,
        ):

            for name in metrics_source:

                try:
                    metrics[name] = context.metric_summary(name)

                except Exception:
                    metrics[name] = metrics_source.get(name)

        configuration = _dict(context.configuration())

        activity = self._activity(optimization_evidence)

        core_traffic = {
            name: self._metric(
                context,
                name,
            )
            for name in CORE_TRAFFIC_METRICS
        }

        active_metric = self._metric(
            context,
            CORE_CONNECTION_METRIC,
        )

        diagnostic_metrics = {
            name: self._metric(
                context,
                name,
            )
            for name in DIAGNOSTIC_METRICS
        }

        diagnostic_values = {
            name: self._diagnostic_metric_value(
                context,
                name,
            )
            for name in DIAGNOSTIC_METRICS
        }

        packet_values = self._packet_traffic_values(context)

        packet_drop_percentage = self._packet_drop_percentage(context)

        traffic_gib = self._core_traffic_gib(context)

        processed_bytes = self._core_traffic_processed_bytes(context)

        active_connections = self._active_connections_value(context)

        derived_activity = {
            **activity,
            "core_traffic_complete": (self._core_traffic_complete(context)),
            "core_traffic_zero": (self._core_traffic_zero(context)),
            "core_traffic_positive": (self._core_traffic_positive(context)),
            "core_traffic_processed_bytes": (processed_bytes),
            "core_traffic_gib": (traffic_gib),
            "traffic_indicator_is_billing_equivalent": (False),
            "traffic_calculation": ("BytesInFromSource + " "BytesInFromDestination"),
            "active_connections": (active_connections),
            "active_connections_complete": (self._active_connections_complete(context)),
            "active_connections_zero": (
                (active_connections == 0) if active_connections is not None else None
            ),
            "idle_timeout_count": (diagnostic_values.get("IdleTimeoutCount")),
            "error_port_allocation": (diagnostic_values.get("ErrorPortAllocation")),
            "packets_dropped": (diagnostic_values.get("PacketsDropCount")),
            "connection_attempts": (diagnostic_values.get("ConnectionAttemptCount")),
            "connections_established": (
                diagnostic_values.get("ConnectionEstablishedCount")
            ),
            "diagnostic_activity": (self._diagnostic_activity(context)),
            "diagnostic_metrics": (diagnostic_metrics),
            "diagnostic_values": (diagnostic_values),
            "packet_traffic_values": (packet_values),
            "packet_drop_percentage": (packet_drop_percentage),
            "diagnostics_do_not_define_activity": (True),
        }

        return Evidence(
            metrics=metrics,
            configuration=dict(configuration),
            topology=_dict(context.topology()),
            resource=_dict(optimization_evidence.get("resource")),
            derived={
                "activity": derived_activity,
                "network": self._network(optimization_evidence),
                "topology_detail": (self._network_detail(optimization_evidence)),
                "fleet": self._fleet(optimization_evidence),
                "core_traffic": core_traffic,
                "active_connections": active_metric,
                "diagnostics": diagnostic_metrics,
                "endpoint_opportunity": (
                    self._endpoint_opportunity_data(optimization_evidence)
                ),
            },
            billing=_dict(context.billing()),
            data_quality=self._quality(optimization_evidence),
        )

    # OBSERVATION PERIOD

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        observation = context.observation_period

        if isinstance(
            observation,
            dict,
        ):

            return ObservationPeriod(
                start=observation.get("start"),
                end=observation.get("end"),
                duration_seconds=observation.get("duration_seconds"),
            )

        cloudwatch = _dict(context.cloudwatch())

        start = (
            cloudwatch.get("start")
            or cloudwatch.get("analysis_start")
            or cloudwatch.get("metric_start")
        )

        end = (
            cloudwatch.get("end")
            or cloudwatch.get("analysis_end")
            or cloudwatch.get("metric_end")
        )

        if not start and not end:
            return None

        return ObservationPeriod(
            start=start,
            end=end,
        )
