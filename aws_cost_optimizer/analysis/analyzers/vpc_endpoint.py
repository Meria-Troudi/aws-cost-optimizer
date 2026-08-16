
"""
VPC Endpoint configuration and optimization analyzer.

"""

from __future__ import annotations

from typing import Any

from ..base import Analyzer
from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from ..registry import register


@register
class VpcEndpointAnalyzer(Analyzer):

    name = "vpc_endpoint"
    version = "3.0"

    SUPPORTED_RESOURCE_TYPE = "vpc_endpoint"

    # ================================================================
    # PUBLIC
    # ================================================================

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            == self.SUPPORTED_RESOURCE_TYPE
        )

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(
            context
        ):
            return []

        if not self._resource_is_analyzable(
            context
        ):
            return []

        checks = (
            self._check_failed_endpoint,
            self._check_gateway_missing_routes,
            self._check_gateway_partial_coverage,
            self._check_interface_missing_enis,
        )

        findings = []

        for check in checks:

            finding = check(
                context
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    # ================================================================
    # BASIC DATA
    # ================================================================

    @staticmethod
    def _resource_is_analyzable(
        context: AnalysisContext,
    ) -> bool:

        state = (
            VpcEndpointAnalyzer._state(
                context
            )
        )

        return state not in {
            "deleted",
            "deleting",
        }

    @staticmethod
    def _identity(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = context.resource.get(
            "identity",
            {},
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _configuration(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = context.configuration()

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _topology(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = context.topology()

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @classmethod
    def _endpoint_type(
        cls,
        context: AnalysisContext,
    ) -> str | None:

        configuration = cls._configuration(
            context
        )

        identity = cls._identity(
            context
        )

        value = (
            configuration.get(
                "endpoint_type"
            )
            or identity.get(
                "endpoint_type"
            )
        )

        if value is None:
            return None

        return str(
            value
        ).strip()

    @classmethod
    def _state(
        cls,
        context: AnalysisContext,
    ) -> str | None:

        configuration = cls._configuration(
            context
        )

        identity = cls._identity(
            context
        )

        value = (
            configuration.get(
                "state"
            )
            or identity.get(
                "state"
            )
        )

        if value is None:
            return None

        return str(
            value
        ).strip().lower()

    @classmethod
    def _service_name(
        cls,
        context: AnalysisContext,
    ) -> str | None:

        identity = cls._identity(
            context
        )

        configuration = cls._configuration(
            context
        )

        value = (
            identity.get(
                "service_name"
            )
            or configuration.get(
                "service_name"
            )
        )

        if value is None:
            return None

        return str(
            value
        )

    @staticmethod
    def _collection_status(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = context.resource.get(
            "collection_status",
            {},
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    # ================================================================
    # OBSERVATION PERIOD
    # ================================================================

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        cloudwatch = context.cloudwatch()

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

    # ================================================================
    # RULE 1 — FAILED ENDPOINT
    # ================================================================

    def _check_failed_endpoint(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        state = self._state(
            context
        )

        if state not in {
            "failed",
            "error",
        }:
            return None

        configuration = self._configuration(
            context
        )

        reason = (
            configuration.get(
                "last_error"
            )
            or configuration.get(
                "failure_reason"
            )
        )

        statements = [
            EvidenceStatement(
                name="endpoint_state",
                value=state,
                description=(
                    "Current VPC endpoint state."
                ),
                source=[
                    "VPC endpoint configuration"
                ],
            )
        ]

        if reason:

            statements.append(
                EvidenceStatement(
                    name="failure_reason",
                    value=reason,
                    description=(
                        "AWS reported an endpoint failure reason."
                    ),
                    source=[
                        "VPC endpoint configuration"
                    ],
                )
            )

        return self._finding(
            context=context,
            finding_type=(
                "vpc_endpoint_failed"
            ),
            title=(
                "VPC endpoint is not operational"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "The VPC endpoint is currently in a failed "
                "or error state."
            ),
            statements=statements,
            metadata={
                "state":
                    state,

                "failure_reason":
                    reason,
            },
            recommendation_eligible=False,
            category="configuration",
        )

    # ================================================================
    # RULE 2 — GATEWAY ENDPOINT WITH NO ROUTES
    # ================================================================

    def _check_gateway_missing_routes(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if (
            self._endpoint_type(
                context
            )
            != "Gateway"
        ):
            return None

        if not self._analysis_topology_complete(
            context
        ):
            return None

        topology = self._topology(
            context
        )

        route_tables = self._as_dict(
            topology.get(
                "route_tables"
            )
        )

        gateway = self._as_dict(
            topology.get(
                "gateway_endpoint"
            )
        )

        configured = self._as_list(
            route_tables.get(
                "configured_route_table_ids"
            )
        )

        route_ids = self._as_list(
            gateway.get(
                "route_table_ids"
            )
        )

        if not configured:
            return None

        if route_ids:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "vpc_endpoint_gateway_missing_route"
            ),
            title=(
                "Gateway endpoint has no effective routes"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "The Gateway endpoint has configured route "
                "tables but no route targeting the endpoint "
                "was detected."
            ),
            statements=[
                EvidenceStatement(
                    name="configured_route_tables",
                    value={
                        "count":
                            len(configured),

                        "ids":
                            configured,
                    },
                    description=(
                        "Route tables configured on the "
                        "Gateway endpoint."
                    ),
                    source=[
                        "VPC endpoint configuration"
                    ],
                ),
                EvidenceStatement(
                    name="endpoint_routes",
                    value={
                        "count":
                            0,
                    },
                    description=(
                        "No effective route targeting "
                        "the Gateway endpoint was detected."
                    ),
                    source=[
                        "VPC route topology"
                    ],
                ),
            ],
            metadata={
                "service_name":
                    self._service_name(
                        context
                    ),

                "configured_route_table_count":
                    len(configured),

                "endpoint_route_count":
                    0,
            },
            recommendation_eligible=False,
            category="configuration",
        )

    # ================================================================
    # RULE 3 — PARTIAL GATEWAY COVERAGE
    # ================================================================

    def _check_gateway_partial_coverage(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if (
            self._endpoint_type(
                context
            )
            != "Gateway"
        ):
            return None

        if not self._analysis_topology_complete(
            context
        ):
            return None

        topology = self._topology(
            context
        )

        route_tables = self._as_dict(
            topology.get(
                "route_tables"
            )
        )

        gateway = self._as_dict(
            topology.get(
                "gateway_endpoint"
            )
        )

        configured = self._as_list(
            route_tables.get(
                "configured_route_table_ids"
            )
        )

        coverage = self._as_list(
            gateway.get(
                "gateway_endpoint_route_table_coverage"
            )
        )

        if not configured:
            return None

        if len(coverage) >= len(configured):
            return None

        missing = sorted(
            set(
                str(value)
                for value in configured
            )
            -
            set(
                str(value)
                for value in coverage
            )
        )

        if not missing:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "vpc_endpoint_gateway_partial_route_coverage"
            ),
            title=(
                "Gateway endpoint has partial route coverage"
            ),
            severity="low",
            confidence="high",
            reason=(
                f"{len(coverage)} of "
                f"{len(configured)} configured route tables "
                "have an effective endpoint route."
            ),
            statements=[
                EvidenceStatement(
                    name="route_table_coverage",
                    value={
                        "configured":
                            len(configured),

                        "covered":
                            len(coverage),

                        "missing":
                            len(missing),
                    },
                    description=(
                        "Not all configured route tables "
                        "have endpoint routing."
                    ),
                    source=[
                        "VPC endpoint topology",
                        "VPC route topology",
                    ],
                ),
                EvidenceStatement(
                    name="uncovered_route_tables",
                    value=missing,
                    description=(
                        "Configured route tables without "
                        "an effective endpoint route."
                    ),
                    source=[
                        "VPC route topology"
                    ],
                ),
            ],
            metadata={
                "service_name":
                    self._service_name(
                        context
                    ),

                "configured_route_table_count":
                    len(configured),

                "covered_route_table_count":
                    len(coverage),

                "uncovered_route_table_count":
                    len(missing),

                "uncovered_route_table_ids":
                    missing,
            },
            recommendation_eligible=False,
            category="configuration",
        )

    # ================================================================
    # RULE 4 — INTERFACE ENDPOINT MISSING ENI
    # ================================================================

    def _check_interface_missing_enis(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if (
            self._endpoint_type(
                context
            )
            != "Interface"
        ):
            return None

        if not self._analysis_topology_complete(
            context
        ):
            return None

        configuration = self._configuration(
            context
        )

        if configuration.get(
            "requester_managed"
        ) is True:

            return None

        configured_eni_ids = self._as_list(
            configuration.get(
                "network_interface_ids"
            )
        )

        network_interfaces = (
            context.resource.get(
                "network_interfaces",
                {},
            )
        )

        if not isinstance(
            network_interfaces,
            dict,
        ):
            return None

        status = network_interfaces.get(
            "status"
        )

        observed_count = (
            network_interfaces.get(
                "observed_count"
            )
        )

        try:
            observed_count = int(
                observed_count
            )
        except (
            TypeError,
            ValueError,
        ):
            return None

        if (
            status != "ok"
            or
            not configured_eni_ids
            or
            observed_count != 0
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "vpc_endpoint_interface_missing_eni"
            ),
            title=(
                "Interface endpoint has no observed ENIs"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "The Interface endpoint configuration "
                "contains network interfaces, but none "
                "were returned by the ENI collector."
            ),
            statements=[
                EvidenceStatement(
                    name="configured_network_interfaces",
                    value={
                        "count":
                            len(
                                configured_eni_ids
                            ),

                        "ids":
                            configured_eni_ids,
                    },
                    description=(
                        "ENIs expected from the endpoint "
                        "configuration."
                    ),
                    source=[
                        "VPC endpoint configuration"
                    ],
                ),
                EvidenceStatement(
                    name="observed_network_interfaces",
                    value=0,
                    description=(
                        "No corresponding ENIs were observed."
                    ),
                    source=[
                        "Network interface inventory"
                    ],
                ),
            ],
            metadata={
                "configured_eni_count":
                    len(
                        configured_eni_ids
                    ),

                "observed_eni_count":
                    observed_count,

                "configured_eni_ids":
                    configured_eni_ids,
            },
            recommendation_eligible=False,
            category="configuration",
        )

    # ================================================================
    # COMPLETENESS
    # ================================================================

    @classmethod
    def _analysis_topology_complete(
        cls,
        context: AnalysisContext,
    ) -> bool:

        status = cls._collection_status(
            context
        )

        if status.get(
            "complete_for_analysis"
        ) is False:

            # A false explicit completeness flag must stop
            # topology-based analysis.
            return False

        topology_status = status.get(
            "topology"
        )

        relationships_status = status.get(
            "relationships"
        )

        if topology_status not in {
            None,
            "ok",
        }:
            return False

        if relationships_status not in {
            None,
            "ok",
        }:
            return False

        endpoint_type = cls._endpoint_type(
            context
        )

        if endpoint_type == "Gateway":
            return (
                status.get(
                    "gateway_route_context"
                )
                in {
                    None,
                    "ok",
                }
            )

        return True

    # ================================================================
    # FINDING
    # ================================================================

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
        recommendation_eligible: bool,
        category: str,
    ) -> Finding:

        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or self.SUPPORTED_RESOURCE_TYPE
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
                context
            ),

            observation_period=(
                self._observation_period(
                    context
                )
            ),

            limitations=self._limitations(
                finding_type
            ),

            metadata=dict(
                metadata
            ),

            recommendation_eligible=(
                recommendation_eligible
            ),

            category=category,
        )

    # ================================================================
    # EVIDENCE
    # ================================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
    ) -> Evidence:

        configuration = self._configuration(
            context
        )

        topology = self._topology(
            context
        )

        metrics = {}

        for name in context.metrics():

            metrics[
                name
            ] = context.metric_summary(
                name
            )

        return Evidence(
            metrics=metrics,

            configuration={
                key:
                    value
                for key, value
                in configuration.items()
                if key not in {
                    "policy_document",
                    "tags",
                    "dns_entries",
                }
            },

            topology={
                key:
                    topology.get(
                        key
                    )
                for key in (
                    "status",
                    "collection_status",
                    "route_tables",
                    "gateway_endpoint",
                    "interface_endpoint",
                    "network_interfaces",
                    "network_dependencies",
                    "subnets",
                    "availability_zones",
                )
                if key in topology
            },

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,

                "service_name":
                    self._service_name(
                        context
                    ),

                "endpoint_type":
                    self._endpoint_type(
                        context
                    ),
            },

            derived={
                "endpoint_type":
                    self._endpoint_type(
                        context
                    ),

                "service_name":
                    self._service_name(
                        context
                    ),

                "state":
                    self._state(
                        context
                    ),

                "collection_status":
                    self._collection_status(
                        context
                    ),
            },

            data_quality={
                "topology_status":
                    self._collection_status(
                        context
                    ).get(
                        "topology"
                    ),

                "relationship_status":
                    self._collection_status(
                        context
                    ).get(
                        "relationships"
                    ),

                "analysis_complete":
                    self._collection_status(
                        context
                    ).get(
                        "complete_for_analysis"
                    ),
            },
        )

    # ================================================================
    # LIMITATIONS
    # ================================================================

    @staticmethod
    def _limitations(
        finding_type: str,
    ) -> list[str]:

        if finding_type in {
            "vpc_endpoint_gateway_missing_route",
            "vpc_endpoint_gateway_partial_route_coverage",
        }:
            return [
                (
                    "Route topology establishes configuration "
                    "state, not application traffic volume."
                ),
            ]

        if finding_type == (
            "vpc_endpoint_interface_missing_eni"
        ):
            return [
                (
                    "The finding indicates an inventory/configuration "
                    "mismatch; it does not establish cost impact."
                ),
            ]

        return []

    # ================================================================
    # GENERIC HELPERS
    # ================================================================

    @staticmethod
    def _as_list(
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

    @staticmethod
    def _as_dict(
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