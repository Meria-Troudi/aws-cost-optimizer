"""
VPC Endpoint analyzer.

The analyzer evaluates one VPC endpoint.

It detects configuration and operational problems only:
- failed/rejected/expired endpoint
- gateway endpoint route mismatch
- gateway endpoint partial route coverage
- interface endpoint ENI mismatch

These findings are diagnostic.
They do not create cost recommendations.

Cost recommendations for interface endpoints require
usage/cost evidence beyond configuration topology.
"""

from __future__ import annotations

from typing import Any

from ....base import Analyzer
from ....condition import EvidenceStatement
from ....context import AnalysisContext
from ....evidence import Evidence
from ....finding import Finding, ObservationPeriod
from ....registry import register


@register
class VpcEndpointAnalyzer(Analyzer):

    name = "vpc_endpoint"
    version = "4.0"

    RESOURCE_TYPE = "vpc_endpoint"

    NON_OPERATIONAL_STATES = {
        "failed",
        "rejected",
        "expired",
        "error",
        "partial",
    }

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            == self.RESOURCE_TYPE
        )

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        if not self._analyzable(context):
            return []

        findings: list[Finding] = []

        checks = (
            self._check_non_operational,
            self._check_gateway_missing_routes,
            self._check_gateway_partial_coverage,
            self._check_interface_missing_enis,
        )

        for check in checks:

            finding = check(context)

            if finding is not None:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Context
    # ------------------------------------------------------------------

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    @classmethod
    def _configuration(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            context.configuration()
        )

    @classmethod
    def _identity(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            context.resource.get(
                "identity"
            )
        )

    @classmethod
    def _topology(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(
            context.topology()
        )

    @classmethod
    def _collection_status(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        status = context.resource.get(
            "collection_status"
        )

        return cls._dict(status)

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

        return str(value).strip()

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

        configuration = cls._configuration(
            context
        )

        identity = cls._identity(
            context
        )

        value = (
            configuration.get(
                "service_name"
            )
            or identity.get(
                "service_name"
            )
        )

        if value is None:
            return None

        return str(value)

    @classmethod
    def _analyzable(
        cls,
        context: AnalysisContext,
    ) -> bool:

        state = cls._state(context)

        return state not in {
            "deleted",
            "deleting",
        }

    @classmethod
    def _topology_complete(
        cls,
        context: AnalysisContext,
    ) -> bool:

        status = cls._collection_status(
            context
        )

        complete = status.get(
            "complete_for_analysis"
        )

        if complete is False:
            return False

        topology_status = status.get(
            "topology"
        )

        relationship_status = status.get(
            "relationships"
        )

        if topology_status != "ok":
            return False

        if relationship_status != "ok":
            return False

        endpoint_type = cls._endpoint_type(
            context
        )

        if endpoint_type == "Gateway":

            return (
                status.get(
                    "gateway_route_context"
                )
                == "ok"
            )

        return True

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def _check_non_operational(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        state = self._state(context)

        if state not in self.NON_OPERATIONAL_STATES:
            return None

        configuration = self._configuration(
            context
        )

        reason_detail = (
            configuration.get(
                "last_error"
            )
            or configuration.get(
                "failure_reason"
            )
        )

        statements = [
            self._statement(
                name="endpoint_state",
                value=state,
                description="Current VPC endpoint state.",
                source=[
                    "VPC endpoint configuration"
                ],
                observed=True,
            )
        ]

        if reason_detail:

            statements.append(
                self._statement(
                    name="failure_reason",
                    value=reason_detail,
                    description="Reported endpoint failure reason.",
                    source=[
                        "VPC endpoint configuration"
                    ],
                    observed=True,
                )
            )

        return self._finding(
            context=context,
            finding_type="vpc_endpoint_non_operational",
            title="VPC endpoint is not operational",
            severity="medium",
            confidence="high",
            reason=(
                f"The VPC endpoint is in '{state}' state."
            ),
            statements=statements,
            metadata={
                "state":
                    state,

                "service_name":
                    self._service_name(
                        context
                    ),

                "endpoint_type":
                    self._endpoint_type(
                        context
                    ),

                "failure_reason":
                    reason_detail,
            },
        )

    def _check_gateway_missing_routes(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if self._endpoint_type(context) != "Gateway":
            return None

        if not self._topology_complete(context):
            return None

        topology = self._topology(
            context
        )

        route_tables = self._dict(
            topology.get(
                "route_tables"
            )
        )

        gateway = self._dict(
            topology.get(
                "gateway_endpoint"
            )
        )

        configured = self._list(
            route_tables.get(
                "configured_route_table_ids"
            )
        )

        covered = self._list(
            gateway.get(
                "route_table_ids"
            )
        )

        if not configured:
            return None

        if covered:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "vpc_endpoint_gateway_missing_route"
            ),
            title="Gateway endpoint has no effective routes",
            severity="medium",
            confidence="high",
            reason=(
                "Configured route tables have no observed "
                "route targeting the gateway endpoint."
            ),
            statements=[
                self._statement(
                    name="configured_route_tables",
                    value=configured,
                    description="Route tables configured for the endpoint.",
                    source=[
                        "VPC endpoint configuration"
                    ],
                    observed=True,
                ),
                self._statement(
                    name="effective_endpoint_routes",
                    value=0,
                    description="Observed gateway endpoint routes.",
                    source=[
                        "VPC route topology"
                    ],
                    observed=True,
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
                    0,
            },
        )

    def _check_gateway_partial_coverage(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if self._endpoint_type(context) != "Gateway":
            return None

        if not self._topology_complete(context):
            return None

        topology = self._topology(
            context
        )

        route_tables = self._dict(
            topology.get(
                "route_tables"
            )
        )

        gateway = self._dict(
            topology.get(
                "gateway_endpoint"
            )
        )

        configured = self._string_list(
            route_tables.get(
                "configured_route_table_ids"
            )
        )

        covered = self._string_list(
            gateway.get(
                "gateway_endpoint_route_table_coverage"
            )
        )

        if not configured:
            return None

        if len(covered) >= len(configured):
            return None

        missing = sorted(
            set(configured)
            - set(covered)
        )

        if not missing:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "vpc_endpoint_gateway_partial_route_coverage"
            ),
            title="Gateway endpoint has partial route coverage",
            severity="low",
            confidence="high",
            reason=(
                f"{len(covered)} of {len(configured)} "
                "configured route tables have endpoint routing."
            ),
            statements=[
                self._statement(
                    name="route_table_coverage",
                    value={
                        "configured":
                            len(configured),

                        "covered":
                            len(covered),

                        "missing":
                            len(missing),
                    },
                    description="Gateway endpoint route coverage.",
                    source=[
                        "VPC endpoint topology",
                        "VPC route topology",
                    ],
                    observed=True,
                ),
                self._statement(
                    name="uncovered_route_tables",
                    value=missing,
                    description=(
                        "Configured route tables without "
                        "observed endpoint routing."
                    ),
                    source=[
                        "VPC route topology"
                    ],
                    observed=True,
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
                    len(covered),

                "uncovered_route_table_ids":
                    missing,
            },
        )

    def _check_interface_missing_enis(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if self._endpoint_type(context) != "Interface":
            return None

        if not self._topology_complete(context):
            return None

        state = self._state(context)

        if state != "available":
            return None

        configuration = self._configuration(
            context
        )

        configured_ids = self._string_list(
            configuration.get(
                "network_interface_ids"
            )
        )

        if not configured_ids:
            return None

        network_interfaces = self._dict(
            context.resource.get(
                "network_interfaces"
            )
        )

        if network_interfaces.get(
            "status"
        ) != "ok":
            return None

        observed_ids = self._string_list(
            [
                item.get(
                    "network_interface_id"
                )
                for item in self._list(
                    network_interfaces.get(
                        "resources"
                    )
                )
                if isinstance(
                    item,
                    dict,
                )
            ]
        )

        observed_count = len(
            observed_ids
        )

        if set(observed_ids) == set(
            configured_ids
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "vpc_endpoint_interface_eni_mismatch"
            ),
            title="Interface endpoint ENI inventory mismatch",
            severity="medium",
            confidence="high",
            reason=(
                f"{len(configured_ids)} endpoint ENIs are "
                f"configured, but {observed_count} were observed."
            ),
            statements=[
                self._statement(
                    name="configured_network_interfaces",
                    value={
                        "count":
                            len(configured_ids),

                        "ids":
                            configured_ids,
                    },
                    description="ENIs configured for the endpoint.",
                    source=[
                        "VPC endpoint configuration"
                    ],
                    observed=True,
                ),
                self._statement(
                    name="observed_network_interfaces",
                    value=observed_count,
                    description="ENIs returned by inventory.",
                    source=[
                        "Network interface inventory"
                    ],
                    observed=True,
                ),
            ],
            metadata={
                "service_name":
                    self._service_name(
                        context
                    ),

                "configured_eni_count":
                    len(configured_ids),

                "observed_eni_count":
                    observed_count,

                "configured_eni_ids":
                    configured_ids,
            },
        )

    # ------------------------------------------------------------------
    # Finding
    # ------------------------------------------------------------------

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
    ) -> Finding:

        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or self.RESOURCE_TYPE
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

            # Important:
            # These are diagnostics, not cost recommendations.
            recommendation_eligible=False,
        )

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

        metrics = {
            name:
                context.metric_summary(name)
            for name in context.metrics()
        }

        return Evidence(
            metrics=metrics,

            configuration={
                key: value
                for key, value
                in configuration.items()
                if key not in {
                    "policy_document",
                    "tags",
                    "dns_entries",
                }
            },

            topology={
                key: topology.get(key)
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
                "service_name":
                    self._service_name(
                        context
                    ),

                "endpoint_type":
                    self._endpoint_type(
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
                "topology_available":
                    bool(topology),

                "analysis_complete":
                    self._collection_status(
                        context
                    ).get(
                        "complete_for_analysis"
                    ),

                "network_interfaces_available":
                    context.resource.get(
                        "network_interfaces",
                        {}
                    ).get(
                        "status"
                    )
                    == "ok"
                    if isinstance(
                        context.resource.get(
                            "network_interfaces"
                        ),
                        dict,
                    )
                    else False,
            },
        )

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
                    "This is a routing configuration finding; "
                    "it does not prove cost impact."
                )
            ]

        if finding_type == (
            "vpc_endpoint_interface_eni_mismatch"
        ):
            return [
                (
                    "The finding indicates a configuration or "
                    "inventory mismatch; it does not prove cost impact."
                )
            ]

        return []

    @staticmethod
    def _statement(
        *,
        name: str,
        value: Any,
        description: str,
        source: list[str],
        observed: bool | None = None,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=list(source),
            observed=observed,
        )

    @staticmethod
    def _list(
        value: Any,
    ) -> list[Any]:

        return (
            value
            if isinstance(value, list)
            else []
        )

    @staticmethod
    def _string_list(
        value: Any,
    ) -> list[str]:

        if not isinstance(value, list):
            return []

        result = []
        seen = set()

        for item in value:

            if item is None:
                continue

            text = str(item).strip()

            if not text or text in seen:
                continue

            seen.add(text)
            result.append(text)

        return result

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int:

        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return 0

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        cloudwatch = context.cloudwatch()

        if not isinstance(
            cloudwatch,
            dict,
        ):
            cloudwatch = {}

        start = (
            cloudwatch.get("start")
            or cloudwatch.get("metric_start")
        )

        end = (
            cloudwatch.get("end")
            or cloudwatch.get("metric_end")
        )

        if start or end:

            return ObservationPeriod(
                start=start,
                end=end,
            )

        value = context.observation_period

        if not isinstance(value, dict):
            return None

        return ObservationPeriod(
            start=value.get("start"),
            end=value.get("end"),
            duration_seconds=value.get(
                "duration_seconds"
            ),
        )