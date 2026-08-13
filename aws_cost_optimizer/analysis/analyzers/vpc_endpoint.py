"""
VPC Endpoint cost optimization analyzer.
"""

from __future__ import annotations

from typing import Any

from .base import Analyzer
from .registry import register
from ..finding import Finding, ObservationPeriod
from ..condition import EvidenceStatement
from ..evidence import Evidence


@register
class VpcEndpointAnalyzer(Analyzer):

    name = "vpc_endpoint_cost_optimizer"
    version = "1.0"

    SUPPORTED_RESOURCE_TYPE = "vpc_endpoint"

    def supports(self, context) -> bool:
        return context.resource_type == self.SUPPORTED_RESOURCE_TYPE

    def analyze(self, context) -> list[Finding]:

        resource = context.resource

        configuration = context.configuration()
        topology = context.topology()

        endpoint_type = (
            configuration.get("endpoint_type")
            or resource.get("identity", {}).get(
                "endpoint_type"
            )
        )

        state = configuration.get("state")

        if state not in {"available", "pending"}:
            return []

        if endpoint_type == "Gateway":
            return self._analyze_gateway(
                context
            )

        if endpoint_type == "Interface":
            return self._analyze_interface(
                context
            )

        return []

    # ------------------------------------------------------------------
    # Gateway endpoints
    # ------------------------------------------------------------------

    def _analyze_gateway(self, context) -> list[Finding]:

        resource = context.resource
        configuration = context.configuration()
        topology = context.topology()

        endpoint_id = context.resource_id

        route_tables = topology.get(
            "route_tables",
            {}
        )

        route_table_ids = (
            route_tables.get(
                "route_table_ids",
                []
            )
            if isinstance(route_tables, dict)
            else []
        )

        endpoint_routes = topology.get(
            "routes",
            {}
        )

        gateway_endpoint_routes = (
            endpoint_routes.get(
                "gateway_endpoint_routes",
                []
            )
            if isinstance(endpoint_routes, dict)
            else []
        )

        dependencies = topology.get(
            "network_dependencies",
            {}
        )

        nat_gateway_ids = (
            dependencies.get(
                "nat_gateway_ids",
                []
            )
            if isinstance(dependencies, dict)
            else []
        )

        findings: list[Finding] = []

        # --------------------------------------------------------------
        # Gateway endpoint without endpoint routes
        # --------------------------------------------------------------

        if (
            route_table_ids
            and not gateway_endpoint_routes
        ):

            findings.append(
                self._gateway_without_routes(
                    context=context,
                    route_table_ids=route_table_ids,
                    nat_gateway_ids=nat_gateway_ids,
                )
            )

        return findings

    def _gateway_without_routes(
        self,
        context,
        route_table_ids: list[str],
        nat_gateway_ids: list[str],
    ) -> Finding:

        endpoint_id = context.resource_id

        resource = context.resource
        configuration = context.configuration()
        topology = context.topology()

        has_nat_path = bool(
            nat_gateway_ids
        )

        if has_nat_path:

            reason = (
                "The Gateway VPC endpoint is associated "
                "with route tables but no route targeting "
                "the endpoint was detected. NAT Gateway "
                "routing is also present, so traffic for "
                "the endpoint service may still use NAT."
            )

        else:

            reason = (
                "The Gateway VPC endpoint is associated "
                "with route tables but no route targeting "
                "the endpoint was detected."
            )

        conditions = [
            EvidenceStatement(
                name="gateway_endpoint",
                value=True,
                description=(
                    "Endpoint type is Gateway."
                ),
                source=[
                    "configuration.endpoint_type"
                ],
            ),
            EvidenceStatement(
                name="associated_route_tables",
                value=len(route_table_ids),
                description=(
                    "Route tables associated with "
                    "the Gateway endpoint."
                ),
                source=[
                    "topology.route_tables.route_table_ids"
                ],
            ),
            EvidenceStatement(
                name="endpoint_routes",
                value=0,
                description=(
                    "No route targeting this Gateway "
                    "endpoint was detected."
                ),
                source=[
                    "topology.routes.gateway_endpoint_routes"
                ],
            ),
        ]

        if has_nat_path:
            conditions.append(
                EvidenceStatement(
                    name="nat_dependency",
                    value=nat_gateway_ids,
                    description=(
                        "NAT Gateway targets are present "
                        "in the relevant route tables."
                    ),
                    source=[
                        "topology.network_dependencies."
                        "nat_gateway_ids"
                    ],
                )
            )

        return Finding(
            finding_type=(
                "vpc_endpoint_gateway_missing_route"
            ),
            resource_type="vpc_endpoint",
            resource_id=endpoint_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="MEDIUM",
            confidence="HIGH",
            reason=reason,
            conditions=conditions,
            evidence=Evidence(
                configuration=configuration,
                topology=topology,
                resource={
                    "resource_id": endpoint_id,
                    "endpoint_type": "Gateway",
                },
                derived={
                    "has_nat_path": has_nat_path,
                    "endpoint_route_count": 0,
                    "route_table_count": len(
                        route_table_ids
                    ),
                },
            ),
            observation_period=None,
            limitations=[
                "The collector does not prove application-level "
                "traffic to the endpoint service."
            ],
            metadata={
                "service_name": (
                    resource.get("identity", {})
                    .get("service_name")
                ),
                "nat_gateway_ids": nat_gateway_ids,
            },
            recommendation_eligible=True,
        )

    # ------------------------------------------------------------------
    # Interface endpoints
    # ------------------------------------------------------------------

    def _analyze_interface(self, context) -> list[Finding]:

        resource = context.resource
        configuration = context.configuration()
        topology = context.topology()

        findings: list[Finding] = []

        endpoint_id = context.resource_id

        requester_managed = configuration.get(
            "requester_managed"
        )

        # --------------------------------------------------------------
        # Never recommend modifying requester-managed endpoints.
        # --------------------------------------------------------------

        if requester_managed:
            return []

        network_interfaces = (
            topology.get(
                "network_interfaces",
                {}
            )
        )

        interface_count = (
            network_interfaces.get(
                "count",
                len(
                    configuration.get(
                        "network_interface_ids",
                        []
                    )
                ),
            )
            if isinstance(network_interfaces, dict)
            else len(
                configuration.get(
                    "network_interface_ids",
                    []
                )
            )
        )

        subnet_info = topology.get(
            "subnets",
            {}
        )

        subnet_count = (
            subnet_info.get(
                "count",
                len(
                    configuration.get(
                        "subnet_ids",
                        []
                    )
                ),
            )
            if isinstance(subnet_info, dict)
            else len(
                configuration.get(
                    "subnet_ids",
                    []
                )
            )
        )

        az_info = topology.get(
            "availability_zones",
            {}
        )

        az_count = (
            az_info.get(
                "count",
                0
            )
            if isinstance(az_info, dict)
            else 0
        )

        nat_dependencies = topology.get(
            "network_dependencies",
            {}
        )

        nat_gateway_ids = (
            nat_dependencies.get(
                "nat_gateway_ids",
                []
            )
            if isinstance(nat_dependencies, dict)
            else []
        )

        # --------------------------------------------------------------
        # Interface endpoint + NAT path
        # --------------------------------------------------------------

        if nat_gateway_ids:

            findings.append(
                self._interface_nat_path(
                    context=context,
                    interface_count=interface_count,
                    subnet_count=subnet_count,
                    az_count=az_count,
                    nat_gateway_ids=nat_gateway_ids,
                )
            )

        return findings

    def _interface_nat_path(
        self,
        context,
        interface_count: int,
        subnet_count: int,
        az_count: int,
        nat_gateway_ids: list[str],
    ) -> Finding:

        configuration = context.configuration()
        topology = context.topology()

        return Finding(
            finding_type=(
                "vpc_endpoint_interface_nat_path"
            ),
            resource_type="vpc_endpoint",
            resource_id=context.resource_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="LOW",
            confidence="MEDIUM",
            reason=(
                "An Interface VPC endpoint exists while "
                "NAT Gateway routing is also present in "
                "the endpoint's network path. Review whether "
                "the endpoint is actually being used for the "
                "intended service traffic and whether the "
                "current endpoint placement is necessary."
            ),
            conditions=[
                EvidenceStatement(
                    name="interface_endpoint",
                    value=True,
                    description=(
                        "Endpoint type is Interface."
                    ),
                    source=[
                        "configuration.endpoint_type"
                    ],
                ),
                EvidenceStatement(
                    name="network_interfaces",
                    value=interface_count,
                    description=(
                        "Network interfaces provisioned "
                        "for the endpoint."
                    ),
                    source=[
                        "configuration.network_interface_ids"
                    ],
                ),
                EvidenceStatement(
                    name="availability_zones",
                    value=az_count,
                    description=(
                        "Availability zones containing "
                        "endpoint subnets."
                    ),
                    source=[
                        "topology.availability_zones"
                    ],
                ),
                EvidenceStatement(
                    name="nat_gateways",
                    value=nat_gateway_ids,
                    description=(
                        "NAT Gateway targets detected "
                        "in the relevant network topology."
                    ),
                    source=[
                        "topology.network_dependencies."
                        "nat_gateway_ids"
                    ],
                ),
            ],
            evidence=Evidence(
                configuration=configuration,
                topology=topology,
                resource={
                    "resource_id": context.resource_id,
                    "service_name": (
                        context.resource.get(
                            "identity",
                            {}
                        ).get(
                            "service_name"
                        )
                    ),
                },
                derived={
                    "interface_count": interface_count,
                    "subnet_count": subnet_count,
                    "availability_zone_count": az_count,
                    "nat_gateway_count": len(
                        nat_gateway_ids
                    ),
                },
            ),
            observation_period=None,
            limitations=[
                "The current collector does not provide "
                "Interface endpoint traffic metrics.",
                "NAT routing does not prove that endpoint "
                "traffic is actually using NAT.",
                "Removing an endpoint without validating "
                "workload dependencies could break private "
                "service access."
            ],
            metadata={
                "service_name": (
                    context.resource.get(
                        "identity",
                        {}
                    ).get(
                        "service_name"
                    )
                ),
                "nat_gateway_ids": nat_gateway_ids,
            },
            recommendation_eligible=True,
        )