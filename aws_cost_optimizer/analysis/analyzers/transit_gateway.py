"""
Transit Gateway cost optimization analyzer.
"""

from __future__ import annotations

from typing import Any

from .base import Analyzer
from .registry import register
from ..finding import Finding
from ..condition import EvidenceStatement
from ..evidence import Evidence


@register
class TransitGatewayAnalyzer(Analyzer):

    name = "transit_gateway_cost_optimizer"
    version = "1.0"

    SUPPORTED_RESOURCE_TYPE = "transit_gateway"

    def supports(self, context) -> bool:
        return context.resource_type == (
            self.SUPPORTED_RESOURCE_TYPE
        )

    def analyze(self, context) -> list[Finding]:

        relationships = context.resource.get(
            "relationships",
            {}
        )

        if not relationships:
            return []

        findings: list[Finding] = []

        findings.extend(
            self._analyze_attachments(context)
        )

        findings.extend(
            self._analyze_routes(context)
        )

        findings.extend(
            self._analyze_vpc_routing(context)
        )

        findings.extend(
            self._analyze_traffic(context)
        )

        return findings

    # ------------------------------------------------------------------
    # Attachments
    # ------------------------------------------------------------------

    def _analyze_attachments(self, context) -> list[Finding]:

        relationships = context.resource.get(
            "relationships",
            {}
        )

        vpc_attachments = relationships.get(
            "vpc_attachments",
            []
        )

        other_attachments = relationships.get(
            "other_attachments",
            []
        )

        peering_attachments = relationships.get(
            "peering_attachments",
            []
        )

        active_vpc = [
            attachment
            for attachment in vpc_attachments
            if attachment.get("state") == "available"
        ]

        active_other = [
            attachment
            for attachment in other_attachments
            if attachment.get("state") == "available"
        ]

        active_peering = [
            attachment
            for attachment in peering_attachments
            if attachment.get("state") == "available"
        ]

        # --------------------------------------------------------------
        # No active attachments
        # --------------------------------------------------------------

        if not active_vpc and not active_other and not active_peering:

            return [
                Finding(
                    finding_type=(
                        "transit_gateway_no_active_attachments"
                    ),
                    resource_type="transit_gateway",
                    resource_id=context.resource_id,
                    analyzer=self.name,
                    analyzer_version=self.version,
                    severity="MEDIUM",
                    confidence="HIGH",
                    reason=(
                        "The Transit Gateway has no active "
                        "attachments. Review whether the "
                        "Transit Gateway is still required."
                    ),
                    conditions=[
                        EvidenceStatement(
                            name="active_vpc_attachments",
                            value=0,
                            description=(
                                "Number of active VPC "
                                "attachments."
                            ),
                            source=[
                                "relationships.vpc_attachments"
                            ],
                        ),
                        EvidenceStatement(
                            name="active_other_attachments",
                            value=0,
                            description=(
                                "Number of active non-VPC "
                                "attachments."
                            ),
                            source=[
                                "relationships.other_attachments"
                            ],
                        ),
                        EvidenceStatement(
                            name="active_peering_attachments",
                            value=0,
                            description=(
                                "Number of active TGW "
                                "peering attachments."
                            ),
                            source=[
                                "relationships."
                                "peering_attachments"
                            ],
                        ),
                    ],
                    evidence=Evidence(
                        configuration=context.configuration(),
                        topology=context.topology(),
                        resource={
                            "resource_id": context.resource_id
                        },
                        derived={
                            "active_attachment_count": 0
                        },
                    ),
                    observation_period=None,
                    limitations=[
                        "No active attachment was detected "
                        "at collection time."
                    ],
                    metadata={
                        "active_attachment_count": 0
                    },
                    recommendation_eligible=True,
                )
            ]

        return []

     

    # ------------------------------------------------------------------
    # VPC attachment routing
    # ------------------------------------------------------------------

    def _analyze_vpc_routing(self, context) -> list[Finding]:

        topology = context.topology()

        vpcs = topology.get(
            "vpcs",
            []
        )

        findings: list[Finding] = []

        for vpc in vpcs:

            if vpc.get("status") != "ok":
                continue

            attachment_id = vpc.get(
                "attachment_id"
            )

            vpc_id = vpc.get(
                "vpc_id"
            )

            tgw_route_count = vpc.get(
                "tgw_route_count",
                0
            )

            if tgw_route_count > 0:
                continue

            findings.append(
                Finding(
                    finding_type=(
                        "transit_gateway_attachment_no_vpc_route"
                    ),
                    resource_type="transit_gateway",
                    resource_id=context.resource_id,
                    analyzer=self.name,
                    analyzer_version=self.version,
                    severity="MEDIUM",
                    confidence="HIGH",
                    reason=(
                        "A VPC is attached to the Transit "
                        "Gateway, but no VPC route targeting "
                        "the Transit Gateway was detected."
                    ),
                    conditions=[
                        EvidenceStatement(
                            name="vpc_attachment",
                            value=attachment_id,
                            description=(
                                "Transit Gateway VPC "
                                "attachment."
                            ),
                            source=[
                                "topology.vpcs.attachment_id"
                            ],
                        ),
                        EvidenceStatement(
                            name="tgw_vpc_routes",
                            value=0,
                            description=(
                                "Number of VPC routes "
                                "targeting this TGW."
                            ),
                            source=[
                                "topology.vpcs.tgw_route_count"
                            ],
                        ),
                    ],
                    evidence=Evidence(
                        configuration=context.configuration(),
                        topology={
                            "vpc": vpc
                        },
                        resource={
                            "resource_id": context.resource_id,
                            "vpc_id": vpc_id,
                            "attachment_id": attachment_id,
                        },
                        derived={
                            "tgw_vpc_route_count": 0
                        },
                    ),
                    observation_period=None,
                    limitations=[
                        "The absence of a VPC route does not "
                        "prove that the attachment is unnecessary."
                    ],
                    metadata={
                        "vpc_id": vpc_id,
                        "attachment_id": attachment_id,
                    },
                    recommendation_eligible=True,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Traffic
    # ------------------------------------------------------------------

    def _analyze_traffic(self, context) -> list[Finding]:

        metrics = context.metrics()

        if not metrics:
            return []

        bytes_in = context.metric_value(
            "BytesIn"
        )

        bytes_out = context.metric_value(
            "BytesOut"
        )

        if bytes_in is None or bytes_out is None:
            return []

        total_bytes = (
            bytes_in + bytes_out
        )

        # --------------------------------------------------------------
        # Do NOT classify missing data as zero.
        # --------------------------------------------------------------

        if total_bytes > 0:
            return []

        relationships = context.resource.get(
            "relationships",
            {}
        )

        vpc_attachments = relationships.get(
            "vpc_attachments",
            []
        )

        active_attachments = [
            attachment
            for attachment in vpc_attachments
            if attachment.get("state") == "available"
        ]

        if not active_attachments:
            return []

        return [
            Finding(
                finding_type=(
                    "transit_gateway_zero_observed_traffic"
                ),
                resource_type="transit_gateway",
                resource_id=context.resource_id,
                analyzer=self.name,
                analyzer_version=self.version,
                severity="MEDIUM",
                confidence="MEDIUM",
                reason=(
                    "The Transit Gateway has active VPC "
                    "attachments but no observed BytesIn or "
                    "BytesOut during the analysis period. "
                    "Review whether the attachments are still "
                    "required."
                ),
                conditions=[
                    EvidenceStatement(
                        name="active_vpc_attachments",
                        value=len(
                            active_attachments
                        ),
                        description=(
                            "Number of active VPC "
                            "attachments."
                        ),
                        source=[
                            "relationships.vpc_attachments"
                        ],
                    ),
                    EvidenceStatement(
                        name="bytes_in",
                        value=bytes_in,
                        description=(
                            "Observed inbound TGW traffic."
                        ),
                        source=[
                            "observations.cloudwatch.metrics."
                            "BytesIn"
                        ],
                    ),
                    EvidenceStatement(
                        name="bytes_out",
                        value=bytes_out,
                        description=(
                            "Observed outbound TGW traffic."
                        ),
                        source=[
                            "observations.cloudwatch.metrics."
                            "BytesOut"
                        ],
                    ),
                ],
                evidence=Evidence(
                    metrics={
                        "BytesIn": context.metric_summary(
                            "BytesIn"
                        ),
                        "BytesOut": context.metric_summary(
                            "BytesOut"
                        ),
                    },
                    configuration=context.configuration(),
                    topology=context.topology(),
                    resource={
                        "resource_id": context.resource_id
                    },
                    derived={
                        "total_bytes": total_bytes,
                        "active_vpc_attachment_count": len(
                            active_attachments
                        ),
                    },
                ),
                observation_period=(
                    context.observation_period
                ),
                limitations=[
                    "Zero observed traffic during the "
                    "analysis period does not prove that "
                    "the attachments are permanently unused.",
                    "Validate scheduled, intermittent, or "
                    "failover workloads before removal."
                ],
                metadata={
                    "active_vpc_attachment_count": len(
                        active_attachments
                    ),
                    "total_bytes": total_bytes,
                },
                recommendation_eligible=True,
            )
        ]

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _analyze_routes(
        self,
        context,
    ) -> list[Finding]:

        relationships = context.resource.get(
            "relationships",
            {},
        )

        routes = relationships.get(
            "routes",
            [],
        )

        blackhole_routes = [
            route
            for route in routes
            if route.get("state") == "blackhole"
        ]

        if not blackhole_routes:
            return []

        return [
            self._blackhole_finding(
                context,
                blackhole_routes,
            )
        ]

    def _blackhole_finding(
        self,
        context,
        routes: list[dict[str, Any]],
    ) -> Finding:

        return Finding(
            finding_type=(
                "transit_gateway_blackhole_routes"
            ),
            resource_type="transit_gateway",
            resource_id=context.resource_id,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="MEDIUM",
            confidence="HIGH",
            reason=(
                "Blackhole routes exist in the Transit "
                "Gateway route tables. Review whether these "
                "routes and their associated attachments "
                "are still required."
            ),
            conditions=[
                EvidenceStatement(
                    name="blackhole_route_count",
                    value=len(routes),
                    description=(
                        "Number of blackhole routes."
                    ),
                    source=[
                        "relationships.routes"
                    ],
                )
            ],
            evidence=Evidence(
                configuration=context.configuration(),
                topology=context.topology(),
                resource={
                    "resource_id": context.resource_id
                },
                derived={
                    "blackhole_route_count": len(routes)
                },
            ),
            observation_period=None,
            limitations=[
                "Blackhole routes can be intentional."
            ],
            metadata={
                "blackhole_routes": routes
            },
            recommendation_eligible=True,
        )