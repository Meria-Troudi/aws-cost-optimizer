"""
Elastic IP / Public IPv4 cost optimization analyzer.
"""

from __future__ import annotations

from typing import Any

from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from .base import Analyzer
from .registry import register


IPV4_CONFIGURATION_FIELDS = (
    "allocation_id",
    "association_id",
    "public_ip",
    "private_ip",
    "network_interface_id",
    "instance_id",
    "domain",
    "network_interface_owner_id",
    "region",
)


def _is_associated(
    configuration: dict[str, Any],
) -> bool | None:


    association_id = configuration.get(
        "association_id"
    )

    network_interface_id = configuration.get(
        "network_interface_id"
    )

    instance_id = configuration.get(
        "instance_id"
    )
    if association_id:
        return True

    if network_interface_id:
        return True

    if instance_id:
        return True

    associated = configuration.get(
        "associated"
    )

    if isinstance(associated, bool):
        return associated

    return None


@register
class IPv4Analyzer(Analyzer):

    name = "ipv4"
    version = "1.0"

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return context.resource_type in {
            "elastic_ip",
            "public_ipv4",
            "ipv4",
        }
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

        finding = self._detect_unassociated(
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

        configuration = (
            context.configuration()
        )

        association = _is_associated(
            configuration
        )

        allocation_id = (
            configuration.get(
                "allocation_id"
            )
            or configuration.get(
                "eip_allocation_id"
            )
        )

        public_ip = configuration.get(
            "public_ip"
        )

        network_interface_id = (
            configuration.get(
                "network_interface_id"
            )
        )

        instance_id = (
            configuration.get(
                "instance_id"
            )
        )

        domain = configuration.get(
            "domain"
        )

        owner_id = (
            configuration.get(
                "network_interface_owner_id"
            )
        )

        association_data_available = (
            association is not None
        )

        return {
            "configuration":
                configuration,

            "association":
                association,

            "association_data_available":
                association_data_available,

            "allocation_id":
                allocation_id,

            "public_ip":
                public_ip,

            "network_interface_id":
                network_interface_id,

            "instance_id":
                instance_id,

            "domain":
                domain,

            "network_interface_owner_id":
                owner_id,
        }
    def _detect_unassociated(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        association = data[
            "association"
        ]

        if association is not False:
            return None

        configuration = data[
            "configuration"
        ]

        public_ip = data[
            "public_ip"
        ]

        allocation_id = data[
            "allocation_id"
        ]

        statements = [
            EvidenceStatement(
                name="ipv4_association",
                value={
                    "associated": False,
                    "allocation_id":
                        allocation_id,
                    "public_ip":
                        public_ip,
                },
                description=(
                    "The public IPv4 address is allocated "
                    "but is not associated with a resource."
                ),
                source=[
                    "EC2 Elastic IP configuration",
                ],
            )
        ]

        statements.append(
            EvidenceStatement(
                name="network_interface",
                value={
                    "network_interface_id":
                        data[
                            "network_interface_id"
                        ],
                    "instance_id":
                        data[
                            "instance_id"
                        ],
                },
                description=(
                    "No associated network interface "
                    "or instance was identified."
                ),
                source=[
                    "EC2 Elastic IP configuration",
                ],
            )
        )

        reason = (
            "The public IPv4 address is allocated "
            "but is not associated with a resource. "
            "An unassociated public IPv4 address can "
            "represent unnecessary cost."
        )

        return self._finding(
            context=context,

            finding_type=(
                "elastic_ip_unassociated"
            ),

            severity="medium",

            confidence="high",

            reason=reason,

            statements=statements,

            metadata={
                "allocation_id":
                    allocation_id,

                "public_ip":
                    public_ip,

                "associated": False,

                "network_interface_id":
                    data[
                        "network_interface_id"
                    ],

                "instance_id":
                    data[
                        "instance_id"
                    ],
            },

            data=data,
        )
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

            resource_type=(
                context.resource_type
                or "elastic_ip"
            ),

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
            for key in IPV4_CONFIGURATION_FIELDS
            if key in configuration
        }

        return Evidence(
            metrics={},

            configuration=filtered_config,

            topology=context.topology(),

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,
            },

            derived={
                "allocation_id":
                    data[
                        "allocation_id"
                    ],

                "public_ip":
                    data[
                        "public_ip"
                    ],

                "associated":
                    data[
                        "association"
                    ],

                "association_data_available":
                    data[
                        "association_data_available"
                    ],

                "network_interface_id":
                    data[
                        "network_interface_id"
                    ],

                "instance_id":
                    data[
                        "instance_id"
                    ],
            },

            data_quality={
                "association_data_available":
                    data[
                        "association_data_available"
                    ],

                "collector_data_quality":
                    context.collector_data_quality(),
            },
        )

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        value = context.observation_period

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