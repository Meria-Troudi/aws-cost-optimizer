"""
Public IPv4 / Elastic IP optimization analyzer.

Responsibilities
----------------
The analyzer evaluates the evidence collected for one public IPv4
resource and emits resource-level findings.

The analyzer does NOT:
- decide aggregation scope
- group resources
- decide regional/account/service reporting
- reconstruct AWS resource ownership from identifiers
- infer service-managed status from resource type
- invent cost attribution

Framework responsibilities
---------------------------
Finding aggregation is performed outside the analyzer.

Each Finding produced here represents:
    one resource + one detected condition
"""

from __future__ import annotations

from typing import Any

from ..base import Analyzer
from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from ..registry import register


IPV4_RESOURCE_TYPES = {
    "elastic_ip",
    "public_ipv4",
    "ipv4",
}


@register
class IPv4Analyzer(Analyzer):

    name = "ipv4"
    version = "5.0"

    SUPPORTED_RESOURCE_TYPES = frozenset(
        IPV4_RESOURCE_TYPES
    )

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
    # ANALYZE
    # ==============================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(
            context
        ):
            return []

        data = self._collect_data(
            context
        )

        findings: list[Finding] = []

        # ----------------------------------------------------------
        # The analyzer relies on explicit collector evidence.
        #
        # Service-managed/requester-managed resources are excluded
        # only when the collector explicitly says optimization is
        # not allowed.
        #
        # Missing eligibility evidence must not be interpreted as
        # permission to optimize.
        # ----------------------------------------------------------

        if data["optimization_allowed"] is not True:
            return findings

        # ----------------------------------------------------------
        # Individual resource conditions
        # ----------------------------------------------------------

        finding = self._detect_unassociated(
            context,
            data,
        )

        if finding is not None:
            findings.append(
                finding
            )

        finding = self._detect_stopped_instance(
            context,
            data,
        )

        if finding is not None:
            findings.append(
                finding
            )

        return findings

    # ==============================================================
    # DATA COLLECTION FROM CONTEXT
    # ==============================================================

    def _collect_data(
        self,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        configuration = context.configuration()

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        associated = configuration.get(
            "associated"
        )

        if not isinstance(
            associated,
            bool,
        ):

            associated = (
                self._associated_fallback(
                    configuration
                )
            )

        optimization_allowed = (
            self._optional_bool(
                configuration.get(
                    "optimization_allowed"
                )
            )
        )

        release_allowed = (
            self._optional_bool(
                configuration.get(
                    "release_allowed"
                )
            )
        )

        requester_managed = (
            self._optional_bool(
                configuration.get(
                    "requester_managed"
                )
            )
        )

        service_managed = (
            self._optional_bool(
                configuration.get(
                    "service_managed"
                )
            )
        )

        instance_state = (
            self._lower(
                configuration.get(
                    "instance_state"
                )
            )
        )

        return {
            "configuration":
                dict(configuration),

            # ------------------------------------------------------
            # Association
            # ------------------------------------------------------

            "associated":
                associated,

            "association_data_available":
                associated is not None,

            # ------------------------------------------------------
            # Eligibility / ownership evidence
            # ------------------------------------------------------

            "optimization_allowed":
                optimization_allowed,

            "release_allowed":
                release_allowed,

            "requester_managed":
                requester_managed,

            "service_managed":
                service_managed,

            # ------------------------------------------------------
            # Resource identity
            # ------------------------------------------------------

            "public_ip":
                configuration.get(
                    "public_ip"
                ),

            "allocation_id":
                configuration.get(
                    "allocation_id"
                ),

            "association_id":
                configuration.get(
                    "association_id"
                ),

            "instance_id":
                configuration.get(
                    "instance_id"
                ),

            "instance_state":
                instance_state,

            "network_interface_id":
                configuration.get(
                    "network_interface_id"
                ),

            "network_interface_type":
                configuration.get(
                    "network_interface_type"
                ),

            # ------------------------------------------------------
            # Network context
            # ------------------------------------------------------

            "vpc_id":
                configuration.get(
                    "vpc_id"
                ),

            "subnet_id":
                configuration.get(
                    "subnet_id"
                ),

            "availability_zone":
                configuration.get(
                    "availability_zone"
                ),

            # ------------------------------------------------------
            # Address classification
            # ------------------------------------------------------

            "public_ip_type":
                configuration.get(
                    "public_ip_type"
                ),

            "address_source":
                configuration.get(
                    "address_source"
                ),
        }

    # ==============================================================
    # FINDING: UNASSOCIATED
    # ==============================================================

    def _detect_unassociated(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        # We need explicit association evidence.
        if data["associated"] is not False:
            return None

        # Release must be explicitly permitted by the collector.
        if data["release_allowed"] is not True:
            return None

        statements = [
            self._statement(
                name="public_ip",
                value=data["public_ip"],
                path="configuration.public_ip",
                source=[
                    "EC2 DescribeAddresses",
                ],
                observed=(
                    data["public_ip"] is not None
                ),
            ),
            self._statement(
                name="allocation_id",
                value=data["allocation_id"],
                path="configuration.allocation_id",
                source=[
                    "EC2 DescribeAddresses",
                ],
                observed=(
                    data["allocation_id"] is not None
                ),
            ),
            self._statement(
                name="associated",
                value=False,
                path="configuration.associated",
                source=[
                    "EC2 DescribeAddresses",
                ],
                observed=True,
            ),
            self._statement(
                name="release_allowed",
                value=True,
                path="configuration.release_allowed",
                source=[
                    "Collector eligibility evidence",
                ],
                observed=True,
            ),
        ]

        return self._finding(
            context=context,
            finding_type="elastic_ip_unassociated",
            title="Unassociated Elastic IP",
            severity="medium",
            confidence="high",
            reason=(
                "The Elastic IP is explicitly reported as "
                "unassociated and eligible for release review."
            ),
            statements=statements,
            metadata={
                "allocation_id":
                    data["allocation_id"],

                "public_ip":
                    data["public_ip"],

                "associated":
                    False,

                "release_allowed":
                    True,

                "region":
                    context.region,
            },
            limitations=[
                (
                    "The address may still be intentionally "
                    "reserved for failover, DNS, migration, "
                    "or future infrastructure."
                )
            ],
            data=data,
        )

    # ==============================================================
    # FINDING: STOPPED EC2 INSTANCE
    # ==============================================================

    def _detect_stopped_instance(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        # The address must currently be associated.
        if data["associated"] is not True:
            return None

        instance_id = data["instance_id"]

        if not instance_id:
            return None

        # We need an explicitly observed instance state.
        if data["instance_state"] != "stopped":
            return None

        # The collector must explicitly say optimization is allowed.
        if data["optimization_allowed"] is not True:
            return None

        statements = [
            self._statement(
                name="public_ip",
                value=data["public_ip"],
                path="configuration.public_ip",
                source=[
                    "EC2 DescribeAddresses",
                ],
                observed=(
                    data["public_ip"] is not None
                ),
            ),
            self._statement(
                name="allocation_id",
                value=data["allocation_id"],
                path="configuration.allocation_id",
                source=[
                    "EC2 DescribeAddresses",
                ],
                observed=(
                    data["allocation_id"] is not None
                ),
            ),
            self._statement(
                name="instance_id",
                value=instance_id,
                path="configuration.instance_id",
                source=[
                    "EC2 DescribeAddresses",
                    "EC2 DescribeNetworkInterfaces",
                ],
                observed=True,
            ),
            self._statement(
                name="instance_state",
                value="stopped",
                path="configuration.instance_state",
                source=[
                    "EC2 DescribeInstances",
                ],
                observed=True,
            ),
            self._statement(
                name="optimization_allowed",
                value=True,
                path="configuration.optimization_allowed",
                source=[
                    "Collector eligibility evidence",
                ],
                observed=True,
            ),
        ]

        return self._finding(
            context=context,
            finding_type="elastic_ip_on_stopped_instance",
            title="Elastic IP attached to stopped EC2",
            severity="medium",
            confidence="high",
            reason=(
                "The Elastic IP remains attached to an "
                "explicitly identified stopped EC2 instance."
            ),
            statements=statements,
            metadata={
                "allocation_id":
                    data["allocation_id"],

                "public_ip":
                    data["public_ip"],

                "instance_id":
                    instance_id,

                "instance_state":
                    data["instance_state"],

                "region":
                    context.region,
            },
            limitations=[
                (
                    "A stopped instance may intentionally "
                    "retain its address for restart, "
                    "failover, DNS, migration, or another "
                    "static-address dependency."
                )
            ],
            data=data,
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
        statements: list[EvidenceStatement],
        metadata: dict[str, Any],
        limitations: list[str],
        data: dict[str, Any],
    ) -> Finding:

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=(
                context.resource_type
                or "public_ipv4"
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
            limitations=limitations,
            metadata=metadata,
            recommendation_eligible=True,
            # IMPORTANT:
            # Do not set aggregation_scope here.
            #
            # The framework owns aggregation.
        )

    # ==============================================================
    # EVIDENCE
    # ==============================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Evidence:

        configuration = data[
            "configuration"
        ]

        return Evidence(
            metrics={},

            configuration=dict(
                configuration
            ),

            topology=dict(
                context.topology()
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
                key:
                    data.get(key)
                for key in (
                    "public_ip",
                    "allocation_id",
                    "associated",
                    "instance_id",
                    "instance_state",
                    "network_interface_id",
                    "network_interface_type",
                    "requester_managed",
                    "service_managed",
                    "optimization_allowed",
                    "release_allowed",
                    "public_ip_type",
                    "address_source",
                    "vpc_id",
                    "subnet_id",
                    "availability_zone",
                )
            },

            data_quality={
                "configuration_available":
                    bool(configuration),

                "association_data_available":
                    data[
                        "association_data_available"
                    ],

                "instance_state_available":
                    data[
                        "instance_state"
                    ] is not None,

                "optimization_control_available":
                    data[
                        "optimization_allowed"
                    ] is not None,

                "release_control_available":
                    data[
                        "release_allowed"
                    ] is not None,

                "requester_managed_available":
                    data[
                        "requester_managed"
                    ] is not None,

                "service_managed_available":
                    data[
                        "service_managed"
                    ] is not None,
            },
        )

    # ==============================================================
    # ASSOCIATION FALLBACK
    # ==============================================================

    @staticmethod
    def _associated_fallback(
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

        if any(
            value
            for value in (
                association_id,
                network_interface_id,
                instance_id,
            )
        ):
            return True

        # IMPORTANT:
        #
        # Absence of identifiers does NOT prove that the address
        # is unassociated. Return None so the analyzer suppresses
        # the finding instead of guessing.
        return None

    # ==============================================================
    # TYPE HELPERS
    # ==============================================================

    @staticmethod
    def _optional_bool(
        value: Any,
    ) -> bool | None:

        if isinstance(
            value,
            bool,
        ):
            return value

        return None

    @staticmethod
    def _lower(
        value: Any,
    ) -> str | None:

        if value is None:
            return None

        value = str(
            value
        ).strip().lower()

        return value or None

    # ==============================================================
    # EVIDENCE STATEMENT
    # ==============================================================

    @staticmethod
    def _statement(
        *,
        name: str,
        value: Any,
        path: str,
        source: list[str],
        description: str = "",
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

    # ==============================================================
    # OBSERVATION PERIOD
    # ==============================================================

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