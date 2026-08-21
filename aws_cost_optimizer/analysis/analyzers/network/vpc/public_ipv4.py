"""
Public IPv4 cost optimization analyzer.

Findings
--------
1. elastic_ip_unassociated
2. elastic_ip_on_stopped_instance
3. public_ipv4_in_use_review

The analyzer does not calculate savings.

It only identifies public IPv4 configurations that warrant
cost review.

Cost attribution remains handled by the billing/reconciliation layer.
"""

from __future__ import annotations

from typing import Any

from ....base import Analyzer
from ....condition import EvidenceStatement
from ....context import AnalysisContext
from ....evidence import Evidence
from ....finding import Finding, ObservationPeriod
from ....registry import register


SUPPORTED_RESOURCE_TYPES = frozenset(
    {
        "public_ipv4",
        "elastic_ip",
        "ipv4",
    }
)


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


@register
class IPv4Analyzer(Analyzer):

    name = "ipv4"
    version = "9.0"

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            in SUPPORTED_RESOURCE_TYPES
        )

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        data = self._data(
            context
        )

        if not data.get(
            "configuration_available"
        ):
            return []

        findings: list[Finding] = []

        finding = (
            self._unassociated_eip(
                context,
                data,
            )
        )

        if finding:
            findings.append(
                finding
            )

        finding = (
            self._stopped_eip(
                context,
                data,
            )
        )

        if finding:
            findings.append(
                finding
            )

        finding = (
            self._in_use_public_ipv4(
                context,
                data,
            )
        )

        if finding:
            findings.append(
                finding
            )

        return findings

    # ==============================================================
    # DATA
    # ==============================================================

    @staticmethod
    def _data(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        configuration = _dict(
            context.configuration()
        )

        return {
            "configuration_available":
                bool(
                    configuration
                ),

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

            "associated":
                configuration.get(
                    "associated"
                ),

            "instance_id":
                configuration.get(
                    "instance_id"
                ),

            "instance_state":
                str(
                    configuration.get(
                        "instance_state"
                    )
                    or ""
                ).lower()
                or None,

            "network_interface_id":
                configuration.get(
                    "network_interface_id"
                ),

            "requester_managed":
                configuration.get(
                    "requester_managed"
                ),

            "service_managed":
                configuration.get(
                    "service_managed"
                ),

            "optimization_candidate":
                configuration.get(
                    "optimization_candidate"
                ),

            "release_candidate":
                configuration.get(
                    "release_candidate"
                ),

            "cost_relevant":
                configuration.get(
                    "cost_relevant"
                ),

            "address_source":
                str(
                    configuration.get(
                        "address_source"
                    )
                    or ""
                ).lower()
                or None,

            "address_type":
                str(
                    configuration.get(
                        "address_type"
                    )
                    or ""
                ).lower()
                or None,

            "public_ip_type":
                str(
                    configuration.get(
                        "public_ip_type"
                    )
                    or ""
                ).lower()
                or None,

            "billing_usage_type":
                configuration.get(
                    "billing_usage_type"
                ),

            "network_interface_type":
                configuration.get(
                    "network_interface_type"
                ),
        }

    # ==============================================================
    # RULE 1 — UNASSOCIATED EIP
    # ==============================================================

    def _unassociated_eip(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["address_source"] != "elastic_ip":
            return None

        if not data["allocation_id"]:
            return None

        if data["associated"] is not False:
            return None

        if data["requester_managed"] is True:
            return None

        if data["release_candidate"] is not True:
            return None

        return self._finding(
            context=context,

            finding_type=
                "elastic_ip_unassociated",

            title=
                "Unassociated Elastic IP",

            severity=
                "medium",

            confidence=
                "high",

            reason=(
                "An allocated Elastic IP is not associated "
                "with a resource."
            ),

            statements=[
                self._statement(
                    "public_ip",
                    data["public_ip"],
                    "configuration.public_ip",
                    "Public IPv4 address.",
                ),

                self._statement(
                    "allocation_id",
                    data["allocation_id"],
                    "configuration.allocation_id",
                    "Elastic IP allocation.",
                ),

                self._statement(
                    "associated",
                    False,
                    "configuration.associated",
                    "No resource association was discovered.",
                ),

                self._statement(
                    "billing_usage_type",
                    data["billing_usage_type"],
                    "configuration.billing_usage_type",
                    "Public IPv4 billing classification.",
                ),
            ],

            metadata={
                "optimization_action":
                    "review_and_release",

                "region":
                    context.region,
            },

            limitations=[
                (
                    "The address may be intentionally retained "
                    "for failover, migration, DNS, or future use."
                ),
                (
                    "Savings are not calculated without valid "
                    "billing attribution."
                ),
            ],

            data=data,

            cost_optimization_type="elimination",
        )

    # ==============================================================
    # RULE 2 — STOPPED EC2
    # ==============================================================

    def _stopped_eip(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["address_source"] != "elastic_ip":
            return None

        if not data["allocation_id"]:
            return None

        if data["associated"] is not True:
            return None

        if not data["instance_id"]:
            return None

        if data["instance_state"] not in {
            "stopped",
            "stopping",
            "hibernated",
        }:
            return None

        if data["requester_managed"] is True:
            return None

        return self._finding(
            context=context,

            finding_type=
                "elastic_ip_on_stopped_instance",

            title=
                "Elastic IP on stopped EC2",

            severity=
                "medium",

            confidence=
                "high",

            reason=(
                "An Elastic IP remains associated with a "
                "stopped EC2 instance and is therefore "
                "classified as idle public IPv4 usage."
            ),

            statements=[
                self._statement(
                    "public_ip",
                    data["public_ip"],
                    "configuration.public_ip",
                    "Public IPv4 address.",
                ),

                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "Associated EC2 instance.",
                ),

                self._statement(
                    "instance_state",
                    data["instance_state"],
                    "configuration.instance_state",
                    "Current EC2 state.",
                ),

                self._statement(
                    "billing_usage_type",
                    data["billing_usage_type"],
                    "configuration.billing_usage_type",
                    "Public IPv4 billing classification.",
                ),
            ],

            metadata={
                "optimization_action":
                    "review_eip_association",

                "instance_id":
                    data["instance_id"],

                "region":
                    context.region,
            },

            limitations=[
                (
                    "The Elastic IP may be intentionally retained "
                    "for restart, failover, DNS, or migration."
                ),
                (
                    "Stopping the EC2 instance does not prove that "
                    "the address can be released."
                ),
                (
                    "Savings are not calculated without valid "
                    "billing attribution."
                ),
            ],

            data=data,
        )

    # ==============================================================
    # RULE 3 — IN-USE PUBLIC IPV4
    # ==============================================================

    def _in_use_public_ipv4(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["cost_relevant"] is not True:
            return None

        if data["associated"] is not True:
            return None

        if data["requester_managed"] is True:
            return None

        if not data["public_ip"]:
            return None

        if (
            data["address_source"] == "elastic_ip"
            and data["instance_state"]
            in {
                "stopped",
                "stopping",
                "hibernated",
            }
        ):
            return None

        return self._finding(
            context=context,

            finding_type=
                "public_ipv4_in_use_review",

            title=
                "Public IPv4 in use",

            severity=
                "low",

            confidence=
                "high",

            reason=(
                "A public IPv4 address is associated with "
                "a resource and incurs an in-use public IPv4 "
                "charge. Review whether direct public IPv4 "
                "connectivity is required."
            ),

            statements=[
                self._statement(
                    "public_ip",
                    data["public_ip"],
                    "configuration.public_ip",
                    "Public IPv4 address.",
                ),

                self._statement(
                    "address_type",
                    data["address_type"],
                    "configuration.address_type",
                    "Public IPv4 address type.",
                ),

                self._statement(
                    "billing_usage_type",
                    data["billing_usage_type"],
                    "configuration.billing_usage_type",
                    "Public IPv4 billing classification.",
                ),
            ],

            metadata={
                "optimization_action":
                    "review_public_ipv4_requirement",

                "instance_id":
                    data["instance_id"],

                "network_interface_id":
                    data["network_interface_id"],

                "region":
                    context.region,
            },

            limitations=[
                (
                    "The public IPv4 address may be required "
                    "for application connectivity."
                ),
                (
                    "Removing it may require architectural "
                    "changes such as a load balancer or "
                    "private connectivity."
                ),
                (
                    "No savings are claimed from inventory "
                    "alone."
                ),
            ],

            data=data,
        )

    # ==============================================================
    # FINDING
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
        metadata: dict[str, Any],
        limitations: list[str],
        data: dict[str, Any],
        cost_optimization_type: str = "review",
    ) -> Finding:

        return Finding(
            finding_type=
                finding_type,

            title=
                title,

            resource_type=(
                context.resource_type
                or "public_ipv4"
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
                severity,

            confidence=
                confidence,

            reason=
                reason,

            conditions=
                statements,

            evidence=
                self._evidence(
                    context,
                    data,
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
                dict(
                    metadata
                ),

            recommendation_eligible=
                True,

            cost_optimization_type=
                cost_optimization_type,
        )

    # ==============================================================
    # EVIDENCE
    # ==============================================================

    def _evidence(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Evidence:

        configuration = dict(
            data.get(
                "configuration",
                context.configuration(),
            )
            or {}
        )

        return Evidence(
            metrics={},

            configuration=
                configuration,

            topology=
                dict(
                    context.topology()
                    or {}
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
                    data.get(
                        key
                    )
                for key
                in (
                    "public_ip",
                    "allocation_id",
                    "associated",
                    "instance_id",
                    "instance_state",
                    "address_source",
                    "address_type",
                    "public_ip_type",
                    "billing_usage_type",
                    "network_interface_id",
                    "requester_managed",
                    "service_managed",
                )
            },

            data_quality={
                "configuration_available":
                    bool(
                        configuration
                    ),

                "public_ip_available":
                    data["public_ip"]
                    is not None,

                "association_available":
                    data["associated"]
                    is not None,

                "instance_state_available":
                    (
                        data["instance_state"]
                        is not None
                        or not data["instance_id"]
                    ),

                "management_available":
                    data["requester_managed"]
                    is not None,

                "billing_classification_available":
                    data["billing_usage_type"]
                    is not None,
            },
        )

    # ==============================================================
    # STATEMENT
    # ==============================================================

    @staticmethod
    def _statement(
        name: str,
        value: Any,
        path: str,
        description: str,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=[
                "AWS EC2 API",
                "collector-derived evidence",
            ],
            evidence_keys=[
                path
            ] if path else [],
            observed=True,
        )

    # ==============================================================
    # OBSERVATION PERIOD
    # ==============================================================

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        period = context.period()

        if not period:
            return None

        return ObservationPeriod(
            start=
                period.get(
                    "start"
                ),

            end=
                period.get(
                    "end"
                ),

            duration_seconds=
                period.get(
                    "duration_seconds"
                ),
        )