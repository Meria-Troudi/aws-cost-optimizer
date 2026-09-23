"""
Public IPv4 cost optimization analyzer.

Purpose
-------
Identify public IPv4 configurations that create a known AWS
public IPv4 cost exposure and determine whether they warrant
cost review.

Findings
--------
1. elastic_ip_unassociated
2. elastic_ip_on_stopped_instance
3. public_ipv4_in_use_review

Important
---------
This analyzer does not calculate savings.

It does not assume that every public IPv4 address is unnecessary.
An associated public IPv4 on a running resource is treated as a
cost-exposure review finding, not as proof of waste.

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

STOPPED_INSTANCE_STATES = frozenset(
    {
        "stopped",
        "stopping",
        "hibernated",
    }
)


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return {}


def _normalise_string(value: Any) -> str | None:
    if value is None:
        return None

    value = str(value).strip().lower()

    return value or None


@register
class IPv4Analyzer(Analyzer):

    name = "ipv4"
    version = "10.0"

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return context.resource_type in SUPPORTED_RESOURCE_TYPES

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        data = self._data(context)

        if not data["configuration_available"]:
            return []

        findings: list[Finding] = []

        finding = self._unassociated_eip(
            context,
            data,
        )

        if finding:
            findings.append(finding)

        finding = self._stopped_eip(
            context,
            data,
        )

        if finding:
            findings.append(finding)

        finding = self._in_use_public_ipv4(
            context,
            data,
        )

        if finding:
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # DATA
    # ------------------------------------------------------------------

    @staticmethod
    def _data(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        configuration = _dict(context.configuration())

        return {
            "configuration_available": bool(configuration),
            "public_ip": configuration.get("public_ip"),
            "allocation_id": configuration.get("allocation_id"),
            "association_id": configuration.get("association_id"),
            "associated": configuration.get("associated"),
            "instance_id": configuration.get("instance_id"),
            "instance_state": _normalise_string(configuration.get("instance_state")),
            "network_interface_id": configuration.get("network_interface_id"),
            "network_interface_type": _normalise_string(
                configuration.get("network_interface_type")
            ),
            "requester_managed": configuration.get("requester_managed"),
            "service_managed": configuration.get("service_managed"),
            "optimization_candidate": configuration.get("optimization_candidate"),
            "release_candidate": configuration.get("release_candidate"),
            "cost_relevant": configuration.get("cost_relevant"),
            "address_source": _normalise_string(configuration.get("address_source")),
            "address_type": _normalise_string(configuration.get("address_type")),
            "public_ip_type": _normalise_string(configuration.get("public_ip_type")),
            "billing_usage_type": configuration.get("billing_usage_type"),
        }

    # ------------------------------------------------------------------
    # RULE 1 — UNASSOCIATED EIP
    # ------------------------------------------------------------------

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

        if data["service_managed"] is True:
            return None

        if data["release_candidate"] is not True:
            return None

        return self._finding(
            context=context,
            finding_type="elastic_ip_unassociated",
            title="Unassociated Elastic IP",
            severity="medium",
            confidence="high",
            reason=(
                "An allocated Elastic IP is not associated with "
                "a resource and is classified as a release candidate."
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
                    data["associated"],
                    "configuration.associated",
                    "Whether the Elastic IP is associated with a resource.",
                ),
                self._statement(
                    "release_candidate",
                    data["release_candidate"],
                    "configuration.release_candidate",
                    "Collector classification indicating that release is a candidate.",
                ),
                self._statement(
                    "billing_usage_type",
                    data["billing_usage_type"],
                    "configuration.billing_usage_type",
                    "Public IPv4 billing classification.",
                ),
            ],
            metadata={
                "optimization_action": "review_and_release",
                "region": context.region,
            },
            data=data,
            cost_optimization_type="elimination",
        )

    # ------------------------------------------------------------------
    # RULE 2 — EIP ON STOPPED INSTANCE
    # ------------------------------------------------------------------

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

        if data["instance_state"] not in STOPPED_INSTANCE_STATES:
            return None

        if data["requester_managed"] is True:
            return None

        if data["service_managed"] is True:
            return None

        return self._finding(
            context=context,
            finding_type="elastic_ip_on_stopped_instance",
            title="Elastic IP on stopped EC2",
            severity="medium",
            confidence="high",
            reason=(
                "An Elastic IP remains associated with a stopped "
                "EC2 instance. Review whether the Elastic IP is "
                "still required."
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
                    "Current EC2 instance state.",
                ),
                self._statement(
                    "billing_usage_type",
                    data["billing_usage_type"],
                    "configuration.billing_usage_type",
                    "Public IPv4 billing classification.",
                ),
            ],
            metadata={
                "optimization_action": "review_eip_association",
                "instance_id": data["instance_id"],
                "region": context.region,
            },
            data=data,
            cost_optimization_type="elimination",
        )

    # ------------------------------------------------------------------
    # RULE 3 — ASSOCIATED PUBLIC IPV4 COST EXPOSURE
    # ------------------------------------------------------------------

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

        if data["service_managed"] is True:
            return None

        if not data["public_ip"]:
            return None

        if data["address_source"] == "elastic_ip":
            if data["instance_state"] in STOPPED_INSTANCE_STATES:
                return None

        return self._finding(
            context=context,
            finding_type="public_ipv4_in_use_review",
            title="Public IPv4 in use",
            severity="low",
            confidence="high",
            reason=(
                "A public IPv4 address is associated with a resource "
                "and creates public IPv4 cost exposure. The evidence "
                "does not establish that the address is unnecessary; "
                "review whether direct public IPv4 connectivity is "
                "required."
            ),
            statements=[
                self._statement(
                    "public_ip",
                    data["public_ip"],
                    "configuration.public_ip",
                    "Public IPv4 address.",
                ),
                self._statement(
                    "associated",
                    data["associated"],
                    "configuration.associated",
                    "Whether the public IPv4 is associated with a resource.",
                ),
                self._statement(
                    "address_source",
                    data["address_source"],
                    "configuration.address_source",
                    "Source of the public IPv4 association.",
                ),
                self._statement(
                    "address_type",
                    data["address_type"],
                    "configuration.address_type",
                    "Public IPv4 address type.",
                ),
                self._statement(
                    "instance_id",
                    data["instance_id"],
                    "configuration.instance_id",
                    "Associated EC2 instance when available.",
                ),
                self._statement(
                    "instance_state",
                    data["instance_state"],
                    "configuration.instance_state",
                    "Current EC2 instance state when available.",
                ),
                self._statement(
                    "network_interface_id",
                    data["network_interface_id"],
                    "configuration.network_interface_id",
                    "Associated network interface when available.",
                ),
                self._statement(
                    "billing_usage_type",
                    data["billing_usage_type"],
                    "configuration.billing_usage_type",
                    "Public IPv4 billing classification.",
                ),
            ],
            metadata={
                "optimization_action": "review_public_ipv4_requirement",
                "instance_id": data["instance_id"],
                "network_interface_id": data["network_interface_id"],
                "address_source": data["address_source"],
                "region": context.region,
            },
            data=data,
            cost_optimization_type="review",
        )

    # ------------------------------------------------------------------
    # FINDING
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
        data: dict[str, Any],
        cost_optimization_type: str = "review",
    ) -> Finding:

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=(context.resource_type or "public_ipv4"),
            resource_id=(context.resource_id or "unknown"),
            analyzer=self.name,
            analyzer_version=self.version,
            severity=severity,
            confidence=confidence,
            reason=reason,
            conditions=statements,
            evidence=self._evidence(
                context,
                data,
            ),
            observation_period=self._observation_period(context),
            metadata=dict(metadata),
            recommendation_eligible=True,
            cost_optimization_type=cost_optimization_type,
        )

    # ------------------------------------------------------------------
    # EVIDENCE
    # ------------------------------------------------------------------

    def _evidence(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Evidence:

        configuration = dict(context.configuration() or {})

        return Evidence(
            metrics={},
            configuration=configuration,
            topology=dict(context.topology() or {}),
            resource={
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "region": context.region,
            },
            derived={
                key: data.get(key)
                for key in (
                    "public_ip",
                    "allocation_id",
                    "association_id",
                    "associated",
                    "instance_id",
                    "instance_state",
                    "address_source",
                    "address_type",
                    "public_ip_type",
                    "billing_usage_type",
                    "network_interface_id",
                    "network_interface_type",
                    "requester_managed",
                    "service_managed",
                )
            },
            data_quality={
                "configuration_available": bool(configuration),
                "public_ip_available": (data["public_ip"] is not None),
                "association_available": (data["associated"] is not None),
                "instance_state_available": (
                    data["instance_state"] is not None or not data["instance_id"]
                ),
                "management_available": (data["requester_managed"] is not None),
                "service_management_available": (data["service_managed"] is not None),
                "billing_classification_available": (
                    data["billing_usage_type"] is not None
                ),
            },
        )

    # ------------------------------------------------------------------
    # STATEMENT
    # ------------------------------------------------------------------

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
            evidence_keys=([path] if path else []),
            observed=True,
        )

    # ------------------------------------------------------------------
    # OBSERVATION PERIOD
    # ------------------------------------------------------------------

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        period = context.period()

        if not period:
            return None

        return ObservationPeriod(
            start=period.get("start"),
            end=period.get("end"),
            duration_seconds=period.get("duration_seconds"),
        )
