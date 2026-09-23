"""
AWS VPC Endpoint cost/configuration analyzer.

Purpose
-------
Generate evidence-based AWS VPC Endpoint findings.

Analyzer responsibilities
-------------------------
This analyzer evaluates:

1. Endpoint operational state
2. Gateway endpoint route coverage
3. Interface endpoint ENI inventory consistency
4. Billing/resource reconciliation when explicit billing evidence exists
5. Historical billing that cannot be attributed to the current endpoint

Important principles
--------------------
- Findings must be supported by collected evidence.
- Billing must not be attributed to a current endpoint unless the
  evidence supports that attribution.
- Historical billing must not be presented as current-resource cost.
- Missing telemetry must not be interpreted as zero usage.
- Configuration/topology problems are findings, not automatic
  optimization recommendations.
- This analyzer stops at findings. Recommendation generation is
  handled separately.
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
    version = "6.0"

    RESOURCE_TYPE = "vpc_endpoint"

    NON_OPERATIONAL_STATES = {
        "failed",
        "rejected",
        "expired",
        "error",
        "partial",
    }

    SUPPORTED_ENDPOINT_TYPES = {
        "Gateway",
        "Interface",
    }

    # ------------------------------------------------------------------
    # Analyzer entry point
    # ------------------------------------------------------------------

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return context.resource_type == self.RESOURCE_TYPE

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        if not self._analysis_data_available(context):
            return []

        findings: list[Finding] = []

        checks = (
            self._check_non_operational,
            self._check_gateway_missing_routes,
            self._check_gateway_partial_coverage,
            self._check_interface_eni_mismatch,
            self._check_billing_reconciliation,
        )

        for check in checks:

            finding = check(context)

            if finding is not None:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:

        return value if isinstance(value, dict) else {}

    @classmethod
    def _configuration(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(context.configuration())

    @classmethod
    def _topology(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(context.topology())

    @classmethod
    def _resource(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(context.resource)

    @classmethod
    def _collection_status(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return cls._dict(cls._resource(context).get("collection_status"))

    @classmethod
    def _endpoint_type(
        cls,
        context: AnalysisContext,
    ) -> str | None:

        configuration = cls._configuration(context)

        identity = cls._dict(cls._resource(context).get("identity"))

        value = configuration.get("endpoint_type") or identity.get("endpoint_type")

        if value is None:
            return None

        value = str(value).strip()

        if not value:
            return None

        # Normalize common AWS representations.
        normalized = value.lower()

        if normalized == "gateway":
            return "Gateway"

        if normalized == "interface":
            return "Interface"

        return value

    @classmethod
    def _state(
        cls,
        context: AnalysisContext,
    ) -> str | None:

        configuration = cls._configuration(context)

        identity = cls._dict(cls._resource(context).get("identity"))

        value = configuration.get("state") or identity.get("state")

        if value is None:
            return None

        value = str(value).strip().lower()

        return value or None

    @classmethod
    def _service_name(
        cls,
        context: AnalysisContext,
    ) -> str | None:

        configuration = cls._configuration(context)

        identity = cls._dict(cls._resource(context).get("identity"))

        value = configuration.get("service_name") or identity.get("service_name")

        if value is None:
            return None

        value = str(value).strip()

        return value or None

    @classmethod
    def _analysis_data_available(
        cls,
        context: AnalysisContext,
    ) -> bool:

        configuration = cls._configuration(context)

        if not configuration:
            return False

        state = cls._state(context)

        # Deleted resources should not be analyzed as current resources.
        #
        # Historical billing reconciliation is intentionally handled
        # elsewhere because a deleted endpoint is no longer current
        # inventory.
        if state in {
            "deleted",
            "deleting",
        }:
            return False

        return True

    # ------------------------------------------------------------------
    # Collection completeness
    # ------------------------------------------------------------------

    @classmethod
    def _topology_complete(
        cls,
        context: AnalysisContext,
    ) -> bool:

        status = cls._collection_status(context)

        if status.get("complete_for_analysis") is not True:
            return False

        if status.get("topology") != "ok":
            return False

        if status.get("relationships") != "ok":
            return False

        endpoint_type = cls._endpoint_type(context)

        if endpoint_type == "Gateway":
            return status.get("gateway_route_context") == "ok"

        return True

    @classmethod
    def _network_interfaces_complete(
        cls,
        context: AnalysisContext,
    ) -> bool:

        status = cls._collection_status(context)

        return status.get("network_interfaces") == "ok"

    # ------------------------------------------------------------------
    # Finding 1: non-operational endpoint
    # ------------------------------------------------------------------

    def _check_non_operational(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        state = self._state(context)

        if state not in self.NON_OPERATIONAL_STATES:
            return None

        configuration = self._configuration(context)

        failure_reason = configuration.get("last_error") or configuration.get(
            "failure_reason"
        )

        statements = [
            self._statement(
                name="endpoint_state",
                value=state,
                description="Current VPC endpoint state.",
                source=["AWS VPC endpoint configuration"],
                observed=True,
            )
        ]

        if failure_reason:

            statements.append(
                self._statement(
                    name="failure_reason",
                    value=failure_reason,
                    description="Reported endpoint failure reason.",
                    source=["AWS VPC endpoint configuration"],
                    observed=True,
                )
            )

        return self._finding(
            context=context,
            finding_type="vpc_endpoint_non_operational",
            title="VPC endpoint is not operational",
            severity="medium",
            confidence="high",
            reason=(f"The VPC endpoint is currently in " f"the '{state}' state."),
            statements=statements,
            metadata={
                "state": state,
                "service_name": self._service_name(context),
                "endpoint_type": self._endpoint_type(context),
                "failure_reason": failure_reason,
            },
        )

    # ------------------------------------------------------------------
    # Finding 2: gateway endpoint has no routes
    # ------------------------------------------------------------------

    def _check_gateway_missing_routes(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if self._endpoint_type(context) != "Gateway":
            return None

        if not self._topology_complete(context):
            return None

        topology = self._topology(context)

        route_tables = self._dict(topology.get("route_tables"))

        gateway = self._dict(topology.get("gateway_endpoint"))

        configured = self._string_list(route_tables.get("configured_route_table_ids"))

        covered = self._string_list(gateway.get("route_table_ids"))

        if not configured:
            return None

        if covered:
            return None

        return self._finding(
            context=context,
            finding_type=("vpc_endpoint_gateway_missing_route"),
            title=("Gateway endpoint has no observed route coverage"),
            severity="medium",
            confidence="high",
            reason=(
                "The gateway endpoint has configured route tables, "
                "but none of those route tables has an observed "
                "route targeting this endpoint."
            ),
            statements=[
                self._statement(
                    name="configured_route_tables",
                    value=configured,
                    description=(
                        "Route tables associated with the " "gateway endpoint."
                    ),
                    source=["AWS VPC endpoint configuration"],
                    observed=True,
                ),
                self._statement(
                    name="covered_route_tables",
                    value=[],
                    description=(
                        "Configured route tables with an observed "
                        "route targeting the gateway endpoint."
                    ),
                    source=["AWS VPC route topology"],
                    observed=True,
                ),
            ],
            metadata={
                "service_name": self._service_name(context),
                "configured_route_table_count": len(configured),
                "covered_route_table_count": 0,
            },
        )

    # ------------------------------------------------------------------
    # Finding 3: gateway endpoint partial route coverage
    # ------------------------------------------------------------------

    def _check_gateway_partial_coverage(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if self._endpoint_type(context) != "Gateway":
            return None

        if not self._topology_complete(context):
            return None

        topology = self._topology(context)

        route_tables = self._dict(topology.get("route_tables"))

        gateway = self._dict(topology.get("gateway_endpoint"))

        configured = self._string_list(route_tables.get("configured_route_table_ids"))

        covered = self._string_list(gateway.get("route_table_ids"))

        if not configured:
            return None

        configured_set = set(configured)
        covered_set = set(covered)

        missing = sorted(configured_set - covered_set)

        if not missing:
            return None

        # If there is zero coverage, the dedicated
        # missing-route finding handles it.
        if not covered_set:
            return None

        return self._finding(
            context=context,
            finding_type=("vpc_endpoint_gateway_partial_route_coverage"),
            title=("Gateway endpoint has partial route coverage"),
            severity="low",
            confidence="high",
            reason=(
                f"{len(covered_set)} of "
                f"{len(configured_set)} configured route tables "
                "have an observed route targeting the "
                "gateway endpoint."
            ),
            statements=[
                self._statement(
                    name="route_table_coverage",
                    value={
                        "configured": len(configured_set),
                        "covered": len(covered_set),
                        "missing": len(missing),
                    },
                    description=("Observed gateway endpoint " "route-table coverage."),
                    source=[
                        "AWS VPC endpoint configuration",
                        "AWS VPC route topology",
                    ],
                    observed=True,
                ),
                self._statement(
                    name="uncovered_route_tables",
                    value=missing,
                    description=(
                        "Configured route tables without "
                        "an observed route targeting "
                        "the endpoint."
                    ),
                    source=["AWS VPC route topology"],
                    observed=True,
                ),
            ],
            metadata={
                "service_name": self._service_name(context),
                "configured_route_table_count": len(configured_set),
                "covered_route_table_count": len(covered_set),
                "uncovered_route_table_ids": missing,
            },
        )

    # ------------------------------------------------------------------
    # Finding 4: interface endpoint ENI mismatch
    # ------------------------------------------------------------------

    def _check_interface_eni_mismatch(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if self._endpoint_type(context) != "Interface":
            return None

        if not self._topology_complete(context):
            return None

        if not self._network_interfaces_complete(context):
            return None

        if self._state(context) != "available":
            return None

        configuration = self._configuration(context)

        configured_ids = self._string_list(configuration.get("network_interface_ids"))

        if not configured_ids:
            return None

        resource = self._resource(context)

        network_interfaces = self._dict(resource.get("network_interfaces"))

        observed_resources = network_interfaces.get("resources")

        if not isinstance(
            observed_resources,
            list,
        ):
            return None

        observed_ids = self._string_list(
            [
                item.get("network_interface_id")
                for item in observed_resources
                if isinstance(item, dict)
            ]
        )

        configured_set = set(configured_ids)
        observed_set = set(observed_ids)

        missing = sorted(configured_set - observed_set)

        unexpected = sorted(observed_set - configured_set)

        if not missing and not unexpected:
            return None

        if missing and not unexpected:

            mismatch_type = "missing"

            reason = (
                f"{len(missing)} configured endpoint ENI(s) "
                "were not returned by network-interface inventory."
            )

        elif unexpected and not missing:

            mismatch_type = "unexpected"

            reason = (
                f"{len(unexpected)} network interface(s) were "
                "observed but are not listed on the endpoint "
                "configuration."
            )

        else:

            mismatch_type = "mixed"

            reason = (
                f"{len(missing)} configured endpoint ENI(s) "
                "are missing from inventory and "
                f"{len(unexpected)} unexpected ENI(s) "
                "were observed."
            )

        return self._finding(
            context=context,
            finding_type=("vpc_endpoint_interface_eni_mismatch"),
            title=("Interface endpoint ENI inventory mismatch"),
            severity="medium",
            confidence="high",
            reason=reason,
            statements=[
                self._statement(
                    name="configured_network_interfaces",
                    value={
                        "count": len(configured_set),
                        "ids": sorted(configured_set),
                    },
                    description=("Network interfaces configured " "for the endpoint."),
                    source=["AWS VPC endpoint configuration"],
                    observed=True,
                ),
                self._statement(
                    name="observed_network_interfaces",
                    value={
                        "count": len(observed_set),
                        "ids": sorted(observed_set),
                    },
                    description=("Network interfaces returned " "by inventory."),
                    source=["AWS EC2 network-interface inventory"],
                    observed=True,
                ),
                self._statement(
                    name="missing_network_interfaces",
                    value=missing,
                    description=("Configured endpoint ENIs not " "found in inventory."),
                    source=["AWS EC2 network-interface inventory"],
                    observed=True,
                ),
                self._statement(
                    name="unexpected_network_interfaces",
                    value=unexpected,
                    description=(
                        "Observed ENIs not present in " "the endpoint configuration."
                    ),
                    source=["AWS EC2 network-interface inventory"],
                    observed=True,
                ),
            ],
            metadata={
                "service_name": self._service_name(context),
                "configured_eni_count": len(configured_set),
                "observed_eni_count": len(observed_set),
                "missing_eni_ids": missing,
                "unexpected_eni_ids": unexpected,
                "mismatch_type": mismatch_type,
            },
        )

    # ------------------------------------------------------------------
    # Finding 5: billing/resource reconciliation
    # ------------------------------------------------------------------

    def _check_billing_reconciliation(
        self,
        context: AnalysisContext,
    ) -> Finding | None:
        """
        Detect explicit billing/resource reconciliation problems.

        This check is intentionally conservative.

        It DOES NOT assume that any VPC Endpoint Hours cost belongs
        to the current endpoint.

        A finding is generated only when the billing evidence explicitly
        indicates that the billed resource cannot be reconciled with
        the current resource.

        Supported evidence patterns are intentionally flexible because
        billing schemas can evolve between collectors.
        """

        billing = _safe_dict(context.billing())

        if not billing:
            return None

        resource_id = context.resource_id or self._resource(context).get("resource_id")

        if not resource_id:
            return None

        reconciliation = self._billing_reconciliation(billing)

        if reconciliation is None:
            return None

        status = reconciliation.get("status")

        if status not in {
            "historical_only",
            "unmatched",
        }:
            return None

        cost = reconciliation.get("cost")

        usage_type = reconciliation.get("usage_type")

        billing_resource_id = reconciliation.get("resource_id")

        period = reconciliation.get("period")

        if status == "historical_only":

            title = (
                "VPC endpoint billing is historical and "
                "cannot be attributed to the current endpoint"
            )

            reason = (
                "Billing evidence exists for a VPC endpoint "
                "but the billed resource cannot be reconciled "
                "to the currently discovered endpoint."
            )

        else:

            title = (
                "VPC endpoint billing cannot be reconciled " "with the current resource"
            )

            reason = (
                "Billing evidence exists for VPC endpoint usage, "
                "but the billed resource identifier does not match "
                "the currently discovered endpoint."
            )

        statements = [
            self._statement(
                name="current_resource_id",
                value=resource_id,
                description=("Currently discovered VPC endpoint."),
                source=["AWS VPC endpoint inventory"],
                observed=True,
            ),
            self._statement(
                name="billing_reconciliation_status",
                value=status,
                description=("Billing-to-resource reconciliation result."),
                source=["AWS billing evidence"],
                observed=True,
            ),
        ]

        if billing_resource_id:

            statements.append(
                self._statement(
                    name="billing_resource_id",
                    value=billing_resource_id,
                    description=(
                        "Resource identifier associated with " "the billing evidence."
                    ),
                    source=["AWS billing evidence"],
                    observed=True,
                )
            )

        if usage_type:

            statements.append(
                self._statement(
                    name="billing_usage_type",
                    value=usage_type,
                    description=(
                        "Billing usage type associated with " "the endpoint charge."
                    ),
                    source=["AWS billing evidence"],
                    observed=True,
                )
            )

        if cost is not None:

            statements.append(
                self._statement(
                    name="billing_cost",
                    value=cost,
                    description=(
                        "Billing cost represented by the "
                        "reconciled billing evidence."
                    ),
                    source=["AWS billing evidence"],
                    observed=True,
                )
            )

        if period:

            statements.append(
                self._statement(
                    name="billing_period",
                    value=period,
                    description=("Billing observation period."),
                    source=["AWS billing evidence"],
                    observed=True,
                )
            )

        return self._finding(
            context=context,
            finding_type=(
                "vpc_endpoint_historical_billing_without_current_resource"
                if status == "historical_only"
                else "vpc_endpoint_billing_resource_mismatch"
            ),
            title=title,
            severity="low",
            confidence="high",
            reason=reason,
            statements=statements,
            metadata={
                "current_resource_id": resource_id,
                "billing_resource_id": billing_resource_id,
                "billing_reconciliation_status": status,
                "usage_type": usage_type,
                "cost": cost,
                "period": period,
                "service_name": self._service_name(context),
                "endpoint_type": self._endpoint_type(context),
            },
        )

    # ------------------------------------------------------------------
    # Billing helpers
    # ------------------------------------------------------------------

    @classmethod
    def _billing_reconciliation(
        cls,
        billing: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Normalize explicit billing reconciliation evidence.

        Accepted forms include:

        {
            "reconciliation": {
                "status": "historical_only",
                "resource_id": "...",
                "usage_type": "...",
                "cost": 73.79,
                "period": {...}
            }
        }

        or:

        {
            "reconciliation_status": "historical_only",
            "resource_id": "...",
            "usage_type": "...",
            "cost": 73.79
        }

        The analyzer deliberately does not infer historical-only status
        from cost alone.
        """

        reconciliation = billing.get("reconciliation")

        if isinstance(
            reconciliation,
            dict,
        ):

            status = reconciliation.get("status")

            if status is None:
                status = reconciliation.get("reconciliation_status")

            if status is None:
                return None

            return {
                "status": str(status).strip().lower(),
                "resource_id": (
                    reconciliation.get("resource_id")
                    or reconciliation.get("billed_resource_id")
                ),
                "usage_type": (
                    reconciliation.get("usage_type")
                    or reconciliation.get("usage_type_group")
                ),
                "cost": (
                    reconciliation.get("cost")
                    if reconciliation.get("cost") is not None
                    else reconciliation.get("amount")
                ),
                "period": reconciliation.get("period"),
            }

        status = billing.get("reconciliation_status") or billing.get(
            "resource_reconciliation_status"
        )

        if status is None:
            return None

        return {
            "status": str(status).strip().lower(),
            "resource_id": (
                billing.get("resource_id") or billing.get("billed_resource_id")
            ),
            "usage_type": (
                billing.get("usage_type") or billing.get("usage_type_group")
            ),
            "cost": (
                billing.get("cost")
                if billing.get("cost") is not None
                else billing.get("amount")
            ),
            "period": billing.get("period"),
        }

    # ------------------------------------------------------------------
    # Finding construction
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
            resource_type=(context.resource_type or self.RESOURCE_TYPE),
            resource_id=(context.resource_id or "unknown"),
            analyzer=self.name,
            analyzer_version=self.version,
            severity=str(severity).lower(),
            confidence=str(confidence).lower(),
            reason=reason,
            conditions=statements,
            evidence=self._build_evidence(context),
            observation_period=(self._observation_period(context)),
            metadata=dict(metadata),
            recommendation_eligible=False,
            impact={},
        )

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def _build_evidence(
        self,
        context: AnalysisContext,
    ) -> Evidence:

        configuration = self._configuration(context)

        topology = self._topology(context)

        collection_status = self._collection_status(context)

        metrics = {name: context.metric_summary(name) for name in context.metrics()}

        return Evidence(
            metrics=metrics,
            configuration={
                key: value
                for key, value in configuration.items()
                if key
                not in {
                    "policy_document",
                    "dns_entries",
                    "tags",
                }
            },
            topology={
                key: value
                for key, value in topology.items()
                if key
                in {
                    "status",
                    "collection_status",
                    "route_tables",
                    "gateway_endpoint",
                    "interface_endpoint",
                    "network_interfaces",
                    "subnets",
                    "availability_zones",
                }
            },
            resource={
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "region": context.region,
                "service_name": self._service_name(context),
                "endpoint_type": self._endpoint_type(context),
                "state": self._state(context),
            },
            derived={
                "endpoint_type": self._endpoint_type(context),
                "service_name": self._service_name(context),
                "state": self._state(context),
                "collection_status": collection_status,
            },
            billing=_safe_dict(context.billing()),
            data_quality={
                "topology_available": (topology.get("status") == "ok"),
                "relationship_data_available": (
                    collection_status.get("relationships") == "ok"
                ),
                "network_interfaces_available": (
                    collection_status.get("network_interfaces") == "ok"
                ),
                "analysis_complete": (collection_status.get("complete_for_analysis")),
            },
        )

    # ------------------------------------------------------------------
    # Observation period
    # ------------------------------------------------------------------

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        cloudwatch = _safe_dict(context.cloudwatch())

        start = cloudwatch.get("start") or cloudwatch.get("metric_start")

        end = cloudwatch.get("end") or cloudwatch.get("metric_end")

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
            start=value.get("start"),
            end=value.get("end"),
            duration_seconds=value.get("duration_seconds"),
        )

    # ------------------------------------------------------------------
    # Statement construction
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _string_list(
        value: Any,
    ) -> list[str]:

        if not isinstance(
            value,
            list,
        ):
            return []

        result: list[str] = []

        seen: set[str] = set()

        for item in value:

            if item is None:
                continue

            text = str(item).strip()

            if not text:
                continue

            if text in seen:
                continue

            seen.add(text)

            result.append(text)

        return result


def _safe_dict(
    value: Any,
) -> dict[str, Any]:

    return value if isinstance(value, dict) else {}
