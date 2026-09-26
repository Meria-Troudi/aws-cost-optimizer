"""
AWS Transit Gateway cost-optimization analyzer.

Purpose
-------
Generate evidence-based AWS Transit Gateway cost findings.

Core philosophy
---------------
The analyzer separates:

1. Cost existence
2. Structural utilization
3. Observed traffic

The analyzer MUST NOT recommend removal merely because:
- Transit Gateway has a cost
- TransitGateway-Bytes billing exists
- traffic is low
- route tables exist
- associations exist
- propagations exist
- telemetry is missing
- billing cannot be perfectly attributed to attachments

Actionable findings
-------------------
1. transit_gateway_no_attachments
   -> No Transit Gateway attachments were found.
   -> Review whether the Transit Gateway is still required.
   -> This is a REVIEW/REMOVAL candidate, not an automatic deletion.

2. transit_gateway_low_utilization
   -> Attachments exist, but complete attachment-level traffic
      telemetry shows no meaningful traffic during the analysis period.
   -> Review Transit Gateway utilization and architecture.
   -> Do NOT directly recommend deleting the Transit Gateway.

No finding
----------
If:
- attachments exist, and
- complete attachment-level traffic telemetry shows meaningful traffic

then the Transit Gateway is actively used and no cost-optimization
finding is emitted.

Evidence rules
--------------
- Billing confirms cost exists.
- Attachment inventory confirms structural usage.
- CloudWatch confirms observed traffic.
- Missing CloudWatch data is NOT zero traffic.
- Incomplete CloudWatch data is NOT zero traffic.
- Zero traffic requires complete telemetry.
- Low/no traffic is a REVIEW signal, not proof that removal is safe.
- Service-level billing is not treated as exact per-attachment cost.
- The analyzer never invents savings.
- The analyzer never invents replacement architecture.
- The analyzer never assumes deletion is safe.
- Every emitted optimization Finding has recommendation_eligible=True.
- No diagnostic/data-quality Finding is emitted.
"""

from __future__ import annotations

from typing import Any

from ....base import Analyzer
from ....condition import EvidenceStatement
from ....context import AnalysisContext
from ....evidence import Evidence
from ....finding import Finding
from ....registry import register

# CONSTANTS

# Operational threshold (NOT a pricing threshold): combined attachment
# traffic <= 1 GiB over the whole period = "no meaningful traffic".
DEFAULT_MEANINGFUL_TRAFFIC_GIB = 1.0


# GENERIC HELPERS


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _non_negative(value: Any) -> float | None:
    number = _number(value)

    if number is None:
        return None

    if number < 0:
        return None

    return number


def _state(value: Any) -> str:
    return str(value or "").strip().lower()


# CONTEXT


def _relationships(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(context.resource.get("relationships"))


def _cloudwatch(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(context.cloudwatch())


def _billing(
    context: AnalysisContext,
) -> dict[str, Any]:

    try:
        return _dict(context.billing())
    except Exception:
        return {}


def _collection_status(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(_relationships(context).get("collection_status"))


# ATTACHMENTS


def _attachments(
    context: AnalysisContext,
) -> list[dict[str, Any]]:

    relationships = _relationships(context)

    values = relationships.get("attachments")

    if isinstance(values, list):
        return [item for item in values if isinstance(item, dict)]

    # Compatibility fallback for older collectors.
    result: list[dict[str, Any]] = []

    for key in (
        "vpc_attachments",
        "peering_attachments",
        "other_attachments",
    ):
        values = relationships.get(key, [])

        if not isinstance(values, list):
            continue

        result.extend(item for item in values if isinstance(item, dict))

    return result


def _active_attachments(
    context: AnalysisContext,
) -> list[dict[str, Any]]:
    """
    Return attachments that are currently able to participate
    in traffic analysis.

    Structural attachment existence is handled separately by
    _attachments().

    Therefore:
        attachment exists != active attachment
    """

    return [
        attachment
        for attachment in _attachments(context)
        if _state(attachment.get("state")) == "available"
    ]


def _attachment_id(
    attachment: dict[str, Any],
) -> str | None:

    value = (
        attachment.get("attachment_id")
        or attachment.get("transit_gateway_attachment_id")
        or attachment.get("id")
    )

    if not value:
        return None

    return str(value)


# CLOUDWATCH STRUCTURE


def _attachment_metrics(
    context: AnalysisContext,
) -> dict[str, Any]:

    cloudwatch = _cloudwatch(context)

    values = cloudwatch.get("attachments")

    if isinstance(values, dict):
        return values

    # Compatibility fallback.
    values = cloudwatch.get("attachment_metrics")

    if isinstance(values, dict):
        return values

    return {}


# METRIC HELPERS


def _metric_total(
    metric: Any,
) -> float | None:

    # Normal collector representation.
    if isinstance(metric, dict):

        for key in (
            "total",
            "sum",
            "value",
        ):
            value = _non_negative(metric.get(key))

            if value is not None:
                return value

        return None

    # Compatibility with a direct numeric metric.
    return _non_negative(metric)


def _metric_has_data(
    metric: Any,
) -> bool:

    if not isinstance(metric, dict):
        return False

    if metric.get("has_data") is True:
        return True

    return _metric_total(metric) is not None


def _metric_complete(
    metric: Any,
) -> bool:

    if not isinstance(metric, dict):
        return False

    # Explicit collector-level completeness wins.
    if metric.get("complete") is True:
        return True

    # Otherwise require actual metric data and successful
    # collection status.
    return metric.get("has_data") is True and _state(metric.get("status")) == "ok"


# ATTACHMENT TRAFFIC


def _attachment_traffic(
    context: AnalysisContext,
    attachment_id: str,
) -> dict[str, Any] | None:
    """
    Return normalized traffic evidence for one attachment.

    None means that the evidence is insufficient.

    Critical semantics:

        missing telemetry   != zero traffic
        no-data             != zero traffic
        incomplete telemetry != zero traffic

    Zero traffic is valid only when BOTH BytesIn and BytesOut
    metrics are complete and explicitly contain zero data.
    """

    metrics = _attachment_metrics(context)

    values = metrics.get(attachment_id)

    if not isinstance(values, dict):
        return None

    bytes_in_metric = values.get("bytes_in")
    bytes_out_metric = values.get("bytes_out")

    # Both metrics must exist as evidence objects.
    if not isinstance(bytes_in_metric, dict):
        return None

    if not isinstance(bytes_out_metric, dict):
        return None

    # Both metrics must be complete.
    bytes_in_complete = _metric_complete(bytes_in_metric)

    bytes_out_complete = _metric_complete(bytes_out_metric)

    if not bytes_in_complete:
        return None

    if not bytes_out_complete:
        return None

    bytes_in = _metric_total(bytes_in_metric)

    bytes_out = _metric_total(bytes_out_metric)

    # Complete does not allow us to invent a zero if the collector
    # did not provide a usable value.
    if bytes_in is None:
        return None

    if bytes_out is None:
        return None

    observed_bytes = bytes_in + bytes_out

    return {
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "observed_bytes": observed_bytes,
        "observed_gib": observed_bytes / (1024**3),
        "complete": True,
        "bytes_in_complete": True,
        "bytes_out_complete": True,
    }


def _collect_attachment_traffic(
    context: AnalysisContext,
) -> list[dict[str, Any]] | None:
    """
    Collect complete traffic evidence for every active attachment.

    Returns:
        list -> complete evidence exists
        None -> evidence is insufficient

    The function deliberately fails closed.
    """

    active = _active_attachments(context)

    rows: list[dict[str, Any]] = []

    for attachment in active:

        attachment_id = _attachment_id(attachment)

        if not attachment_id:
            return None

        traffic = _attachment_traffic(
            context,
            attachment_id,
        )

        # Missing/incomplete telemetry means that the utilization
        # conclusion cannot be made.
        if traffic is None:
            return None

        rows.append(
            {
                "attachment_id": attachment_id,
                "resource_id": attachment.get("resource_id"),
                "resource_type": attachment.get("resource_type"),
                "classification": attachment.get("classification"),
                "state": attachment.get("state"),
                "bytes_in": traffic["bytes_in"],
                "bytes_out": traffic["bytes_out"],
                "observed_bytes": traffic["observed_bytes"],
                "observed_gib": traffic["observed_gib"],
                "traffic_complete": True,
            }
        )

    return rows


def _total_attachment_traffic_gib(
    rows: list[dict[str, Any]],
) -> float:

    return sum(_non_negative(row.get("observed_gib")) or 0.0 for row in rows)


# BILLING


def _tgw_cost(
    context: AnalysisContext,
) -> float:

    billing = _billing(context)

    return _non_negative(billing.get("amount")) or 0.0


def _has_tgw_cost(
    context: AnalysisContext,
) -> bool:

    return _tgw_cost(context) > 0


# ANALYZER CONFIGURATION


def _analyzer_config(
    context: AnalysisContext,
) -> dict[str, Any]:

    resource = _dict(context.resource)

    for key in (
        "analyzer_config",
        "optimization_config",
    ):

        value = resource.get(key)

        if isinstance(value, dict):
            return value

    return {}


def _meaningful_traffic_threshold_gib(
    context: AnalysisContext,
) -> float:

    config = _analyzer_config(context)

    value = _non_negative(config.get("meaningful_traffic_gib"))

    if value is None:
        value = _non_negative(config.get("low_traffic_gib"))

    if value is None:
        return DEFAULT_MEANINGFUL_TRAFFIC_GIB

    return value


# FINDING FACTORY


def _finding(
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

    billing = _billing(context)

    relationships = _relationships(context)

    observations = _cloudwatch(context)

    return Finding(
        finding_type=finding_type,
        title=title,
        resource_type=(context.resource_type or "transit_gateway"),
        resource_id=(context.resource_id or "unknown"),
        analyzer="transit_gateway",
        analyzer_version="15.0",
        severity=severity.lower(),
        confidence=confidence.lower(),
        reason=reason,
        conditions=statements,
        evidence=Evidence(
            metrics={
                "cloudwatch": observations,
            },
            configuration={},
            topology={
                "relationships": relationships,
            },
            resource={
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "region": context.region,
            },
            derived={
                **metadata,
                "optimization_rule": finding_type,
                "cost_confirmed": True,
                "finding_is_actionable": True,
            },
            billing=billing,
            data_quality={
                "collection_status": _collection_status(context),
            },
        ),
        observation_period=None,
        metadata={
            **metadata,
            "cost_optimization": True,
            "recommendation_required": True,
        },
        recommendation_eligible=True,
        impact={},
    )


# ANALYZER


@register
class TransitGatewayAnalyzer(Analyzer):

    name = "transit_gateway"

    version = "15.0"

    SUPPORTED_RESOURCE_TYPES = {
        "transit_gateway",
    }

    # SUPPORT

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return context.resource_type in self.SUPPORTED_RESOURCE_TYPES

    # MAIN

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        # HARD COST GATE

        if not _has_tgw_cost(context):
            return []

        # STRUCTURAL EVIDENCE

        findings: list[Finding] = []

        no_attachment_finding = self._no_attachments(context)

        if no_attachment_finding is not None:
            findings.append(no_attachment_finding)

            # No attachments means utilization analysis is not
            # applicable.
            return findings

        # UTILIZATION ANALYSIS

        low_utilization_finding = self._low_utilization(context)

        if low_utilization_finding is not None:
            findings.append(low_utilization_finding)

        return findings

    # RULE 1 — NO ATTACHMENTS

    def _no_attachments(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        status = _collection_status(context)

        # Fail closed.
        #
        # Missing/unknown attachment inventory must never be
        # interpreted as zero attachments.
        if status.get("attachments_complete") is not True:
            return None

        attachments = _attachments(context)

        # Any discovered attachment means the TGW is structurally
        # used. Do not classify it as unused.
        if attachments:
            return None

        cost = _tgw_cost(context)

        return _finding(
            context=context,
            finding_type="transit_gateway_no_attachments",
            title="Review Transit Gateway removal",
            severity="high",
            confidence="high",
            reason=(
                f"Transit Gateway billing confirms "
                f"${cost:,.2f} of Transit Gateway cost, "
                "but the completed attachment inventory "
                "contains no Transit Gateway attachments. "
                "Review whether the Transit Gateway is still "
                "required. If it is no longer needed, retiring "
                "the Transit Gateway can eliminate its ongoing "
                "cost."
            ),
            statements=[
                EvidenceStatement(
                    name="transit_gateway_cost",
                    value=cost,
                    description="Confirmed Transit Gateway " "billing cost.",
                    source=[
                        "Cost Explorer",
                        "TransitGateway-Hours",
                        "TransitGateway-Bytes",
                    ],
                ),
                EvidenceStatement(
                    name="attachment_count",
                    value=0,
                    description="Completed Transit Gateway "
                    "attachment inventory found "
                    "no attachments.",
                    source=[
                        "EC2.DescribeTransitGatewayAttachments",
                    ],
                ),
            ],
            metadata={
                "cost_driver": "transit_gateway",
                "transit_gateway_cost": cost,
                "attachment_count": 0,
                "active_attachment_count": 0,
                "action": "review_transit_gateway_removal",
                "removal_is_not_automatic": True,
                "traffic_required": False,
                "missing_is_zero": False,
            },
        )

    # RULE 2 — LOW UTILIZATION

    def _low_utilization(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        status = _collection_status(context)

        # Attachment inventory must be complete.
        if status.get("attachments_complete") is not True:
            return None

        attachments = _attachments(context)

        # Structural usage exists.
        if not attachments:
            return None

        active = _active_attachments(context)

        # Existing but non-available attachments are not treated as
        # "unused". There is simply insufficient traffic evidence
        # for the utilization rule.
        if not active:
            return None

        # COMPLETE ATTACHMENT TELEMETRY IS REQUIRED

        traffic_rows = _collect_attachment_traffic(context)

        # Missing or incomplete telemetry must never become
        # a zero-traffic conclusion.
        if traffic_rows is None:
            return None

        threshold = _meaningful_traffic_threshold_gib(context)

        total_gib = _total_attachment_traffic_gib(traffic_rows)

        # MEANINGFUL TRAFFIC

        if total_gib > threshold:
            return None

        # LOW / NO MEANINGFUL TRAFFIC

        cost = _tgw_cost(context)

        return _finding(
            context=context,
            finding_type="transit_gateway_low_utilization",
            title="Review Transit Gateway utilization",
            severity="medium",
            confidence="high",
            reason=(
                f"Transit Gateway billing confirms "
                f"${cost:,.2f} of Transit Gateway cost, "
                f"and {len(active)} active attachment(s) "
                f"were observed. Complete attachment-level "
                f"telemetry shows {total_gib:,.4f} GiB of "
                f"combined traffic during the analysis period, "
                f"which is at or below the configured "
                f"{threshold:,.2f} GiB operational threshold. "
                "Review whether the Transit Gateway and its "
                "attached network paths are appropriately "
                "utilized before considering architectural "
                "changes."
            ),
            statements=[
                EvidenceStatement(
                    name="transit_gateway_cost",
                    value=cost,
                    description="Confirmed Transit Gateway " "billing cost.",
                    source=[
                        "Cost Explorer",
                        "TransitGateway-Hours",
                        "TransitGateway-Bytes",
                    ],
                ),
                EvidenceStatement(
                    name="attachment_count",
                    value=len(attachments),
                    description="Transit Gateway attachments "
                    "observed in the completed "
                    "attachment inventory.",
                    source=[
                        "EC2.DescribeTransitGatewayAttachments",
                    ],
                ),
                EvidenceStatement(
                    name="active_attachment_count",
                    value=len(active),
                    description="Transit Gateway attachments "
                    "currently in available state.",
                    source=[
                        "EC2.DescribeTransitGatewayAttachments",
                    ],
                ),
                EvidenceStatement(
                    name="observed_attachment_traffic_gib",
                    value=total_gib,
                    description="Combined observed traffic across "
                    "all active Transit Gateway "
                    "attachments during the complete "
                    "analysis period.",
                    source=[
                        "AWS/TransitGateway",
                        "TransitGatewayAttachment",
                        "BytesIn",
                        "BytesOut",
                    ],
                ),
                EvidenceStatement(
                    name="meaningful_traffic_threshold_gib",
                    value=threshold,
                    description=(
                        "Operational threshold used by "
                        "the analyzer to classify meaningful "
                        "traffic. This is not an AWS pricing "
                        "threshold."
                    ),
                    source=[
                        "Transit Gateway analyzer configuration",
                    ],
                ),
                EvidenceStatement(
                    name="attachment_traffic",
                    value=traffic_rows,
                    description=(
                        "Complete traffic evidence for "
                        "every active Transit Gateway "
                        "attachment considered by the "
                        "utilization assessment."
                    ),
                    source=[
                        "AWS/TransitGateway",
                        "TransitGatewayAttachment",
                        "BytesIn",
                        "BytesOut",
                    ],
                ),
            ],
            metadata={
                "cost_driver": "transit_gateway",
                "transit_gateway_cost": cost,
                "attachment_count": len(attachments),
                "active_attachment_count": len(active),
                "observed_traffic_gib": total_gib,
                "meaningful_traffic_threshold_gib": threshold,
                "traffic_complete": True,
                "missing_is_zero": False,
                "action": "review_transit_gateway_utilization",
                # Explicitly prevent a downstream recommendation
                # generator from interpreting this as deletion.
                "removal_recommendation": False,
                "removal_is_not_automatic": True,
                "attachments": traffic_rows,
            },
        )

    # EVIDENCE-GAP FINDINGS

    def _topology_incomplete(
        self,
        context: AnalysisContext,
    ) -> Finding | None:
        """
        Detect incomplete *topology* evidence (attachment inventory,
        associations, route tables/routes).

        A TGW whose route_table_count/route_count came back unknown
        because the route-table API call was denied is NOT "under
        monitored" -- the structural evidence any removal decision
        depends on was never collected.  This is a data-quality
        finding (never recommendation-eligible) and must never be
        read as "zero attachments" or "zero routes".
        """

        status = _collection_status(context)

        # No completeness information is not a claim of
        # incompleteness.
        if not status:
            return None

        sections: list[str] = []

        if status.get("attachments_complete") is False:
            sections.append("attachment inventory")

        if status.get("association_evidence_complete") is False:
            sections.append("associations")

        if status.get("route_data_complete") is False:
            sections.append("route tables and routes")

        if not sections:
            return None

        sections_text = " and ".join(sections)

        return Finding(
            finding_type=("transit_gateway_topology_incomplete"),
            title=("Transit Gateway topology evidence " "is incomplete"),
            resource_type=(context.resource_type or "transit_gateway"),
            resource_id=(context.resource_id or "unknown"),
            analyzer=self.name,
            analyzer_version=self.version,
            severity="info",
            confidence="high",
            reason=(
                "Transit Gateway topology evidence is "
                f"incomplete ({sections_text}). Counts "
                "remain unknown rather than zero. This is "
                "a data-quality evidence gap, not a "
                "CloudWatch telemetry gap, and no "
                "optimization finding is generated from it."
            ),
            conditions=[],
            evidence=Evidence(
                metrics={},
                configuration={},
                topology={
                    "relationships": (_relationships(context)),
                },
                resource={
                    "resource_id": context.resource_id,
                    "resource_type": context.resource_type,
                    "region": context.region,
                },
                derived={},
                data_quality={
                    "collection_status": status,
                },
            ),
            observation_period=None,
            metadata={
                "evidence_gap": "topology",
                "incomplete_sections": sections,
                "missing_is_zero": False,
            },
            recommendation_eligible=False,
            impact={},
        )

    # OUTCOME CLASSIFICATION

    def classify(
        self,
        context: AnalysisContext,
        findings: list[Finding],
    ) -> tuple[str, str | None]:

        if findings:
            return (
                "finding_generated",
                None,
            )

        status = _collection_status(context)

        # Incomplete route/topology evidence is insufficient evidence:
        # we cannot safely decide the TGW is unused or under-utilized
        # when the routing structure was never collected.
        if status.get("route_data_complete") is False:
            return (
                "insufficient_evidence",
                "route data incomplete: route topology evidence is "
                "unknown rather than zero (route topology incomplete)",
            )

        # If attachment completeness is explicitly false,
        # evidence is insufficient.
        if status.get("attachments_complete") is False:
            return (
                "insufficient_evidence",
                "attachment inventory incomplete: "
                "attachment count is unknown rather than zero",
            )

        # Missing completeness information is also not evidence
        # of zero attachments.
        if status.get("attachments_complete") is not True:
            return (
                "insufficient_evidence",
                "attachment inventory completeness is unknown",
            )

        attachments = _attachments(context)

        # Existing attachments but incomplete traffic telemetry.
        if attachments:

            active = _active_attachments(context)

            if active:

                traffic_rows = _collect_attachment_traffic(context)

                if traffic_rows is None:
                    return (
                        "insufficient_evidence",
                        "attachment traffic telemetry is "
                        "missing or incomplete; zero traffic "
                        "cannot be inferred",
                    )

        return (
            "no_optimization_match",
            None,
        )
