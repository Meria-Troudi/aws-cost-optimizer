"""
Transit Gateway cost and network analyzer.

Cost findings
-------------
1. transit_gateway_no_observed_traffic
2. transit_gateway_high_traffic

Operational findings
--------------------
3. transit_gateway_unrouted_attachment
4. transit_gateway_unassociated_attachment
5. transit_gateway_blackhole_routes
6. transit_gateway_vpc_blackhole_routes

No cost savings are calculated here.

CloudWatch traffic is evidence.
Cost Explorer / billing reconciliation remains the authority
for actual monetary attribution.
"""

from __future__ import annotations

from typing import Any

from ....base import Analyzer
from ....condition import EvidenceStatement
from ....context import AnalysisContext
from ....evidence import Evidence
from ....finding import Finding, ObservationPeriod
from ....registry import register


DEFAULT_HIGH_INGRESS_GIB = 100.0


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


def _list(
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


def _number(
    value: Any,
) -> float | None:

    if value is None:
        return None

    if isinstance(
        value,
        bool,
    ):
        return None

    try:
        return float(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


def _relationships(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        context.resource.get(
            "relationships"
        )
    )


def _topology(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        context.topology()
    )


def _cloudwatch(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        context.cloudwatch()
    )


def _traffic(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        _cloudwatch(context).get(
            "traffic"
        )
    )


def _attachment_traffic(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        _cloudwatch(context).get(
            "attachment_traffic"
        )
    )


def _collection_status(
    context: AnalysisContext,
) -> dict[str, Any]:

    return _dict(
        _relationships(context).get(
            "collection_status"
        )
    )


def _attachments(
    context: AnalysisContext,
) -> list[dict[str, Any]]:

    relationships = _relationships(
        context
    )

    result: list[
        dict[str, Any]
    ] = []

    for key in (
        "vpc_attachments",
        "other_attachments",
        "peering_attachments",
    ):

        values = relationships.get(
            key,
            [],
        )

        if not isinstance(
            values,
            list,
        ):
            continue

        result.extend(
            item
            for item in values
            if isinstance(
                item,
                dict,
            )
        )

    return result


def _vpc_attachments(
    context: AnalysisContext,
) -> list[dict[str, Any]]:

    values = _relationships(
        context
    ).get(
        "vpc_attachments",
        [],
    )

    return [
        item
        for item in values
        if isinstance(
            item,
            dict,
        )
    ] if isinstance(
        values,
        list,
    ) else []


def _attachments_complete(
    context: AnalysisContext,
) -> bool:

    return (
        _collection_status(context).get(
            "attachments_complete"
        )
        is True
    )


def _route_data_complete(
    context: AnalysisContext,
) -> bool:

    return (
        _collection_status(context).get(
            "route_data_complete"
        )
        is True
    )


def _topology_complete(
    context: AnalysisContext,
) -> bool:

    return (
        _dict(
            _topology(context).get(
                "summary"
            )
        ).get(
            "topology_complete"
        )
        is True
    )


def _route_table_accessible(
    context: AnalysisContext,
) -> bool:

    return (
        _dict(
            _relationships(context).get(
                "route_table_access"
            )
        ).get(
            "status"
        )
        == "accessible"
    )


def _tgw_routes(
    context: AnalysisContext,
) -> list[dict[str, Any]]:

    if not _route_data_complete(
        context
    ):
        return []

    values = _relationships(
        context
    ).get(
        "routes",
        [],
    )

    return [
        route
        for route in values
        if isinstance(
            route,
            dict,
        )
    ] if isinstance(
        values,
        list,
    ) else []


def _vpc_topologies(
    context: AnalysisContext,
) -> list[dict[str, Any]]:

    values = _topology(
        context
    ).get(
        "vpcs",
        [],
    )

    return [
        value
        for value in values
        if isinstance(
            value,
            dict,
        )
    ] if isinstance(
        values,
        list,
    ) else []


def _threshold(
    context: AnalysisContext,
    name: str,
    default: float,
) -> float:

    config = context.resource.get(
        "analyzer_config"
    )

    if isinstance(
        config,
        dict,
    ):

        value = _number(
            config.get(
                name
            )
        )

        if value is not None:
            return max(
                value,
                0.0,
            )

        transit = config.get(
            "transit_gateway"
        )

        if isinstance(
            transit,
            dict,
        ):

            value = _number(
                transit.get(
                    name
                )
            )

            if value is not None:
                return max(
                    value,
                    0.0,
                )

    return default


def _observation_period(
    context: AnalysisContext,
) -> ObservationPeriod | None:

    cloudwatch = _cloudwatch(
        context
    )

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
            duration_seconds=None,
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


def _statement(
    *,
    name: str,
    value: Any,
    description: str,
    source: list[str],
) -> EvidenceStatement:

    return EvidenceStatement(
        name=name,
        value=value,
        description=description,
        source=list(source),
    )


@register
class TransitGatewayAnalyzer(Analyzer):

    name = "transit_gateway"
    version = "5.0"

    SUPPORTED_RESOURCE_TYPES = {
        "transit_gateway",
    }

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            in self.SUPPORTED_RESOURCE_TYPES
        )

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(
            context
        ):
            return []

        findings: list[
            Finding
        ] = []

        for detector in (
            self._no_traffic,
            self._high_ingress,
            self._unrouted_attachment,
            self._unassociated_attachment,
            self._blackhole_routes,
            self._vpc_blackhole_routes,
        ):

            finding = detector(
                context
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    # ==============================================================
    # COST FINDING 1
    # ==============================================================

    def _no_traffic(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _attachments_complete(
            context
        ):
            return None

        attachments = [
            attachment
            for attachment in _attachments(
                context
            )
            if str(
                attachment.get(
                    "state",
                    "",
                )
            ).lower()
            == "available"
        ]

        if not attachments:
            return None

        traffic = _traffic(
            context
        )

        if traffic.get(
            "traffic_complete"
        ) is not True:
            return None

        if traffic.get(
            "traffic_observed"
        ) is not False:
            return None

        return self._finding(
            context=context,

            finding_type=
                "transit_gateway_no_observed_traffic",

            title=
                "Transit Gateway has no observed traffic",

            severity=
                "medium",

            confidence=
                "high",

            recommendation_eligible=
                True,

            reason=(
                f"{len(attachments)} active attachment(s) "
                "are present, but no TGW traffic was observed "
                "during the complete observation period."
            ),

            statements=[
                _statement(
                    name="traffic",
                    value=traffic,
                    description=(
                        "Complete CloudWatch traffic evidence."
                    ),
                    source=[
                        "CloudWatch.BytesIn",
                        "CloudWatch.BytesOut",
                    ],
                ),

                _statement(
                    name="active_attachments",
                    value=len(attachments),
                    description=(
                        "Active Transit Gateway attachments."
                    ),
                    source=[
                        "Transit Gateway attachment inventory"
                    ],
                ),
            ],

            metadata={
                "active_attachment_count":
                    len(attachments),

                "ingress_gib":
                    traffic.get(
                        "ingress_gib"
                    ),
            },

            limitations=[
                (
                    "No observed traffic does not prove that "
                    "the Transit Gateway or its attachments "
                    "are unnecessary."
                ),
                (
                    "Scheduled, intermittent, failover, or "
                    "future workloads may exist."
                ),
                (
                    "Savings are not calculated without valid "
                    "billing attribution."
                ),
            ],
        )

    # ==============================================================
    # COST FINDING 2
    # ==============================================================

    def _high_ingress(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        traffic = _traffic(
            context
        )

        if traffic.get(
            "traffic_complete"
        ) is not True:
            return None

        ingress_gib = _number(
            traffic.get(
                "ingress_gib"
            )
        )

        if ingress_gib is None:
            return None

        threshold = _threshold(
            context,
            "high_ingress_gib",
            DEFAULT_HIGH_INGRESS_GIB,
        )

        if ingress_gib < threshold:
            return None

        attachment_traffic = (
            _attachment_traffic(
                context
            )
        )

        return self._finding(
            context=context,

            finding_type=
                "transit_gateway_high_traffic",

            title=
                "Transit Gateway has high ingress traffic",

            severity=
                "medium",

            confidence=
                "high",

            recommendation_eligible=
                True,

            reason=(
                f"Approximately {ingress_gib:,.1f} GiB of "
                "traffic entered the Transit Gateway during "
                "the observation period."
            ),

            statements=[
                _statement(
                    name="ingress_traffic",
                    value={
                        "bytes":
                            traffic.get(
                                "bytes_in"
                            ),

                        "gib":
                            ingress_gib,

                        "threshold_gib":
                            threshold,
                    },
                    description=(
                        "Observed TGW ingress traffic. "
                        "This is a cost-exposure signal, "
                        "not a monetary billing amount."
                    ),
                    source=[
                        "CloudWatch.BytesIn"
                    ],
                ),

                _statement(
                    name="attachment_traffic",
                    value={
                        "count":
                            attachment_traffic.get(
                                "count"
                            ),

                        "complete":
                            attachment_traffic.get(
                                "complete"
                            ),
                    },
                    description=(
                        "Attachment-level traffic evidence "
                        "available for source analysis."
                    ),
                    source=[
                        "CloudWatch.TransitGatewayAttachment"
                    ],
                ),
            ],

            metadata={
                "ingress_bytes":
                    traffic.get(
                        "bytes_in"
                    ),

                "ingress_gib":
                    ingress_gib,

                "threshold_gib":
                    threshold,

                "attachment_traffic_complete":
                    attachment_traffic.get(
                        "complete"
                    ),
            },

            limitations=[
                (
                    "Traffic volume is a cost-exposure signal, "
                    "not a savings estimate."
                ),
                (
                    "TGW ingress can include traffic paths that "
                    "have different pricing treatment."
                ),
                (
                    "Review attachment sources, routing, and "
                    "architecture before claiming savings."
                ),
            ],
        )

    # ==============================================================
    # OPERATIONAL FINDING
    # ==============================================================

    def _unrouted_attachment(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _attachments_complete(
            context
        ):
            return None

        if not _topology_complete(
            context
        ):
            return None

        topologies = {
            item.get(
                "attachment_id"
            ):
                item
            for item in _vpc_topologies(
                context
            )
            if item.get(
                "attachment_id"
            )
        }

        candidates = []

        for attachment in _vpc_attachments(
            context
        ):

            if str(
                attachment.get(
                    "state",
                    "",
                )
            ).lower() != "available":
                continue

            attachment_id = attachment.get(
                "attachment_id"
            )

            topology = (
                topologies.get(
                    attachment_id
                )
            )

            if not topology:
                continue

            count = _number(
                topology.get(
                    "vpc_routes_to_tgw_count"
                )
            )

            if count == 0:

                candidates.append(
                    {
                        "attachment_id":
                            attachment_id,

                        "vpc_id":
                            attachment.get(
                                "vpc_id"
                            ),
                    }
                )

        if not candidates:
            return None

        return self._finding(
            context=context,

            finding_type=
                "transit_gateway_unrouted_attachment",

            title=
                "Transit Gateway attachment has no VPC route",

            severity=
                "medium",

            confidence=
                "high",

            recommendation_eligible=
                False,

            reason=(
                f"{len(candidates)} active VPC attachment(s) "
                "have no discovered VPC route targeting the TGW."
            ),

            statements=[
                _statement(
                    name="unrouted_attachments",
                    value=candidates,
                    description=(
                        "VPC-side routing evidence."
                    ),
                    source=[
                        "VPC route topology",
                        "Transit Gateway attachments",
                    ],
                )
            ],

            metadata={
                "candidate_count":
                    len(candidates),

                "candidates":
                    candidates,
            },

            limitations=[
                (
                    "This is an operational routing finding, "
                    "not direct evidence of cost savings."
                )
            ],
        )

    # ==============================================================
    # OPERATIONAL FINDING
    # ==============================================================

    def _unassociated_attachment(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _route_table_accessible(
            context
        ):
            return None

        if not _route_data_complete(
            context
        ):
            return None

        associations = _relationships(
            context
        ).get(
            "associations",
            [],
        )

        if not isinstance(
            associations,
            list,
        ):
            return None

        associated_ids = {
            item.get(
                "attachment_id"
            )
            for item in associations
            if isinstance(
                item,
                dict,
            )
            and item.get(
                "attachment_id"
            )
        }

        candidates = []

        for attachment in _attachments(
            context
        ):

            if str(
                attachment.get(
                    "state",
                    "",
                )
            ).lower() != "available":
                continue

            attachment_id = attachment.get(
                "attachment_id"
            )

            if not attachment_id:
                continue

            if attachment_id in associated_ids:
                continue

            if str(
                attachment.get(
                    "resource_type",
                    "",
                )
            ).lower() in {
                "peering",
                "tgw-peering",
            }:
                continue

            candidates.append(
                {
                    "attachment_id":
                        attachment_id,

                    "resource_id":
                        attachment.get(
                            "resource_id"
                        ),

                    "resource_type":
                        attachment.get(
                            "resource_type"
                        ),
                }
            )

        if not candidates:
            return None

        return self._finding(
            context=context,

            finding_type=
                "transit_gateway_unassociated_attachment",

            title=
                "Transit Gateway attachment is not associated",

            severity=
                "medium",

            confidence=
                "high",

            recommendation_eligible=
                False,

            reason=(
                f"{len(candidates)} active attachment(s) "
                "have no route-table association."
            ),

            statements=[
                _statement(
                    name="unassociated_attachments",
                    value=candidates,
                    description=(
                        "Complete TGW association data."
                    ),
                    source=[
                        "Transit Gateway route-table associations"
                    ],
                )
            ],

            metadata={
                "candidate_count":
                    len(candidates),

                "candidates":
                    candidates,
            },

            limitations=[
                (
                    "This is an operational routing finding, "
                    "not direct evidence of cost savings."
                )
            ],
        )

    # ==============================================================
    # OPERATIONAL FINDING
    # ==============================================================

    def _blackhole_routes(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        routes = _tgw_routes(
            context
        )

        blackholes = [
            route
            for route in routes
            if route.get(
                "state"
            ) == "blackhole"
        ]

        if not blackholes:
            return None

        return self._finding(
            context=context,

            finding_type=
                "transit_gateway_blackhole_routes",

            title=
                "Transit Gateway has blackhole routes",

            severity=
                "medium",

            confidence=
                "high",

            recommendation_eligible=
                False,

            reason=(
                f"{len(blackholes)} TGW route(s) "
                "are in blackhole state."
            ),

            statements=[
                _statement(
                    name="blackhole_routes",
                    value=blackholes,
                    description=(
                        "Transit Gateway routing evidence."
                    ),
                    source=[
                        "Transit Gateway route tables"
                    ],
                )
            ],

            metadata={
                "blackhole_route_count":
                    len(blackholes),
            },

            limitations=[
                (
                    "This is an operational network finding, "
                    "not direct evidence of cost savings."
                )
            ],
        )

    # ==============================================================
    # OPERATIONAL FINDING
    # ==============================================================

    def _vpc_blackhole_routes(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _topology_complete(
            context
        ):
            return None

        affected = []

        for item in _vpc_topologies(
            context
        ):

            count = _number(
                item.get(
                    "blackhole_vpc_routes_to_tgw_count"
                )
            )

            if count is None or count <= 0:
                continue

            affected.append(
                {
                    "attachment_id":
                        item.get(
                            "attachment_id"
                        ),

                    "vpc_id":
                        item.get(
                            "vpc_id"
                        ),

                    "count":
                        int(count),
                }
            )

        if not affected:
            return None

        total = sum(
            item["count"]
            for item in affected
        )

        return self._finding(
            context=context,

            finding_type=
                "transit_gateway_vpc_blackhole_routes",

            title=
                "VPC routes to Transit Gateway are blackholed",

            severity=
                "medium",

            confidence=
                "high",

            recommendation_eligible=
                False,

            reason=(
                f"{total} VPC-side route(s) targeting "
                "the Transit Gateway are blackholed."
            ),

            statements=[
                _statement(
                    name="blackhole_vpc_routes",
                    value=affected,
                    description=(
                        "VPC routing evidence."
                    ),
                    source=[
                        "VPC route topology"
                    ],
                )
            ],

            metadata={
                "blackhole_route_count":
                    total,

                "affected_vpcs":
                    affected,
            },

            limitations=[
                (
                    "This is an operational network finding, "
                    "not direct evidence of cost savings."
                )
            ],
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
        statements: list[
            EvidenceStatement
        ],
        metadata: dict[str, Any],
        limitations: list[str],
        recommendation_eligible: bool,
    ) -> Finding:

        final_metadata = {
            "region":
                context.region,

            **metadata,
        }

        return Finding(
            finding_type=
                finding_type,

            title=
                title,

            resource_type=(
                context.resource_type
                or "transit_gateway"
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
                self._build_evidence(
                    context,
                    final_metadata,
                ),

            observation_period=
                _observation_period(
                    context
                ),

            limitations=
                limitations,

            metadata=
                final_metadata,

            recommendation_eligible=
                recommendation_eligible,

            impact={},
        )

    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: dict[str, Any],
    ) -> Evidence:

        relationships = _relationships(
            context
        )

        topology = _topology(
            context
        )

        configuration = _dict(
            context.configuration()
        )

        metrics = {
            name:
                context.metric_summary(
                    name
                )
            for name in context.metrics()
        }

        return Evidence(
            metrics=metrics,

            configuration={
                key: value
                for key, value
                in configuration.items()
                if key != "tags"
            },

            topology={
                "relationships":
                    {
                        "summary":
                            _dict(
                                relationships.get(
                                    "summary"
                                )
                            ),

                        "collection_status":
                            relationships.get(
                                "collection_status",
                                {},
                            ),
                    },

                "network":
                    _dict(
                        topology.get(
                            "summary"
                        )
                    ),
            },

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,
            },

            derived={
                "traffic":
                    _traffic(
                        context
                    ),

                "attachment_traffic":
                    _attachment_traffic(
                        context
                    ),

                **metadata,
            },

            billing=
                context.billing(),

            data_quality={
                "attachments_complete":
                    _attachments_complete(
                        context
                    ),

                "route_data_complete":
                    _route_data_complete(
                        context
                    ),

                "topology_complete":
                    _topology_complete(
                        context
                    ),

                "cloudwatch_status":
                    _cloudwatch(
                        context
                    ).get(
                        "status"
                    ),
            },
        )