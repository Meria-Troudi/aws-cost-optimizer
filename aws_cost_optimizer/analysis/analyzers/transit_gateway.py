
"""
Transit Gateway cost and network optimization analyzer.

Evidence-first and account-independent.

The analyzer does not:
- invent prices
- invent savings
- recommend a replacement architecture
- delete attachments
- delete routes
- assume inaccessible data is empty

A finding is emitted only when the required evidence for
that finding is available and valid.
"""

from __future__ import annotations

from typing import Any

from ..base import Analyzer
from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from ..registry import register


DEFAULT_HIGH_TRAFFIC_GIB = 100.0


# ======================================================================
# HELPERS
# ======================================================================


def _as_number(
    value: Any,
) -> float | None:

    if value is None:
        return None

    try:
        return float(value)

    except (
        TypeError,
        ValueError,
    ):
        return None


def _config(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = context.configuration()

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def _relationships(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = context.resource.get(
        "relationships",
        {},
    )

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def _topology(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = context.topology()

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def _cloudwatch(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = context.cloudwatch()

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def _traffic(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = _cloudwatch(
        context
    ).get(
        "traffic",
        {},
    )

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def _collection_status(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = _relationships(
        context
    ).get(
        "collection_status",
        {},
    )

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def _attachments(
    context: AnalysisContext,
) -> list[dict[str, Any]]:

    relationships = _relationships(
        context
    )

    result = []

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

        for item in values:

            if isinstance(
                item,
                dict,
            ):
                result.append(
                    item
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
    ]


def _route_data_complete(
    context: AnalysisContext,
) -> bool:

    return (
        _collection_status(
            context
        ).get(
            "route_data_complete"
        )
        is True
    )


def _attachments_complete(
    context: AnalysisContext,
) -> bool:

    return (
        _collection_status(
            context
        ).get(
            "attachments_complete"
        )
        is True
    )


def _topology_complete(
    context: AnalysisContext,
) -> bool:

    return (
        _topology(
            context
        ).get(
            "summary",
            {},
        ).get(
            "topology_complete"
        )
        is True
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
        item
        for item in values
        if isinstance(
            item,
            dict,
        )
    ]


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
        item
        for item in values
        if isinstance(
            item,
            dict,
        )
    ]


def _route_table_accessible(
    context: AnalysisContext,
) -> bool:

    access = _relationships(
        context
    ).get(
        "route_table_access",
        {},
    )

    return (
        isinstance(
            access,
            dict,
        )
        and
        access.get(
            "status"
        )
        == "accessible"
    )


def _threshold(
    context: AnalysisContext,
    key: str,
    default: float,
) -> float:

    resource = context.resource

    for root_name in (
        "analyzer_config",
        "analysis_config",
        "config",
    ):

        root = resource.get(
            root_name
        )

        if not isinstance(
            root,
            dict,
        ):
            continue

        transit = root.get(
            "transit_gateway"
        )

        if not isinstance(
            transit,
            dict,
        ):
            continue

        value = transit.get(
            key
        )

        if value is None:
            continue

        try:
            parsed = float(
                value
            )

            if parsed >= 0:
                return parsed

        except (
            TypeError,
            ValueError,
        ):
            pass

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
        or
        cloudwatch.get(
            "metric_start"
        )
    )

    end = (
        cloudwatch.get(
            "end"
        )
        or
        cloudwatch.get(
            "metric_end"
        )
    )

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
        source=source,
    )


# ======================================================================
# ANALYZER
# ======================================================================


@register
class TransitGatewayAnalyzer(Analyzer):

    name = "transit_gateway"
    version = "3.0"

    SUPPORTED_RESOURCE_TYPES = {
        "transit_gateway",
    }

    # ================================================================
    # SUPPORT
    # ================================================================

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            in self.SUPPORTED_RESOURCE_TYPES
        )

    # ================================================================
    # MAIN
    # ================================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(
            context
        ):
            return []

        checks = (
            self._check_no_attachments,
            self._check_no_observed_traffic,
            self._check_unrouted_vpc_attachments,
            self._check_unassociated_attachments,
            self._check_tgw_blackhole_routes,
            self._check_vpc_blackhole_routes,
            self._check_high_traffic,
            self._check_shared_ownership,
        )

        findings = []

        for check in checks:

            finding = check(
                context
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    # ================================================================
    # RULE 1 — NO ATTACHMENTS
    # ================================================================

    def _check_no_attachments(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        # We need a complete attachment inventory.
        if not _attachments_complete(
            context
        ):
            return None

        attachments = _attachments(
            context
        )

        if attachments:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "transit_gateway_no_attachments"
            ),
            title=(
                "Transit Gateway has no attachments"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "The complete attachment inventory contains "
                "no VPC, other, or peering attachments."
            ),
            statements=[
                _statement(
                    name="attachments",
                    value={
                        "total": 0,
                        "vpc": 0,
                        "other": 0,
                        "peering": 0,
                    },
                    description=(
                        "Complete Transit Gateway attachment "
                        "inventory returned no attachments."
                    ),
                    source=[
                        "Transit Gateway attachment inventory"
                    ],
                )
            ],
            metadata={
                "attachment_count":
                    0,
            },
            recommendation_eligible=True,
        )

    # ================================================================
    # RULE 2 — NO OBSERVED TRAFFIC
    # ================================================================

    def _check_no_observed_traffic(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _attachments_complete(
            context
        ):
            return None

        if not _attachments(
            context
        ):
            return None

        traffic = _traffic(
            context
        )

        # Strict requirement:
        #
        # BytesIn observed
        # AND
        # BytesOut observed
        # AND
        # both are zero.
        if (
            traffic.get(
                "traffic_complete"
            )
            is not True
        ):
            return None

        if (
            traffic.get(
                "traffic_observed"
            )
            is not False
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "transit_gateway_no_observed_traffic"
            ),
            title=(
                "Transit Gateway has no observed traffic"
            ),
            severity="low",
            confidence="high",
            reason=(
                "Both inbound and outbound Transit Gateway "
                "traffic metrics were observed at zero during "
                "the complete analysis period."
            ),
            statements=[
                _statement(
                    name="traffic",
                    value={
                        "bytes_in":
                            traffic.get(
                                "bytes_in"
                            ),

                        "bytes_out":
                            traffic.get(
                                "bytes_out"
                            ),

                        "total_bytes":
                            traffic.get(
                                "total_bytes"
                            ),

                        "total_gib":
                            traffic.get(
                                "total_bytes_gib"
                            ),
                    },
                    description=(
                        "CloudWatch traffic evidence."
                    ),
                    source=[
                        "CloudWatch.BytesIn",
                        "CloudWatch.BytesOut",
                    ],
                )
            ],
            metadata={
                "bytes_in":
                    traffic.get(
                        "bytes_in"
                    ),

                "bytes_out":
                    traffic.get(
                        "bytes_out"
                    ),

                "traffic_bytes":
                    traffic.get(
                        "total_bytes"
                    ),

                "traffic_gib":
                    traffic.get(
                        "total_bytes_gib"
                    ),
            },
            recommendation_eligible=True,
        )

    # ================================================================
    # RULE 3 — VPC ATTACHMENT WITHOUT VPC-SIDE ROUTING
    # ================================================================

    def _check_unrouted_vpc_attachments(
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

        vpc_attachments = (
            _vpc_attachments(
                context
            )
        )

        topologies = (
            _vpc_topologies(
                context
            )
        )

        topology_by_attachment = {
            item.get(
                "attachment_id"
            ):
                item
            for item in topologies
            if item.get(
                "attachment_id"
            )
        }

        candidates = []

        for attachment in vpc_attachments:

            if str(
                attachment.get(
                    "state",
                    ""
                )
            ).lower() != "available":
                continue

            attachment_id = attachment.get(
                "attachment_id"
            )

            topology = (
                topology_by_attachment.get(
                    attachment_id
                )
            )

            if not isinstance(
                topology,
                dict,
            ):
                continue

            route_count = _as_number(
                topology.get(
                    "vpc_routes_to_tgw_count"
                )
            )

            if route_count is None:
                continue

            if route_count != 0:
                continue

            candidates.append(
                {
                    "attachment_id":
                        attachment_id,

                    "vpc_id":
                        attachment.get(
                            "vpc_id"
                        ),

                    "state":
                        attachment.get(
                            "state"
                        ),
                }
            )

        if not candidates:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "transit_gateway_unrouted_attachment"
            ),
            title=(
                "Transit Gateway attachment has no "
                "VPC-side route"
            ),
            severity="medium",
            confidence="high",
            reason=(
                f"{len(candidates)} active VPC attachment(s) "
                "have no VPC route targeting the Transit Gateway."
            ),
            statements=[
                _statement(
                    name="unrouted_attachments",
                    value=candidates,
                    description=(
                        "Complete VPC topology shows no "
                        "VPC-side route targeting the TGW."
                    ),
                    source=[
                        "VPC route topology",
                        "Transit Gateway attachment inventory",
                    ],
                )
            ],
            metadata={
                "candidate_count":
                    len(candidates),

                "candidates":
                    candidates,
            },
            recommendation_eligible=True,
        )

    # ================================================================
    # RULE 4 — UNASSOCIATED ATTACHMENT
    # ================================================================

    def _check_unassociated_attachments(
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

        relationships = _relationships(
            context
        )

        associations = relationships.get(
            "associations",
            [],
        )

        if not isinstance(
            associations,
            list,
        ):
            return None

        associated_ids = {
            association.get(
                "attachment_id"
            )
            for association in associations
            if isinstance(
                association,
                dict,
            )
            and association.get(
                "attachment_id"
            )
        }

        candidates = []

        for attachment in _attachments(
            context
        ):

            attachment_id = attachment.get(
                "attachment_id"
            )

            if not attachment_id:
                continue

            if str(
                attachment.get(
                    "state",
                    ""
                )
            ).lower() != "available":
                continue

            resource_type = str(
                attachment.get(
                    "resource_type",
                    ""
                )
            ).lower()

            if resource_type in {
                "peering",
                "tgw-peering",
            }:
                continue

            if attachment_id not in associated_ids:

                candidates.append(
                    {
                        "attachment_id":
                            attachment_id,

                        "resource_id":
                            attachment.get(
                                "resource_id"
                            ),

                        "resource_type":
                            resource_type,
                    }
                )

        if not candidates:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "transit_gateway_unassociated_attachment"
            ),
            title=(
                "Transit Gateway attachment is not associated"
            ),
            severity="medium",
            confidence="high",
            reason=(
                f"{len(candidates)} active attachment(s) "
                "have no Transit Gateway route-table association."
            ),
            statements=[
                _statement(
                    name="unassociated_attachments",
                    value=candidates,
                    description=(
                        "Complete Transit Gateway association "
                        "data shows active attachments without "
                        "a route-table association."
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
            recommendation_eligible=True,
        )

    # ================================================================
    # RULE 5 — TGW BLACKHOLE ROUTES
    # ================================================================

    def _check_tgw_blackhole_routes(
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
            finding_type=(
                "transit_gateway_blackhole_routes"
            ),
            title=(
                "Transit Gateway has blackhole routes"
            ),
            severity="medium",
            confidence="high",
            reason=(
                f"{len(blackholes)} Transit Gateway route(s) "
                "are currently in blackhole state."
            ),
            statements=[
                _statement(
                    name="blackhole_routes",
                    value=blackholes,
                    description=(
                        "Complete TGW route-table data "
                        "contains blackhole routes."
                    ),
                    source=[
                        "Transit Gateway route tables"
                    ],
                )
            ],
            metadata={
                "blackhole_route_count":
                    len(blackholes),

                "routes":
                    blackholes,
            },
            # This is an operational/network correctness
            # signal, not direct proof of cost waste.
            recommendation_eligible=False,
        )

    # ================================================================
    # RULE 6 — VPC BLACKHOLE ROUTES
    # ================================================================

    def _check_vpc_blackhole_routes(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not _topology_complete(
            context
        ):
            return None

        topologies = (
            _vpc_topologies(
                context
            )
        )

        candidates = []

        for topology in topologies:

            count = _as_number(
                topology.get(
                    "blackhole_vpc_routes_to_tgw_count"
                )
            )

            if count is None:
                continue

            if count <= 0:
                continue

            candidates.append(
                {
                    "attachment_id":
                        topology.get(
                            "attachment_id"
                        ),

                    "vpc_id":
                        topology.get(
                            "vpc_id"
                        ),

                    "blackhole_route_count":
                        int(count),
                }
            )

        if not candidates:
            return None

        total = sum(
            item[
                "blackhole_route_count"
            ]
            for item in candidates
        )

        return self._finding(
            context=context,
            finding_type=(
                "transit_gateway_vpc_blackhole_routes"
            ),
            title=(
                "VPC routes to Transit Gateway are blackholed"
            ),
            severity="medium",
            confidence="high",
            reason=(
                f"{total} VPC-side route(s) targeting "
                "the Transit Gateway are in blackhole state."
            ),
            statements=[
                _statement(
                    name="vpc_blackhole_routes",
                    value=candidates,
                    description=(
                        "VPC topology contains blackhole "
                        "routes targeting the TGW."
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
                    candidates,
            },
            recommendation_eligible=False,
        )

    # ================================================================
    # RULE 7 — HIGH TRAFFIC
    # ================================================================

    def _check_high_traffic(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        traffic = _traffic(
            context
        )

        if (
            traffic.get(
                "traffic_complete"
            )
            is not True
        ):
            return None

        total_gib = _as_number(
            traffic.get(
                "total_bytes_gib"
            )
        )

        if total_gib is None:
            return None

        threshold = _threshold(
            context,
            "high_traffic_gib",
            DEFAULT_HIGH_TRAFFIC_GIB,
        )

        if total_gib < threshold:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "transit_gateway_high_traffic"
            ),
            title=(
                "Transit Gateway carries high traffic volume"
            ),
            severity="info",
            confidence="high",
            reason=(
                f"Approximately {total_gib:,.1f} GiB "
                "of TGW traffic was observed during "
                "the analysis period."
            ),
            statements=[
                _statement(
                    name="traffic_volume",
                    value={
                        "bytes":
                            traffic.get(
                                "total_bytes"
                            ),

                        "gib":
                            total_gib,

                        "review_threshold_gib":
                            threshold,
                    },
                    description=(
                        "Observed Transit Gateway traffic "
                        "exceeds the configured review threshold."
                    ),
                    source=[
                        "CloudWatch.BytesIn",
                        "CloudWatch.BytesOut",
                    ],
                )
            ],
            metadata={
                "traffic_bytes":
                    traffic.get(
                        "total_bytes"
                    ),

                "traffic_gib":
                    total_gib,

                "threshold_gib":
                    threshold,
            },
            recommendation_eligible=False,
        )

    # ================================================================
    # RULE 8 — SHARED OWNERSHIP
    # ================================================================

    def _check_shared_ownership(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        identity = context.resource.get(
            "identity",
            {},
        )

        if not isinstance(
            identity,
            dict,
        ):
            return None

        ownership = identity.get(
            "ownership",
            {},
        )

        if not isinstance(
            ownership,
            dict,
        ):
            return None

        is_owner = ownership.get(
            "is_resource_owner"
        )

        if is_owner is not False:
            return None

        owner_account = ownership.get(
            "owner_account_id"
        )

        scan_account = ownership.get(
            "scan_account_id"
        )

        return self._finding(
            context=context,
            finding_type=(
                "transit_gateway_shared_ownership"
            ),
            title=(
                "Transit Gateway is owned by another account"
            ),
            severity="info",
            confidence="high",
            reason=(
                "The scanned account uses a Transit Gateway "
                "owned by another AWS account."
            ),
            statements=[
                _statement(
                    name="ownership",
                    value={
                        "scan_account":
                            scan_account,

                        "owner_account":
                            owner_account,
                    },
                    description=(
                        "Transit Gateway ownership differs "
                        "from the scanned account."
                    ),
                    source=[
                        "Transit Gateway configuration"
                    ],
                )
            ],
            metadata={
                "scan_account_id":
                    scan_account,

                "owner_account_id":
                    owner_account,
            },
            recommendation_eligible=False,
        )

    # ================================================================
    # FINDING BUILDER
    # ================================================================

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
        recommendation_eligible: bool,
    ) -> Finding:

        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or "transit_gateway"
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
                context,
                metadata,
            ),

            observation_period=(
                _observation_period(
                    context
                )
            ),

            limitations=[],

            metadata=dict(
                metadata
            ),

            recommendation_eligible=(
                recommendation_eligible
            ),
        )

    # ================================================================
    # EVIDENCE
    # ================================================================

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

        configuration = _config(
            context
        )

        traffic = _traffic(
            context
        )

        metrics = {}

        for name in context.metrics():

            metrics[
                name
            ] = context.metric_summary(
                name
            )

        relationship_summary = (
            relationships.get(
                "summary",
                {},
            )
        )

        if not isinstance(
            relationship_summary,
            dict,
        ):
            relationship_summary = {}

        topology_summary = (
            topology.get(
                "summary",
                {},
            )
        )

        if not isinstance(
            topology_summary,
            dict,
        ):
            topology_summary = {}

        return Evidence(
            metrics=metrics,

            configuration={
                key: value
                for key, value
                in configuration.items()
                if key != "tags"
            },

            topology={
                "relationship_summary":
                    relationship_summary,

                "network_summary":
                    topology_summary,

                "route_table_access":
                    relationships.get(
                        "route_table_access",
                        {},
                    ),

                "collection_status":
                    relationships.get(
                        "collection_status",
                        {},
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
                    traffic,

                **metadata,
            },

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

                "route_table_access":
                    relationships.get(
                        "route_table_access",
                        {},
                    ),

                "cloudwatch_status":
                    _cloudwatch(
                        context
                    ).get(
                        "status"
                    ),

                "cloudwatch_available":
                    bool(
                        context.metrics()
                    ),
            },
        )
