"""
AWS Transit Gateway collector.

Purpose
-------
Collect reliable evidence for:

- TGW configuration
- attachment inventory
- TGW routing
- VPC-side routing
- CloudWatch traffic
- attachment-level traffic
- cost-exposure signals

The collector does NOT calculate savings.

Important semantics
-------------------
Successful empty collection:
    status = "ok"

Failed collection:
    status = "error"

Inaccessible collection:
    status = "inaccessible"

An empty successful result must never be confused with
an unavailable result.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.registry import register

from collection.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)

from collection.shared.topology import (
    NetworkTopologyCollector,
)

from collection.shared.relationships import (
    NetworkRelationshipResolver,
)


@register
class TransitGatewayCollector(BaseCollector):

    key = "transit_gateway"
    resource_type = "transit_gateway"

    DEFAULT_NAMESPACE = "AWS/TransitGateway"
    DEFAULT_PERIOD = 3600

    BILLABLE_SOURCE_TYPES = frozenset(
        {
            "vpc",
            "vpn",
            "direct-connect-gateway",
            "network-function",
        }
    )

    def __init__(
        self,
        scan: Any,
        region: str,
        profile: Any = None,
    ) -> None:

        super().__init__(
            scan=scan,
            region=region,
            profile=profile,
        )

        if not region:
            raise ValueError(
                "Transit Gateway collector requires a region."
            )

        self.region = region

        self.profile = (
            profile
            if isinstance(profile, dict)
            else {}
        )

        self.account_id = str(
            getattr(
                scan,
                "account_id",
                "",
            )
            or ""
        )

        self.ec2 = get_client(
            "ec2",
            region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            region,
        )

        self.metric_collector = (
            CloudWatchMetricCollector(
                self.cloudwatch
            )
        )

        self.topology_collector = (
            NetworkTopologyCollector(
                region
            )
        )

        self._owner_cache: dict[
            str,
            Optional[str],
        ] = {}

        self._metrics_batch_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

    # ==============================================================
    # PROFILE
    # ==============================================================

    def _observations_profile(
        self,
    ) -> dict[str, Any]:

        value = self.profile.get(
            "observations",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def _cloudwatch_profile(
        self,
    ) -> dict[str, Any]:

        value = self._observations_profile().get(
            "cloudwatch",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    # ==============================================================
    # DISCOVERY
    # ==============================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: list[
            Dict[str, Any]
        ] = []

        paginator = (
            self.ec2.get_paginator(
                "describe_transit_gateways"
            )
        )

        try:

            for page in paginator.paginate():

                for tgw in page.get(
                    "TransitGateways",
                    [],
                ):

                    if not isinstance(
                        tgw,
                        dict,
                    ):
                        continue

                    tgw_id = tgw.get(
                        "TransitGatewayId"
                    )

                    if not tgw_id:
                        continue

                    state = str(
                        tgw.get(
                            "State",
                            "",
                        )
                    ).lower()

                    if state not in {
                        "available",
                        "pending",
                    }:
                        continue

                    resources.append(
                        {
                            "id":
                                str(tgw_id),

                            "raw":
                                tgw,
                        }
                    )

        except Exception as exc:

            raise RuntimeError(
                "Failed to discover Transit Gateways "
                f"in {self.region}: {exc}"
            ) from exc

        self._prefetch_metrics_batch(
            resources
        )

        return resources

    # ==============================================================
    # CLOUDWATCH PREFETCH
    # ==============================================================

    def _prefetch_metrics_batch(
        self,
        resources: list[dict[str, Any]],
    ) -> None:

        profile = self._cloudwatch_profile()

        if not profile:
            return

        if profile.get(
            "enabled",
            True,
        ) is not True:
            return

        specs = self._normalize_metric_specs(
            profile.get(
                "metrics",
                [],
            )
        )

        if not specs:
            return

        namespace = str(
            profile.get(
                "namespace",
                self.DEFAULT_NAMESPACE,
            )
        ).strip()

        try:
            period = int(
                profile.get(
                    "period",
                    self.DEFAULT_PERIOD,
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            period = self.DEFAULT_PERIOD

        period = max(
            period,
            60,
        )

        try:

            start, end = (
                self.get_analysis_period()
            )

        except ValueError:

            return

        requests: list[
            dict[str, Any]
        ] = []

        # ----------------------------------------------------------
        # TGW-level metrics
        # ----------------------------------------------------------

        for resource in resources:

            tgw_id = resource.get(
                "id"
            )

            if not tgw_id:
                continue

            requests.append(
                {
                    "resource_key":
                        str(tgw_id),

                    "namespace":
                        namespace,

                    "dimensions": [
                        {
                            "Name":
                                "TransitGateway",

                            "Value":
                                str(tgw_id),
                        }
                    ],

                    "metric_specs":
                        specs,
                }
            )

        # ----------------------------------------------------------
        # Attachment-level metrics
        # ----------------------------------------------------------

        for resource in resources:

            tgw_id = resource.get(
                "id"
            )

            if not tgw_id:
                continue

            try:

                attachment_data = (
                    self._discover_attachments_for_metrics(
                        str(tgw_id)
                    )
                )

            except Exception:

                continue

            for attachment in attachment_data:

                attachment_id = (
                    attachment.get(
                        "attachment_id"
                    )
                )

                if not attachment_id:
                    continue

                requests.append(
                    {
                        "resource_key":
                            self._attachment_metric_key(
                                tgw_id,
                                attachment_id,
                            ),

                        "namespace":
                            namespace,

                        "dimensions": [
                            {
                                "Name":
                                    "TransitGatewayAttachment",

                                "Value":
                                    str(
                                        attachment_id
                                    ),
                            }
                        ],

                        "metric_specs":
                            specs,
                    }
                )

        if not requests:
            return

        self._metrics_batch_cache = (
            self.metric_collector.collect_batch(
                requests,
                start=start,
                end=end,
                requested_period=period,
            )
        )

    def _discover_attachments_for_metrics(
        self,
        tgw_id: str,
    ) -> list[dict[str, Any]]:

        result: list[
            dict[str, Any]
        ] = []

        paginator = (
            self.ec2.get_paginator(
                "describe_transit_gateway_attachments"
            )
        )

        for page in paginator.paginate(
            Filters=[
                {
                    "Name":
                        "transit-gateway-id",

                    "Values":
                        [tgw_id],
                }
            ]
        ):

            for attachment in page.get(
                "TransitGatewayAttachments",
                [],
            ):

                attachment_id = (
                    attachment.get(
                        "TransitGatewayAttachmentId"
                    )
                )

                if not attachment_id:
                    continue

                result.append(
                    {
                        "attachment_id":
                            attachment_id,

                        "resource_type":
                            str(
                                attachment.get(
                                    "ResourceType",
                                    "",
                                )
                            ).lower(),
                    }
                )

        return result

    @staticmethod
    def _attachment_metric_key(
        tgw_id: str,
        attachment_id: str,
    ) -> str:

        return (
            f"{tgw_id}:attachment:{attachment_id}"
        )

    # ==============================================================
    # IDENTITY
    # ==============================================================

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        value = resource.get(
            "id"
        )

        if not value:
            raise ValueError(
                "Transit Gateway ID is missing."
            )

        return str(value)

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        tgw = (
            resource.get(
                "raw"
            )
            or {}
        )

        tags = self._tags(
            tgw.get(
                "Tags",
                [],
            )
        )

        owner_id = (
            tgw.get(
                "OwnerId"
            )
        )

        return {
            "name":
                (
                    tags.get("Name")
                    or tgw.get("Description")
                    or resource.get("id")
                ),

            "transit_gateway_id":
                resource.get(
                    "id"
                ),

            "state":
                tgw.get(
                    "State"
                ),

            "owner_id":
                owner_id,

            "description":
                tgw.get(
                    "Description"
                ),

            "ownership": {
                "scan_account_id":
                    self.account_id or None,

                "owner_account_id":
                    (
                        str(owner_id)
                        if owner_id
                        else None
                    ),

                "is_resource_owner":
                    bool(
                        self.account_id
                        and owner_id
                        and
                        self.account_id
                        == str(owner_id)
                    ),
            },

            "tags":
                tags,
        }

    # ==============================================================
    # CONFIGURATION
    # ==============================================================

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        tgw = (
            resource.get(
                "raw"
            )
            or {}
        )

        options = (
            tgw.get(
                "Options"
            )
            or {}
        )

        return {
            "transit_gateway_id":
                tgw.get(
                    "TransitGatewayId"
                ),

            "state":
                tgw.get(
                    "State"
                ),

            "owner_id":
                tgw.get(
                    "OwnerId"
                ),

            "creation_time":
                self._iso(
                    tgw.get(
                        "CreationTime"
                    )
                ),

            "description":
                tgw.get(
                    "Description"
                ),

            "amazon_side_asn":
                options.get(
                    "AmazonSideAsn"
                ),

            "transit_gateway_cidr_blocks":
                list(
                    options.get(
                        "TransitGatewayCidrBlocks",
                        [],
                    )
                    or []
                ),

            "default_route_table_association":
                options.get(
                    "DefaultRouteTableAssociation"
                ),

            "default_route_table_propagation":
                options.get(
                    "DefaultPropagationRouteTable"
                )
                or options.get(
                    "DefaultRouteTablePropagation"
                ),

            "association_default_route_table_id":
                options.get(
                    "AssociationDefaultRouteTableId"
                ),

            "propagation_default_route_table_id":
                options.get(
                    "PropagationDefaultRouteTableId"
                ),

            "dns_support":
                options.get(
                    "DnsSupport"
                ),

            "vpn_ecmp_support":
                options.get(
                    "VpnEcmpSupport"
                ),

            "auto_accept_shared_attachments":
                options.get(
                    "AutoAcceptSharedAttachments"
                ),

            "security_group_referencing_support":
                options.get(
                    "SecurityGroupReferencingSupport"
                ),

            "multicast_support":
                options.get(
                    "MulticastSupport"
                ),
        }

    # ==============================================================
    # RELATIONSHIPS
    # ==============================================================

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        tgw_id = resource.get(
            "id"
        )

        if not tgw_id:

            return {
                "status":
                    "incomplete",

                "reason":
                    "Transit Gateway ID is missing.",
            }

        vpc_attachments, vpc_status = (
            self._collect_vpc_attachments(
                str(tgw_id)
            )
        )

        other_attachments, other_status = (
            self._collect_other_attachments(
                str(tgw_id)
            )
        )

        peering_attachments, peering_status = (
            self._collect_peering_attachments(
                str(tgw_id)
            )
        )

        route_table_result = (
            self._collect_route_tables(
                str(tgw_id)
            )
        )

        route_tables = route_table_result.get(
            "route_tables",
            [],
        )

        route_access = (
            route_table_result.get(
                "access",
                {},
            )
        )

        routes: list[
            dict[str, Any]
        ] = []

        associations: list[
            dict[str, Any]
        ] = []

        propagations: list[
            dict[str, Any]
        ] = []

        routes_ok = True
        associations_ok = True
        propagations_ok = True

        if (
            route_access.get("status")
            == "accessible"
        ):

            for table in route_tables:

                route_table_id = (
                    table.get(
                        "transit_gateway_route_table_id"
                    )
                )

                if not route_table_id:
                    continue

                collected, status = (
                    self._collect_routes(
                        route_table_id
                    )
                )

                routes.extend(
                    collected
                )

                routes_ok &= (
                    status.get(
                        "status"
                    )
                    == "ok"
                )

                collected, status = (
                    self._collect_associations(
                        route_table_id
                    )
                )

                associations.extend(
                    collected
                )

                associations_ok &= (
                    status.get(
                        "status"
                    )
                    == "ok"
                )

                collected, status = (
                    self._collect_propagations(
                        route_table_id
                    )
                )

                propagations.extend(
                    collected
                )

                propagations_ok &= (
                    status.get(
                        "status"
                    )
                    == "ok"
                )

        route_data_complete = (
            route_access.get(
                "status"
            )
            == "accessible"
            and routes_ok
            and associations_ok
            and propagations_ok
        )

        attachments_complete = all(
            status.get(
                "status"
            ) == "ok"
            for status in (
                vpc_status,
                other_status,
                peering_status,
            )
        )

        active_routes = [
            route
            for route in routes
            if route.get("state") == "active"
        ]

        blackhole_routes = [
            route
            for route in routes
            if route.get("state") == "blackhole"
        ]

        active_attachments = [
            attachment
            for attachment in (
                vpc_attachments
                + other_attachments
                + peering_attachments
            )
            if str(
                attachment.get(
                    "state",
                    "",
                )
            ).lower() == "available"
        ]

        associated_attachment_ids = sorted(
            {
                association.get(
                    "attachment_id"
                )
                for association in associations
                if association.get(
                    "attachment_id"
                )
            }
        ) if route_data_complete else []

        enabled_propagation_attachment_ids = sorted(
            {
                propagation.get(
                    "attachment_id"
                )
                for propagation in propagations
                if propagation.get(
                    "state"
                ) == "enabled"
            }
        ) if route_data_complete else []

        return {
            "status":
                "ok",

            "vpc_attachments":
                vpc_attachments,

            "other_attachments":
                other_attachments,

            "peering_attachments":
                peering_attachments,

            "route_tables":
                route_tables,

            "routes":
                routes,

            "associations":
                associations,

            "propagations":
                propagations,

            "route_table_access":
                route_access,

            "collection_status": {
                "vpc_attachments":
                    vpc_status,

                "other_attachments":
                    other_status,

                "peering_attachments":
                    peering_status,

                "route_tables":
                    route_access,

                "routes":
                    {
                        "status":
                            "ok"
                            if routes_ok
                            else "error",
                    },

                "associations":
                    {
                        "status":
                            "ok"
                            if associations_ok
                            else "error",
                    },

                "propagations":
                    {
                        "status":
                            "ok"
                            if propagations_ok
                            else "error",
                    },

                "attachments_complete":
                    attachments_complete,

                "route_data_complete":
                    route_data_complete,
            },

            "summary": {
                "attachment_count":
                    len(
                        vpc_attachments
                        + other_attachments
                        + peering_attachments
                    ),

                "active_attachment_count":
                    len(
                        active_attachments
                    ),

                "vpc_attachment_count":
                    len(
                        vpc_attachments
                    ),

                "active_vpc_attachment_count":
                    sum(
                        str(
                            item.get(
                                "state",
                                "",
                            )
                        ).lower()
                        == "available"
                        for item in vpc_attachments
                    ),

                "other_attachment_count":
                    len(
                        other_attachments
                    ),

                "peering_attachment_count":
                    len(
                        peering_attachments
                    ),

                "route_table_count":
                    (
                        len(route_tables)
                        if route_access.get(
                            "status"
                        ) == "accessible"
                        else None
                    ),

                "route_count":
                    (
                        len(routes)
                        if route_data_complete
                        else None
                    ),

                "active_route_count":
                    (
                        len(active_routes)
                        if route_data_complete
                        else None
                    ),

                "blackhole_route_count":
                    (
                        len(blackhole_routes)
                        if route_data_complete
                        else None
                    ),

                "association_count":
                    (
                        len(associations)
                        if route_data_complete
                        else None
                    ),

                "propagation_count":
                    (
                        len(propagations)
                        if route_data_complete
                        else None
                    ),

                "associated_attachment_count":
                    (
                        len(
                            associated_attachment_ids
                        )
                        if route_data_complete
                        else None
                    ),

                "enabled_propagation_attachment_count":
                    (
                        len(
                            enabled_propagation_attachment_ids
                        )
                        if route_data_complete
                        else None
                    ),

                "collection_complete":
                    (
                        attachments_complete
                        and route_data_complete
                    ),
            },
        }

    # ==============================================================
    # VPC ATTACHMENTS
    # ==============================================================

    def _collect_vpc_attachments(
        self,
        tgw_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: list[
            dict[str, Any]
        ] = []

        paginator = (
            self.ec2.get_paginator(
                "describe_transit_gateway_vpc_attachments"
            )
        )

        try:

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name":
                            "transit-gateway-id",

                        "Values":
                            [tgw_id],
                    }
                ]
            ):

                for attachment in page.get(
                    "TransitGatewayVpcAttachments",
                    [],
                ):

                    attachment_id = (
                        attachment.get(
                            "TransitGatewayAttachmentId"
                        )
                    )

                    if not attachment_id:
                        continue

                    association = (
                        attachment.get(
                            "Association"
                        )
                        or {}
                    )

                    options = (
                        attachment.get(
                            "Options"
                        )
                        or {}
                    )

                    result.append(
                        {
                            "attachment_id":
                                attachment_id,

                            "resource_type":
                                "vpc",

                            "transit_gateway_id":
                                attachment.get(
                                    "TransitGatewayId"
                                ),

                            "vpc_id":
                                attachment.get(
                                    "VpcId"
                                ),

                            "vpc_owner_id":
                                attachment.get(
                                    "VpcOwnerId"
                                ),

                            "state":
                                attachment.get(
                                    "State"
                                ),

                            "creation_time":
                                self._iso(
                                    attachment.get(
                                        "CreationTime"
                                    )
                                ),

                            "route_table_id":
                                association.get(
                                    "TransitGatewayRouteTableId"
                                ),

                            "association_state":
                                (
                                    attachment.get(
                                        "AssociationState"
                                    )
                                    or association.get(
                                        "State"
                                    )
                                ),

                            "subnet_ids":
                                list(
                                    attachment.get(
                                        "SubnetIds",
                                        [],
                                    )
                                    or []
                                ),

                            "dns_support":
                                options.get(
                                    "DnsSupport"
                                ),

                            "ipv6_support":
                                options.get(
                                    "Ipv6Support"
                                ),

                            "appliance_mode_support":
                                options.get(
                                    "ApplianceModeSupport"
                                ),

                            "security_group_referencing_support":
                                options.get(
                                    "SecurityGroupReferencingSupport"
                                ),

                            "tags":
                                self._tags(
                                    attachment.get(
                                        "Tags",
                                        [],
                                    )
                                ),
                        }
                    )

        except Exception as exc:

            return (
                result,
                {
                    "status":
                        "error",

                    "error":
                        str(exc),
                },
            )

        return (
            result,
            {
                "status":
                    "ok",

                "count":
                    len(result),
            },
        )

    # ==============================================================
    # OTHER ATTACHMENTS
    # ==============================================================

    def _collect_other_attachments(
        self,
        tgw_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: list[
            dict[str, Any]
        ] = []

        paginator = (
            self.ec2.get_paginator(
                "describe_transit_gateway_attachments"
            )
        )

        try:

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name":
                            "transit-gateway-id",

                        "Values":
                            [tgw_id],
                    }
                ]
            ):

                for attachment in page.get(
                    "TransitGatewayAttachments",
                    [],
                ):

                    attachment_id = (
                        attachment.get(
                            "TransitGatewayAttachmentId"
                        )
                    )

                    if not attachment_id:
                        continue

                    resource_type = str(
                        attachment.get(
                            "ResourceType",
                            "",
                        )
                    ).lower()

                    if resource_type in {
                        "vpc",
                        "peering",
                        "tgw-peering",
                    }:
                        continue

                    association = (
                        attachment.get(
                            "Association"
                        )
                        or {}
                    )

                    result.append(
                        {
                            "attachment_id":
                                attachment_id,

                            "transit_gateway_id":
                                tgw_id,

                            "resource_type":
                                resource_type,

                            "resource_id":
                                attachment.get(
                                    "ResourceId"
                                ),

                            "resource_owner_id":
                                attachment.get(
                                    "ResourceOwnerId"
                                ),

                            "state":
                                attachment.get(
                                    "State"
                                ),

                            "creation_time":
                                self._iso(
                                    attachment.get(
                                        "CreationTime"
                                    )
                                ),

                            "route_table_id":
                                association.get(
                                    "TransitGatewayRouteTableId"
                                ),

                            "association_state":
                                association.get(
                                    "State"
                                ),

                            "tags":
                                self._tags(
                                    attachment.get(
                                        "Tags",
                                        [],
                                    )
                                ),
                        }
                    )

        except Exception as exc:

            return (
                result,
                {
                    "status":
                        "error",

                    "error":
                        str(exc),
                },
            )

        return (
            result,
            {
                "status":
                    "ok",

                "count":
                    len(result),
            },
        )

    # ==============================================================
    # PEERING
    # ==============================================================

    def _collect_peering_attachments(
        self,
        tgw_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: list[
            dict[str, Any]
        ] = []

        paginator = (
            self.ec2.get_paginator(
                "describe_transit_gateway_peering_attachments"
            )
        )

        try:

            for page in paginator.paginate():

                for attachment in page.get(
                    "TransitGatewayPeeringAttachments",
                    [],
                ):

                    requester = (
                        attachment.get(
                            "RequesterTgwInfo"
                        )
                        or {}
                    )

                    accepter = (
                        attachment.get(
                            "AccepterTgwInfo"
                        )
                        or {}
                    )

                    requester_id = (
                        requester.get(
                            "TransitGatewayId"
                        )
                    )

                    accepter_id = (
                        accepter.get(
                            "TransitGatewayId"
                        )
                    )

                    if (
                        requester_id != tgw_id
                        and accepter_id != tgw_id
                    ):
                        continue

                    attachment_id = (
                        attachment.get(
                            "TransitGatewayAttachmentId"
                        )
                    )

                    if not attachment_id:
                        continue

                    result.append(
                        {
                            "attachment_id":
                                attachment_id,

                            "resource_type":
                                "peering",

                            "state":
                                attachment.get(
                                    "State"
                                ),

                            "creation_time":
                                self._iso(
                                    attachment.get(
                                        "CreationTime"
                                    )
                                ),

                            "requester_tgw_id":
                                requester_id,

                            "accepter_tgw_id":
                                accepter_id,

                            "requester_owner_id":
                                requester.get(
                                    "OwnerId"
                                ),

                            "accepter_owner_id":
                                accepter.get(
                                    "OwnerId"
                                ),

                            "requester_region":
                                requester.get(
                                    "Region"
                                ),

                            "accepter_region":
                                accepter.get(
                                    "Region"
                                ),

                            "cross_region":
                                (
                                    bool(
                                        requester.get(
                                            "Region"
                                        )
                                        and accepter.get(
                                            "Region"
                                        )
                                        and
                                        requester.get(
                                            "Region"
                                        )
                                        != accepter.get(
                                            "Region"
                                        )
                                    )
                                ),

                            "tags":
                                self._tags(
                                    attachment.get(
                                        "Tags",
                                        [],
                                    )
                                ),
                        }
                    )

        except Exception as exc:

            return (
                result,
                {
                    "status":
                        "error",

                    "error":
                        str(exc),
                },
            )

        return (
            result,
            {
                "status":
                    "ok",

                "count":
                    len(result),
            },
        )

    # ==============================================================
    # TGW ROUTE TABLES
    # ==============================================================

    def _collect_route_tables(
        self,
        tgw_id: str,
    ) -> dict[str, Any]:

        owner_id = (
            self._get_tgw_owner_id(
                tgw_id
            )
        )

        if (
            self.account_id
            and owner_id
            and self.account_id != owner_id
        ):

            return {
                "route_tables":
                    [],

                "access": {
                    "status":
                        "inaccessible",

                    "reason":
                        (
                            "Transit Gateway is owned by another "
                            "AWS account and route-table inspection "
                            "is not considered available to the "
                            "scanned account."
                        ),

                    "scan_account_id":
                        self.account_id,

                    "owner_account_id":
                        owner_id,
                },
            }

        result: list[
            dict[str, Any]
        ] = []

        paginator = (
            self.ec2.get_paginator(
                "describe_transit_gateway_route_tables"
            )
        )

        try:

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name":
                            "transit-gateway-id",

                        "Values":
                            [tgw_id],
                    }
                ]
            ):

                for table in page.get(
                    "TransitGatewayRouteTables",
                    [],
                ):

                    if table.get(
                        "TransitGatewayRouteTableId"
                    ):

                        result.append(
                            self._normalize_route_table(
                                table
                            )
                        )

        except Exception as exc:

            return {
                "route_tables":
                    result,

                "access": {
                    "status":
                        "error",

                    "reason":
                        "Transit Gateway route-table collection failed.",

                    "error":
                        str(exc),

                    "scan_account_id":
                        self.account_id
                        or None,

                    "owner_account_id":
                        owner_id,
                },
            }

        return {
            "route_tables":
                result,

            "access": {
                "status":
                    "accessible",

                "scan_account_id":
                    self.account_id
                    or None,

                "owner_account_id":
                    owner_id,

                "route_table_count":
                    len(result),
            },
        }

    def _get_tgw_owner_id(
        self,
        tgw_id: str,
    ) -> Optional[str]:

        if tgw_id in self._owner_cache:

            return self._owner_cache[
                tgw_id
            ]

        try:

            response = (
                self.ec2.describe_transit_gateways(
                    TransitGatewayIds=[
                        tgw_id
                    ]
                )
            )

            gateways = response.get(
                "TransitGateways",
                [],
            )

            if not gateways:

                self._owner_cache[
                    tgw_id
                ] = None

                return None

            owner_id = (
                gateways[0].get(
                    "OwnerId"
                )
            )

            result = (
                str(owner_id)
                if owner_id
                else None
            )

            self._owner_cache[
                tgw_id
            ] = result

            return result

        except Exception:

            self._owner_cache[
                tgw_id
            ] = None

            return None

    @staticmethod
    def _normalize_route_table(
        table: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "transit_gateway_route_table_id":
                table.get(
                    "TransitGatewayRouteTableId"
                ),

            "transit_gateway_id":
                table.get(
                    "TransitGatewayId"
                ),

            "state":
                table.get(
                    "State"
                ),

            "default_association":
                table.get(
                    "DefaultAssociationRouteTable"
                ),

            "default_propagation":
                table.get(
                    "DefaultPropagationRouteTable"
                ),

            "creation_time":
                TransitGatewayCollector._iso(
                    table.get(
                        "CreationTime"
                    )
                ),

            "tags":
                TransitGatewayCollector._tags(
                    table.get(
                        "Tags",
                        [],
                    )
                ),
        }

    # ==============================================================
    # ROUTES
    # ==============================================================

    def _collect_routes(
        self,
        route_table_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: list[
            dict[str, Any]
        ] = []

        try:

            paginator = (
                self.ec2.get_paginator(
                    "search_transit_gateway_routes"
                )
            )

            for page in paginator.paginate(
                TransitGatewayRouteTableId=
                    route_table_id,

                Filters=[
                    {
                        "Name":
                            "state",

                        "Values":
                            [
                                "active",
                                "blackhole",
                            ],
                    }
                ],
            ):

                for route in page.get(
                    "Routes",
                    [],
                ):

                    attachments = []

                    for attachment in (
                        route.get(
                            "TransitGatewayAttachments",
                            [],
                        )
                        or []
                    ):

                        attachments.append(
                            {
                                "attachment_id":
                                    attachment.get(
                                        "TransitGatewayAttachmentId"
                                    ),

                                "resource_id":
                                    attachment.get(
                                        "ResourceId"
                                    ),

                                "resource_type":
                                    attachment.get(
                                        "ResourceType"
                                    ),
                            }
                        )

                    state = route.get(
                        "State"
                    )

                    result.append(
                        {
                            "route_table_id":
                                route_table_id,

                            "destination":
                                (
                                    route.get(
                                        "DestinationCidrBlock"
                                    )
                                    or route.get(
                                        "PrefixListId"
                                    )
                                ),

                            "destination_cidr_block":
                                route.get(
                                    "DestinationCidrBlock"
                                ),

                            "prefix_list_id":
                                route.get(
                                    "PrefixListId"
                                ),

                            "state":
                                state,

                            "type":
                                route.get(
                                    "Type"
                                ),

                            "attachments":
                                attachments,

                            "is_blackhole":
                                state == "blackhole",

                            "has_attachment_target":
                                bool(
                                    attachments
                                ),
                        }
                    )

        except Exception as exc:

            return (
                result,
                {
                    "status":
                        "error",

                    "error":
                        str(exc),
                },
            )

        return (
            result,
            {
                "status":
                    "ok",

                "count":
                    len(result),
            },
        )

    # ==============================================================
    # ASSOCIATIONS / PROPAGATIONS
    # ==============================================================

    def _collect_associations(
        self,
        route_table_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        return self._collect_route_table_items(
            operation="get_transit_gateway_route_table_associations",
            result_key="Associations",
            route_table_id=route_table_id,
            normalize=self._normalize_association,
        )

    def _collect_propagations(
        self,
        route_table_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        return self._collect_route_table_items(
            operation="get_transit_gateway_route_table_propagations",
            result_key="TransitGatewayRouteTablePropagations",
            route_table_id=route_table_id,
            normalize=self._normalize_propagation,
        )

    def _collect_route_table_items(
        self,
        *,
        operation: str,
        result_key: str,
        route_table_id: str,
        normalize,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: list[
            dict[str, Any]
        ] = []

        token: Optional[str] = None

        try:

            while True:

                client_method = getattr(
                    self.ec2,
                    operation,
                )

                kwargs = {
                    "TransitGatewayRouteTableId":
                        route_table_id,
                }

                if token:
                    kwargs["NextToken"] = token

                response = (
                    client_method(
                        **kwargs
                    )
                )

                for item in response.get(
                    result_key,
                    [],
                ):

                    if isinstance(
                        item,
                        dict,
                    ):

                        result.append(
                            normalize(
                                item,
                                route_table_id,
                            )
                        )

                token = (
                    response.get(
                        "NextToken"
                    )
                )

                if not token:
                    break

        except Exception as exc:

            return (
                result,
                {
                    "status":
                        "error",

                    "error":
                        str(exc),
                },
            )

        return (
            result,
            {
                "status":
                    "ok",

                "count":
                    len(result),
            },
        )

    @staticmethod
    def _normalize_association(
        item: dict[str, Any],
        route_table_id: str,
    ) -> dict[str, Any]:

        return {
            "route_table_id":
                route_table_id,

            "attachment_id":
                item.get(
                    "TransitGatewayAttachmentId"
                ),

            "resource_id":
                item.get(
                    "ResourceId"
                ),

            "resource_type":
                item.get(
                    "ResourceType"
                ),

            "state":
                item.get(
                    "State"
                ),
        }

    @staticmethod
    def _normalize_propagation(
        item: dict[str, Any],
        route_table_id: str,
    ) -> dict[str, Any]:

        return {
            "route_table_id":
                route_table_id,

            "attachment_id":
                item.get(
                    "TransitGatewayAttachmentId"
                ),

            "resource_id":
                item.get(
                    "ResourceId"
                ),

            "resource_type":
                item.get(
                    "ResourceType"
                ),

            "state":
                item.get(
                    "State"
                ),

            "route_table_announcement_id":
                item.get(
                    "TransitGatewayRouteTableAnnouncementId"
                ),
        }

    # ==============================================================
    # OBSERVATIONS
    # ==============================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        profile = self._cloudwatch_profile()

        if not profile:

            return {
                "cloudwatch": {
                    "status":
                        "not_configured",

                    "metrics":
                        {},
                }
            }

        if profile.get(
            "enabled",
            True,
        ) is not True:

            return {
                "cloudwatch": {
                    "status":
                        "disabled",

                    "metrics":
                        {},
                }
            }

        try:
            start, end = (
                self.get_analysis_period()
            )
        except ValueError as exc:

            return {
                "cloudwatch": {
                    "status":
                        "error",

                    "metrics":
                        {},

                    "error":
                        str(exc),
                }
            }

        requested_period = self._safe_period(
            profile.get(
                "period",
                self.DEFAULT_PERIOD,
            )
        )

        tgw_id = str(
            resource.get(
                "id"
            )
        )

        results = self._metrics_batch_cache.get(
            tgw_id,
            [],
        )

        metrics = self._normalize_metric_results(
            results
        )

        attachment_metrics = (
            self._collect_attachment_metric_results(
                tgw_id
            )
        )

        counts = self._metric_counts(
            metrics
        )

        traffic = self._build_traffic_summary(
            metrics
        )

        attachment_traffic = (
            self._build_attachment_traffic_summary(
                attachment_metrics
            )
        )

        if (
            counts["queried"]
            and
            counts["errors"]
            == counts["queried"]
        ):

            status = "error"

        elif counts["observed"]:

            status = "ok"

        elif (
            counts["no_data"]
            or counts["invalid"]
        ):

            status = "no_data"

        else:

            status = "not_queried"

        return {
            "cloudwatch": {
                "status":
                    status,

                "namespace":
                    str(
                        profile.get(
                            "namespace",
                            self.DEFAULT_NAMESPACE,
                        )
                    ),

                "requested_period":
                    requested_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions": [
                    {
                        "Name":
                            "TransitGateway",

                        "Value":
                            tgw_id,
                    }
                ],

                "metrics":
                    metrics,

                "traffic":
                    traffic,

                "attachment_traffic":
                    attachment_traffic,

                "metric_counts":
                    counts,

                "data_quality": {
                    "traffic_complete":
                        traffic.get(
                            "traffic_complete"
                        ),

                    "attachment_traffic_complete":
                        attachment_traffic.get(
                            "complete"
                        ),
                },
            }
        }

    def _collect_attachment_metric_results(
        self,
        tgw_id: str,
    ) -> dict[str, list[dict[str, Any]]]:

        prefix = (
            f"{tgw_id}:attachment:"
        )

        result: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        for key, metrics in (
            self._metrics_batch_cache.items()
        ):

            if not key.startswith(prefix):
                continue

            attachment_id = key[len(prefix):]

            result[
                attachment_id
            ] = self._normalize_metric_results(
                metrics
            )

        return result

    @staticmethod
    def _normalize_metric_results(
        results: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:

        metrics: dict[
            str,
            dict[str, Any],
        ] = {}

        for result in (
            results or []
        ):

            if not isinstance(
                result,
                dict,
            ):
                continue

            key = (
                result.get(
                    "metric_key"
                )
                or result.get(
                    "metric_name"
                )
            )

            if key:
                metrics[
                    str(key)
                ] = result

        return metrics

    @staticmethod
    def _metric_counts(
        metrics: dict[str, dict[str, Any]],
    ) -> dict[str, int]:

        return {
            "queried":
                len(metrics),

            "observed":
                sum(
                    metric.get(
                        "status"
                    ) == "ok"
                    and metric.get(
                        "has_data"
                    ) is True
                    for metric in metrics.values()
                ),

            "no_data":
                sum(
                    metric.get(
                        "status"
                    ) == "no_data"
                    for metric in metrics.values()
                ),

            "invalid":
                sum(
                    metric.get(
                        "status"
                    ) == "invalid_data"
                    for metric in metrics.values()
                ),

            "errors":
                sum(
                    metric.get(
                        "status"
                    ) == "error"
                    for metric in metrics.values()
                ),
        }

    @classmethod
    def _metric_value(
        cls,
        metrics: dict[str, dict[str, Any]],
        name: str,
    ) -> Optional[float]:

        metric = metrics.get(
            name
        )

        if not isinstance(
            metric,
            dict,
        ):
            return None

        if metric.get(
            "status"
        ) != "ok":
            return None

        if metric.get(
            "has_data"
        ) is not True:
            return None

        value = metric.get(
            "value"
        )

        if isinstance(
            value,
            (int, float),
        ):
            return float(value)

        return None

    @classmethod
    def _build_traffic_summary(
        cls,
        metrics: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:

        bytes_in = cls._metric_value(
            metrics,
            "BytesIn",
        )

        bytes_out = cls._metric_value(
            metrics,
            "BytesOut",
        )

        traffic_complete = (
            bytes_in is not None
            and bytes_out is not None
        )

        return {
            "bytes_in":
                bytes_in,

            "bytes_out":
                bytes_out,

            "total_bytes":
                (
                    bytes_in + bytes_out
                    if traffic_complete
                    else None
                ),

            "ingress_gib":
                (
                    bytes_in / (1024 ** 3)
                    if bytes_in is not None
                    else None
                ),

            "total_gib":
                (
                    (bytes_in + bytes_out)
                    / (1024 ** 3)
                    if traffic_complete
                    else None
                ),

            "traffic_observed":
                (
                    bytes_in > 0
                    or bytes_out > 0
                )
                if (
                    bytes_in is not None
                    and bytes_out is not None
                )
                else None,

            "traffic_complete":
                traffic_complete,

            "missing_is_zero":
                False,

            "semantics": {
                "purpose":
                    "operational_activity_and_cost_exposure",

                "bytes_in_role":
                    (
                        "closest CloudWatch proxy for "
                        "traffic entering the TGW from "
                        "source attachments"
                    ),

                "bytes_are_billing_amount":
                    False,
            },
        }

    def _build_attachment_traffic_summary(
        self,
        attachment_metrics: dict[
            str,
            dict[str, dict[str, Any]]
        ],
    ) -> dict[str, Any]:

        items: list[
            dict[str, Any]
        ] = []

        for attachment_id, metrics in (
            attachment_metrics.items()
        ):

            bytes_in = self._metric_value(
                metrics,
                "BytesIn",
            )

            bytes_out = self._metric_value(
                metrics,
                "BytesOut",
            )

            complete = (
                bytes_in is not None
                and bytes_out is not None
            )

            items.append(
                {
                    "attachment_id":
                        attachment_id,

                    "bytes_in":
                        bytes_in,

                    "bytes_out":
                        bytes_out,

                    "ingress_gib":
                        (
                            bytes_in / (1024 ** 3)
                            if bytes_in is not None
                            else None
                        ),

                    "complete":
                        complete,

                    "observed":
                        (
                            bytes_in > 0
                            or bytes_out > 0
                        )
                        if complete
                        else None,
                }
            )

        complete = bool(
            attachment_metrics
        ) and all(
            item.get(
                "complete"
            ) is True
            for item in items
        )

        return {
            "items":
                items,

            "count":
                len(items),

            "complete":
                complete,

            "semantics": {
                "purpose":
                    "attachment_level_traffic",

                "billing_amount":
                    False,
            },
        }

    # ==============================================================
    # TOPOLOGY
    # ==============================================================

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        relationships = (
            collected_resource.get(
                "relationships",
                {},
            )
        )

        if not isinstance(
            relationships,
            dict,
        ):
            return {
                "status":
                    "incomplete",

                "reason":
                    "Transit Gateway relationships unavailable.",
            }

        tgw_id = resource.get(
            "id"
        )

        vpc_attachments = (
            relationships.get(
                "vpc_attachments",
                [],
            )
        )

        if not isinstance(
            vpc_attachments,
            list,
        ):
            vpc_attachments = []

        attachment_status = (
            relationships.get(
                "collection_status",
                {},
            ).get(
                "vpc_attachments",
                {},
            )
        )

        vpc_topologies: list[
            dict[str, Any]
        ] = []

        for attachment in vpc_attachments:

            if not isinstance(
                attachment,
                dict,
            ):
                continue

            vpc_id = attachment.get(
                "vpc_id"
            )

            attachment_id = (
                attachment.get(
                    "attachment_id"
                )
            )

            if not vpc_id:
                continue

            try:

                topology = (
                    self.topology_collector.collect(
                        vpc_id=vpc_id,
                        resource_type=self.resource_type,
                        resource_id=tgw_id,
                    )
                )

                if (
                    not isinstance(
                        topology,
                        dict,
                    )
                    or topology.get(
                        "status"
                    ) != "ok"
                ):

                    vpc_topologies.append(
                        {
                            "vpc_id":
                                vpc_id,

                            "attachment_id":
                                attachment_id,

                            "status":
                                "incomplete",
                        }
                    )

                    continue

                resolver = (
                    NetworkRelationshipResolver(
                        topology
                    )
                )

                routes = (
                    resolver.routes_targeting(
                        "transit_gateway",
                        tgw_id,
                    )
                )

                if not isinstance(
                    routes,
                    list,
                ):
                    routes = []

                active = [
                    route
                    for route in routes
                    if route.get(
                        "state"
                    ) == "active"
                ]

                blackhole = [
                    route
                    for route in routes
                    if route.get(
                        "state"
                    ) == "blackhole"
                ]

                vpc_topologies.append(
                    {
                        "vpc_id":
                            vpc_id,

                        "attachment_id":
                            attachment_id,

                        "attachment_state":
                            attachment.get(
                                "state"
                            ),

                        "status":
                            "ok",

                        "vpc_routes_to_tgw_count":
                            len(routes),

                        "active_vpc_routes_to_tgw_count":
                            len(active),

                        "blackhole_vpc_routes_to_tgw_count":
                            len(blackhole),

                        "vpc_route_table_ids":
                            sorted(
                                {
                                    route.get(
                                        "route_table_id"
                                    )
                                    for route in routes
                                    if route.get(
                                        "route_table_id"
                                    )
                                }
                            ),

                        "tgw_subnet_ids":
                            sorted(
                                {
                                    route.get(
                                        "subnet_id"
                                    )
                                    for route in routes
                                    if route.get(
                                        "subnet_id"
                                    )
                                }
                            ),
                    }
                )

            except Exception as exc:

                vpc_topologies.append(
                    {
                        "vpc_id":
                            vpc_id,

                        "attachment_id":
                            attachment_id,

                        "status":
                            "error",

                        "error":
                            str(exc),
                    }
                )

        valid = [
            item
            for item in vpc_topologies
            if item.get(
                "status"
            ) == "ok"
        ]

        return {
            "status":
                "ok",

            "transit_gateway_id":
                tgw_id,

            "vpcs":
                vpc_topologies,

            "attached_vpc_ids":
                sorted(
                    {
                        item.get(
                            "vpc_id"
                        )
                        for item in valid
                        if item.get(
                            "vpc_id"
                        )
                    }
                ),

            "vpc_route_table_ids":
                sorted(
                    {
                        route_table_id
                        for item in valid
                        for route_table_id in item.get(
                            "vpc_route_table_ids",
                            [],
                        )
                    }
                ),

            "tgw_subnet_ids":
                sorted(
                    {
                        subnet_id
                        for item in valid
                        for subnet_id in item.get(
                            "tgw_subnet_ids",
                            [],
                        )
                    }
                ),

            "vpc_routes_to_tgw_count":
                sum(
                    item.get(
                        "vpc_routes_to_tgw_count",
                        0,
                    )
                    or 0
                    for item in valid
                ),

            "active_vpc_routes_to_tgw_count":
                sum(
                    item.get(
                        "active_vpc_routes_to_tgw_count",
                        0,
                    )
                    or 0
                    for item in valid
                ),

            "blackhole_vpc_routes_to_tgw_count":
                sum(
                    item.get(
                        "blackhole_vpc_routes_to_tgw_count",
                        0,
                    )
                    or 0
                    for item in valid
                ),

            "summary": {
                "attached_vpc_count":
                    len(
                        {
                            item.get(
                                "vpc_id"
                            )
                            for item in valid
                            if item.get(
                                "vpc_id"
                            )
                        }
                    ),

                "vpc_route_table_count":
                    len(
                        {
                            route_table_id
                            for item in valid
                            for route_table_id in item.get(
                                "vpc_route_table_ids",
                                [],
                            )
                        }
                    ),

                "tgw_subnet_count":
                    len(
                        {
                            subnet_id
                            for item in valid
                            for subnet_id in item.get(
                                "tgw_subnet_ids",
                                [],
                            )
                        }
                    ),

                "vpc_routes_to_tgw_count":
                    sum(
                        item.get(
                            "vpc_routes_to_tgw_count",
                            0,
                        )
                        or 0
                        for item in valid
                    ),

                "active_vpc_routes_to_tgw_count":
                    sum(
                        item.get(
                            "active_vpc_routes_to_tgw_count",
                            0,
                        )
                        or 0
                        for item in valid
                    ),

                "blackhole_vpc_routes_to_tgw_count":
                    sum(
                        item.get(
                            "blackhole_vpc_routes_to_tgw_count",
                            0,
                        )
                        or 0
                        for item in valid
                    ),

                "topology_complete":
                    len(valid)
                    == len(vpc_attachments),
            },

            "collection_status": {
                "vpc_attachments":
                    attachment_status,

                "topology_complete":
                    len(valid)
                    == len(vpc_attachments),
            },
        }

    # ==============================================================
    # OPTIMIZATION EVIDENCE
    # ==============================================================

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._dict(
            collected_resource.get(
                "identity"
            )
        )

        configuration = self._dict(
            collected_resource.get(
                "configuration"
            )
        )

        relationships = self._dict(
            collected_resource.get(
                "relationships"
            )
        )

        topology = self._dict(
            collected_resource.get(
                "topology"
            )
        )

        observations = self._dict(
            collected_resource.get(
                "observations"
            )
        )

        cloudwatch = self._dict(
            observations.get(
                "cloudwatch"
            )
        )

        relationship_summary = self._dict(
            relationships.get(
                "summary"
            )
        )

        topology_summary = self._dict(
            topology.get(
                "summary"
            )
        )

        return {
            "resource": {
                "resource_id":
                    resource.get(
                        "id"
                    ),

                "resource_type":
                    self.resource_type,

                "name":
                    identity.get(
                        "name"
                    ),

                "state":
                    identity.get(
                        "state"
                    ),

                "owner_id":
                    identity.get(
                        "owner_id"
                    ),
            },

            "configuration":
                {
                    key: value
                    for key, value
                    in configuration.items()
                    if key != "tags"
                },

            "relationships": {
                "attachment_count":
                    relationship_summary.get(
                        "attachment_count"
                    ),

                "active_attachment_count":
                    relationship_summary.get(
                        "active_attachment_count"
                    ),

                "vpc_attachment_count":
                    relationship_summary.get(
                        "vpc_attachment_count"
                    ),

                "other_attachment_count":
                    relationship_summary.get(
                        "other_attachment_count"
                    ),

                "peering_attachment_count":
                    relationship_summary.get(
                        "peering_attachment_count"
                    ),

                "route_table_count":
                    relationship_summary.get(
                        "route_table_count"
                    ),

                "route_count":
                    relationship_summary.get(
                        "route_count"
                    ),

                "active_route_count":
                    relationship_summary.get(
                        "active_route_count"
                    ),

                "blackhole_route_count":
                    relationship_summary.get(
                        "blackhole_route_count"
                    ),

                "association_count":
                    relationship_summary.get(
                        "association_count"
                    ),

                "propagation_count":
                    relationship_summary.get(
                        "propagation_count"
                    ),

                "collection_complete":
                    relationship_summary.get(
                        "collection_complete"
                    ),

                "vpc_attachments":
                    relationships.get(
                        "vpc_attachments",
                        [],
                    ),

                "other_attachments":
                    relationships.get(
                        "other_attachments",
                        [],
                    ),

                "peering_attachments":
                    relationships.get(
                        "peering_attachments",
                        [],
                    ),
            },

            "network": {
                "attached_vpc_count":
                    topology_summary.get(
                        "attached_vpc_count"
                    ),

                "vpc_routes_to_tgw_count":
                    topology_summary.get(
                        "vpc_routes_to_tgw_count"
                    ),

                "active_vpc_routes_to_tgw_count":
                    topology_summary.get(
                        "active_vpc_routes_to_tgw_count"
                    ),

                "blackhole_vpc_routes_to_tgw_count":
                    topology_summary.get(
                        "blackhole_vpc_routes_to_tgw_count"
                    ),

                "vpc_route_table_count":
                    topology_summary.get(
                        "vpc_route_table_count"
                    ),

                "tgw_subnet_count":
                    topology_summary.get(
                        "tgw_subnet_count"
                    ),
            },

            "traffic":
                cloudwatch.get(
                    "traffic",
                    {},
                ),

            "attachment_traffic":
                cloudwatch.get(
                    "attachment_traffic",
                    {},
                ),

            "data_quality": {
                "attachments_complete":
                    relationships.get(
                        "collection_status",
                        {},
                    ).get(
                        "attachments_complete"
                    ),

                "route_data_complete":
                    relationships.get(
                        "collection_status",
                        {},
                    ).get(
                        "route_data_complete"
                    ),

                "topology_complete":
                    topology_summary.get(
                        "topology_complete"
                    ),

                "cloudwatch_status":
                    cloudwatch.get(
                        "status"
                    ),

                "traffic_complete":
                    self._dict(
                        cloudwatch.get(
                            "traffic"
                        )
                    ).get(
                        "traffic_complete"
                    ),

                "attachment_traffic_complete":
                    self._dict(
                        cloudwatch.get(
                            "attachment_traffic"
                        )
                    ).get(
                        "complete"
                    ),
            },

            "semantics": {
                "traffic_is_billing_amount":
                    False,

                "ingress_is_cost_exposure_proxy":
                    True,

                "attachment_traffic_supports_source_analysis":
                    True,
            },
        }

    # ==============================================================
    # HELPERS
    # ==============================================================

    @staticmethod
    def _safe_period(
        value: Any,
    ) -> int:

        try:
            value = int(value)
        except (
            TypeError,
            ValueError,
        ):
            value = (
                TransitGatewayCollector.DEFAULT_PERIOD
            )

        return max(
            value,
            60,
        )

    @staticmethod
    def _normalize_metric_specs(
        specs: Any,
    ) -> list[dict[str, Any]]:

        if not isinstance(
            specs,
            list,
        ):
            return []

        result = []

        for spec in specs:

            if isinstance(
                spec,
                str,
            ):

                name = spec.strip()

                if name:
                    result.append(
                        {
                            "name":
                                name,

                            "statistic":
                                "Sum",
                        }
                    )

                continue

            if not isinstance(
                spec,
                dict,
            ):
                continue

            name = str(
                spec.get(
                    "name",
                    "",
                )
            ).strip()

            if not name:
                continue

            normalized = {
                "name":
                    name,

                "statistic":
                    spec.get(
                        "statistic",
                        "Sum",
                    ),
            }

            if spec.get(
                "unit"
            ):
                normalized["unit"] = (
                    spec["unit"]
                )

            if spec.get(
                "key"
            ):
                normalized["key"] = (
                    spec["key"]
                )

            result.append(
                normalized
            )

        return result

    @staticmethod
    def _tags(
        tags: List[
            Dict[str, Any]
        ],
    ) -> Dict[str, Any]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        return {
            str(tag["Key"]):
                tag.get("Value")
            for tag in tags
            if (
                isinstance(
                    tag,
                    dict,
                )
                and tag.get("Key")
            )
        }

    @staticmethod
    def _iso(
        value: Any,
    ) -> Optional[str]:

        if value is None:
            return None

        if hasattr(
            value,
            "isoformat",
        ):
            return value.isoformat()

        return str(value)

    @staticmethod
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