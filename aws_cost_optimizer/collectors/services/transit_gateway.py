
"""
AWS Transit Gateway Collector.

Evidence-first collector.

The collector:
- discovers Transit Gateways
- collects ownership/configuration
- collects VPC / other / peering attachments
- collects TGW route tables, routes, associations and propagations
- collects VPC-side routes targeting the TGW
- collects CloudWatch traffic
- exposes explicit collection status

Important semantic rule
-----------------------
An API failure is NEVER represented as an empty successful collection.

Therefore:

    successful empty result -> status="ok", items=[]
    failed collection      -> status="error", items=[]
    inaccessible collection-> status="inaccessible", items=[]

This prevents analyzers from confusing:

    "nothing exists"

with:

    "we could not inspect it".
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register

from collectors.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)

from collectors.network.topology import (
    NetworkTopologyCollector,
)

from collectors.network.relationships import (
    NetworkRelationshipResolver,
)


@register
class TransitGatewayCollector(BaseCollector):

    key = "transit_gateway"
    resource_type = "transit_gateway"

    # ================================================================
    # INITIALIZATION
    # ================================================================

    def __init__(
        self,
        scan: Any,
        region: str,
        profile: Any = None,
    ):
        super().__init__(
            scan,
            region=region,
            profile=profile,
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

    # ================================================================
    # DISCOVERY
    # ================================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: List[Dict[str, Any]] = []

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

                    # Keep only currently usable /
                    # transitional gateways.
                    if state not in {
                        "available",
                        "pending",
                    }:
                        continue

                    resources.append(
                        {
                            "id":
                                tgw_id,

                            "raw":
                                tgw,
                        }
                    )

        except Exception as exc:

            raise RuntimeError(
                "Failed to discover Transit Gateways "
                f"in {self.region}: {exc}"
            ) from exc

        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        resource_id = resource.get(
            "id"
        )

        if not resource_id:
            raise ValueError(
                "Transit Gateway ID is missing"
            )

        return str(
            resource_id
        )

    # ================================================================
    # IDENTITY
    # ================================================================

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

        owner_id = str(
            tgw.get(
                "OwnerId"
            )
            or ""
        )

        scan_account = (
            self.account_id
            or None
        )

        return {
            "name":
                (
                    tags.get("Name")
                    or tgw.get("Description")
                    or resource.get("id")
                ),

            "transit_gateway_id":
                resource.get("id"),

            "state":
                tgw.get("State"),

            "owner_id":
                tgw.get("OwnerId"),

            "description":
                tgw.get("Description"),

            "tags":
                tags,

            "ownership": {
                "scan_account_id":
                    scan_account,

                "owner_account_id":
                    owner_id or None,

                "is_resource_owner":
                    (
                        bool(
                            scan_account
                            and owner_id
                        )
                        and
                        scan_account == owner_id
                    ),
            },
        }

    # ================================================================
    # CONFIGURATION
    # ================================================================

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

    # ================================================================
    # RELATIONSHIPS
    # ================================================================

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
                    "Transit Gateway ID is missing",
            }

        vpc_attachments, vpc_status = (
            self._collect_vpc_attachments(
                tgw_id
            )
        )

        other_attachments, other_status = (
            self._collect_other_attachments(
                tgw_id
            )
        )

        peering_attachments, peering_status = (
            self._collect_peering_attachments(
                tgw_id
            )
        )

        route_table_result = (
            self._collect_route_tables(
                tgw_id
            )
        )

        route_tables = route_table_result.get(
            "route_tables",
            [],
        )

        route_table_access = (
            route_table_result.get(
                "access",
                {},
            )
        )

        route_table_status = (
            route_table_access.get(
                "status"
            )
        )

        routes: List[
            Dict[str, Any]
        ] = []

        associations: List[
            Dict[str, Any]
        ] = []

        propagations: List[
            Dict[str, Any]
        ] = []

        routes_status = {
            "status":
                "not_queried"
        }

        associations_status = {
            "status":
                "not_queried"
        }

        propagations_status = {
            "status":
                "not_queried"
        }

        if route_table_status == "accessible":

            for route_table in route_tables:

                route_table_id = (
                    route_table.get(
                        "transit_gateway_route_table_id"
                    )
                )

                if not route_table_id:
                    continue

                collected_routes, status = (
                    self._collect_routes(
                        route_table_id
                    )
                )

                routes.extend(
                    collected_routes
                )

                if status.get("status") == "error":

                    routes_status = {
                        "status":
                            "error",

                        "error":
                            status.get("error"),
                    }

                elif routes_status.get(
                    "status"
                ) == "not_queried":

                    routes_status = {
                        "status":
                            "ok",
                    }

                collected_associations, status = (
                    self._collect_associations(
                        route_table_id
                    )
                )

                associations.extend(
                    collected_associations
                )

                if status.get("status") == "error":

                    associations_status = {
                        "status":
                            "error",

                        "error":
                            status.get("error"),
                    }

                elif associations_status.get(
                    "status"
                ) == "not_queried":

                    associations_status = {
                        "status":
                            "ok",
                    }

                collected_propagations, status = (
                    self._collect_propagations(
                        route_table_id
                    )
                )

                propagations.extend(
                    collected_propagations
                )

                if status.get("status") == "error":

                    propagations_status = {
                        "status":
                            "error",

                        "error":
                            status.get("error"),
                    }

                elif propagations_status.get(
                    "status"
                ) == "not_queried":

                    propagations_status = {
                        "status":
                            "ok",
                    }

        active_routes = [
            route
            for route in routes
            if route.get(
                "state"
            ) == "active"
        ]

        blackhole_routes = [
            route
            for route in routes
            if route.get(
                "state"
            ) == "blackhole"
        ]

        active_vpc_attachments = [
            attachment
            for attachment in vpc_attachments
            if str(
                attachment.get(
                    "state",
                    "",
                )
            ).lower()
            == "available"
        ]

        active_other_attachments = [
            attachment
            for attachment in other_attachments
            if str(
                attachment.get(
                    "state",
                    "",
                )
            ).lower()
            == "available"
        ]

        active_peering_attachments = [
            attachment
            for attachment in peering_attachments
            if str(
                attachment.get(
                    "state",
                    "",
                )
            ).lower()
            == "available"
        ]

        attached_vpcs = sorted(
            {
                attachment.get(
                    "vpc_id"
                )
                for attachment in vpc_attachments
                if attachment.get(
                    "vpc_id"
                )
            }
        )

        associations_valid = (
            associations_status.get(
                "status"
            )
            == "ok"
        )

        propagations_valid = (
            propagations_status.get(
                "status"
            )
            == "ok"
        )

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
        ) if associations_valid else []

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
        ) if propagations_valid else []

        attachment_collections_complete = all(
            status.get(
                "status"
            ) == "ok"
            for status in (
                vpc_status,
                other_status,
                peering_status,
            )
        )

        route_collections_complete = (
            route_table_status == "accessible"
            and
            routes_status.get(
                "status"
            ) == "ok"
            and
            associations_status.get(
                "status"
            ) == "ok"
            and
            propagations_status.get(
                "status"
            ) == "ok"
        )

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
                route_table_access,

            "collection_status": {
                "vpc_attachments":
                    vpc_status,

                "other_attachments":
                    other_status,

                "peering_attachments":
                    peering_status,

                "route_tables":
                    route_table_access,

                "routes":
                    routes_status,

                "associations":
                    associations_status,

                "propagations":
                    propagations_status,

                "attachments_complete":
                    attachment_collections_complete,

                "route_data_complete":
                    route_collections_complete,
            },

            "summary": {
                "vpc_count":
                    len(attached_vpcs),

                "vpc_attachment_count":
                    len(vpc_attachments),

                "active_vpc_attachment_count":
                    len(active_vpc_attachments),

                "other_attachment_count":
                    len(other_attachments),

                "active_other_attachment_count":
                    len(active_other_attachments),

                "peering_attachment_count":
                    len(peering_attachments),

                "active_peering_attachment_count":
                    len(active_peering_attachments),

                "route_table_count":
                    (
                        len(route_tables)
                        if (
                            route_table_status
                            == "accessible"
                        )
                        else None
                    ),

                "route_count":
                    (
                        len(routes)
                        if (
                            route_table_status
                            == "accessible"
                            and
                            routes_status.get(
                                "status"
                            ) == "ok"
                        )
                        else None
                    ),

                "active_route_count":
                    (
                        len(active_routes)
                        if (
                            route_table_status
                            == "accessible"
                            and
                            routes_status.get(
                                "status"
                            ) == "ok"
                        )
                        else None
                    ),

                "blackhole_route_count":
                    (
                        len(blackhole_routes)
                        if (
                            route_table_status
                            == "accessible"
                            and
                            routes_status.get(
                                "status"
                            ) == "ok"
                        )
                        else None
                    ),

                "association_count":
                    (
                        len(associations)
                        if associations_valid
                        else None
                    ),

                "propagation_count":
                    (
                        len(propagations)
                        if propagations_valid
                        else None
                    ),

                "associated_attachment_count":
                    (
                        len(
                            associated_attachment_ids
                        )
                        if associations_valid
                        else None
                    ),

                "enabled_propagation_attachment_count":
                    (
                        len(
                            enabled_propagation_attachment_ids
                        )
                        if propagations_valid
                        else None
                    ),

                "has_attachments":
                    (
                        bool(
                            vpc_attachments
                            or other_attachments
                            or peering_attachments
                        )
                        if attachment_collections_complete
                        else None
                    ),

                "has_routes":
                    (
                        bool(routes)
                        if route_collections_complete
                        else None
                    ),

                "has_blackhole_routes":
                    (
                        bool(
                            blackhole_routes
                        )
                        if route_collections_complete
                        else None
                    ),

                "collection_complete":
                    (
                        attachment_collections_complete
                        and
                        route_collections_complete
                    ),
            },
        }

    # ================================================================
    # VPC ATTACHMENTS
    # ================================================================

    def _collect_vpc_attachments(
        self,
        transit_gateway_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: List[
            Dict[str, Any]
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
                            [transit_gateway_id],
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

                            "subnet_ids":
                                list(
                                    attachment.get(
                                        "SubnetIds",
                                        [],
                                    )
                                    or []
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
                [],
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

    # ================================================================
    # OTHER ATTACHMENTS
    # ================================================================

    def _collect_other_attachments(
        self,
        transit_gateway_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: List[
            Dict[str, Any]
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
                            [transit_gateway_id],
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

                            "resource_id":
                                attachment.get(
                                    "ResourceId"
                                ),

                            "resource_type":
                                resource_type,

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
                [],
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

    # ================================================================
    # TGW PEERING
    # ================================================================

    def _collect_peering_attachments(
        self,
        transit_gateway_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: List[
            Dict[str, Any]
        ] = []

        try:

            paginator = (
                self.ec2.get_paginator(
                    "describe_transit_gateway_peering_attachments"
                )
            )

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
                        requester_id
                        != transit_gateway_id
                        and
                        accepter_id
                        != transit_gateway_id
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
                [],
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

    # ================================================================
    # TGW ROUTE TABLES
    # ================================================================

    def _collect_route_tables(
        self,
        transit_gateway_id: str,
    ) -> Dict[str, Any]:

        owner_id = (
            self._get_tgw_owner_id(
                transit_gateway_id
            )
        )

        # A shared TGW can be discovered by the participant
        # account, but route-table management belongs to the owner.
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
                            "AWS account; TGW route-table inspection "
                            "is not treated as available to the scanned "
                            "account."
                        ),

                    "scan_account_id":
                        self.account_id,

                    "owner_account_id":
                        owner_id,
                },
            }

        result: List[
            Dict[str, Any]
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
                            [transit_gateway_id],
                    }
                ]
            ):

                for table in page.get(
                    "TransitGatewayRouteTables",
                    [],
                ):

                    route_table_id = (
                        table.get(
                            "TransitGatewayRouteTableId"
                        )
                    )

                    if not route_table_id:
                        continue

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
                        (
                            "Transit Gateway route-table "
                            "collection failed."
                        ),

                    "error":
                        str(exc),

                    "scan_account_id":
                        self.account_id or None,

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
                    self.account_id or None,

                "owner_account_id":
                    owner_id,

                "route_table_count":
                    len(result),
            },
        }

    def _get_tgw_owner_id(
        self,
        transit_gateway_id: str,
    ) -> Optional[str]:

        try:

            response = (
                self.ec2.describe_transit_gateways(
                    TransitGatewayIds=[
                        transit_gateway_id
                    ]
                )
            )

            gateways = response.get(
                "TransitGateways",
                [],
            )

            if not gateways:
                return None

            owner_id = (
                gateways[0].get(
                    "OwnerId"
                )
            )

            return (
                str(owner_id)
                if owner_id
                else None
            )

        except Exception:
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

    # ================================================================
    # TGW ROUTES
    # ================================================================

    def _collect_routes(
        self,
        route_table_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: List[
            Dict[str, Any]
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

                        "Values": [
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
                [],
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

    # ================================================================
    # ASSOCIATIONS
    # ================================================================

    def _collect_associations(
        self,
        route_table_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: List[
            Dict[str, Any]
        ] = []

        try:

            paginator = (
                self.ec2.get_paginator(
                    "get_transit_gateway_route_table_associations"
                )
            )

            for page in paginator.paginate(
                TransitGatewayRouteTableId=
                    route_table_id
            ):

                items = (
                    page.get(
                        "Associations",
                        []
                    )
                    or []
                )

                for association in items:

                    result.append(
                        {
                            "route_table_id":
                                route_table_id,

                            "attachment_id":
                                association.get(
                                    "TransitGatewayAttachmentId"
                                ),

                            "resource_id":
                                association.get(
                                    "ResourceId"
                                ),

                            "resource_type":
                                association.get(
                                    "ResourceType"
                                ),

                            "state":
                                association.get(
                                    "State"
                                ),
                        }
                    )

        except Exception as exc:

            return (
                [],
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

    # ================================================================
    # PROPAGATIONS
    # ================================================================

    def _collect_propagations(
        self,
        route_table_id: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, Any],
    ]:

        result: List[
            Dict[str, Any]
        ] = []

        try:

            paginator = (
                self.ec2.get_paginator(
                    "get_transit_gateway_route_table_propagations"
                )
            )

            for page in paginator.paginate(
                TransitGatewayRouteTableId=
                    route_table_id
            ):

                items = (
                    page.get(
                        "TransitGatewayRouteTablePropagations",
                        [],
                    )
                    or []
                )

                for propagation in items:

                    result.append(
                        {
                            "route_table_id":
                                route_table_id,

                            "attachment_id":
                                propagation.get(
                                    "TransitGatewayAttachmentId"
                                ),

                            "resource_id":
                                propagation.get(
                                    "ResourceId"
                                ),

                            "resource_type":
                                propagation.get(
                                    "ResourceType"
                                ),

                            "state":
                                propagation.get(
                                    "State"
                                ),

                            "route_table_announcement_id":
                                propagation.get(
                                    "TransitGatewayRouteTableAnnouncementId"
                                ),
                        }
                    )

        except Exception as exc:

            return (
                [],
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

    # ================================================================
    # CLOUDWATCH
    # ================================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        observations_profile = (
            self.profile.get(
                "observations",
                {},
            )
        )

        if not isinstance(
            observations_profile,
            dict,
        ):
            observations_profile = {}

        cloudwatch_config = (
            observations_profile.get(
                "cloudwatch",
                {},
            )
        )

        if not isinstance(
            cloudwatch_config,
            dict,
        ):
            cloudwatch_config = {}

        enabled = (
            cloudwatch_config.get(
                "enabled",
                True,
            )
            is True
        )

        if not enabled:

            return {
                "cloudwatch": {
                    "status":
                        "disabled",

                    "metrics":
                        {},
                }
            }

        namespace = (
            cloudwatch_config.get(
                "namespace",
                "AWS/TransitGateway",
            )
        )

        try:

            requested_period = int(
                cloudwatch_config.get(
                    "period",
                    3600,
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            requested_period = 3600

        raw_specs = (
            cloudwatch_config.get(
                "metrics",
                [],
            )
        )

        metric_specs = (
            self._normalize_metric_specs(
                raw_specs
            )
        )

        if not metric_specs:

            return {
                "cloudwatch": {
                    "status":
                        "not_queried",

                    "namespace":
                        namespace,

                    "metrics":
                        {},

                    "reason":
                        "No CloudWatch metrics configured",
                }
            }

        start, end = (
            self.get_analysis_period()
        )

        dimensions = [
            {
                "Name":
                    "TransitGateway",

                "Value":
                    resource.get(
                        "id"
                    ),
            }
        ]

        try:

            results = (
                self.metric_collector.collect(
                    namespace=namespace,

                    dimensions=dimensions,

                    metric_specs=metric_specs,

                    start=start,

                    end=end,

                    requested_period=requested_period,
                )
            )

        except Exception as exc:

            return {
                "cloudwatch": {
                    "status":
                        "error",

                    "namespace":
                        namespace,

                    "requested_period":
                        requested_period,

                    "effective_period":
                        requested_period,

                    "start":
                        start.isoformat(),

                    "end":
                        end.isoformat(),

                    "dimensions":
                        dimensions,

                    "metrics":
                        {},

                    "traffic":
                        {
                            "traffic_available":
                                False,

                            "traffic_complete":
                                False,

                            "traffic_observed":
                                None,

                            "missing_is_zero":
                                False,
                        },

                    "metric_counts": {
                        "queried":
                            0,

                        "observed":
                            0,

                        "no_data":
                            0,

                        "invalid":
                            0,

                        "errors":
                            len(metric_specs),
                    },

                    "error":
                        str(exc),
                }
            }

        metrics: Dict[
            str,
            Any,
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

            if not key:
                continue

            metrics[
                str(key)
            ] = result

        queried_count = len(
            metrics
        )

        observed_count = sum(
            1
            for metric in metrics.values()
            if (
                metric.get(
                    "status"
                ) == "ok"
                and
                metric.get(
                    "has_data"
                ) is True
            )
        )

        no_data_count = sum(
            1
            for metric in metrics.values()
            if metric.get(
                "status"
            ) == "no_data"
        )

        invalid_count = sum(
            1
            for metric in metrics.values()
            if metric.get(
                "status"
            ) == "invalid_data"
        )

        error_count = sum(
            1
            for metric in metrics.values()
            if metric.get(
                "status"
            ) == "error"
        )

        effective_period = (
            self._effective_period(
                metrics,
                requested_period,
            )
        )

        traffic = (
            self._build_traffic_summary(
                metrics
            )
        )

        if (
            queried_count > 0
            and error_count == queried_count
        ):

            status = "error"

        elif observed_count > 0:

            status = "ok"

        elif (
            no_data_count > 0
            or invalid_count > 0
        ):

            status = "no_data"

        else:

            status = "not_queried"

        return {
            "cloudwatch": {
                "status":
                    status,

                "namespace":
                    namespace,

                "requested_period":
                    requested_period,

                "effective_period":
                    effective_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions":
                    dimensions,

                "metrics":
                    metrics,

                "traffic":
                    traffic,

                "metric_counts": {
                    "queried":
                        queried_count,

                    "observed":
                        observed_count,

                    "no_data":
                        no_data_count,

                    "invalid":
                        invalid_count,

                    "errors":
                        error_count,
                },

                "data_quality": {
                    "metric_count":
                        queried_count,

                    "queried_metric_count":
                        queried_count,

                    "observed_metric_count":
                        observed_count,

                    "no_data_metric_count":
                        no_data_count,

                    "invalid_metric_count":
                        invalid_count,

                    "metric_error_count":
                        error_count,

                    "observation_window_available":
                        (
                            start is not None
                            and end is not None
                        ),
                },
            }
        }

    @staticmethod
    def _normalize_metric_specs(
        metric_specs: List[Any],
    ) -> List[Dict[str, Any]]:

        result: List[
            Dict[str, Any]
        ] = []

        if not isinstance(
            metric_specs,
            list,
        ):
            return result

        for spec in metric_specs:

            if isinstance(
                spec,
                str,
            ):

                name = spec.strip()

                if not name:
                    continue

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

            if (
                "unit" in spec
                and spec.get(
                    "unit"
                )
            ):

                normalized[
                    "unit"
                ] = spec.get(
                    "unit"
                )

            if spec.get(
                "key"
            ):

                normalized[
                    "key"
                ] = spec.get(
                    "key"
                )

            result.append(
                normalized
            )

        return result

    # ================================================================
    # CLOUDWATCH SUMMARY
    # ================================================================

    @staticmethod
    def _effective_period(
        metrics: Dict[str, Any],
        default: int,
    ) -> int:

        for metric in metrics.values():

            if not isinstance(
                metric,
                dict,
            ):
                continue

            value = metric.get(
                "effective_period"
            )

            if value is None:
                continue

            try:
                return int(
                    value
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

        return default

    @staticmethod
    def _metric_value(
        metrics: Dict[str, Any],
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
            return float(
                value
            )

        return None

    @classmethod
    def _build_traffic_summary(
        cls,
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:

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

        total_bytes = (
            bytes_in + bytes_out
            if traffic_complete
            else None
        )

        if total_bytes is not None:

            traffic_observed = (
                total_bytes > 0
            )

        else:

            traffic_observed = None

        return {
            "bytes_in":
                bytes_in,

            "bytes_out":
                bytes_out,

            "total_bytes":
                total_bytes,

            "total_bytes_gib":
                (
                    total_bytes / (1024 ** 3)
                    if total_bytes is not None
                    else None
                ),

            "traffic_available":
                traffic_complete,

            "traffic_complete":
                traffic_complete,

            "traffic_partial":
                (
                    (bytes_in is not None)
                    !=
                    (bytes_out is not None)
                ),

            "traffic_observed":
                traffic_observed,

            "missing_is_zero":
                False,

            "semantics": {
                "purpose":
                    "operational_activity_observation",

                "billing_source":
                    False,

                "zero_means":
                    "observed_zero",

                "none_means":
                    "missing_or_unavailable",
            },
        }

    # ================================================================
    # TOPOLOGY
    # ================================================================

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
                    "Transit Gateway relationships "
                    "were not collected.",
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

        collection_status = (
            relationships.get(
                "collection_status",
                {},
            )
        )

        if not isinstance(
            collection_status,
            dict,
        ):
            collection_status = {}

        vpc_topologies: List[
            Dict[str, Any]
        ] = []

        for attachment in vpc_attachments:

            vpc_id = attachment.get(
                "vpc_id"
            )

            attachment_id = attachment.get(
                "attachment_id"
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
                    or
                    topology.get(
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

                            "reason":
                                (
                                    topology.get(
                                        "reason"
                                    )
                                    if isinstance(
                                        topology,
                                        dict,
                                    )
                                    else "VPC topology unavailable"
                                ),
                        }
                    )

                    continue

                resolver = (
                    NetworkRelationshipResolver(
                        topology
                    )
                )

                vpc_routes_to_tgw = (
                    resolver.routes_targeting(
                        "transit_gateway",
                        tgw_id,
                    )
                )

                if not isinstance(
                    vpc_routes_to_tgw,
                    list,
                ):
                    vpc_routes_to_tgw = []

                route_table_ids = sorted(
                    {
                        route.get(
                            "route_table_id"
                        )
                        for route in vpc_routes_to_tgw
                        if route.get(
                            "route_table_id"
                        )
                    }
                )

                subnet_ids = sorted(
                    {
                        route.get(
                            "subnet_id"
                        )
                        for route in vpc_routes_to_tgw
                        if route.get(
                            "subnet_id"
                        )
                    }
                )

                blackhole_routes = [
                    route
                    for route
                    in vpc_routes_to_tgw
                    if route.get(
                        "state"
                    ) == "blackhole"
                ]

                active_routes = [
                    route
                    for route
                    in vpc_routes_to_tgw
                    if route.get(
                        "state"
                    ) == "active"
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
                            len(
                                vpc_routes_to_tgw
                            ),

                        "active_vpc_routes_to_tgw_count":
                            len(
                                active_routes
                            ),

                        "blackhole_vpc_routes_to_tgw_count":
                            len(
                                blackhole_routes
                            ),

                        "vpc_route_table_ids":
                            route_table_ids,

                        "tgw_subnet_ids":
                            subnet_ids,

                        "vpc_route_count":
                            len(
                                vpc_routes_to_tgw
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

        valid_topologies = [
            item
            for item in vpc_topologies
            if item.get(
                "status"
            ) == "ok"
        ]

        attached_vpc_ids = sorted(
            {
                item.get(
                    "vpc_id"
                )
                for item in valid_topologies
                if item.get(
                    "vpc_id"
                )
            }
        )

        vpc_route_table_ids = sorted(
            {
                route_table_id
                for item in valid_topologies
                for route_table_id in item.get(
                    "vpc_route_table_ids",
                    [],
                )
            }
        )

        tgw_subnet_ids = sorted(
            {
                subnet_id
                for item in valid_topologies
                for subnet_id in item.get(
                    "tgw_subnet_ids",
                    [],
                )
            }
        )

        total_routes = sum(
            int(
                item.get(
                    "vpc_routes_to_tgw_count",
                    0,
                )
                or 0
            )
            for item in valid_topologies
        )

        total_active_routes = sum(
            int(
                item.get(
                    "active_vpc_routes_to_tgw_count",
                    0,
                )
                or 0
            )
            for item in valid_topologies
        )

        total_blackhole_routes = sum(
            int(
                item.get(
                    "blackhole_vpc_routes_to_tgw_count",
                    0,
                )
                or 0
            )
            for item in valid_topologies
        )

        topology_complete = (
            len(
                valid_topologies
            )
            == len(
                vpc_attachments
            )
        )

        return {
            "status":
                "ok",

            "transit_gateway_id":
                tgw_id,

            "vpcs":
                vpc_topologies,

            "attached_vpc_ids":
                attached_vpc_ids,

            "vpc_route_table_ids":
                vpc_route_table_ids,

            "tgw_subnet_ids":
                tgw_subnet_ids,

            "vpc_routes_to_tgw_count":
                total_routes,

            "active_vpc_routes_to_tgw_count":
                total_active_routes,

            "blackhole_vpc_routes_to_tgw_count":
                total_blackhole_routes,

            "summary": {
                "vpc_count":
                    len(
                        vpc_attachments
                    ),

                "attached_vpc_count":
                    len(
                        attached_vpc_ids
                    ),

                "vpc_route_table_count":
                    len(
                        vpc_route_table_ids
                    ),

                "tgw_subnet_count":
                    len(
                        tgw_subnet_ids
                    ),

                "vpc_routes_to_tgw_count":
                    total_routes,

                "active_vpc_routes_to_tgw_count":
                    total_active_routes,

                "blackhole_vpc_routes_to_tgw_count":
                    total_blackhole_routes,

                "topology_complete":
                    topology_complete,
            },

            "collection_status": {
                "attachment_collection":
                    collection_status.get(
                        "vpc_attachments"
                    ),

                "topology_complete":
                    topology_complete,
            },
        }

    # ================================================================
    # OPTIMIZATION EVIDENCE
    # ================================================================

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = (
            collected_resource.get(
                "identity",
                {},
            )
        )

        configuration = (
            collected_resource.get(
                "configuration",
                {},
            )
        )

        relationships = (
            collected_resource.get(
                "relationships",
                {},
            )
        )

        topology = (
            collected_resource.get(
                "topology",
                {},
            )
        )

        observations = (
            collected_resource.get(
                "observations",
                {},
            )
        )

        if not isinstance(
            identity,
            dict,
        ):
            identity = {}

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        if not isinstance(
            relationships,
            dict,
        ):
            relationships = {}

        if not isinstance(
            topology,
            dict,
        ):
            topology = {}

        if not isinstance(
            observations,
            dict,
        ):
            observations = {}

        cloudwatch = (
            observations.get(
                "cloudwatch",
                {},
            )
        )

        if not isinstance(
            cloudwatch,
            dict,
        ):
            cloudwatch = {}

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
                dict(
                    configuration
                ),

            "relationships": {
                "vpc_attachment_count":
                    len(
                        relationships.get(
                            "vpc_attachments",
                            [],
                        )
                    ),

                "other_attachment_count":
                    len(
                        relationships.get(
                            "other_attachments",
                            [],
                        )
                    ),

                "peering_attachment_count":
                    len(
                        relationships.get(
                            "peering_attachments",
                            [],
                        )
                    ),

                "route_table_access":
                    relationships.get(
                        "route_table_access",
                        {},
                    ),

                "route_table_count":
                    relationships.get(
                        "summary",
                        {},
                    ).get(
                        "route_table_count"
                    ),

                "route_count":
                    relationships.get(
                        "summary",
                        {},
                    ).get(
                        "route_count"
                    ),

                "blackhole_route_count":
                    relationships.get(
                        "summary",
                        {},
                    ).get(
                        "blackhole_route_count"
                    ),

                "association_count":
                    relationships.get(
                        "summary",
                        {},
                    ).get(
                        "association_count"
                    ),

                "propagation_count":
                    relationships.get(
                        "summary",
                        {},
                    ).get(
                        "propagation_count"
                    ),
            },

            "network": {
                "attached_vpc_count":
                    topology.get(
                        "summary",
                        {},
                    ).get(
                        "attached_vpc_count"
                    ),

                "vpc_routes_to_tgw_count":
                    topology.get(
                        "vpc_routes_to_tgw_count"
                    ),

                "active_vpc_routes_to_tgw_count":
                    topology.get(
                        "active_vpc_routes_to_tgw_count"
                    ),

                "blackhole_vpc_routes_to_tgw_count":
                    topology.get(
                        "blackhole_vpc_routes_to_tgw_count"
                    ),

                "vpc_route_table_count":
                    len(
                        topology.get(
                            "vpc_route_table_ids",
                            [],
                        )
                    ),

                "tgw_subnet_count":
                    len(
                        topology.get(
                            "tgw_subnet_ids",
                            [],
                        )
                    ),
            },

            "traffic":
                cloudwatch.get(
                    "traffic",
                    {},
                ),

            "data_quality": {
                "relationship_collection_complete":
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
                    topology.get(
                        "summary",
                        {},
                    ).get(
                        "topology_complete"
                    ),

                "cloudwatch_status":
                    cloudwatch.get(
                        "status"
                    ),

                "metric_counts":
                    cloudwatch.get(
                        "metric_counts",
                        {},
                    ),
            },
        }

    # ================================================================
    # HELPERS
    # ================================================================

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
            tag["Key"]:
                tag.get(
                    "Value"
                )
            for tag in tags
            if (
                isinstance(
                    tag,
                    dict,
                )
                and tag.get(
                    "Key"
                )
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
