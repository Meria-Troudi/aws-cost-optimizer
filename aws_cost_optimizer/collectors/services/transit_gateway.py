"""
AWS Transit Gateway Collector.

Collects:

- Transit Gateway identity
- Configuration
- VPC attachments
- Other attachments
- Peering attachments
- Transit Gateway route tables
- Transit Gateway routes
- Route table associations
- Route table propagations
- CloudWatch traffic observations
- VPC-side routing topology
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register
from collectors.metrics.cloudwatch import CloudWatchMetricCollector
from collectors.network.topology import NetworkTopologyCollector
from collectors.network.relationships import NetworkRelationshipResolver


@register
class TransitGatewayCollector(BaseCollector):

    key = "transit_gateway"
    resource_type = "transit_gateway"

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
        self.profile = profile or {}

        self.ec2 = get_client(
            "ec2",
            region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            region,
        )

        self.metric_collector = CloudWatchMetricCollector(
            self.cloudwatch
        )

    def discover(self) -> List[Dict[str, Any]]:

        resources: List[Dict[str, Any]] = []

        paginator = self.ec2.get_paginator(
            "describe_transit_gateways"
        )

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

                state = tgw.get(
                    "State"
                )

                if state not in {
                    "available",
                    "pending",
                }:
                    continue

                resources.append(
                    {
                        "id": tgw_id,
                        "raw": tgw,
                    }
                )

        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return resource["id"]

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        tgw = resource["raw"]

        tags = self._tags(
            tgw.get(
                "Tags",
                [],
            )
        )

        return {
            "name": (
                tags.get("Name")
                or tgw.get("Description")
                or resource["id"]
            ),
            "transit_gateway_id": resource["id"],
            "state": tgw.get("State"),
            "owner_id": tgw.get("OwnerId"),
            "tags": tags,
        }

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        tgw = resource["raw"]

        options = (
            tgw.get("Options")
            or {}
        )

        return {
            "transit_gateway_id": tgw.get(
                "TransitGatewayId"
            ),

            "state": tgw.get(
                "State"
            ),

            "owner_id": tgw.get(
                "OwnerId"
            ),

            "creation_time": self._iso(
                tgw.get("CreationTime")
            ),

            "amazon_side_asn": options.get(
                "AmazonSideAsn"
            ),

            "transit_gateway_cidr_blocks": (
                options.get(
                    "TransitGatewayCidrBlocks",
                    [],
                )
            ),

            "default_route_table_association": (
                options.get(
                    "DefaultRouteTableAssociation"
                )
            ),

            "default_route_table_propagation": (
                options.get(
                    "DefaultRouteTablePropagation"
                )
            ),

            "association_default_route_table_id": (
                options.get(
                    "AssociationDefaultRouteTableId"
                )
            ),

            "propagation_default_route_table_id": (
                options.get(
                    "PropagationDefaultRouteTableId"
                )
            ),

            "dns_support": options.get(
                "DnsSupport"
            ),

            "vpn_ecmp_support": options.get(
                "VpnEcmpSupport"
            ),

            "auto_accept_shared_attachments": (
                options.get(
                    "AutoAcceptSharedAttachments"
                )
            ),
        }

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        tgw_id = resource["id"]

        vpc_attachments = (
            self._collect_vpc_attachments(
                tgw_id
            )
        )

        other_attachments = (
            self._collect_other_attachments(
                tgw_id
            )
        )

        peering_attachments = (
            self._collect_peering_attachments(
                tgw_id
            )
        )

        route_tables = (
            self._collect_route_tables(
                tgw_id
            )
        )

        routes: List[Dict[str, Any]] = []

        for route_table in route_tables:

            route_table_id = route_table.get(
                "transit_gateway_route_table_id"
            )

            if not route_table_id:
                continue

            routes.extend(
                self._collect_routes(
                    route_table_id
                )
            )

        associations = (
            self._collect_associations(
                route_tables
            )
        )

        propagations = (
            self._collect_propagations(
                route_tables
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

        active_vpc_attachments = [
            attachment
            for attachment in vpc_attachments
            if attachment.get("state") == "available"
        ]

        active_other_attachments = [
            attachment
            for attachment in other_attachments
            if attachment.get("state") == "available"
        ]

        attached_vpcs = sorted(
            {
                attachment.get("vpc_id")
                for attachment in vpc_attachments
                if attachment.get("vpc_id")
            }
        )

        return {
            "status": "ok",

            "vpc_attachments": vpc_attachments,

            "other_attachments": other_attachments,

            "peering_attachments": peering_attachments,

            "route_tables": route_tables,

            "routes": routes,

            "associations": associations,

            "propagations": propagations,

            "summary": {
                "vpc_count": len(
                    attached_vpcs
                ),

                "vpc_attachment_count": len(
                    vpc_attachments
                ),

                "active_vpc_attachment_count": len(
                    active_vpc_attachments
                ),

                "other_attachment_count": len(
                    other_attachments
                ),

                "active_other_attachment_count": len(
                    active_other_attachments
                ),

                "peering_attachment_count": len(
                    peering_attachments
                ),

                "route_table_count": len(
                    route_tables
                ),

                "route_count": len(
                    routes
                ),

                "active_route_count": len(
                    active_routes
                ),

                "blackhole_route_count": len(
                    blackhole_routes
                ),

                "association_count": len(
                    associations
                ),

                "propagation_count": len(
                    propagations
                ),

                "has_attachments": bool(
                    vpc_attachments
                    or other_attachments
                    or peering_attachments
                ),

                "has_routes": bool(
                    routes
                ),

                "has_blackhole_routes": bool(
                    blackhole_routes
                ),
            },
        }

    def _collect_vpc_attachments(
        self,
        transit_gateway_id: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        paginator = self.ec2.get_paginator(
            "describe_transit_gateway_vpc_attachments"
        )

        for page in paginator.paginate(
            Filters=[
                {
                    "Name": "transit-gateway-id",
                    "Values": [transit_gateway_id],
                }
            ]
        ):

            for attachment in page.get(
                "TransitGatewayVpcAttachments",
                [],
            ):

                attachment_id = attachment.get(
                    "TransitGatewayAttachmentId"
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
                        "attachment_id": attachment_id,

                        "transit_gateway_id": attachment.get(
                            "TransitGatewayId"
                        ),

                        "vpc_id": attachment.get(
                            "VpcId"
                        ),

                        "vpc_owner_id": attachment.get(
                            "VpcOwnerId"
                        ),

                        "state": attachment.get(
                            "State"
                        ),

                        "creation_time": self._iso(
                            attachment.get(
                                "CreationTime"
                            )
                        ),

                        "route_table_id": association.get(
                            "TransitGatewayRouteTableId"
                        ),

                        "association_state": (
                            attachment.get(
                                "AssociationState"
                            )
                        ),

                        "dns_support": options.get(
                            "DnsSupport"
                        ),

                        "ipv6_support": options.get(
                            "Ipv6Support"
                        ),

                        "appliance_mode_support": options.get(
                            "ApplianceModeSupport"
                        ),

                        "subnet_ids": attachment.get(
                            "SubnetIds",
                            [],
                        ),

                        "tags": self._tags(
                            attachment.get(
                                "Tags",
                                [],
                            )
                        ),
                    }
                )

        return result

    def _collect_other_attachments(
        self,
        transit_gateway_id: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        paginator = self.ec2.get_paginator(
            "describe_transit_gateway_attachments"
        )

        for page in paginator.paginate(
            Filters=[
                {
                    "Name": "transit-gateway-id",
                    "Values": [transit_gateway_id],
                }
            ]
        ):

            for attachment in page.get(
                "TransitGatewayAttachments",
                [],
            ):

                attachment_id = attachment.get(
                    "TransitGatewayAttachmentId"
                )

                if not attachment_id:
                    continue

                resource_type = attachment.get(
                    "ResourceType"
                )

                if resource_type in {
                    "vpc",
                    "peering",
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
                        "attachment_id": attachment_id,

                        "resource_id": attachment.get(
                            "ResourceId"
                        ),

                        "resource_type": resource_type,

                        "resource_owner_id": attachment.get(
                            "ResourceOwnerId"
                        ),

                        "state": attachment.get(
                            "State"
                        ),

                        "creation_time": self._iso(
                            attachment.get(
                                "CreationTime"
                            )
                        ),

                        "route_table_id": association.get(
                            "TransitGatewayRouteTableId"
                        ),

                        "association_state": association.get(
                            "State"
                        ),

                        "tags": self._tags(
                            attachment.get(
                                "Tags",
                                [],
                            )
                        ),
                    }
                )

        return result

    def _collect_peering_attachments(
        self,
        transit_gateway_id: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        try:

            paginator = self.ec2.get_paginator(
                "describe_transit_gateway_peering_attachments"
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

                    requester_id = requester.get(
                        "TransitGatewayId"
                    )

                    accepter_id = accepter.get(
                        "TransitGatewayId"
                    )

                    if (
                        requester_id != transit_gateway_id
                        and accepter_id != transit_gateway_id
                    ):
                        continue

                    attachment_id = attachment.get(
                        "TransitGatewayAttachmentId"
                    )

                    if not attachment_id:
                        continue

                    result.append(
                        {
                            "attachment_id": attachment_id,

                            "state": attachment.get(
                                "State"
                            ),

                            "creation_time": self._iso(
                                attachment.get(
                                    "CreationTime"
                                )
                            ),

                            "requester_tgw_id": requester_id,

                            "accepter_tgw_id": accepter_id,

                            "requester_owner_id": (
                                requester.get(
                                    "OwnerId"
                                )
                            ),

                            "accepter_owner_id": (
                                accepter.get(
                                    "OwnerId"
                                )
                            ),

                            "tags": self._tags(
                                attachment.get(
                                    "Tags",
                                    [],
                                )
                            ),
                        }
                    )

        except Exception as exc:

            print(
                "Transit Gateway peering collection "
                f"warning: {exc}"
            )

        return result

    def _collect_route_tables(
        self,
        transit_gateway_id: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        paginator = self.ec2.get_paginator(
            "describe_transit_gateway_route_tables"
        )

        try:

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "transit-gateway-id",
                        "Values": [transit_gateway_id],
                    }
                ]
            ):

                for table in page.get(
                    "TransitGatewayRouteTables",
                    [],
                ):

                    route_table_id = table.get(
                        "TransitGatewayRouteTableId"
                    )

                    if not route_table_id:
                        continue

                    result.append(
                        self._normalize_route_table(
                            table
                        )
                    )

        except Exception as exc:

            print(
                "Transit Gateway route table discovery "
                f"warning: {exc}"
            )

        return result

    def _normalize_route_table(
        self,
        table: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "transit_gateway_route_table_id": (
                table.get(
                    "TransitGatewayRouteTableId"
                )
            ),

            "transit_gateway_id": (
                table.get(
                    "TransitGatewayId"
                )
            ),

            "state": table.get(
                "State"
            ),

            "default_association": (
                table.get(
                    "DefaultAssociationRouteTable"
                )
            ),

            "default_propagation": (
                table.get(
                    "DefaultPropagationRouteTable"
                )
            ),

            "creation_time": self._iso(
                table.get(
                    "CreationTime"
                )
            ),

            "tags": self._tags(
                table.get(
                    "Tags",
                    [],
                )
            ),
        }

    def _collect_routes(
        self,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        try:

            paginator = self.ec2.get_paginator(
                "search_transit_gateway_routes"
            )

            for page in paginator.paginate(
                TransitGatewayRouteTableId=route_table_id,
                Filters=[
                    {
                        "Name": "state",
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
                            []
                        )
                        or []
                    ):

                        attachments.append(
                            {
                                "attachment_id": (
                                    attachment.get(
                                        "TransitGatewayAttachmentId"
                                    )
                                ),

                                "resource_id": (
                                    attachment.get(
                                        "ResourceId"
                                    )
                                ),

                                "resource_type": (
                                    attachment.get(
                                        "ResourceType"
                                    )
                                ),
                            }
                        )

                    result.append(
                        {
                            "route_table_id": route_table_id,

                            "destination": route.get(
                                "DestinationCidrBlock"
                            ),

                            "state": route.get(
                                "State"
                            ),

                            "type": route.get(
                                "Type"
                            ),

                            "prefix_list_id": route.get(
                                "PrefixListId"
                            ),

                            "attachments": attachments,
                        }
                    )

        except Exception as exc:

            print(
                "Transit Gateway route collection "
                f"warning for {route_table_id}: {exc}"
            )

        return result

    def _collect_associations(
        self,
        route_tables: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        for table in route_tables:

            route_table_id = table.get(
                "transit_gateway_route_table_id"
            )

            if not route_table_id:
                continue

            try:

                paginator = self.ec2.get_paginator(
                    "get_transit_gateway_route_table_associations"
                )

                for page in paginator.paginate(
                    TransitGatewayRouteTableId=route_table_id
                ):

                    for association in page.get(
                        "Associations",
                        [],
                    ):

                        result.append(
                            {
                                "route_table_id": route_table_id,

                                "attachment_id": (
                                    association.get(
                                        "TransitGatewayAttachmentId"
                                    )
                                ),

                                "resource_id": (
                                    association.get(
                                        "ResourceId"
                                    )
                                ),

                                "resource_type": (
                                    association.get(
                                        "ResourceType"
                                    )
                                ),

                                "state": association.get(
                                    "State"
                                ),
                            }
                        )

            except Exception as exc:

                print(
                    "Transit Gateway association "
                    f"collection warning for "
                    f"{route_table_id}: {exc}"
                )

        return result
    def _collect_propagations(
        self,
        route_tables: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        for table in route_tables:

            route_table_id = table.get(
                "transit_gateway_route_table_id"
            )

            if not route_table_id:
                continue

            try:

                paginator = self.ec2.get_paginator(
                    "get_transit_gateway_route_table_propagations"
                )

                for page in paginator.paginate(
                    TransitGatewayRouteTableId=route_table_id
                ):

                    for propagation in page.get(
                        "TransitGatewayRouteTablePropagations",
                        [],
                    ):

                        result.append(
                            {
                                "route_table_id": route_table_id,

                                "attachment_id": (
                                    propagation.get(
                                        "TransitGatewayAttachmentId"
                                    )
                                ),

                                "resource_type": (
                                    propagation.get(
                                        "ResourceType"
                                    )
                                ),

                                "state": propagation.get(
                                    "State"
                                ),
                            }
                        )

            except Exception as exc:

                print(
                    "Transit Gateway propagation "
                    f"collection warning for "
                    f"{route_table_id}: {exc}"
                )

        return result

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        cloudwatch_config = (
            self.profile
            .get("observations", {})
            .get("cloudwatch", {})
        )

        namespace = cloudwatch_config.get(
            "namespace",
            "AWS/TransitGateway",
        )

        requested_period = int(
            cloudwatch_config.get(
                "period",
                3600,
            )
        )

        metric_specs = cloudwatch_config.get(
            "metrics"
        )

        if not metric_specs:

            metric_specs = [
                {
                    "name": "BytesIn",
                    "statistic": "Sum",
                    "unit": "Bytes",
                },
                {
                    "name": "BytesOut",
                    "statistic": "Sum",
                    "unit": "Bytes",
                },
                {
                    "name": "PacketsIn",
                    "statistic": "Sum",
                    "unit": "Count",
                },
                {
                    "name": "PacketsOut",
                    "statistic": "Sum",
                    "unit": "Count",
                },
                {
                    "name": "BytesDropCountBlackhole",
                    "statistic": "Sum",
                    "unit": "Bytes",
                },
                {
                    "name": "BytesDropCountNoRoute",
                    "statistic": "Sum",
                    "unit": "Bytes",
                },
                {
                    "name": "PacketDropCountBlackhole",
                    "statistic": "Sum",
                    "unit": "Count",
                },
                {
                    "name": "PacketDropCountNoRoute",
                    "statistic": "Sum",
                    "unit": "Count",
                },
            ]

        start, end = self.get_analysis_period()

        dimensions = [
            {
                "Name": "TransitGateway",
                "Value": resource["id"],
            }
        ]

        try:

            results = self.metric_collector.collect(
                namespace=namespace,
                dimensions=dimensions,
                metric_specs=metric_specs,
                start=start,
                end=end,
                requested_period=requested_period,
            )

        except Exception as exc:

            return {
                "cloudwatch": {
                    "namespace": namespace,
                    "requested_period": requested_period,
                    "effective_period": requested_period,
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "dimensions": dimensions,
                    "metrics": {},
                    "traffic": {},
                    "status": "error",
                    "error": str(exc),
                }
            }

        metrics: Dict[str, Any] = {}

        for item in results:

            metric_name = item.get(
                "metric_name"
            )

            if metric_name:
                metrics[metric_name] = item

        effective_period = (
            results[0].get(
                "effective_period",
                requested_period,
            )
            if results
            else requested_period
        )

        return {
            "cloudwatch": {
                "namespace": namespace,
                "requested_period": requested_period,
                "effective_period": effective_period,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "dimensions": dimensions,
                "metrics": metrics,
                "traffic": self._build_traffic_summary(
                    metrics
                ),
                "status": "ok",
            }
        }
    @staticmethod
    def _build_traffic_summary(
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:

        def value(
            name: str,
        ) -> Optional[float]:

            metric = metrics.get(name)

            if not metric:
                return None

            if not metric.get(
                "has_data",
                False,
            ):
                return None

            raw_value = metric.get(
                "value"
            )

            if isinstance(
                raw_value,
                (int, float),
            ):
                return float(raw_value)

            return None

        bytes_in = value("BytesIn")
        bytes_out = value("BytesOut")

        packets_in = value("PacketsIn")
        packets_out = value("PacketsOut")

        blackhole_bytes = value(
            "BytesDropCountBlackhole"
        )

        no_route_bytes = value(
            "BytesDropCountNoRoute"
        )

        blackhole_packets = value(
            "PacketDropCountBlackhole"
        )

        no_route_packets = value(
            "PacketDropCountNoRoute"
        )

        total_bytes = None

        if (
            bytes_in is not None
            or bytes_out is not None
        ):
            total_bytes = (
                (bytes_in or 0.0)
                + (bytes_out or 0.0)
            )

        total_packets = None

        if (
            packets_in is not None
            or packets_out is not None
        ):
            total_packets = (
                (packets_in or 0.0)
                + (packets_out or 0.0)
            )

        total_drop_bytes = None

        if (
            blackhole_bytes is not None
            or no_route_bytes is not None
        ):
            total_drop_bytes = (
                (blackhole_bytes or 0.0)
                + (no_route_bytes or 0.0)
            )

        total_drop_packets = None

        if (
            blackhole_packets is not None
            or no_route_packets is not None
        ):
            total_drop_packets = (
                (blackhole_packets or 0.0)
                + (no_route_packets or 0.0)
            )

        return {
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "total_bytes": total_bytes,

            "total_bytes_gib": (
                total_bytes / (1024 ** 3)
                if total_bytes is not None
                else None
            ),

            "packets_in": packets_in,
            "packets_out": packets_out,
            "total_packets": total_packets,

            "bytes_drop_blackhole": blackhole_bytes,
            "bytes_drop_no_route": no_route_bytes,
            "total_drop_bytes": total_drop_bytes,

            "packets_drop_blackhole": blackhole_packets,
            "packets_drop_no_route": no_route_packets,
            "total_drop_packets": total_drop_packets,

            "traffic_available": (
                total_bytes is not None
            ),

            "traffic_observed": (
                total_bytes > 0
                if total_bytes is not None
                else None
            ),

            "drop_metrics_available": (
                total_drop_bytes is not None
            ),

            "has_byte_drops": (
                total_drop_bytes > 0
                if total_drop_bytes is not None
                else None
            ),

            "semantics": {
                "purpose": "operational_observation",
                "billing_source": False,
                "none_means": "no_observation",
                "zero_means": "observed_zero",
            },
        }
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

        if not relationships:

            return {
                "status": "incomplete",
                "reason": (
                    "Transit Gateway relationships "
                    "not available"
                ),
            }

        tgw_id = resource["id"]

        vpc_attachments = relationships.get(
            "vpc_attachments",
            [],
        )

        other_attachments = relationships.get(
            "other_attachments",
            [],
        )

        peering_attachments = relationships.get(
            "peering_attachments",
            [],
        )

        route_tables = relationships.get(
            "route_tables",
            [],
        )

        routes = relationships.get(
            "routes",
            [],
        )

        associations = relationships.get(
            "associations",
            [],
        )

        propagations = relationships.get(
            "propagations",
            [],
        )

        topology_collector = NetworkTopologyCollector(
            region=self.region
        )

        vpc_topologies: List[Dict[str, Any]] = []

        for attachment in vpc_attachments:

            vpc_id = attachment.get(
                "vpc_id"
            )

            if not vpc_id:
                continue

            try:

                topology = topology_collector.collect(
                    vpc_id=vpc_id,
                    resource_type=self.resource_type,
                    resource_id=tgw_id,
                )

                if topology.get("status") != "ok":

                    vpc_topologies.append(
                        {
                            "vpc_id": vpc_id,
                            "attachment_id": attachment.get(
                                "attachment_id"
                            ),
                            "status": "incomplete",
                            "reason": topology.get(
                                "reason"
                            ),
                        }
                    )

                    continue

                resolver = NetworkRelationshipResolver(
                    topology
                )

                tgw_routes = (
                    resolver.routes_targeting(
                        target_type="transit_gateway",
                        target_id=tgw_id,
                    )
                )

                tgw_subnet_ids = sorted(
                    {
                        route.get("subnet_id")
                        for route in tgw_routes
                        if route.get("subnet_id")
                    }
                )

                tgw_route_table_ids = sorted(
                    {
                        route.get("route_table_id")
                        for route in tgw_routes
                        if route.get("route_table_id")
                    }
                )

                endpoint_ids = sorted(
                    {
                        endpoint.get(
                            "vpc_endpoint_id"
                        )
                        for subnet_id in tgw_subnet_ids
                        for endpoint in resolver.endpoints_for_subnet(
                            subnet_id
                        )
                        if endpoint.get(
                            "vpc_endpoint_id"
                        )
                    }
                )

                referenced = (
                    resolver.resources_referenced_by_routes()
                    if hasattr(
                        resolver,
                        "resources_referenced_by_routes",
                    )
                    else {}
                )

                vpc_topologies.append(
                    {
                        "vpc_id": vpc_id,

                        "attachment_id": attachment.get(
                            "attachment_id"
                        ),

                        "status": "ok",

                        "subnet_count": len(
                            topology.get(
                                "subnets",
                                [],
                            )
                        ),

                        "route_table_count": len(
                            topology.get(
                                "route_tables",
                                [],
                            )
                        ),

                        "vpc_route_count": sum(
                            len(
                                table.get(
                                    "routes",
                                    [],
                                )
                            )
                            for table in topology.get(
                                "route_tables",
                                [],
                            )
                        ),

                        "tgw_route_count": len(
                            tgw_routes
                        ),

                        "tgw_subnet_count": len(
                            tgw_subnet_ids
                        ),

                        "tgw_subnet_ids": (
                            tgw_subnet_ids
                        ),

                        "tgw_route_table_ids": (
                            tgw_route_table_ids
                        ),

                        "vpc_endpoint_count": len(
                            endpoint_ids
                        ),

                        "vpc_endpoint_ids": (
                            endpoint_ids
                        ),

                        "referenced_resources": {
                            key: values
                            for key, values
                            in referenced.items()
                            if values
                        },
                    }
                )

            except Exception as exc:

                vpc_topologies.append(
                    {
                        "vpc_id": vpc_id,
                        "attachment_id": attachment.get(
                            "attachment_id"
                        ),
                        "status": "error",
                        "error": str(exc),
                    }
                )

        valid_vpc_topologies = [
            item
            for item in vpc_topologies
            if item.get("status") == "ok"
        ]

        attached_vpc_ids = sorted(
            {
                item.get("vpc_id")
                for item in valid_vpc_topologies
                if item.get("vpc_id")
            }
        )

        tgw_subnet_ids = sorted(
            {
                subnet_id
                for item in valid_vpc_topologies
                for subnet_id in item.get(
                    "tgw_subnet_ids",
                    [],
                )
            }
        )

        vpc_route_table_ids = sorted(
            {
                route_table_id
                for item in valid_vpc_topologies
                for route_table_id in item.get(
                    "tgw_route_table_ids",
                    [],
                )
            }
        )

        total_tgw_vpc_routes = sum(
            item.get(
                "tgw_route_count",
                0,
            )
            for item in valid_vpc_topologies
        )

        total_vpc_endpoints = sum(
            item.get(
                "vpc_endpoint_count",
                0,
            )
            for item in valid_vpc_topologies
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

        related_resource_count = (
            len(vpc_attachments)
            + len(other_attachments)
            + len(peering_attachments)
        )

        return {
            "status": "ok",

            "transit_gateway_id": tgw_id,

            "vpcs": vpc_topologies,

            "other_attachments": other_attachments,

            "peering_attachments": peering_attachments,

            "route_table_ids": [
                table.get(
                    "transit_gateway_route_table_id"
                )
                for table in route_tables
                if table.get(
                    "transit_gateway_route_table_id"
                )
            ],

            "route_count": len(routes),

            "active_route_count": len(
                active_routes
            ),

            "blackhole_route_count": len(
                blackhole_routes
            ),

            "association_count": len(
                associations
            ),

            "propagation_count": len(
                propagations
            ),

            "attached_vpc_ids": attached_vpc_ids,

            "vpc_route_table_ids": (
                vpc_route_table_ids
            ),

            "tgw_subnet_ids": tgw_subnet_ids,

            "tgw_subnet_count": len(
                tgw_subnet_ids
            ),

            "tgw_vpc_route_count": (
                total_tgw_vpc_routes
            ),

            "vpc_endpoint_count": (
                total_vpc_endpoints
            ),

            "summary": {
                "vpc_count": len(
                    vpc_attachments
                ),

                "other_attachment_count": len(
                    other_attachments
                ),

                "peering_attachment_count": len(
                    peering_attachments
                ),

                "route_table_count": len(
                    route_tables
                ),

                "route_count": len(
                    routes
                ),

                "active_route_count": len(
                    active_routes
                ),

                "blackhole_route_count": len(
                    blackhole_routes
                ),

                "association_count": len(
                    associations
                ),

                "propagation_count": len(
                    propagations
                ),

                "vpc_route_table_count": len(
                    vpc_route_table_ids
                ),

                "tgw_vpc_route_count": (
                    total_tgw_vpc_routes
                ),

                "tgw_subnet_count": len(
                    tgw_subnet_ids
                ),

                "vpc_endpoint_count": (
                    total_vpc_endpoints
                ),

                "related_resource_count": (
                    related_resource_count
                ),

                "has_attachments": (
                    related_resource_count > 0
                ),

                "has_vpc_routing": (
                    total_tgw_vpc_routes > 0
                ),

                "has_routes": bool(
                    routes
                ),

                "has_blackhole_routes": bool(
                    blackhole_routes
                ),
            },
        }
    @staticmethod
    def _tags(
        tags: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        return {
            tag["Key"]: tag.get("Value")
            for tag in tags
            if tag.get("Key")
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