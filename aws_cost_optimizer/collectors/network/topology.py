"""
Generic AWS VPC network topology collector.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client


class NetworkTopologyCollector:

    def __init__(
        self,
        region: str,
    ):

        self.region = region

        self.ec2 = get_client(
            "ec2",
            region,
        )

        self._vpc_cache = {}
    def collect(
        self,
        vpc_id: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        resource = {
            "resource_type":
                resource_type,

            "resource_id":
                resource_id,
        }

        if vpc_id in self._vpc_cache:

            result = dict(
                self._vpc_cache[vpc_id]
            )

            result["resource"] = resource

            return result

        vpc = self._collect_vpc(
            vpc_id
        )

        if not vpc:

            return {
                "status": "incomplete",
                "resource": resource,
                "region": self.region,
                "vpc_id": vpc_id,
                "reason":
                    "VPC not found or inaccessible",
            }

        subnets = self._collect_subnets(
            vpc_id
        )

        route_tables = (
            self._collect_route_tables(
                vpc_id
            )
        )

        effective_routes = (
            self._resolve_effective_routes(
                route_tables,
                subnets,
            )
        )

        vpc_endpoints = (
            self._collect_vpc_endpoints(
                vpc_id
            )
        )

        route_targets = (
            self._collect_route_targets(
                route_tables
            )
        )

        result = {
            "status": "ok",
            "resource": resource,
            "region": self.region,
            "vpc_id": vpc_id,

            "vpc": vpc,

            "subnets":
                subnets,

            "route_tables":
                route_tables,

            "effective_routes":
                effective_routes,

            "route_targets":
                route_targets,

            "vpc_endpoints":
                vpc_endpoints,

            "summary": {
                "subnet_count":
                    len(subnets),

                "route_table_count":
                    len(route_tables),

                "route_count":
                    sum(
                        len(
                            table.get(
                                "routes",
                                [],
                            )
                        )
                        for table in route_tables
                    ),

                "effective_route_count":
                    len(effective_routes),

                "vpc_endpoint_count":
                    len(vpc_endpoints),
            },
        }

        self._vpc_cache[vpc_id] = result

        return result
    def _collect_vpc(
        self,
        vpc_id: str,
    ) -> Optional[Dict[str, Any]]:

        try:

            response = self.ec2.describe_vpcs(
                VpcIds=[vpc_id]
            )

        except Exception:
            return None

        vpcs = response.get(
            "Vpcs",
            [],
        )

        if not vpcs:
            return None

        vpc = vpcs[0]

        return {
            "vpc_id":
                vpc.get("VpcId"),

            "cidr_block":
                vpc.get("CidrBlock"),

            "cidr_block_associations": [
                association.get(
                    "CidrBlock"
                )
                for association in vpc.get(
                    "CidrBlockAssociationSet",
                    [],
                )
                if association.get(
                    "CidrBlock"
                )
            ],

            "ipv6_cidr_blocks": [
                association.get(
                    "Ipv6CidrBlock"
                )
                for association in vpc.get(
                    "Ipv6CidrBlockAssociationSet",
                    [],
                )
                if association.get(
                    "Ipv6CidrBlock"
                )
            ],

            "state":
                vpc.get("State"),

            "is_default":
                vpc.get("IsDefault"),

            "instance_tenancy":
                vpc.get("InstanceTenancy"),

            "tags":
                self._tags(
                    vpc.get(
                        "Tags",
                        [],
                    )
                ),
        }
    def _collect_subnets(
        self,
        vpc_id: str,
    ) -> List[Dict[str, Any]]:

        result = []

        paginator = self.ec2.get_paginator(
            "describe_subnets"
        )

        for page in paginator.paginate(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc_id],
                }
            ]
        ):

            for subnet in page.get(
                "Subnets",
                [],
            ):

                subnet_id = subnet.get(
                    "SubnetId"
                )

                if not subnet_id:
                    continue

                result.append(
                    {
                        "subnet_id":
                            subnet_id,

                        "vpc_id":
                            subnet.get("VpcId"),

                        "cidr_block":
                            subnet.get(
                                "CidrBlock"
                            ),

                        "availability_zone":
                            subnet.get(
                                "AvailabilityZone"
                            ),

                        "availability_zone_id":
                            subnet.get(
                                "AvailabilityZoneId"
                            ),

                        "state":
                            subnet.get("State"),

                        "available_ip_address_count":
                            subnet.get(
                                "AvailableIpAddressCount"
                            ),

                        "map_public_ip_on_launch":
                            subnet.get(
                                "MapPublicIpOnLaunch"
                            ),

                        "default_for_az":
                            subnet.get(
                                "DefaultForAz"
                            ),

                        "assign_ipv6_address_on_creation":
                            subnet.get(
                                "AssignIpv6AddressOnCreation"
                            ),

                        "tags":
                            self._tags(
                                subnet.get(
                                    "Tags",
                                    [],
                                )
                            ),
                    }
                )

        return result

    def _collect_route_tables(
        self,
        vpc_id: str,
    ) -> List[Dict[str, Any]]:

        result = []

        paginator = self.ec2.get_paginator(
            "describe_route_tables"
        )

        for page in paginator.paginate(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc_id],
                }
            ]
        ):

            for table in page.get(
                "RouteTables",
                [],
            ):

                route_table_id = table.get(
                    "RouteTableId"
                )

                if not route_table_id:
                    continue

                result.append(
                    {
                        "route_table_id":
                            route_table_id,

                        "vpc_id":
                            table.get("VpcId"),

                        "routes": [
                            self._normalize_route(
                                route
                            )
                            for route in table.get(
                                "Routes",
                                [],
                            )
                        ],

                        "associations": [
                            self._normalize_association(
                                association
                            )
                            for association in table.get(
                                "Associations",
                                [],
                            )
                        ],
                    }
                )

        return result
    def _resolve_effective_routes(
        self,
        route_tables: List[Dict[str, Any]],
        subnets: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        explicit = {}

        main_route_table_id = None

        for table in route_tables:

            table_id = table.get(
                "route_table_id"
            )

            if not table_id:
                continue

            for association in table.get(
                "associations",
                [],
            ):

                subnet_id = association.get(
                    "subnet_id"
                )

                if subnet_id:
                    explicit[
                        subnet_id
                    ] = table_id

                if association.get(
                    "main"
                ):
                    main_route_table_id = (
                        table_id
                    )

        result = []

        for subnet in subnets:

            subnet_id = subnet.get(
                "subnet_id"
            )

            if not subnet_id:
                continue

            route_table_id = (
                explicit.get(
                    subnet_id
                )
            )

            source = "explicit"

            if not route_table_id:

                route_table_id = (
                    main_route_table_id
                )

                source = "main"

            result.append(
                {
                    "subnet_id":
                        subnet_id,

                    "route_table_id":
                        route_table_id,

                    "source":
                        source,
                }
            )

        return result
    def _collect_vpc_endpoints(
        self,
        vpc_id: str,
    ) -> List[Dict[str, Any]]:

        result = []

        paginator = self.ec2.get_paginator(
            "describe_vpc_endpoints"
        )

        for page in paginator.paginate(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc_id],
                }
            ]
        ):

            for endpoint in page.get(
                "VpcEndpoints",
                [],
            ):

                endpoint_id = endpoint.get(
                    "VpcEndpointId"
                )

                if not endpoint_id:
                    continue

                endpoint_type = endpoint.get(
                    "VpcEndpointType"
                )

                result.append(
                    {
                        "vpc_endpoint_id":
                            endpoint_id,

                        "service_name":
                            endpoint.get(
                                "ServiceName"
                            ),

                        "service_region":
                            endpoint.get(
                                "ServiceRegion"
                            ),

                        "endpoint_type":
                            endpoint_type,

                        "category":
                            self._endpoint_category(
                                endpoint_type
                            ),

                        "state":
                            endpoint.get("State"),

                        "route_table_ids":
                            endpoint.get(
                                "RouteTableIds",
                                [],
                            ),

                        "subnet_ids":
                            endpoint.get(
                                "SubnetIds",
                                [],
                            ),

                        "network_interface_ids":
                            endpoint.get(
                                "NetworkInterfaceIds",
                                [],
                            ),

                        "private_dns_enabled":
                            endpoint.get(
                                "PrivateDnsEnabled"
                            ),

                        "ip_address_type":
                            endpoint.get(
                                "IpAddressType"
                            ),

                        "owner_id":
                            endpoint.get(
                                "OwnerId"
                            ),

                        "policy_document":
                            endpoint.get(
                                "PolicyDocument"
                            ),

                        "tags":
                            self._tags(
                                endpoint.get(
                                    "Tags",
                                    [],
                                )
                            ),
                    }
                )

        return result
    def _collect_route_targets(
        self,
        route_tables: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:

        targets = {
            "internet_gateways": set(),
            "nat_gateways": set(),
            "transit_gateways": set(),
            "vpc_peering_connections": set(),
            "network_interfaces": set(),
            "instances": set(),
            "carrier_gateways": set(),
            "local_gateways": set(),
            "egress_only_internet_gateways": set(),
            "core_networks": set(),
        }

        for table in route_tables:

            for route in table.get(
                "routes",
                [],
            ):

                mapping = {
                    "gateway_id":
                        "internet_gateways",

                    "nat_gateway_id":
                        "nat_gateways",

                    "transit_gateway_id":
                        "transit_gateways",

                    "vpc_peering_connection_id":
                        "vpc_peering_connections",

                    "network_interface_id":
                        "network_interfaces",

                    "instance_id":
                        "instances",

                    "carrier_gateway_id":
                        "carrier_gateways",

                    "local_gateway_id":
                        "local_gateways",

                    "egress_only_internet_gateway_id":
                        "egress_only_internet_gateways",

                    "core_network_arn":
                        "core_networks",
                }

                for field, category in mapping.items():

                    value = route.get(field)

                    if not value:
                        continue

                    if (
                        field == "gateway_id"
                        and not value.startswith(
                            "igw-"
                        )
                    ):
                        continue

                    targets[
                        category
                    ].add(value)

        return {
            key: sorted(values)
            for key, values in targets.items()
        }
    @staticmethod
    def _normalize_route(
        route: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "destination_cidr_block":
                route.get(
                    "DestinationCidrBlock"
                ),

            "destination_ipv6_cidr_block":
                route.get(
                    "DestinationIpv6CidrBlock"
                ),

            "destination_prefix_list_id":
                route.get(
                    "DestinationPrefixListId"
                ),

            "gateway_id":
                route.get(
                    "GatewayId"
                ),

            "nat_gateway_id":
                route.get(
                    "NatGatewayId"
                ),

            "transit_gateway_id":
                route.get(
                    "TransitGatewayId"
                ),

            "network_interface_id":
                route.get(
                    "NetworkInterfaceId"
                ),

            "vpc_peering_connection_id":
                route.get(
                    "VpcPeeringConnectionId"
                ),

            "instance_id":
                route.get(
                    "InstanceId"
                ),

            "carrier_gateway_id":
                route.get(
                    "CarrierGatewayId"
                ),

            "local_gateway_id":
                route.get(
                    "LocalGatewayId"
                ),

            "egress_only_internet_gateway_id":
                route.get(
                    "EgressOnlyInternetGatewayId"
                ),

            "core_network_arn":
                route.get(
                    "CoreNetworkArn"
                ),

            "state":
                route.get("State"),

            "origin":
                route.get("Origin"),
        }

    @staticmethod
    def _normalize_association(
        association: Dict[str, Any],
    ) -> Dict[str, Any]:

        state = (
            association.get(
                "AssociationState"
            )
            or {}
        )

        return {
            "association_id":
                association.get(
                    "RouteTableAssociationId"
                ),

            "subnet_id":
                association.get(
                    "SubnetId"
                ),

            "main":
                bool(
                    association.get(
                        "Main",
                        False,
                    )
                ),

            "state":
                state.get("State"),
        }

    @staticmethod
    def _endpoint_category(
        endpoint_type: Optional[str],
    ) -> str:

        return {
            "Gateway":
                "gateway",

            "Interface":
                "interface",

            "GatewayLoadBalancer":
                "gateway_load_balancer",
        }.get(
            endpoint_type,
            "unknown",
        )

    @staticmethod
    def _tags(
        tags: List[Dict[str, str]],
    ) -> Dict[str, str]:

        return {
            tag["Key"]:
                tag.get("Value")
            for tag in tags
            if tag.get("Key")
        }