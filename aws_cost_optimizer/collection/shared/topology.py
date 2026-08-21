"""
Generic AWS VPC network topology collector.

Collects a reusable VPC graph:

VPC
 -> subnets
 -> effective route tables
 -> routes
 -> route targets
 -> VPC endpoints
 -> subnet network profiles
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client


_ROUTE_TARGET_FIELDS = (
    "gateway_id",
    "nat_gateway_id",
    "transit_gateway_id",
    "network_interface_id",
    "vpc_peering_connection_id",
    "instance_id",
    "carrier_gateway_id",
    "local_gateway_id",
    "egress_only_internet_gateway_id",
    "core_network_arn",
)


class NetworkTopologyCollector:

    def __init__(
        self,
        region: str,
    ) -> None:

        self.region = region

        self.ec2 = get_client(
            "ec2",
            region,
        )

        self._vpc_cache: dict[
            str,
            Dict[str, Any],
        ] = {}

        self._subnet_az_cache: dict[
            str,
            Optional[str],
        ] = {}
    def collect(
        self,
        vpc_id: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        resource = {
            "resource_type": resource_type,
            "resource_id": resource_id,
        }

        if not vpc_id:
            return {
                "status": "incomplete",
                "resource": resource,
                "region": self.region,
                "vpc_id": None,
                "reason": "VPC ID not provided",
            }

        if vpc_id in self._vpc_cache:

            cached = self._vpc_cache[vpc_id]

            result = dict(cached)
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

        subnet_profiles = (
            self._build_subnet_profiles(
                subnets=subnets,
                route_tables=route_tables,
                effective_routes=effective_routes,
                vpc_endpoints=vpc_endpoints,
            )
        )

        all_routes = [
            route
            for table in route_tables
            for route in table.get(
                "routes",
                [],
            )
            if isinstance(route, dict)
        ]

        result: Dict[str, Any] = {
            "status": "ok",
            "resource": resource,
            "region": self.region,
            "vpc_id": vpc_id,

            "vpc": vpc,

            "subnets":
                subnets,

            "route_tables":
                route_tables,

            "routes":
                all_routes,

            "effective_routes":
                effective_routes,

            "subnet_profiles":
                subnet_profiles,

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
                    len(all_routes),

                "effective_route_count":
                    len(effective_routes),

                "vpc_endpoint_count":
                    len(vpc_endpoints),

                "internet_gateway_count":
                    len(
                        route_targets.get(
                            "internet_gateways",
                            [],
                        )
                    ),

                "nat_gateway_count":
                    len(
                        route_targets.get(
                            "nat_gateways",
                            [],
                        )
                    ),

                "transit_gateway_count":
                    len(
                        route_targets.get(
                            "transit_gateways",
                            [],
                        )
                    ),

                "vpc_peering_connection_count":
                    len(
                        route_targets.get(
                            "vpc_peering_connections",
                            [],
                        )
                    ),

                "network_interface_target_count":
                    len(
                        route_targets.get(
                            "network_interfaces",
                            [],
                        )
                    ),
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

        result: list[Dict[str, Any]] = []

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

                        "ipv6_cidr_block_association_count":
                            len(
                                subnet.get(
                                    "Ipv6CidrBlockAssociationSet",
                                    [],
                                )
                                or []
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

        result: list[Dict[str, Any]] = []

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

                routes = [
                    self._normalize_route(
                        route
                    )
                    for route in table.get(
                        "Routes",
                        [],
                    )
                ]

                associations = [
                    self._normalize_association(
                        association
                    )
                    for association in table.get(
                        "Associations",
                        [],
                    )
                ]

                result.append(
                    {
                        "route_table_id":
                            route_table_id,

                        "vpc_id":
                            table.get("VpcId"),

                        "routes":
                            routes,

                        "associations":
                            associations,

                        "is_main":
                            any(
                                association.get("main")
                                for association
                                in associations
                            ),
                    }
                )

        return result
    def _resolve_effective_routes(
        self,
        route_tables: List[Dict[str, Any]],
        subnets: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        explicit: dict[str, str] = {}

        main_route_table_id: Optional[str] = None

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

        result: list[Dict[str, Any]] = []

        for subnet in subnets:

            subnet_id = subnet.get(
                "subnet_id"
            )

            if not subnet_id:
                continue

            route_table_id = explicit.get(
                subnet_id
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
    def _build_subnet_profiles(
        self,
        *,
        subnets: List[Dict[str, Any]],
        route_tables: List[Dict[str, Any]],
        effective_routes: List[Dict[str, Any]],
        vpc_endpoints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        route_table_index = {
            table.get("route_table_id"):
                table
            for table in route_tables
            if table.get("route_table_id")
        }

        endpoint_route_table_index: dict[
            str,
            list[Dict[str, Any]],
        ] = {}

        endpoint_subnet_index: dict[
            str,
            list[Dict[str, Any]],
        ] = {}

        for endpoint in vpc_endpoints:

            for route_table_id in (
                endpoint.get(
                    "route_table_ids",
                    [],
                )
                or []
            ):

                endpoint_route_table_index.setdefault(
                    route_table_id,
                    [],
                ).append(
                    endpoint
                )

            for subnet_id in (
                endpoint.get(
                    "subnet_ids",
                    [],
                )
                or []
            ):

                endpoint_subnet_index.setdefault(
                    subnet_id,
                    [],
                ).append(
                    endpoint
                )

        effective_index = {
            mapping.get("subnet_id"):
                mapping
            for mapping in effective_routes
            if mapping.get("subnet_id")
        }

        result: list[Dict[str, Any]] = []

        for subnet in subnets:

            subnet_id = subnet.get(
                "subnet_id"
            )

            if not subnet_id:
                continue

            mapping = effective_index.get(
                subnet_id
            )

            route_table_id = (
                mapping.get("route_table_id")
                if mapping
                else None
            )

            route_table = (
                route_table_index.get(
                    route_table_id
                )
                if route_table_id
                else None
            )

            routes = (
                route_table.get(
                    "routes",
                    [],
                )
                if route_table
                else []
            )

            nat_gateway_ids: set[str] = set()
            transit_gateway_ids: set[str] = set()
            internet_gateway_ids: set[str] = set()
            peering_ids: set[str] = set()
            network_interface_ids: set[str] = set()
            instance_ids: set[str] = set()
            carrier_gateway_ids: set[str] = set()
            local_gateway_ids: set[str] = set()
            egress_only_gateway_ids: set[str] = set()
            core_network_arns: set[str] = set()

            has_default_nat_route = False
            has_default_igw_route = False
            has_default_tgw_route = False

            route_count = 0
            blackhole_route_count = 0

            for route in routes:

                if not isinstance(
                    route,
                    dict,
                ):
                    continue

                route_count += 1

                if route.get(
                    "state"
                ) == "blackhole":
                    blackhole_route_count += 1

                is_default = bool(
                    route.get(
                        "is_default_route"
                    )
                )

                if is_default:

                    if route.get(
                        "nat_gateway_id"
                    ):
                        has_default_nat_route = True

                    if (
                        route.get("gateway_id")
                        and str(
                            route.get("gateway_id")
                        ).startswith("igw-")
                    ):
                        has_default_igw_route = True

                    if route.get(
                        "transit_gateway_id"
                    ):
                        has_default_tgw_route = True

                for field, target in (
                    (
                        "nat_gateway_id",
                        nat_gateway_ids,
                    ),
                    (
                        "transit_gateway_id",
                        transit_gateway_ids,
                    ),
                    (
                        "network_interface_id",
                        network_interface_ids,
                    ),
                    (
                        "instance_id",
                        instance_ids,
                    ),
                    (
                        "vpc_peering_connection_id",
                        peering_ids,
                    ),
                    (
                        "carrier_gateway_id",
                        carrier_gateway_ids,
                    ),
                    (
                        "local_gateway_id",
                        local_gateway_ids,
                    ),
                    (
                        "egress_only_internet_gateway_id",
                        egress_only_gateway_ids,
                    ),
                    (
                        "core_network_arn",
                        core_network_arns,
                    ),
                ):
                    value = route.get(field)

                    if value:
                        target.add(
                            str(value)
                        )

                gateway_id = route.get(
                    "gateway_id"
                )

                if (
                    gateway_id
                    and str(
                        gateway_id
                    ).startswith("igw-")
                ):
                    internet_gateway_ids.add(
                        str(gateway_id)
                    )

            gateway_endpoints = (
                endpoint_subnet_index.get(
                    subnet_id,
                    [],
                )
                +
                endpoint_route_table_index.get(
                    route_table_id,
                    [],
                )
            )

            endpoint_ids = sorted(
                {
                    endpoint.get(
                        "vpc_endpoint_id"
                    )
                    for endpoint
                    in gateway_endpoints
                    if endpoint.get(
                        "vpc_endpoint_id"
                    )
                }
            )

            endpoint_services = sorted(
                {
                    str(
                        endpoint.get(
                            "service_name"
                        )
                    )
                    for endpoint
                    in gateway_endpoints
                    if endpoint.get(
                        "service_name"
                    )
                }
            )

            result.append(
                {
                    "subnet_id":
                        subnet_id,

                    "availability_zone":
                        subnet.get(
                            "availability_zone"
                        ),

                    "route_table_id":
                        route_table_id,

                    "route_table_source":
                        (
                            mapping.get("source")
                            if mapping
                            else None
                        ),

                    "route_count":
                        route_count,

                    "blackhole_route_count":
                        blackhole_route_count,

                    "has_default_nat_route":
                        has_default_nat_route,

                    "has_default_internet_gateway_route":
                        has_default_igw_route,

                    "has_default_transit_gateway_route":
                        has_default_tgw_route,

                    "nat_gateway_ids":
                        sorted(
                            nat_gateway_ids
                        ),

                    "transit_gateway_ids":
                        sorted(
                            transit_gateway_ids
                        ),

                    "internet_gateway_ids":
                        sorted(
                            internet_gateway_ids
                        ),

                    "vpc_peering_connection_ids":
                        sorted(
                            peering_ids
                        ),

                    "network_interface_ids":
                        sorted(
                            network_interface_ids
                        ),

                    "instance_ids":
                        sorted(
                            instance_ids
                        ),

                    "carrier_gateway_ids":
                        sorted(
                            carrier_gateway_ids
                        ),

                    "local_gateway_ids":
                        sorted(
                            local_gateway_ids
                        ),

                    "egress_only_internet_gateway_ids":
                        sorted(
                            egress_only_gateway_ids
                        ),

                    "core_network_arns":
                        sorted(
                            core_network_arns
                        ),

                    "vpc_endpoint_ids":
                        endpoint_ids,

                    "vpc_endpoint_services":
                        endpoint_services,
                }
            )

        return result
    def _collect_vpc_endpoints(
        self,
        vpc_id: str,
    ) -> List[Dict[str, Any]]:

        result: list[Dict[str, Any]] = []

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

                        "vpc_id":
                            endpoint.get(
                                "VpcId"
                            ),

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
                            endpoint.get(
                                "State"
                            ),

                        "route_table_ids":
                            list(
                                endpoint.get(
                                    "RouteTableIds",
                                    [],
                                )
                                or []
                            ),

                        "subnet_ids":
                            list(
                                endpoint.get(
                                    "SubnetIds",
                                    [],
                                )
                                or []
                            ),

                        "network_interface_ids":
                            list(
                                endpoint.get(
                                    "NetworkInterfaceIds",
                                    [],
                                )
                                or []
                            ),

                        "security_group_ids": [
                            group.get("GroupId")
                            for group
                            in endpoint.get(
                                "Groups",
                                [],
                            )
                            if group.get(
                                "GroupId"
                            )
                        ],

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

                        "requester_managed":
                            endpoint.get(
                                "RequesterManaged"
                            ),

                        "policy_document":
                            endpoint.get(
                                "PolicyDocument"
                            ),

                        "dns_options":
                            endpoint.get(
                                "DnsOptions"
                            ),

                        "dns_entries":
                            endpoint.get(
                                "DnsEntries",
                                [],
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

        targets: dict[
            str,
            set[str],
        ] = {
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

        field_mapping = {
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

        for table in route_tables:

            for route in table.get(
                "routes",
                [],
            ):

                for field, category in (
                    field_mapping.items()
                ):

                    value = route.get(
                        field
                    )

                    if not value:
                        continue

                    if field == "gateway_id":
                        if not str(
                            value
                        ).startswith(
                            "igw-"
                        ):
                            continue

                    targets[
                        category
                    ].add(
                        str(value)
                    )

        return {
            key: sorted(values)
            for key, values in targets.items()
        }
    @staticmethod
    def _normalize_route(
        route: Dict[str, Any],
    ) -> Dict[str, Any]:

        destination_cidr = route.get(
            "DestinationCidrBlock"
        )

        destination_ipv6 = route.get(
            "DestinationIpv6CidrBlock"
        )

        prefix_list_id = route.get(
            "DestinationPrefixListId"
        )

        gateway_id = route.get(
            "GatewayId"
        )

        nat_gateway_id = route.get(
            "NatGatewayId"
        )

        transit_gateway_id = route.get(
            "TransitGatewayId"
        )

        route_class = "local"

        if nat_gateway_id:
            route_class = "nat_gateway"

        elif transit_gateway_id:
            route_class = "transit_gateway"

        elif (
            gateway_id
            and str(
                gateway_id
            ).startswith("igw-")
        ):
            route_class = "internet_gateway"

        elif gateway_id:
            # GatewayId is also used for gateway endpoint routes.
            route_class = "gateway_endpoint"

        elif route.get(
            "VpcPeeringConnectionId"
        ):
            route_class = "vpc_peering"

        elif route.get(
            "NetworkInterfaceId"
        ):
            route_class = "network_interface"

        elif route.get(
            "InstanceId"
        ):
            route_class = "instance"

        elif route.get(
            "CarrierGatewayId"
        ):
            route_class = "carrier_gateway"

        elif route.get(
            "LocalGatewayId"
        ):
            route_class = "local_gateway"

        elif route.get(
            "EgressOnlyInternetGatewayId"
        ):
            route_class = "egress_only_gateway"

        elif route.get(
            "CoreNetworkArn"
        ):
            route_class = "core_network"

        elif destination_cidr:
            route_class = "cidr"

        elif destination_ipv6:
            route_class = "ipv6"

        elif prefix_list_id:
            route_class = "prefix_list"

        destination = (
            destination_cidr
            or destination_ipv6
            or prefix_list_id
        )

        is_default_route = (
            destination_cidr == "0.0.0.0/0"
            or destination_ipv6 == "::/0"
        )

        return {
            "destination_cidr_block":
                destination_cidr,

            "destination_ipv6_cidr_block":
                destination_ipv6,

            "destination_prefix_list_id":
                prefix_list_id,

            "destination":
                destination,

            "gateway_id":
                gateway_id,

            "nat_gateway_id":
                nat_gateway_id,

            "transit_gateway_id":
                transit_gateway_id,

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
                route.get(
                    "State"
                ),

            "origin":
                route.get(
                    "Origin"
                ),

            "route_class":
                route_class,

            "is_default_route":
                is_default_route,
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
                state.get(
                    "State"
                ),
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

            "Resource":
                "resource",

            "ServiceNetwork":
                "service_network",
        }.get(
            endpoint_type,
            "unknown",
        )

    @staticmethod
    def _tags(
        tags: List[Dict[str, str]],
    ) -> Dict[str, str]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        return {
            tag["Key"]:
                tag.get("Value")
            for tag in tags
            if isinstance(tag, dict)
            and tag.get("Key")
        }