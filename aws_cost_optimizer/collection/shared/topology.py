"""
Generic AWS VPC network topology collector.

Purpose
-------
Collect reusable network evidence required by downstream analyzers.

VPC
 ├── subnets
 ├── route tables
 │    ├── associations
 │    └── routes
 ├── effective subnet -> route table mapping
 ├── effective subnet -> routes
 ├── route targets
 ├── VPC endpoints
 └── subnet network profiles

Important semantics
-------------------
- Explicit subnet association wins.
- A subnet without an explicit association uses the VPC main route table.
- Missing topology evidence is not represented as an empty successful
  result when the underlying AWS call failed.
- Routes are preserved independently from effective subnet mappings.
- Gateway endpoint routes target the VPC endpoint ID.
- The collector never decides whether a target is unnecessary.
  It only provides topology evidence.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client


class NetworkTopologyCollector:

    def __init__(
        self,
        region: str,
    ) -> None:
        if not region or not str(region).strip():
            raise ValueError("Region is required")

        self.region = str(region).strip()

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self._vpc_cache: Dict[
            str,
            Dict[str, Any],
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

        vpc_id = self._normalize_id(vpc_id)

        if not vpc_id:
            return {
                "status": "incomplete",
                "resource": resource,
                "region": self.region,
                "vpc_id": None,
                "reason": "VPC ID not provided",
                "errors": [],
                "summary": self._empty_summary(),
            }

        cached = self._vpc_cache.get(vpc_id)

        if cached is not None:
            result = deepcopy(cached)
            result["resource"] = resource
            return result

        errors: List[Dict[str, Any]] = []

        vpc = self._collect_vpc(
            vpc_id,
            errors,
        )

        if not vpc:
            return {
                "status": "error" if errors else "incomplete",
                "resource": resource,
                "region": self.region,
                "vpc_id": vpc_id,
                "reason": "VPC not found or inaccessible",
                "errors": errors,
                "summary": self._empty_summary(),
            }

        subnets = self._collect_subnets(
            vpc_id,
            errors,
        )

        route_tables = self._collect_route_tables(
            vpc_id,
            errors,
        )

        # AWS semantics:
        # - explicit subnet association wins
        # - otherwise the subnet uses the VPC main route table
        effective_mappings = self._resolve_effective_route_tables(
            route_tables=route_tables,
            subnets=subnets,
        )

        effective_routes = self._build_effective_routes(
            route_tables=route_tables,
            subnets=subnets,
            effective_route_table_mappings=effective_mappings,
        )

        vpc_endpoints = self._collect_vpc_endpoints(
            vpc_id,
            errors,
        )

        route_targets = self._collect_route_targets(route_tables)

        subnet_profiles = self._build_subnet_profiles(
            subnets=subnets,
            route_tables=route_tables,
            effective_route_table_mappings=effective_mappings,
            vpc_endpoints=vpc_endpoints,
        )

        all_routes = [
            route
            for table in route_tables
            for route in (table.get("routes", []) or [])
            if isinstance(route, dict)
        ]

        # Determine whether every discovered subnet has an effective
        # route-table mapping.
        subnet_ids = {
            self._normalize_id(subnet.get("subnet_id"))
            for subnet in subnets
            if self._normalize_id(subnet.get("subnet_id"))
        }

        mapped_subnet_ids = {
            self._normalize_id(mapping.get("subnet_id"))
            for mapping in effective_mappings
            if self._normalize_id(mapping.get("subnet_id"))
        }

        unmapped_subnet_ids = sorted(subnet_ids - mapped_subnet_ids)

        route_table_ids = {
            self._normalize_id(table.get("route_table_id"))
            for table in route_tables
            if self._normalize_id(table.get("route_table_id"))
        }

        mapped_route_table_ids = {
            self._normalize_id(mapping.get("route_table_id"))
            for mapping in effective_mappings
            if self._normalize_id(mapping.get("route_table_id"))
        }

        missing_effective_route_tables = sorted(
            route_table_id
            for route_table_id in mapped_route_table_ids
            if route_table_id not in route_table_ids
        )

        topology_complete = (
            not errors
            and not unmapped_subnet_ids
            and not missing_effective_route_tables
        )

        if errors:
            status = "partial"
        elif not topology_complete:
            status = "partial"
        else:
            status = "ok"

        summary = {
            "subnet_count": len(subnets),
            "route_table_count": len(route_tables),
            "route_count": len(all_routes),
            "effective_route_count": len(effective_routes),
            "effective_route_table_mapping_count": len(effective_mappings),
            "vpc_endpoint_count": len(vpc_endpoints),
            "internet_gateway_count": len(
                route_targets.get(
                    "internet_gateways",
                    [],
                )
            ),
            "nat_gateway_count": len(
                route_targets.get(
                    "nat_gateways",
                    [],
                )
            ),
            "transit_gateway_count": len(
                route_targets.get(
                    "transit_gateways",
                    [],
                )
            ),
            "vpc_endpoint_route_target_count": len(
                route_targets.get(
                    "vpc_endpoints",
                    [],
                )
            ),
            "vpc_peering_connection_count": len(
                route_targets.get(
                    "vpc_peering_connections",
                    [],
                )
            ),
            "network_interface_target_count": len(
                route_targets.get(
                    "network_interfaces",
                    [],
                )
            ),
            "mapped_subnet_count": len(mapped_subnet_ids),
            "unmapped_subnet_count": len(unmapped_subnet_ids),
            "unmapped_subnet_ids": unmapped_subnet_ids,
            "missing_effective_route_table_count": len(missing_effective_route_tables),
            "missing_effective_route_table_ids": (missing_effective_route_tables),
            "topology_complete": topology_complete,
        }

        result: Dict[str, Any] = {
            "status": status,
            "resource": resource,
            "region": self.region,
            "vpc_id": vpc_id,
            "vpc": vpc,
            "subnets": subnets,
            "route_tables": route_tables,
            "routes": all_routes,
            "effective_route_table_mappings": effective_mappings,
            "effective_routes": effective_routes,
            "subnet_profiles": subnet_profiles,
            "route_targets": route_targets,
            "vpc_endpoints": vpc_endpoints,
            "errors": errors,
            "summary": summary,
        }

        # Only cache fully reliable topology.
        if status == "ok":
            self._vpc_cache[vpc_id] = deepcopy(result)

        return deepcopy(result)

    def _collect_vpc(
        self,
        vpc_id: str,
        errors: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:

        try:
            response = self.ec2.describe_vpcs(VpcIds=[vpc_id])
        except Exception as exc:
            errors.append(
                self._error(
                    "describe_vpcs",
                    vpc_id,
                    exc,
                )
            )
            return None

        vpcs = response.get("Vpcs", [])

        if not isinstance(vpcs, list):
            errors.append(
                {
                    "operation": "describe_vpcs",
                    "resource_id": vpc_id,
                    "error_type": "InvalidResponse",
                    "error": "AWS response field 'Vpcs' is not a list",
                }
            )
            return None

        if not vpcs:
            return None

        vpc = vpcs[0]

        if not isinstance(vpc, dict):
            errors.append(
                {
                    "operation": "describe_vpcs",
                    "resource_id": vpc_id,
                    "error_type": "InvalidResponse",
                    "error": "VPC entry is not a mapping",
                }
            )
            return None

        return {
            "vpc_id": vpc.get("VpcId"),
            "cidr_block": vpc.get("CidrBlock"),
            "cidr_block_associations": [
                association.get("CidrBlock")
                for association in (
                    vpc.get(
                        "CidrBlockAssociationSet",
                        [],
                    )
                    or []
                )
                if isinstance(association, dict) and association.get("CidrBlock")
            ],
            "ipv6_cidr_blocks": [
                association.get("Ipv6CidrBlock")
                for association in (
                    vpc.get(
                        "Ipv6CidrBlockAssociationSet",
                        [],
                    )
                    or []
                )
                if isinstance(association, dict) and association.get("Ipv6CidrBlock")
            ],
            "state": vpc.get("State"),
            "is_default": vpc.get("IsDefault"),
            "instance_tenancy": vpc.get("InstanceTenancy"),
            "tags": self._tags(vpc.get("Tags", [])),
        }

    def _collect_subnets(
        self,
        vpc_id: str,
        errors: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        try:
            paginator = self.ec2.get_paginator("describe_subnets")

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id],
                    }
                ]
            ):
                subnets = page.get("Subnets", [])

                if not isinstance(subnets, list):
                    errors.append(
                        {
                            "operation": "describe_subnets",
                            "resource_id": vpc_id,
                            "error_type": "InvalidResponse",
                            "error": ("AWS response field " "'Subnets' is not a list"),
                        }
                    )
                    continue

                for subnet in subnets:
                    if not isinstance(subnet, dict):
                        continue

                    subnet_id = self._normalize_id(subnet.get("SubnetId"))

                    if not subnet_id:
                        continue

                    result.append(
                        {
                            "subnet_id": subnet_id,
                            "vpc_id": subnet.get("VpcId"),
                            "cidr_block": subnet.get("CidrBlock"),
                            "availability_zone": subnet.get("AvailabilityZone"),
                            "availability_zone_id": subnet.get("AvailabilityZoneId"),
                            "state": subnet.get("State"),
                            "available_ip_address_count": (
                                subnet.get("AvailableIpAddressCount")
                            ),
                            "map_public_ip_on_launch": (
                                subnet.get("MapPublicIpOnLaunch")
                            ),
                            "default_for_az": subnet.get("DefaultForAz"),
                            "assign_ipv6_address_on_creation": (
                                subnet.get("AssignIpv6AddressOnCreation")
                            ),
                            "ipv6_cidr_block_association_count": len(
                                subnet.get(
                                    "Ipv6CidrBlockAssociationSet",
                                    [],
                                )
                                or []
                            ),
                            "tags": self._tags(subnet.get("Tags", [])),
                        }
                    )

        except Exception as exc:
            errors.append(
                self._error(
                    "describe_subnets",
                    vpc_id,
                    exc,
                )
            )

        return result

    def _collect_route_tables(
        self,
        vpc_id: str,
        errors: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        try:
            paginator = self.ec2.get_paginator("describe_route_tables")

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id],
                    }
                ]
            ):
                tables = page.get("RouteTables", [])

                if not isinstance(tables, list):
                    errors.append(
                        {
                            "operation": "describe_route_tables",
                            "resource_id": vpc_id,
                            "error_type": "InvalidResponse",
                            "error": (
                                "AWS response field " "'RouteTables' is not a list"
                            ),
                        }
                    )
                    continue

                for table in tables:
                    if not isinstance(table, dict):
                        continue

                    route_table_id = self._normalize_id(table.get("RouteTableId"))

                    if not route_table_id:
                        continue

                    routes: List[Dict[str, Any]] = []

                    for route in table.get("Routes", []) or []:
                        if not isinstance(route, dict):
                            continue

                        normalized = self._normalize_route(route)

                        if normalized:
                            routes.append(normalized)

                    associations: List[Dict[str, Any]] = []

                    for association in table.get("Associations", []) or []:
                        if not isinstance(association, dict):
                            continue

                        normalized = self._normalize_association(association)

                        if normalized:
                            associations.append(normalized)

                    result.append(
                        {
                            "route_table_id": route_table_id,
                            "vpc_id": table.get("VpcId"),
                            "routes": routes,
                            "associations": associations,
                            "is_main": any(
                                association.get("main") is True
                                for association in associations
                            ),
                            "propagating_vgws": [
                                item
                                for item in (
                                    table.get(
                                        "PropagatingVgws",
                                        [],
                                    )
                                    or []
                                )
                                if isinstance(item, dict)
                            ],
                            "tags": self._tags(table.get("Tags", [])),
                        }
                    )

        except Exception as exc:
            errors.append(
                self._error(
                    "describe_route_tables",
                    vpc_id,
                    exc,
                )
            )

        return result

    def _resolve_effective_route_tables(
        self,
        route_tables: List[Dict[str, Any]],
        subnets: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        explicit: Dict[str, str] = {}

        main_route_table_id: Optional[str] = None

        for table in route_tables:
            table_id = self._normalize_id(table.get("route_table_id"))

            if not table_id:
                continue

            for association in table.get("associations", []) or []:
                if not isinstance(association, dict):
                    continue

                state = association.get("state")

                if state not in {
                    None,
                    "associated",
                }:
                    continue

                if association.get("main") is True:
                    main_route_table_id = table_id

                subnet_id = self._normalize_id(association.get("subnet_id"))

                if subnet_id:
                    explicit[subnet_id] = table_id

        result: List[Dict[str, Any]] = []

        for subnet in subnets:
            subnet_id = self._normalize_id(subnet.get("subnet_id"))

            if not subnet_id:
                continue

            route_table_id = explicit.get(subnet_id)

            if route_table_id:
                result.append(
                    {
                        "subnet_id": subnet_id,
                        "route_table_id": route_table_id,
                        "source": "explicit",
                    }
                )
                continue

            if main_route_table_id:
                result.append(
                    {
                        "subnet_id": subnet_id,
                        "route_table_id": main_route_table_id,
                        "source": "main",
                    }
                )

        return result

    def _build_effective_routes(
        self,
        *,
        route_tables: List[Dict[str, Any]],
        subnets: List[Dict[str, Any]],
        effective_route_table_mappings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        route_table_index = {
            self._normalize_id(table.get("route_table_id")): table
            for table in route_tables
            if self._normalize_id(table.get("route_table_id"))
        }

        subnet_index = {
            self._normalize_id(subnet.get("subnet_id")): subnet
            for subnet in subnets
            if self._normalize_id(subnet.get("subnet_id"))
        }

        effective_routes: List[Dict[str, Any]] = []

        seen: set[tuple] = set()

        for mapping in effective_route_table_mappings:
            subnet_id = self._normalize_id(mapping.get("subnet_id"))

            route_table_id = self._normalize_id(mapping.get("route_table_id"))

            if not subnet_id or not route_table_id:
                continue

            table = route_table_index.get(route_table_id)

            if not table:
                continue

            subnet = subnet_index.get(subnet_id)

            for route in table.get("routes", []) or []:
                if not isinstance(route, dict):
                    continue

                normalized = {
                    **route,
                    "subnet_id": subnet_id,
                    "route_table_id": route_table_id,
                    "route_table_source": mapping.get("source"),
                    "availability_zone": (
                        subnet.get("availability_zone") if subnet else None
                    ),
                }

                key = self._effective_route_key(normalized)

                if key in seen:
                    continue

                seen.add(key)
                effective_routes.append(normalized)

        return effective_routes

    @staticmethod
    def _effective_route_key(
        route: Dict[str, Any],
    ) -> tuple:
        return (
            route.get("subnet_id"),
            route.get("route_table_id"),
            route.get("destination_cidr_block"),
            route.get("destination_ipv6_cidr_block"),
            route.get("destination_prefix_list_id"),
            route.get("gateway_id"),
            route.get("nat_gateway_id"),
            route.get("transit_gateway_id"),
            route.get("vpc_endpoint_id"),
            route.get("network_interface_id"),
            route.get("vpc_peering_connection_id"),
            route.get("instance_id"),
            route.get("carrier_gateway_id"),
            route.get("local_gateway_id"),
            route.get("egress_only_internet_gateway_id"),
            route.get("core_network_arn"),
            route.get("odb_network_arn"),
            route.get("state"),
            route.get("origin"),
        )

    # Subnet profiles

    def _build_subnet_profiles(
        self,
        *,
        subnets: List[Dict[str, Any]],
        route_tables: List[Dict[str, Any]],
        effective_route_table_mappings: List[Dict[str, Any]],
        vpc_endpoints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        route_table_index = {
            self._normalize_id(table.get("route_table_id")): table
            for table in route_tables
            if self._normalize_id(table.get("route_table_id"))
        }

        effective_index = {
            self._normalize_id(mapping.get("subnet_id")): mapping
            for mapping in effective_route_table_mappings
            if self._normalize_id(mapping.get("subnet_id"))
        }

        endpoint_route_table_index: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        endpoint_subnet_index: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        for endpoint in vpc_endpoints:
            for route_table_id in endpoint.get("route_table_ids", []) or []:
                normalized_route_table_id = self._normalize_id(route_table_id)

                if normalized_route_table_id:
                    endpoint_route_table_index.setdefault(
                        normalized_route_table_id,
                        [],
                    ).append(endpoint)

            for subnet_id in endpoint.get("subnet_ids", []) or []:
                normalized_subnet_id = self._normalize_id(subnet_id)

                if normalized_subnet_id:
                    endpoint_subnet_index.setdefault(
                        normalized_subnet_id,
                        [],
                    ).append(endpoint)

        result: List[Dict[str, Any]] = []

        for subnet in subnets:
            subnet_id = self._normalize_id(subnet.get("subnet_id"))

            if not subnet_id:
                continue

            mapping = effective_index.get(subnet_id)

            route_table_id = (
                self._normalize_id(mapping.get("route_table_id")) if mapping else None
            )

            route_table = (
                route_table_index.get(route_table_id) if route_table_id else None
            )

            routes = route_table.get("routes", []) if route_table else []

            target_sets = {
                "nat_gateway_ids": set(),
                "transit_gateway_ids": set(),
                "internet_gateway_ids": set(),
                "vpc_endpoint_route_ids": set(),
                "vpc_peering_connection_ids": set(),
                "network_interface_ids": set(),
                "instance_ids": set(),
                "carrier_gateway_ids": set(),
                "local_gateway_ids": set(),
                "egress_only_internet_gateway_ids": set(),
                "core_network_arns": set(),
                "odb_network_arns": set(),
            }

            has_default_nat_route = False
            has_default_igw_route = False
            has_default_tgw_route = False

            route_count = 0
            active_route_count = 0
            blackhole_route_count = 0

            for route in routes:
                if not isinstance(route, dict):
                    continue

                route_count += 1

                state = route.get("state")

                if state == "blackhole":
                    blackhole_route_count += 1
                else:
                    active_route_count += 1

                if route.get("is_default_route"):
                    if route.get("nat_gateway_id"):
                        has_default_nat_route = True

                    gateway_id = route.get("gateway_id")

                    if gateway_id and str(gateway_id).startswith("igw-"):
                        has_default_igw_route = True

                    if route.get("transit_gateway_id"):
                        has_default_tgw_route = True

                field_targets = {
                    "nat_gateway_id": "nat_gateway_ids",
                    "transit_gateway_id": "transit_gateway_ids",
                    "vpc_endpoint_id": "vpc_endpoint_route_ids",
                    "network_interface_id": "network_interface_ids",
                    "instance_id": "instance_ids",
                    "vpc_peering_connection_id": ("vpc_peering_connection_ids"),
                    "carrier_gateway_id": "carrier_gateway_ids",
                    "local_gateway_id": "local_gateway_ids",
                    "egress_only_internet_gateway_id": (
                        "egress_only_internet_gateway_ids"
                    ),
                    "core_network_arn": "core_network_arns",
                    "odb_network_arn": "odb_network_arns",
                }

                for field, target_name in field_targets.items():
                    value = route.get(field)

                    if value:
                        target_sets[target_name].add(str(value))

                gateway_id = route.get("gateway_id")

                if gateway_id and str(gateway_id).startswith("igw-"):
                    target_sets["internet_gateway_ids"].add(str(gateway_id))

            endpoint_matches = list(
                endpoint_subnet_index.get(
                    subnet_id,
                    [],
                )
            )

            if route_table_id:
                endpoint_matches.extend(
                    endpoint_route_table_index.get(
                        route_table_id,
                        [],
                    )
                )

            endpoint_ids = sorted(
                {
                    str(endpoint.get("vpc_endpoint_id"))
                    for endpoint in endpoint_matches
                    if endpoint.get("vpc_endpoint_id")
                }
            )

            endpoint_services = sorted(
                {
                    str(endpoint.get("service_name"))
                    for endpoint in endpoint_matches
                    if endpoint.get("service_name")
                }
            )

            result.append(
                {
                    "subnet_id": subnet_id,
                    "availability_zone": subnet.get("availability_zone"),
                    "route_table_id": route_table_id,
                    "route_table_source": (mapping.get("source") if mapping else None),
                    "route_table_resolved": route_table is not None,
                    "route_count": route_count,
                    "active_route_count": active_route_count,
                    "blackhole_route_count": blackhole_route_count,
                    "has_default_nat_route": (has_default_nat_route),
                    "has_default_internet_gateway_route": (has_default_igw_route),
                    "has_default_transit_gateway_route": (has_default_tgw_route),
                    "nat_gateway_ids": sorted(target_sets["nat_gateway_ids"]),
                    "transit_gateway_ids": sorted(target_sets["transit_gateway_ids"]),
                    "internet_gateway_ids": sorted(target_sets["internet_gateway_ids"]),
                    "vpc_endpoint_route_ids": sorted(
                        target_sets["vpc_endpoint_route_ids"]
                    ),
                    "vpc_endpoint_ids": endpoint_ids,
                    "vpc_endpoint_services": endpoint_services,
                    "vpc_peering_connection_ids": sorted(
                        target_sets["vpc_peering_connection_ids"]
                    ),
                    "network_interface_ids": sorted(
                        target_sets["network_interface_ids"]
                    ),
                    "instance_ids": sorted(target_sets["instance_ids"]),
                    "carrier_gateway_ids": sorted(target_sets["carrier_gateway_ids"]),
                    "local_gateway_ids": sorted(target_sets["local_gateway_ids"]),
                    "egress_only_internet_gateway_ids": sorted(
                        target_sets["egress_only_internet_gateway_ids"]
                    ),
                    "core_network_arns": sorted(target_sets["core_network_arns"]),
                    "odb_network_arns": sorted(target_sets["odb_network_arns"]),
                }
            )

        return result

    def _collect_vpc_endpoints(
        self,
        vpc_id: str,
        errors: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        try:
            paginator = self.ec2.get_paginator("describe_vpc_endpoints")

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id],
                    }
                ]
            ):
                endpoints = page.get("VpcEndpoints", [])

                if not isinstance(endpoints, list):
                    errors.append(
                        {
                            "operation": "describe_vpc_endpoints",
                            "resource_id": vpc_id,
                            "error_type": "InvalidResponse",
                            "error": (
                                "AWS response field " "'VpcEndpoints' is not a list"
                            ),
                        }
                    )
                    continue

                for endpoint in endpoints:
                    if not isinstance(endpoint, dict):
                        continue

                    endpoint_id = self._normalize_id(endpoint.get("VpcEndpointId"))

                    if not endpoint_id:
                        continue

                    endpoint_type = endpoint.get("VpcEndpointType")

                    result.append(
                        {
                            "vpc_endpoint_id": endpoint_id,
                            "vpc_id": endpoint.get("VpcId"),
                            "service_name": endpoint.get("ServiceName"),
                            "service_region": endpoint.get("ServiceRegion"),
                            "endpoint_type": endpoint_type,
                            "category": self._endpoint_category(endpoint_type),
                            "state": endpoint.get("State"),
                            "route_table_ids": [
                                str(value)
                                for value in (
                                    endpoint.get(
                                        "RouteTableIds",
                                        [],
                                    )
                                    or []
                                )
                                if value
                            ],
                            "subnet_ids": [
                                str(value)
                                for value in (
                                    endpoint.get(
                                        "SubnetIds",
                                        [],
                                    )
                                    or []
                                )
                                if value
                            ],
                            "network_interface_ids": [
                                str(value)
                                for value in (
                                    endpoint.get(
                                        "NetworkInterfaceIds",
                                        [],
                                    )
                                    or []
                                )
                                if value
                            ],
                            "security_group_ids": [
                                group.get("GroupId")
                                for group in (
                                    endpoint.get(
                                        "Groups",
                                        [],
                                    )
                                    or []
                                )
                                if isinstance(group, dict) and group.get("GroupId")
                            ],
                            "private_dns_enabled": endpoint.get("PrivateDnsEnabled"),
                            "ip_address_type": endpoint.get("IpAddressType"),
                            "owner_id": endpoint.get("OwnerId"),
                            "requester_managed": endpoint.get("RequesterManaged"),
                            "tags": self._tags(endpoint.get("Tags", [])),
                        }
                    )

        except Exception as exc:
            errors.append(
                self._error(
                    "describe_vpc_endpoints",
                    vpc_id,
                    exc,
                )
            )

        return result

    def _collect_route_targets(
        self,
        route_tables: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:

        targets: Dict[str, set[str]] = {
            "internet_gateways": set(),
            "nat_gateways": set(),
            "transit_gateways": set(),
            "vpc_endpoints": set(),
            "vpc_peering_connections": set(),
            "network_interfaces": set(),
            "instances": set(),
            "carrier_gateways": set(),
            "local_gateways": set(),
            "egress_only_internet_gateways": set(),
            "core_networks": set(),
            "odb_networks": set(),
        }

        field_mapping = {
            "gateway_id": "internet_gateways",
            "nat_gateway_id": "nat_gateways",
            "transit_gateway_id": "transit_gateways",
            "vpc_endpoint_id": "vpc_endpoints",
            "vpc_peering_connection_id": ("vpc_peering_connections"),
            "network_interface_id": "network_interfaces",
            "instance_id": "instances",
            "carrier_gateway_id": "carrier_gateways",
            "local_gateway_id": "local_gateways",
            "egress_only_internet_gateway_id": ("egress_only_internet_gateways"),
            "core_network_arn": "core_networks",
            "odb_network_arn": "odb_networks",
        }

        for table in route_tables:
            for route in table.get("routes", []) or []:
                if not isinstance(route, dict):
                    continue

                for field, category in field_mapping.items():
                    value = route.get(field)

                    if not value:
                        continue

                    value = str(value)

                    if field == "gateway_id" and not value.startswith("igw-"):
                        continue

                    targets[category].add(value)

        return {key: sorted(values) for key, values in targets.items()}

    # Route normalization

    @staticmethod
    def _normalize_route(
        route: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not isinstance(route, dict):
            return {}

        destination_cidr = route.get("DestinationCidrBlock")

        destination_ipv6 = route.get("DestinationIpv6CidrBlock")

        prefix_list_id = route.get("DestinationPrefixListId")

        gateway_id = route.get("GatewayId")
        nat_gateway_id = route.get("NatGatewayId")
        transit_gateway_id = route.get("TransitGatewayId")
        vpc_endpoint_id = route.get("VpcEndpointId")

        vpc_peering_connection_id = route.get("VpcPeeringConnectionId")

        network_interface_id = route.get("NetworkInterfaceId")

        instance_id = route.get("InstanceId")
        carrier_gateway_id = route.get("CarrierGatewayId")
        local_gateway_id = route.get("LocalGatewayId")

        egress_only_gateway_id = route.get("EgressOnlyInternetGatewayId")

        core_network_arn = route.get("CoreNetworkArn")
        odb_network_arn = route.get("OdbNetworkArn")

        route_class = "local"

        if nat_gateway_id:
            route_class = "nat_gateway"
        elif transit_gateway_id:
            route_class = "transit_gateway"
        elif vpc_endpoint_id:
            route_class = "vpc_endpoint"
        elif gateway_id and str(gateway_id).startswith("igw-"):
            route_class = "internet_gateway"
        elif vpc_peering_connection_id:
            route_class = "vpc_peering"
        elif network_interface_id:
            route_class = "network_interface"
        elif instance_id:
            route_class = "instance"
        elif carrier_gateway_id:
            route_class = "carrier_gateway"
        elif local_gateway_id:
            route_class = "local_gateway"
        elif egress_only_gateway_id:
            route_class = "egress_only_gateway"
        elif core_network_arn:
            route_class = "core_network"
        elif odb_network_arn:
            route_class = "odb_network"
        elif prefix_list_id:
            route_class = "prefix_list"
        elif destination_cidr:
            route_class = "cidr"
        elif destination_ipv6:
            route_class = "ipv6"
        elif gateway_id:
            route_class = "gateway"

        destination = destination_cidr or destination_ipv6 or prefix_list_id

        is_default_route = destination_cidr == "0.0.0.0/0" or destination_ipv6 == "::/0"

        return {
            "destination_cidr_block": destination_cidr,
            "destination_ipv6_cidr_block": destination_ipv6,
            "destination_prefix_list_id": prefix_list_id,
            "destination": destination,
            "gateway_id": gateway_id,
            "nat_gateway_id": nat_gateway_id,
            "transit_gateway_id": transit_gateway_id,
            "vpc_endpoint_id": vpc_endpoint_id,
            "network_interface_id": network_interface_id,
            "vpc_peering_connection_id": (vpc_peering_connection_id),
            "instance_id": instance_id,
            "carrier_gateway_id": carrier_gateway_id,
            "local_gateway_id": local_gateway_id,
            "egress_only_internet_gateway_id": (egress_only_gateway_id),
            "core_network_arn": core_network_arn,
            "odb_network_arn": odb_network_arn,
            "state": route.get("State"),
            "origin": route.get("Origin"),
            "route_class": route_class,
            "is_default_route": is_default_route,
        }

    @staticmethod
    def _normalize_association(
        association: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not isinstance(association, dict):
            return {}

        state = association.get("AssociationState")

        if not isinstance(state, dict):
            state = {}

        return {
            "association_id": association.get("RouteTableAssociationId"),
            "route_table_id": association.get("RouteTableId"),
            "subnet_id": association.get("SubnetId"),
            "gateway_id": association.get("GatewayId"),
            "main": bool(
                association.get(
                    "Main",
                    False,
                )
            ),
            "state": state.get("State"),
        }

    @staticmethod
    def _endpoint_category(
        endpoint_type: Optional[str],
    ) -> str:
        return {
            "Gateway": "gateway",
            "Interface": "interface",
            "GatewayLoadBalancer": ("gateway_load_balancer"),
            "Resource": "resource",
            "ServiceNetwork": "service_network",
        }.get(
            endpoint_type,
            "unknown",
        )

    @staticmethod
    def _tags(
        tags: Any,
    ) -> Dict[str, Any]:

        if not isinstance(tags, list):
            return {}

        result: Dict[str, Any] = {}

        for tag in tags:
            if not isinstance(tag, dict):
                continue

            key = tag.get("Key")

            if key is None:
                continue

            key = str(key).strip()

            if not key:
                continue

            result[key] = tag.get("Value")

        return result

    @staticmethod
    def _normalize_id(
        value: Any,
    ) -> Optional[str]:

        if value is None:
            return None

        value = str(value).strip()

        return value or None

    @staticmethod
    def _empty_summary() -> Dict[str, Any]:
        return {
            "subnet_count": 0,
            "route_table_count": 0,
            "route_count": 0,
            "effective_route_count": 0,
            "effective_route_table_mapping_count": 0,
            "vpc_endpoint_count": 0,
            "internet_gateway_count": 0,
            "nat_gateway_count": 0,
            "transit_gateway_count": 0,
            "vpc_endpoint_route_target_count": 0,
            "vpc_peering_connection_count": 0,
            "network_interface_target_count": 0,
            "mapped_subnet_count": 0,
            "unmapped_subnet_count": 0,
            "unmapped_subnet_ids": [],
            "missing_effective_route_table_count": 0,
            "missing_effective_route_table_ids": [],
            "topology_complete": False,
        }

    @staticmethod
    def _error(
        operation: str,
        resource_id: str,
        exc: Exception,
    ) -> Dict[str, Any]:

        return {
            "operation": operation,
            "resource_id": resource_id,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
