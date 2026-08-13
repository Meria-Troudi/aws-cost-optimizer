"""
AWS VPC Endpoint Collector.

Collects:

- Endpoint identity
- Endpoint configuration
- Gateway endpoint route relationships
- Interface endpoint subnet relationships
- Network interfaces
- Security groups
- Availability zones
- VPC route tables
- NAT Gateway dependencies
- Transit Gateway dependencies
- Internet Gateway dependencies
- VPC peering dependencies
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register

from collectors.network.topology import NetworkTopologyCollector
from collectors.network.relationships import NetworkRelationshipResolver


@register
class VpcEndpointCollector(BaseCollector):

    key = "vpc_endpoint"
    resource_type = "vpc_endpoint"

 
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

     # DISCOVERY
 
    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        endpoints = (
            self._collect_all_endpoints()
        )

        resources: List[Dict[str, Any]] = []

        for endpoint in endpoints:

            resource = self._build_resource(
                endpoint
            )

            vpc_id = endpoint.get(
                "vpc_id"
            )

            endpoint_id = endpoint.get(
                "vpc_endpoint_id"
            )

            if vpc_id:

                topology = self._collect_topology(
                    vpc_id=vpc_id,
                    endpoint_id=endpoint_id,
                )

                resource["topology"] = topology

                resource["relationships"] = (
                    self._build_relationships(
                        endpoint=endpoint,
                        topology=topology,
                    )
                )

            resources.append(
                resource
            )

        return resources

     # AWS COLLECTION
 
    def _collect_all_endpoints(
        self,
    ) -> List[Dict[str, Any]]:

        paginator = self.ec2.get_paginator(
            "describe_vpc_endpoints"
        )

        result: List[Dict[str, Any]] = []

        try:

            for page in paginator.paginate():

                for endpoint in page.get(
                    "VpcEndpoints",
                    [],
                ):

                    normalized = (
                        self._normalize_endpoint(
                            endpoint
                        )
                    )

                    endpoint_id = normalized.get(
                        "vpc_endpoint_id"
                    )

                    if endpoint_id:
                        result.append(
                            normalized
                        )

        except Exception as exc:

            raise RuntimeError(
                "Failed to collect VPC endpoints "
                f"in {self.region}: {exc}"
            ) from exc

        return result

     # NORMALIZATION
 
    def _normalize_endpoint(
        self,
        endpoint: Dict[str, Any],
    ) -> Dict[str, Any]:

        endpoint_type = endpoint.get(
            "VpcEndpointType"
        )

        subnet_ids = list(
            endpoint.get(
                "SubnetIds",
                [],
            )
            or []
        )

        route_table_ids = list(
            endpoint.get(
                "RouteTableIds",
                [],
            )
            or []
        )

        network_interface_ids = list(
            endpoint.get(
                "NetworkInterfaceIds",
                [],
            )
            or []
        )

        security_group_ids = [
            group.get("GroupId")
            for group in endpoint.get(
                "Groups",
                [],
            )
            if group.get("GroupId")
        ]

        return {
              # Identity
  
            "vpc_endpoint_id": endpoint.get(
                "VpcEndpointId"
            ),

            "vpc_id": endpoint.get(
                "VpcId"
            ),

            "service_name": endpoint.get(
                "ServiceName"
            ),

            "service_region": endpoint.get(
                "ServiceRegion"
            ),

            "endpoint_type": endpoint_type,

              # State
  
            "state": endpoint.get(
                "State"
            ),

            "creation_timestamp": (
                self._serialize_datetime(
                    endpoint.get(
                        "CreationTimestamp"
                    )
                )
            ),

            "last_error": endpoint.get(
                "LastError"
            ),

            "failure_reason": endpoint.get(
                "FailureReason"
            ),

              # DNS
  
            "private_dns_enabled": endpoint.get(
                "PrivateDnsEnabled"
            ),

            "dns_options": endpoint.get(
                "DnsOptions"
            ),

            "dns_entries": endpoint.get(
                "DnsEntries",
                [],
            ),

              # Routing
  
            "route_table_ids": route_table_ids,

            "subnet_ids": subnet_ids,

              # Network
  
            "network_interface_ids": (
                network_interface_ids
            ),

            "security_group_ids": (
                security_group_ids
            ),

            "ip_address_type": endpoint.get(
                "IpAddressType"
            ),

              # Ownership
  
            "owner_id": endpoint.get(
                "OwnerId"
            ),

            "requester_managed": endpoint.get(
                "RequesterManaged"
            ),

              # Policy
  
            "policy_document": endpoint.get(
                "PolicyDocument"
            ),

              # Tags
  
            "tags": self._tags(
                endpoint.get(
                    "Tags",
                    [],
                )
            ),

              # Classification
  
            "category": self._endpoint_category(
                endpoint_type
            ),

            "is_gateway": (
                endpoint_type == "Gateway"
            ),

            "is_interface": (
                endpoint_type == "Interface"
            ),

            "is_gateway_load_balancer": (
                endpoint_type
                == "GatewayLoadBalancer"
            ),
        }

     # TOPOLOGY
 
    def _collect_topology(
        self,
        vpc_id: str,
        endpoint_id: Optional[str],
    ) -> Dict[str, Any]:

        topology_collector = (
            NetworkTopologyCollector(
                region=self.region
            )
        )

        try:

            return topology_collector.collect(
                vpc_id=vpc_id,
                resource_type=self.resource_type,
                resource_id=endpoint_id,
            )

        except Exception as exc:

            return {
                "status": "error",
                "error": str(exc),
            }

     # RELATIONSHIPS
 
    def _build_relationships(
        self,
        endpoint: Dict[str, Any],
        topology: Dict[str, Any],
    ) -> Dict[str, Any]:

        if topology.get(
            "status"
        ) != "ok":

            return {
                "status": "incomplete",
                "reason": topology.get(
                    "reason",
                    "VPC topology unavailable",
                ),
            }

        resolver = (
            NetworkRelationshipResolver(
                topology
            )
        )

        endpoint_id = endpoint.get(
            "vpc_endpoint_id"
        )

        endpoint_type = endpoint.get(
            "endpoint_type"
        )

        subnet_ids = list(
            endpoint.get(
                "subnet_ids",
                [],
            )
            or []
        )

        route_table_ids = list(
            endpoint.get(
                "route_table_ids",
                [],
            )
            or []
        )
        endpoint_subnets: List[
            Dict[str, Any]
        ] = []

        if endpoint_type == "Gateway":

            seen_subnets = set()

            for route_table_id in route_table_ids:

                for subnet in (
                    resolver.subnets_for_route_table(
                        route_table_id
                    )
                ):

                    subnet_id = subnet.get(
                        "subnet_id"
                    )

                    if (
                        subnet_id
                        and subnet_id
                        not in seen_subnets
                    ):

                        seen_subnets.add(
                            subnet_id
                        )

                        endpoint_subnets.append(
                            subnet
                        )

        else:

            for subnet_id in subnet_ids:

                subnet = resolver.subnet(
                    subnet_id
                )

                if subnet:
                    endpoint_subnets.append(
                        subnet
                    )

           # Availability zones
   
        availability_zones = sorted(
            {
                subnet.get(
                    "availability_zone"
                )
                for subnet in endpoint_subnets
                if subnet.get(
                    "availability_zone"
                )
            }
        )

           # Route tables
   
        endpoint_route_tables = [
            table
            for table in topology.get(
                "route_tables",
                [],
            )
            if table.get(
                "route_table_id"
            ) in route_table_ids
        ]
        gateway_endpoint_routes: List[
            Dict[str, Any]
        ] = []

        if endpoint_type == "Gateway":

            gateway_endpoint_routes = (
                resolver.routes_targeting_vpc_endpoint(
                    endpoint_id
                )
            )


        interface_subnet_routes: List[
            Dict[str, Any]
        ] = []

        if endpoint_type == "Interface":

            for subnet_id in subnet_ids:

                interface_subnet_routes.extend(
                    resolver.routes_for_subnet(
                        subnet_id
                    )
                )
        relevant_routes = []

        if endpoint_type == "Gateway":

            relevant_routes = (
                gateway_endpoint_routes
            )

        elif endpoint_type == "Interface":

            relevant_routes = (
                interface_subnet_routes
            )

        nat_gateway_ids = set()
        transit_gateway_ids = set()
        internet_gateway_ids = set()
        vpc_peering_connection_ids = set()

        for route in relevant_routes:

            nat_gateway_id = route.get(
                "nat_gateway_id"
            )

            if nat_gateway_id:
                nat_gateway_ids.add(
                    nat_gateway_id
                )

            transit_gateway_id = route.get(
                "transit_gateway_id"
            )

            if transit_gateway_id:
                transit_gateway_ids.add(
                    transit_gateway_id
                )

            gateway_id = route.get(
                "gateway_id"
            )

            if (
                gateway_id
                and str(gateway_id).startswith(
                    "igw-"
                )
            ):
                internet_gateway_ids.add(
                    gateway_id
                )

            peering_id = route.get(
                "vpc_peering_connection_id"
            )

            if peering_id:
                vpc_peering_connection_ids.add(
                    peering_id
                )
   
        nat_routes = [
            route
            for route in relevant_routes
            if route.get(
                "nat_gateway_id"
            )
        ]

        transit_gateway_routes = [
            route
            for route in relevant_routes
            if route.get(
                "transit_gateway_id"
            )
        ]

        internet_gateway_routes = [
            route
            for route in relevant_routes
            if (
                route.get(
                    "gateway_id"
                )
                and str(
                    route.get(
                        "gateway_id"
                    )
                ).startswith("igw-")
            )
        ]

        return {
            "status": "ok",

              # VPC
  
            "vpc": {
                "vpc_id": endpoint.get(
                    "vpc_id"
                ),
            },

              # Subnets
  
            "subnets": {
                "subnet_ids": [
                    subnet.get(
                        "subnet_id"
                    )
                    for subnet in endpoint_subnets
                    if subnet.get(
                        "subnet_id"
                    )
                ],

                "count": len(
                    endpoint_subnets
                ),

                "resources": endpoint_subnets,
            },

              # AZs
  
            "availability_zones": {
                "names": availability_zones,

                "count": len(
                    availability_zones
                ),
            },

              # Route tables
  
            "route_tables": {
                "route_table_ids": route_table_ids,

                "count": len(
                    route_table_ids
                ),

                "resources": endpoint_route_tables,
            },

              # Network interfaces
  
            "network_interfaces": {
                "network_interface_ids": (
                    endpoint.get(
                        "network_interface_ids",
                        [],
                    )
                ),

                "count": len(
                    endpoint.get(
                        "network_interface_ids",
                        [],
                    )
                ),
            },

              # Security groups
  
            "security_groups": {
                "security_group_ids": (
                    endpoint.get(
                        "security_group_ids",
                        [],
                    )
                ),

                "count": len(
                    endpoint.get(
                        "security_group_ids",
                        [],
                    )
                ),
            },

              # Gateway endpoint routing
  
            "gateway_endpoint": {
                "route_count": len(
                    gateway_endpoint_routes
                ),

                "routes": (
                    gateway_endpoint_routes
                ),
            },

              # Interface endpoint routing context
  
            "interface_endpoint": {
                "subnet_route_count": len(
                    interface_subnet_routes
                ),

                "subnet_routes": (
                    interface_subnet_routes
                ),
            },

              # Network dependencies
  
            "network_dependencies": {
                "nat_gateway_ids": sorted(
                    nat_gateway_ids
                ),

                "transit_gateway_ids": sorted(
                    transit_gateway_ids
                ),

                "internet_gateway_ids": sorted(
                    internet_gateway_ids
                ),

                "vpc_peering_connection_ids": (
                    sorted(
                        vpc_peering_connection_ids
                    )
                ),
            },

              # Optimization evidence
  
            "optimization_evidence": {
                "gateway_endpoint_route_count": (
                    len(
                        gateway_endpoint_routes
                    )
                ),

                "interface_endpoint_subnet_count": (
                    len(
                        subnet_ids
                    )
                ),

                "availability_zone_count": (
                    len(
                        availability_zones
                    )
                ),

                "network_interface_count": (
                    len(
                        endpoint.get(
                            "network_interface_ids",
                            [],
                        )
                    )
                ),

                "uses_nat_gateway": bool(
                    nat_gateway_ids
                ),

                "uses_transit_gateway": bool(
                    transit_gateway_ids
                ),

                "uses_internet_gateway": bool(
                    internet_gateway_ids
                ),

                "has_gateway_endpoint_routes": bool(
                    gateway_endpoint_routes
                ),

                "private_dns_enabled": (
                    endpoint.get(
                        "private_dns_enabled"
                    )
                ),
            },
        }

     # IDENTITY
 
    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return (
            resource.get(
                "resource_id"
            )
            or resource.get(
                "vpc_endpoint_id"
            )
        )

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = resource.get(
            "identity"
        )

        if identity:
            return identity

        return {
            "vpc_endpoint_id": (
                self.get_resource_id(
                    resource
                )
            ),

            "vpc_id": resource.get(
                "vpc_id"
            ),

            "service_name": resource.get(
                "service_name"
            ),

            "endpoint_type": resource.get(
                "endpoint_type"
            ),
        }

     # CONFIGURATION
 
    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = resource.get(
            "configuration"
        )

        if configuration:
            return configuration

        return {}

     # TOPOLOGY
 
    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return resource.get(
            "topology",
            {},
        )

     # RELATIONSHIPS
 
    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return resource.get(
            "relationships",
            {},
        )

     # RESOURCE
 
    def _build_resource(
        self,
        endpoint: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "resource_type": self.resource_type,

            "resource_id": endpoint.get(
                "vpc_endpoint_id"
            ),

            "region": self.region,

            "identity": {
                "vpc_endpoint_id": endpoint.get(
                    "vpc_endpoint_id"
                ),

                "vpc_id": endpoint.get(
                    "vpc_id"
                ),

                "service_name": endpoint.get(
                    "service_name"
                ),

                "endpoint_type": endpoint.get(
                    "endpoint_type"
                ),

                "category": endpoint.get(
                    "category"
                ),
            },

            "configuration": {
                "service_region": endpoint.get(
                    "service_region"
                ),

                "state": endpoint.get(
                    "state"
                ),

                "creation_timestamp": endpoint.get(
                    "creation_timestamp"
                ),

                "policy_document": endpoint.get(
                    "policy_document"
                ),

                "private_dns_enabled": endpoint.get(
                    "private_dns_enabled"
                ),

                "dns_options": endpoint.get(
                    "dns_options"
                ),

                "dns_entries": endpoint.get(
                    "dns_entries",
                    [],
                ),

                "route_table_ids": endpoint.get(
                    "route_table_ids",
                    [],
                ),

                "subnet_ids": endpoint.get(
                    "subnet_ids",
                    [],
                ),

                "network_interface_ids": endpoint.get(
                    "network_interface_ids",
                    [],
                ),

                "security_group_ids": endpoint.get(
                    "security_group_ids",
                    [],
                ),

                "owner_id": endpoint.get(
                    "owner_id"
                ),

                "requester_managed": endpoint.get(
                    "requester_managed"
                ),

                "ip_address_type": endpoint.get(
                    "ip_address_type"
                ),

                "last_error": endpoint.get(
                    "last_error"
                ),

                "failure_reason": endpoint.get(
                    "failure_reason"
                ),

                "tags": endpoint.get(
                    "tags",
                    {},
                ),

                "category": endpoint.get(
                    "category"
                ),

                "is_gateway": endpoint.get(
                    "is_gateway"
                ),

                "is_interface": endpoint.get(
                    "is_interface"
                ),

                "is_gateway_load_balancer": (
                    endpoint.get(
                        "is_gateway_load_balancer"
                    )
                ),
            },
        }

     # HELPERS
 
    @staticmethod
    def _endpoint_category(
        endpoint_type: Optional[str],
    ) -> str:

        mapping = {
            "Gateway": "gateway",

            "Interface": "interface",

            "GatewayLoadBalancer": (
                "gateway_load_balancer"
            ),
        }

        return mapping.get(
            endpoint_type,
            "unknown",
        )

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
    def _serialize_datetime(
        value: Any,
    ) -> Any:

        if value is None:
            return None

        if hasattr(
            value,
            "isoformat",
        ):
            return value.isoformat()

        return value