
"""
AWS VPC Endpoint Collector.

"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.registry import register

from collection.shared.interfaces import (
    NetworkInterfaceCollector,
)

from collection.shared.topology import (
    NetworkTopologyCollector,
)

from collection.shared.relationships import (
    NetworkRelationshipResolver,
)


@register
class VpcEndpointCollector(BaseCollector):

    key = "vpc_endpoint"
    resource_type = "vpc_endpoint"

     # INITIALIZATION
 
    def __init__(
        self,
        scan: Any,
        region: str,
        profile: Any = None,
    ) -> None:

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

        self.ec2 = get_client(
            "ec2",
            region,
        )

        self.topology_collector = (
            NetworkTopologyCollector(
                region
            )
        )

        self.interface_collector = (
            NetworkInterfaceCollector(
                region
            )
        )

     # DISCOVERY
 
    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        endpoints = (
            self._collect_all_endpoints()
        )

        resources: List[
            Dict[str, Any]
        ] = []

        for endpoint in endpoints:

            resource = (
                self._build_resource(
                    endpoint
                )
            )

            endpoint_id = endpoint.get(
                "vpc_endpoint_id"
            )

            vpc_id = endpoint.get(
                "vpc_id"
            )

            if vpc_id:

                topology = (
                    self._collect_topology(
                        vpc_id=vpc_id,
                        endpoint_id=endpoint_id,
                    )
                )

                resource[
                    "topology"
                ] = topology

                if topology.get(
                    "status"
                ) == "ok":

                    resource[
                        "relationships"
                    ] = (
                        self._build_relationships(
                            endpoint=endpoint,
                            topology=topology,
                        )
                    )

                else:

                    resource[
                        "relationships"
                    ] = {
                        "status":
                            "incomplete",

                        "reason":
                            topology.get(
                                "reason",
                                topology.get(
                                    "error",
                                    "VPC topology unavailable",
                                ),
                            ),
                    }

            else:

                resource[
                    "topology"
                ] = {
                    "status":
                        "incomplete",

                    "reason":
                        "VPC ID unavailable",
                }

                resource[
                    "relationships"
                ] = {
                    "status":
                        "incomplete",

                    "reason":
                        "VPC ID unavailable",
                }
            interface_ids = list(
                endpoint.get(
                    "network_interface_ids",
                    [],
                )
                or []
            )

            if interface_ids:

                try:

                    eni_result = (
                        self.interface_collector.collect(
                            interface_ids
                        )
                    )

                    resource[
                        "network_interfaces"
                    ] = {
                        "status":
                            "ok",

                        "resources":
                            (
                                eni_result
                                if isinstance(
                                    eni_result,
                                    list,
                                )
                                else []
                            ),

                        "requested_count":
                            len(interface_ids),

                        "observed_count":
                            (
                                len(eni_result)
                                if isinstance(
                                    eni_result,
                                    list,
                                )
                                else 0
                            ),
                    }

                except Exception as exc:

                    resource[
                        "network_interfaces"
                    ] = {
                        "status":
                            "error",

                        "resources":
                            [],

                        "requested_count":
                            len(interface_ids),

                        "observed_count":
                            0,

                        "error":
                            str(exc),
                    }

            else:

                resource[
                    "network_interfaces"
                ] = {
                    "status":
                        "ok",

                    "resources":
                        [],

                    "requested_count":
                        0,

                    "observed_count":
                        0,
                }

            resource[
                "collection_status"
            ] = (
                self._build_collection_status(
                    endpoint=endpoint,
                    resource=resource,
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

        paginator = (
            self.ec2.get_paginator(
                "describe_vpc_endpoints"
            )
        )

        result: List[
            Dict[str, Any]
        ] = []

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

                    endpoint_id = (
                        normalized.get(
                            "vpc_endpoint_id"
                        )
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

        endpoint_type = (
            endpoint.get(
                "VpcEndpointType"
            )
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
            group.get(
                "GroupId"
            )
            for group in (
                endpoint.get(
                    "Groups",
                    [],
                )
                or []
            )
            if (
                isinstance(
                    group,
                    dict,
                )
                and group.get(
                    "GroupId"
                )
            )
        ]

        return {
            "vpc_endpoint_id":
                endpoint.get(
                    "VpcEndpointId"
                ),

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

            "state":
                endpoint.get(
                    "State"
                ),

            "creation_timestamp":
                self._serialize_datetime(
                    endpoint.get(
                        "CreationTimestamp"
                    )
                ),

            "last_error":
                endpoint.get(
                    "LastError"
                ),

            "failure_reason":
                endpoint.get(
                    "FailureReason"
                ),

            "private_dns_enabled":
                endpoint.get(
                    "PrivateDnsEnabled"
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

            "route_table_ids":
                route_table_ids,

            "subnet_ids":
                subnet_ids,

            "network_interface_ids":
                network_interface_ids,

            "security_group_ids":
                security_group_ids,

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

            "tags":
                self._tags(
                    endpoint.get(
                        "Tags",
                        [],
                    )
                ),

            "category":
                self._endpoint_category(
                    endpoint_type
                ),

            "is_gateway":
                endpoint_type == "Gateway",

            "is_interface":
                endpoint_type == "Interface",

            "is_gateway_load_balancer":
                endpoint_type
                == "GatewayLoadBalancer",

            "is_resource":
                endpoint_type == "Resource",

            "is_service_network":
                endpoint_type
                == "ServiceNetwork",
        }

     # TOPOLOGY
 
    def _collect_topology(
        self,
        vpc_id: str,
        endpoint_id: Optional[str],
    ) -> Dict[str, Any]:

        try:

            topology = (
                self.topology_collector.collect(
                    vpc_id=vpc_id,
                    resource_type=self.resource_type,
                    resource_id=endpoint_id,
                )
            )

        except Exception as exc:

            return {
                "status":
                    "error",

                "error":
                    str(exc),
            }

        if not isinstance(
            topology,
            dict,
        ):

            return {
                "status":
                    "error",

                "error":
                    "Network topology collector returned "
                    "an invalid result.",
            }

        if topology.get(
            "status"
        ) != "ok":

            return {
                **topology,

                "status":
                    "incomplete",
            }

        return topology

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
                "status":
                    "incomplete",

                "reason":
                    topology.get(
                        "reason",
                        topology.get(
                            "error",
                            "VPC topology unavailable",
                        ),
                    ),
            }

        resolver = (
            NetworkRelationshipResolver(
                topology
            )
        )

        endpoint_id = (
            endpoint.get(
                "vpc_endpoint_id"
            )
        )

        endpoint_type = (
            endpoint.get(
                "endpoint_type"
            )
        )

        configured_subnet_ids = list(
            endpoint.get(
                "subnet_ids",
                [],
            )
            or []
        )

        configured_route_table_ids = list(
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

            for route_table_id in (
                configured_route_table_ids
            ):

                if not route_table_id:
                    continue

                try:

                    endpoint_subnets.extend(
                        resolver.subnets_for_route_table(
                            route_table_id
                        )
                    )

                except Exception:
                    continue

        elif endpoint_type == "Interface":

            for subnet_id in (
                configured_subnet_ids
            ):

                if not subnet_id:
                    continue

                try:

                    subnet = (
                        resolver.subnet(
                            subnet_id
                        )
                    )

                except Exception:
                    subnet = None

                if subnet:

                    endpoint_subnets.append(
                        subnet
                    )

        endpoint_subnets = (
            self._deduplicate_dicts(
                endpoint_subnets,
                key="subnet_id",
            )
        )

        endpoint_subnet_ids = sorted(
            {
                subnet.get(
                    "subnet_id"
                )
                for subnet in endpoint_subnets
                if subnet.get(
                    "subnet_id"
                )
            }
        )

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

        route_tables = topology.get(
            "route_tables",
            [],
        )

        if not isinstance(
            route_tables,
            list,
        ):
            route_tables = []

        endpoint_route_tables = [
            table
            for table in route_tables
            if (
                isinstance(
                    table,
                    dict,
                )
                and table.get(
                    "route_table_id"
                )
                in configured_route_table_ids
            )
        ]

        gateway_endpoint_routes = []

        if (
            endpoint_type == "Gateway"
            and endpoint_id
        ):

            try:

                gateway_endpoint_routes = (
                    resolver.routes_targeting(
                        target_type="gateway_endpoint",
                        target_id=endpoint_id,
                    )
                )

            except Exception:

                gateway_endpoint_routes = []

        gateway_route_table_ids = sorted(
            {
                route.get(
                    "route_table_id"
                )
                for route in gateway_endpoint_routes
                if route.get(
                    "route_table_id"
                )
            }
        )

        gateway_coverage = sorted(
            set(
                configured_route_table_ids
            )
            &
            set(
                gateway_route_table_ids
            )
        )

        interface_subnet_routes = []

        if endpoint_type == "Interface":

            for subnet_id in (
                configured_subnet_ids
            ):

                try:

                    interface_subnet_routes.extend(
                        resolver.routes_for_subnet(
                            subnet_id
                        )
                    )

                except Exception:

                    continue

        interface_subnet_routes = (
            self._deduplicate_dicts(
                interface_subnet_routes,
                key="_route_key",
            )
        )

        surrounding_routes = []

        for subnet_id in (
            endpoint_subnet_ids
        ):

            try:

                surrounding_routes.extend(
                    resolver.routes_for_subnet(
                        subnet_id
                    )
                )

            except Exception:

                continue

        surrounding_routes = (
            self._deduplicate_dicts(
                surrounding_routes,
                key="_route_key",
            )
        )

        dependencies = (
            self._dependency_ids_for_routes(
                surrounding_routes
            )
        )

        return {
            "status":
                "ok",

            "collection_status": {
    "topology":
        "ok",

    "gateway_route_context":
        "ok",
},

            "vpc": {
                "vpc_id":
                    endpoint.get(
                        "vpc_id"
                    ),
            },

            "endpoint": {
                "vpc_endpoint_id":
                    endpoint_id,

                "service_name":
                    endpoint.get(
                        "service_name"
                    ),

                "endpoint_type":
                    endpoint_type,

                "state":
                    endpoint.get(
                        "state"
                    ),
            },

            "subnets": {
                "configured_subnet_ids":
                    configured_subnet_ids,

                "effective_subnet_ids":
                    endpoint_subnet_ids,

                "count":
                    len(
                        endpoint_subnet_ids
                    ),

                "resources":
                    endpoint_subnets,
            },

            "availability_zones": {
                "names":
                    availability_zones,

                "count":
                    len(
                        availability_zones
                    ),
            },

            "route_tables": {
                "configured_route_table_ids":
                    configured_route_table_ids,

                "gateway_endpoint_route_table_ids":
                    gateway_route_table_ids,

                "gateway_endpoint_route_table_coverage":
                    gateway_coverage,

                "count":
                    len(
                        configured_route_table_ids
                    ),

                "resources":
                    endpoint_route_tables,

                "configuration_complete":
                    (
                        endpoint_type != "Gateway"
                        or not configured_route_table_ids
                        or bool(
                            endpoint_route_tables
                        )
                    ),
            },

            "network_interfaces": {
                "network_interface_ids":
                    list(
                        endpoint.get(
                            "network_interface_ids",
                            [],
                        )
                        or []
                    ),

                "count":
                    len(
                        endpoint.get(
                            "network_interface_ids",
                            [],
                        )
                        or []
                    ),
            },

            "security_groups": {
                "security_group_ids":
                    list(
                        endpoint.get(
                            "security_group_ids",
                            [],
                        )
                        or []
                    ),

                "count":
                    len(
                        endpoint.get(
                            "security_group_ids",
                            [],
                        )
                        or []
                    ),
            },

            "gateway_endpoint": {
                "route_count":
                    len(
                        gateway_endpoint_routes
                    ),

                "routes":
                    gateway_endpoint_routes,

                "route_table_ids":
                    gateway_route_table_ids,

                "configured_route_table_count":
                    len(
                        configured_route_table_ids
                    ),

                "covered_route_table_count":
                    len(
                        gateway_coverage
                    ),

                "coverage_complete":
                    (
                        (
                            not configured_route_table_ids
                        )
                        or
                        (
                            set(
                                configured_route_table_ids
                            )
                            <=
                            set(
                                gateway_route_table_ids
                            )
                        )
                    ),

                "has_expected_routes":
                    bool(
                        gateway_endpoint_routes
                    ),
            },

            "interface_endpoint": {
                "configured_subnet_count":
                    len(
                        configured_subnet_ids
                    ),

                "effective_subnet_count":
                    len(
                        endpoint_subnet_ids
                    ),

                "subnet_route_count":
                    len(
                        interface_subnet_routes
                    ),

                "subnet_routes":
                    interface_subnet_routes,
            },

            "surrounding_network": {
                "route_count":
                    len(
                        surrounding_routes
                    ),

                "routes":
                    surrounding_routes,
            },

            "network_dependencies": {
                key:
                    sorted(
                        dependencies.get(
                            key,
                            [],
                        )
                    )
                for key in (
                    "nat_gateway_ids",
                    "transit_gateway_ids",
                    "internet_gateway_ids",
                    "vpc_peering_connection_ids",
                    "network_interface_ids",
                    "instance_ids",
                    "carrier_gateway_ids",
                    "local_gateway_ids",
                    "egress_only_internet_gateway_ids",
                    "core_network_arns",
                )
            },

            "optimization_evidence": {
                "endpoint_type":
                    endpoint_type,

                "service_name":
                    endpoint.get(
                        "service_name"
                    ),

                "state":
                    endpoint.get(
                        "state"
                    ),

                "gateway_endpoint_route_count":
                    len(
                        gateway_endpoint_routes
                    ),

                "configured_route_table_count":
                    len(
                        configured_route_table_ids
                    ),

                "gateway_route_table_coverage_count":
                    len(
                        gateway_coverage
                    ),

                "effective_subnet_count":
                    len(
                        endpoint_subnet_ids
                    ),

                "availability_zone_count":
                    len(
                        availability_zones
                    ),

                "network_interface_count":
                    len(
                        endpoint.get(
                            "network_interface_ids",
                            [],
                        )
                        or []
                    ),

                "security_group_count":
                    len(
                        endpoint.get(
                            "security_group_ids",
                            [],
                        )
                        or []
                    ),

                "private_dns_enabled":
                    endpoint.get(
                        "private_dns_enabled"
                    ),

                "requester_managed":
                    endpoint.get(
                        "requester_managed"
                    ),
            },
        }

     # BASE INTERFACE
 
    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        value = (
            resource.get(
                "resource_id"
            )
            or resource.get(
                "vpc_endpoint_id"
            )
        )

        return str(
            value
            if value
            else "unknown"
        )

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        value = resource.get(
            "identity"
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        value = resource.get(
            "configuration"
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        value = resource.get(
            "topology"
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        value = resource.get(
            "relationships"
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

     # RESOURCE
 
    def _build_resource(
        self,
        endpoint: Dict[str, Any],
    ) -> Dict[str, Any]:

        endpoint_type = (
            endpoint.get(
                "endpoint_type"
            )
        )

        return {
            "resource_type":
                self.resource_type,

            "resource_id":
                endpoint.get(
                    "vpc_endpoint_id"
                ),

            "region":
                self.region,

            "identity": {
                "vpc_endpoint_id":
                    endpoint.get(
                        "vpc_endpoint_id"
                    ),

                "vpc_id":
                    endpoint.get(
                        "vpc_id"
                    ),

                "service_name":
                    endpoint.get(
                        "service_name"
                    ),

                "endpoint_type":
                    endpoint_type,

                "category":
                    endpoint.get(
                        "category"
                    ),
            },

            "configuration": {
                "service_name":
                    endpoint.get(
                        "service_name"
                    ),

                "service_region":
                    endpoint.get(
                        "service_region"
                    ),

                "endpoint_type":
                    endpoint_type,

                "state":
                    endpoint.get(
                        "state"
                    ),

                "creation_timestamp":
                    endpoint.get(
                        "creation_timestamp"
                    ),

                "policy_document":
                    endpoint.get(
                        "policy_document"
                    ),

                "private_dns_enabled":
                    endpoint.get(
                        "private_dns_enabled"
                    ),

                "dns_options":
                    endpoint.get(
                        "dns_options"
                    ),

                "dns_entries":
                    endpoint.get(
                        "dns_entries",
                        [],
                    ),

                "route_table_ids":
                    endpoint.get(
                        "route_table_ids",
                        [],
                    ),

                "subnet_ids":
                    endpoint.get(
                        "subnet_ids",
                        [],
                    ),

                "network_interface_ids":
                    endpoint.get(
                        "network_interface_ids",
                        [],
                    ),

                "security_group_ids":
                    endpoint.get(
                        "security_group_ids",
                        [],
                    ),

                "owner_id":
                    endpoint.get(
                        "owner_id"
                    ),

                "requester_managed":
                    endpoint.get(
                        "requester_managed"
                    ),

                "ip_address_type":
                    endpoint.get(
                        "ip_address_type"
                    ),

                "last_error":
                    endpoint.get(
                        "last_error"
                    ),

                "failure_reason":
                    endpoint.get(
                        "failure_reason"
                    ),

                "tags":
                    endpoint.get(
                        "tags",
                        {},
                    ),
            },
        }
    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._as_dict(
            collected_resource.get(
                "identity"
            )
        )

        configuration = self._as_dict(
            collected_resource.get(
                "configuration"
            )
        )

        topology = self._as_dict(
            collected_resource.get(
                "topology"
            )
        )

        relationships = self._as_dict(
            collected_resource.get(
                "relationships"
            )
        )

        network_interfaces_raw = (
            collected_resource.get(
                "network_interfaces"
            )
        )

        if isinstance(
            network_interfaces_raw,
            dict,
        ):

            network_interfaces = (
                network_interfaces_raw
            )

        elif isinstance(
            network_interfaces_raw,
            list,
        ):

            network_interfaces = {
                "status":
                    "ok",

                "resources":
                    network_interfaces_raw,

                "requested_count":
                    len(
                        configuration.get(
                            "network_interface_ids",
                            [],
                        )
                        or []
                    ),

                "observed_count":
                    len(
                        network_interfaces_raw
                    ),

                "count":
                    len(
                        network_interfaces_raw
                    ),
            }

        else:

            network_interfaces = {
                "status":
                    "missing",

                "resources":
                    [],

                "requested_count":
                    0,

                "observed_count":
                    0,

                "count":
                    0,
            }

        endpoint_subnets = self._as_dict(
            topology.get(
                "subnets"
            )
        )

        availability_zones = self._as_dict(
            topology.get(
                "availability_zones"
            )
        )

        gateway_endpoint = self._as_dict(
            topology.get(
                "gateway_endpoint"
            )
        )

        interface_endpoint = self._as_dict(
            topology.get(
                "interface_endpoint"
            )
        )

        network_dependencies = self._as_dict(
            topology.get(
                "network_dependencies"
            )
        )

        collection_status = self._as_dict(
            topology.get(
                "collection_status"
            )
        )
        endpoint_type = (
            identity.get(
                "endpoint_type"
            )
            or configuration.get(
                "endpoint_type"
            )
        )

        service_name = (
            identity.get(
                "service_name"
            )
            or configuration.get(
                "service_name"
            )
        )

        state = configuration.get(
            "state"
        )

        configured_route_tables = self._as_list(
            topology
            .get(
                "route_tables",
                {},
            )
            if isinstance(
                topology.get(
                    "route_tables"
                ),
                dict,
            )
            else []
        )
        topology_available = (
            topology.get(
                "status"
            )
            == "ok"
        )

        relationship_available = (
            relationships.get(
                "status"
            )
            == "ok"
        )

        network_interfaces_available = (
            network_interfaces.get(
                "status"
            )
            in {
                "ok",
                "partial",
            }
        )

        return {
            "resource": {
                "resource_id":
                    resource.get(
                        "resource_id"
                    ),

                "resource_type":
                    self.resource_type,

                "service_name":
                    service_name,

                "endpoint_type":
                    endpoint_type,

                "state":
                    state,
            },

            "network": {
                "effective_subnet_count":
                    self._safe_int(
                        endpoint_subnets.get(
                            "count"
                        )
                    ),

                "availability_zone_count":
                    self._safe_int(
                        availability_zones.get(
                            "count"
                        )
                    ),

                "network_interface_count":
                    self._safe_int(
                        network_interfaces.get(
                            "observed_count",
                            network_interfaces.get(
                                "count"
                            )
                        )
                    ),

                "configured_route_table_count":
                    self._safe_int(
                        gateway_endpoint.get(
                            "configured_route_table_count"
                        )
                    ),

                "covered_route_table_count":
                    self._safe_int(
                        gateway_endpoint.get(
                            "covered_route_table_count"
                        )
                    ),

                "gateway_endpoint_route_count":
                    self._safe_int(
                        gateway_endpoint.get(
                            "route_count"
                        )
                    ),

                "interface_configured_subnet_count":
                    self._safe_int(
                        interface_endpoint.get(
                            "configured_subnet_count"
                        )
                    ),

                "interface_effective_subnet_count":
                    self._safe_int(
                        interface_endpoint.get(
                            "effective_subnet_count"
                        )
                    ),
            },

            "configuration": {
                "private_dns_enabled":
                    configuration.get(
                        "private_dns_enabled"
                    ),

                "requester_managed":
                    configuration.get(
                        "requester_managed"
                    ),

                "state":
                    state,

                "endpoint_type":
                    endpoint_type,
            },

            "dependencies":
                network_dependencies,

            "network_interfaces":
                network_interfaces,

            "route_context": {
                "configured_route_table_count":
                    self._safe_int(
                        gateway_endpoint.get(
                            "configured_route_table_count"
                        )
                    ),

                "covered_route_table_count":
                    self._safe_int(
                        gateway_endpoint.get(
                            "covered_route_table_count"
                        )
                    ),

                "gateway_endpoint_route_count":
                    self._safe_int(
                        gateway_endpoint.get(
                            "route_count"
                        )
                    ),

                "interface_subnet_route_count":
                    self._safe_int(
                        interface_endpoint.get(
                            "subnet_route_count"
                        )
                    ),
            },

            "data_quality": {
                "topology_available":
                    topology_available,

                "relationship_data_available":
                    relationship_available,

                "network_interfaces_available":
                    network_interfaces_available,

                "network_context_available":
                    bool(
                        relationships
                    ),

                "configuration_available":
                    bool(
                        configuration
                    ),

                "identity_available":
                    bool(
                        identity
                    ),

                "collection_status":
                    collection_status,
            },
        }

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int:

        if isinstance(
            value,
            bool,
        ):
            return int(value)

        try:
            return int(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

     # COLLECTION STATUS
 
    @staticmethod
    def _build_collection_status(
        endpoint: Dict[str, Any],
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        topology = resource.get(
            "topology",
            {},
        )

        relationships = resource.get(
            "relationships",
            {},
        )

        network_interfaces = resource.get(
            "network_interfaces",
            {},
        )

        endpoint_type = endpoint.get(
            "endpoint_type"
        )

        topology_ok = (
            isinstance(
                topology,
                dict,
            )
            and
            topology.get(
                "status"
            ) == "ok"
        )

        relationships_ok = (
            isinstance(
                relationships,
                dict,
            )
            and
            relationships.get(
                "status"
            ) == "ok"
        )

        eni_ok = (
            isinstance(
                network_interfaces,
                dict,
            )
            and
            network_interfaces.get(
                "status"
            ) == "ok"
        )

        requested_eni_count = len(
            endpoint.get(
                "network_interface_ids",
                [],
            )
            or []
        )

        observed_eni_count = (
            network_interfaces.get(
                "observed_count",
                0,
            )
            if isinstance(
                network_interfaces,
                dict,
            )
            else 0
        )

        eni_complete = (
            requested_eni_count == 0
            or (
                eni_ok
                and
                observed_eni_count
                == requested_eni_count
            )
        )

        gateway_route_context_complete = (
            endpoint_type != "Gateway"
            or (
                topology_ok
                and relationships_ok
                and isinstance(
                    topology.get(
                        "gateway_endpoint"
                    ),
                    dict,
                )
            )
        )

        return {
            "endpoint":
                "ok",

            "topology":
                "ok"
                if topology_ok
                else "incomplete",

            "relationships":
                "ok"
                if relationships_ok
                else "incomplete",

            "network_interfaces":
                "ok"
                if eni_complete
                else (
                    "error"
                    if (
                        isinstance(
                            network_interfaces,
                            dict,
                        )
                        and
                        network_interfaces.get(
                            "status"
                        ) == "error"
                    )
                    else "incomplete"
                ),

            "gateway_route_context":
                "ok"
                if gateway_route_context_complete
                else "incomplete",

            "complete_for_analysis":
                (
                    topology_ok
                    and relationships_ok
                    and eni_complete
                    and gateway_route_context_complete
                ),
        }

     # HELPERS
 
    @staticmethod
    def _dependency_ids_for_routes(
        routes: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:

        fields = {
            "nat_gateway_ids":
                "nat_gateway_id",

            "transit_gateway_ids":
                "transit_gateway_id",

            "internet_gateway_ids":
                "gateway_id",

            "vpc_peering_connection_ids":
                "vpc_peering_connection_id",

            "network_interface_ids":
                "network_interface_id",

            "instance_ids":
                "instance_id",

            "carrier_gateway_ids":
                "carrier_gateway_id",

            "local_gateway_ids":
                "local_gateway_id",

            "egress_only_internet_gateway_ids":
                "egress_only_internet_gateway_id",

            "core_network_arns":
                "core_network_arn",
        }

        collected = {
            key: set()
            for key in fields
        }

        for route in routes:

            if not isinstance(
                route,
                dict,
            ):
                continue

            for result_key, field in (
                fields.items()
            ):

                value = route.get(
                    field
                )

                if not value:
                    continue

                if (
                    result_key
                    == "internet_gateway_ids"
                    and not str(
                        value
                    ).startswith(
                        "igw-"
                    )
                ):
                    continue

                collected[
                    result_key
                ].add(
                    str(value)
                )

        return {
            key:
                sorted(
                    values
                )
            for key, values in collected.items()
            if values
        }

    @staticmethod
    def _deduplicate_dicts(
        values: List[Dict[str, Any]],
        key: str,
    ) -> List[Dict[str, Any]]:

        result = []
        seen = set()

        for value in values:

            if not isinstance(
                value,
                dict,
            ):
                continue

            if key == "_route_key":

                identity = repr(
                    sorted(
                        value.items(),
                        key=lambda item:
                        str(item[0]),
                    )
                )

            else:

                raw_key = value.get(
                    key
                )

                identity = (
                    str(raw_key)
                    if raw_key is not None
                    else repr(value)
                )

            if identity in seen:
                continue

            seen.add(
                identity
            )

            result.append(
                value
            )

        return result

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
    def _as_dict(
        value: Any,
    ) -> Dict[str, Any]:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _as_list(
        value: Any,
    ) -> List[Any]:

        return (
            value
            if isinstance(
                value,
                list,
            )
            else []
        )

    @staticmethod
    def _tags(
        tags: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        return {
            tag["Key"]:
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