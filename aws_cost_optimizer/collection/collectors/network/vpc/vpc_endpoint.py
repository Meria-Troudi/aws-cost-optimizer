"""
AWS VPC Endpoint collector.

Purpose
-------
Collect only evidence required to analyze VPC endpoints for:

    - endpoint operational state
    - gateway endpoint route coverage
    - gateway endpoint route-state consistency
    - interface endpoint ENI inventory consistency
    - interface endpoint subnet/AZ placement
    - network topology required to validate those conditions

The collector does NOT:

    - calculate cost
    - estimate savings
    - make optimization decisions
    - recommend endpoint deletion
    - recommend changing endpoint type

Cost analysis requires billing and usage evidence elsewhere.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

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

    # ------------------------------------------------------------------
    # INITIALIZATION
    # ------------------------------------------------------------------

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

        if not region or not str(region).strip():
            raise ValueError("VPC Endpoint collector requires a region.")

        self.region = str(region).strip()

        self.profile = profile if isinstance(profile, dict) else {}

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self.topology_collector = NetworkTopologyCollector(self.region)

        self.interface_collector = NetworkInterfaceCollector(self.region)

    # ------------------------------------------------------------------
    # DISCOVERY
    # ------------------------------------------------------------------

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        endpoints = self._collect_all_endpoints()

        resources: List[Dict[str, Any]] = []

        for endpoint in endpoints:

            resource = self._build_resource(endpoint)

            endpoint_id = endpoint.get("vpc_endpoint_id")

            vpc_id = endpoint.get("vpc_id")

            # ----------------------------------------------------------
            # Topology
            # ----------------------------------------------------------

            if vpc_id:

                topology = self._collect_topology(
                    vpc_id=str(vpc_id),
                    endpoint_id=endpoint_id,
                )

                resource["topology"] = topology

            else:

                resource["topology"] = {
                    "status": "incomplete",
                    "reason": ("VPC ID unavailable"),
                }

            # ----------------------------------------------------------
            # Relationships
            # ----------------------------------------------------------

            topology = resource.get(
                "topology",
                {},
            )

            if isinstance(topology, dict) and topology.get("status") == "ok":

                resource["relationships"] = self._build_relationships(
                    endpoint=endpoint,
                    topology=topology,
                )

            else:

                resource["relationships"] = {
                    "status": "incomplete",
                    "reason": (
                        topology.get(
                            "reason",
                            topology.get(
                                "error",
                                "VPC topology unavailable",
                            ),
                        )
                        if isinstance(
                            topology,
                            dict,
                        )
                        else ("VPC topology unavailable")
                    ),
                }

            # ----------------------------------------------------------
            # Interface endpoint ENIs
            # ----------------------------------------------------------

            self._collect_network_interfaces(
                endpoint=endpoint,
                resource=resource,
            )

            # ----------------------------------------------------------
            # Collection status
            # ----------------------------------------------------------

            resource["collection_status"] = self._build_collection_status(
                endpoint=endpoint,
                resource=resource,
            )

            resources.append(resource)

        return resources

    # ------------------------------------------------------------------
    # AWS COLLECTION
    # ------------------------------------------------------------------

    def _collect_all_endpoints(
        self,
    ) -> List[Dict[str, Any]]:

        paginator = self.ec2.get_paginator("describe_vpc_endpoints")

        result: List[Dict[str, Any]] = []

        try:

            for page in paginator.paginate():

                endpoints = page.get(
                    "VpcEndpoints",
                    [],
                )

                if not isinstance(
                    endpoints,
                    list,
                ):
                    continue

                for endpoint in endpoints:

                    if not isinstance(
                        endpoint,
                        dict,
                    ):
                        continue

                    normalized = self._normalize_endpoint(endpoint)

                    if normalized.get("vpc_endpoint_id"):
                        result.append(normalized)

        except Exception as exc:

            raise RuntimeError(
                f"Failed to collect VPC endpoints " f"in {self.region}: {exc}"
            ) from exc

        return result

    # ------------------------------------------------------------------
    # NORMALIZATION
    # ------------------------------------------------------------------

    def _normalize_endpoint(
        self,
        endpoint: Dict[str, Any],
    ) -> Dict[str, Any]:

        endpoint_type = endpoint.get("VpcEndpointType")

        route_table_ids = self._string_list(
            endpoint.get(
                "RouteTableIds",
                [],
            )
        )

        subnet_ids = self._string_list(
            endpoint.get(
                "SubnetIds",
                [],
            )
        )

        network_interface_ids = self._string_list(
            endpoint.get(
                "NetworkInterfaceIds",
                [],
            )
        )

        security_group_ids = self._string_list(
            [
                group.get("GroupId")
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
                    and group.get("GroupId")
                )
            ]
        )

        return {
            "vpc_endpoint_id": endpoint.get("VpcEndpointId"),
            "vpc_id": endpoint.get("VpcId"),
            "service_name": endpoint.get("ServiceName"),
            "service_region": endpoint.get("ServiceRegion"),
            "endpoint_type": endpoint_type,
            "state": endpoint.get("State"),
            "creation_timestamp": (
                self._serialize_datetime(endpoint.get("CreationTimestamp"))
            ),
            "last_error": endpoint.get("LastError"),
            "failure_reason": endpoint.get("FailureReason"),
            "private_dns_enabled": endpoint.get("PrivateDnsEnabled"),
            "route_table_ids": (route_table_ids),
            "subnet_ids": subnet_ids,
            "network_interface_ids": (network_interface_ids),
            "security_group_ids": (security_group_ids),
            "requester_managed": endpoint.get("RequesterManaged"),
            "ip_address_type": endpoint.get("IpAddressType"),
            "category": (self._endpoint_category(endpoint_type)),
            "is_gateway": (endpoint_type == "Gateway"),
            "is_interface": (endpoint_type == "Interface"),
        }

    # ------------------------------------------------------------------
    # TOPOLOGY
    # ------------------------------------------------------------------

    def _collect_topology(
        self,
        vpc_id: str,
        endpoint_id: Optional[str],
    ) -> Dict[str, Any]:

        try:

            topology = self.topology_collector.collect(
                vpc_id=vpc_id,
                resource_type=self.resource_type,
                resource_id=endpoint_id,
            )

        except Exception as exc:

            return {
                "status": "error",
                "error": str(exc),
            }

        if not isinstance(
            topology,
            dict,
        ):

            return {
                "status": "error",
                "error": ("Network topology collector returned " "an invalid result."),
            }

        if topology.get("status") != "ok":

            return {
                **topology,
                "status": "incomplete",
            }

        return topology

    # ------------------------------------------------------------------
    # NETWORK INTERFACES
    # ------------------------------------------------------------------

    def _collect_network_interfaces(
        self,
        endpoint: Dict[str, Any],
        resource: Dict[str, Any],
    ) -> None:

        interface_ids = self._string_list(
            endpoint.get(
                "network_interface_ids",
                [],
            )
        )

        if not interface_ids:

            resource["network_interfaces"] = {
                "status": "ok",
                "resources": [],
                "requested_count": 0,
                "observed_count": 0,
                "missing_ids": [],
                "unexpected_ids": [],
                "subnet_mismatches": [],
                "availability_zone_mismatches": [],
            }

            return

        try:

            result = self.interface_collector.collect(interface_ids)

        except Exception as exc:

            resource["network_interfaces"] = {
                "status": "error",
                "resources": [],
                "requested_count": len(interface_ids),
                "observed_count": 0,
                "missing_ids": (interface_ids),
                "unexpected_ids": [],
                "subnet_mismatches": [],
                "availability_zone_mismatches": [],
                "error": str(exc),
            }

            return

        # CRITICAL FIX:
        # NetworkInterfaceCollector returns a dictionary,
        # not a list.

        if not isinstance(
            result,
            dict,
        ):

            resource["network_interfaces"] = {
                "status": "error",
                "resources": [],
                "requested_count": len(interface_ids),
                "observed_count": 0,
                "missing_ids": interface_ids,
                "unexpected_ids": [],
                "subnet_mismatches": [],
                "availability_zone_mismatches": [],
                "error": ("NetworkInterfaceCollector returned " "an invalid result."),
            }

            return

        resources = result.get(
            "interfaces",
            [],
        )

        resources = (
            resources
            if isinstance(
                resources,
                list,
            )
            else []
        )

        observed_ids = {
            str(interface.get("network_interface_id"))
            for interface in resources
            if (
                isinstance(
                    interface,
                    dict,
                )
                and interface.get("network_interface_id")
            )
        }

        requested_ids = set(interface_ids)

        missing_ids = sorted(requested_ids - observed_ids)

        unexpected_ids = sorted(observed_ids - requested_ids)

        resource["network_interfaces"] = {
            "status": (
                result.get("status")
                if result.get("status")
                in {
                    "ok",
                    "partial",
                    "error",
                    "empty",
                }
                else "error"
            ),
            "resources": resources,
            "requested_count": len(interface_ids),
            "observed_count": len(resources),
            "missing_ids": missing_ids,
            "unexpected_ids": (unexpected_ids),
            "subnet_mismatches": [],
            "availability_zone_mismatches": [],
            "collector_status": result.get("status"),
            "collector_errors": (
                result.get(
                    "errors",
                    [],
                )
                if isinstance(
                    result.get(
                        "errors",
                        [],
                    ),
                    list,
                )
                else []
            ),
        }

    # ------------------------------------------------------------------
    # RELATIONSHIPS
    # ------------------------------------------------------------------

    def _build_relationships(
        self,
        endpoint: Dict[str, Any],
        topology: Dict[str, Any],
    ) -> Dict[str, Any]:

        if topology.get("status") != "ok":

            return {
                "status": "incomplete",
                "reason": (
                    topology.get(
                        "reason",
                        topology.get(
                            "error",
                            "VPC topology unavailable",
                        ),
                    )
                ),
            }

        resolver = NetworkRelationshipResolver(topology)

        endpoint_id = endpoint.get("vpc_endpoint_id")

        endpoint_type = endpoint.get("endpoint_type")

        configured_subnet_ids = self._string_list(
            endpoint.get(
                "subnet_ids",
                [],
            )
        )

        configured_route_table_ids = self._string_list(
            endpoint.get(
                "route_table_ids",
                [],
            )
        )

        topology_mappings = topology.get(
            "effective_route_table_mappings",
            [],
        )

        topology_mappings = (
            topology_mappings
            if isinstance(
                topology_mappings,
                list,
            )
            else []
        )

        # --------------------------------------------------------------
        # EFFECTIVE SUBNET -> ROUTE TABLE MAPPING
        # --------------------------------------------------------------

        effective_subnet_to_route_table: Dict[
            str,
            Dict[str, Any],
        ] = {}

        for mapping in topology_mappings:

            if not isinstance(
                mapping,
                dict,
            ):
                continue

            subnet_id = mapping.get("subnet_id")

            route_table_id = mapping.get("route_table_id")

            if not subnet_id or not route_table_id:
                continue

            effective_subnet_to_route_table[str(subnet_id)] = {
                "subnet_id": str(subnet_id),
                "route_table_id": str(route_table_id),
                "source": mapping.get("source"),
            }

        # --------------------------------------------------------------
        # ENDPOINT SUBNETS
        # --------------------------------------------------------------

        endpoint_subnets: List[Dict[str, Any]] = []

        if endpoint_type == "Gateway":

            # Gateway endpoints are associated with route tables.
            effective_subnet_ids = {
                subnet_id
                for subnet_id, mapping in effective_subnet_to_route_table.items()
                if (mapping.get("route_table_id") in set(configured_route_table_ids))
            }

            for subnet_id in sorted(effective_subnet_ids):

                subnet = resolver.subnet(subnet_id)

                if subnet:
                    endpoint_subnets.append(subnet)

        elif endpoint_type == "Interface":

            for subnet_id in configured_subnet_ids:

                subnet = resolver.subnet(subnet_id)

                if subnet:
                    endpoint_subnets.append(subnet)

        endpoint_subnets = self._deduplicate_dicts(
            endpoint_subnets,
            key="subnet_id",
        )

        endpoint_subnet_ids = sorted(
            {
                str(subnet.get("subnet_id"))
                for subnet in endpoint_subnets
                if subnet.get("subnet_id")
            }
        )

        availability_zones = sorted(
            {
                str(subnet.get("availability_zone"))
                for subnet in endpoint_subnets
                if subnet.get("availability_zone")
            }
        )

        # --------------------------------------------------------------
        # ROUTE TABLE RESOURCES
        # --------------------------------------------------------------

        raw_route_tables = topology.get(
            "route_tables",
            [],
        )

        raw_route_tables = (
            raw_route_tables
            if isinstance(
                raw_route_tables,
                list,
            )
            else []
        )

        configured_route_table_resources = [
            table
            for table in raw_route_tables
            if (
                isinstance(
                    table,
                    dict,
                )
                and table.get("route_table_id") in configured_route_table_ids
            )
        ]

        configured_route_table_resource_ids = {
            str(table.get("route_table_id"))
            for table in configured_route_table_resources
            if table.get("route_table_id")
        }

        missing_route_table_ids = sorted(
            set(configured_route_table_ids) - configured_route_table_resource_ids
        )

        # --------------------------------------------------------------
        # GATEWAY ENDPOINT ROUTES
        # --------------------------------------------------------------

        gateway_endpoint_routes: List[Dict[str, Any]] = []

        if endpoint_type == "Gateway" and endpoint_id:

            gateway_endpoint_routes = resolver.routes_targeting(
                target_type=("gateway_endpoint"),
                target_id=str(endpoint_id),
            )

            if not isinstance(
                gateway_endpoint_routes,
                list,
            ):
                gateway_endpoint_routes = []

        active_gateway_routes = [
            route
            for route in gateway_endpoint_routes
            if (
                isinstance(
                    route,
                    dict,
                )
                and route.get("state") != "blackhole"
            )
        ]

        blackhole_gateway_routes = [
            route
            for route in gateway_endpoint_routes
            if (
                isinstance(
                    route,
                    dict,
                )
                and route.get("state") == "blackhole"
            )
        ]

        gateway_route_table_ids = sorted(
            {
                str(route.get("route_table_id"))
                for route in active_gateway_routes
                if route.get("route_table_id")
            }
        )

        blackhole_gateway_route_table_ids = sorted(
            {
                str(route.get("route_table_id"))
                for route in blackhole_gateway_routes
                if route.get("route_table_id")
            }
        )

        gateway_coverage = sorted(
            set(configured_route_table_ids) & set(gateway_route_table_ids)
        )

        uncovered_route_table_ids = sorted(
            set(configured_route_table_ids) - set(gateway_route_table_ids)
        )

        gateway_route_table_context_complete = endpoint_type != "Gateway" or (
            topology.get("status") == "ok"
            and (not configured_route_table_ids or not missing_route_table_ids)
        )

        gateway_route_coverage_complete = endpoint_type != "Gateway" or (
            gateway_route_table_context_complete
            and (set(configured_route_table_ids) <= set(gateway_route_table_ids))
        )

        # --------------------------------------------------------------
        # INTERFACE ENDPOINT ROUTE CONTEXT
        # --------------------------------------------------------------

        interface_subnet_routes: List[Dict[str, Any]] = []

        if endpoint_type == "Interface":

            for subnet_id in configured_subnet_ids:

                try:

                    interface_subnet_routes.extend(
                        resolver.routes_for_subnet(subnet_id)
                    )

                except Exception:
                    continue

        interface_subnet_routes = self._deduplicate_dicts(
            interface_subnet_routes,
            key="_route_key",
        )

        return {
            "status": "ok",
            "collection_status": {
                "topology": "ok",
                "gateway_route_context": (
                    "ok" if (gateway_route_table_context_complete) else "incomplete"
                ),
                "gateway_route_coverage": (
                    "ok" if (gateway_route_coverage_complete) else "incomplete"
                ),
                "interface_subnet_context": (
                    "ok" if endpoint_type == "Interface" else "not_required"
                ),
            },
            "vpc": {
                "vpc_id": endpoint.get("vpc_id"),
            },
            "endpoint": {
                "vpc_endpoint_id": endpoint_id,
                "service_name": endpoint.get("service_name"),
                "endpoint_type": endpoint_type,
                "state": endpoint.get("state"),
            },
            "subnets": {
                "configured_subnet_ids": (configured_subnet_ids),
                "effective_subnet_ids": (endpoint_subnet_ids),
                "count": len(endpoint_subnet_ids),
                "resources": (endpoint_subnets),
                "availability_zones": (availability_zones),
            },
            "availability_zones": {
                "names": (availability_zones),
                "count": len(availability_zones),
            },
            "route_tables": {
                "configured_route_table_ids": (configured_route_table_ids),
                "gateway_endpoint_route_table_ids": (gateway_route_table_ids),
                "gateway_endpoint_blackhole_route_table_ids": (
                    blackhole_gateway_route_table_ids
                ),
                "gateway_endpoint_route_table_coverage": (gateway_coverage),
                "uncovered_route_table_ids": (uncovered_route_table_ids),
                "missing_route_table_ids": (missing_route_table_ids),
                "count": len(configured_route_table_ids),
                "resources": (configured_route_table_resources),
                "configuration_complete": (not missing_route_table_ids),
            },
            "network_interfaces": {
                "network_interface_ids": (
                    self._string_list(
                        endpoint.get(
                            "network_interface_ids",
                            [],
                        )
                    )
                ),
                "count": len(
                    self._string_list(
                        endpoint.get(
                            "network_interface_ids",
                            [],
                        )
                    )
                ),
            },
            "security_groups": {
                "security_group_ids": (
                    self._string_list(
                        endpoint.get(
                            "security_group_ids",
                            [],
                        )
                    )
                ),
                "count": len(
                    self._string_list(
                        endpoint.get(
                            "security_group_ids",
                            [],
                        )
                    )
                ),
            },
            "gateway_endpoint": {
                "route_count": len(gateway_endpoint_routes),
                "active_route_count": len(active_gateway_routes),
                "blackhole_route_count": len(blackhole_gateway_routes),
                "routes": (gateway_endpoint_routes),
                "active_routes": (active_gateway_routes),
                "blackhole_routes": (blackhole_gateway_routes),
                "route_table_ids": (gateway_route_table_ids),
                "blackhole_route_table_ids": (blackhole_gateway_route_table_ids),
                "configured_route_table_count": (len(configured_route_table_ids)),
                "covered_route_table_count": (len(gateway_coverage)),
                "uncovered_route_table_count": (len(uncovered_route_table_ids)),
                "coverage_complete": (gateway_route_coverage_complete),
                "has_expected_routes": bool(gateway_endpoint_routes),
                "has_active_routes": bool(active_gateway_routes),
                "has_blackhole_routes": bool(blackhole_gateway_routes),
            },
            "interface_endpoint": {
                "configured_subnet_count": (len(configured_subnet_ids)),
                "effective_subnet_count": (len(endpoint_subnet_ids)),
                "subnet_route_count": (len(interface_subnet_routes)),
                "subnet_routes": (interface_subnet_routes),
            },
        }

    # ------------------------------------------------------------------
    # BASE INTERFACE
    # ------------------------------------------------------------------

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        value = resource.get("resource_id") or resource.get("vpc_endpoint_id")

        return str(value if value else "unknown")

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        value = resource.get("identity")

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

        value = resource.get("configuration")

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

        value = resource.get("topology")

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

        value = resource.get("relationships")

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    # ------------------------------------------------------------------
    # RESOURCE
    # ------------------------------------------------------------------

    def _build_resource(
        self,
        endpoint: Dict[str, Any],
    ) -> Dict[str, Any]:

        endpoint_type = endpoint.get("endpoint_type")

        return {
            "resource_type": (self.resource_type),
            "resource_id": endpoint.get("vpc_endpoint_id"),
            "region": self.region,
            "identity": {
                "vpc_endpoint_id": endpoint.get("vpc_endpoint_id"),
                "vpc_id": endpoint.get("vpc_id"),
                "service_name": endpoint.get("service_name"),
                "service_region": endpoint.get("service_region"),
                "endpoint_type": (endpoint_type),
                "category": endpoint.get("category"),
                "state": endpoint.get("state"),
                "requester_managed": endpoint.get("requester_managed"),
            },
            "configuration": {
                "service_name": endpoint.get("service_name"),
                "service_region": endpoint.get("service_region"),
                "endpoint_type": endpoint_type,
                "state": endpoint.get("state"),
                "creation_timestamp": endpoint.get("creation_timestamp"),
                "private_dns_enabled": endpoint.get("private_dns_enabled"),
                "route_table_ids": (
                    endpoint.get(
                        "route_table_ids",
                        [],
                    )
                ),
                "subnet_ids": (
                    endpoint.get(
                        "subnet_ids",
                        [],
                    )
                ),
                "network_interface_ids": (
                    endpoint.get(
                        "network_interface_ids",
                        [],
                    )
                ),
                "security_group_ids": (
                    endpoint.get(
                        "security_group_ids",
                        [],
                    )
                ),
                "requester_managed": endpoint.get("requester_managed"),
                "ip_address_type": endpoint.get("ip_address_type"),
                "last_error": endpoint.get("last_error"),
                "failure_reason": endpoint.get("failure_reason"),
            },
        }

    # ------------------------------------------------------------------
    # OPTIMIZATION EVIDENCE
    # ------------------------------------------------------------------

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._as_dict(collected_resource.get("identity"))

        configuration = self._as_dict(collected_resource.get("configuration"))

        topology = self._as_dict(collected_resource.get("topology"))

        relationships = self._as_dict(collected_resource.get("relationships"))

        network_interfaces = self._as_dict(collected_resource.get("network_interfaces"))

        collection_status = self._as_dict(collected_resource.get("collection_status"))

        endpoint_type = identity.get("endpoint_type") or configuration.get(
            "endpoint_type"
        )

        service_name = identity.get("service_name") or configuration.get("service_name")

        state = configuration.get("state")

        route_tables = self._as_dict(topology.get("route_tables"))

        gateway_endpoint = self._as_dict(topology.get("gateway_endpoint"))

        interface_endpoint = self._as_dict(topology.get("interface_endpoint"))

        subnets = self._as_dict(topology.get("subnets"))

        availability_zones = self._as_dict(topology.get("availability_zones"))

        return {
            "resource": {
                "resource_id": resource.get("resource_id"),
                "resource_type": (self.resource_type),
                "service_name": service_name,
                "endpoint_type": (endpoint_type),
                "state": state,
            },
            "configuration": {
                "service_name": service_name,
                "endpoint_type": (endpoint_type),
                "state": state,
                "private_dns_enabled": (configuration.get("private_dns_enabled")),
                "requester_managed": (configuration.get("requester_managed")),
                "route_table_ids": (
                    self._string_list(configuration.get("route_table_ids"))
                ),
                "subnet_ids": (self._string_list(configuration.get("subnet_ids"))),
                "network_interface_ids": (
                    self._string_list(configuration.get("network_interface_ids"))
                ),
            },
            "network": {
                "effective_subnet_count": (self._safe_int(subnets.get("count"))),
                "availability_zone_count": (
                    self._safe_int(availability_zones.get("count"))
                ),
                "network_interface_count": (
                    self._safe_int(network_interfaces.get("observed_count"))
                ),
                "configured_route_table_count": (
                    self._safe_int(gateway_endpoint.get("configured_route_table_count"))
                ),
                "covered_route_table_count": (
                    self._safe_int(gateway_endpoint.get("covered_route_table_count"))
                ),
                "uncovered_route_table_count": (
                    self._safe_int(gateway_endpoint.get("uncovered_route_table_count"))
                ),
                "gateway_endpoint_route_count": (
                    self._safe_int(gateway_endpoint.get("route_count"))
                ),
                "gateway_endpoint_active_route_count": (
                    self._safe_int(gateway_endpoint.get("active_route_count"))
                ),
                "gateway_endpoint_blackhole_route_count": (
                    self._safe_int(gateway_endpoint.get("blackhole_route_count"))
                ),
                "interface_configured_subnet_count": (
                    self._safe_int(interface_endpoint.get("configured_subnet_count"))
                ),
                "interface_effective_subnet_count": (
                    self._safe_int(interface_endpoint.get("effective_subnet_count"))
                ),
                "interface_subnet_route_count": (
                    self._safe_int(interface_endpoint.get("subnet_route_count"))
                ),
            },
            "route_context": {
                "configured_route_table_ids": (
                    self._string_list(route_tables.get("configured_route_table_ids"))
                ),
                "covered_route_table_ids": (
                    self._string_list(
                        route_tables.get("gateway_endpoint_route_table_coverage")
                    )
                ),
                "uncovered_route_table_ids": (
                    self._string_list(route_tables.get("uncovered_route_table_ids"))
                ),
                "blackhole_route_table_ids": (
                    self._string_list(
                        route_tables.get("gateway_endpoint_blackhole_route_table_ids")
                    )
                ),
                "configured_route_table_count": (
                    self._safe_int(gateway_endpoint.get("configured_route_table_count"))
                ),
                "covered_route_table_count": (
                    self._safe_int(gateway_endpoint.get("covered_route_table_count"))
                ),
                "gateway_endpoint_route_count": (
                    self._safe_int(gateway_endpoint.get("route_count"))
                ),
                "gateway_endpoint_active_route_count": (
                    self._safe_int(gateway_endpoint.get("active_route_count"))
                ),
                "gateway_endpoint_blackhole_route_count": (
                    self._safe_int(gateway_endpoint.get("blackhole_route_count"))
                ),
                "gateway_route_coverage_complete": (
                    gateway_endpoint.get("coverage_complete")
                ),
                "interface_subnet_route_count": (
                    self._safe_int(interface_endpoint.get("subnet_route_count"))
                ),
            },
            "network_interfaces": {
                "status": (network_interfaces.get("status")),
                "requested_count": (
                    self._safe_int(network_interfaces.get("requested_count"))
                ),
                "observed_count": (
                    self._safe_int(network_interfaces.get("observed_count"))
                ),
                "missing_ids": (
                    self._string_list(network_interfaces.get("missing_ids"))
                ),
                "unexpected_ids": (
                    self._string_list(network_interfaces.get("unexpected_ids"))
                ),
                "subnet_mismatches": (
                    network_interfaces.get(
                        "subnet_mismatches",
                        [],
                    )
                    if isinstance(
                        network_interfaces.get(
                            "subnet_mismatches",
                            [],
                        ),
                        list,
                    )
                    else []
                ),
                "resources": (
                    network_interfaces.get(
                        "resources",
                        [],
                    )
                    if isinstance(
                        network_interfaces.get(
                            "resources",
                            [],
                        ),
                        list,
                    )
                    else []
                ),
            },
            "data_quality": {
                "topology_available": (topology.get("status") == "ok"),
                "relationship_data_available": (relationships.get("status") == "ok"),
                "network_interfaces_available": (
                    network_interfaces.get("status")
                    in {
                        "ok",
                        "empty",
                    }
                ),
                "network_interfaces_complete": (
                    not network_interfaces.get("missing_ids", [])
                    and not network_interfaces.get("unexpected_ids", [])
                ),
                "configuration_available": bool(configuration),
                "identity_available": bool(identity),
                "collection_status": (collection_status),
            },
        }

    # ------------------------------------------------------------------
    # COLLECTION STATUS
    # ------------------------------------------------------------------

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

        endpoint_type = endpoint.get("endpoint_type")

        topology_ok = (
            isinstance(
                topology,
                dict,
            )
            and topology.get("status") == "ok"
        )

        relationships_ok = (
            isinstance(
                relationships,
                dict,
            )
            and relationships.get("status") == "ok"
        )

        if isinstance(
            network_interfaces,
            dict,
        ):

            interface_status = network_interfaces.get("status")

            requested_eni_count = int(
                network_interfaces.get(
                    "requested_count",
                    0,
                )
                or 0
            )

            observed_eni_count = int(
                network_interfaces.get(
                    "observed_count",
                    0,
                )
                or 0
            )

            missing_ids = network_interfaces.get(
                "missing_ids",
                [],
            )

            unexpected_ids = network_interfaces.get(
                "unexpected_ids",
                [],
            )

        else:

            interface_status = "error"

            requested_eni_count = 0
            observed_eni_count = 0

            missing_ids = []
            unexpected_ids = []

        missing_ids = (
            missing_ids
            if isinstance(
                missing_ids,
                list,
            )
            else []
        )

        unexpected_ids = (
            unexpected_ids
            if isinstance(
                unexpected_ids,
                list,
            )
            else []
        )

        eni_complete = requested_eni_count == 0 or (
            interface_status
            in {
                "ok",
                "partial",
            }
            and (observed_eni_count == requested_eni_count)
            and not missing_ids
            and not unexpected_ids
        )

        gateway_endpoint = (
            topology.get("gateway_endpoint")
            if isinstance(
                topology,
                dict,
            )
            else {}
        )

        if not isinstance(
            gateway_endpoint,
            dict,
        ):
            gateway_endpoint = {}

        gateway_route_context_complete = endpoint_type != "Gateway" or (
            topology_ok and bool(gateway_endpoint.get("coverage_complete") is not None)
        )

        gateway_route_coverage_complete = endpoint_type != "Gateway" or (
            topology_ok and gateway_endpoint.get("coverage_complete") is True
        )

        complete_for_analysis = (
            topology_ok
            and relationships_ok
            and eni_complete
            and gateway_route_context_complete
            and gateway_route_coverage_complete
        )

        return {
            "endpoint": "ok",
            "topology": ("ok" if topology_ok else "incomplete"),
            "relationships": ("ok" if relationships_ok else "incomplete"),
            "network_interfaces": (
                "ok"
                if eni_complete
                else ("error" if interface_status == "error" else "incomplete")
            ),
            "gateway_route_context": (
                "ok" if gateway_route_context_complete else "incomplete"
            ),
            "gateway_route_coverage": (
                "ok" if gateway_route_coverage_complete else "incomplete"
            ),
            "complete_for_analysis": (complete_for_analysis),
        }

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

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
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return 0

    @staticmethod
    def _string_list(
        value: Any,
    ) -> List[str]:

        if not isinstance(
            value,
            list,
        ):
            return []

        result: List[str] = []

        seen: set[str] = set()

        for item in value:

            if item is None:
                continue

            text = str(item).strip()

            if not text or text in seen:
                continue

            seen.add(text)

            result.append(text)

        return result

    @staticmethod
    def _deduplicate_dicts(
        values: List[Dict[str, Any]],
        key: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

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
                        key=lambda item: str(item[0]),
                    )
                )

            else:

                raw_key = value.get(key)

                identity = str(raw_key) if raw_key is not None else repr(value)

            if identity in seen:
                continue

            seen.add(identity)

            result.append(value)

        return result

    @staticmethod
    def _endpoint_category(
        endpoint_type: Optional[str],
    ) -> str:

        return {
            "Gateway": "gateway",
            "Interface": "interface",
            "GatewayLoadBalancer": ("gateway_load_balancer"),
            "Resource": "resource",
            "ServiceNetwork": ("service_network"),
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
