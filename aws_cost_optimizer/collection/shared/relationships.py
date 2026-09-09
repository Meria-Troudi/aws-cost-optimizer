"""
Reusable AWS VPC network relationship resolver.

Purpose
-------
Resolve relationships from already-collected topology evidence.

This class does NOT call AWS APIs.

Important semantics
-------------------
- A subnet's effective route table comes from
  effective_route_table_mappings.
- effective_routes contains actual routes, not subnet mappings.
- Gateway endpoint routes target VpcEndpointId.
- Missing topology is not converted into a positive dependency.
- The resolver returns evidence only; it does not make optimization
  decisions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

_TARGET_FIELD_MAP: dict[str, str] = {
    "nat_gateway": "nat_gateway_id",
    "internet_gateway": "gateway_id",
    "transit_gateway": "transit_gateway_id",
    "vpc_endpoint": "vpc_endpoint_id",
    "gateway_endpoint": "vpc_endpoint_id",
    "network_interface": "network_interface_id",
    "instance": "instance_id",
    "vpc_peering_connection": ("vpc_peering_connection_id"),
    "carrier_gateway": "carrier_gateway_id",
    "local_gateway": "local_gateway_id",
    "egress_only_internet_gateway": ("egress_only_internet_gateway_id"),
    "core_network": "core_network_arn",
    "odb_network": "odb_network_arn",
}


class NetworkRelationshipResolver:

    def __init__(
        self,
        topology: Dict[str, Any],
    ) -> None:

        self.topology = topology if isinstance(topology, dict) else {}

        self.status = self.topology.get("status")

        self.summary = (
            self.topology.get("summary", {})
            if isinstance(
                self.topology.get("summary", {}),
                dict,
            )
            else {}
        )

        self.errors = self._as_list(self.topology.get("errors"))

        self.subnets = self._as_list(self.topology.get("subnets"))

        self.route_tables = self._as_list(self.topology.get("route_tables"))

        # IMPORTANT:
        # This is the subnet -> effective route-table mapping.
        self.effective_route_table_mappings = self._as_list(
            self.topology.get("effective_route_table_mappings")
        )

        # These are actual effective routes.
        self.effective_routes = self._as_list(self.topology.get("effective_routes"))

        self.vpc_endpoints = self._as_list(self.topology.get("vpc_endpoints"))

        self._subnet_index: dict[
            str,
            Dict[str, Any],
        ] = {
            str(subnet.get("subnet_id")): subnet
            for subnet in self.subnets
            if subnet.get("subnet_id")
        }

        self._route_table_index: dict[
            str,
            Dict[str, Any],
        ] = {
            str(table.get("route_table_id")): table
            for table in self.route_tables
            if table.get("route_table_id")
        }

        # FIX:
        # Build the subnet mapping from
        # effective_route_table_mappings, NOT effective_routes.
        self._effective_route_index: dict[
            str,
            Dict[str, Any],
        ] = {
            str(mapping.get("subnet_id")): mapping
            for mapping in self.effective_route_table_mappings
            if mapping.get("subnet_id")
        }

        self._effective_routes_by_subnet: dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        for route in self.effective_routes:
            subnet_id = route.get("subnet_id")

            if not subnet_id:
                continue

            subnet_id = str(subnet_id)

            self._effective_routes_by_subnet.setdefault(
                subnet_id,
                [],
            ).append(route)

    # ------------------------------------------------------------------
    # Basic helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _as_list(
        value: Any,
    ) -> list[Dict[str, Any]]:

        if not isinstance(value, list):
            return []

        return [item for item in value if isinstance(item, dict)]

    def _route_table_by_id(
        self,
        route_table_id: str,
    ) -> Optional[Dict[str, Any]]:

        if not route_table_id:
            return None

        return self._route_table_index.get(str(route_table_id))

    # ------------------------------------------------------------------
    # Subnet lookup
    # ------------------------------------------------------------------

    def subnet(
        self,
        subnet_id: str,
    ) -> Optional[Dict[str, Any]]:

        if not subnet_id:
            return None

        return self._subnet_index.get(str(subnet_id))

    def route_table_id_for_subnet(
        self,
        subnet_id: str,
    ) -> Optional[str]:

        if not subnet_id:
            return None

        mapping = self._effective_route_index.get(str(subnet_id))

        if not mapping:
            return None

        value = mapping.get("route_table_id")

        return str(value) if value else None

    def route_table_for_subnet(
        self,
        subnet_id: str,
    ) -> Optional[Dict[str, Any]]:

        route_table_id = self.route_table_id_for_subnet(subnet_id)

        if not route_table_id:
            return None

        return self._route_table_by_id(route_table_id)

    def subnets_for_route_table(
        self,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        if not route_table_id:
            return []

        requested = str(route_table_id)

        return [
            subnet
            for subnet in self.subnets
            if (self.route_table_id_for_subnet(subnet.get("subnet_id")) == requested)
        ]

    def subnets_for_route_tables(
        self,
        route_table_ids: List[str],
    ) -> List[Dict[str, Any]]:

        requested = {
            str(route_table_id)
            for route_table_id in (route_table_ids or [])
            if route_table_id
        }

        if not requested:
            return []

        seen: set[str] = set()
        result: List[Dict[str, Any]] = []

        for subnet in self.subnets:
            subnet_id = subnet.get("subnet_id")

            if not subnet_id:
                continue

            subnet_id = str(subnet_id)

            effective_table = self.route_table_id_for_subnet(subnet_id)

            if effective_table not in requested:
                continue

            if subnet_id in seen:
                continue

            seen.add(subnet_id)
            result.append(subnet)

        return result

    # ------------------------------------------------------------------
    # Route lookup
    # ------------------------------------------------------------------

    def routes_for_subnet(
        self,
        subnet_id: str,
    ) -> List[Dict[str, Any]]:

        if not subnet_id:
            return []

        subnet_id = str(subnet_id)

        # Prefer precomputed effective routes.
        effective = self._effective_routes_by_subnet.get(subnet_id)

        if effective is not None:
            return [dict(route) for route in effective]

        # Defensive fallback.
        route_table_id = self.route_table_id_for_subnet(subnet_id)

        if not route_table_id:
            return []

        return self._routes_for_subnet_and_table(
            subnet_id,
            route_table_id,
        )

    def routes_for_subnets(
        self,
        subnet_ids: List[str],
    ) -> List[Dict[str, Any]]:

        requested = {str(subnet_id) for subnet_id in (subnet_ids or []) if subnet_id}

        if not requested:
            return []

        result: List[Dict[str, Any]] = []
        seen: set[tuple] = set()

        for subnet_id in requested:

            for route in self.routes_for_subnet(subnet_id):
                key = self._route_key(route)

                if key in seen:
                    continue

                seen.add(key)
                result.append(route)

        return result

    def routes_for_route_table(
        self,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        table = self._route_table_by_id(route_table_id)

        if not table:
            return []

        return [
            {
                **route,
                "route_table_id": str(route_table_id),
                "route_table_source": "direct",
                "subnet_id": None,
                "availability_zone": None,
            }
            for route in (table.get("routes", []) or [])
            if isinstance(route, dict)
        ]

    def routes_for_route_tables(
        self,
        route_table_ids: List[str],
    ) -> List[Dict[str, Any]]:

        requested = {
            str(route_table_id)
            for route_table_id in (route_table_ids or [])
            if route_table_id
        }

        if not requested:
            return []

        result: List[Dict[str, Any]] = []
        seen: set[tuple] = set()

        for route_table_id in requested:
            for route in self.routes_for_route_table(route_table_id):
                key = self._route_key(route)

                if key in seen:
                    continue

                seen.add(key)
                result.append(route)

        return result

    # ------------------------------------------------------------------
    # Target relationships
    # ------------------------------------------------------------------

    def routes_targeting(
        self,
        target_type: str,
        target_id: str,
    ) -> List[Dict[str, Any]]:

        field = _TARGET_FIELD_MAP.get(target_type)

        if not field:
            raise ValueError(f"Unsupported target type: {target_type}")

        if not target_id:
            return []

        target_id = str(target_id)

        results: List[Dict[str, Any]] = []

        # Use effective routes directly.
        for route in self.effective_routes:

            route_target = route.get(field)

            if route_target is None:
                continue

            if str(route_target) != target_id:
                continue

            if target_type == "internet_gateway" and not target_id.startswith("igw-"):
                continue

            results.append(
                {
                    **route,
                    "target_type": target_type,
                    "target_id": target_id,
                }
            )

        return results

    def routes_for_target(
        self,
        subnet_id: str,
        target_type: str,
        target_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:

        field = _TARGET_FIELD_MAP.get(target_type)

        if not field:
            raise ValueError(f"Unsupported target type: {target_type}")

        if not subnet_id:
            return []

        subnet_id = str(subnet_id)

        results: List[Dict[str, Any]] = []

        for route in self.routes_for_subnet(subnet_id):
            route_target_id = route.get(field)

            if not route_target_id:
                continue

            route_target_id = str(route_target_id)

            if target_type == "internet_gateway" and not route_target_id.startswith(
                "igw-"
            ):
                continue

            if target_id is not None and route_target_id != str(target_id):
                continue

            results.append(
                {
                    **route,
                    "target_type": target_type,
                    "target_id": route_target_id,
                }
            )

        return results

    def subnets_targeting(
        self,
        target_type: str,
        target_id: str,
    ) -> List[Dict[str, Any]]:

        routes = self.routes_targeting(
            target_type,
            target_id,
        )

        ids = {
            str(route.get("subnet_id")) for route in routes if route.get("subnet_id")
        }

        return [
            subnet
            for subnet in self.subnets
            if subnet.get("subnet_id") and str(subnet.get("subnet_id")) in ids
        ]

    def route_tables_targeting(
        self,
        target_type: str,
        target_id: str,
    ) -> List[Dict[str, Any]]:

        routes = self.routes_targeting(
            target_type,
            target_id,
        )

        ids = {
            str(route.get("route_table_id"))
            for route in routes
            if route.get("route_table_id")
        }

        return [
            table
            for table in self.route_tables
            if table.get("route_table_id") and str(table.get("route_table_id")) in ids
        ]

    # ------------------------------------------------------------------
    # Dependency extraction
    # ------------------------------------------------------------------

    def dependency_ids_for_routes(
        self,
        routes: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:

        mapping = {
            "gateway_id": "internet_gateway_ids",
            "nat_gateway_id": "nat_gateway_ids",
            "transit_gateway_id": "transit_gateway_ids",
            "vpc_endpoint_id": "vpc_endpoint_ids",
            "vpc_peering_connection_id": ("vpc_peering_connection_ids"),
            "network_interface_id": "network_interface_ids",
            "instance_id": "instance_ids",
            "carrier_gateway_id": "carrier_gateway_ids",
            "local_gateway_id": "local_gateway_ids",
            "egress_only_internet_gateway_id": ("egress_only_internet_gateway_ids"),
            "core_network_arn": "core_network_arns",
            "odb_network_arn": "odb_network_arns",
        }

        result: Dict[str, set[str]] = {value: set() for value in mapping.values()}

        for route in routes or []:

            if not isinstance(route, dict):
                continue

            for field, category in mapping.items():

                value = route.get(field)

                if not value:
                    continue

                value = str(value)

                if field == "gateway_id" and not value.startswith("igw-"):
                    continue

                result[category].add(value)

        return {key: sorted(values) for key, values in result.items() if values}

    def resources_referenced_by_routes(
        self,
    ) -> Dict[str, List[str]]:

        return self.dependency_ids_for_routes(self.effective_routes)

    def endpoints_for_subnet(
        self,
        subnet_id: str,
    ) -> List[Dict[str, Any]]:

        if not subnet_id:
            return []

        subnet_id = str(subnet_id)

        return [
            endpoint
            for endpoint in self.vpc_endpoints
            if subnet_id
            in {
                str(value)
                for value in (
                    endpoint.get(
                        "subnet_ids",
                        [],
                    )
                    or []
                )
            }
        ]

    def endpoints_for_route_table(
        self,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        if not route_table_id:
            return []

        route_table_id = str(route_table_id)

        return [
            endpoint
            for endpoint in self.vpc_endpoints
            if route_table_id
            in {
                str(value)
                for value in (
                    endpoint.get(
                        "route_table_ids",
                        [],
                    )
                    or []
                )
            }
        ]

    def endpoints_for_service(
        self,
        service_name: str,
    ) -> List[Dict[str, Any]]:

        requested = str(service_name or "").lower()

        if not requested:
            return []

        return [
            endpoint
            for endpoint in self.vpc_endpoints
            if str(
                endpoint.get(
                    "service_name",
                    "",
                )
                or ""
            ).lower()
            == requested
        ]

    def routes_targeting_vpc_endpoint(
        self,
        vpc_endpoint_id: str,
    ) -> List[Dict[str, Any]]:

        return self.routes_targeting(
            target_type="gateway_endpoint",
            target_id=vpc_endpoint_id,
        )

    # ------------------------------------------------------------------
    # Boolean helpers
    # ------------------------------------------------------------------

    def subnet_has_nat_gateway(
        self,
        subnet_id: str,
        nat_gateway_id: Optional[str] = None,
    ) -> bool:

        return bool(
            self.routes_for_target(
                subnet_id,
                "nat_gateway",
                nat_gateway_id,
            )
        )

    def subnet_has_internet_gateway(
        self,
        subnet_id: str,
        internet_gateway_id: Optional[str] = None,
    ) -> bool:

        return bool(
            self.routes_for_target(
                subnet_id,
                "internet_gateway",
                internet_gateway_id,
            )
        )

    def subnet_has_transit_gateway(
        self,
        subnet_id: str,
        transit_gateway_id: Optional[str] = None,
    ) -> bool:

        return bool(
            self.routes_for_target(
                subnet_id,
                "transit_gateway",
                transit_gateway_id,
            )
        )

    def _routes_for_subnet_and_table(
        self,
        subnet_id: str,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        table = self._route_table_by_id(route_table_id)

        if not table:
            return []

        mapping = self._effective_route_index.get(str(subnet_id))

        subnet = self.subnet(subnet_id)

        availability_zone = subnet.get("availability_zone") if subnet else None

        route_source = mapping.get("source") if mapping else None

        result: List[Dict[str, Any]] = []

        for route in table.get("routes", []) or []:

            if not isinstance(route, dict):
                continue

            result.append(
                {
                    **route,
                    "subnet_id": str(subnet_id),
                    "route_table_id": str(route_table_id),
                    "route_table_source": route_source,
                    "availability_zone": availability_zone,
                }
            )

        return result

    @staticmethod
    def _route_key(
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
