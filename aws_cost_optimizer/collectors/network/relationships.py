"""
Reusable AWS VPC network relationship resolver.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


_TARGET_FIELD_MAP = {
    "nat_gateway": "nat_gateway_id",
    "internet_gateway": "gateway_id",
    "transit_gateway": "transit_gateway_id",
    "network_interface": "network_interface_id",
    "instance": "instance_id",
    "vpc_peering_connection": "vpc_peering_connection_id",
    "carrier_gateway": "carrier_gateway_id",
    "local_gateway": "local_gateway_id",
    "egress_only_internet_gateway":
        "egress_only_internet_gateway_id",
    "core_network": "core_network_arn",
    "gateway_endpoint": "gateway_id",
}


class NetworkRelationshipResolver:

    def __init__(
        self,
        topology: Dict[str, Any],
    ):

        self.topology = topology

        self.subnets = topology.get(
            "subnets",
            [],
        )

        self.route_tables = topology.get(
            "route_tables",
            [],
        )

        self.effective_routes = topology.get(
            "effective_routes",
            [],
        )

        self.vpc_endpoints = topology.get(
            "vpc_endpoints",
            [],
        )

        self._subnet_index = {
            subnet.get("subnet_id"): subnet
            for subnet in self.subnets
            if subnet.get("subnet_id")
        }

        self._route_table_index = {
            table.get("route_table_id"): table
            for table in self.route_tables
            if table.get("route_table_id")
        }

        self._effective_route_index = {
            mapping.get("subnet_id"): mapping
            for mapping in self.effective_routes
            if mapping.get("subnet_id")
        }

    def subnet(
        self,
        subnet_id: str,
    ) -> Optional[Dict[str, Any]]:

        return self._subnet_index.get(
            subnet_id
        )
    def route_table_for_subnet(
        self,
        subnet_id: str,
    ) -> Optional[Dict[str, Any]]:

        route_table_id = (
            self.route_table_id_for_subnet(
                subnet_id
            )
        )

        if not route_table_id:
            return None

        return self._route_table_by_id(
            route_table_id
        )

    def route_table_id_for_subnet(
        self,
        subnet_id: str,
    ) -> Optional[str]:

        mapping = (
            self._effective_route_index.get(
                subnet_id
            )
        )

        if not mapping:
            return None

        return mapping.get(
            "route_table_id"
        )
    def routes_for_subnet(
        self,
        subnet_id: str,
    ) -> List[Dict[str, Any]]:

        route_table_id = (
            self.route_table_id_for_subnet(
                subnet_id
            )
        )

        if not route_table_id:
            return []

        return self._routes_for_subnet_and_table(
            subnet_id,
            route_table_id,
        )
    def routes_for_route_table(
        self,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        table = self._route_table_by_id(
            route_table_id
        )

        if not table:
            return []

        return [
            {
                **route,

                "route_table_id": route_table_id,

                "route_table_source": "explicit",

                "subnet_id": None,

                "availability_zone": None,
            }
            for route in table.get(
                "routes",
                [],
            )
        ]

    def subnets_for_route_table(
        self,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        subnet_ids = {
            mapping.get("subnet_id")
            for mapping in self.effective_routes
            if (
                mapping.get("route_table_id")
                == route_table_id
            )
            and mapping.get("subnet_id")
        }

        return [
            subnet
            for subnet in self.subnets
            if subnet.get(
                "subnet_id"
            ) in subnet_ids
        ]

    def routes_targeting(
        self,
        target_type: str,
        target_id: str,
    ) -> List[Dict[str, Any]]:

        field = _TARGET_FIELD_MAP.get(
            target_type
        )

        if not field:
            raise ValueError(
                f"Unsupported target type: "
                f"{target_type}"
            )

        results: List[
            Dict[str, Any]
        ] = []

        for mapping in self.effective_routes:

            subnet_id = mapping.get(
                "subnet_id"
            )

            route_table_id = mapping.get(
                "route_table_id"
            )

            if not subnet_id or not route_table_id:
                continue

            route_table = (
                self._route_table_by_id(
                    route_table_id
                )
            )

            if not route_table:
                continue

            subnet = self.subnet(
                subnet_id
            )

            availability_zone = (
                subnet.get(
                    "availability_zone"
                )
                if subnet
                else None
            )

            for route in route_table.get(
                "routes",
                [],
            ):

                route_target = route.get(
                    field
                )

                if route_target != target_id:
                    continue

                if (
                    target_type
                    == "internet_gateway"
                    and not str(
                        route_target
                    ).startswith(
                        "igw-"
                    )
                ):
                    continue

                results.append(
                    {
                        **route,

                        "subnet_id": subnet_id,

                        "route_table_id": (
                            route_table_id
                        ),

                        "route_table_source": (
                            mapping.get(
                                "source"
                            )
                        ),

                        "availability_zone": (
                            availability_zone
                        ),

                        "target_type": (
                            target_type
                        ),

                        "target_id": (
                            target_id
                        ),
                    }
                )

        return results

    def routes_for_target(
        self,
        subnet_id: str,
        target_type: str,
        target_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:

        field = _TARGET_FIELD_MAP.get(
            target_type
        )

        if not field:
            raise ValueError(
                f"Unsupported target type: "
                f"{target_type}"
            )

        route_table_id = (
            self.route_table_id_for_subnet(
                subnet_id
            )
        )

        if not route_table_id:
            return []

        route_table = (
            self._route_table_by_id(
                route_table_id
            )
        )

        if not route_table:
            return []

        mapping = (
            self._effective_route_index.get(
                subnet_id
            )
        )

        subnet = self.subnet(
            subnet_id
        )

        availability_zone = (
            subnet.get(
                "availability_zone"
            )
            if subnet
            else None
        )

        results: List[
            Dict[str, Any]
        ] = []

        for route in route_table.get(
            "routes",
            [],
        ):

            route_target_id = route.get(
                field
            )

            if not route_target_id:
                continue

            if (
                target_type
                == "internet_gateway"
                and not str(
                    route_target_id
                ).startswith(
                    "igw-"
                )
            ):
                continue

            if (
                target_id is not None
                and route_target_id != target_id
            ):
                continue

            results.append(
                {
                    **route,

                    "subnet_id": subnet_id,

                    "route_table_id": (
                        route_table_id
                    ),

                    "route_table_source": (
                        mapping.get("source")
                        if mapping
                        else None
                    ),

                    "availability_zone": (
                        availability_zone
                    ),

                    "target_type": (
                        target_type
                    ),

                    "target_id": (
                        route_target_id
                    ),
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
            route.get("subnet_id")
            for route in routes
            if route.get("subnet_id")
        }

        return [
            subnet
            for subnet in self.subnets
            if subnet.get(
                "subnet_id"
            ) in ids
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
            route.get("route_table_id")
            for route in routes
            if route.get("route_table_id")
        }

        return [
            table
            for table in self.route_tables
            if table.get(
                "route_table_id"
            ) in ids
        ]

    def endpoints_for_subnet(
        self,
        subnet_id: str,
    ) -> List[Dict[str, Any]]:

        return [
            endpoint
            for endpoint in self.vpc_endpoints
            if subnet_id in endpoint.get(
                "subnet_ids",
                [],
            )
        ]

    def endpoints_for_route_table(
        self,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        return [
            endpoint
            for endpoint in self.vpc_endpoints
            if route_table_id in endpoint.get(
                "route_table_ids",
                [],
            )
        ]

    def endpoints_for_service(
        self,
        service_name: str,
    ) -> List[Dict[str, Any]]:

        requested = (
            service_name.lower()
        )

        return [
            endpoint
            for endpoint in self.vpc_endpoints
            if endpoint.get(
                "service_name",
                "",
            ).lower() == requested
        ]

    def routes_targeting_vpc_endpoint(
        self,
        vpc_endpoint_id: str,
    ) -> List[Dict[str, Any]]:

        return self.routes_targeting(
            target_type="gateway_endpoint",
            target_id=vpc_endpoint_id,
        )

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

 
    def resources_referenced_by_routes(
        self,
    ) -> Dict[str, List[str]]:

        result: Dict[
            str,
            set
        ] = {}

        for table in self.route_tables:

            for route in table.get(
                "routes",
                [],
            ):

                for target_type, field in (
                    _TARGET_FIELD_MAP.items()
                ):

                    target_id = route.get(
                        field
                    )

                    if not target_id:
                        continue

                    result.setdefault(
                        target_type,
                        set(),
                    ).add(
                        target_id
                    )

        return {
            key: sorted(
                values
            )
            for key, values in result.items()
        }

    def _route_table_by_id(
        self,
        route_table_id: str,
    ) -> Optional[Dict[str, Any]]:

        return self._route_table_index.get(
            route_table_id
        )
    
    def _routes_for_subnet_and_table(
        self,
        subnet_id: str,
        route_table_id: str,
    ) -> List[Dict[str, Any]]:

        table = self._route_table_by_id(
            route_table_id
        )

        if not table:
            return []

        mapping = (
            self._effective_route_index.get(
                subnet_id
            )
        )

        subnet = self.subnet(
            subnet_id
        )

        availability_zone = (
            subnet.get(
                "availability_zone"
            )
            if subnet
            else None
        )

        return [
            {
                **route,

                "subnet_id": subnet_id,

                "route_table_id": (
                    route_table_id
                ),

                "route_table_source": (
                    mapping.get(
                        "source"
                    )
                    if mapping
                    else None
                ),

                "availability_zone": (
                    availability_zone
                ),
            }
            for route in table.get(
                "routes",
                [],
            )
        ]