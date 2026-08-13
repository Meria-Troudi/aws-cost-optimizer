"""
NAT Gateway Collector.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register

from collectors.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)

from collectors.network.topology import (
    NetworkTopologyCollector,
)

from aws_cost_optimizer.analysis.metrics import (
    metric_has_observed_data,
    metric_is_sum,
    metric_numeric_value,
    metric_sum_value,
)

from collectors.network.relationships import (
    NetworkRelationshipResolver,
)


@register
class NatGatewayCollector(BaseCollector):

    key = "nat_gateway"
    resource_type = "nat_gateway"

    _TRAFFIC_DIRECTION_METRICS = (
        "BytesOutToDestination",
        "BytesOutToSource",
    )

    def __init__(
        self,
        scan,
        region=None,
        profile=None,
    ):

        super().__init__(
            scan=scan,
            region=region,
            profile=profile,
        )

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.network_collector = (
            NetworkTopologyCollector(
                self.region
            )
        )

        self.metric_collector = (
            CloudWatchMetricCollector(
                self.cloudwatch
            )
        )


    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        paginator = self.ec2.get_paginator(
            "describe_nat_gateways"
        )

        resources = []

        for page in paginator.paginate():

            for nat in page.get(
                "NatGateways",
                [],
            ):

                nat_id = nat.get(
                    "NatGatewayId"
                )

                if not nat_id:
                    continue

                resources.append(
                    {
                        "id": nat_id,
                        "raw": nat,
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

        nat = resource["raw"]

        tags = self._tags(
            nat.get(
                "Tags",
                [],
            )
        )

        return {
            "name": (
                tags.get("Name")
                or resource["id"]
            ),
            "state": nat.get("State"),
            "state_category": self._state_category(
                nat.get("State")
            ),
            "tags": tags,
        }


    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        nat = resource["raw"]

        addresses = nat.get(
            "NatGatewayAddresses",
            [],
        )

        address = (
            addresses[0]
            if addresses
            else {}
        )

        subnet_id = nat.get(
            "SubnetId"
        )

        return {
            "nat_gateway_id": nat.get(
                "NatGatewayId"
            ),
            "vpc_id": nat.get(
                "VpcId"
            ),
            "subnet_id": subnet_id,
            "availability_zone": (
                self._get_subnet_az(
                    subnet_id
                )
            ),
            "connectivity_type": nat.get(
                "ConnectivityType"
            ),
            "availability_mode": nat.get(
                "AvailabilityMode"
            ),
            "state": nat.get("State"),
            "create_time": (
                nat["CreateTime"].isoformat()
                if nat.get("CreateTime")
                else None
            ),
            "public_ip": address.get(
                "PublicIp"
            ),
            "private_ip": address.get(
                "PrivateIp"
            ),
            "elastic_ip_allocation_id": (
                address.get(
                    "AllocationId"
                )
            ),
            "network_interface_id": (
                address.get(
                    "NetworkInterfaceId"
                )
            ),
            "failure_code": nat.get(
                "FailureCode"
            ),
            "failure_message": nat.get(
                "FailureMessage"
            ),
            "address_count": len(
                addresses
            ),
        }


    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        cw_config = (
            self.profile
            .get("observations", {})
            .get("cloudwatch", {})
        )

        metric_specs = cw_config.get(
            "metrics",
            [],
        )

        if not metric_specs:
            return {}

        namespace = cw_config.get(
            "namespace",
            "AWS/NATGateway",
        )

        start, end = (
            self.get_analysis_period()
        )

        requested_period = int(
            cw_config.get(
                "period",
                3600,
            )
        )

        dimensions = [
            {
                "Name": "NatGatewayId",
                "Value": resource["id"],
            }
        ]

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

        metrics = {}

        for result in results:

            metric_name = result.get(
                "metric_name"
            )

            if metric_name:

                metrics[metric_name] = result

        derived = self._build_derived_data(
            metrics
        )

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
            },
            "derived": derived,
        }

    

    def _build_derived_data(
        self,
        metrics_dict: Dict[str, Any],
    ) -> Dict[str, Any]:

        destination_metric = metrics_dict.get(
            "BytesOutToDestination"
        )
        source_metric = metrics_dict.get(
            "BytesOutToSource"
        )

        destination_available = metric_has_observed_data(
            destination_metric
        )
        source_available = metric_has_observed_data(
            source_metric
        )

        traffic_available = (
            destination_available
            or source_available
        )
        traffic_complete = (
            destination_available
            and source_available
        )

        outbound_bytes = metric_sum_value(
            destination_metric
        )
        return_bytes = metric_sum_value(
            source_metric
        )

        traffic_semantics_valid = all(
            not metric_has_observed_data(
                metrics_dict.get(name)
            )
            or metric_is_sum(
                metrics_dict.get(name)
            )
            for name in self._TRAFFIC_DIRECTION_METRICS
        )

        byte_values = [
            value
            for value in (outbound_bytes, return_bytes)
            if value is not None
        ]

        total_bytes = (
            sum(byte_values)
            if byte_values
            else None
        )

        total_gib = (
            total_bytes / (1024 ** 3)
            if total_bytes is not None
            else None
        )

        traffic_observed = (
            total_bytes > 0
            if total_bytes is not None
            else None
        )

        active_connections = metric_numeric_value(
            metrics_dict.get("ActiveConnectionCount")
        )

        connection_attempts = metric_numeric_value(
            metrics_dict.get("ConnectionAttemptCount")
        )

        connections_established = metric_numeric_value(
            metrics_dict.get("ConnectionEstablishedCount")
        )

        connection_values = [
            value
            for value in (
                active_connections,
                connection_attempts,
                connections_established,
            )
            if value is not None
        ]

        connection_available = any(
            metric_has_observed_data(metrics_dict.get(name))
            for name in (
                "ActiveConnectionCount",
                "ConnectionAttemptCount",
                "ConnectionEstablishedCount",
            )
        )

        connection_observed = (
            any(
                value > 0
                for value in connection_values
            )
            if connection_available
            else None
        )

        activity_observed = None

        if (
            traffic_observed is not None
            or connection_observed is not None
        ):

            activity_observed = any(
                value is True
                for value in (
                    traffic_observed,
                    connection_observed,
                )
            )

        return {
            "traffic": {
                "outbound_bytes": outbound_bytes,
                "return_bytes": return_bytes,
                "total_bytes": total_bytes,
                "total_gib": total_gib,
                "available": traffic_available,
                "complete": traffic_complete,
                "observed": traffic_observed,
            },

            "connections": {
                "active": active_connections,
                "attempts": connection_attempts,
                "established": connections_established,
                "available": connection_available,
                "observed": connection_observed,
            },

            "activity": {
                "observed": activity_observed,
            },

            "semantics": {
                "traffic_source": "CloudWatch",
                "traffic_is_billing_usage": False,
                "connection_metrics_are_billing_usage": False,
                "traffic_value_requires_sum_statistic": True,
                "traffic_semantics_valid": traffic_semantics_valid,
                "activity_indicator_label": (
                    "cloudwatch_activity_indicator"
                ),
                "purpose": (
                    "operational_activity_observation"
                ),
            },
        }

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = (
            collected_resource.get(
                "configuration",
                {},
            )
        )

        vpc_id = configuration.get(
            "vpc_id"
        )

        if not vpc_id:

            return {
                "status": "incomplete",
                "reason": "VPC ID not available",
            }

        nat_id = resource["id"]

        topology = (
            self.network_collector.collect(
                vpc_id=vpc_id,
                resource_type="nat_gateway",
                resource_id=nat_id,
            )
        )

        resolver = (
            NetworkRelationshipResolver(
                topology
            )
        )

        nat_routes = (
            resolver.routes_targeting(
                target_type="nat_gateway",
                target_id=nat_id,
            )
        )

        route_dependent_subnet_ids = sorted(
            {
                route.get("subnet_id")
                for route in nat_routes
                if route.get("subnet_id")
            }
        )

        route_dependent_route_table_ids = sorted(
            {
                route.get("route_table_id")
                for route in nat_routes
                if route.get("route_table_id")
            }
        )

        route_dependent_subnets = [
            resolver.subnet(subnet_id)
            for subnet_id in route_dependent_subnet_ids
            if resolver.subnet(subnet_id)
        ]

        nat_route_summary = (
            self._build_nat_route_summary(
                nat_routes
            )
        )

        endpoints = topology.get(
            "vpc_endpoints",
            [],
        )

        relevant_endpoints = (
            self._find_relevant_endpoints(
                endpoints=endpoints,
                nat_routes=nat_routes,
            )
        )

        endpoint_summary = (
            self._build_endpoint_summary(
                relevant_endpoints
            )
        )

    
        nat_az = configuration.get(
            "availability_zone"
        )

        dependent_azs = sorted(
            {
                subnet.get(
                    "availability_zone"
                )
                for subnet in route_dependent_subnets
                if subnet.get(
                    "availability_zone"
                )
            }
        )

        cross_az_subnets = [
            subnet.get("subnet_id")
            for subnet in route_dependent_subnets
            if (
                subnet.get("availability_zone")
                and nat_az
                and subnet.get("availability_zone")
                != nat_az
            )
        ]

        route_targets = topology.get(
            "route_targets",
            {},
        )

        network_summary = {
            "vpc": topology.get("vpc"),

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

            "route_count": len(
                topology.get(
                    "routes",
                    [],
                )
            ),

            "endpoint_count": len(
                endpoints
            ),
        }
        summary = {

            "vpc_id": vpc_id,

            "nat_subnet": configuration.get(
                "subnet_id"
            ),

            "nat_availability_zone": nat_az,

            "connectivity_type": (
                configuration.get(
                    "connectivity_type"
                )
            ),

            "availability_mode": (
                configuration.get(
                    "availability_mode"
                )
            ),

            "route_dependent_subnet_count": len(
                route_dependent_subnet_ids
            ),

            "route_dependent_route_table_count": len(
                route_dependent_route_table_ids
            ),

            "nat_route_count": len(
                nat_routes
            ),

            "route_dependent_availability_zones": (
                dependent_azs
            ),

            "cross_az_subnet_count": len(
                cross_az_subnets
            ),

            "has_cross_az_route_dependency": bool(
                cross_az_subnets
            ),

            "vpc_endpoint_count": len(
                endpoints
            ),

            "relevant_endpoint_count": len(
                relevant_endpoints
            ),

            "has_s3_endpoint_on_route_dependent_tables": (
                endpoint_summary["has_s3"]
            ),

            "has_dynamodb_endpoint_on_route_dependent_tables": (
                endpoint_summary["has_dynamodb"]
            ),

            "has_ecr_endpoint_on_route_dependent_tables": (
                endpoint_summary["has_ecr"]
            ),

            "relevant_endpoint_services": (
                endpoint_summary["services"]
            ),

            "has_blackhole_routes": (
                nat_route_summary[
                    "has_blackhole_routes"
                ]
            ),
        }

        return {

            "status": "ok",

            "vpc_id": vpc_id,

            "nat_gateway_id": nat_id,

            "nat_subnet": configuration.get(
                "subnet_id"
            ),

            "nat_availability_zone": nat_az,

            "route_dependency": {
                "kind": "configuration_route_dependency",
                "description": (
                    "Subnets whose effective route tables contain a "
                    "route targeting this NAT Gateway."
                ),
            },

            "route_dependent_subnet_ids": (
                route_dependent_subnet_ids
            ),

            "route_dependent_subnets": (
                route_dependent_subnets
            ),

            "route_dependent_route_table_ids": (
                route_dependent_route_table_ids
            ),

            "nat_routes": nat_routes,

            "vpc_endpoints": endpoints,

            "relevant_endpoints": (
                relevant_endpoints
            ),

            "endpoint_summary": (
                endpoint_summary
            ),

            "cross_az_subnets": (
                cross_az_subnets
            ),

            "route_targets": (
                route_targets
            ),

            "route_summary": (
                nat_route_summary
            ),

            "network_summary": (
                network_summary
            ),

            "summary": summary,
        }

    @staticmethod
    def _build_nat_route_summary(
        nat_routes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        azs = {
            route.get("availability_zone")
            for route in nat_routes
            if route.get("availability_zone")
        }

        route_states = {}

        for route in nat_routes:

            state = route.get("state")

            if not state:
                continue

            route_states[state] = (
                route_states.get(
                    state,
                    0,
                )
                + 1
            )

        return {

            "route_count": len(
                nat_routes
            ),

            "route_dependent_subnet_count": len(
                {
                    route.get("subnet_id")
                    for route in nat_routes
                    if route.get("subnet_id")
                }
            ),

            "dependent_subnet_count": len(
                {
                    route.get("subnet_id")
                    for route in nat_routes
                    if route.get("subnet_id")
                }
            ),

            "route_dependent_route_table_count": len(
                {
                    route.get("route_table_id")
                    for route in nat_routes
                    if route.get("route_table_id")
                }
            ),

            "dependent_route_table_count": len(
                {
                    route.get("route_table_id")
                    for route in nat_routes
                    if route.get("route_table_id")
                }
            ),

            "availability_zones": sorted(
                azs
            ),

            "route_states": route_states,

            "has_blackhole_routes": (
                route_states.get(
                    "blackhole",
                    0,
                )
                > 0
            ),
        }

    @staticmethod
    def _find_relevant_endpoints(
        endpoints: List[Dict[str, Any]],
        nat_routes: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        route_table_ids = {
            route.get(
                "route_table_id"
            )
            for route in nat_routes
            if route.get(
                "route_table_id"
            )
        }

        subnet_ids = {
            route.get(
                "subnet_id"
            )
            for route in nat_routes
            if route.get(
                "subnet_id"
            )
        }

        result = []

        for endpoint in endpoints:

            endpoint_id = endpoint.get(
                "vpc_endpoint_id"
            )

            if not endpoint_id:
                continue

            endpoint_type = endpoint.get(
                "endpoint_type"
            )

            endpoint_route_tables = set(
                endpoint.get(
                    "route_table_ids",
                    [],
                )
            )

            endpoint_subnets = set(
                endpoint.get(
                    "subnet_ids",
                    [],
                )
            )

            shared_route_tables = (
                endpoint_route_tables
                & route_table_ids
            )

            shared_subnets = (
                endpoint_subnets
                & subnet_ids
            )

            if endpoint_type == "Gateway":

                relevant = bool(
                    shared_route_tables
                )

            elif endpoint_type == "Interface":

                relevant = bool(
                    shared_subnets
                )

            else:

                relevant = bool(
                    shared_route_tables
                    or shared_subnets
                )

            if not relevant:
                continue

            result.append(
                {
                    "vpc_endpoint_id": (
                        endpoint_id
                    ),
                    "service_name": (
                        endpoint.get(
                            "service_name"
                        )
                    ),
                    "endpoint_type": (
                        endpoint_type
                    ),
                    "route_table_ids": sorted(
                        shared_route_tables
                    ),
                    "subnet_ids": sorted(
                        shared_subnets
                    ),
                    "applies_to_route_dependent_tables": bool(
                        shared_route_tables
                    ),
                }
            )

        return result
    @staticmethod
    def _build_endpoint_summary(
        endpoints: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        services = set()

        has_s3 = False
        has_dynamodb = False
        has_ecr = False

        for endpoint in endpoints:

            service = (
                endpoint.get(
                    "service_name",
                    "",
                )
                .lower()
            )

            if service:
                services.add(service)

            if "s3" in service:
                has_s3 = True

            if "dynamodb" in service:
                has_dynamodb = True

            if "ecr" in service:
                has_ecr = True

        return {
            "services": sorted(
                services
            ),
            "has_s3": has_s3,
            "has_dynamodb": has_dynamodb,
            "has_ecr": has_ecr,
        }
    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        identity = collected_resource.get(
            "identity",
            {},
        )

        configuration = collected_resource.get(
            "configuration",
            {},
        )

        observations = collected_resource.get(
            "observations",
            {},
        )

        topology = collected_resource.get(
            "topology",
            {},
        )

        derived = observations.get(
            "derived",
            {},
        )

        traffic = derived.get(
            "traffic",
            {},
        )

        connections = derived.get(
            "connections",
            {},
        )

        activity = derived.get(
            "activity",
            {},
        )

        summary = topology.get(
            "summary",
            {},
        )

        return {

            "resource": {
                "id": resource["id"],
                "name": identity.get("name"),
                "state": identity.get("state"),
                "state_category": identity.get("state_category"),
            },

            "configuration": {

                "connectivity_type": (
                    configuration.get(
                        "connectivity_type"
                    )
                ),

                "availability_mode": (
                    configuration.get(
                        "availability_mode"
                    )
                ),

                "availability_zone": (
                    configuration.get(
                        "availability_zone"
                    )
                ),

                "vpc_id": (
                    configuration.get(
                        "vpc_id"
                    )
                ),

                "subnet_id": (
                    configuration.get(
                        "subnet_id"
                    )
                ),
            },

            "activity": {

                "traffic_available": (
                    traffic.get(
                        "available"
                    )
                ),

                "traffic_complete": (
                    traffic.get(
                        "complete"
                    )
                ),

                "traffic_observed": (
                    traffic.get(
                        "observed"
                    )
                ),

                "activity_bytes_indicator": (
                    traffic.get(
                        "total_bytes"
                    )
                ),

                "activity_gib_indicator": (
                    traffic.get(
                        "total_gib"
                    )
                ),

                "connection_metrics_available": (
                    connections.get(
                        "available"
                    )
                ),

                "connection_observed": (
                    connections.get(
                        "observed"
                    )
                ),

                "activity_observed": (
                    activity.get(
                        "observed"
                    )
                ),
            },

            "network": {

                "route_dependency_kind": (
                    topology.get(
                        "route_dependency",
                        {},
                    ).get("kind")
                ),

                "route_dependent_subnet_count": (
                    summary.get(
                        "route_dependent_subnet_count",
                        0,
                    )
                ),

                "route_dependent_route_table_count": (
                    summary.get(
                        "route_dependent_route_table_count",
                        0,
                    )
                ),

                "nat_route_count": (
                    summary.get(
                        "nat_route_count",
                        0,
                    )
                ),

                "cross_az_subnet_count": (
                    summary.get(
                        "cross_az_subnet_count",
                        0,
                    )
                ),

                "has_cross_az_route_dependency": (
                    summary.get(
                        "has_cross_az_route_dependency",
                        False,
                    )
                ),

                "has_s3_endpoint_on_route_dependent_tables": (
                    summary.get(
                        "has_s3_endpoint_on_route_dependent_tables",
                        False,
                    )
                ),

                "has_dynamodb_endpoint_on_route_dependent_tables": (
                    summary.get(
                        "has_dynamodb_endpoint_on_route_dependent_tables",
                        False,
                    )
                ),

                "has_ecr_endpoint_on_route_dependent_tables": (
                    summary.get(
                        "has_ecr_endpoint_on_route_dependent_tables",
                        False,
                    )
                ),

                "has_blackhole_routes": (
                    summary.get(
                        "has_blackhole_routes",
                        False,
                    )
                ),
            },

            "data_quality": {

                "cloudwatch_available": bool(
                    observations.get(
                        "cloudwatch",
                        {}
                    ).get(
                        "metrics",
                        {}
                    )
                ),

                "topology_available": (
                    topology.get(
                        "status"
                    )
                    == "ok"
                ),

                "activity_evidence_available": (
                    traffic.get(
                        "available"
                    )
                    or connections.get(
                        "available"
                    )
                ),

                "traffic_semantics_valid": (
                    derived.get(
                        "semantics",
                        {},
                    ).get(
                        "traffic_semantics_valid"
                    )
                ),
            },
        }

    @staticmethod
    def _state_category(
        state: str | None,
    ) -> str:

        if state == "available":
            return "operational"

        if state in {"pending"}:
            return "transitional"

        if state in {"failed", "deleting", "deleted"}:
            return "non_operational"

        return "unknown"

    def _get_subnet_az(
        self,
        subnet_id: str,
    ):

        if not subnet_id:
            return None

        try:

            response = (
                self.ec2.describe_subnets(
                    SubnetIds=[
                        subnet_id
                    ]
                )
            )

        except Exception:

            return None

        subnets = response.get(
            "Subnets",
            [],
        )

        if not subnets:
            return None

        return subnets[0].get(
            "AvailabilityZone"
        )

    @staticmethod
    def _tags(
        tags: List[Dict[str, str]],
    ) -> Dict[str, str]:

        return {
            tag["Key"]: tag.get("Value")
            for tag in tags
            if tag.get("Key")
        }