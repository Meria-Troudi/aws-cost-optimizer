"""
AWS NAT Gateway Collector.

Collects:

- NAT Gateway identity
- NAT Gateway configuration
- CloudWatch operational observations
- Network relationships
- Route dependencies
- Same-AZ / cross-AZ topology
- VPC endpoint relationships
- Profile-driven optimization evidence

The collector does not make optimization decisions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register

from collectors.metrics.cloudwatch import CloudWatchMetricCollector
from collectors.network.topology import NetworkTopologyCollector
from collectors.network.relationships import NetworkRelationshipResolver

from aws_cost_optimizer.analysis.metrics import (
    metric_has_observed_data,
    metric_is_sum,
    metric_numeric_value,
    metric_sum_value,
)


@register
class NatGatewayCollector(BaseCollector):

    key = "nat_gateway"
    resource_type = "nat_gateway"

    def __init__(
        self,
        scan,
        region: Optional[str] = None,
        profile: Optional[dict] = None,
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

        self.network_collector = NetworkTopologyCollector(
            self.region
        )

        self.metric_collector = CloudWatchMetricCollector(
            self.cloudwatch
        )

        self._subnet_az_cache: dict[
            str,
            Optional[str],
        ] = {}

    # ==================================================================
    # PROFILE
    # ==================================================================

    def _profile_section(
        self,
        name: str,
    ) -> dict[str, Any]:

        if not isinstance(
            self.profile,
            dict,
        ):
            return {}

        value = self.profile.get(
            name,
            {},
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    def _cloudwatch_profile(
        self,
    ) -> dict[str, Any]:

        observations = self._profile_section(
            "observations"
        )

        return self._dict(
            observations.get(
                "cloudwatch"
            )
        )

    def _metric_group(
        self,
        name: str,
    ) -> tuple[str, ...]:

        groups = self._profile_section(
            "metric_groups"
        )

        values = groups.get(
            name,
            [],
        )

        if not isinstance(
            values,
            list,
        ):
            return ()

        result: list[str] = []

        for value in values:

            text = str(
                value
            ).strip()

            if (
                text
                and text not in result
            ):
                result.append(
                    text
                )

        return tuple(
            result
        )

    def _traffic_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group(
            "traffic"
        )

    def _connection_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group(
            "connection"
        )

    def _error_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group(
            "error"
        )

    def _activity_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group(
            "activity"
        )

    # ==================================================================
    # DISCOVERY
    # ==================================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        paginator = self.ec2.get_paginator(
            "describe_nat_gateways"
        )

        resources: list[Dict[str, Any]] = []

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

        return str(
            resource["id"]
        )

    # ==================================================================
    # IDENTITY
    # ==================================================================

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

        state = nat.get(
            "State"
        )

        return {
            "name":
                tags.get(
                    "Name"
                )
                or resource["id"],

            "nat_gateway_id":
                resource["id"],

            "state":
                state,

            "state_category":
                self._state_category(
                    state
                ),

            "tags":
                tags,
        }

    # ==================================================================
    # CONFIGURATION
    # ==================================================================

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        nat = resource["raw"]

        addresses = (
            nat.get(
                "NatGatewayAddresses",
                [],
            )
            or []
        )

        address = (
            addresses[0]
            if addresses
            else {}
        )

        subnet_id = nat.get(
            "SubnetId"
        )

        availability_zone = (
            self._get_subnet_az(
                subnet_id
            )
        )

        connectivity_type = nat.get(
            "ConnectivityType"
        )

        return {
            "nat_gateway_id":
                nat.get(
                    "NatGatewayId"
                ),

            "vpc_id":
                nat.get(
                    "VpcId"
                ),

            "subnet_id":
                subnet_id,

            "availability_zone":
                availability_zone,

            "connectivity_type":
                connectivity_type,

            "availability_mode":
                nat.get(
                    "AvailabilityMode"
                ),

            "state":
                nat.get(
                    "State"
                ),

            "create_time":
                (
                    nat["CreateTime"].isoformat()
                    if nat.get("CreateTime")
                    else None
                ),

            "public_ip":
                address.get(
                    "PublicIp"
                ),

            "private_ip":
                address.get(
                    "PrivateIp"
                ),

            "elastic_ip_allocation_id":
                address.get(
                    "AllocationId"
                ),

            "network_interface_id":
                address.get(
                    "NetworkInterfaceId"
                ),

            "failure_code":
                nat.get(
                    "FailureCode"
                ),

            "failure_message":
                nat.get(
                    "FailureMessage"
                ),

            "address_count":
                len(
                    addresses
                ),

            "public":
                connectivity_type == "public",

            "private":
                connectivity_type == "private",
        }

    # ==================================================================
    # OBSERVATIONS
    # ==================================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        cloudwatch_profile = (
            self._cloudwatch_profile()
        )

        if not cloudwatch_profile:
            raise ValueError(
                "NAT Gateway profile must define "
                "observations.cloudwatch."
            )

        enabled = cloudwatch_profile.get(
            "enabled",
            True,
        )

        if enabled is False:
            return {
                "status":
                    "disabled",

                "derived":
                    {},

                "cloudwatch":
                    {},
            }

        metric_specs = cloudwatch_profile.get(
            "metrics",
            [],
        )

        if not isinstance(
            metric_specs,
            list,
        ):
            raise ValueError(
                "NAT Gateway profile "
                "observations.cloudwatch.metrics "
                "must be a list."
            )

        if not metric_specs:
            raise ValueError(
                "NAT Gateway profile does not "
                "define any CloudWatch metrics."
            )

        namespace = str(
            cloudwatch_profile.get(
                "namespace"
            )
            or "AWS/NATGateway"
        ).strip()

        requested_period = int(
            cloudwatch_profile.get(
                "period",
                3600,
            )
        )

        start, end = (
            self.get_analysis_period()
        )

        dimensions = [
            {
                "Name":
                    "NatGatewayId",

                "Value":
                    resource["id"],
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

        metrics: Dict[str, Any] = {}

        for result in results:

            metric_name = result.get(
                "metric_name"
            )

            if metric_name:
                metrics[
                    metric_name
                ] = result

        effective_period = (
            results[0].get(
                "effective_period",
                requested_period,
            )
            if results
            else requested_period
        )

        derived = (
            self._build_derived_data(
                metrics
            )
        )

        return {
            "status":
                "ok",

            "cloudwatch": {
                "namespace":
                    namespace,

                "requested_period":
                    requested_period,

                "effective_period":
                    effective_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions":
                    dimensions,

                "metrics":
                    metrics,
            },

            "derived":
                derived,
        }

    # ==================================================================
    # DERIVED DATA
    # ==================================================================

    def _build_derived_data(
        self,
        metrics_dict: Dict[str, Any],
    ) -> Dict[str, Any]:

        traffic_metrics = (
            self._traffic_metrics()
        )

        connection_metrics = (
            self._connection_metrics()
        )

        error_metrics = (
            self._error_metrics()
        )

        activity_metrics = (
            self._activity_metrics()
        )

        if not traffic_metrics:
            raise ValueError(
                "NAT Gateway profile must define "
                "metric_groups.traffic."
            )

        if not connection_metrics:
            raise ValueError(
                "NAT Gateway profile must define "
                "metric_groups.connection."
            )

        if not error_metrics:
            raise ValueError(
                "NAT Gateway profile must define "
                "metric_groups.error."
            )

        if not activity_metrics:
            raise ValueError(
                "NAT Gateway profile must define "
                "metric_groups.activity."
            )

        # --------------------------------------------------------------
        # TRAFFIC
        # --------------------------------------------------------------

        traffic_values = {
            name:
                metric_sum_value(
                    metrics_dict.get(
                        name
                    )
                )
            for name in traffic_metrics
        }

        traffic_observed_data = {
            name:
                metric_has_observed_data(
                    metrics_dict.get(
                        name
                    )
                )
            for name in traffic_metrics
        }

        traffic_available = any(
            traffic_observed_data.values()
        )

        traffic_complete = all(
            traffic_observed_data.values()
        )

        traffic_semantics_valid = all(
            not traffic_observed_data[name]
            or metric_is_sum(
                metrics_dict.get(
                    name
                )
            )
            for name in traffic_metrics
        )

        observed_traffic_values = [
            float(value)
            for value
            in traffic_values.values()
            if value is not None
        ]

        # IMPORTANT:
        # These NAT metrics are directional views.
        # They are not treated as independent billing volumes.
        activity_bytes_indicator = (
            max(
                observed_traffic_values
            )
            if observed_traffic_values
            else None
        )

        activity_gib_indicator = (
            activity_bytes_indicator
            / (1024 ** 3)
            if activity_bytes_indicator
            is not None
            else None
        )

        traffic_observed = (
            activity_bytes_indicator > 0
            if activity_bytes_indicator
            is not None
            else None
        )

        traffic_zero = (
            traffic_complete
            and traffic_semantics_valid
            and bool(
                traffic_values
            )
            and all(
                value is not None
                and value == 0
                for value
                in traffic_values.values()
            )
        )

        # --------------------------------------------------------------
        # CONNECTIONS
        # --------------------------------------------------------------

        connection_values = {
            name:
                metric_numeric_value(
                    metrics_dict.get(
                        name
                    )
                )
            for name in connection_metrics
        }

        connection_observed_data = {
            name:
                metric_has_observed_data(
                    metrics_dict.get(
                        name
                    )
                )
            for name in connection_metrics
        }

        connection_available = any(
            connection_observed_data.values()
        )

        connection_complete = all(
            connection_observed_data.values()
        )

        observed_connection_values = [
            float(value)
            for value
            in connection_values.values()
            if value is not None
        ]

        connection_observed = (
            any(
                value > 0
                for value
                in observed_connection_values
            )
            if connection_available
            else None
        )

        # --------------------------------------------------------------
        # ACTIVITY
        # --------------------------------------------------------------

        activity_values = {}

        for name in activity_metrics:

            activity_values[name] = (
                metric_numeric_value(
                    metrics_dict.get(
                        name
                    )
                )
            )

        observed_activity_values = [
            value
            for value
            in activity_values.values()
            if value is not None
        ]

        activity_available = bool(
            observed_activity_values
        )

        activity_zero = (
            activity_available
            and all(
                value == 0
                for value
                in observed_activity_values
            )
        )

        activity_observed = (
            any(
                value > 0
                for value
                in observed_activity_values
            )
            if activity_available
            else None
        )

        # --------------------------------------------------------------
        # ERRORS
        # --------------------------------------------------------------

        error_values = {
            name:
                metric_sum_value(
                    metrics_dict.get(
                        name
                    )
                )
            for name in error_metrics
        }

        packet_drops = error_values.get(
            "PacketsDropCount"
        )

        port_allocation_errors = error_values.get(
            "ErrorPortAllocation"
        )

        idle_timeouts = error_values.get(
            "IdleTimeoutCount"
        )

        errors_available = any(
            value is not None
            for value
            in error_values.values()
        )

        # --------------------------------------------------------------
        # METADATA
        # --------------------------------------------------------------

        return {
            "metric_groups": {
                "traffic":
                    list(
                        traffic_metrics
                    ),

                "connection":
                    list(
                        connection_metrics
                    ),

                "error":
                    list(
                        error_metrics
                    ),

                "activity":
                    list(
                        activity_metrics
                    ),
            },

            "traffic": {
                "bytes_out_to_destination":
                    traffic_values.get(
                        "BytesOutToDestination"
                    ),

                "bytes_out_to_source":
                    traffic_values.get(
                        "BytesOutToSource"
                    ),

                "bytes_in_from_source":
                    traffic_values.get(
                        "BytesInFromSource"
                    ),

                "bytes_in_from_destination":
                    traffic_values.get(
                        "BytesInFromDestination"
                    ),

                "activity_bytes_indicator":
                    activity_bytes_indicator,

                "activity_gib_indicator":
                    activity_gib_indicator,

                "available":
                    traffic_available,

                "complete":
                    traffic_complete,

                "observed":
                    traffic_observed,

                "zero_activity":
                    traffic_zero,

                "metric_observation":
                    traffic_observed_data,
            },

            "connections": {
                "active":
                    connection_values.get(
                        "ActiveConnectionCount"
                    ),

                "attempts":
                    connection_values.get(
                        "ConnectionAttemptCount"
                    ),

                "established":
                    connection_values.get(
                        "ConnectionEstablishedCount"
                    ),

                "available":
                    connection_available,

                "complete":
                    connection_complete,

                "observed":
                    connection_observed,

                "metric_observation":
                    connection_observed_data,
            },

            "activity": {
                "observed":
                    activity_observed,

                "zero":
                    activity_zero,

                "traffic_observed":
                    traffic_observed,

                "connection_observed":
                    connection_observed,

                "available":
                    activity_available,
            },

            "errors": {
                "packet_drops":
                    packet_drops,

                "port_allocation_errors":
                    port_allocation_errors,

                "idle_timeouts":
                    idle_timeouts,

                "available":
                    errors_available,
            },

            "semantics": {
                "traffic_source":
                    "CloudWatch",

                "traffic_is_billing_usage":
                    False,

                "connection_metrics_are_billing_usage":
                    False,

                "traffic_value_requires_sum_statistic":
                    True,

                "traffic_semantics_valid":
                    traffic_semantics_valid,

                "activity_indicator_label":
                    "observed_directional_traffic_bytes",

                "purpose":
                    "operational_activity_observation",

                "missing_is_zero":
                    False,
            },
        }

    # ==================================================================
    # TOPOLOGY
    # ==================================================================

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = collected_resource.get(
            "configuration",
            {},
        )

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        vpc_id = configuration.get(
            "vpc_id"
        )

        nat_id = resource.get(
            "id"
        )

        if not vpc_id:
            return {
                "status":
                    "incomplete",

                "reason":
                    "VPC ID not available",
            }

        if not nat_id:
            return {
                "status":
                    "incomplete",

                "reason":
                    "NAT Gateway ID not available",
            }

        topology = (
            self.network_collector.collect(
                vpc_id=vpc_id,
                resource_type=self.resource_type,
                resource_id=nat_id,
            )
        )

        if topology.get(
            "status"
        ) != "ok":
            return topology

        resolver = (
            NetworkRelationshipResolver(
                topology
            )
        )

        nat_routes = (
            resolver.routes_targeting(
                "nat_gateway",
                nat_id,
            )
        )

        route_dependent_subnet_ids = sorted(
            {
                route.get(
                    "subnet_id"
                )
                for route in nat_routes
                if route.get(
                    "subnet_id"
                )
            }
        )

        route_dependent_route_table_ids = sorted(
            {
                route.get(
                    "route_table_id"
                )
                for route in nat_routes
                if route.get(
                    "route_table_id"
                )
            }
        )

        route_dependent_subnets = [
            subnet
            for subnet in (
                resolver.subnet(
                    subnet_id
                )
                for subnet_id
                in route_dependent_subnet_ids
            )
            if subnet
        ]

        subnet_profile_index = {
            profile.get(
                "subnet_id"
            ):
                profile
            for profile in topology.get(
                "subnet_profiles",
                [],
            )
            if (
                isinstance(
                    profile,
                    dict,
                )
                and profile.get(
                    "subnet_id"
                )
            )
        }

        dependent_subnet_profiles = [
            subnet_profile_index[subnet_id]
            for subnet_id
            in route_dependent_subnet_ids
            if subnet_id
            in subnet_profile_index
        ]

        if not dependent_subnet_profiles:

            dependent_subnet_profiles = [
                {
                    "subnet_id":
                        subnet.get(
                            "subnet_id"
                        ),

                    "availability_zone":
                        subnet.get(
                            "availability_zone"
                        ),

                    "route_table_id":
                        resolver.route_table_id_for_subnet(
                            subnet.get(
                                "subnet_id"
                            )
                        ),
                }
                for subnet
                in route_dependent_subnets
                if subnet.get(
                    "subnet_id"
                )
            ]

        nat_az = configuration.get(
            "availability_zone"
        )

        dependent_azs = sorted(
            {
                profile.get(
                    "availability_zone"
                )
                for profile
                in dependent_subnet_profiles
                if profile.get(
                    "availability_zone"
                )
            }
        )

        cross_az_subnets = sorted(
            {
                profile.get(
                    "subnet_id"
                )
                for profile
                in dependent_subnet_profiles
                if (
                    profile.get(
                        "subnet_id"
                    )
                    and profile.get(
                        "availability_zone"
                    )
                    and nat_az
                    and profile.get(
                        "availability_zone"
                    ) != nat_az
                )
            }
        )

        same_az_subnets = sorted(
            {
                profile.get(
                    "subnet_id"
                )
                for profile
                in dependent_subnet_profiles
                if (
                    profile.get(
                        "subnet_id"
                    )
                    and profile.get(
                        "availability_zone"
                    )
                    and nat_az
                    and profile.get(
                        "availability_zone"
                    ) == nat_az
                )
            }
        )

        endpoints = topology.get(
            "vpc_endpoints",
            [],
        )

        if not isinstance(
            endpoints,
            list,
        ):
            endpoints = []

        relevant_endpoints = (
            self._find_relevant_endpoints(
                endpoints=endpoints,
                nat_routes=nat_routes,
                resolver=resolver,
            )
        )

        endpoint_summary = (
            self._build_endpoint_summary(
                relevant_endpoints
            )
        )

        nat_route_summary = (
            self._build_nat_route_summary(
                nat_routes
            )
        )

        route_targets = topology.get(
            "route_targets",
            {},
        )

        if not isinstance(
            route_targets,
            dict,
        ):
            route_targets = {}

        all_routes = topology.get(
            "routes",
            [],
        )

        if not isinstance(
            all_routes,
            list,
        ):
            all_routes = []

        return {
            "status":
                "ok",

            "vpc_id":
                vpc_id,

            "nat_gateway_id":
                nat_id,

            "nat_subnet":
                configuration.get(
                    "subnet_id"
                ),

            "nat_availability_zone":
                nat_az,

            "route_dependency": {
                "kind":
                    "configuration_route_dependency",

                "description":
                    (
                        "Subnets whose effective route tables "
                        "contain a route targeting this NAT Gateway."
                    ),
            },

            "route_dependent_subnet_ids":
                route_dependent_subnet_ids,

            "route_dependent_subnets":
                route_dependent_subnets,

            "route_dependent_subnet_profiles":
                dependent_subnet_profiles,

            "route_dependent_route_table_ids":
                route_dependent_route_table_ids,

            "nat_routes":
                nat_routes,

            "vpc_endpoints":
                endpoints,

            "relevant_endpoints":
                relevant_endpoints,

            "endpoint_summary":
                endpoint_summary,

            "same_az_subnets":
                same_az_subnets,

            "cross_az_subnets":
                cross_az_subnets,

            "route_targets":
                route_targets,

            "network_summary": {
                "vpc":
                    topology.get(
                        "vpc"
                    ),

                "subnet_count":
                    len(
                        topology.get(
                            "subnets",
                            [],
                        )
                    ),

                "route_table_count":
                    len(
                        topology.get(
                            "route_tables",
                            [],
                        )
                    ),

                "route_count":
                    len(
                        all_routes
                    ),

                "effective_route_count":
                    len(
                        topology.get(
                            "effective_routes",
                            [],
                        )
                    ),

                "endpoint_count":
                    len(
                        endpoints
                    ),
            },

            "summary": {
                "vpc_id":
                    vpc_id,

                "nat_subnet":
                    configuration.get(
                        "subnet_id"
                    ),

                "nat_availability_zone":
                    nat_az,

                "connectivity_type":
                    configuration.get(
                        "connectivity_type"
                    ),

                "availability_mode":
                    configuration.get(
                        "availability_mode"
                    ),

                "route_dependent_subnet_count":
                    len(
                        route_dependent_subnet_ids
                    ),

                "route_dependent_route_table_count":
                    len(
                        route_dependent_route_table_ids
                    ),

                "nat_route_count":
                    len(
                        nat_routes
                    ),

                "route_dependent_availability_zones":
                    dependent_azs,

                "same_az_subnet_count":
                    len(
                        same_az_subnets
                    ),

                "cross_az_subnet_count":
                    len(
                        cross_az_subnets
                    ),

                "has_same_az_route_dependency":
                    bool(
                        same_az_subnets
                    ),

                "has_cross_az_route_dependency":
                    bool(
                        cross_az_subnets
                    ),

                "vpc_endpoint_count":
                    len(
                        endpoints
                    ),

                "relevant_endpoint_count":
                    len(
                        relevant_endpoints
                    ),

                "has_s3_endpoint_on_route_dependent_tables":
                    endpoint_summary.get(
                        "has_s3",
                        False,
                    ),

                "has_dynamodb_endpoint_on_route_dependent_tables":
                    endpoint_summary.get(
                        "has_dynamodb",
                        False,
                    ),

                "has_ecr_endpoint_on_route_dependent_tables":
                    endpoint_summary.get(
                        "has_ecr",
                        False,
                    ),

                "relevant_endpoint_services":
                    endpoint_summary.get(
                        "services",
                        [],
                    ),

                "has_blackhole_routes":
                    nat_route_summary.get(
                        "has_blackhole_routes",
                        False,
                    ),

                "blackhole_route_count":
                    nat_route_summary.get(
                        "blackhole_route_count",
                        0,
                    ),
            },
        }

    # ==================================================================
    # OPTIMIZATION EVIDENCE
    # ==================================================================

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._dict(
            collected_resource.get(
                "identity"
            )
        )

        configuration = self._dict(
            collected_resource.get(
                "configuration"
            )
        )

        observations = self._dict(
            collected_resource.get(
                "observations"
            )
        )

        topology = self._dict(
            collected_resource.get(
                "topology"
            )
        )

        derived = self._dict(
            observations.get(
                "derived"
            )
        )

        traffic = self._dict(
            derived.get(
                "traffic"
            )
        )

        connections = self._dict(
            derived.get(
                "connections"
            )
        )

        errors = self._dict(
            derived.get(
                "errors"
            )
        )

        activity = self._dict(
            derived.get(
                "activity"
            )
        )

        semantics = self._dict(
            derived.get(
                "semantics"
            )
        )

        summary = self._dict(
            topology.get(
                "summary"
            )
        )

        endpoint_summary = self._dict(
            topology.get(
                "endpoint_summary"
            )
        )

        route_summary = self._dict(
            topology.get(
                "route_summary"
            )
        )

        available = {
            "configuration": {
                "nat_gateway_id":
                    configuration.get(
                        "nat_gateway_id"
                    ),

                "connectivity_type":
                    configuration.get(
                        "connectivity_type"
                    ),

                "availability_mode":
                    configuration.get(
                        "availability_mode"
                    ),

                "availability_zone":
                    configuration.get(
                        "availability_zone"
                    ),

                "vpc_id":
                    configuration.get(
                        "vpc_id"
                    ),

                "subnet_id":
                    configuration.get(
                        "subnet_id"
                    ),

                "state":
                    configuration.get(
                        "state"
                    ),
            },

            "activity": {
                "traffic_available":
                    traffic.get(
                        "available"
                    ),

                "traffic_complete":
                    traffic.get(
                        "complete"
                    ),

                "traffic_observed":
                    traffic.get(
                        "observed"
                    ),

                "traffic_zero":
                    traffic.get(
                        "zero_activity"
                    ),

                "activity_bytes_indicator":
                    traffic.get(
                        "activity_bytes_indicator"
                    ),

                "activity_gib_indicator":
                    traffic.get(
                        "activity_gib_indicator"
                    ),

                "bytes_in_from_source":
                    traffic.get(
                        "bytes_in_from_source"
                    ),

                "bytes_in_from_destination":
                    traffic.get(
                        "bytes_in_from_destination"
                    ),

                "bytes_out_to_destination":
                    traffic.get(
                        "bytes_out_to_destination"
                    ),

                "bytes_out_to_source":
                    traffic.get(
                        "bytes_out_to_source"
                    ),

                "connection_metrics_available":
                    connections.get(
                        "available"
                    ),

                "connection_observed":
                    connections.get(
                        "observed"
                    ),

                "activity_observed":
                    activity.get(
                        "observed"
                    ),

                "packet_drops":
                    errors.get(
                        "packet_drops"
                    ),

                "port_allocation_errors":
                    errors.get(
                        "port_allocation_errors"
                    ),

                "idle_timeouts":
                    errors.get(
                        "idle_timeouts"
                    ),
            },

            "network": {
                "route_dependent_subnet_count":
                    summary.get(
                        "route_dependent_subnet_count",
                        0,
                    ),

                "route_dependent_route_table_count":
                    summary.get(
                        "route_dependent_route_table_count",
                        0,
                    ),

                "nat_route_count":
                    summary.get(
                        "nat_route_count",
                        0,
                    ),

                "same_az_subnet_count":
                    summary.get(
                        "same_az_subnet_count",
                        0,
                    ),

                "cross_az_subnet_count":
                    summary.get(
                        "cross_az_subnet_count",
                        0,
                    ),

                "has_same_az_route_dependency":
                    summary.get(
                        "has_same_az_route_dependency",
                        False,
                    ),

                "has_cross_az_route_dependency":
                    summary.get(
                        "has_cross_az_route_dependency",
                        False,
                    ),

                "has_s3_endpoint_on_route_dependent_tables":
                    summary.get(
                        "has_s3_endpoint_on_route_dependent_tables",
                        False,
                    ),

                "has_dynamodb_endpoint_on_route_dependent_tables":
                    summary.get(
                        "has_dynamodb_endpoint_on_route_dependent_tables",
                        False,
                    ),

                "has_ecr_endpoint_on_route_dependent_tables":
                    summary.get(
                        "has_ecr_endpoint_on_route_dependent_tables",
                        False,
                    ),

                "relevant_endpoint_services":
                    endpoint_summary.get(
                        "services",
                        [],
                    ),

                "relevant_endpoint_count":
                    summary.get(
                        "relevant_endpoint_count",
                        0,
                    ),

                "has_blackhole_routes":
                    route_summary.get(
                        "has_blackhole_routes",
                        False,
                    ),

                "blackhole_route_count":
                    route_summary.get(
                        "blackhole_route_count",
                        0,
                    ),
            },
        }

        optimization_profile = (
            self._profile_section(
                "optimization_evidence"
            )
        )

        enabled = optimization_profile.get(
            "enabled",
            False,
        )

        if enabled is not True:
            return self._default_optimization_evidence(
                resource=resource,
                identity=identity,
                available=available,
                observations=observations,
                topology=topology,
                semantics=semantics,
            )

        sections = optimization_profile.get(
            "sections",
            {},
        )

        if not isinstance(
            sections,
            dict,
        ):
            return self._default_optimization_evidence(
                resource=resource,
                identity=identity,
                available=available,
                observations=observations,
                topology=topology,
                semantics=semantics,
            )

        result: Dict[str, Any] = {
            "resource": {
                "id":
                    resource.get(
                        "id"
                    ),

                "name":
                    identity.get(
                        "name"
                    ),

                "state":
                    identity.get(
                        "state"
                    ),

                "state_category":
                    identity.get(
                        "state_category"
                    ),
            }
        }

        for section_name, fields in sections.items():

            if not isinstance(
                fields,
                list,
            ):
                continue

            source = available.get(
                section_name,
                {},
            )

            if not isinstance(
                source,
                dict,
            ):
                continue

            result[
                section_name
            ] = {
                field:
                    source.get(
                        field
                    )
                for field
                in fields
                if field in source
            }

        result["data_quality"] = {
            "cloudwatch_available":
                bool(
                    self._dict(
                        observations.get(
                            "cloudwatch"
                        )
                    ).get(
                        "metrics",
                        {},
                    )
                ),

            "traffic_available":
                traffic.get(
                    "available"
                ),

            "traffic_complete":
                traffic.get(
                    "complete"
                ),

            "connection_data_available":
                connections.get(
                    "available"
                ),

            "activity_evidence_available":
                bool(
                    traffic.get(
                        "available"
                    )
                    or connections.get(
                        "available"
                    )
                ),

            "topology_available":
                topology.get(
                    "status"
                ) == "ok",

            "traffic_semantics_valid":
                semantics.get(
                    "traffic_semantics_valid"
                ),

            "missing_is_zero":
                False,
        }

        return result

    # ==================================================================
    # DEFAULT OPTIMIZATION EVIDENCE
    # ==================================================================

    @staticmethod
    def _default_optimization_evidence(
        resource: Dict[str, Any],
        identity: Dict[str, Any],
        available: Dict[str, Any],
        observations: Dict[str, Any],
        topology: Dict[str, Any],
        semantics: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "resource": {
                "id":
                    resource.get(
                        "id"
                    ),

                "name":
                    identity.get(
                        "name"
                    ),

                "state":
                    identity.get(
                        "state"
                    ),

                "state_category":
                    identity.get(
                        "state_category"
                    ),
            },

            **{
                key: dict(
                    value
                )
                for key, value
                in available.items()
                if isinstance(
                    value,
                    dict,
                )
            },

            "data_quality": {
                "cloudwatch_available":
                    bool(
                        NatGatewayCollector._dict(
                            observations.get(
                                "cloudwatch"
                            )
                        ).get(
                            "metrics",
                            {},
                        )
                    ),

                "topology_available":
                    topology.get(
                        "status"
                    ) == "ok",

                "traffic_semantics_valid":
                    semantics.get(
                        "traffic_semantics_valid"
                    ),

                "missing_is_zero":
                    False,
            },
        }

    # ==================================================================
    # ROUTE SUMMARY
    # ==================================================================

    @staticmethod
    def _build_nat_route_summary(
        nat_routes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        azs = {
            route.get(
                "availability_zone"
            )
            for route in nat_routes
            if route.get(
                "availability_zone"
            )
        }

        route_states: dict[str, int] = {}
        route_classes: dict[str, int] = {}

        default_route_count = 0
        blackhole_route_count = 0

        for route in nat_routes:

            state = route.get(
                "state"
            )

            if state:

                route_states[state] = (
                    route_states.get(
                        state,
                        0,
                    )
                    + 1
                )

            route_class = route.get(
                "route_class"
            )

            if route_class:

                route_classes[route_class] = (
                    route_classes.get(
                        route_class,
                        0,
                    )
                    + 1
                )

            if route.get(
                "is_default_route"
            ):
                default_route_count += 1

            if state == "blackhole":
                blackhole_route_count += 1

        dependent_subnet_ids = {
            route.get(
                "subnet_id"
            )
            for route in nat_routes
            if route.get(
                "subnet_id"
            )
        }

        dependent_route_table_ids = {
            route.get(
                "route_table_id"
            )
            for route in nat_routes
            if route.get(
                "route_table_id"
            )
        }

        return {
            "route_count":
                len(
                    nat_routes
                ),

            "route_dependent_subnet_count":
                len(
                    dependent_subnet_ids
                ),

            "route_dependent_route_table_count":
                len(
                    dependent_route_table_ids
                ),

            "availability_zones":
                sorted(
                    azs
                ),

            "route_states":
                route_states,

            "route_classes":
                route_classes,

            "default_route_count":
                default_route_count,

            "blackhole_route_count":
                blackhole_route_count,

            "has_blackhole_routes":
                blackhole_route_count > 0,
        }

    # ==================================================================
    # ENDPOINT RELATIONSHIPS
    # ==================================================================

    @staticmethod
    def _find_relevant_endpoints(
        endpoints: List[Dict[str, Any]],
        nat_routes: List[Dict[str, Any]],
        resolver: NetworkRelationshipResolver,
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

        result: list[Dict[str, Any]] = []

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
                or []
            )

            endpoint_subnets = set(
                endpoint.get(
                    "subnet_ids",
                    [],
                )
                or []
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

                gateway_routes = (
                    resolver.routes_targeting_vpc_endpoint(
                        endpoint_id
                    )
                )

                gateway_route_table_ids = {
                    route.get(
                        "route_table_id"
                    )
                    for route
                    in gateway_routes
                    if route.get(
                        "route_table_id"
                    )
                }

                shared_route_tables = (
                    gateway_route_table_ids
                    & route_table_ids
                )

                relevant = bool(
                    shared_route_tables
                )

                relationship_kind = (
                    "gateway_endpoint_route_table_overlap"
                    if relevant
                    else "none"
                )

            elif endpoint_type == "Interface":

                relevant = bool(
                    shared_subnets
                )

                relationship_kind = (
                    "interface_endpoint_subnet_overlap"
                    if relevant
                    else "none"
                )

            else:

                relevant = bool(
                    shared_route_tables
                    or shared_subnets
                )

                relationship_kind = (
                    "network_overlap"
                    if relevant
                    else "none"
                )

            if not relevant:
                continue

            result.append(
                {
                    "vpc_endpoint_id":
                        endpoint_id,

                    "service_name":
                        endpoint.get(
                            "service_name"
                        ),

                    "endpoint_type":
                        endpoint_type,

                    "route_table_ids":
                        sorted(
                            shared_route_tables
                        ),

                    "subnet_ids":
                        sorted(
                            shared_subnets
                        ),

                    "applies_to_route_dependent_tables":
                        bool(
                            shared_route_tables
                        ),

                    "applies_to_route_dependent_subnets":
                        bool(
                            shared_subnets
                        ),

                    "relationship_kind":
                        relationship_kind,

                    "requester_managed":
                        endpoint.get(
                            "requester_managed"
                        ),
                }
            )

        return result

    @staticmethod
    def _build_endpoint_summary(
        endpoints: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        services: set[str] = set()

        has_s3 = False
        has_dynamodb = False
        has_ecr = False

        gateway_count = 0
        interface_count = 0

        for endpoint in endpoints:

            service = str(
                endpoint.get(
                    "service_name",
                    "",
                )
                or ""
            ).lower()

            if service:
                services.add(
                    service
                )

            endpoint_type = endpoint.get(
                "endpoint_type"
            )

            if endpoint_type == "Gateway":
                gateway_count += 1

            elif endpoint_type == "Interface":
                interface_count += 1

            if "s3" in service:
                has_s3 = True

            if "dynamodb" in service:
                has_dynamodb = True

            if "ecr" in service:
                has_ecr = True

        return {
            "services":
                sorted(
                    services
                ),

            "has_s3":
                has_s3,

            "has_dynamodb":
                has_dynamodb,

            "has_ecr":
                has_ecr,

            "gateway_count":
                gateway_count,

            "interface_count":
                interface_count,
        }

    # ==================================================================
    # HELPERS
    # ==================================================================

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _state_category(
        state: Optional[str],
    ) -> str:

        if state == "available":
            return "operational"

        if state == "pending":
            return "transitional"

        if state in {
            "failed",
            "deleting",
            "deleted",
        }:
            return "non_operational"

        return "unknown"

    def _get_subnet_az(
        self,
        subnet_id: Optional[str],
    ) -> Optional[str]:

        if not subnet_id:
            return None

        if (
            subnet_id
            in self._subnet_az_cache
        ):
            return (
                self._subnet_az_cache[
                    subnet_id
                ]
            )

        try:

            response = (
                self.ec2.describe_subnets(
                    SubnetIds=[
                        subnet_id
                    ]
                )
            )

        except Exception:

            self._subnet_az_cache[
                subnet_id
            ] = None

            return None

        subnets = response.get(
            "Subnets",
            [],
        )

        if not subnets:

            self._subnet_az_cache[
                subnet_id
            ] = None

            return None

        availability_zone = (
            subnets[0].get(
                "AvailabilityZone"
            )
        )

        self._subnet_az_cache[
            subnet_id
        ] = availability_zone

        return availability_zone

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
                tag.get(
                    "Value"
                )
            for tag in tags
            if (
                isinstance(
                    tag,
                    dict,
                )
                and tag.get(
                    "Key"
                )
            )
        }