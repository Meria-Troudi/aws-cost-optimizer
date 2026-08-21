"""
AWS NAT Gateway collector.

Purpose
-------
Collect stable NAT Gateway evidence for cost optimization:

    identity
    configuration
    CloudWatch activity
    route dependency
    Availability Zone relationships
    NAT fleet architecture
    endpoint coverage
    optimization evidence

Important
---------
This collector does NOT attribute Cost Explorer spend to an individual
NAT Gateway.

CloudWatch traffic is operational evidence.

Billing attribution must come from the billing/reconciliation layer.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.metrics.cloudwatch import CloudWatchMetricCollector
from collection.registry import register
from collection.shared.relationships import NetworkRelationshipResolver
from collection.shared.topology import NetworkTopologyCollector

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

    DEFAULT_NAMESPACE = "AWS/NATGateway"
    DEFAULT_PERIOD = 3600

    TRAFFIC_GROUP = "traffic"
    CONNECTION_GROUP = "connection"
    ERROR_GROUP = "error"
    ACTIVITY_GROUP = "activity"

    def __init__(
        self,
        scan,
        region: Optional[str] = None,
        profile: Optional[dict] = None,
    ) -> None:

        super().__init__(
            scan=scan,
            region=region,
            profile=profile,
        )

        if not self.region:
            raise ValueError(
                "NAT Gateway collector requires a region."
            )

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = CloudWatchMetricCollector(
            self.cloudwatch
        )

        self.network_collector = NetworkTopologyCollector(
            self.region
        )

        self._subnet_az_cache: dict[
            str,
            Optional[str],
        ] = {}

        self._metrics_batch_cache: dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        # Complete NAT inventory for the current region.
        #
        # Used to understand:
        #
        #   VPC → NAT count
        #   VPC → NATs per AZ
        #   regional vs zonal NAT
        #   same-AZ alternatives
        self._nat_fleet: List[Dict[str, Any]] = []

        self._nat_fleet_by_vpc: dict[
            str,
            list[Dict[str, Any]],
        ] = {}

        self._nat_by_id: dict[
            str,
            Dict[str, Any],
        ] = {}

    # ==============================================================
    # PROFILE
    # ==============================================================

    def _profile_section(
        self,
        name: str,
    ) -> dict[str, Any]:

        value = self.profile.get(
            name,
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def _cloudwatch_profile(
        self,
    ) -> dict[str, Any]:

        observations = self._profile_section(
            "observations"
        )

        value = observations.get(
            "cloudwatch",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
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

            if text and text not in result:
                result.append(text)

        return tuple(result)

    def _traffic_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group(
            self.TRAFFIC_GROUP
        )

    def _connection_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group(
            self.CONNECTION_GROUP
        )

    def _error_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group(
            self.ERROR_GROUP
        )

    def _activity_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group(
            self.ACTIVITY_GROUP
        )

    # ==============================================================
    # DISCOVERY
    # ==============================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        paginator = self.ec2.get_paginator(
            "describe_nat_gateways"
        )

        resources: list[
            Dict[str, Any]
        ] = []

        fleet: list[
            Dict[str, Any]
        ] = []

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

                nat_id = str(
                    nat_id
                )

                resource = {
                    "id": nat_id,
                    "raw": nat,
                }

                resources.append(
                    resource
                )

                normalized = (
                    self._normalize_nat_for_fleet(
                        nat
                    )
                )

                if normalized:
                    fleet.append(
                        normalized
                    )

        self._nat_fleet = fleet

        self._nat_by_id = {
            item["nat_gateway_id"]:
                item
            for item in fleet
            if item.get("nat_gateway_id")
        }

        by_vpc: dict[
            str,
            list[Dict[str, Any]],
        ] = defaultdict(list)

        for item in fleet:

            vpc_id = item.get(
                "vpc_id"
            )

            if vpc_id:
                by_vpc[
                    str(vpc_id)
                ].append(
                    item
                )

        self._nat_fleet_by_vpc = dict(
            by_vpc
        )

        self._prefetch_metrics_batch(
            resources
        )

        return resources

    # ==============================================================
    # CLOUDWATCH
    # ==============================================================

    def _prefetch_metrics_batch(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        profile = self._cloudwatch_profile()

        if not profile:
            return

        if profile.get(
            "enabled",
            True,
        ) is False:
            return

        metric_specs = profile.get(
            "metrics",
            [],
        )

        if not isinstance(
            metric_specs,
            list,
        ):
            return

        if not metric_specs:
            return

        namespace = str(
            profile.get(
                "namespace"
            )
            or self.DEFAULT_NAMESPACE
        ).strip()

        requested_period = (
            self._safe_period(
                profile.get(
                    "period",
                    self.DEFAULT_PERIOD,
                )
            )
        )

        try:

            start, end = (
                self.get_analysis_period()
            )

        except ValueError:

            return

        requests: list[
            Dict[str, Any]
        ] = []

        request_metadata: dict[
            str,
            Dict[str, Any],
        ] = {}

        for resource in resources:

            nat_id = resource.get(
                "id"
            )

            if not nat_id:
                continue

            raw = resource.get(
                "raw"
            )

            raw = (
                raw
                if isinstance(raw, dict)
                else {}
            )

            availability_mode = str(
                raw.get(
                    "AvailabilityMode"
                )
                or "zonal"
            ).lower()

            # ------------------------------------------------------
            # Zonal NAT
            # ------------------------------------------------------

            if availability_mode != "regional":

                query_key = str(
                    nat_id
                )

                requests.append(
                    {
                        "resource_key":
                            query_key,

                        "namespace":
                            namespace,

                        "dimensions": [
                            {
                                "Name":
                                    "NatGatewayId",

                                "Value":
                                    str(nat_id),
                            }
                        ],

                        "metric_specs":
                            metric_specs,
                    }
                )

                request_metadata[
                    query_key
                ] = {
                    "nat_gateway_id":
                        str(nat_id),

                    "availability_zone":
                        self._get_nat_primary_az(
                            raw
                        ),

                    "regional":
                        False,
                }

                continue

            # ------------------------------------------------------
            # Regional NAT
            #
            # AWS requires:
            #
            #   NatGatewayId
            #   AvailabilityZone
            #
            # Regional NAT can cover multiple AZs.
            # ------------------------------------------------------

            availability_zones = (
                self._get_nat_coverage_azs(
                    raw
                )
            )

            # If AWS does not expose the covered AZs yet, do not
            # silently invent them. Fall back to the subnet AZ only
            # for discovery context, but do not fabricate a metric
            # query for a missing AZ.
            if not availability_zones:

                continue

            for availability_zone in (
                availability_zones
            ):

                query_key = (
                    f"{nat_id}@@{availability_zone}"
                )

                requests.append(
                    {
                        "resource_key":
                            query_key,

                        "namespace":
                            namespace,

                        "dimensions": [
                            {
                                "Name":
                                    "NatGatewayId",

                                "Value":
                                    str(nat_id),
                            },
                            {
                                "Name":
                                    "AvailabilityZone",

                                "Value":
                                    str(
                                        availability_zone
                                    ),
                            },
                        ],

                        "metric_specs":
                            metric_specs,
                    }
                )

                request_metadata[
                    query_key
                ] = {
                    "nat_gateway_id":
                        str(nat_id),

                    "availability_zone":
                        str(
                            availability_zone
                        ),

                    "regional":
                        True,
                }

        if not requests:
            return

        raw_results = (
            self.metric_collector.collect_batch(
                requests,
                start=start,
                end=end,
                requested_period=requested_period,
            )
        )

        self._metrics_batch_cache = (
            self._normalize_metric_batch_results(
                raw_results,
                request_metadata,
            )
        )

    def _normalize_metric_batch_results(
        self,
        raw_results: Dict[
            str,
            List[Dict[str, Any]],
        ],
        request_metadata: Dict[
            str,
            Dict[str, Any],
        ],
    ) -> Dict[
        str,
        List[Dict[str, Any]],
    ]:

        grouped: dict[
            str,
            list[tuple[
                str,
                Dict[str, Any],
            ]],
        ] = defaultdict(list)

        for query_key, results in (
            raw_results or {}
        ).items():

            meta = request_metadata.get(
                query_key
            )

            if not meta:
                continue

            nat_id = meta.get(
                "nat_gateway_id"
            )

            if not nat_id:
                continue

            for result in results or []:

                if not isinstance(
                    result,
                    dict,
                ):
                    continue

                grouped[
                    str(nat_id)
                ].append(
                    (
                        str(query_key),
                        result,
                    )
                )

        final: dict[
            str,
            list[Dict[str, Any]],
        ] = {}

        for nat_id, entries in grouped.items():

            regional = any(
                request_metadata.get(
                    key,
                    {},
                ).get(
                    "regional"
                )
                is True
                for key, _ in entries
            )

            if not regional:

                final[
                    nat_id
                ] = [
                    result
                    for _, result in entries
                ]

                continue

            by_metric: dict[
                str,
                list[Dict[str, Any]],
            ] = defaultdict(list)

            for _, result in entries:

                metric_name = result.get(
                    "metric_name"
                )

                if not metric_name:
                    continue

                by_metric[
                    str(metric_name)
                ].append(
                    result
                )

            merged: list[
                Dict[str, Any]
            ] = []

            for metric_name, metric_results in (
                by_metric.items()
            ):

                merged.append(
                    self._merge_regional_metric_results(
                        nat_id=nat_id,
                        metric_name=metric_name,
                        results=metric_results,
                    )
                )

            final[
                nat_id
            ] = merged

        return final

    @staticmethod
    def _merge_regional_metric_results(
        *,
        nat_id: str,
        metric_name: str,
        results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        if not results:
            return {}

        first = results[0]

        statistic = str(
            first.get(
                "statistic"
            )
            or "Average"
        )

        unit = first.get(
            "unit"
        )

        observed_results = [
            result
            for result in results
            if result.get(
                "status"
            ) == "ok"
            and result.get(
                "has_data"
            ) is True
        ]

        # ----------------------------------------------------------
        # Aggregate the summary values without pretending that the
        # CloudWatch result is a directly billable resource amount.
        # ----------------------------------------------------------

        values = [
            float(result["value"])
            for result in observed_results
            if isinstance(
                result.get("value"),
                (int, float),
            )
        ]

        totals = [
            float(result["total"])
            for result in observed_results
            if isinstance(
                result.get("total"),
                (int, float),
            )
        ]

        averages = [
            float(result["average"])
            for result in observed_results
            if isinstance(
                result.get("average"),
                (int, float),
            )
        ]

        maximums = [
            float(result["maximum"])
            for result in observed_results
            if isinstance(
                result.get("maximum"),
                (int, float),
            )
        ]

        minimums = [
            float(result["minimum"])
            for result in observed_results
            if isinstance(
                result.get("minimum"),
                (int, float),
            )
        ]

        if statistic == "Sum":

            value = (
                sum(values)
                if values
                else None
            )

            total = (
                sum(totals)
                if totals
                else value
            )

            average = (
                sum(averages)
                / len(averages)
                if averages
                else None
            )

            maximum = (
                max(maximums)
                if maximums
                else value
            )

            minimum = (
                min(minimums)
                if minimums
                else value
            )

        elif statistic == "Maximum":

            value = (
                max(values)
                if values
                else None
            )

            total = value

            average = (
                sum(averages)
                / len(averages)
                if averages
                else value
            )

            maximum = (
                max(maximums)
                if maximums
                else value
            )

            minimum = (
                min(minimums)
                if minimums
                else value
            )

        elif statistic == "Minimum":

            value = (
                min(values)
                if values
                else None
            )

            total = value

            average = (
                sum(averages)
                / len(averages)
                if averages
                else value
            )

            maximum = (
                max(maximums)
                if maximums
                else value
            )

            minimum = (
                min(minimums)
                if minimums
                else value
            )

        else:

            # For Average metrics, equal-period values are averaged.
            value = (
                sum(values)
                / len(values)
                if values
                else None
            )

            total = (
                sum(totals)
                if totals
                else value
            )

            average = (
                sum(averages)
                / len(averages)
                if averages
                else value
            )

            maximum = (
                max(maximums)
                if maximums
                else value
            )

            minimum = (
                min(minimums)
                if minimums
                else value
            )

        coverage_values = [
            float(result["coverage_ratio"])
            for result in results
            if isinstance(
                result.get("coverage_ratio"),
                (int, float),
            )
        ]

        coverage_ratio = (
            min(coverage_values)
            if coverage_values
            else 0.0
        )

        coverage_percent = (
            coverage_ratio
            * 100.0
        )

        data_quality = (
            "complete"
            if coverage_ratio >= 0.95
            else "good"
            if coverage_ratio >= 0.80
            else "partial"
            if coverage_ratio >= 0.50
            else "poor"
            if coverage_ratio > 0
            else "no_data"
        )

        successful = bool(
            observed_results
        )

        return {
            **first,

            "metric_key":
                first.get(
                    "metric_key"
                )
                or metric_name,

            "metric_name":
                metric_name,

            "status":
                "ok"
                if successful
                else (
                    "error"
                    if any(
                        result.get(
                            "status"
                        )
                        == "error"
                        for result in results
                    )
                    else "no_data"
                ),

            "available":
                successful,

            "has_data":
                successful,

            "samples":
                max(
                    (
                        int(
                            result.get(
                                "samples",
                                0,
                            )
                            or 0
                        )
                        for result in results
                    ),
                    default=0,
                ),

            "datapoints":
                max(
                    (
                        int(
                            result.get(
                                "datapoints",
                                0,
                            )
                            or 0
                        )
                        for result in results
                    ),
                    default=0,
                ),

            "value":
                round(value, 6)
                if value is not None
                else None,

            "total":
                round(total, 6)
                if total is not None
                else None,

            "average":
                round(average, 6)
                if average is not None
                else None,

            "maximum":
                round(maximum, 6)
                if maximum is not None
                else None,

            "minimum":
                round(minimum, 6)
                if minimum is not None
                else None,

            "coverage_ratio":
                round(
                    coverage_ratio,
                    4,
                ),

            "coverage_percent":
                round(
                    coverage_percent,
                    2,
                ),

            "complete":
                coverage_ratio >= 0.95,

            "data_quality":
                data_quality,

            "unit":
                unit,

            "regional_aggregation":
                True,

            "availability_zones":
                sorted(
                    {
                        str(
                            result.get(
                                "dimensions",
                                []
                            )[-1].get(
                                "Value"
                            )
                        )
                        for result in results
                        if isinstance(
                            result.get(
                                "dimensions"
                            ),
                            list,
                        )
                        and result.get(
                            "dimensions"
                        )
                    }
                ),

            # The underlying CloudWatch results remain the source;
            # raw datapoint merging is intentionally not fabricated.
            "raw_datapoints":
                [],

            "error":
                (
                    next(
                        (
                            result.get(
                                "error"
                            )
                            for result in results
                            if result.get(
                                "error"
                            )
                        ),
                        None,
                    )
                    if not successful
                    else None
                ),
        }

    # ==============================================================
    # RESOURCE ID
    # ==============================================================

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return str(
            resource["id"]
        )

    # ==============================================================
    # IDENTITY
    # ==============================================================

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        nat = resource["raw"]

        state = nat.get(
            "State"
        )

        tags = self._tags(
            nat.get(
                "Tags",
                [],
            )
        )

        availability_mode = str(
            nat.get(
                "AvailabilityMode"
            )
            or "zonal"
        ).lower()

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

            "availability_mode":
                availability_mode,

            "regional":
                availability_mode == "regional",

            "connectivity_type":
                nat.get(
                    "ConnectivityType"
                ),

            "tags":
                tags,
        }

    # ==============================================================
    # CONFIGURATION
    # ==============================================================

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

        if not isinstance(
            addresses,
            list,
        ):
            addresses = []

        address = (
            addresses[0]
            if addresses
            and isinstance(
                addresses[0],
                dict,
            )
            else {}
        )

        subnet_id = nat.get(
            "SubnetId"
        )

        availability_mode = str(
            nat.get(
                "AvailabilityMode"
            )
            or "zonal"
        ).lower()

        covered_azs = (
            self._get_nat_coverage_azs(
                nat
            )
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
                self._get_nat_primary_az(
                    nat
                ),

            "availability_zones":
                covered_azs,

            "availability_mode":
                availability_mode,

            "regional":
                availability_mode == "regional",

            "auto_provision_zones":
                nat.get(
                    "AutoProvisionZones"
                ),

            "auto_scaling_ips":
                nat.get(
                    "AutoScalingIps"
                ),

            "connectivity_type":
                nat.get(
                    "ConnectivityType"
                ),

            "state":
                nat.get(
                    "State"
                ),

            "create_time":
                (
                    nat["CreateTime"].isoformat()
                    if nat.get(
                        "CreateTime"
                    )
                    else None
                ),

            "delete_time":
                (
                    nat["DeleteTime"].isoformat()
                    if nat.get(
                        "DeleteTime"
                    )
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
                len(addresses),

            "public":
                nat.get(
                    "ConnectivityType"
                )
                == "public",

            "private":
                nat.get(
                    "ConnectivityType"
                )
                == "private",
        }

    # ==============================================================
    # OBSERVATIONS
    # ==============================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        profile = self._cloudwatch_profile()

        if not profile:

            raise ValueError(
                "NAT Gateway profile must define "
                "observations.cloudwatch."
            )

        if profile.get(
            "enabled",
            True,
        ) is False:

            return {
                "status": "disabled",
                "cloudwatch": {},
                "derived": {},
            }

        metric_specs = profile.get(
            "metrics",
            [],
        )

        if not isinstance(
            metric_specs,
            list,
        ) or not metric_specs:

            raise ValueError(
                "NAT Gateway profile must define "
                "CloudWatch metrics."
            )

        namespace = str(
            profile.get(
                "namespace"
            )
            or self.DEFAULT_NAMESPACE
        ).strip()

        requested_period = (
            self._safe_period(
                profile.get(
                    "period",
                    self.DEFAULT_PERIOD,
                )
            )
        )

        start, end = (
            self.get_analysis_period()
        )

        resource_id = str(
            resource["id"]
        )

        results = (
            self._metrics_batch_cache.get(
                resource_id,
                [],
            )
        )

        metrics: Dict[
            str,
            Any,
        ] = {}

        for result in results:

            metric_name = result.get(
                "metric_name"
            )

            if metric_name:
                metrics[
                    str(metric_name)
                ] = result

        effective_periods = sorted(
            {
                result.get(
                    "effective_period"
                )
                for result in results
                if result.get(
                    "effective_period"
                ) is not None
            }
        )

        effective_period = (
            effective_periods[0]
            if len(effective_periods) == 1
            else None
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

                "effective_periods":
                    effective_periods,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions":
                    [
                        {
                            "Name":
                                "NatGatewayId",

                            "Value":
                                resource_id,
                        }
                    ],

                "metrics":
                    metrics,
            },

            "derived":
                derived,
        }

    # ==============================================================
    # DERIVED ACTIVITY
    # ==============================================================

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
                "NAT profile must define "
                "metric_groups.traffic."
            )

        # ----------------------------------------------------------
        # Traffic
        # ----------------------------------------------------------

        traffic_values = {
            name:
                metric_sum_value(
                    metrics_dict.get(name)
                )
            for name in traffic_metrics
        }

        traffic_observed = {
            name:
                metric_has_observed_data(
                    metrics_dict.get(name)
                )
            for name in traffic_metrics
        }

        traffic_available = any(
            traffic_observed.values()
        )

        traffic_complete = (
            bool(traffic_metrics)
            and all(
                traffic_observed.values()
            )
        )

        traffic_semantics_valid = all(
            not traffic_observed[name]
            or metric_is_sum(
                metrics_dict.get(name)
            )
            for name in traffic_metrics
        )

        observed_traffic_values = [
            float(value)
            for value in traffic_values.values()
            if value is not None
        ]

        # IMPORTANT:
        #
        # This remains a traffic indicator.
        # It is not a billing amount.
        directional_traffic_bytes = (
            max(
                observed_traffic_values
            )
            if observed_traffic_values
            else None
        )

        directional_traffic_gib = (
            directional_traffic_bytes
            / (1024 ** 3)
            if directional_traffic_bytes is not None
            else None
        )

        traffic_zero = (
            traffic_complete
            and traffic_semantics_valid
            and all(
                value is not None
                and value == 0
                for value in traffic_values.values()
            )
        )

        # ----------------------------------------------------------
        # Connections
        # ----------------------------------------------------------

        connection_values = {
            name:
                metric_numeric_value(
                    metrics_dict.get(name)
                )
            for name in connection_metrics
        }

        connection_observed = {
            name:
                metric_has_observed_data(
                    metrics_dict.get(name)
                )
            for name in connection_metrics
        }

        connection_available = any(
            connection_observed.values()
        )

        connection_complete = (
            bool(connection_metrics)
            and all(
                connection_observed.values()
            )
        )

        observed_connection_values = [
            float(value)
            for value in connection_values.values()
            if value is not None
        ]

        has_active_connection = (
            any(
                value > 0
                for value
                in observed_connection_values
            )
            if connection_available
            else None
        )

        connections_zero = (
            connection_complete
            and all(
                value is not None
                and value == 0
                for value
                in connection_values.values()
            )
        )

        # ----------------------------------------------------------
        # Errors
        # ----------------------------------------------------------

        error_values = {
            name:
                metric_sum_value(
                    metrics_dict.get(name)
                )
            for name in error_metrics
        }

        observed_error_values = {
            name: value
            for name, value
            in error_values.items()
            if value is not None
        }

        errors_available = bool(
            observed_error_values
        )

        # ----------------------------------------------------------
        # Generic activity
        # ----------------------------------------------------------

        activity_values = {
            name:
                (
                    metric_numeric_value(
                        metrics_dict.get(name)
                    )
                )
            for name in activity_metrics
        }

        observed_activity_values = [
            value
            for value in activity_values.values()
            if value is not None
        ]

        activity_available = bool(
            observed_activity_values
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

        # ----------------------------------------------------------
        # Peak metrics
        # ----------------------------------------------------------

        peak_bytes = (
            metric_numeric_value(
                metrics_dict.get(
                    "PeakBytesPerSecond"
                )
            )
        )

        peak_packets = (
            metric_numeric_value(
                metrics_dict.get(
                    "PeakPacketsPerSecond"
                )
            )
        )

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

                "directional_traffic_bytes":
                    directional_traffic_bytes,

                "directional_traffic_gib":
                    directional_traffic_gib,

                "available":
                    traffic_available,

                "complete":
                    traffic_complete,

                "observed":
                    (
                        directional_traffic_bytes is not None
                        and directional_traffic_bytes > 0
                    )
                    if directional_traffic_bytes is not None
                    else None,

                "zero":
                    traffic_zero,

                "metric_observation":
                    traffic_observed,
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
                    has_active_connection,

                "zero":
                    connections_zero,

                "metric_observation":
                    connection_observed,
            },

            "performance": {
                "peak_bytes_per_second":
                    peak_bytes,

                "peak_packets_per_second":
                    peak_packets,

                "available":
                    peak_bytes is not None
                    or peak_packets is not None,
            },

            "activity": {
                "observed":
                    activity_observed,

                "traffic_observed":
                    (
                        directional_traffic_bytes is not None
                        and directional_traffic_bytes > 0
                    )
                    if directional_traffic_bytes is not None
                    else None,

                "connection_observed":
                    has_active_connection,

                "available":
                    activity_available,
            },

            "errors": {
                "packet_drops":
                    error_values.get(
                        "PacketsDropCount"
                    ),

                "port_allocation_errors":
                    error_values.get(
                        "ErrorPortAllocation"
                    ),

                "idle_timeouts":
                    error_values.get(
                        "IdleTimeoutCount"
                    ),

                "available":
                    errors_available,
            },

            "semantics": {
                "traffic_source":
                    "CloudWatch",

                "traffic_is_billing_usage":
                    False,

                "connection_is_billing_usage":
                    False,

                "traffic_requires_sum_statistic":
                    True,

                "traffic_semantics_valid":
                    traffic_semantics_valid,

                "traffic_indicator":
                    "maximum_directional_traffic",

                "missing_is_zero":
                    False,
            },
        }

    # ==============================================================
    # TOPOLOGY
    # ==============================================================

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = self._dict(
            collected_resource.get(
                "configuration"
            )
        )

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
            for subnet_id
            in route_dependent_subnet_ids
            for subnet in [
                resolver.subnet(
                    subnet_id
                )
            ]
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

        # ----------------------------------------------------------
        # NAT AZ relationships
        # ----------------------------------------------------------

        nat_az = (
            configuration.get(
                "availability_zone"
            )
        )

        availability_mode = str(
            configuration.get(
                "availability_mode"
            )
            or "zonal"
        ).lower()

        covered_azs = (
            configuration.get(
                "availability_zones",
                [],
            )
            or []
        )

        if not isinstance(
            covered_azs,
            list,
        ):
            covered_azs = []

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

        # Regional NAT already spans supported AZs.
        # Therefore a subnet in another AZ is not, by itself,
        # evidence of the classic "cross-AZ NAT gateway" problem.
        cross_az_subnets = []

        same_az_subnets = []

        if availability_mode != "regional":

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
                        and nat_az
                        and profile.get(
                            "availability_zone"
                        )
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
                        and nat_az
                        and profile.get(
                            "availability_zone"
                        )
                        and profile.get(
                            "availability_zone"
                        ) == nat_az
                    )
                }
            )

        # ----------------------------------------------------------
        # NAT fleet architecture
        # ----------------------------------------------------------

        fleet_context = (
            self._build_nat_fleet_context(
                vpc_id=str(vpc_id),
                nat_id=str(nat_id),
                route_dependent_subnet_ids=(
                    route_dependent_subnet_ids
                ),
                dependent_subnet_profiles=(
                    dependent_subnet_profiles
                ),
            )
        )

        # ----------------------------------------------------------
        # Endpoints
        # ----------------------------------------------------------

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

        route_summary = (
            self._build_nat_route_summary(
                nat_routes
            )
        )

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

            "availability_mode":
                availability_mode,

            "covered_availability_zones":
                covered_azs,

            "route_dependent_subnet_ids":
                route_dependent_subnet_ids,

            "route_dependent_subnets":
                route_dependent_subnets,

            "route_dependent_subnet_profiles":
                dependent_subnet_profiles,

            "route_dependent_route_table_ids":
                route_dependent_route_table_ids,

            "dependent_availability_zones":
                dependent_azs,

            "nat_routes":
                nat_routes,

            "route_summary":
                route_summary,

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

            "fleet":
                fleet_context,

            "network_summary": {
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

                "endpoint_count":
                    len(endpoints),

                "nat_gateway_count_in_vpc":
                    fleet_context.get(
                        "nat_gateway_count",
                        0,
                    ),

                "operational_nat_gateway_count_in_vpc":
                    fleet_context.get(
                        "operational_nat_gateway_count",
                        0,
                    ),
            },

            "summary": {
                "route_dependent_subnet_count":
                    len(
                        route_dependent_subnet_ids
                    ),

                "route_dependent_route_table_count":
                    len(
                        route_dependent_route_table_ids
                    ),

                "nat_route_count":
                    len(nat_routes),

                "same_az_subnet_count":
                    len(same_az_subnets),

                "cross_az_subnet_count":
                    len(cross_az_subnets),

                "has_same_az_route_dependency":
                    bool(
                        same_az_subnets
                    ),

                "has_cross_az_route_dependency":
                    bool(
                        cross_az_subnets
                    ),

                "regional_nat":
                    availability_mode == "regional",

                "covered_az_count":
                    len(
                        covered_azs
                    ),

                "vpc_endpoint_count":
                    len(endpoints),

                "relevant_endpoint_count":
                    len(relevant_endpoints),

                "relevant_endpoint_services":
                    endpoint_summary.get(
                        "services",
                        [],
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

                "same_az_alternative_nat_count":
                    fleet_context.get(
                        "same_az_alternative_nat_count",
                        0,
                    ),

                "same_vpc_nat_count":
                    fleet_context.get(
                        "nat_gateway_count",
                        0,
                    ),

                "same_vpc_operational_nat_count":
                    fleet_context.get(
                        "operational_nat_gateway_count",
                        0,
                    ),
            },
        }

    # ==============================================================
    # NAT FLEET CONTEXT
    # ==============================================================

    def _build_nat_fleet_context(
        self,
        *,
        vpc_id: str,
        nat_id: str,
        route_dependent_subnet_ids: List[str],
        dependent_subnet_profiles: List[
            Dict[str, Any]
        ],
    ) -> Dict[str, Any]:

        nats = list(
            self._nat_fleet_by_vpc.get(
                vpc_id,
                [],
            )
        )

        operational = [
            nat
            for nat in nats
            if nat.get(
                "state"
            ) == "available"
        ]

        regional = [
            nat
            for nat in operational
            if nat.get(
                "availability_mode"
            ) == "regional"
        ]

        zonal = [
            nat
            for nat in operational
            if nat.get(
                "availability_mode"
            ) != "regional"
        ]

        az_counts: dict[
            str,
            int,
        ] = defaultdict(int)

        for nat in zonal:

            az = nat.get(
                "availability_zone"
            )

            if az:
                az_counts[
                    str(az)
                ] += 1

        current = (
            self._nat_by_id.get(
                nat_id,
                {},
            )
        )

        current_az = (
            current.get(
                "availability_zone"
            )
        )

        same_az_alternatives = [
            nat
            for nat in operational
            if (
                nat.get(
                    "nat_gateway_id"
                )
                != nat_id
                and
                nat.get(
                    "availability_mode"
                ) != "regional"
                and
                current_az
                and
                nat.get(
                    "availability_zone"
                ) == current_az
            )
        ]

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

        covered_by_operational_nat = {
            az: [
                nat.get(
                    "nat_gateway_id"
                )
                for nat in operational
                if (
                    nat.get(
                        "availability_mode"
                    ) == "regional"
                    or nat.get(
                        "availability_zone"
                    ) == az
                )
            ]
            for az in dependent_azs
        }

        return {
            "nat_gateway_count":
                len(nats),

            "operational_nat_gateway_count":
                len(operational),

            "regional_nat_gateway_count":
                len(regional),

            "zonal_nat_gateway_count":
                len(zonal),

            "nat_gateway_ids":
                sorted(
                    str(
                        nat.get(
                            "nat_gateway_id"
                        )
                    )
                    for nat in nats
                    if nat.get(
                        "nat_gateway_id"
                    )
                ),

            "operational_nat_gateway_ids":
                sorted(
                    str(
                        nat.get(
                            "nat_gateway_id"
                        )
                    )
                    for nat in operational
                    if nat.get(
                        "nat_gateway_id"
                    )
                ),

            "availability_zone_nat_counts":
                dict(
                    sorted(
                        az_counts.items()
                    )
                ),

            "dependent_availability_zones":
                dependent_azs,

            "same_az_alternative_nat_ids":
                sorted(
                    str(
                        nat.get(
                            "nat_gateway_id"
                        )
                    )
                    for nat
                    in same_az_alternatives
                    if nat.get(
                        "nat_gateway_id"
                    )
                ),

            "same_az_alternative_nat_count":
                len(
                    same_az_alternatives
                ),

            "dependent_az_nat_coverage":
                covered_by_operational_nat,

            "has_regional_nat":
                bool(regional),

            "has_multiple_operational_nats":
                len(operational) > 1,

            "has_multiple_nats_in_same_az":
                any(
                    count > 1
                    for count
                    in az_counts.values()
                ),

            "current_nat_availability_zone":
                current_az,

            "current_nat_is_regional":
                current.get(
                    "availability_mode"
                ) == "regional",

            "route_dependent_subnet_count":
                len(
                    route_dependent_subnet_ids
                ),
        }

    # ==============================================================
    # OPTIMIZATION EVIDENCE
    # ==============================================================

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

        performance = self._dict(
            derived.get(
                "performance"
            )
        )

        errors = self._dict(
            derived.get(
                "errors"
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

        fleet = self._dict(
            topology.get(
                "fleet"
            )
        )

        endpoint_summary = self._dict(
            topology.get(
                "endpoint_summary"
            )
        )

        result = {
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

            "configuration": {
                "nat_gateway_id":
                    configuration.get(
                        "nat_gateway_id"
                    ),

                "vpc_id":
                    configuration.get(
                        "vpc_id"
                    ),

                "subnet_id":
                    configuration.get(
                        "subnet_id"
                    ),

                "availability_zone":
                    configuration.get(
                        "availability_zone"
                    ),

                "availability_zones":
                    configuration.get(
                        "availability_zones",
                        [],
                    ),

                "availability_mode":
                    configuration.get(
                        "availability_mode"
                    ),

                "regional":
                    configuration.get(
                        "regional"
                    ),

                "connectivity_type":
                    configuration.get(
                        "connectivity_type"
                    ),

                "availability_mode":
                    configuration.get(
                        "availability_mode"
                    ),

                "auto_provision_zones":
                    configuration.get(
                        "auto_provision_zones"
                    ),

                "auto_scaling_ips":
                    configuration.get(
                        "auto_scaling_ips"
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
                        "zero"
                    ),

                "directional_traffic_bytes":
                    traffic.get(
                        "directional_traffic_bytes"
                    ),

                "directional_traffic_gib":
                    traffic.get(
                        "directional_traffic_gib"
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

                "connection_complete":
                    connections.get(
                        "complete"
                    ),

                "connection_observed":
                    connections.get(
                        "observed"
                    ),

                "connections_zero":
                    connections.get(
                        "zero"
                    ),

                "peak_bytes_per_second":
                    performance.get(
                        "peak_bytes_per_second"
                    ),

                "peak_packets_per_second":
                    performance.get(
                        "peak_packets_per_second"
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

                "regional_nat":
                    summary.get(
                        "regional_nat",
                        False,
                    ),

                "covered_az_count":
                    summary.get(
                        "covered_az_count",
                        0,
                    ),

                "relevant_endpoint_count":
                    summary.get(
                        "relevant_endpoint_count",
                        0,
                    ),

                "relevant_endpoint_services":
                    endpoint_summary.get(
                        "services",
                        [],
                    ),

                "has_s3_endpoint":
                    summary.get(
                        "has_s3_endpoint_on_route_dependent_tables",
                        False,
                    ),

                "has_dynamodb_endpoint":
                    summary.get(
                        "has_dynamodb_endpoint_on_route_dependent_tables",
                        False,
                    ),

                "has_ecr_endpoint":
                    summary.get(
                        "has_ecr_endpoint_on_route_dependent_tables",
                        False,
                    ),
            },

            "fleet": fleet,

            "data_quality": {
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

                "connection_data_complete":
                    connections.get(
                        "complete"
                    ),

                "peak_metrics_available":
                    performance.get(
                        "available"
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

            "semantics": {
                "traffic_is_billing_usage":
                    False,

                "connection_is_billing_usage":
                    False,

                "traffic_indicator":
                    "maximum_directional_traffic",

                "billing_attribution":
                    "handled_by_cost_reconciliation",

            },
        }

        return result

    # ==============================================================
    # ROUTE SUMMARY
    # ==============================================================

    @staticmethod
    def _build_nat_route_summary(
        nat_routes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        route_states: dict[
            str,
            int,
        ] = {}

        route_classes: dict[
            str,
            int,
        ] = {}

        default_route_count = 0
        blackhole_route_count = 0

        for route in nat_routes:

            if not isinstance(
                route,
                dict,
            ):
                continue

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

                route_classes[
                    route_class
                ] = (
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

        return {
            "route_count":
                len(nat_routes),

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

    # ==============================================================
    # ENDPOINT RELATIONSHIPS
    # ==============================================================

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

        result: list[
            Dict[str, Any]
        ] = []

        for endpoint in endpoints:

            if not isinstance(
                endpoint,
                dict,
            ):
                continue

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

            # ------------------------------------------------------
            # Gateway endpoint
            # ------------------------------------------------------

            if endpoint_type == "Gateway":

                gateway_routes = (
                    resolver.routes_targeting_vpc_endpoint(
                        endpoint_id
                    )
                )

                gateway_route_tables = {
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
                    gateway_route_tables
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

            # ------------------------------------------------------
            # Interface endpoint
            # ------------------------------------------------------

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

        services: set[
            str
        ] = set()

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

    # ==============================================================
    # NAT INVENTORY NORMALIZATION
    # ==============================================================

    def _normalize_nat_for_fleet(
        self,
        nat: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        if not isinstance(
            nat,
            dict,
        ):
            return None

        nat_id = nat.get(
            "NatGatewayId"
        )

        if not nat_id:
            return None

        availability_mode = str(
            nat.get(
                "AvailabilityMode"
            )
            or "zonal"
        ).lower()

        return {
            "nat_gateway_id":
                str(nat_id),

            "vpc_id":
                nat.get(
                    "VpcId"
                ),

            "subnet_id":
                nat.get(
                    "SubnetId"
                ),

            "availability_zone":
                self._get_nat_primary_az(
                    nat
                ),

            "availability_zones":
                self._get_nat_coverage_azs(
                    nat
                ),

            "availability_mode":
                availability_mode,

            "regional":
                availability_mode == "regional",

            "connectivity_type":
                nat.get(
                    "ConnectivityType"
                ),

            "state":
                nat.get(
                    "State"
                ),

            "auto_provision_zones":
                nat.get(
                    "AutoProvisionZones"
                ),

            "auto_scaling_ips":
                nat.get(
                    "AutoScalingIps"
                ),
        }

    def _get_nat_primary_az(
        self,
        nat: Dict[str, Any],
    ) -> Optional[str]:

        if not isinstance(
            nat,
            dict,
        ):
            return None

        addresses = (
            nat.get(
                "NatGatewayAddresses",
                [],
            )
            or []
        )

        for address in addresses:

            if not isinstance(
                address,
                dict,
            ):
                continue

            az = (
                address.get(
                    "AvailabilityZone"
                )
            )

            if az:
                return str(
                    az
                )

        subnet_id = nat.get(
            "SubnetId"
        )

        return self._get_subnet_az(
            subnet_id
        )

    def _get_nat_coverage_azs(
        self,
        nat: Dict[str, Any],
    ) -> list[str]:

        if not isinstance(
            nat,
            dict,
        ):
            return []

        values: set[str] = set()

        addresses = (
            nat.get(
                "NatGatewayAddresses",
                [],
            )
            or []
        )

        for address in addresses:

            if not isinstance(
                address,
                dict,
            ):
                continue

            az = address.get(
                "AvailabilityZone"
            )

            if az:
                values.add(
                    str(az)
                )

        primary = self._get_nat_primary_az(
            nat
        )

        if primary:
            values.add(
                str(primary)
            )

        return sorted(
            values
        )

    # ==============================================================
    # HELPERS
    # ==============================================================

    @staticmethod
    def _safe_period(
        value: Any,
    ) -> int:

        try:
            period = int(value)

        except (
            TypeError,
            ValueError,
        ):

            return (
                NatGatewayCollector.DEFAULT_PERIOD
            )

        return max(
            period,
            60,
        )

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

        if subnet_id in self._subnet_az_cache:

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
        tags: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        return {
            str(
                tag["Key"]
            ):
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