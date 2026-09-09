"""
AWS NAT Gateway collector.

Purpose
-------
Collect only evidence required to explain NAT Gateway cost and determine
whether the NAT Gateway is operationally justified.

Evidence domains
----------------
1. NAT identity and lifecycle state
2. NAT configuration
3. NAT addresses / connectivity
4. CloudWatch traffic evidence
5. CloudWatch connection evidence
6. CloudWatch diagnostic evidence
7. Packet / peak-rate evidence
8. NAT-dependent route topology
9. Dependent subnet and Availability Zone topology
10. Cross-AZ dependency evidence
11. NAT fleet / alternative NAT evidence
12. Gateway endpoint evidence
13. Interface endpoint evidence
14. Endpoint coverage against NAT-dependent subnets/AZs
15. Route-table endpoint evidence
16. Data-quality / completeness evidence
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from aws_cost_optimizer.analysis.metrics import (
    metric_has_observed_data,
    metric_is_sum,
    metric_numeric_value,
    metric_sum_value,
)
from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.metrics.cloudwatch import (
    DEFAULT_CLOUDWATCH_PERIOD,
    CloudWatchMetricCollector,
)
from collection.registry import register

from collection.shared.relationships import (
    NetworkRelationshipResolver,
)
from collection.shared.topology import (
    NetworkTopologyCollector,
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
    ) -> None:

        super().__init__(
            scan=scan,
            region=region,
            profile=profile,
        )

        if not self.region:
            raise ValueError("NAT Gateway collector requires a region.")

        self.core_traffic_metrics = self._metric_role("core_traffic")
        self.core_connection_metrics = self._metric_role("core_connection")
        self.diagnostic_connection_metrics = self._metric_role("diagnostic")
        self.packet_metrics = self._metric_role("packet")
        self.peak_metrics = self._metric_role("peak")

        self.active_route_states = self._profile_states("active_route_states")
        self.operational_states = self._profile_states("operational_states")

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = CloudWatchMetricCollector(self.cloudwatch)

        self.network_collector = NetworkTopologyCollector(self.region)

        self._subnet_az_cache: dict[
            str,
            Optional[str],
        ] = {}

        self._metrics_batch_cache: dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._nat_fleet: List[Dict[str, Any]] = []

        self._nat_fleet_by_vpc: dict[
            str,
            list[Dict[str, Any]],
        ] = {}

        self._nat_by_id: dict[
            str,
            Dict[str, Any],
        ] = {}

    # PROFILE

    def _profile_section(
        self,
        name: str,
    ) -> dict[str, Any]:

        value = self.profile.get(
            name,
            {},
        )

        return value if isinstance(value, dict) else {}

    def _cloudwatch_profile(
        self,
    ) -> dict[str, Any]:

        observations = self._profile_section("observations")

        value = observations.get(
            "cloudwatch",
            {},
        )

        return value if isinstance(value, dict) else {}

    def _profile_metric_specs(
        self,
    ) -> list[dict[str, Any]]:

        specs = self._cloudwatch_profile().get(
            "metrics",
            [],
        )

        if not isinstance(specs, list):
            return []

        return [item for item in specs if isinstance(item, dict)]

    def _metric_group(
        self,
        name: str,
    ) -> tuple[str, ...]:

        result: list[str] = []

        for spec in self._profile_metric_specs():

            if str(spec.get("group") or "").strip() != name:
                continue

            metric_name = str(spec.get("name") or "").strip()

            if metric_name and metric_name not in result:
                result.append(metric_name)

        return tuple(result)

    def _traffic_metrics(
        self,
    ) -> tuple[str, ...]:

        configured = self._metric_group("traffic")

        return configured or self.core_traffic_metrics

    def _connection_metrics(
        self,
    ) -> tuple[str, ...]:

        configured = self._metric_group("connection")

        return configured or (
            self.core_connection_metrics + self.diagnostic_connection_metrics
        )

    def _metric_role(
        self,
        role: str,
    ) -> tuple[str, ...]:


        result: list[str] = []

        for spec in self._profile_metric_specs():

            if str(spec.get("role") or "").strip() != role:
                continue

            metric_name = str(spec.get("name") or "").strip()

            if metric_name and metric_name not in result:
                result.append(metric_name)

        if not result:
            raise ValueError(
                f"{self.__class__.__name__} profile has no "
                f"observations.cloudwatch.metrics entries tagged "
                f"role: {role!r}."
            )

        return tuple(result)

    def _profile_states(
        self,
        key: str,
    ) -> frozenset[str]:
        """
        Reads a named state vocabulary (e.g. "active_route_states")
        from the profile's top-level `states` section.
        """

        states = self.profile.get("states")

        values = states.get(key) if isinstance(states, dict) else None

        if not isinstance(values, list) or not values:
            raise ValueError(
                f"{self.__class__.__name__} profile must define "
                f"states.{key} as a non-empty list."
            )

        return frozenset(str(value).strip().lower() for value in values)

    # GENERAL HELPERS

    @staticmethod
    def _dict(value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _tags(tags: Any) -> Dict[str, Any]:

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
    def _safe_period(value: Any) -> int:

        if value is None:
            return DEFAULT_CLOUDWATCH_PERIOD

        try:
            value = int(value)
        except (TypeError, ValueError):
            return DEFAULT_CLOUDWATCH_PERIOD

        return max(value, 60)

    def _state_category(self, state: Any) -> str:
 

        normalized = str(state or "").strip().lower()

        if normalized in self.operational_states:
            return "operational"

        return normalized or "unknown"

    def _get_subnet_az(self, subnet_id: Any) -> Optional[str]:


        if not subnet_id:
            return None

        subnet_id = str(subnet_id)

        if subnet_id in self._subnet_az_cache:
            return self._subnet_az_cache[subnet_id]

        az: Optional[str] = None

        try:
            response = self.ec2.describe_subnets(SubnetIds=[subnet_id])
            subnets = response.get("Subnets", [])

            if subnets and isinstance(subnets[0], dict):
                az = subnets[0].get("AvailabilityZone")

        except Exception:
            az = None

        self._subnet_az_cache[subnet_id] = az

        return az

    def _get_nat_primary_az(self, raw: Dict[str, Any]) -> Optional[str]:


        raw = self._dict(raw)

        return self._get_subnet_az(raw.get("SubnetId"))

    def _get_nat_coverage_azs(self, raw: Dict[str, Any]) -> List[str]:


        raw = self._dict(raw)

        zones = raw.get("AutoProvisionZones")

        result: List[str] = []

        if isinstance(zones, list):

            for entry in zones:

                if isinstance(entry, dict):
                    zone = (
                        entry.get("Zone")
                        or entry.get("AvailabilityZone")
                        or entry.get("ZoneName")
                    )
                else:
                    zone = entry

                if zone and str(zone) not in result:
                    result.append(str(zone))

        if result:
            return sorted(result)

        primary = self._get_nat_primary_az(raw)

        return [primary] if primary else []

    def _build_nat_route_summary(
        self,
        routes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:


        routes = [route for route in routes if isinstance(route, dict)]

        by_state: Dict[str, int] = defaultdict(int)

        for route in routes:
            state = str(route.get("state") or "unknown").strip().lower()
            by_state[state] += 1

        return {
            "route_count": len(routes),
            "routes_by_state": dict(sorted(by_state.items())),
            "route_table_ids": sorted(
                {
                    str(route.get("route_table_id"))
                    for route in routes
                    if route.get("route_table_id")
                }
            ),
            "subnet_ids": sorted(
                {
                    str(route.get("subnet_id"))
                    for route in routes
                    if route.get("subnet_id")
                }
            ),
        }

    def _normalize_nat_for_fleet(
        self,
        nat: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        nat = self._dict(nat)

        nat_id = nat.get("NatGatewayId")

        if not nat_id:
            return None

        state = nat.get("State")

        mode = str(nat.get("AvailabilityMode") or "zonal").lower()

        return {
            "nat_gateway_id": str(nat_id),
            "vpc_id": nat.get("VpcId"),
            "state": state,
            "state_category": self._state_category(state),
            "availability_mode": mode,
            "availability_zone": self._get_nat_primary_az(nat),
        }

    # DISCOVERY

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        self._metrics_batch_cache = {}
        self._nat_fleet = []
        self._nat_fleet_by_vpc = {}
        self._nat_by_id = {}

        paginator = self.ec2.get_paginator("describe_nat_gateways")

        resources: list[Dict[str, Any]] = []

        fleet: list[Dict[str, Any]] = []

        for page in paginator.paginate():

            nat_gateways = page.get(
                "NatGateways",
                [],
            )

            if not isinstance(
                nat_gateways,
                list,
            ):
                continue

            for nat in nat_gateways:

                if not isinstance(
                    nat,
                    dict,
                ):
                    continue

                nat_id = nat.get("NatGatewayId")

                if not nat_id:
                    continue

                nat_id = str(nat_id)

                resources.append(
                    {
                        "id": nat_id,
                        "raw": nat,
                    }
                )

                normalized = self._normalize_nat_for_fleet(nat)

                if normalized:
                    fleet.append(normalized)

        self._nat_fleet = fleet

        self._nat_by_id = {
            item["nat_gateway_id"]: item for item in fleet if item.get("nat_gateway_id")
        }

        by_vpc: dict[
            str,
            list[Dict[str, Any]],
        ] = defaultdict(list)

        for item in fleet:

            vpc_id = item.get("vpc_id")

            if not vpc_id:
                continue

            by_vpc[str(vpc_id)].append(item)

        self._nat_fleet_by_vpc = dict(by_vpc)

        self._prefetch_metrics_batch(resources)

        return resources

    # CLOUDWATCH

    def _prefetch_metrics_batch(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        profile = self._cloudwatch_profile()

        if not profile:
            return

        if (
            profile.get(
                "enabled",
                True,
            )
            is False
        ):
            return

        metric_specs = self._profile_metric_specs()

        if not metric_specs:
            return

        namespace = str(profile.get("namespace") or self.cloudwatch_namespace())

        requested_period = self._safe_period(profile.get("period"))

        try:
            start, end = self.get_analysis_period()
        except ValueError:
            return

        requests: list[Dict[str, Any]] = []

        request_metadata: dict[
            str,
            Dict[str, Any],
        ] = {}

        for resource in resources:

            nat_id = resource.get("id")

            if not nat_id:
                continue

            raw = resource.get("raw")

            raw = raw if isinstance(raw, dict) else {}

            mode = str(raw.get("AvailabilityMode") or "zonal").lower()

            # Zonal NAT

            if mode != "regional":

                query_key = str(nat_id)

                requests.append(
                    {
                        "resource_key": query_key,
                        "namespace": namespace,
                        "dimensions": [
                            {
                                "Name": "NatGatewayId",
                                "Value": str(nat_id),
                            }
                        ],
                        "metric_specs": metric_specs,
                    }
                )

                request_metadata[query_key] = {
                    "nat_gateway_id": str(nat_id),
                    "availability_zone": (self._get_nat_primary_az(raw)),
                    "regional": False,
                }

                continue

            # Regional NAT
            #
            # AWS requires AvailabilityZone together with NatGatewayId
            # for regional NAT metrics.

            availability_zones = self._get_nat_coverage_azs(raw)

            for az in availability_zones:

                query_key = f"{nat_id}@@{az}"

                requests.append(
                    {
                        "resource_key": query_key,
                        "namespace": namespace,
                        "dimensions": [
                            {
                                "Name": "NatGatewayId",
                                "Value": str(nat_id),
                            },
                            {
                                "Name": "AvailabilityZone",
                                "Value": str(az),
                            },
                        ],
                        "metric_specs": metric_specs,
                    }
                )

                request_metadata[query_key] = {
                    "nat_gateway_id": str(nat_id),
                    "availability_zone": str(az),
                    "regional": True,
                }

        if not requests:
            return

        raw_results = self.metric_collector.collect_batch(
            requests,
            start=start,
            end=end,
            requested_period=requested_period,
        )

        self._metrics_batch_cache = self._normalize_metric_batch_results(
            raw_results,
            request_metadata,
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
            list[
                tuple[
                    str,
                    Dict[str, Any],
                ]
            ],
        ] = defaultdict(list)

        for query_key, results in (raw_results or {}).items():

            metadata = request_metadata.get(query_key)

            if not metadata:
                continue

            nat_id = metadata.get("nat_gateway_id")

            if not nat_id:
                continue

            for result in results or []:

                if not isinstance(
                    result,
                    dict,
                ):
                    continue

                grouped[str(nat_id)].append(
                    (
                        str(query_key),
                        dict(result),
                    )
                )

        final: dict[
            str,
            list[Dict[str, Any]],
        ] = {}

        for metadata in request_metadata.values():

            nat_id = metadata.get("nat_gateway_id")

            if nat_id:
                final.setdefault(
                    str(nat_id),
                    [],
                )

        for nat_id, entries in grouped.items():

            regional = any(
                request_metadata.get(
                    query_key,
                    {},
                ).get("regional")
                is True
                for query_key, _ in entries
            )

            if not regional:

                final[nat_id] = [result for _, result in entries]

                continue

            by_metric: dict[
                str,
                list[
                    tuple[
                        str,
                        Dict[str, Any],
                    ]
                ],
            ] = defaultdict(list)

            for query_key, result in entries:

                metric_name = result.get("metric_name")

                if metric_name:
                    by_metric[str(metric_name)].append(
                        (
                            query_key,
                            result,
                        )
                    )

            merged: list[Dict[str, Any]] = []

            for (
                metric_name,
                metric_results,
            ) in by_metric.items():

                result = self._merge_regional_metric_results(
                    nat_id=nat_id,
                    metric_name=metric_name,
                    results=metric_results,
                    request_metadata=request_metadata,
                )

                if result:
                    merged.append(result)

            final[nat_id] = merged

        return final

    @staticmethod
    def _merge_regional_metric_results(
        *,
        nat_id: str,
        metric_name: str,
        results: List[
            tuple[
                str,
                Dict[str, Any],
            ]
        ],
        request_metadata: Dict[
            str,
            Dict[str, Any],
        ],
    ) -> Dict[str, Any]:

        if not results:
            return {}

        first = results[0][1]

        statistic = str(first.get("statistic") or "Average").strip()

        observed_results = [
            result
            for _, result in results
            if (result.get("status") == "ok" and result.get("has_data") is True)
        ]

        numeric_values = [
            float(result["value"])
            for _, result in results
            if (
                result.get("status") == "ok"
                and result.get("has_data") is True
                and isinstance(
                    result.get("value"),
                    (int, float),
                )
            )
        ]

        totals = [
            float(result["total"])
            for _, result in results
            if (
                result.get("status") == "ok"
                and result.get("has_data") is True
                and isinstance(
                    result.get("total"),
                    (int, float),
                )
            )
        ]

        maximums = [
            float(result["maximum"])
            for _, result in results
            if (
                result.get("status") == "ok"
                and result.get("has_data") is True
                and isinstance(
                    result.get("maximum"),
                    (int, float),
                )
            )
        ]

        minimums = [
            float(result["minimum"])
            for _, result in results
            if (
                result.get("status") == "ok"
                and result.get("has_data") is True
                and isinstance(
                    result.get("minimum"),
                    (int, float),
                )
            )
        ]

        if statistic == "Sum":

            value = sum(numeric_values) if numeric_values else None

            total = sum(totals) if totals else value

            average = None

            maximum = max(maximums) if maximums else None

            minimum = min(minimums) if minimums else None

        elif statistic == "Maximum":

            value = max(numeric_values) if numeric_values else None

            total = value
            average = None

            maximum = max(maximums) if maximums else value

            minimum = min(minimums) if minimums else value

        elif statistic == "Minimum":

            value = min(numeric_values) if numeric_values else None

            total = value
            average = None

            maximum = max(maximums) if maximums else value

            minimum = min(minimums) if minimums else value

        else:

            value = (
                sum(numeric_values) / len(numeric_values) if numeric_values else None
            )

            total = sum(totals) if totals else value

            average = value

            maximum = max(maximums) if maximums else value

            minimum = min(minimums) if minimums else value

        coverage_values = [
            float(result["coverage_ratio"])
            for _, result in results
            if isinstance(
                result.get("coverage_ratio"),
                (int, float),
            )
        ]

        coverage_ratio = min(coverage_values) if coverage_values else 0.0

        if coverage_ratio >= 0.95:
            data_quality = "complete"
        elif coverage_ratio >= 0.80:
            data_quality = "good"
        elif coverage_ratio >= 0.50:
            data_quality = "partial"
        elif coverage_ratio > 0:
            data_quality = "poor"
        else:
            data_quality = "no_data"

        successful = bool(observed_results)

        availability_zones = sorted(
            {
                str(
                    request_metadata.get(
                        query_key,
                        {},
                    ).get("availability_zone")
                )
                for query_key, _ in results
                if request_metadata.get(
                    query_key,
                    {},
                ).get("availability_zone")
            }
        )

        regional_by_az: dict[
            str,
            Dict[str, Any],
        ] = {}

        for query_key, result in results:

            az = request_metadata.get(
                query_key,
                {},
            ).get("availability_zone")

            if az:
                regional_by_az[str(az)] = result

        error = next(
            (result.get("error") for _, result in results if result.get("error")),
            None,
        )

        return {
            **first,
            "metric_key": (first.get("metric_key") or metric_name),
            "metric_name": metric_name,
            "status": (
                "ok"
                if successful
                else (
                    "error"
                    if any(result.get("status") == "error" for _, result in results)
                    else "no_data"
                )
            ),
            "available": successful,
            "has_data": successful,
            "samples": max(
                (
                    int(
                        result.get(
                            "samples",
                            0,
                        )
                        or 0
                    )
                    for _, result in results
                ),
                default=0,
            ),
            "datapoints": max(
                (
                    int(
                        result.get(
                            "datapoints",
                            0,
                        )
                        or 0
                    )
                    for _, result in results
                ),
                default=0,
            ),
            "value": (round(value, 6) if value is not None else None),
            "total": (round(total, 6) if total is not None else None),
            "average": (round(average, 6) if average is not None else None),
            "maximum": (round(maximum, 6) if maximum is not None else None),
            "minimum": (round(minimum, 6) if minimum is not None else None),
            "coverage_ratio": round(
                coverage_ratio,
                4,
            ),
            "coverage_percent": round(
                coverage_ratio * 100.0,
                2,
            ),
            "complete": (coverage_ratio >= 0.95),
            "data_quality": data_quality,
            "regional_aggregation": True,
            "nat_gateway_id": nat_id,
            "availability_zones": (availability_zones),
            "regional_by_az": (regional_by_az),
            "regional_dimension_complete": (
                bool(availability_zones) and len(availability_zones) == len(results)
            ),
            "raw_datapoints": [
                datapoint
                for _, result in results
                for datapoint in (
                    result.get(
                        "raw_datapoints",
                        [],
                    )
                    or []
                )
                if isinstance(
                    datapoint,
                    dict,
                )
            ],
            "error": (error if not successful else None),
        }

    # RESOURCE ID

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return str(resource["id"])

    # IDENTITY

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        nat = self._dict(resource.get("raw"))

        state = nat.get("State")

        tags = self._tags(
            nat.get(
                "Tags",
                [],
            )
        )

        mode = str(nat.get("AvailabilityMode") or "zonal").lower()

        return {
            "name": (tags.get("Name") or resource["id"]),
            "nat_gateway_id": (resource["id"]),
            "state": state,
            "state_category": (self._state_category(state)),
            "vpc_id": nat.get("VpcId"),
            "subnet_id": nat.get("SubnetId"),
            "availability_mode": mode,
            "regional": (mode == "regional"),
            "connectivity_type": (nat.get("ConnectivityType")),
            "tags": tags,
        }

    # CONFIGURATION

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        nat = self._dict(resource.get("raw"))

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

        primary: Dict[str, Any] = {}

        for address in addresses:

            if not isinstance(
                address,
                dict,
            ):
                continue

            if address.get("IsPrimary"):
                primary = address
                break

        if (
            not primary
            and addresses
            and isinstance(
                addresses[0],
                dict,
            )
        ):
            primary = addresses[0]

        mode = str(nat.get("AvailabilityMode") or "zonal").lower()

        covered_azs = self._get_nat_coverage_azs(nat)

        create_time = nat.get("CreateTime")

        delete_time = nat.get("DeleteTime")

        connectivity_type = nat.get("ConnectivityType")

        return {
            "nat_gateway_id": nat.get("NatGatewayId"),
            "vpc_id": nat.get("VpcId"),
            "subnet_id": nat.get("SubnetId"),
            "availability_zone": (self._get_nat_primary_az(nat)),
            "availability_zones": (covered_azs),
            "availability_mode": mode,
            "regional": (mode == "regional"),
            "connectivity_type": (connectivity_type),
            "state": nat.get("State"),
            "create_time": (
                create_time.isoformat()
                if hasattr(
                    create_time,
                    "isoformat",
                )
                else (str(create_time) if create_time else None)
            ),
            "delete_time": (
                delete_time.isoformat()
                if hasattr(
                    delete_time,
                    "isoformat",
                )
                else (str(delete_time) if delete_time else None)
            ),
            "nat_gateway_addresses": (addresses),
            "public_ip": primary.get("PublicIp"),
            "private_ip": primary.get("PrivateIp"),
            "elastic_ip_allocation_id": (primary.get("AllocationId")),
            "network_interface_id": (primary.get("NetworkInterfaceId")),
            "auto_provision_zones": (nat.get("AutoProvisionZones")),
            "auto_scaling_ips": (nat.get("AutoScalingIps")),
            "attached_appliances": (
                nat.get(
                    "AttachedAppliances",
                    [],
                )
            ),
            "failure_code": (nat.get("FailureCode")),
            "failure_message": (nat.get("FailureMessage")),
            "address_count": len(addresses),
            "public": (connectivity_type == "public"),
            "private": (connectivity_type == "private"),
            "tags": self._tags(
                nat.get(
                    "Tags",
                    [],
                )
            ),
        }

    # OBSERVATIONS

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        profile = self._cloudwatch_profile()

        if not profile:
            return {
                "status": "incomplete",
                "cloudwatch": {"metrics": {}},
                "derived": {},
                "error": (
                    "NAT Gateway profile must define " "observations.cloudwatch."
                ),
            }

        if (
            profile.get(
                "enabled",
                True,
            )
            is False
        ):
            return {
                "status": "disabled",
                "cloudwatch": {},
                "derived": {},
            }

        metric_specs = self._profile_metric_specs()

        if not metric_specs:
            return {
                "status": "incomplete",
                "cloudwatch": {"metrics": {}},
                "derived": {},
                "error": ("NAT Gateway profile must define " "CloudWatch metrics."),
            }

        namespace = str(profile.get("namespace") or self.cloudwatch_namespace())

        requested_period = self._safe_period(profile.get("period"))

        try:
            start, end = self.get_analysis_period()
        except ValueError as exc:
            return {
                "status": "incomplete",
                "cloudwatch": {"metrics": {}},
                "derived": {},
                "error": str(exc),
            }

        resource_id = str(resource["id"])

        results = self._metrics_batch_cache.get(
            resource_id,
            [],
        )

        metrics: Dict[
            str,
            Any,
        ] = {}

        for result in results:

            if not isinstance(
                result,
                dict,
            ):
                continue

            metric_name = result.get("metric_name")

            if metric_name:
                metrics[str(metric_name)] = result

        expected_metric_names = sorted(
            {
                str(spec.get("name") or "").strip()
                for spec in metric_specs
                if str(spec.get("name") or "").strip()
            }
        )

        observed_metric_names = sorted(
            {
                name
                for name, metric in metrics.items()
                if metric_has_observed_data(metric)
            }
        )

        no_data_metric_names = sorted(
            {
                name
                for name, metric in metrics.items()
                if (
                    metric.get("status")
                    in {
                        "no_data",
                        "missing",
                    }
                    or not metric_has_observed_data(metric)
                )
            }
        )

        missing_metric_names = sorted(set(expected_metric_names) - set(metrics.keys()))

        metric_errors = sorted(
            {
                str(result.get("error"))
                for result in metrics.values()
                if (result.get("status") == "error" and result.get("error"))
            }
        )

        if metric_errors:
            observation_status = "error"

        elif missing_metric_names:
            observation_status = "partial"

        elif no_data_metric_names:
            observation_status = "partial" if observed_metric_names else "no_data"

        elif results:
            observation_status = "ok"

        else:
            observation_status = "no_data"

        effective_periods = sorted(
            {
                result.get("effective_period")
                for result in results
                if (result.get("effective_period") is not None)
            }
        )

        effective_period = effective_periods[0] if len(effective_periods) == 1 else None

        derived = self._build_derived_data(metrics)

        return {
            "status": observation_status,
            "cloudwatch": {
                "namespace": namespace,
                "requested_period": (requested_period),
                "effective_period": (effective_period),
                "effective_periods": (effective_periods),
                "start": start.isoformat(),
                "end": end.isoformat(),
                "metrics": metrics,
                "expected_metric_names": (expected_metric_names),
                "observed_metric_names": (observed_metric_names),
                "no_data_metric_names": (no_data_metric_names),
                "missing_metric_names": (missing_metric_names),
                "metric_errors": (metric_errors),
                "metric_count": len(expected_metric_names),
                "observed_metric_count": len(observed_metric_names),
                "no_data_metric_count": len(no_data_metric_names),
                "missing_metric_count": len(missing_metric_names),
                "error_metric_count": len(metric_errors),
            },
            "derived": derived,
        }

    # DERIVED ACTIVITY

    def _build_derived_data(
        self,
        metrics_dict: Dict[
            str,
            Any,
        ],
    ) -> Dict[str, Any]:

        traffic_metrics = self._traffic_metrics()

        connection_metrics = self._connection_metrics()

        # --------------------------------------------------------------
        # Traffic
        # --------------------------------------------------------------

        traffic_values = {
            name: metric_sum_value(metrics_dict.get(name)) for name in traffic_metrics
        }

        traffic_observed = {
            name: metric_has_observed_data(metrics_dict.get(name))
            for name in traffic_metrics
        }

        traffic_available = any(traffic_observed.values())

        core_traffic_values = {
            name: metric_sum_value(metrics_dict.get(name))
            for name in self.core_traffic_metrics
        }

        core_traffic_observation = {
            name: metric_has_observed_data(metrics_dict.get(name))
            for name in self.core_traffic_metrics
        }

        core_traffic_complete = all(core_traffic_observation.values())

        core_traffic_semantics_valid = all(
            (
                not core_traffic_observation[name]
                or metric_is_sum(metrics_dict.get(name))
            )
            for name in self.core_traffic_metrics
        )

        source_bytes = core_traffic_values.get("BytesInFromSource")

        destination_bytes = core_traffic_values.get("BytesOutToDestination")

        reverse_destination_bytes = core_traffic_values.get("BytesInFromDestination")

        reverse_source_bytes = core_traffic_values.get("BytesOutToSource")

        primary_path_values = [
            value
            for value in (
                source_bytes,
                destination_bytes,
            )
            if value is not None
        ]

        reverse_path_values = [
            value
            for value in (
                reverse_destination_bytes,
                reverse_source_bytes,
            )
            if value is not None
        ]

        primary_path_bytes = max(primary_path_values) if primary_path_values else None

        reverse_path_bytes = max(reverse_path_values) if reverse_path_values else None

        directional_bytes = [
            value
            for value in (
                primary_path_bytes,
                reverse_path_bytes,
            )
            if value is not None
        ]

        traffic_bytes = max(directional_bytes) if directional_bytes else None

        traffic_gib = traffic_bytes / (1024.0**3) if traffic_bytes is not None else None

        traffic_values_present = all(
            value is not None for value in core_traffic_values.values()
        )

        core_traffic_zero = (
            core_traffic_complete
            and core_traffic_semantics_valid
            and traffic_values_present
            and all(value == 0 for value in core_traffic_values.values())
        )

        core_traffic_positive = any(
            value is not None and value > 0 for value in core_traffic_values.values()
        )

        traffic_complete = core_traffic_complete and core_traffic_semantics_valid

        # --------------------------------------------------------------
        # Connections
        # --------------------------------------------------------------

        active_metric = metrics_dict.get("ActiveConnectionCount")

        active_observed = metric_has_observed_data(active_metric)

        active_connection_count = (
            metric_numeric_value(active_metric) if active_observed else None
        )

        active_connection_semantics_valid = (
            (metric_numeric_value(active_metric) is not None)
            if active_observed
            else False
        )

        core_connection_available = active_observed

        core_connection_complete = active_observed and active_connection_semantics_valid

        active_connections_zero = (
            core_connection_complete and active_connection_count == 0
        )

        active_connections_positive = (
            active_connection_count is not None and active_connection_count > 0
        )

        # --------------------------------------------------------------
        # Diagnostics
        # --------------------------------------------------------------

        diagnostic_values = {}
        diagnostic_observed = {}
        diagnostic_semantics_valid = {}

        for name in self.diagnostic_connection_metrics:

            metric = metrics_dict.get(name)

            observed = metric_has_observed_data(metric)

            diagnostic_observed[name] = observed

            diagnostic_values[name] = metric_sum_value(metric) if observed else None

            diagnostic_semantics_valid[name] = (
                (metric_sum_value(metric) is not None) if observed else False
            )

        diagnostic_available = any(diagnostic_observed.values())

        diagnostic_complete = all(
            diagnostic_observed.get(
                name,
                False,
            )
            for name in (self.diagnostic_connection_metrics)
        )

        diagnostic_semantics_all_valid = all(
            (
                not diagnostic_observed.get(
                    name,
                    False,
                )
                or diagnostic_semantics_valid.get(
                    name,
                    False,
                )
            )
            for name in (self.diagnostic_connection_metrics)
        )

        connection_attempt_count = diagnostic_values.get("ConnectionAttemptCount")

        connection_established_count = diagnostic_values.get(
            "ConnectionEstablishedCount"
        )

        error_port_allocation = diagnostic_values.get("ErrorPortAllocation")

        idle_timeout_count = diagnostic_values.get("IdleTimeoutCount")

        packets_drop_count = diagnostic_values.get("PacketsDropCount")

        diagnostic_activity = any(
            value is not None and value > 0
            for value in (
                connection_attempt_count,
                connection_established_count,
                error_port_allocation,
                idle_timeout_count,
                packets_drop_count,
            )
        )

        # --------------------------------------------------------------
        # Packet metrics
        # --------------------------------------------------------------

        packet_metrics = {
            name: {
                "value": metric_sum_value(metrics_dict.get(name)),
                "observed": (metric_has_observed_data(metrics_dict.get(name))),
            }
            for name in self.packet_metrics
        }

        # --------------------------------------------------------------
        # Peak metrics
        # --------------------------------------------------------------

        peak_bytes_metric = metrics_dict.get("PeakBytesPerSecond")

        peak_packets_metric = metrics_dict.get("PeakPacketsPerSecond")

        peak_bytes_per_second = (
            metric_numeric_value(peak_bytes_metric)
            if metric_has_observed_data(peak_bytes_metric)
            else None
        )

        peak_packets_per_second = (
            metric_numeric_value(peak_packets_metric)
            if metric_has_observed_data(peak_packets_metric)
            else None
        )

        # --------------------------------------------------------------
        # Core activity
        # --------------------------------------------------------------

        activity_available = traffic_available or core_connection_available

        if core_traffic_complete and core_connection_complete:

            core_activity_observed = (
                core_traffic_positive or active_connections_positive
            )

        elif core_traffic_complete and core_traffic_zero:

            core_activity_observed = (
                False
                if (core_connection_complete and active_connections_zero)
                else None
            )

        elif active_connections_positive:

            core_activity_observed = True

        else:

            core_activity_observed = None

        return {
            "profile_metric_groups": {
                "traffic": list(traffic_metrics),
                "connection": list(connection_metrics),
                "core_traffic": list(self.core_traffic_metrics),
                "core_connection": list(self.core_connection_metrics),
                "diagnostic": list(self.diagnostic_connection_metrics),
            },
            "traffic": {
                "bytes_in_from_source": (source_bytes),
                "bytes_out_to_destination": (destination_bytes),
                "bytes_in_from_destination": (reverse_destination_bytes),
                "bytes_out_to_source": (reverse_source_bytes),
                "primary_path_bytes": (primary_path_bytes),
                "reverse_path_bytes": (reverse_path_bytes),
                "traffic_bytes": (traffic_bytes),
                "traffic_gib": (traffic_gib),
                "available": (traffic_available),
                "complete": (traffic_complete),
                "observed": (core_traffic_positive if core_traffic_complete else None),
                "zero": (core_traffic_zero),
                "metric_observation": (core_traffic_observation),
                "all_configured_metric_observation": (traffic_observed),
            },
            "connections": {
                "active": (active_connection_count),
                "active_zero": (active_connections_zero),
                "active_positive": (active_connections_positive),
                "available": (core_connection_available),
                "complete": (core_connection_complete),
                "observed": (
                    active_connections_positive if core_connection_complete else None
                ),
                "zero": (active_connections_zero),
                "metric_observation": {"ActiveConnectionCount": (active_observed)},
                "semantics_valid": (
                    active_connection_semantics_valid if active_observed else False
                ),
            },
            "diagnostics": {
                "available": (diagnostic_available),
                "complete": (diagnostic_complete),
                "activity_observed": (
                    diagnostic_activity if diagnostic_available else None
                ),
                "connection_attempts": (connection_attempt_count),
                "connections_established": (connection_established_count),
                "error_port_allocation": (error_port_allocation),
                "idle_timeouts": (idle_timeout_count),
                "packets_dropped": (packets_drop_count),
                "metric_observation": (diagnostic_observed),
                "semantics_valid": (diagnostic_semantics_all_valid),
            },
            "packets": {name: packet_metrics.get(name) for name in self.packet_metrics},
            "peak": {
                "bytes_per_second": (peak_bytes_per_second),
                "packets_per_second": (peak_packets_per_second),
            },
            "activity": {
                "available": (activity_available),
                "observed": (core_activity_observed),
                "traffic_observed": (
                    core_traffic_positive if core_traffic_complete else None
                ),
                "connection_observed": (
                    active_connections_positive if core_connection_complete else None
                ),
                "core_traffic_zero": (core_traffic_zero),
                "core_connections_zero": (active_connections_zero),
                "diagnostic_activity": (
                    diagnostic_activity if diagnostic_available else None
                ),
            },
            "semantics": {
                "traffic_source": "CloudWatch",
                "traffic_is_billing_usage": False,
                "connection_is_billing_usage": False,
                "diagnostic_is_billing_usage": False,
                "traffic_requires_sum_statistic": True,
                "active_connection_requires_max_statistic": True,
                "diagnostic_counters_require_sum_statistic": True,
                "traffic_semantics_valid": (core_traffic_semantics_valid),
                "connection_semantics_valid": (active_connection_semantics_valid),
                "diagnostic_semantics_valid": (diagnostic_semantics_all_valid),
                "traffic_indicator": ("nat_gateway_processed_traffic_evidence"),
                "connection_indicator": ("nat_gateway_active_connection_evidence"),
                "diagnostic_indicator": ("nat_gateway_connection_diagnostic_evidence"),
                "missing_is_zero": False,
            },
        }

    # TOPOLOGY

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = self._dict(collected_resource.get("configuration"))

        vpc_id = configuration.get("vpc_id")

        nat_id = resource.get("id")

        if not vpc_id:
            return {
                "status": "incomplete",
                "reason": "VPC ID not available",
                "vpc_id": None,
                "nat_gateway_id": nat_id,
                "summary": {
                    "topology_complete": False,
                    "dependency_evidence_complete": False,
                },
            }

        if not nat_id:
            return {
                "status": "incomplete",
                "reason": "NAT Gateway ID not available",
                "vpc_id": vpc_id,
                "nat_gateway_id": None,
                "summary": {
                    "topology_complete": False,
                    "dependency_evidence_complete": False,
                },
            }

        topology = self.network_collector.collect(
            vpc_id=str(vpc_id),
            resource_type=self.resource_type,
            resource_id=str(nat_id),
        )

        topology_status = str(topology.get("status") or "unknown")

        topology_summary = topology.get(
            "summary",
            {},
        )

        if not isinstance(
            topology_summary,
            dict,
        ):
            topology_summary = {}

        topology_complete = topology_summary.get("topology_complete") is True

        resolver = NetworkRelationshipResolver(topology)

        # --------------------------------------------------------------
        # NAT routes
        # --------------------------------------------------------------

        all_nat_routes = resolver.routes_targeting(
            "nat_gateway",
            str(nat_id),
        )

        if not isinstance(
            all_nat_routes,
            list,
        ):
            all_nat_routes = []

        active_nat_routes = [
            route
            for route in all_nat_routes
            if (
                isinstance(
                    route,
                    dict,
                )
                and route.get("state") in self.active_route_states
            )
        ]

        blackhole_nat_routes = [
            route
            for route in all_nat_routes
            if (
                isinstance(
                    route,
                    dict,
                )
                and route.get("state") == "blackhole"
            )
        ]

        dependent_subnet_ids = sorted(
            {
                str(route.get("subnet_id"))
                for route in active_nat_routes
                if route.get("subnet_id")
            }
        )

        dependent_route_table_ids = sorted(
            {
                str(route.get("route_table_id"))
                for route in active_nat_routes
                if route.get("route_table_id")
            }
        )

        dependent_subnets = [
            subnet
            for subnet_id in dependent_subnet_ids
            for subnet in [resolver.subnet(subnet_id)]
            if subnet
        ]

        subnet_profile_index = {
            str(profile.get("subnet_id")): profile
            for profile in (
                topology.get(
                    "subnet_profiles",
                    [],
                )
                or []
            )
            if (
                isinstance(
                    profile,
                    dict,
                )
                and profile.get("subnet_id")
            )
        }

        dependent_subnet_profiles = [
            subnet_profile_index[subnet_id]
            for subnet_id in dependent_subnet_ids
            if subnet_id in subnet_profile_index
        ]

        missing_dependent_subnet_profiles = sorted(
            set(dependent_subnet_ids)
            - set(
                str(profile.get("subnet_id"))
                for profile in dependent_subnet_profiles
                if profile.get("subnet_id")
            )
        )

        # --------------------------------------------------------------
        # AZ analysis
        # --------------------------------------------------------------

        nat_az = configuration.get("availability_zone")

        mode = str(configuration.get("availability_mode") or "zonal").lower()

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
                str(profile.get("availability_zone"))
                for profile in dependent_subnet_profiles
                if profile.get("availability_zone")
            }
        )

        same_az_subnets: list[str] = []
        cross_az_subnets: list[str] = []
        unresolved_az_subnets: list[str] = []

        if mode != "regional":

            for profile in dependent_subnet_profiles:

                subnet_id = profile.get("subnet_id")

                subnet_az = profile.get("availability_zone")

                if not subnet_id:
                    continue

                subnet_id = str(subnet_id)

                if not subnet_az:

                    unresolved_az_subnets.append(subnet_id)

                elif nat_az and subnet_az == nat_az:

                    same_az_subnets.append(subnet_id)

                elif nat_az and subnet_az != nat_az:

                    cross_az_subnets.append(subnet_id)

        same_az_subnets = sorted(set(same_az_subnets))

        cross_az_subnets = sorted(set(cross_az_subnets))

        unresolved_az_subnets = sorted(set(unresolved_az_subnets))

        # --------------------------------------------------------------
        # Strong endpoint analysis
        # --------------------------------------------------------------

        endpoints = topology.get(
            "vpc_endpoints",
            [],
        )

        if not isinstance(
            endpoints,
            list,
        ):
            endpoints = []

        endpoint_evidence = self._build_strong_endpoint_evidence(
            endpoints=endpoints,
            dependent_route_table_ids=(dependent_route_table_ids),
            dependent_subnet_ids=(dependent_subnet_ids),
            dependent_azs=(dependent_azs),
            active_nat_routes=(active_nat_routes),
            topology=topology,
        )

        # --------------------------------------------------------------
        # Fleet
        # --------------------------------------------------------------

        fleet_context = self._build_nat_fleet_context(
            vpc_id=str(vpc_id),
            nat_id=str(nat_id),
            route_dependent_subnet_ids=(dependent_subnet_ids),
            dependent_subnet_profiles=(dependent_subnet_profiles),
        )

        # --------------------------------------------------------------
        # Route summary
        # --------------------------------------------------------------

        route_summary = self._build_nat_route_summary(all_nat_routes)

        all_routes = topology.get(
            "routes",
            [],
        )

        if not isinstance(
            all_routes,
            list,
        ):
            all_routes = []

        missing_dependency_route_tables = sorted(
            {
                str(route.get("route_table_id"))
                for route in active_nat_routes
                if (
                    route.get("route_table_id")
                    and not resolver.route_table_for_subnet(str(route.get("subnet_id")))
                )
            }
        )

        dependency_evidence_complete = (
            topology_complete
            and not missing_dependent_subnet_profiles
            and not missing_dependency_route_tables
        )

        route_dependent_az_count = len(dependent_azs)

        return {
            "status": topology_status,
            "vpc_id": vpc_id,
            "nat_gateway_id": nat_id,
            "nat_subnet": configuration.get("subnet_id"),
            "nat_availability_zone": (nat_az),
            "availability_mode": mode,
            "covered_availability_zones": sorted(
                {str(value) for value in covered_azs if value}
            ),
            "nat_routes": all_nat_routes,
            "active_nat_routes": active_nat_routes,
            "blackhole_nat_routes": (blackhole_nat_routes),
            "route_dependent_subnet_ids": (dependent_subnet_ids),
            "route_dependent_subnets": (dependent_subnets),
            "route_dependent_subnet_profiles": (dependent_subnet_profiles),
            "route_dependent_route_table_ids": (dependent_route_table_ids),
            "route_summary": route_summary,
            "dependency_evidence_complete": (dependency_evidence_complete),
            "missing_dependent_subnet_profiles": (missing_dependent_subnet_profiles),
            "missing_dependency_route_tables": (missing_dependency_route_tables),
            "dependent_availability_zones": (dependent_azs),
            "dependent_availability_zone_count": (route_dependent_az_count),
            "same_az_subnets": (same_az_subnets),
            "cross_az_subnets": (cross_az_subnets),
            "unresolved_az_subnets": (unresolved_az_subnets),
            # Strong endpoint evidence
            "endpoint_evidence": endpoint_evidence,
            # Compatibility with existing analyzer fields
            "relevant_endpoints": (
                endpoint_evidence.get(
                    "relevant_endpoints",
                    [],
                )
            ),
            "endpoint_summary": (
                endpoint_evidence.get(
                    "summary",
                    {},
                )
            ),
            "fleet": fleet_context,
            "network_summary": {
                "subnet_count": len(
                    topology.get(
                        "subnets",
                        [],
                    )
                    or []
                ),
                "route_table_count": len(
                    topology.get(
                        "route_tables",
                        [],
                    )
                    or []
                ),
                "route_count": len(all_routes),
                "effective_route_count": len(
                    topology.get(
                        "effective_routes",
                        [],
                    )
                    or []
                ),
                "effective_route_table_mapping_count": len(
                    topology.get(
                        "effective_route_table_mappings",
                        [],
                    )
                    or []
                ),
                "endpoint_count": len(endpoints),
                "nat_gateway_count_in_vpc": (
                    fleet_context.get(
                        "nat_gateway_count",
                        0,
                    )
                ),
                "operational_nat_gateway_count_in_vpc": (
                    fleet_context.get(
                        "operational_nat_gateway_count",
                        0,
                    )
                ),
                "topology_complete": (topology_complete),
                "dependency_evidence_complete": (dependency_evidence_complete),
            },
            "summary": {
                "nat_route_count": len(all_nat_routes),
                "active_nat_route_count": len(active_nat_routes),
                "blackhole_nat_route_count": len(blackhole_nat_routes),
                "route_dependent_subnet_count": (len(dependent_subnet_ids)),
                "route_dependent_route_table_count": (len(dependent_route_table_ids)),
                "same_az_subnet_count": (len(same_az_subnets)),
                "cross_az_subnet_count": (len(cross_az_subnets)),
                "unresolved_az_subnet_count": (len(unresolved_az_subnets)),
                "has_active_route_dependency": bool(active_nat_routes),
                "has_blackhole_route_dependency": bool(blackhole_nat_routes),
                "has_same_az_route_dependency": bool(same_az_subnets),
                "has_cross_az_route_dependency": bool(cross_az_subnets),
                "regional_nat": (mode == "regional"),
                "covered_az_count": len(covered_azs),
                "relevant_endpoint_count": (
                    endpoint_evidence.get(
                        "summary",
                        {},
                    ).get(
                        "relevant_endpoint_count",
                        0,
                    )
                ),
                "relevant_endpoint_services": (
                    endpoint_evidence.get(
                        "summary",
                        {},
                    ).get(
                        "services",
                        [],
                    )
                ),
                "has_s3_endpoint_on_route_dependent_tables": (
                    endpoint_evidence.get(
                        "summary",
                        {},
                    ).get(
                        "has_s3_gateway_route_coverage",
                        False,
                    )
                ),
                "has_dynamodb_endpoint_on_route_dependent_tables": (
                    endpoint_evidence.get(
                        "summary",
                        {},
                    ).get(
                        "has_dynamodb_gateway_route_coverage",
                        False,
                    )
                ),
                "has_ecr_endpoint_on_route_dependent_tables": (
                    endpoint_evidence.get(
                        "summary",
                        {},
                    ).get(
                        "has_ecr_interface_coverage",
                        False,
                    )
                ),
                "same_az_alternative_nat_count": (
                    fleet_context.get(
                        "same_az_alternative_nat_count",
                        0,
                    )
                ),
                "same_vpc_nat_count": (
                    fleet_context.get(
                        "nat_gateway_count",
                        0,
                    )
                ),
                "same_vpc_operational_nat_count": (
                    fleet_context.get(
                        "operational_nat_gateway_count",
                        0,
                    )
                ),
                "dependency_evidence_complete": (dependency_evidence_complete),
                "topology_complete": (topology_complete),
            },
        }

    # STRONG ENDPOINT EVIDENCE

    def _build_strong_endpoint_evidence(
        self,
        *,
        endpoints: List[Dict[str, Any]],
        dependent_route_table_ids: List[str],
        dependent_subnet_ids: List[str],
        dependent_azs: List[str],
        active_nat_routes: List[Dict[str, Any]],
        topology: Dict[str, Any],
    ) -> Dict[str, Any]:

        route_table_set = {str(value) for value in dependent_route_table_ids if value}

        subnet_set = {str(value) for value in dependent_subnet_ids if value}

        az_set = {str(value) for value in dependent_azs if value}

        relevant = []

        gateway_route_coverage = []
        interface_subnet_coverage = []

        services = set()

        gateway_s3 = []
        gateway_dynamodb = []

        interface_ecr = []

        for endpoint in endpoints:

            if not isinstance(
                endpoint,
                dict,
            ):
                continue

            normalized = self._normalize_endpoint_evidence(endpoint)

            endpoint_id = normalized.get("endpoint_id")

            endpoint_type = normalized.get("endpoint_type")

            service = normalized.get("service")

            state = normalized.get("state")

            route_table_ids = {
                str(value)
                for value in normalized.get(
                    "route_table_ids",
                    [],
                )
                if value
            }

            subnet_ids = {
                str(value)
                for value in normalized.get(
                    "subnet_ids",
                    [],
                )
                if value
            }

            endpoint_azs = {
                str(value)
                for value in normalized.get(
                    "availability_zones",
                    [],
                )
                if value
            }

            route_overlap = sorted(route_table_set & route_table_ids)

            subnet_overlap = sorted(subnet_set & subnet_ids)

            az_overlap = sorted(az_set & endpoint_azs)

            route_relevant = bool(route_overlap)

            subnet_relevant = bool(subnet_overlap)

            az_relevant = bool(az_overlap)

            if route_relevant or subnet_relevant or az_relevant:

                relevant.append(
                    {
                        **normalized,
                        "relevance": {
                            "route_table_overlap": (route_overlap),
                            "subnet_overlap": (subnet_overlap),
                            "availability_zone_overlap": (az_overlap),
                            "route_relevant": (route_relevant),
                            "subnet_relevant": (subnet_relevant),
                            "availability_zone_relevant": (az_relevant),
                        },
                    }
                )

            # Gateway endpoints

            if endpoint_type == "Gateway":

                if route_relevant:

                    gateway_route_coverage.append(
                        {
                            "endpoint_id": endpoint_id,
                            "service": service,
                            "state": state,
                            "route_table_ids": sorted(route_table_ids),
                            "dependent_route_table_ids": (route_overlap),
                            "coverage_complete": (
                                route_table_set.issubset(route_table_ids)
                                if route_table_set
                                else False
                            ),
                        }
                    )

                    if service and self._is_s3_service(service):
                        gateway_s3.append(endpoint_id)

                    if service and self._is_dynamodb_service(service):
                        gateway_dynamodb.append(endpoint_id)

            # Interface endpoints

            elif endpoint_type == "Interface":

                if subnet_relevant or az_relevant:

                    interface_subnet_coverage.append(
                        {
                            "endpoint_id": endpoint_id,
                            "service": service,
                            "state": state,
                            "private_dns_enabled": (
                                normalized.get("private_dns_enabled")
                            ),
                            "subnet_ids": sorted(subnet_ids),
                            "dependent_subnet_ids": (subnet_overlap),
                            "availability_zones": sorted(endpoint_azs),
                            "dependent_availability_zones": (az_overlap),
                            "coverage_complete": (
                                subnet_set.issubset(subnet_ids) if subnet_set else False
                            ),
                        }
                    )

                    if service and self._is_ecr_service(service):
                        interface_ecr.append(endpoint_id)

            if service:
                services.add(str(service))

        relevant = sorted(
            relevant,
            key=lambda item: str(item.get("endpoint_id") or ""),
        )

        # --------------------------------------------------------------
        # Strong evidence semantics
        # --------------------------------------------------------------

        gateway_route_table_covered = {
            route_table_id
            for item in gateway_route_coverage
            for route_table_id in item.get(
                "dependent_route_table_ids",
                [],
            )
        }

        endpoint_route_table_coverage_complete = bool(
            route_table_set
        ) and route_table_set.issubset(gateway_route_table_covered)

        interface_subnet_covered = {
            subnet_id
            for item in interface_subnet_coverage
            for subnet_id in item.get(
                "dependent_subnet_ids",
                [],
            )
        }

        interface_subnet_coverage_complete = bool(subnet_set) and subnet_set.issubset(
            interface_subnet_covered
        )

        has_s3_gateway_route_coverage = bool(
            gateway_s3
            and any(
                item.get("service") and self._is_s3_service(item.get("service"))
                for item in gateway_route_coverage
            )
        )

        has_dynamodb_gateway_route_coverage = bool(
            gateway_dynamodb
            and any(
                item.get("service") and self._is_dynamodb_service(item.get("service"))
                for item in gateway_route_coverage
            )
        )

        has_ecr_interface_coverage = bool(interface_ecr)

        return {
            "status": (
                "ok"
                if isinstance(
                    endpoints,
                    list,
                )
                else "incomplete"
            ),
            "endpoint_count": len(endpoints),
            "relevant_endpoints": relevant,
            "gateway_route_coverage": (gateway_route_coverage),
            "interface_subnet_coverage": (interface_subnet_coverage),
            "route_dependent_route_table_ids": (sorted(route_table_set)),
            "route_dependent_subnet_ids": (sorted(subnet_set)),
            "route_dependent_availability_zones": (sorted(az_set)),
            "endpoint_route_table_coverage_complete": (
                endpoint_route_table_coverage_complete
            ),
            "interface_subnet_coverage_complete": (interface_subnet_coverage_complete),
            "summary": {
                "relevant_endpoint_count": len(relevant),
                "services": sorted(services),
                "gateway_endpoint_count": len(gateway_route_coverage),
                "interface_endpoint_count": len(interface_subnet_coverage),
                "has_s3_gateway_route_coverage": (has_s3_gateway_route_coverage),
                "has_dynamodb_gateway_route_coverage": (
                    has_dynamodb_gateway_route_coverage
                ),
                "has_ecr_interface_coverage": (has_ecr_interface_coverage),
                "gateway_route_table_coverage_complete": (
                    endpoint_route_table_coverage_complete
                ),
                "interface_subnet_coverage_complete": (
                    interface_subnet_coverage_complete
                ),
                # Explicitly distinguish evidence from a conclusion.
                "endpoint_opportunity_evidence_available": bool(
                    gateway_route_coverage or interface_subnet_coverage
                ),
                "does_not_prove_nat_traffic_avoidance": True,
            },
            "data_quality": {
                "endpoint_inventory_available": True,
                "route_table_context_available": bool(route_table_set),
                "subnet_context_available": bool(subnet_set),
                "az_context_available": bool(az_set),
            },
        }

    # ENDPOINT NORMALIZATION

    @staticmethod
    def _normalize_endpoint_evidence(
        endpoint: Dict[str, Any],
    ) -> Dict[str, Any]:

        endpoint_id = (
            endpoint.get("VpcEndpointId")
            or endpoint.get("VpcEndpointID")
            or endpoint.get("endpoint_id")
            or endpoint.get("id")
        )

        endpoint_type = (
            endpoint.get("VpcEndpointType")
            or endpoint.get("endpoint_type")
            or endpoint.get("type")
        )

        state = endpoint.get("State") or endpoint.get("state")

        service = (
            endpoint.get("ServiceName")
            or endpoint.get("service_name")
            or endpoint.get("service")
        )

        route_table_ids = (
            endpoint.get("RouteTableIds") or endpoint.get("route_table_ids") or []
        )

        subnet_ids = endpoint.get("SubnetIds") or endpoint.get("subnet_ids") or []

        availability_zones = (
            endpoint.get("AvailabilityZones")
            or endpoint.get("availability_zones")
            or []
        )

        private_dns_enabled = endpoint.get("PrivateDnsEnabled")

        if private_dns_enabled is None:
            private_dns_enabled = endpoint.get("private_dns_enabled")

        policy = endpoint.get("PolicyDocument") or endpoint.get("policy_document")

        dns_entries = endpoint.get("DnsEntries") or endpoint.get("dns_entries") or []

        network_interface_ids = (
            endpoint.get("NetworkInterfaceIds")
            or endpoint.get("network_interface_ids")
            or []
        )

        return {
            "endpoint_id": (str(endpoint_id) if endpoint_id else None),
            "endpoint_type": (str(endpoint_type) if endpoint_type else None),
            "state": (str(state) if state else None),
            "service": (str(service) if service else None),
            "route_table_ids": sorted(
                {str(value) for value in route_table_ids if value}
            ),
            "subnet_ids": sorted({str(value) for value in subnet_ids if value}),
            "availability_zones": sorted(
                {str(value) for value in availability_zones if value}
            ),
            "private_dns_enabled": (private_dns_enabled),
            "policy_present": (policy is not None),
            "dns_entry_count": (
                len(dns_entries)
                if isinstance(
                    dns_entries,
                    list,
                )
                else 0
            ),
            "network_interface_ids": sorted(
                {str(value) for value in network_interface_ids if value}
            ),
            "raw": endpoint,
        }

    # ENDPOINT SERVICE HELPERS

    @staticmethod
    def _is_s3_service(
        service: Optional[str],
    ) -> bool:

        if not service:
            return False

        value = str(service).lower()

        return ".s3" in value or "s3.amazonaws.com" in value

    @staticmethod
    def _is_dynamodb_service(
        service: Optional[str],
    ) -> bool:

        if not service:
            return False

        value = str(service).lower()

        return "dynamodb" in value

    @staticmethod
    def _is_ecr_service(
        service: Optional[str],
    ) -> bool:

        if not service:
            return False

        value = str(service).lower()

        return "ecr.api" in value or "ecr.dkr" in value or "ecr" in value

    # NAT FLEET

    def _build_nat_fleet_context(
        self,
        *,
        vpc_id: str,
        nat_id: str,
        route_dependent_subnet_ids: List[str],
        dependent_subnet_profiles: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        nats = list(
            self._nat_fleet_by_vpc.get(
                vpc_id,
                [],
            )
        )

        operational = [
            nat for nat in nats if nat.get("state") in self.operational_states
        ]

        regional = [
            nat for nat in operational if nat.get("availability_mode") == "regional"
        ]

        zonal = [
            nat for nat in operational if nat.get("availability_mode") != "regional"
        ]

        az_counts: dict[
            str,
            int,
        ] = defaultdict(int)

        for nat in zonal:

            az = nat.get("availability_zone")

            if az:
                az_counts[str(az)] += 1

        current = self._nat_by_id.get(
            nat_id,
            {},
        )

        current_az = current.get("availability_zone")

        same_az_alternatives = [
            nat
            for nat in operational
            if (
                nat.get("nat_gateway_id") != nat_id
                and nat.get("availability_mode") != "regional"
                and current_az
                and nat.get("availability_zone") == current_az
            )
        ]

        dependent_azs = sorted(
            {
                str(profile.get("availability_zone"))
                for profile in dependent_subnet_profiles
                if profile.get("availability_zone")
            }
        )

        covered_by_operational_nat = {
            az: [
                nat.get("nat_gateway_id")
                for nat in operational
                if (
                    nat.get("availability_mode") == "regional"
                    or nat.get("availability_zone") == az
                )
            ]
            for az in dependent_azs
        }

        return {
            "nat_gateway_count": len(nats),
            "operational_nat_gateway_count": len(operational),
            "regional_nat_gateway_count": len(regional),
            "zonal_nat_gateway_count": len(zonal),
            "nat_gateway_ids": sorted(
                {
                    str(nat.get("nat_gateway_id"))
                    for nat in nats
                    if nat.get("nat_gateway_id")
                }
            ),
            "operational_nat_gateway_ids": sorted(
                {
                    str(nat.get("nat_gateway_id"))
                    for nat in operational
                    if nat.get("nat_gateway_id")
                }
            ),
            "availability_zone_nat_counts": dict(sorted(az_counts.items())),
            "dependent_availability_zones": (dependent_azs),
            "same_az_alternative_nat_ids": sorted(
                {
                    str(nat.get("nat_gateway_id"))
                    for nat in same_az_alternatives
                    if nat.get("nat_gateway_id")
                }
            ),
            "same_az_alternative_nat_count": len(same_az_alternatives),
            "dependent_az_nat_coverage": (covered_by_operational_nat),
            "has_regional_nat": bool(regional),
            "has_multiple_operational_nats": (len(operational) > 1),
            "has_multiple_nats_in_same_az": any(
                count > 1 for count in az_counts.values()
            ),
            "current_nat_availability_zone": (current_az),
            "current_nat_is_regional": (current.get("availability_mode") == "regional"),
            "current_nat_operational": (
                current.get("state") in self.operational_states
            ),
            "route_dependent_subnet_count": len(route_dependent_subnet_ids),
        }

    # OPTIMIZATION EVIDENCE

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._dict(collected_resource.get("identity"))

        configuration = self._dict(collected_resource.get("configuration"))

        observations = self._dict(collected_resource.get("observations"))

        topology = self._dict(collected_resource.get("topology"))

        derived = self._dict(observations.get("derived"))

        traffic = self._dict(derived.get("traffic"))

        connections = self._dict(derived.get("connections"))

        diagnostics = self._dict(derived.get("diagnostics"))

        packets = self._dict(derived.get("packets"))

        peak = self._dict(derived.get("peak"))

        activity = self._dict(derived.get("activity"))

        semantics = self._dict(derived.get("semantics"))

        summary = self._dict(topology.get("summary"))

        fleet = self._dict(topology.get("fleet"))

        endpoint_evidence = self._dict(topology.get("endpoint_evidence"))

        endpoint_summary = self._dict(endpoint_evidence.get("summary"))

        cloudwatch = self._dict(observations.get("cloudwatch"))

        return {
            "resource": {
                "id": resource.get("id"),
                "name": identity.get("name"),
                "state": identity.get("state"),
                "state_category": identity.get("state_category"),
            },
            "configuration": {
                "nat_gateway_id": configuration.get("nat_gateway_id"),
                "vpc_id": configuration.get("vpc_id"),
                "subnet_id": configuration.get("subnet_id"),
                "availability_zone": configuration.get("availability_zone"),
                "availability_zones": configuration.get(
                    "availability_zones",
                    [],
                ),
                "availability_mode": configuration.get("availability_mode"),
                "regional": configuration.get("regional"),
                "connectivity_type": configuration.get("connectivity_type"),
                "address_count": configuration.get("address_count"),
                "attached_appliances": configuration.get(
                    "attached_appliances",
                    [],
                ),
                "auto_provision_zones": configuration.get("auto_provision_zones"),
                "auto_scaling_ips": configuration.get("auto_scaling_ips"),
                "state": configuration.get("state"),
            },
            "activity": {
                "traffic_available": traffic.get("available"),
                "traffic_complete": traffic.get("complete"),
                "traffic_observed": traffic.get("observed"),
                "traffic_zero": traffic.get("zero"),
                "traffic_bytes": traffic.get("traffic_bytes"),
                "traffic_gib": traffic.get("traffic_gib"),
                "bytes_in_from_source": traffic.get("bytes_in_from_source"),
                "bytes_out_to_destination": traffic.get("bytes_out_to_destination"),
                "bytes_in_from_destination": traffic.get("bytes_in_from_destination"),
                "bytes_out_to_source": traffic.get("bytes_out_to_source"),
                "primary_path_bytes": traffic.get("primary_path_bytes"),
                "reverse_path_bytes": traffic.get("reverse_path_bytes"),
                "connection_metrics_available": (connections.get("available")),
                "connection_complete": (connections.get("complete")),
                "active_connections": (connections.get("active")),
                "active_connections_zero": (connections.get("active_zero")),
                "active_connections_positive": (connections.get("active_positive")),
                "connection_attempts": (diagnostics.get("connection_attempts")),
                "connections_established": (diagnostics.get("connections_established")),
                "error_port_allocation": (diagnostics.get("error_port_allocation")),
                "idle_timeouts": (diagnostics.get("idle_timeouts")),
                "packets_dropped": (diagnostics.get("packets_dropped")),
                "diagnostic_activity": (diagnostics.get("activity_observed")),
                "packet_metrics": packets,
                "peak": peak,
                "core_activity_observed": (activity.get("observed")),
                "traffic_observed": (activity.get("traffic_observed")),
                "connection_observed": (activity.get("connection_observed")),
                "core_traffic_zero": (activity.get("core_traffic_zero")),
                "core_connections_zero": (activity.get("core_connections_zero")),
            },
            "network": {
                "topology_status": topology.get("status"),
                "topology_complete": (summary.get("topology_complete")),
                "dependency_evidence_complete": (
                    summary.get(
                        "dependency_evidence_complete",
                        topology.get("dependency_evidence_complete"),
                    )
                ),
                "nat_route_count": summary.get(
                    "nat_route_count",
                    0,
                ),
                "active_nat_route_count": summary.get(
                    "active_nat_route_count",
                    0,
                ),
                "blackhole_nat_route_count": summary.get(
                    "blackhole_nat_route_count",
                    0,
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
                "same_az_subnet_count": summary.get(
                    "same_az_subnet_count",
                    0,
                ),
                "cross_az_subnet_count": summary.get(
                    "cross_az_subnet_count",
                    0,
                ),
                "unresolved_az_subnet_count": summary.get(
                    "unresolved_az_subnet_count",
                    0,
                ),
                "has_active_route_dependency": summary.get(
                    "has_active_route_dependency",
                    False,
                ),
                "has_blackhole_route_dependency": summary.get(
                    "has_blackhole_route_dependency",
                    False,
                ),
                "has_same_az_route_dependency": summary.get(
                    "has_same_az_route_dependency",
                    False,
                ),
                "has_cross_az_route_dependency": summary.get(
                    "has_cross_az_route_dependency",
                    False,
                ),
                "regional_nat": summary.get(
                    "regional_nat",
                    False,
                ),
                "covered_az_count": summary.get(
                    "covered_az_count",
                    0,
                ),
            },
            # Strong endpoint evidence
            "endpoints": {
                "endpoint_count": (
                    endpoint_evidence.get(
                        "endpoint_count",
                        0,
                    )
                ),
                "relevant_endpoint_count": (
                    endpoint_summary.get(
                        "relevant_endpoint_count",
                        0,
                    )
                ),
                "services": endpoint_summary.get(
                    "services",
                    [],
                ),
                "gateway_route_coverage": (
                    endpoint_evidence.get(
                        "gateway_route_coverage",
                        [],
                    )
                ),
                "interface_subnet_coverage": (
                    endpoint_evidence.get(
                        "interface_subnet_coverage",
                        [],
                    )
                ),
                "route_table_coverage_complete": (
                    endpoint_evidence.get("endpoint_route_table_coverage_complete")
                ),
                "interface_subnet_coverage_complete": (
                    endpoint_evidence.get("interface_subnet_coverage_complete")
                ),
                "has_s3_gateway_route_coverage": (
                    endpoint_summary.get(
                        "has_s3_gateway_route_coverage",
                        False,
                    )
                ),
                "has_dynamodb_gateway_route_coverage": (
                    endpoint_summary.get(
                        "has_dynamodb_gateway_route_coverage",
                        False,
                    )
                ),
                "has_ecr_interface_coverage": (
                    endpoint_summary.get(
                        "has_ecr_interface_coverage",
                        False,
                    )
                ),
                "endpoint_opportunity_evidence_available": (
                    endpoint_summary.get(
                        "endpoint_opportunity_evidence_available",
                        False,
                    )
                ),
                "does_not_prove_nat_traffic_avoidance": True,
            },
            "fleet": fleet,
            "topology_detail": {
                "route_dependent_subnet_ids": topology.get(
                    "route_dependent_subnet_ids",
                    [],
                ),
                "route_dependent_route_table_ids": topology.get(
                    "route_dependent_route_table_ids",
                    [],
                ),
                "dependent_availability_zones": topology.get(
                    "dependent_availability_zones",
                    [],
                ),
                "same_az_subnets": topology.get(
                    "same_az_subnets",
                    [],
                ),
                "cross_az_subnets": topology.get(
                    "cross_az_subnets",
                    [],
                ),
                "unresolved_az_subnets": topology.get(
                    "unresolved_az_subnets",
                    [],
                ),
                "nat_routes": topology.get(
                    "nat_routes",
                    [],
                ),
                "active_nat_routes": topology.get(
                    "active_nat_routes",
                    [],
                ),
                "blackhole_nat_routes": topology.get(
                    "blackhole_nat_routes",
                    [],
                ),
                "relevant_endpoints": topology.get(
                    "relevant_endpoints",
                    [],
                ),
            },
            "data_quality": {
                "cloudwatch_status": observations.get("status"),
                "cloudwatch_available": bool(cloudwatch.get("metrics")),
                "traffic_available": traffic.get("available"),
                "traffic_complete": traffic.get("complete"),
                "connection_data_available": connections.get("available"),
                "connection_data_complete": connections.get("complete"),
                "diagnostic_data_available": diagnostics.get("available"),
                "diagnostic_data_complete": diagnostics.get("complete"),
                "topology_available": topology.get("status")
                in {
                    "ok",
                    "partial",
                },
                "topology_complete": summary.get("topology_complete"),
                "dependency_evidence_complete": topology.get(
                    "dependency_evidence_complete"
                ),
                "endpoint_inventory_available": ("endpoint_evidence" in topology),
                "traffic_semantics_valid": semantics.get("traffic_semantics_valid"),
                "connection_semantics_valid": semantics.get(
                    "connection_semantics_valid"
                ),
                "diagnostic_semantics_valid": semantics.get(
                    "diagnostic_semantics_valid"
                ),
                "missing_is_zero": False,
            },
            "semantics": {
                "traffic_is_billing_usage": False,
                "connection_is_billing_usage": False,
                "diagnostic_is_billing_usage": False,
                "traffic_indicator": ("nat_gateway_processed_traffic_evidence"),
                "connection_indicator": ("nat_gateway_active_connection_evidence"),
                "diagnostic_indicator": ("nat_gateway_connection_diagnostic_evidence"),
                "billing_attribution": ("handled_by_cost_reconciliation"),
            },
        }
