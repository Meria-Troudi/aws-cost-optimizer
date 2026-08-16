"""
Elastic Load Balancer collector.

Metric configuration is supplied entirely by collection_profiles.yaml.

The collector does NOT hardcode:
    - metric names
    - statistics
    - units
    - metric keys
    - metric scopes

The YAML profile defines the required CloudWatch dimensions.

Example:

    metrics:
      - name: RequestCount
        statistic: Sum
        unit: Count
        key: request_count
        dimensions:
          - LoadBalancer

      - name: HealthyHostCount
        statistic: Average
        unit: Count
        key: healthy_host_count
        dimensions:
          - LoadBalancer
          - TargetGroup

CloudWatch dimension values are resolved dynamically from the
load balancer and its target groups.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register

from collectors.network.topology import (
    NetworkTopologyCollector,
)

from collectors.network.relationships import (
    NetworkRelationshipResolver,
)

from collectors.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)


@register
class ElbCollector(BaseCollector):

    key = "elb"
    resource_type = "load_balancer"

    def __init__(
        self,
        scan,
        region: Optional[str] = None,
        profile: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            scan,
            region=region,
            profile=profile,
        )

        self.region = region or scan.region

        self.elbv2 = get_client(
            "elbv2",
            self.region,
        )

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = (
            CloudWatchMetricCollector(
                self.cloudwatch
            )
        )

        self.topology_collector = (
            NetworkTopologyCollector(
                self.region
            )
        )

    # ==================================================================
    # DISCOVERY
    # ==================================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: List[Dict[str, Any]] = []

        paginator = (
            self.elbv2.get_paginator(
                "describe_load_balancers"
            )
        )

        for page in paginator.paginate():

            for load_balancer in page.get(
                "LoadBalancers",
                [],
            ):

                arn = load_balancer.get(
                    "LoadBalancerArn"
                )

                if not arn:
                    continue

                resources.append(
                    load_balancer
                )

        return resources

    # ==================================================================
    # RESOURCE IDENTITY
    # ==================================================================

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        arn = resource.get(
            "LoadBalancerArn"
        )

        if not arn:
            raise ValueError(
                "Load balancer ARN is missing"
            )

        return arn

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        state = (
            resource.get(
                "State"
            )
            or {}
        )

        return {
            "load_balancer_arn":
                resource.get(
                    "LoadBalancerArn"
                ),

            "load_balancer_name":
                resource.get(
                    "LoadBalancerName"
                ),

            "type":
                resource.get(
                    "Type"
                ),

            "scheme":
                resource.get(
                    "Scheme"
                ),

            "state":
                state.get(
                    "Code"
                ),

            "state_reason":
                state.get(
                    "Reason"
                ),

            "created_time":
                self._isoformat(
                    resource.get(
                        "CreatedTime"
                    )
                ),

            "vpc_id":
                resource.get(
                    "VpcId"
                ),

            "dns_name":
                resource.get(
                    "DNSName"
                ),

            "canonical_hosted_zone_id":
                resource.get(
                    "CanonicalHostedZoneId"
                ),

            "ip_address_type":
                resource.get(
                    "IpAddressType"
                ),

            "tags":
                self._get_tags(
                    resource.get(
                        "Tags",
                        [],
                    )
                ),
        }

    # ==================================================================
    # CONFIGURATION
    # ==================================================================

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        availability_zones = (
            self._normalize_availability_zones(
                resource.get(
                    "AvailabilityZones",
                    [],
                )
            )
        )

        subnet_ids = sorted(
            {
                item.get("subnet_id")
                for item in availability_zones
                if item.get("subnet_id")
            }
        )

        security_groups = sorted(
            {
                str(group_id)
                for group_id in (
                    resource.get(
                        "SecurityGroups",
                        [],
                    )
                    or []
                )
                if group_id
            }
        )

        ipam_pools = (
            resource.get(
                "IpamPools"
            )
            or {}
        )

        return {
            "load_balancer_arn":
                resource.get(
                    "LoadBalancerArn"
                ),

            "load_balancer_name":
                resource.get(
                    "LoadBalancerName"
                ),

            "type":
                resource.get(
                    "Type"
                ),

            "scheme":
                resource.get(
                    "Scheme"
                ),

            "state":
                (
                    resource.get(
                        "State"
                    )
                    or {}
                ).get("Code"),

            "state_reason":
                (
                    resource.get(
                        "State"
                    )
                    or {}
                ).get("Reason"),

            "created_time":
                self._isoformat(
                    resource.get(
                        "CreatedTime"
                    )
                ),

            "vpc_id":
                resource.get(
                    "VpcId"
                ),

            "dns_name":
                resource.get(
                    "DNSName"
                ),

            "canonical_hosted_zone_id":
                resource.get(
                    "CanonicalHostedZoneId"
                ),

            "ip_address_type":
                resource.get(
                    "IpAddressType"
                ),

            "availability_zones":
                availability_zones,

            "availability_zone_count":
                len(
                    availability_zones
                ),

            "subnet_ids":
                subnet_ids,

            "subnet_count":
                len(
                    subnet_ids
                ),

            "security_groups":
                security_groups,

            "security_group_count":
                len(
                    security_groups
                ),

            "customer_owned_ipv4_pool":
                resource.get(
                    "CustomerOwnedIpv4Pool"
                ),

            "enforce_security_group_inbound_rules_on_private_link_traffic":
                resource.get(
                    "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic"
                ),

            "enable_prefix_for_ipv6_source_nat":
                resource.get(
                    "EnablePrefixForIpv6SourceNat"
                ),

            "ipam_pool_id":
                ipam_pools.get(
                    "Ipv4IpamPoolId"
                ),

            "tags":
                self._get_tags(
                    resource.get(
                        "Tags",
                        [],
                    )
                ),
        }

    # ==================================================================
    # RELATIONSHIPS
    # ==================================================================

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        load_balancer_arn = resource.get(
            "LoadBalancerArn"
        )

        if not load_balancer_arn:
            return {
                "status": "incomplete",
                "reason":
                    "Load balancer ARN is not available",
            }

        listeners = (
            self._collect_listeners(
                load_balancer_arn
            )
        )

        rules = (
            self._collect_listener_rules(
                listeners
            )
        )

        target_groups = (
            self._collect_target_groups(
                load_balancer_arn
            )
        )

        target_count = sum(
            int(
                target_group.get(
                    "target_count",
                    0,
                )
                or 0
            )
            for target_group in target_groups
        )

        healthy_target_count = sum(
            int(
                target_group.get(
                    "healthy_target_count",
                    0,
                )
                or 0
            )
            for target_group in target_groups
        )

        unhealthy_target_count = sum(
            int(
                target_group.get(
                    "unhealthy_target_count",
                    0,
                )
                or 0
            )
            for target_group in target_groups
        )

        listener_target_group_ids = sorted(
            {
                target_group_id
                for listener in listeners
                for target_group_id in (
                    listener.get(
                        "default_target_group_ids",
                        [],
                    )
                )
                if target_group_id
            }
        )

        target_group_arns = sorted(
            {
                target_group.get(
                    "target_group_arn"
                )
                for target_group in target_groups
                if target_group.get(
                    "target_group_arn"
                )
            }
        )

        target_types = sorted(
            {
                target_group.get(
                    "target_type"
                )
                for target_group in target_groups
                if target_group.get(
                    "target_type"
                )
            }
        )

        return {
            "status": "ok",

            "listeners":
                listeners,

            "rules":
                rules,

            "target_groups":
                target_groups,

            "summary": {
                "listener_count":
                    len(listeners),

                "rule_count":
                    len(rules),

                "target_group_count":
                    len(target_groups),

                "target_group_arns":
                    target_group_arns,

                "listener_target_group_count":
                    len(
                        listener_target_group_ids
                    ),

                "target_count":
                    target_count,

                "healthy_target_count":
                    healthy_target_count,

                "unhealthy_target_count":
                    unhealthy_target_count,

                "target_types":
                    target_types,

                "has_targets":
                    target_count > 0,

                "has_healthy_targets":
                    healthy_target_count > 0,

                "has_unhealthy_targets":
                    unhealthy_target_count > 0,

                "has_listeners":
                    bool(listeners),

                "has_rules":
                    bool(rules),
            },
        }

    # ==================================================================
    # LISTENERS
    # ==================================================================

    def _collect_listeners(
        self,
        load_balancer_arn: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        paginator = (
            self.elbv2.get_paginator(
                "describe_listeners"
            )
        )

        for page in paginator.paginate(
            LoadBalancerArn=load_balancer_arn
        ):

            for listener in page.get(
                "Listeners",
                [],
            ):

                default_actions = (
                    listener.get(
                        "DefaultActions",
                        [],
                    )
                    or []
                )

                default_target_group_ids = sorted(
                    {
                        action.get(
                            "TargetGroupArn"
                        )
                        for action in default_actions
                        if action.get(
                            "TargetGroupArn"
                        )
                    }
                )

                result.append(
                    {
                        "listener_arn":
                            listener.get(
                                "ListenerArn"
                            ),

                        "load_balancer_arn":
                            listener.get(
                                "LoadBalancerArn"
                            ),

                        "protocol":
                            listener.get(
                                "Protocol"
                            ),

                        "port":
                            listener.get(
                                "Port"
                            ),

                        "ssl_policy":
                            listener.get(
                                "SslPolicy"
                            ),

                        "certificates":
                            listener.get(
                                "Certificates",
                                [],
                            ),

                        "default_actions":
                            default_actions,

                        "default_target_group_ids":
                            default_target_group_ids,

                        "alpn_policy":
                            listener.get(
                                "AlpnPolicy",
                                [],
                            ),

                        "mutual_authentication":
                            listener.get(
                                "MutualAuthentication"
                            ),
                    }
                )

        return result

    # ==================================================================
    # LISTENER RULES
    # ==================================================================

    def _collect_listener_rules(
        self,
        listeners: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        paginator = (
            self.elbv2.get_paginator(
                "describe_rules"
            )
        )

        for listener in listeners:

            listener_arn = listener.get(
                "listener_arn"
            )

            if not listener_arn:
                continue

            try:

                for page in paginator.paginate(
                    ListenerArn=listener_arn
                ):

                    for rule in page.get(
                        "Rules",
                        [],
                    ):

                        actions = (
                            rule.get(
                                "Actions",
                                [],
                            )
                            or []
                        )

                        target_group_ids = sorted(
                            {
                                action.get(
                                    "TargetGroupArn"
                                )
                                for action in actions
                                if action.get(
                                    "TargetGroupArn"
                                )
                            }
                        )

                        result.append(
                            {
                                "rule_arn":
                                    rule.get(
                                        "RuleArn"
                                    ),

                                "listener_arn":
                                    listener_arn,

                                "priority":
                                    rule.get(
                                        "Priority"
                                    ),

                                "is_default":
                                    rule.get(
                                        "IsDefault"
                                    )
                                    is True,

                                "conditions":
                                    rule.get(
                                        "Conditions",
                                        [],
                                    ),

                                "actions":
                                    actions,

                                "target_group_ids":
                                    target_group_ids,

                                "status":
                                    rule.get(
                                        "Status"
                                    ),
                            }
                        )

            except Exception as exc:

                result.append(
                    {
                        "listener_arn":
                            listener_arn,

                        "status":
                            "error",

                        "error":
                            str(exc),
                    }
                )

        return result

    # ==================================================================
    # TARGET GROUPS
    # ==================================================================

    def _collect_target_groups(
        self,
        load_balancer_arn: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        paginator = (
            self.elbv2.get_paginator(
                "describe_target_groups"
            )
        )

        for page in paginator.paginate(
            LoadBalancerArn=load_balancer_arn
        ):

            for target_group in page.get(
                "TargetGroups",
                [],
            ):

                target_group_arn = (
                    target_group.get(
                        "TargetGroupArn"
                    )
                )

                if not target_group_arn:
                    continue

                target_health = (
                    self._collect_target_health(
                        target_group_arn
                    )
                )

                states = [
                    target.get("health")
                    for target in target_health
                    if isinstance(target, dict)
                    and target.get("health")
                ]

                result.append(
                    {
                        "target_group_arn":
                            target_group_arn,

                        "target_group_name":
                            target_group.get(
                                "TargetGroupName"
                            ),

                        "protocol":
                            target_group.get(
                                "Protocol"
                            ),

                        "protocol_version":
                            target_group.get(
                                "ProtocolVersion"
                            ),

                        "port":
                            target_group.get(
                                "Port"
                            ),

                        "target_type":
                            target_group.get(
                                "TargetType"
                            ),

                        "ip_address_type":
                            target_group.get(
                                "IpAddressType"
                            ),

                        "vpc_id":
                            target_group.get(
                                "VpcId"
                            ),

                        "health_check_enabled":
                            target_group.get(
                                "HealthCheckEnabled"
                            ),

                        "health_check_protocol":
                            target_group.get(
                                "HealthCheckProtocol"
                            ),

                        "health_check_port":
                            target_group.get(
                                "HealthCheckPort"
                            ),

                        "health_check_path":
                            target_group.get(
                                "HealthCheckPath"
                            ),

                        "health_check_interval_seconds":
                            target_group.get(
                                "HealthCheckIntervalSeconds"
                            ),

                        "health_check_timeout_seconds":
                            target_group.get(
                                "HealthCheckTimeoutSeconds"
                            ),

                        "healthy_threshold_count":
                            target_group.get(
                                "HealthyThresholdCount"
                            ),

                        "unhealthy_threshold_count":
                            target_group.get(
                                "UnhealthyThresholdCount"
                            ),

                        "matcher":
                            target_group.get(
                                "Matcher"
                            ),

                        "load_balancer_arns":
                            target_group.get(
                                "LoadBalancerArns",
                                [],
                            ),

                        "stickiness_enabled":
                            self._extract_stickiness_enabled(
                                target_group
                            ),

                        "targets":
                            target_health,

                        "target_count":
                            len(target_health),

                        "healthy_target_count":
                            states.count("healthy"),

                        "unhealthy_target_count":
                            states.count("unhealthy"),

                        "initial_target_count":
                            states.count("initial"),

                        "draining_target_count":
                            states.count("draining"),

                        "unused_target_count":
                            states.count("unused"),
                    }
                )

        return result

    def _collect_target_health(
        self,
        target_group_arn: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        try:

            paginator = (
                self.elbv2.get_paginator(
                    "describe_target_health"
                )
            )

            for page in paginator.paginate(
                TargetGroupArn=target_group_arn
            ):

                for description in page.get(
                    "TargetHealthDescriptions",
                    [],
                ):

                    target = (
                        description.get(
                            "Target"
                        )
                        or {}
                    )

                    health = (
                        description.get(
                            "TargetHealth"
                        )
                        or {}
                    )

                    anomaly = (
                        description.get(
                            "AnomalyDetection"
                        )
                        or {}
                    )

                    result.append(
                        {
                            "id":
                                target.get("Id"),

                            "port":
                                target.get("Port"),

                            "availability_zone":
                                description.get(
                                    "AvailabilityZone"
                                ),

                            "health":
                                health.get("State"),

                            "reason":
                                health.get("Reason"),

                            "description":
                                health.get("Description"),

                            "anomaly_detection":
                                anomaly,
                        }
                    )

        except Exception as exc:

            return [
                {
                    "status": "error",
                    "error": str(exc),
                }
            ]

        return result

    # ==================================================================
    # CLOUDWATCH OBSERVATIONS
    # ==================================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        observations_config = (
            self._get_observations_config()
        )

        cloudwatch_config = (
            observations_config.get(
                "cloudwatch",
                {},
            )
        )

        if not isinstance(
            cloudwatch_config,
            dict,
        ):
            cloudwatch_config = {}

        if cloudwatch_config.get(
            "enabled",
            True,
        ) is not True:

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                }
            }

        namespace = (
            cloudwatch_config.get(
                "namespace"
            )
        )

        if not namespace:

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                    "reason":
                        "CloudWatch namespace is not configured",
                }
            }

        try:

            requested_period = int(
                cloudwatch_config.get(
                    "period",
                    3600,
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            requested_period = 3600

        metric_specs = (
            cloudwatch_config.get(
                "metrics"
            )
        )

        if not isinstance(
            metric_specs,
            list,
        ) or not metric_specs:

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                    "namespace": namespace,
                    "reason":
                        "No CloudWatch metrics configured",
                }
            }

        load_balancer_arn = (
            resource.get(
                "LoadBalancerArn"
            )
        )

        if not load_balancer_arn:

            return {
                "cloudwatch": {
                    "status": "error",
                    "namespace": namespace,
                    "metrics": {},
                    "error":
                        "Load balancer ARN is not available",
                }
            }

        start, end = (
            self.get_analysis_period()
        )

        available_dimensions = (
            self._build_cloudwatch_dimension_values(
                resource
            )
        )

        all_metrics: Dict[str, Any] = {}
        query_descriptions: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for raw_spec in metric_specs:

            if not isinstance(
                raw_spec,
                dict,
            ):
                continue

            metric_name = str(
                raw_spec.get(
                    "name",
                    "",
                )
            ).strip()

            if not metric_name:
                continue

            dimensions_config = (
                raw_spec.get(
                    "dimensions",
                    [],
                )
            )

            if not isinstance(
                dimensions_config,
                list,
            ):
                dimensions_config = []

            dimensions_config = [
                str(item)
                for item in dimensions_config
                if item
            ]

            dimension_sets = (
                self._resolve_dimension_sets(
                    dimensions_config,
                    available_dimensions,
                )
            )

            if not dimension_sets:

                query_descriptions.append(
                    {
                        "metric_name":
                            metric_name,

                        "status":
                            "skipped",

                        "reason":
                            "No valid dimension set could be resolved",

                        "configured_dimensions":
                            dimensions_config,
                    }
                )

                continue

            for dimension_index, dimensions in enumerate(
                dimension_sets
            ):

                metric_spec = dict(
                    raw_spec
                )

                metric_spec.pop(
                    "dimensions",
                    None,
                )

                metric_spec["key"] = (
                    raw_spec.get("key")
                    or metric_name
                )

                result = (
                    self._query_metric(
                        namespace=namespace,
                        metric_spec=metric_spec,
                        dimensions=dimensions,
                        start=start,
                        end=end,
                        requested_period=requested_period,
                    )
                )

                if not result:
                    continue

                dimension_suffix = (
                    self._dimension_key(
                        dimensions
                    )
                )

                base_key = (
                    raw_spec.get("key")
                    or metric_name
                )

                if len(
                    dimension_sets
                ) == 1 and not dimension_suffix:

                    metric_key = base_key

                else:

                    metric_key = (
                        f"{base_key}"
                        f"[{dimension_suffix}]"
                    )

                result["metric_key"] = (
                    metric_key
                )

                result["configured_dimensions"] = (
                    dimensions_config
                )

                result["dimensions"] = (
                    dimensions
                )

                all_metrics[
                    metric_key
                ] = result

                query_descriptions.append(
                    {
                        "metric_name":
                            metric_name,

                        "metric_key":
                            metric_key,

                        "configured_dimensions":
                            dimensions_config,

                        "dimensions":
                            dimensions,

                        "status":
                            result.get(
                                "status"
                            ),
                    }
                )

                if result.get(
                    "status"
                ) == "error":

                    errors.append(
                        {
                            "metric_name":
                                metric_name,

                            "metric_key":
                                metric_key,

                            "error":
                                result.get(
                                    "error"
                                ),
                        }
                    )

        queried_count = len(
            all_metrics
        )

        observed_count = sum(
            1
            for metric in all_metrics.values()
            if (
                metric.get("status") == "ok"
                and metric.get("has_data") is True
            )
        )

        no_data_count = sum(
            1
            for metric in all_metrics.values()
            if metric.get("status")
            in {
                "no_data",
                "missing",
            }
            or (
                metric.get("status") == "ok"
                and metric.get("has_data") is not True
            )
        )

        error_count = sum(
            1
            for metric in all_metrics.values()
            if metric.get(
                "status"
            ) == "error"
        )

        effective_period = (
            self._effective_period(
                all_metrics,
                requested_period,
            )
        )

        metric_state = (
            "error"
            if (
                queried_count > 0
                and error_count == queried_count
            )
            else (
                "observed"
                if observed_count > 0
                else (
                    "no_data"
                    if queried_count > 0
                    else "not_queried"
                )
            )
        )

        return {
            "cloudwatch": {
                "status":
                    "ok",

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

                "metrics":
                    all_metrics,

                "query_descriptions":
                    query_descriptions,

                "metric_state":
                    metric_state,

                "metric_counts": {
                    "queried":
                        queried_count,

                    "observed":
                        observed_count,

                    "no_data":
                        no_data_count,

                    "errors":
                        error_count,
                },

                "activity":
                    self._build_activity_summary(
                        all_metrics
                    ),

                "data_quality": {
                    "metric_count":
                        queried_count,

                    "queried_metric_count":
                        queried_count,

                    "observed_metric_count":
                        observed_count,

                    "no_data_metric_count":
                        no_data_count,

                    "metric_error_count":
                        error_count,

                    "observation_window_available":
                        True,
                },

                **(
                    {
                        "errors":
                            errors
                    }
                    if errors
                    else {}
                ),
            }
        }

    # ==================================================================
    # CLOUDWATCH CONFIGURATION
    # ==================================================================

    def _build_cloudwatch_dimension_values(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        values: Dict[str, List[str]] = {
            "LoadBalancer": [],
            "TargetGroup": [],
            "AvailabilityZone": [],
        }

        load_balancer_arn = (
            resource.get(
                "LoadBalancerArn"
            )
        )

        if load_balancer_arn:
            values["LoadBalancer"] = [
                self._cloudwatch_dimension(
                    load_balancer_arn
                )
            ]

        load_balancer_type = str(
            resource.get(
                "Type"
            )
            or ""
        ).lower()

        if load_balancer_type == "application":
            target_groups = (
                self._collect_metric_target_groups(
                    load_balancer_arn
                )
            )

            values["TargetGroup"] = sorted(
                {
                    self._cloudwatch_target_group_dimension(
                        target_group["TargetGroupArn"]
                    )
                    for target_group in target_groups
                    if target_group.get(
                        "TargetGroupArn"
                    )
                }
            )

        values["AvailabilityZone"] = sorted(
            {
                zone.get("ZoneName")
                for zone in (
                    resource.get(
                        "AvailabilityZones",
                        [],
                    )
                    or []
                )
                if isinstance(zone, dict)
                and zone.get("ZoneName")
            }
        )

        return values

    def _resolve_dimension_sets(
        self,
        dimension_names: List[str],
        available: Dict[str, List[str]],
    ) -> List[List[Dict[str, str]]]:

        if not dimension_names:
            return [[]]

        normalized = [
            str(name).strip()
            for name in dimension_names
            if str(name).strip()
        ]

        if not normalized:
            return [[]]

        for name in normalized:

            if name not in available:
                return []

            if not available[name]:
                return []

        combinations: List[List[Dict[str, str]]] = [[]]

        for dimension_name in normalized:

            next_combinations = []

            for combination in combinations:

                for value in available[
                    dimension_name
                ]:

                    next_combinations.append(
                        combination
                        + [
                            {
                                "Name":
                                    dimension_name,

                                "Value":
                                    value,
                            }
                        ]
                    )

            combinations = (
                next_combinations
            )

        return combinations

    @staticmethod
    def _dimension_key(
        dimensions: List[Dict[str, str]],
    ) -> str:

        parts = []

        for dimension in dimensions:

            name = dimension.get(
                "Name"
            )

            value = dimension.get(
                "Value"
            )

            if name and value:

                parts.append(
                    f"{name}={value}"
                )

        return ",".join(parts)

    def _query_metric(
        self,
        *,
        namespace: str,
        metric_spec: Dict[str, Any],
        dimensions: List[Dict[str, str]],
        start,
        end,
        requested_period: int,
    ) -> Dict[str, Any]:

        try:

            results = (
                self.metric_collector.collect(
                    namespace=namespace,
                    dimensions=dimensions,
                    metric_specs=[
                        metric_spec
                    ],
                    start=start,
                    end=end,
                    requested_period=requested_period,
                )
            )

        except Exception as exc:

            return {
                "metric_name":
                    metric_spec.get(
                        "name"
                    ),

                "status":
                    "error",

                "has_data":
                    False,

                "value":
                    None,

                "requested_period":
                    requested_period,

                "effective_period":
                    requested_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions":
                    dimensions,

                "error":
                    str(exc),
            }

        if not results:

            return {
                "metric_name":
                    metric_spec.get(
                        "name"
                    ),

                "status":
                    "no_data",

                "has_data":
                    False,

                "value":
                    None,

                "requested_period":
                    requested_period,

                "effective_period":
                    requested_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions":
                    dimensions,
            }

        result = results[0]

        if not isinstance(
            result,
            dict,
        ):

            return {
                "metric_name":
                    metric_spec.get(
                        "name"
                    ),

                "status":
                    "no_data",

                "has_data":
                    False,

                "value":
                    None,

                "requested_period":
                    requested_period,

                "effective_period":
                    requested_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions":
                    dimensions,
            }

        result = dict(
            result
        )

        result.setdefault(
            "metric_name",
            metric_spec.get(
                "name"
            ),
        )

        result.setdefault(
            "dimensions",
            dimensions,
        )

        result.setdefault(
            "requested_period",
            requested_period,
        )

        result.setdefault(
            "effective_period",
            requested_period,
        )

        result["metric_config"] = {
            key: value
            for key, value in metric_spec.items()
            if key not in {
                "dimensions"
            }
        }

        return result

    # ==================================================================
    # TOPOLOGY
    # ==================================================================

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        vpc_id = resource.get(
            "VpcId"
        )

        if not vpc_id:
            return {
                "status":
                    "incomplete",

                "reason":
                    "VPC ID not available",
            }

        try:

            topology = (
                self.topology_collector.collect(
                    vpc_id=vpc_id,
                    resource_type=self.resource_type,
                    resource_id=resource.get(
                        "LoadBalancerArn"
                    ),
                )
            )

        except Exception as exc:

            return {
                "status":
                    "error",

                "vpc_id":
                    vpc_id,

                "error":
                    str(exc),
            }

        if topology.get(
            "status"
        ) != "ok":
            return topology

        resolver = (
            NetworkRelationshipResolver(
                topology
            )
        )

        subnet_ids = [
            item.get(
                "SubnetId"
            )
            for item in (
                resource.get(
                    "AvailabilityZones",
                    [],
                )
                or []
            )
            if isinstance(item, dict)
            and item.get(
                "SubnetId"
            )
        ]

        load_balancer_routes = []

        for subnet_id in subnet_ids:

            subnet_routes = (
                resolver.routes_for_subnet(
                    subnet_id
                )
            )

            for route in subnet_routes:

                load_balancer_routes.append(
                    {
                        **route,

                        "load_balancer_subnet_id":
                            subnet_id,

                        "context_kind":
                            "load_balancer_subnet_route",
                    }
                )

        route_targets = (
            self._summarize_route_targets(
                load_balancer_routes
            )
        )

        network_interfaces = (
            self._collect_load_balancer_enis(
                resource
            )
        )

        topology["load_balancer"] = {
            "subnet_ids":
                subnet_ids,

            "network_interfaces":
                network_interfaces,

            "route_context":
                load_balancer_routes,

            "route_target_summary":
                route_targets,
        }

        existing_summary = (
            topology.get(
                "summary",
                {},
            )
        )

        if not isinstance(
            existing_summary,
            dict,
        ):
            existing_summary = {}

        topology["summary"] = {
            **existing_summary,

            "load_balancer_subnet_count":
                len(subnet_ids),

            "load_balancer_network_interface_count":
                len(network_interfaces),

            "load_balancer_route_count":
                len(load_balancer_routes),

            "load_balancer_uses_nat":
                bool(
                    route_targets.get(
                        "nat_gateway_ids"
                    )
                ),

            "load_balancer_uses_transit_gateway":
                bool(
                    route_targets.get(
                        "transit_gateway_ids"
                    )
                ),

            "load_balancer_uses_internet_gateway":
                bool(
                    route_targets.get(
                        "internet_gateway_ids"
                    )
                ),

            "load_balancer_uses_vpc_peering":
                bool(
                    route_targets.get(
                        "vpc_peering_connection_ids"
                    )
                ),
        }

        return topology

    # ==================================================================
    # OPTIMIZATION EVIDENCE
    # ==================================================================

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = collected_resource.get(
            "identity",
            {}
        )

        configuration = collected_resource.get(
            "configuration",
            {}
        )

        relationships = collected_resource.get(
            "relationships",
            {}
        )

        topology = collected_resource.get(
            "topology",
            {}
        )

        observations = collected_resource.get(
            "observations",
            {}
        )

        if not isinstance(identity, dict):
            identity = {}

        if not isinstance(configuration, dict):
            configuration = {}

        if not isinstance(relationships, dict):
            relationships = {}

        if not isinstance(topology, dict):
            topology = {}

        if not isinstance(observations, dict):
            observations = {}

        relationship_summary = (
            relationships.get(
                "summary",
                {},
            )
        )

        if not isinstance(
            relationship_summary,
            dict,
        ):
            relationship_summary = {}

        cloudwatch = (
            observations.get(
                "cloudwatch",
                {},
            )
        )

        if not isinstance(
            cloudwatch,
            dict,
        ):
            cloudwatch = {}

        metrics = (
            cloudwatch.get(
                "metrics",
                {},
            )
        )

        if not isinstance(
            metrics,
            dict,
        ):
            metrics = {}

        activity = (
            cloudwatch.get(
                "activity",
                {},
            )
        )

        if not isinstance(
            activity,
            dict,
        ):
            activity = {}

        topology_summary = (
            topology.get(
                "summary",
                {},
            )
        )

        if not isinstance(
            topology_summary,
            dict,
        ):
            topology_summary = {}

        return {
            "resource": {
                "resource_id":
                    resource.get(
                        "LoadBalancerArn"
                    ),

                "resource_type":
                    self.resource_type,

                "name":
                    identity.get(
                        "load_balancer_name"
                    ),

                "type":
                    identity.get(
                        "type"
                    ),

                "scheme":
                    identity.get(
                        "scheme"
                    ),

                "state":
                    identity.get(
                        "state"
                    ),

                "vpc_id":
                    identity.get(
                        "vpc_id"
                    ),
            },

            "configuration": {
                "load_balancer_type":
                    configuration.get(
                        "type"
                    ),

                "scheme":
                    configuration.get(
                        "scheme"
                    ),

                "availability_zone_count":
                    configuration.get(
                        "availability_zone_count",
                        0,
                    ),

                "subnet_count":
                    configuration.get(
                        "subnet_count",
                        0,
                    ),

                "security_group_count":
                    configuration.get(
                        "security_group_count",
                        0,
                    ),

                "ip_address_type":
                    configuration.get(
                        "ip_address_type"
                    ),
            },

            "relationships": {
                "listener_count":
                    relationship_summary.get(
                        "listener_count",
                        0,
                    ),

                "rule_count":
                    relationship_summary.get(
                        "rule_count",
                        0,
                    ),

                "target_group_count":
                    relationship_summary.get(
                        "target_group_count",
                        0,
                    ),

                "target_count":
                    relationship_summary.get(
                        "target_count",
                        0,
                    ),

                "healthy_target_count":
                    relationship_summary.get(
                        "healthy_target_count",
                        0,
                    ),

                "unhealthy_target_count":
                    relationship_summary.get(
                        "unhealthy_target_count",
                        0,
                    ),

                "target_types":
                    relationship_summary.get(
                        "target_types",
                        [],
                    ),
            },

            "activity": {
                "request_count":
                    activity.get(
                        "request_count"
                    ),

                "processed_bytes":
                    activity.get(
                        "processed_bytes"
                    ),

                "processed_gib":
                    activity.get(
                        "processed_gib"
                    ),

                "active_connections":
                    activity.get(
                        "active_connections"
                    ),

                "new_connections":
                    activity.get(
                        "new_connections"
                    ),

                "rejected_connections":
                    activity.get(
                        "rejected_connections"
                    ),

                "consumed_lcus":
                    activity.get(
                        "consumed_lcus"
                    ),

                "traffic_available":
                    activity.get(
                        "traffic_available"
                    ),

                "traffic_observed":
                    activity.get(
                        "traffic_observed"
                    ),
            },

            "network": {
                "load_balancer_subnet_count":
                    topology_summary.get(
                        "load_balancer_subnet_count",
                        0,
                    ),

                "load_balancer_route_count":
                    topology_summary.get(
                        "load_balancer_route_count",
                        0,
                    ),

                "uses_nat_gateway":
                    topology_summary.get(
                        "load_balancer_uses_nat",
                        False,
                    ),

                "uses_transit_gateway":
                    topology_summary.get(
                        "load_balancer_uses_transit_gateway",
                        False,
                    ),

                "uses_internet_gateway":
                    topology_summary.get(
                        "load_balancer_uses_internet_gateway",
                        False,
                    ),

                "uses_vpc_peering":
                    topology_summary.get(
                        "load_balancer_uses_vpc_peering",
                        False,
                    ),
            },

            "data_quality": {
                "topology_available":
                    topology.get(
                        "status"
                    ) == "ok",

                "relationship_data_available":
                    relationships.get(
                        "status"
                    ) == "ok",

                "cloudwatch_status":
                    cloudwatch.get(
                        "status"
                    ),

                "metric_count":
                    len(metrics),

                "metric_counts":
                    cloudwatch.get(
                        "metric_counts",
                        {},
                    ),
            },
        }

    # ==================================================================
    # ACTIVITY
    # ==================================================================

    @staticmethod
    def _build_activity_summary(
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:

        def numeric(
            name: str,
        ) -> Optional[float]:

            metric = metrics.get(
                name
            )

            if not isinstance(
                metric,
                dict,
            ):
                return None

            if metric.get(
                "status"
            ) != "ok":
                return None

            if metric.get(
                "has_data"
            ) is not True:
                return None

            value = metric.get(
                "value"
            )

            if not isinstance(
                value,
                (int, float),
            ):
                return None

            return float(value)

        request_count = numeric(
            "request_count"
        )

        processed_bytes = numeric(
            "processed_bytes"
        )

        active_connections = numeric(
            "active_connections"
        )

        new_connections = numeric(
            "new_connections"
        )

        processed_gib = (
            processed_bytes / (1024 ** 3)
            if processed_bytes is not None
            else None
        )

        traffic_available = (
            request_count is not None
            or processed_bytes is not None
            or active_connections is not None
            or new_connections is not None
        )

        traffic_observed = None

        if traffic_available:

            values = [
                request_count,
                processed_bytes,
                active_connections,
                new_connections,
            ]

            observed_values = [
                value
                for value in values
                if value is not None
            ]

            if observed_values:
                traffic_observed = any(
                    value > 0
                    for value in observed_values
                )

        return {
            "request_count":
                request_count,

            "processed_bytes":
                processed_bytes,

            "processed_gib":
                processed_gib,

            "active_connections":
                active_connections,

            "new_connections":
                new_connections,

            "traffic_available":
                traffic_available,

            "traffic_observed":
                traffic_observed,

            "semantics": {
                "purpose":
                    "operational_activity_observation",

                "billing_source":
                    False,

                "none_means":
                    "metric_not_observed",

                "zero_means":
                    "observed_zero",
            },
        }

    # ==================================================================
    # NETWORK INTERFACES
    # ==================================================================

    def _collect_load_balancer_enis(
        self,
        resource: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        subnet_ids = [
            item.get("SubnetId")
            for item in (
                resource.get(
                    "AvailabilityZones",
                    [],
                )
                or []
            )
            if isinstance(item, dict)
            and item.get("SubnetId")
        ]

        if not subnet_ids:
            return []

        try:

            paginator = (
                self.ec2.get_paginator(
                    "describe_network_interfaces"
                )
            )

            result = []

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name":
                            "subnet-id",

                        "Values":
                            subnet_ids,
                    }
                ]
            ):

                for eni in page.get(
                    "NetworkInterfaces",
                    [],
                ):

                    description = (
                        eni.get(
                            "Description"
                        )
                        or ""
                    )

                    interface_type = (
                        eni.get(
                            "InterfaceType"
                        )
                    )

                    is_elb_related = (
                        "ELB" in description.upper()
                        or "loadbalancer"
                        in description.lower()
                        or interface_type
                        in {
                            "network_load_balancer",
                            "gateway_load_balancer",
                        }
                    )

                    if not is_elb_related:
                        continue

                    result.append(
                        {
                            "network_interface_id":
                                eni.get(
                                    "NetworkInterfaceId"
                                ),

                            "subnet_id":
                                eni.get(
                                    "SubnetId"
                                ),

                            "vpc_id":
                                eni.get(
                                    "VpcId"
                                ),

                            "availability_zone":
                                eni.get(
                                    "AvailabilityZone"
                                ),

                            "interface_type":
                                interface_type,

                            "description":
                                description,

                            "status":
                                eni.get(
                                    "Status"
                                ),

                            "requester_managed":
                                eni.get(
                                    "RequesterManaged"
                                ),

                            "requester_id":
                                eni.get(
                                    "RequesterId"
                                ),
                        }
                    )

            return result

        except Exception:
            return []

    # ==================================================================
    # ROUTES
    # ==================================================================

    @staticmethod
    def _summarize_route_targets(
        routes: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:

        nat_gateway_ids = set()
        transit_gateway_ids = set()
        internet_gateway_ids = set()
        vpc_peering_connection_ids = set()

        for route in routes:

            if route.get("nat_gateway_id"):
                nat_gateway_ids.add(
                    route["nat_gateway_id"]
                )

            if route.get("transit_gateway_id"):
                transit_gateway_ids.add(
                    route["transit_gateway_id"]
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

            if route.get(
                "vpc_peering_connection_id"
            ):
                vpc_peering_connection_ids.add(
                    route[
                        "vpc_peering_connection_id"
                    ]
                )

        return {
            "nat_gateway_ids":
                sorted(nat_gateway_ids),

            "transit_gateway_ids":
                sorted(transit_gateway_ids),

            "internet_gateway_ids":
                sorted(internet_gateway_ids),

            "vpc_peering_connection_ids":
                sorted(vpc_peering_connection_ids),
        }

    # ==================================================================
    # PROFILE
    # ==================================================================

    def _get_observations_config(
        self,
    ) -> Dict[str, Any]:

        profile = (
            self.profile
            if isinstance(
                self.profile,
                dict,
            )
            else {}
        )

        observations = profile.get(
            "observations",
            {},
        )

        return (
            observations
            if isinstance(
                observations,
                dict,
            )
            else {}
        )

    # ==================================================================
    # PERIOD
    # ==================================================================

    @staticmethod
    def _effective_period(
        metrics: Dict[str, Any],
        default: int,
    ) -> int:

        for metric in metrics.values():

            if not isinstance(
                metric,
                dict,
            ):
                continue

            value = metric.get(
                "effective_period"
            )

            if value is not None:

                try:
                    return int(value)

                except (
                    TypeError,
                    ValueError,
                ):
                    continue

        return default

    # ==================================================================
    # HELPERS
    # ==================================================================

    @staticmethod
    def _normalize_availability_zones(
        zones: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        result = []

        for zone in zones or []:

            if not isinstance(
                zone,
                dict,
            ):
                continue

            zone_name = zone.get(
                "ZoneName"
            )

            subnet_id = zone.get(
                "SubnetId"
            )

            if not zone_name and not subnet_id:
                continue

            result.append(
                {
                    "zone_name":
                        zone_name,

                    "subnet_id":
                        subnet_id,

                    "outpost_id":
                        zone.get(
                            "OutpostId"
                        ),

                    "load_balancer_addresses":
                        zone.get(
                            "LoadBalancerAddresses",
                            [],
                        ),

                    "source_nat_ipv6_prefixes":
                        zone.get(
                            "SourceNatIpv6Prefixes",
                            [],
                        ),
                }
            )

        return result

    def _collect_metric_target_groups(
        self,
        load_balancer_arn: str | None,
    ) -> List[Dict[str, Any]]:

        if not load_balancer_arn:
            return []

        try:

            paginator = (
                self.elbv2.get_paginator(
                    "describe_target_groups"
                )
            )

            result = []

            for page in paginator.paginate(
                LoadBalancerArn=load_balancer_arn
            ):

                for target_group in page.get(
                    "TargetGroups",
                    [],
                ):

                    arn = target_group.get(
                        "TargetGroupArn"
                    )

                    if not arn:
                        continue

                    result.append(
                        {
                            "TargetGroupArn":
                                arn,

                            "TargetGroupName":
                                target_group.get(
                                    "TargetGroupName"
                                ),
                        }
                    )

            return result

        except Exception:
            return []

    @staticmethod
    def _extract_stickiness_enabled(
        target_group: Dict[str, Any],
    ) -> bool:

        attributes = target_group.get(
            "TargetGroupAttributes"
        )

        if not isinstance(
            attributes,
            list,
        ):
            return False

        for attribute in attributes:

            if (
                isinstance(attribute, dict)
                and attribute.get("Key")
                == "stickiness.enabled"
            ):

                return (
                    str(
                        attribute.get(
                            "Value",
                            "",
                        )
                    ).lower()
                    == "true"
                )

        return False

    @staticmethod
    def _get_tags(
        tags: List[Dict[str, str]],
    ) -> Dict[str, str]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        return {
            tag["Key"]:
                tag.get("Value")
            for tag in tags
            if isinstance(
                tag,
                dict,
            )
            and tag.get("Key")
        }

    @staticmethod
    def _cloudwatch_dimension(
        arn: str,
    ) -> str:

        marker = "loadbalancer/"

        if marker not in arn:
            raise ValueError(
                "Invalid load balancer ARN: "
                f"{arn}"
            )

        return arn.split(
            marker,
            1,
        )[1]

    @staticmethod
    def _cloudwatch_target_group_dimension(
        arn: str,
    ) -> str:

        marker = "targetgroup/"

        if marker not in arn:
            raise ValueError(
                "Invalid target group ARN: "
                f"{arn}"
            )

        return arn.split(
            marker,
            1,
        )[1]

    @staticmethod
    def _isoformat(
        value: Any,
    ) -> Optional[str]:

        if value is None:
            return None

        if hasattr(
            value,
            "isoformat",
        ):
            return value.isoformat()

        return str(value)