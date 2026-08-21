"""
Elastic Load Balancer collector.

Responsibilities
----------------
- Discover ELBv2 load balancers.
- Collect load-balancer configuration.
- Collect listeners and target groups.
- Collect target registration and target-health evidence.
- Collect CloudWatch usage metrics.
- Preserve CloudWatch data-quality semantics.
- Collect topology evidence.
- Never interpret missing data as zero.
- Never create optimization conclusions.

The analyzer is responsible for interpreting this evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from ...base import BaseCollector
from ...registry import register
from ...metrics.cloudwatch import (
    CloudWatchMetricCollector,
)
from ...shared.topology import (
    NetworkTopologyCollector,
)


@register
class ElbCollector(BaseCollector):

    key = "elb"
    resource_type = "load_balancer"

    # ================================================================
    # INITIALIZATION
    # ================================================================

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

        self.elbv2 = get_client(
            "elbv2",
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

    # ================================================================
    # DISCOVERY
    # ================================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: List[Dict[str, Any]] = []

        paginator = self.elbv2.get_paginator(
            "describe_load_balancers"
        )

        for page in paginator.paginate():

            resources.extend(
                page.get(
                    "LoadBalancers",
                    [],
                )
            )

        return resources

    # ================================================================
    # RESOURCE ID
    # ================================================================

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        arn = resource.get(
            "LoadBalancerArn"
        )

        if not arn:
            raise ValueError(
                "ELB resource has no LoadBalancerArn"
            )

        return arn

    # ================================================================
    # IDENTITY
    # ================================================================

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

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
                ).get(
                    "Code"
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

    # ================================================================
    # CONFIGURATION
    # ================================================================

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        availability_zones = [
            {
                "zone_name":
                    az.get(
                        "ZoneName"
                    ),

                "subnet_id":
                    az.get(
                        "SubnetId"
                    ),
            }
            for az in resource.get(
                "AvailabilityZones",
                [],
            )
            if isinstance(
                az,
                dict,
            )
        ]

        subnet_ids = [
            az.get(
                "subnet_id"
            )
            for az in availability_zones
            if az.get(
                "subnet_id"
            )
        ]

        security_groups = list(
            resource.get(
                "SecurityGroups",
                [],
            )
            or []
        )

        lb_type = str(
            resource.get(
                "Type"
            )
            or ""
        ).lower()

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
                lb_type or None,

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
                ).get(
                    "Code"
                ),

            "state_reason":
                (
                    resource.get(
                        "State"
                    )
                    or {}
                ).get(
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

            "service_managed":
                False,

            "optimization_allowed":
                True,

            "release_allowed":
                True,

            "tags":
                self._get_tags(
                    resource.get(
                        "Tags",
                        [],
                    )
                ),
        }

    # ================================================================
    # RELATIONSHIPS
    # ================================================================

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        load_balancer_arn = resource.get(
            "LoadBalancerArn"
        )

        if not load_balancer_arn:
            return {
                "status": "error",
                "listeners": [],
                "target_groups": [],
                "summary": {
                    "listener_count": 0,
                    "listener_default_action_count": 0,
                    "target_group_count": 0,
                    "target_count": None,
                    "healthy_target_count": None,
                    "unhealthy_target_count": None,
                    "target_health_complete": False,
                },
                "error":
                    "LoadBalancerArn is missing",
            }

        listeners, listener_errors = (
            self._collect_listeners(
                load_balancer_arn
            )
        )

        target_groups, target_errors = (
            self._collect_target_groups(
                load_balancer_arn
            )
        )

        target_health_complete = (
            bool(target_groups)
            and all(
                group.get(
                    "target_health_status"
                ) == "ok"
                for group in target_groups
            )
        )

        # If there are no target groups, that is a valid
        # configuration fact, not a target-health failure.
        no_target_groups = (
            len(target_groups) == 0
            and not target_errors
        )

        if no_target_groups:
            target_health_complete = True

        target_count: Optional[int] = 0
        healthy_count: Optional[int] = 0
        unhealthy_count: Optional[int] = 0

        if target_health_complete:

            for group in target_groups:

                group_target_count = (
                    group.get(
                        "target_count"
                    )
                )

                group_healthy_count = (
                    group.get(
                        "healthy_target_count"
                    )
                )

                group_unhealthy_count = (
                    group.get(
                        "unhealthy_target_count"
                    )
                )

                if not isinstance(
                    group_target_count,
                    int,
                ):
                    target_count = None

                elif target_count is not None:
                    target_count += (
                        group_target_count
                    )

                if not isinstance(
                    group_healthy_count,
                    int,
                ):
                    healthy_count = None

                elif healthy_count is not None:
                    healthy_count += (
                        group_healthy_count
                    )

                if not isinstance(
                    group_unhealthy_count,
                    int,
                ):
                    unhealthy_count = None

                elif unhealthy_count is not None:
                    unhealthy_count += (
                        group_unhealthy_count
                    )

        else:
            target_count = None
            healthy_count = None
            unhealthy_count = None

        errors = (
            listener_errors
            + target_errors
        )

        status = (
            "ok"
            if not errors
            else "partial"
        )

        return {
            "status": status,

            "listeners":
                listeners,

            "target_groups":
                target_groups,

            "summary": {
                "listener_count":
                    len(
                        listeners
                    ),

                "listener_default_action_count":
                    self._count_listener_rules(
                        listeners
                    ),

                "target_group_count":
                    len(
                        target_groups
                    ),

                "target_count":
                    target_count,

                "healthy_target_count":
                    healthy_count,

                "unhealthy_target_count":
                    unhealthy_count,

                "target_health_complete":
                    target_health_complete,
            },

            "errors":
                errors,
        }

    # ================================================================
    # CLOUDWATCH OBSERVATIONS
    # ================================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        observations_config = (
            self._get_observations_config()
        )

        if not observations_config:

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                }
            }

        cloudwatch_config = (
            self._select_cloudwatch_config(
                resource,
                observations_config,
            )
        )

        if not cloudwatch_config:

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                }
            }

        if not cloudwatch_config.get(
            "enabled",
            True,
        ):

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                }
            }

        namespace = cloudwatch_config.get(
            "namespace"
        )

        metric_specs = (
            cloudwatch_config.get(
                "metrics",
                [],
            )
        )

        requested_period = (
            cloudwatch_config.get(
                "period",
                3600,
            )
        )

        if not namespace:

            return {
                "cloudwatch": {
                    "status": "invalid",
                    "metrics": {},
                    "error":
                        "CloudWatch namespace is not configured",
                }
            }

        if not metric_specs:

            return {
                "cloudwatch": {
                    "status": "no_metrics",
                    "namespace":
                        namespace,
                    "metrics": {},
                }
            }

        load_balancer_arn = resource.get(
            "LoadBalancerArn"
        )

        if not load_balancer_arn:

            return {
                "cloudwatch": {
                    "status": "error",
                    "namespace":
                        namespace,
                    "metrics": {},
                    "error":
                        "LoadBalancerArn is not available",
                }
            }

        start, end = (
            self.get_analysis_period()
        )

        lb_dimension = (
            self._cloudwatch_load_balancer_dimension(
                load_balancer_arn
            )
        )

        target_groups = (
            self._collect_target_group_inventory(
                load_balancer_arn
            )
        )

        metrics: Dict[str, Any] = {}

        collection_errors: List[str] = []

        # ------------------------------------------------------------
        # Load-balancer-level metrics
        # ------------------------------------------------------------

        lb_specs = [
            spec
            for spec in metric_specs
            if self._metric_dimensions(
                spec
            ) == (
                "LoadBalancer",
            )
        ]

        if lb_specs:

            try:

                results = (
                    self.metric_collector.collect(
                        namespace=namespace,
                        dimensions=[
                            {
                                "Name":
                                    "LoadBalancer",

                                "Value":
                                    lb_dimension,
                            }
                        ],
                        metric_specs=lb_specs,
                        start=start,
                        end=end,
                        requested_period=(
                            requested_period
                        ),
                    )
                )

                self._merge_metric_results(
                    metrics,
                    results,
                )

            except Exception as exc:

                collection_errors.append(
                    (
                        "load_balancer_metrics: "
                        f"{exc}"
                    )
                )

        # ------------------------------------------------------------
        # Target-group-level metrics
        # ------------------------------------------------------------

        tg_specs = [
            spec
            for spec in metric_specs
            if self._metric_dimensions(
                spec
            ) == (
                "LoadBalancer",
                "TargetGroup",
            )
        ]

        if tg_specs:

            for target_group in target_groups:

                target_group_arn = (
                    target_group.get(
                        "target_group_arn"
                    )
                )

                if not target_group_arn:
                    continue

                target_group_dimension = (
                    self._cloudwatch_target_group_dimension(
                        target_group_arn
                    )
                )

                try:

                    results = (
                        self.metric_collector.collect(
                            namespace=namespace,
                            dimensions=[
                                {
                                    "Name":
                                        "LoadBalancer",

                                    "Value":
                                        lb_dimension,
                                },
                                {
                                    "Name":
                                        "TargetGroup",

                                    "Value":
                                        target_group_dimension,
                                },
                            ],
                            metric_specs=tg_specs,
                            start=start,
                            end=end,
                            requested_period=(
                                requested_period
                            ),
                        )
                    )

                    self._merge_metric_results(
                        metrics,
                        results,
                        target_group_arn=(
                            target_group_arn
                        ),
                    )

                except Exception as exc:

                    collection_errors.append(
                        (
                            "target_group_metrics:"
                            f"{target_group_arn}: "
                            f"{exc}"
                        )
                    )

        cloudwatch_status = (
            "ok"
            if not collection_errors
            else "partial"
        )

        activity = (
            self._build_activity_summary(
                metrics
            )
        )

        return {
            "cloudwatch": {
                "status":
                    cloudwatch_status,

                "namespace":
                    namespace,

                "requested_period":
                    requested_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "metrics":
                    metrics,

                "activity":
                    activity,

                "collection_errors":
                    collection_errors,
            }
        }

    # ================================================================
    # TOPOLOGY
    # ================================================================

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
                "status": "incomplete",
                "reason":
                    "VPC ID is not available",
            }

        return (
            self.topology_collector.collect(
                vpc_id=vpc_id,
                resource_type=(
                    self.resource_type
                ),
                resource_id=(
                    resource.get(
                        "LoadBalancerArn"
                    )
                ),
            )
        )

    # ================================================================
    # OPTIMIZATION EVIDENCE
    # ================================================================

    def build_optimization_evidence(
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

        relationships = (
            collected_resource.get(
                "relationships",
                {},
            )
        )

        summary = (
            relationships.get(
                "summary",
                {},
            )
        )

        observations = (
            collected_resource.get(
                "observations",
                {},
            )
        )

        cloudwatch = (
            observations.get(
                "cloudwatch",
                {}
            )
        )

        return {
            "load_balancer_type":
                configuration.get(
                    "type"
                ),

            "scheme":
                configuration.get(
                    "scheme"
                ),

            "state":
                configuration.get(
                    "state"
                ),

            "availability_zone_count":
                configuration.get(
                    "availability_zone_count",
                    0,
                ),

            "listener_count":
                summary.get(
                    "listener_count"
                ),

            "listener_default_action_count":
                summary.get(
                    "listener_default_action_count"
                ),

            "target_group_count":
                summary.get(
                    "target_group_count"
                ),

            "target_count":
                summary.get(
                    "target_count"
                ),

            "healthy_target_count":
                summary.get(
                    "healthy_target_count"
                ),

            "unhealthy_target_count":
                summary.get(
                    "unhealthy_target_count"
                ),

            "target_health_complete":
                summary.get(
                    "target_health_complete"
                ),

            "cloudwatch_status":
                cloudwatch.get(
                    "status"
                ),

            "traffic_available":
                (
                    cloudwatch.get(
                        "activity",
                        {},
                    ).get(
                        "traffic_available"
                    )
                    is True
                ),
        }

    # ================================================================
    # LISTENERS
    # ================================================================

    def _collect_listeners(
        self,
        load_balancer_arn: str,
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        try:

            paginator = (
                self.elbv2.get_paginator(
                    "describe_listeners"
                )
            )

            listeners: List[
                Dict[str, Any]
            ] = []

            for page in paginator.paginate(
                LoadBalancerArn=(
                    load_balancer_arn
                )
            ):

                listeners.extend(
                    page.get(
                        "Listeners",
                        [],
                    )
                )

            result = []

            for listener in listeners:

                if not isinstance(
                    listener,
                    dict,
                ):
                    continue

                result.append(
                    {
                        "listener_arn":
                            listener.get(
                                "ListenerArn"
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

                        "default_actions":
                            listener.get(
                                "DefaultActions",
                                [],
                            ),

                        "certificates":
                            listener.get(
                                "Certificates",
                                [],
                            ),
                    }
                )

            return result, []

        except Exception as exc:

            return [], [
                f"listener_collection_error: {exc}"
            ]

    # ================================================================
    # TARGET GROUPS
    # ================================================================

    def _collect_target_groups(
        self,
        load_balancer_arn: str,
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        try:

            paginator = (
                self.elbv2.get_paginator(
                    "describe_target_groups"
                )
            )

            target_groups_raw: List[
                Dict[str, Any]
            ] = []

            for page in paginator.paginate(
                LoadBalancerArn=(
                    load_balancer_arn
                )
            ):

                target_groups_raw.extend(
                    page.get(
                        "TargetGroups",
                        [],
                    )
                )

        except Exception as exc:

            return [], [
                f"target_group_collection_error: {exc}"
            ]

        result: List[
            Dict[str, Any]
        ] = []

        errors: List[str] = []

        for target_group in target_groups_raw:

            if not isinstance(
                target_group,
                dict,
            ):
                continue

            target_group_arn = (
                target_group.get(
                    "TargetGroupArn"
                )
            )

            if not target_group_arn:
                continue

            base = {
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

                "port":
                    target_group.get(
                        "Port"
                    ),

                "protocol_version":
                    target_group.get(
                        "ProtocolVersion"
                    ),

                "target_type":
                    target_group.get(
                        "TargetType"
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

                "health_check_interval":
                    target_group.get(
                        "HealthCheckIntervalSeconds"
                    ),

                "health_check_timeout":
                    target_group.get(
                        "HealthCheckTimeoutSeconds"
                    ),

                "healthy_threshold":
                    target_group.get(
                        "HealthyThresholdCount"
                    ),

                "unhealthy_threshold":
                    target_group.get(
                        "UnhealthyThresholdCount"
                    ),

                "load_balancer_arns":
                    target_group.get(
                        "LoadBalancerArns",
                        [],
                    ),

                "targets": [],

                "target_count": None,

                "healthy_target_count":
                    None,

                "unhealthy_target_count":
                    None,

                "initial_target_count":
                    None,

                "draining_target_count":
                    None,

                "target_health_status":
                    "unknown",

                "target_health_error":
                    None,
            }

            try:

                health_response = (
                    self.elbv2.describe_target_health(
                        TargetGroupArn=(
                            target_group_arn
                        )
                    )
                )

                descriptions = (
                    health_response.get(
                        "TargetHealthDescriptions",
                        [],
                    )
                )

                targets = []

                healthy_count = 0
                unhealthy_count = 0
                initial_count = 0
                draining_count = 0

                for description in descriptions:

                    if not isinstance(
                        description,
                        dict,
                    ):
                        continue

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

                    state = (
                        health.get(
                            "State"
                        )
                    )

                    if state == "healthy":
                        healthy_count += 1

                    elif state == "draining":
                        draining_count += 1

                    elif state == "initial":
                        initial_count += 1

                    elif state in {
                        "unhealthy",
                        "unavailable",
                    }:
                        unhealthy_count += 1

                    targets.append(
                        {
                            "id":
                                target.get(
                                    "Id"
                                ),

                            "port":
                                target.get(
                                    "Port"
                                ),

                            "availability_zone":
                                description.get(
                                    "AvailabilityZone"
                                ),

                            "health":
                                state,

                            "reason":
                                health.get(
                                    "Reason"
                                ),

                            "description":
                                health.get(
                                    "Description"
                                ),
                        }
                    )

                base.update(
                    {
                        "targets":
                            targets,

                        "target_count":
                            len(targets),

                        "healthy_target_count":
                            healthy_count,

                        "unhealthy_target_count":
                            unhealthy_count,

                        "initial_target_count":
                            initial_count,

                        "draining_target_count":
                            draining_count,

                        "target_health_status":
                            "ok",

                        "target_health_error":
                            None,
                    }
                )

            except Exception as exc:

                # Critical:
                # health failure does NOT become zero targets.
                base.update(
                    {
                        "targets": [],

                        "target_count":
                            None,

                        "healthy_target_count":
                            None,

                        "unhealthy_target_count":
                            None,

                        "initial_target_count":
                            None,

                        "draining_target_count":
                            None,

                        "target_health_status":
                            "error",

                        "target_health_error":
                            str(exc),
                    }
                )

                errors.append(
                    (
                        "target_health_collection_error:"
                        f"{target_group_arn}: "
                        f"{exc}"
                    )
                )

            result.append(
                base
            )

        return result, errors

    # ================================================================
    # TARGET GROUP INVENTORY
    # ================================================================

    def _collect_target_group_inventory(
        self,
        load_balancer_arn: str,
    ) -> List[Dict[str, Any]]:

        try:

            response = (
                self.elbv2.describe_target_groups(
                    LoadBalancerArn=(
                        load_balancer_arn
                    )
                )
            )

        except Exception:
            return []

        result = []

        for group in response.get(
            "TargetGroups",
            [],
        ):

            if not isinstance(
                group,
                dict,
            ):
                continue

            arn = group.get(
                "TargetGroupArn"
            )

            if not arn:
                continue

            result.append(
                {
                    "target_group_arn":
                        arn,

                    "target_group_name":
                        group.get(
                            "TargetGroupName"
                        ),
                }
            )

        return result

    # ================================================================
    # CLOUDWATCH HELPERS
    # ================================================================

    @staticmethod
    def _metric_dimensions(
        metric_spec: Dict[str, Any],
    ) -> tuple[str, ...]:

        dimensions = metric_spec.get(
            "dimensions"
        )

        if not isinstance(
            dimensions,
            list,
        ):
            return (
                "LoadBalancer",
            )

        normalized = []

        for dimension in dimensions:

            if isinstance(
                dimension,
                str,
            ):
                normalized.append(
                    dimension
                )

            elif isinstance(
                dimension,
                dict,
            ):

                name = dimension.get(
                    "Name"
                )

                if name:
                    normalized.append(
                        str(name)
                    )

        return tuple(
            normalized
        )

    @classmethod
    def _merge_metric_results(
        cls,
        destination: Dict[str, Any],
        results: List[Dict[str, Any]],
        target_group_arn: Optional[str] = None,
    ) -> None:

        for result in results:

            if not isinstance(
                result,
                dict,
            ):
                continue

            metric_key = result.get(
                "metric_key"
            )

            if not metric_key:
                continue

            if target_group_arn:

                scoped_key = (
                    f"{metric_key}"
                    f"[TargetGroup={target_group_arn}]"
                )

                copied = dict(
                    result
                )

                copied[
                    "target_group_arn"
                ] = target_group_arn

                destination[
                    scoped_key
                ] = copied

            else:

                destination[
                    str(metric_key)
                ] = result

    @staticmethod
    def _build_activity_summary(
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:

        activity_metric_names = {
            "request_count",
            "processed_bytes",
            "active_connections",
            "new_connections",
            "active_flow_count",
            "new_flow_count",
        }

        available: Dict[
            str,
            float,
        ] = {}

        for key, metric in metrics.items():

            if not isinstance(
                metric,
                dict,
            ):
                continue

            metric_key = str(
                metric.get(
                    "metric_key"
                )
                or ""
            )

            if metric_key not in (
                activity_metric_names
            ):
                continue

            if metric.get(
                "observed"
            ) is not True:

                continue

            value = metric.get(
                "value"
            )

            if not isinstance(
                value,
                (int, float),
            ):
                continue

            available[
                metric_key
            ] = float(value)

        if not available:

            return {
                "traffic_available":
                    False,

                "traffic_observed":
                    None,

                "request_count":
                    None,

                "processed_bytes":
                    None,

                "active_connections":
                    None,

                "new_connections":
                    None,
            }

        request_count = (
            available.get(
                "request_count"
            )
        )

        processed_bytes = (
            available.get(
                "processed_bytes"
            )
        )

        active_connections = (
            available.get(
                "active_connections"
            )
        )

        new_connections = (
            available.get(
                "new_connections"
            )
        )

        positive_values = [
            value
            for value in (
                request_count,
                processed_bytes,
                active_connections,
                new_connections,
                available.get(
                    "active_flow_count"
                ),
                available.get(
                    "new_flow_count"
                ),
            )
            if value is not None
        ]

        traffic_observed = (
            any(
                value > 0
                for value in positive_values
            )
            if positive_values
            else None
        )

        return {
            "traffic_available":
                True,

            "traffic_observed":
                traffic_observed,

            "request_count":
                request_count,

            "processed_bytes":
                processed_bytes,

            "processed_gib":
                (
                    processed_bytes
                    / (1024 ** 3)
                    if processed_bytes is not None
                    else None
                ),

            "active_connections":
                active_connections,

            "new_connections":
                new_connections,

            "available_metrics":
                sorted(
                    available.keys()
                ),
        }

    # ================================================================
    # PROFILE
    # ================================================================

    def _get_observations_config(
        self,
    ) -> Dict[str, Any]:

        profile = (
            self.profile
            or {}
        )

        observations = (
            profile.get(
                "observations",
                {},
            )
        )

        return (
            observations
            if isinstance(
                observations,
                dict,
            )
            else {}
        )

    @staticmethod
    def _select_cloudwatch_config(
        resource: Dict[str, Any],
        observations_config: Dict[str, Any],
    ) -> Dict[str, Any]:

        lb_type = str(
            resource.get(
                "Type"
            )
            or ""
        ).lower()

        by_type = (
            observations_config.get(
                "cloudwatch_by_type",
                {},
            )
        )

        if isinstance(
            by_type,
            dict,
        ):

            selected = by_type.get(
                lb_type
            )

            if isinstance(
                selected,
                dict,
            ):
                return selected

        fallback = (
            observations_config.get(
                "cloudwatch",
                {}
            )
        )

        return (
            fallback
            if isinstance(
                fallback,
                dict,
            )
            else {}
        )

    # ================================================================
    # CLOUDWATCH DIMENSIONS
    # ================================================================

    @staticmethod
    def _cloudwatch_load_balancer_dimension(
        arn: str,
    ) -> str:

        marker = (
            "loadbalancer/"
        )

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

        marker = (
            "targetgroup/"
        )

        if marker not in arn:

            raise ValueError(
                "Invalid target group ARN: "
                f"{arn}"
            )

        return arn.split(
            marker,
            1,
        )[1]

    # ================================================================
    # UTILITIES
    # ================================================================

    @staticmethod
    def _count_listener_rules(
        listeners: List[Dict[str, Any]],
    ) -> int:

        count = 0

        for listener in listeners:

            actions = (
                listener.get(
                    "default_actions",
                    [],
                )
            )

            if isinstance(
                actions,
                list,
            ):
                count += len(
                    actions
                )

        return count

    @staticmethod
    def _get_tags(
        tags: List[Dict[str, str]],
    ) -> Dict[str, str]:

        return {
            str(
                tag.get(
                    "Key"
                )
            ):
                tag.get(
                    "Value"
                )
            for tag in tags
            if isinstance(
                tag,
                dict,
            )
            and tag.get(
                "Key"
            )
        }

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