"""
Elastic Load Balancer collector.

Responsibilities
----------------
- Discover ELBv2 load balancers.
- Collect load-balancer identity/configuration.
- Collect listeners.
- Collect listener rules.
- Collect target groups.
- Collect target-group attributes.
- Collect registered-target and target-health evidence.
- Collect CloudWatch usage metrics.
- Preserve CloudWatch data-quality semantics.
- Collect topology only when explicitly enabled.
- Never interpret missing data as zero.
- Never create optimization conclusions.

The analyzer is responsible for interpreting this evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from ...base import BaseCollector
from ...registry import register
from ...metrics.cloudwatch import CloudWatchMetricCollector
from ...shared.topology import NetworkTopologyCollector


@register
class ElbCollector(BaseCollector):

    key = "elb"
    resource_type = "load_balancer"

    # ==================================================================
    # INITIALIZATION
    # ==================================================================

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

        self.metric_collector = CloudWatchMetricCollector(self.cloudwatch)

        self.topology_collector = NetworkTopologyCollector(self.region)

    # ==================================================================
    # DISCOVERY
    # ==================================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: List[Dict[str, Any]] = []

        paginator = self.elbv2.get_paginator("describe_load_balancers")

        for page in paginator.paginate():

            resources.extend(
                page.get(
                    "LoadBalancers",
                    [],
                )
            )

        return resources

    # ==================================================================
    # RESOURCE ID
    # ==================================================================

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        arn = resource.get("LoadBalancerArn")

        if not arn:
            raise ValueError("ELB resource has no LoadBalancerArn")

        return str(arn)

    # ==================================================================
    # IDENTITY
    # ==================================================================

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        state = resource.get("State") or {}

        return {
            "load_balancer_arn": resource.get("LoadBalancerArn"),
            "load_balancer_name": resource.get("LoadBalancerName"),
            "type": resource.get("Type"),
            "scheme": resource.get("Scheme"),
            "state": state.get("Code"),
            "vpc_id": resource.get("VpcId"),
            "tags": self._get_tags(resource.get("Tags", [])),
        }

    # ==================================================================
    # CONFIGURATION
    # ==================================================================

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        availability_zones = []

        for az in resource.get(
            "AvailabilityZones",
            [],
        ):

            if not isinstance(az, dict):
                continue

            availability_zones.append(
                {
                    "zone_name": az.get("ZoneName"),
                    "subnet_id": az.get("SubnetId"),
                    "load_balancer_addresses": az.get(
                        "LoadBalancerAddresses",
                        [],
                    ),
                }
            )

        subnet_ids = [
            az.get("subnet_id") for az in availability_zones if az.get("subnet_id")
        ]

        security_groups = list(
            resource.get(
                "SecurityGroups",
                [],
            )
            or []
        )

        lb_type = str(resource.get("Type") or "").strip().lower()

        state = resource.get("State") or {}

        return {
            "load_balancer_arn": resource.get("LoadBalancerArn"),
            "load_balancer_name": resource.get("LoadBalancerName"),
            "type": lb_type or None,
            "scheme": resource.get("Scheme"),
            "state": state.get("Code"),
            "state_reason": state.get("Reason"),
            "created_time": self._isoformat(resource.get("CreatedTime")),
            "vpc_id": resource.get("VpcId"),
            "dns_name": resource.get("DNSName"),
            "canonical_hosted_zone_id": resource.get("CanonicalHostedZoneId"),
            "ip_address_type": resource.get("IpAddressType"),
            "availability_zones": availability_zones,
            "availability_zone_count": len(availability_zones),
            "subnet_ids": subnet_ids,
            "subnet_count": len(subnet_ids),
            "security_groups": security_groups,
            "security_group_count": len(security_groups),
            "service_managed": False,
            "optimization_allowed": True,
            "release_allowed": True,
            "tags": self._get_tags(resource.get("Tags", [])),
        }

    # ==================================================================
    # RELATIONSHIPS
    # ==================================================================

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        load_balancer_arn = resource.get("LoadBalancerArn")

        if not load_balancer_arn:

            return {
                "status": "error",
                "listeners": [],
                "listener_rules": [],
                "target_groups": [],
                "summary": {
                    "listener_count": 0,
                    "listener_rule_count": 0,
                    "listener_default_action_count": 0,
                    "target_group_count": 0,
                    "target_count": None,
                    "healthy_target_count": None,
                    "unhealthy_target_count": None,
                    "initial_target_count": None,
                    "draining_target_count": None,
                    "target_health_complete": False,
                },
                "errors": ["LoadBalancerArn is missing"],
            }

        listeners, listener_errors = self._collect_listeners(load_balancer_arn)

        listener_rules, rule_errors = self._collect_listener_rules(listeners)

        target_groups, target_errors = self._collect_target_groups(load_balancer_arn)

        target_group_attributes, attribute_errors = (
            self._collect_target_group_attributes(target_groups)
        )

        self._attach_target_group_attributes(
            target_groups,
            target_group_attributes,
        )

        target_health_complete = self._target_health_complete(target_groups)

        no_target_groups = len(target_groups) == 0 and not target_errors

        if no_target_groups:
            target_health_complete = True

        (
            target_count,
            healthy_count,
            unhealthy_count,
            initial_count,
            draining_count,
        ) = self._aggregate_target_health(
            target_groups,
            target_health_complete,
        )

        errors = listener_errors + rule_errors + target_errors + attribute_errors

        status = "ok" if not errors else "partial"

        return {
            "status": status,
            "listeners": listeners,
            "listener_rules": listener_rules,
            "target_groups": target_groups,
            "target_group_attributes": target_group_attributes,
            "summary": {
                "listener_count": len(listeners),
                "listener_rule_count": len(listener_rules),
                "listener_default_action_count": (
                    self._count_listener_default_actions(listeners)
                ),
                "target_group_count": len(target_groups),
                "target_count": target_count,
                "healthy_target_count": healthy_count,
                "unhealthy_target_count": unhealthy_count,
                "initial_target_count": initial_count,
                "draining_target_count": draining_count,
                "target_health_complete": (target_health_complete),
            },
            "errors": errors,
        }

    # ==================================================================
    # CLOUDWATCH OBSERVATIONS
    # ==================================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        observations_config = self._get_observations_config()

        if not observations_config:

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                }
            }

        cloudwatch_config = self._select_cloudwatch_config(
            resource,
            observations_config,
        )

        if not cloudwatch_config:

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                }
            }

        if (
            cloudwatch_config.get(
                "enabled",
                True,
            )
            is not True
        ):

            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                }
            }

        namespace = cloudwatch_config.get("namespace")

        metric_specs = cloudwatch_config.get(
            "metrics",
            [],
        )

        requested_period = cloudwatch_config.get(
            "period",
            3600,
        )

        if not namespace:

            return {
                "cloudwatch": {
                    "status": "invalid",
                    "metrics": {},
                    "error": ("CloudWatch namespace is not configured"),
                }
            }

        if (
            not isinstance(
                metric_specs,
                list,
            )
            or not metric_specs
        ):

            return {
                "cloudwatch": {
                    "status": "no_metrics",
                    "namespace": namespace,
                    "metrics": {},
                }
            }

        load_balancer_arn = resource.get("LoadBalancerArn")

        if not load_balancer_arn:

            return {
                "cloudwatch": {
                    "status": "error",
                    "namespace": namespace,
                    "metrics": {},
                    "error": ("LoadBalancerArn is not available"),
                }
            }

        start, end = self.get_analysis_period()

        lb_dimension = self._cloudwatch_load_balancer_dimension(str(load_balancer_arn))

        target_groups = self._collect_target_group_inventory(str(load_balancer_arn))

        metrics: Dict[str, Any] = {}

        collection_errors: List[str] = []

        # --------------------------------------------------------------
        # LOAD-BALANCER LEVEL METRICS
        # --------------------------------------------------------------

        lb_specs = [
            spec
            for spec in metric_specs
            if isinstance(spec, dict)
            and self._metric_dimensions(spec) == ("LoadBalancer",)
        ]

        if lb_specs:

            try:

                results = self.metric_collector.collect(
                    namespace=namespace,
                    dimensions=[
                        {
                            "Name": "LoadBalancer",
                            "Value": lb_dimension,
                        }
                    ],
                    metric_specs=lb_specs,
                    start=start,
                    end=end,
                    requested_period=(requested_period),
                )

                self._merge_metric_results(
                    metrics,
                    results,
                )

            except Exception as exc:

                collection_errors.append("load_balancer_metrics: " f"{exc}")

        # --------------------------------------------------------------
        # TARGET-GROUP LEVEL METRICS
        # --------------------------------------------------------------

        tg_specs = [
            spec
            for spec in metric_specs
            if isinstance(spec, dict)
            and self._metric_dimensions(spec)
            == (
                "LoadBalancer",
                "TargetGroup",
            )
        ]

        if tg_specs:

            for target_group in target_groups:

                target_group_arn = target_group.get("target_group_arn")

                if not target_group_arn:
                    continue

                try:

                    target_group_dimension = self._cloudwatch_target_group_dimension(
                        target_group_arn
                    )

                    results = self.metric_collector.collect(
                        namespace=namespace,
                        dimensions=[
                            {
                                "Name": "LoadBalancer",
                                "Value": lb_dimension,
                            },
                            {
                                "Name": "TargetGroup",
                                "Value": target_group_dimension,
                            },
                        ],
                        metric_specs=tg_specs,
                        start=start,
                        end=end,
                        requested_period=(requested_period),
                    )

                    self._merge_metric_results(
                        metrics,
                        results,
                        target_group_arn=(target_group_arn),
                    )

                except Exception as exc:

                    collection_errors.append(
                        "target_group_metrics:" f"{target_group_arn}: " f"{exc}"
                    )

        if collection_errors:

            cloudwatch_status = "partial" if metrics else "error"

        else:

            cloudwatch_status = "ok"

        activity = self._build_activity_summary(
            metrics,
            lb_type=str(resource.get("Type") or "").lower(),
        )

        return {
            "cloudwatch": {
                "status": cloudwatch_status,
                "namespace": namespace,
                "requested_period": requested_period,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "metrics": metrics,
                "activity": activity,
                "collection_errors": collection_errors,
            }
        }

    # ==================================================================
    # TOPOLOGY
    # ==================================================================

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not self._topology_enabled():

            return {"status": "disabled"}

        vpc_id = resource.get("VpcId")

        if not vpc_id:

            return {
                "status": "incomplete",
                "reason": ("VPC ID is not available"),
            }

        return self.topology_collector.collect(
            vpc_id=vpc_id,
            resource_type=self.resource_type,
            resource_id=resource.get("LoadBalancerArn"),
        )

    # ==================================================================
    # OPTIMIZATION EVIDENCE
    # ==================================================================

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = collected_resource.get(
            "configuration",
            {},
        )

        relationships = collected_resource.get(
            "relationships",
            {},
        )

        summary = relationships.get(
            "summary",
            {},
        )

        observations = collected_resource.get(
            "observations",
            {},
        )

        cloudwatch = observations.get(
            "cloudwatch",
            {},
        )

        activity = cloudwatch.get(
            "activity",
            {},
        )

        return {
            "load_balancer_type": configuration.get("type"),
            "scheme": configuration.get("scheme"),
            "state": configuration.get("state"),
            "availability_zone_count": (configuration.get("availability_zone_count")),
            "listener_count": summary.get("listener_count"),
            "listener_rule_count": summary.get("listener_rule_count"),
            "listener_default_action_count": (
                summary.get("listener_default_action_count")
            ),
            "target_group_count": summary.get("target_group_count"),
            "target_count": summary.get("target_count"),
            "healthy_target_count": summary.get("healthy_target_count"),
            "unhealthy_target_count": summary.get("unhealthy_target_count"),
            "target_health_complete": summary.get("target_health_complete"),
            "cloudwatch_status": cloudwatch.get("status"),
            "traffic_available": activity.get("traffic_available"),
            "traffic_observed": activity.get("traffic_observed"),
        }

    # ==================================================================
    # LISTENERS
    # ==================================================================

    def _collect_listeners(
        self,
        load_balancer_arn: str,
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        try:

            paginator = self.elbv2.get_paginator("describe_listeners")

            listeners_raw: List[Dict[str, Any]] = []

            for page in paginator.paginate(LoadBalancerArn=load_balancer_arn):

                listeners_raw.extend(
                    page.get(
                        "Listeners",
                        [],
                    )
                )

        except Exception as exc:

            return [], [f"listener_collection_error: {exc}"]

        result = []

        for listener in listeners_raw:

            if not isinstance(
                listener,
                dict,
            ):
                continue

            result.append(
                {
                    "listener_arn": listener.get("ListenerArn"),
                    "load_balancer_arn": (load_balancer_arn),
                    "protocol": listener.get("Protocol"),
                    "port": listener.get("Port"),
                    "ssl_policy": listener.get("SslPolicy"),
                    "alpn_policy": listener.get("AlpnPolicy"),
                    "default_actions": listener.get(
                        "DefaultActions",
                        [],
                    ),
                    "certificates": listener.get(
                        "Certificates",
                        [],
                    ),
                }
            )

        return result, []

    # ==================================================================
    # LISTENER RULES
    # ==================================================================

    def _collect_listener_rules(
        self,
        listeners: List[Dict[str, Any]],
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        rules: List[Dict[str, Any]] = []
        errors: List[str] = []

        for listener in listeners:

            listener_arn = listener.get("listener_arn")

            if not listener_arn:
                continue

            try:

                paginator = self.elbv2.get_paginator("describe_rules")

                for page in paginator.paginate(ListenerArn=listener_arn):

                    for rule in page.get(
                        "Rules",
                        [],
                    ):

                        if not isinstance(
                            rule,
                            dict,
                        ):
                            continue

                        rules.append(
                            {
                                "rule_arn": rule.get("RuleArn"),
                                "listener_arn": (listener_arn),
                                "priority": rule.get("Priority"),
                                "conditions": rule.get(
                                    "Conditions",
                                    [],
                                ),
                                "actions": rule.get(
                                    "Actions",
                                    [],
                                ),
                                "is_default": rule.get("IsDefault"),
                            }
                        )

            except Exception as exc:

                errors.append(
                    "listener_rule_collection_error:" f"{listener_arn}: {exc}"
                )

        return rules, errors

    # ==================================================================
    # TARGET GROUPS
    # ==================================================================

    def _collect_target_groups(
        self,
        load_balancer_arn: str,
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        try:

            paginator = self.elbv2.get_paginator("describe_target_groups")

            target_groups_raw: List[Dict[str, Any]] = []

            for page in paginator.paginate(LoadBalancerArn=load_balancer_arn):

                target_groups_raw.extend(
                    page.get(
                        "TargetGroups",
                        [],
                    )
                )

        except Exception as exc:

            return [], ["target_group_collection_error: " f"{exc}"]

        result: List[Dict[str, Any]] = []

        errors: List[str] = []

        for target_group in target_groups_raw:

            if not isinstance(
                target_group,
                dict,
            ):
                continue

            target_group_arn = target_group.get("TargetGroupArn")

            if not target_group_arn:
                continue

            base = {
                "target_group_arn": (target_group_arn),
                "target_group_name": (target_group.get("TargetGroupName")),
                "protocol": target_group.get("Protocol"),
                "port": target_group.get("Port"),
                "protocol_version": (target_group.get("ProtocolVersion")),
                "target_type": target_group.get("TargetType"),
                "vpc_id": target_group.get("VpcId"),
                "health_check_enabled": (target_group.get("HealthCheckEnabled")),
                "health_check_protocol": (target_group.get("HealthCheckProtocol")),
                "health_check_port": (target_group.get("HealthCheckPort")),
                "health_check_path": (target_group.get("HealthCheckPath")),
                "health_check_interval": (
                    target_group.get("HealthCheckIntervalSeconds")
                ),
                "health_check_timeout": (target_group.get("HealthCheckTimeoutSeconds")),
                "healthy_threshold": (target_group.get("HealthyThresholdCount")),
                "unhealthy_threshold": (target_group.get("UnhealthyThresholdCount")),
                "load_balancer_arns": (
                    target_group.get(
                        "LoadBalancerArns",
                        [],
                    )
                ),
                "targets": [],
                "target_count": None,
                "healthy_target_count": None,
                "unhealthy_target_count": None,
                "initial_target_count": None,
                "draining_target_count": None,
                "target_health_status": "unknown",
                "target_health_error": None,
                "attributes": {},
                "attributes_status": "not_collected",
                "attributes_error": None,
            }

            try:

                health_response = self.elbv2.describe_target_health(
                    TargetGroupArn=(target_group_arn)
                )

                descriptions = health_response.get(
                    "TargetHealthDescriptions",
                    [],
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

                    target = description.get("Target") or {}

                    health = description.get("TargetHealth") or {}

                    state = health.get("State")

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
                            "id": target.get("Id"),
                            "port": target.get("Port"),
                            "availability_zone": (description.get("AvailabilityZone")),
                            "health": state,
                            "reason": health.get("Reason"),
                            "description": (health.get("Description")),
                        }
                    )

                base.update(
                    {
                        "targets": targets,
                        "target_count": len(targets),
                        "healthy_target_count": (healthy_count),
                        "unhealthy_target_count": (unhealthy_count),
                        "initial_target_count": (initial_count),
                        "draining_target_count": (draining_count),
                        "target_health_status": "ok",
                        "target_health_error": None,
                    }
                )

            except Exception as exc:

                base.update(
                    {
                        "targets": [],
                        "target_count": None,
                        "healthy_target_count": None,
                        "unhealthy_target_count": None,
                        "initial_target_count": None,
                        "draining_target_count": None,
                        "target_health_status": "error",
                        "target_health_error": str(exc),
                    }
                )

                errors.append(
                    "target_health_collection_error:" f"{target_group_arn}: {exc}"
                )

            result.append(base)

        return result, errors

    # ==================================================================
    # TARGET GROUP ATTRIBUTES
    # ==================================================================

    def _collect_target_group_attributes(
        self,
        target_groups: List[Dict[str, Any]],
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        result: List[Dict[str, Any]] = []

        errors: List[str] = []

        for group in target_groups:

            arn = group.get("target_group_arn")

            if not arn:
                continue

            try:

                response = self.elbv2.describe_target_group_attributes(
                    TargetGroupArn=arn
                )

                attributes = {}

                for item in response.get(
                    "Attributes",
                    [],
                ):

                    if not isinstance(
                        item,
                        dict,
                    ):
                        continue

                    key = item.get("Key")

                    if key:

                        attributes[str(key)] = item.get("Value")

                result.append(
                    {
                        "target_group_arn": arn,
                        "attributes": attributes,
                        "status": "ok",
                        "error": None,
                    }
                )

            except Exception as exc:

                result.append(
                    {
                        "target_group_arn": arn,
                        "attributes": {},
                        "status": "error",
                        "error": str(exc),
                    }
                )

                errors.append(
                    "target_group_attribute_collection_error:" f"{arn}: {exc}"
                )

        return result, errors

    @staticmethod
    def _attach_target_group_attributes(
        target_groups: List[Dict[str, Any]],
        attributes: List[Dict[str, Any]],
    ) -> None:

        by_arn = {
            item.get("target_group_arn"): item
            for item in attributes
            if isinstance(item, dict)
        }

        for group in target_groups:

            arn = group.get("target_group_arn")

            item = by_arn.get(arn)

            if not item:
                continue

            group["attributes"] = item.get(
                "attributes",
                {},
            )

            group["attributes_status"] = item.get("status")

            group["attributes_error"] = item.get("error")

    # ==================================================================
    # TARGET GROUP INVENTORY
    # ==================================================================

    def _collect_target_group_inventory(
        self,
        load_balancer_arn: str,
    ) -> List[Dict[str, Any]]:

        try:

            paginator = self.elbv2.get_paginator("describe_target_groups")

            result = []

            for page in paginator.paginate(LoadBalancerArn=load_balancer_arn):

                for group in page.get(
                    "TargetGroups",
                    [],
                ):

                    if not isinstance(
                        group,
                        dict,
                    ):
                        continue

                    arn = group.get("TargetGroupArn")

                    if not arn:
                        continue

                    result.append(
                        {
                            "target_group_arn": arn,
                            "target_group_name": (group.get("TargetGroupName")),
                        }
                    )

            return result

        except Exception:

            return []

    # ==================================================================
    # TARGET HEALTH AGGREGATION
    # ==================================================================

    @staticmethod
    def _target_health_complete(
        target_groups: List[Dict[str, Any]],
    ) -> bool:

        if not target_groups:
            return False

        return all(group.get("target_health_status") == "ok" for group in target_groups)

    @staticmethod
    def _aggregate_target_health(
        target_groups: List[Dict[str, Any]],
        complete: bool,
    ) -> tuple[
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
    ]:

        if not complete:

            return (
                None,
                None,
                None,
                None,
                None,
            )

        totals = [
            0,
            0,
            0,
            0,
            0,
        ]

        fields = (
            "target_count",
            "healthy_target_count",
            "unhealthy_target_count",
            "initial_target_count",
            "draining_target_count",
        )

        for group in target_groups:

            for index, field in enumerate(fields):

                value = group.get(field)

                if not isinstance(
                    value,
                    int,
                ):

                    return (
                        None,
                        None,
                        None,
                        None,
                        None,
                    )

                totals[index] += value

        return tuple(totals)  # type: ignore[return-value]

    # ==================================================================
    # CLOUDWATCH HELPERS
    # ==================================================================

    @staticmethod
    def _metric_dimensions(
        metric_spec: Dict[str, Any],
    ) -> tuple[str, ...]:

        dimensions = metric_spec.get("dimensions")

        if not isinstance(
            dimensions,
            list,
        ):
            return ("LoadBalancer",)

        normalized: List[str] = []

        for dimension in dimensions:

            if isinstance(
                dimension,
                str,
            ):

                normalized.append(dimension)

            elif isinstance(
                dimension,
                dict,
            ):

                name = dimension.get("Name")

                if name:
                    normalized.append(str(name))

        return tuple(normalized)

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

            metric_key = result.get("metric_key")

            if not metric_key:
                continue

            if target_group_arn:

                scoped_key = f"{metric_key}" f"[TargetGroup={target_group_arn}]"

                copied = dict(result)

                copied["target_group_arn"] = target_group_arn

                destination[scoped_key] = copied

            else:

                destination[str(metric_key)] = result

    @staticmethod
    def _build_activity_summary(
        metrics: Dict[str, Any],
        lb_type: str,
    ) -> Dict[str, Any]:

        available: Dict[
            str,
            float,
        ] = {}

        for _, metric in metrics.items():

            if not isinstance(
                metric,
                dict,
            ):
                continue

            metric_key = str(metric.get("metric_key") or "")

            if metric.get("observed") is not True:

                continue

            value = metric.get("value")

            if not isinstance(
                value,
                (int, float),
            ):
                continue

            # Keep the first valid value for a
            # load-balancer-level activity metric.
            if metric.get("target_group_arn") is None:

                available[metric_key] = float(value)

        request_count = available.get("request_count")

        processed_bytes = available.get("processed_bytes")

        active_connections = available.get("active_connections")

        new_connections = available.get("new_connections")

        active_flow_count = available.get("active_flow_count")

        new_flow_count = available.get("new_flow_count")

        # --------------------------------------------------------------
        # Determine whether sufficient activity evidence exists.
        # --------------------------------------------------------------

        evidence_values: List[float] = []

        if processed_bytes is not None:
            evidence_values.append(processed_bytes)

        if lb_type == "application":

            if request_count is not None:
                evidence_values.append(request_count)

        elif lb_type in {
            "network",
            "gateway",
        }:

            if active_flow_count is not None:
                evidence_values.append(active_flow_count)

            if new_flow_count is not None:
                evidence_values.append(new_flow_count)

            if active_connections is not None:
                evidence_values.append(active_connections)

            if new_connections is not None:
                evidence_values.append(new_connections)

        else:

            if request_count is not None:
                evidence_values.append(request_count)

        if not evidence_values:

            return {
                "traffic_available": False,
                "traffic_observed": None,
                "request_count": request_count,
                "processed_bytes": processed_bytes,
                "processed_gib": (
                    processed_bytes / (1024**3) if processed_bytes is not None else None
                ),
                "active_connections": (active_connections),
                "new_connections": (new_connections),
                "active_flow_count": (active_flow_count),
                "new_flow_count": (new_flow_count),
                "available_metrics": sorted(available.keys()),
            }

        return {
            "traffic_available": True,
            "traffic_observed": any(value > 0 for value in evidence_values),
            "request_count": request_count,
            "processed_bytes": processed_bytes,
            "processed_gib": (
                processed_bytes / (1024**3) if processed_bytes is not None else None
            ),
            "active_connections": (active_connections),
            "new_connections": (new_connections),
            "active_flow_count": (active_flow_count),
            "new_flow_count": (new_flow_count),
            "available_metrics": sorted(available.keys()),
        }

    # ==================================================================
    # PROFILE
    # ==================================================================

    def _get_observations_config(
        self,
    ) -> Dict[str, Any]:

        profile = self.profile or {}

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

    @staticmethod
    def _select_cloudwatch_config(
        resource: Dict[str, Any],
        observations_config: Dict[str, Any],
    ) -> Dict[str, Any]:

        lb_type = str(resource.get("Type") or "").strip().lower()

        by_type = observations_config.get(
            "cloudwatch_by_type",
            {},
        )

        if isinstance(
            by_type,
            dict,
        ):

            selected = by_type.get(lb_type)

            if isinstance(
                selected,
                dict,
            ):

                return selected

        fallback = observations_config.get("cloudwatch", {})

        return (
            fallback
            if isinstance(
                fallback,
                dict,
            )
            else {}
        )

    def _topology_enabled(self) -> bool:

        profile = self.profile or {}

        topology = profile.get(
            "topology",
            {},
        )

        if not isinstance(
            topology,
            dict,
        ):
            return False

        return (
            topology.get(
                "enabled",
                False,
            )
            is True
        )

    # ==================================================================
    # CLOUDWATCH DIMENSIONS
    # ==================================================================

    @staticmethod
    def _cloudwatch_load_balancer_dimension(
        arn: str,
    ) -> str:

        marker = "loadbalancer/"

        if marker not in arn:

            raise ValueError("Invalid load balancer ARN: " f"{arn}")

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

            raise ValueError("Invalid target group ARN: " f"{arn}")

        return arn.split(
            marker,
            1,
        )[1]

    # ==================================================================
    # COUNTS
    # ==================================================================

    @staticmethod
    def _count_listener_default_actions(
        listeners: List[Dict[str, Any]],
    ) -> int:

        count = 0

        for listener in listeners:

            actions = listener.get(
                "default_actions",
                [],
            )

            if isinstance(
                actions,
                list,
            ):

                count += len(actions)

        return count

    # ==================================================================
    # TAGS
    # ==================================================================

    @staticmethod
    def _get_tags(
        tags: List[Dict[str, str]],
    ) -> Dict[str, str]:

        return {
            str(tag.get("Key")): tag.get("Value")
            for tag in tags
            if isinstance(
                tag,
                dict,
            )
            and tag.get("Key")
        }

    # ==================================================================
    # TIME
    # ==================================================================

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
