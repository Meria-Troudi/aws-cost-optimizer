"""
Elastic Load Balancer collector.


"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register
from collectors.network.topology import NetworkTopologyCollector
from collectors.metrics.cloudwatch import CloudWatchMetricCollector


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

        self.elbv2 = get_client(
            "elbv2",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = CloudWatchMetricCollector(
            self.cloudwatch
        )

        self.topology_collector = NetworkTopologyCollector(
            self.region
        )

        # Discovery
    
    def discover(self) -> List[Dict[str, Any]]:
       
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

        # Resource identity
    
    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:
        return resource["LoadBalancerArn"]

        # Identity
    
    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
    
        return {
            "load_balancer_arn": resource.get(
                "LoadBalancerArn"
            ),
            "load_balancer_name": resource.get(
                "LoadBalancerName"
            ),
            "type": resource.get(
                "Type"
            ),
            "scheme": resource.get(
                "Scheme"
            ),
            "state": (
                resource.get("State") or {}
            ).get("Code"),
            "created_time": self._isoformat(
                resource.get("CreatedTime")
            ),
            "vpc_id": resource.get(
                "VpcId"
            ),
            "dns_name": resource.get(
                "DNSName"
            ),
            "canonical_hosted_zone_id": resource.get(
                "CanonicalHostedZoneId"
            ),
            "ip_address_type": resource.get(
                "IpAddressType"
            ),
            "tags": self._get_tags(
                resource.get(
                    "Tags",
                    [],
                )
            ),
        }

        # Configuration
    
    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        availability_zones = [
            {
                "zone_name": az.get(
                    "ZoneName"
                ),
                "subnet_id": az.get(
                    "SubnetId"
                ),
            }
            for az in resource.get(
                "AvailabilityZones",
                [],
            )
        ]

        subnet_ids = [
            az["subnet_id"]
            for az in availability_zones
            if az.get("subnet_id")
        ]

        return {
            "load_balancer_arn": resource.get(
                "LoadBalancerArn"
            ),
            "load_balancer_name": resource.get(
                "LoadBalancerName"
            ),
            "type": resource.get(
                "Type"
            ),
            "scheme": resource.get(
                "Scheme"
            ),
            "state": (
                resource.get("State") or {}
            ).get("Code"),
            "created_time": self._isoformat(
                resource.get("CreatedTime")
            ),
            "vpc_id": resource.get(
                "VpcId"
            ),
            "dns_name": resource.get(
                "DNSName"
            ),
            "canonical_hosted_zone_id": resource.get(
                "CanonicalHostedZoneId"
            ),
            "ip_address_type": resource.get(
                "IpAddressType"
            ),
            "availability_zones": availability_zones,
            "subnet_ids": subnet_ids,
            "security_groups": resource.get(
                "SecurityGroups",
                [],
            ),
            "tags": self._get_tags(
                resource.get(
                    "Tags",
                    [],
                )
            ),
        }

        # Relationships
    
    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        load_balancer_arn = resource[
            "LoadBalancerArn"
        ]

        listeners = self._collect_listeners(
            load_balancer_arn
        )

        target_groups = self._collect_target_groups(
            load_balancer_arn
        )

        target_count = sum(
            len(
                target_group.get(
                    "targets",
                    [],
                )
            )
            for target_group in target_groups
        )

        healthy_target_count = sum(
            target_group.get(
                "healthy_target_count",
                0,
            )
            for target_group in target_groups
        )

        return {
            "status": "ok",
            "listeners": listeners,
            "target_groups": target_groups,
            "summary": {
                "listener_count": len(
                    listeners
                ),
                "target_group_count": len(
                    target_groups
                ),
                "target_count": target_count,
                "healthy_target_count": (
                    healthy_target_count
                ),
            },
        }

        # CloudWatch observations
    
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
                    "metrics": [],
                }
            }

        cloudwatch_config = (
            observations_config.get(
                "cloudwatch",
                {}
            )
        )

        if not cloudwatch_config:
            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": [],
                }
            }

        enabled = cloudwatch_config.get(
            "enabled",
            True,
        )

        if not enabled:
            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": [],
                }
            }

        namespace = cloudwatch_config.get(
            "namespace"
        )

        metrics = cloudwatch_config.get(
            "metrics",
            []
        )

        period = cloudwatch_config.get(
            "period",
            3600,
        )

        if not namespace:
            return {
                "cloudwatch": {
                    "status": "invalid",
                    "metrics": [],
                    "error": (
                        "CloudWatch namespace "
                        "is not configured"
                    ),
                }
            }

        if not metrics:
            return {
                "cloudwatch": {
                    "status": "no_metrics",
                    "namespace": namespace,
                    "metrics": [],
                }
            }

        start, end = self.get_analysis_period()

        load_balancer_arn = resource.get(
            "LoadBalancerArn"
        )

        if not load_balancer_arn:
            return {
                "cloudwatch": {
                    "status": "error",
                    "namespace": namespace,
                    "metrics": [],
                    "error": (
                        "Load balancer ARN "
                        "is not available"
                    ),
                }
            }

        dimension = self._cloudwatch_dimension(
            load_balancer_arn
        )

        results = self.metric_collector.collect(
            namespace=namespace,
            dimensions=[
                {
                    "Name": "LoadBalancer",
                    "Value": dimension,
                }
            ],
            metric_specs=metrics,
            start=start,
            end=end,
            requested_period=period,
        )

        return {
            "cloudwatch": {
                "status": "ok",
                "namespace": namespace,
                "period": period,
                "metrics": results,
            }
        }

        # Topology
    
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
                "reason": (
                    "VPC ID not available"
                ),
            }

        return self.topology_collector.collect(
            vpc_id=vpc_id,
            resource_type=self.resource_type,
            resource_id=resource.get(
                "LoadBalancerArn"
            ),
        )

        # Optimization evidence
    
    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:
       

        relationships = (
            collected_resource.get(
                "relationships",
                {}
            )
        )

        summary = relationships.get(
            "summary",
            {}
        )

        return {
            "load_balancer_type": resource.get(
                "Type"
            ),
            "scheme": resource.get(
                "Scheme"
            ),
            "state": (
                resource.get("State") or {}
            ).get("Code"),
            "availability_zone_count": len(
                resource.get(
                    "AvailabilityZones",
                    [],
                )
            ),
            "target_group_count": summary.get(
                "target_group_count",
                0,
            ),
            "target_count": summary.get(
                "target_count",
                0,
            ),
            "healthy_target_count": summary.get(
                "healthy_target_count",
                0,
            ),
            "listener_count": summary.get(
                "listener_count",
                0,
            ),
        }

        # ELB relationships
    
    def _collect_listeners(
        self,
        load_balancer_arn: str,
    ) -> List[Dict[str, Any]]:
    
        response = self.elbv2.describe_listeners(
            LoadBalancerArn=load_balancer_arn
        )

        result = []

        for listener in response.get(
            "Listeners",
            [],
        ):
            result.append(
                {
                    "listener_arn": listener.get(
                        "ListenerArn"
                    ),
                    "protocol": listener.get(
                        "Protocol"
                    ),
                    "port": listener.get(
                        "Port"
                    ),
                    "ssl_policy": listener.get(
                        "SslPolicy"
                    ),
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

        return result

    def _collect_target_groups(
        self,
        load_balancer_arn: str,
    ) -> List[Dict[str, Any]]:

        response = self.elbv2.describe_target_groups(
            LoadBalancerArn=load_balancer_arn
        )

        result = []

        for target_group in response.get(
            "TargetGroups",
            [],
        ):
            target_group_arn = target_group.get(
                "TargetGroupArn"
            )

            if not target_group_arn:
                continue

            health_response = (
                self.elbv2.describe_target_health(
                    TargetGroupArn=target_group_arn
                )
            )

            targets = []
            healthy_count = 0

            for description in health_response.get(
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

                state = health.get(
                    "State"
                )

                if state == "healthy":
                    healthy_count += 1

                targets.append(
                    {
                        "id": target.get(
                            "Id"
                        ),
                        "port": target.get(
                            "Port"
                        ),
                        "availability_zone": (
                            description.get(
                                "AvailabilityZone"
                            )
                        ),
                        "health": state,
                        "reason": health.get(
                            "Reason"
                        ),
                        "description": health.get(
                            "Description"
                        ),
                    }
                )

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

                    "port":
                        target_group.get(
                            "Port"
                        ),

                    "target_type":
                        target_group.get(
                            "TargetType"
                        ),

                    "vpc_id":
                        target_group.get(
                            "VpcId"
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

                    "targets":
                        targets,

                    "healthy_target_count":
                        healthy_count,

                    "target_count":
                        len(targets),
                }
            )

        return result

        # Profile helpers
    
    def _get_observations_config(
        self,
    ) -> Dict[str, Any]:

        profile = self.profile or {}

        observations = profile.get(
            "observations",
            {}
        )

        if not isinstance(
            observations,
            dict,
        ):
            return {}

        return observations

        # Utilities
    
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
    def _get_tags(
        tags: List[Dict[str, str]],
    ) -> Dict[str, str]:
        return {
            tag["Key"]: tag.get("Value")
            for tag in tags
            if tag.get("Key")
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