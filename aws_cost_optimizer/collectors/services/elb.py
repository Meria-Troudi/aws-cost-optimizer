"""
Elastic Load Balancer Collector
"""

from datetime import datetime, timedelta

from aws.client import get_client
from collectors.base import BaseCollector
from collectors.registry import register
from collectors.metric_collector import CloudWatchMetricCollector
@register
class ELBCollector(BaseCollector):

    key = "elb"

    def collect(self):

        elbv2 = get_client(
            "elbv2",
            self.region
        )

        cloudwatch = get_client(
            "cloudwatch",
            self.region
        )

        resources = []

        metric_collector = CloudWatchMetricCollector(
            cloudwatch
        )
        start = datetime.utcnow() - timedelta(days=30)
        end = datetime.utcnow()
        paginator = elbv2.get_paginator(
            "describe_load_balancers"
        )

        load_balancers = []

        for page in paginator.paginate():
            load_balancers.extend(
                page.get(
                    "LoadBalancers",
                    []
                )
            )

        print(
            f"[{self.region}] ELB discovered: {len(load_balancers)}"
        )

        for lb in load_balancers:

            arn = lb[
                "LoadBalancerArn"
            ]

            listeners = (
                elbv2
                .describe_listeners(
                    LoadBalancerArn=arn
                )
                .get(
                    "Listeners",
                    []
                )
            )

            target_groups = (
                elbv2
                .describe_target_groups(
                    LoadBalancerArn=arn
                )
                .get(
                    "TargetGroups",
                    []
                )
            )

            metrics = metric_collector.collect(
                namespace="AWS/ApplicationELB",
                dimensions=[
                    {
                        "Name": "LoadBalancer",
                        "Value": lb["LoadBalancerArn"]
                        .split("loadbalancer/")[1]
                    }
                ],
                start=start,
                end=end
            )

            resources.append({
                "resource_id": arn,
                "resource_type": "load_balancer",
                "region": self.region,
                "state": lb["State"]["Code"],
                "name": lb["LoadBalancerName"],
                "tags": {},
                "attributes": {
                    "type": lb.get("Type"),
                    "scheme": lb.get("Scheme"),
                    "dns_name": lb.get("DNSName"),
                    "ip_address_type": lb.get("IpAddressType"),
                    "availability_zones": [
                        z["ZoneName"]
                        for z in lb.get("AvailabilityZones", [])
                    ],
                    "listeners_count": len(listeners),
                    "target_groups_count": len(target_groups),
                    "target_groups": [
                        {
                            "name": tg["TargetGroupName"],
                            "type": tg["TargetType"],
                            "protocol": tg["Protocol"]
                        }
                        for tg in target_groups
                    ]
                },
                "metrics": metrics,
                "raw": lb
            })

        return resources