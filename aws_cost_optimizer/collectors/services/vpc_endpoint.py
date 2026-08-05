"""
VPC Endpoint Collector
"""

from aws.client import get_client
from collectors.base import BaseCollector
from collectors.registry import register


@register
class VPCEndpointCollector(BaseCollector):

    key = "vpc_endpoint"

    def collect(self):

        ec2 = get_client(
            "ec2",
            self.region
        )

        paginator = ec2.get_paginator(
            "describe_vpc_endpoints"
        )

        endpoints = []

        for page in paginator.paginate():
            endpoints.extend(
                page.get(
                    "VpcEndpoints",
                    []
                )
            )

        print(
            f"[{self.region}] VPC endpoints discovered: {len(endpoints)}"
        )

        resources = []

        for endpoint in endpoints:

            endpoint_id = endpoint[
                "VpcEndpointId"
            ]

            attributes = {
                "service_name": endpoint.get("ServiceName"),
                "endpoint_type": endpoint.get("VpcEndpointType"),
                "state": endpoint.get("State"),
                "vpc_id": endpoint.get("VpcId"),
                "route_table_ids": endpoint.get("RouteTableIds", []),
                "subnet_ids": endpoint.get("SubnetIds", []),
                "network_interfaces": endpoint.get("NetworkInterfaceIds", []),
                "policy": endpoint.get("PolicyDocument")
            }

            resources.append({
                "resource_id": endpoint_id,
                "resource_type": "vpc_endpoint",
                "region": self.region,
                "state": endpoint.get("State"),
                "name": endpoint_id,
                "tags": {
                    t["Key"]: t["Value"]
                    for t in endpoint.get("Tags", [])
                },
                "attributes": attributes,
                "metrics": [],
                "raw": endpoint
            })

        return resources