"""
Elastic IP Collector

Collect:
- Elastic IPs
- Association information
- Network interface
- Instance attachment
"""

from aws.client import get_client
from collectors.base import BaseCollector
from collectors.registry import register


@register
class ElasticIPCollector(BaseCollector):

    key = "elastic_ip"

    def collect(self):

        ec2 = get_client(
            "ec2",
            self.region
        )

        response = ec2.describe_addresses()

        addresses = response.get(
            "Addresses",
            []
        )

        print(
            f"[{self.region}] Elastic IPs discovered: {len(addresses)}"
        )

        resources = []

        for eip in addresses:

            allocation_id = eip.get(
                "AllocationId"
            )

            association_id = eip.get(
                "AssociationId"
            )

            attributes = {
                "public_ip": eip.get("PublicIp"),
                "allocation_id": allocation_id,
                "association_id": association_id,
                "domain": eip.get("Domain"),
                "network_interface_id": eip.get("NetworkInterfaceId"),
                "instance_id": eip.get("InstanceId"),
                "private_ip": eip.get("PrivateIpAddress"),
                "network_border_group": eip.get("NetworkBorderGroup"),
                "public_ipv4_pool": eip.get("PublicIpv4Pool")
            }

            state = (
                "associated"
                if association_id
                else "idle"
            )

            resources.append({
                "resource_id": allocation_id,
                "resource_type": "elastic_ip",
                "region": self.region,
                "state": state,
                "name": eip.get("PublicIp"),
                "tags": {},
                "attributes": attributes,
                "metrics": [],
                "raw": eip
            })

        return resources