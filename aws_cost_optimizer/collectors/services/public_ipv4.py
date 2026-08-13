"""
Public IPv4 Collector.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client
from collectors.base import BaseCollector
from collectors.registry import register


@register
class PublicIPv4Collector(BaseCollector):
    key = "public_ipv4"
    resource_type = "public_ipv4"

    def __init__(
        self,
        scan,
        region=None,
        profile=None,
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

    def discover(self) -> List[Dict[str, Any]]:


        resources: List[Dict[str, Any]] = []

        eip_response = self.ec2.describe_addresses()

        for address in eip_response.get("Addresses", []):
            public_ip = address.get("PublicIp")

            if not public_ip:
                continue

            resources.append(
                {
                    "id": self._eip_resource_id(address),
                    "raw": address,
                    "source": "elastic_ip",
                }
            )

        paginator = self.ec2.get_paginator(
            "describe_network_interfaces"
        )

        seen_ips = {
            resource["raw"].get("PublicIp")
            for resource in resources
            if resource.get("raw")
        }

        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []):

                association = eni.get("Association", {})
                public_ip = association.get("PublicIp")

                if not public_ip:
                    continue

                if public_ip in seen_ips:
                    continue

                seen_ips.add(public_ip)

                resources.append(
                    {
                        "id": self._public_ip_resource_id(
                            public_ip
                        ),
                        "raw": eni,
                        "source": "network_interface",
                    }
                )

        return resources
    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:
        return resource["id"]

    @staticmethod
    def _eip_resource_id(
        address: Dict[str, Any],
    ) -> str:
        allocation_id = address.get("AllocationId")

        if allocation_id:
            return allocation_id

        public_ip = address.get("PublicIp")

        if public_ip:
            return f"public-ip:{public_ip}"

        return "unknown-public-ip"

    @staticmethod
    def _public_ip_resource_id(
        public_ip: str,
    ) -> str:
        return f"public-ip:{public_ip}"
    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        source = resource.get("source")

        if source == "elastic_ip":
            return self._collect_eip_identity(resource)

        return self._collect_eni_identity(resource)

    def _collect_eip_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        address = resource["raw"]

        public_ip = address.get("PublicIp")
        allocation_id = address.get("AllocationId")
        association_id = address.get("AssociationId")

        return {
            "name": public_ip or allocation_id,
            "public_ip": public_ip,
            "resource_id": resource["id"],
            "resource_type": "elastic_ip",
            "tags": self._tags(
                address.get("Tags", [])
            ),
        }

    def _collect_eni_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        eni = resource["raw"]

        association = eni.get("Association", {})

        public_ip = association.get("PublicIp")
        eni_id = eni.get("NetworkInterfaceId")

        return {
            "name": public_ip or eni_id,
            "public_ip": public_ip,
            "resource_id": resource["id"],
            "resource_type": "public_ipv4",
            "tags": self._tags(
                eni.get("TagSet", [])
            ),
        }
    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        source = resource.get("source")

        if source == "elastic_ip":
            return self._collect_eip_configuration(
                resource
            )

        return self._collect_eni_configuration(
            resource
        )
    def _collect_eip_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        address = resource["raw"]

        allocation_id = address.get(
            "AllocationId"
        )

        association_id = address.get(
            "AssociationId"
        )

        network_interface_id = address.get(
            "NetworkInterfaceId"
        )

        network_interface = None

        if network_interface_id:
            network_interface = (
                self._get_network_interface(
                    network_interface_id
                )
            )

        return {
            "allocation_id": allocation_id,
            "association_id": association_id,

            "public_ip": address.get(
                "PublicIp"
            ),

            "private_ip": address.get(
                "PrivateIpAddress"
            ),

            "instance_id": address.get(
                "InstanceId"
            ),

            "network_interface_id":
                network_interface_id,

            "network_interface_type":
                self._get(
                    network_interface,
                    "InterfaceType",
                ),

            "network_interface_owner_id":
                self._get(
                    network_interface,
                    "RequesterId",
                ),

            "requester_managed":
                self._is_requester_managed(
                    network_interface
                ),

            "requester_id":
                self._get(
                    network_interface,
                    "RequesterId",
                ),

            "vpc_id":
                self._get(
                    network_interface,
                    "VpcId",
                ),

            "subnet_id":
                self._get(
                    network_interface,
                    "SubnetId",
                ),

            "availability_zone":
                self._get(
                    network_interface,
                    "AvailabilityZone",
                ),

            "state": (
                "associated"
                if association_id
                else "idle"
            ),

            "public_ip_type": "elastic_ip",

            "service_principal":
                self._get(
                    network_interface,
                    "RequesterId",
                ),

            "interface_description":
                self._get(
                    network_interface,
                    "Description",
                ),

            "tags": self._tags(
                address.get("Tags", [])
            ),
        }
    def _collect_eni_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        eni = resource["raw"]

        association = eni.get(
            "Association",
            {},
        )

        public_ip = association.get(
            "PublicIp"
        )

        return {
            "allocation_id": None,

            "association_id":
                association.get(
                    "AssociationId"
                ),

            "public_ip":
                public_ip,

            "private_ip":
                self._get_primary_private_ip(
                    eni
                ),

            "instance_id":
                self._get_instance_id(
                    eni
                ),

            "network_interface_id":
                eni.get(
                    "NetworkInterfaceId"
                ),

            "network_interface_type":
                eni.get(
                    "InterfaceType"
                ),

            "network_interface_owner_id":
                eni.get(
                    "RequesterId"
                ),

            "requester_managed":
                self._is_requester_managed(
                    eni
                ),

            "requester_id":
                eni.get(
                    "RequesterId"
                ),

            "vpc_id":
                eni.get(
                    "VpcId"
                ),

            "subnet_id":
                eni.get(
                    "SubnetId"
                ),

            "availability_zone":
                eni.get(
                    "AvailabilityZone"
                ),

            "state":
                "associated",

            "public_ip_type":
                self._determine_eni_public_ip_type(
                    eni
                ),

            "service_principal":
                eni.get(
                    "RequesterId"
                ),

            "interface_description":
                eni.get(
                    "Description"
                ),

            "tags": self._tags(
                eni.get(
                    "TagSet",
                    []
                )
            ),
        }
    def collect_topology(
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

        return {
            "status": "ok",
            "resource": {
                "resource_type":
                    self.resource_type,
                "resource_id":
                    resource["id"],
            },
            "relationships": [
                {
                    "type": "vpc",
                    "id": configuration.get(
                        "vpc_id"
                    ),
                },
                {
                    "type": "subnet",
                    "id": configuration.get(
                        "subnet_id"
                    ),
                },
                {
                    "type": "network_interface",
                    "id": configuration.get(
                        "network_interface_id"
                    ),
                },
                {
                    "type": "instance",
                    "id": configuration.get(
                        "instance_id"
                    ),
                },
            ],
        }
    def _get_network_interface(
        self,
        network_interface_id: str,
    ) -> Optional[Dict[str, Any]]:

        try:
            response = (
                self.ec2.describe_network_interfaces(
                    NetworkInterfaceIds=[
                        network_interface_id
                    ]
                )
            )

            interfaces = response.get(
                "NetworkInterfaces",
                [],
            )

            if interfaces:
                return interfaces[0]

        except Exception:
            pass

        return None

    @staticmethod
    def _get(
        obj: Optional[Dict[str, Any]],
        key: str,
    ) -> Any:

        if not obj:
            return None

        return obj.get(key)

    @staticmethod
    def _get_instance_id(
        eni: Dict[str, Any],
    ) -> Optional[str]:

        attachment = eni.get(
            "Attachment",
            {}
        )

        instance_id = attachment.get(
            "InstanceId"
        )

        if instance_id:
            return instance_id

        return None

    @staticmethod
    def _get_primary_private_ip(
        eni: Dict[str, Any],
    ) -> Optional[str]:

        private_ip = eni.get(
            "PrivateIpAddress"
        )

        if private_ip:
            return private_ip

        private_ips = eni.get(
            "PrivateIpAddresses",
            [],
        )

        for item in private_ips:

            if item.get(
                "Primary"
            ):
                return item.get(
                    "PrivateIpAddress"
                )

        return None

    @staticmethod
    def _is_requester_managed(
        eni: Optional[Dict[str, Any]],
    ) -> bool:

        if not eni:
            return False

        return bool(
            eni.get(
                "RequesterManaged",
                False,
            )
        )

    @staticmethod
    def _determine_eni_public_ip_type(
        eni: Dict[str, Any],
    ) -> str:

        interface_type = eni.get(
            "InterfaceType"
        )

        requester_managed = eni.get(
            "RequesterManaged",
            False,
        )

        if requester_managed:
            return "service_managed"

        if interface_type == "nat_gateway":
            return "nat_gateway"

        if interface_type:
            return interface_type

        return "ec2_public_ipv4"

    @staticmethod
    def _tags(
        tags: List[Dict[str, str]],
    ) -> Dict[str, str]:

        return {
            tag["Key"]: tag.get(
                "Value"
            )
            for tag in tags
            if "Key" in tag
        }