"""
AWS Public IPv4 Collector.

Collects:
- Elastic IP allocations
- public IPv4 addresses associated with ENIs
- EC2 instance state when an address is attached to an EC2 instance

The collector exposes evidence.
It does not make optimization decisions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register

from collectors.network.topology import (
    NetworkTopologyCollector,
)


@register
class PublicIPv4Collector(BaseCollector):

    key = "public_ipv4"
    resource_type = "public_ipv4"

    def __init__(
        self,
        scan,
        region: Optional[str] = None,
        profile: Optional[dict] = None,
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

        self.network_collector = (
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

        resources: List[
            Dict[str, Any]
        ] = []

        try:

            response = (
                self.ec2.describe_addresses()
            )

        except Exception as exc:

            raise RuntimeError(
                "Failed to collect Elastic IP "
                f"addresses in {self.region}: {exc}"
            ) from exc

        for address in response.get(
            "Addresses",
            [],
        ):

            public_ip = address.get(
                "PublicIp"
            )

            if not public_ip:
                continue

            resources.append(
                {
                    "id":
                        self._eip_resource_id(
                            address
                        ),

                    "raw":
                        address,

                    "source":
                        "elastic_ip",
                }
            )

        paginator = (
            self.ec2.get_paginator(
                "describe_network_interfaces"
            )
        )

        seen_public_ips = {
            resource["raw"].get(
                "PublicIp"
            )
            for resource in resources
            if (
                resource.get("raw")
                and resource.get("source")
                == "elastic_ip"
            )
        }

        for page in paginator.paginate():

            for eni in page.get(
                "NetworkInterfaces",
                [],
            ):

                association = (
                    eni.get(
                        "Association",
                        {},
                    )
                    or {}
                )

                public_ip = association.get(
                    "PublicIp"
                )

                if not public_ip:
                    continue

                if public_ip in seen_public_ips:
                    continue

                seen_public_ips.add(
                    public_ip
                )

                resources.append(
                    {
                        "id":
                            self._public_ip_resource_id(
                                public_ip
                            ),

                        "raw":
                            eni,

                        "source":
                            "network_interface",
                    }
                )

        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return resource["id"]

    # ==================================================================
    # IDENTIFIERS
    # ==================================================================

    @staticmethod
    def _eip_resource_id(
        address: Dict[str, Any],
    ) -> str:

        allocation_id = address.get(
            "AllocationId"
        )

        if allocation_id:
            return allocation_id

        public_ip = address.get(
            "PublicIp"
        )

        if public_ip:
            return f"public-ip:{public_ip}"

        return "unknown-public-ip"

    @staticmethod
    def _public_ip_resource_id(
        public_ip: str,
    ) -> str:

        return f"public-ip:{public_ip}"

    # ==================================================================
    # IDENTITY
    # ==================================================================

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        if (
            resource.get("source")
            == "elastic_ip"
        ):

            return self._collect_eip_identity(
                resource
            )

        return self._collect_eni_identity(
            resource
        )

    def _collect_eip_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        address = resource["raw"]

        return {
            "name":
                address.get("PublicIp")
                or address.get("AllocationId"),

            "public_ip":
                address.get("PublicIp"),

            "allocation_id":
                address.get("AllocationId"),

            "association_id":
                address.get("AssociationId"),

            "resource_id":
                resource["id"],

            "resource_type":
                "elastic_ip",

            "source":
                "elastic_ip",

            "tags":
                self._tags(
                    address.get(
                        "Tags",
                        [],
                    )
                ),
        }

    def _collect_eni_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        eni = resource["raw"]

        association = (
            eni.get(
                "Association",
                {},
            )
            or {}
        )

        return {
            "name":
                association.get("PublicIp")
                or eni.get(
                    "NetworkInterfaceId"
                ),

            "public_ip":
                association.get(
                    "PublicIp"
                ),

            "network_interface_id":
                eni.get(
                    "NetworkInterfaceId"
                ),

            "resource_id":
                resource["id"],

            "resource_type":
                "public_ipv4",

            "source":
                "network_interface",

            "requester_managed":
                bool(
                    eni.get(
                        "RequesterManaged",
                        False,
                    )
                ),

            "network_interface_type":
                eni.get(
                    "InterfaceType"
                ),

            "service_managed":
                bool(
                    eni.get(
                        "RequesterManaged",
                        False,
                    )
                ),

            "tags":
                self._tags(
                    eni.get(
                        "TagSet",
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

        if (
            resource.get("source")
            == "elastic_ip"
        ):

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

        instance_id = address.get(
            "InstanceId"
        )

        network_interface = None

        if network_interface_id:

            network_interface = (
                self._get_network_interface(
                    network_interface_id
                )
            )

        if network_interface:

            requester_managed = (
                self._is_requester_managed(
                    network_interface
                )
            )

            network_interface_type = (
                network_interface.get(
                    "InterfaceType"
                )
            )

            requester_id = (
                network_interface.get(
                    "RequesterId"
                )
            )

            vpc_id = network_interface.get(
                "VpcId"
            )

            subnet_id = network_interface.get(
                "SubnetId"
            )

            availability_zone = (
                network_interface.get(
                    "AvailabilityZone"
                )
            )

            interface_description = (
                network_interface.get(
                    "Description"
                )
            )

        else:

            requester_managed = False
            network_interface_type = None
            requester_id = None
            vpc_id = None
            subnet_id = None
            availability_zone = None
            interface_description = None

        associated = bool(
            association_id
            or network_interface_id
            or instance_id
        )

        instance_state = (
            self._get_instance_state(
                instance_id
            )
            if instance_id
            else None
        )

        public_ip_type = (
            self._classify_eip(
                requester_managed=
                    requester_managed,
                network_interface_type=
                    network_interface_type,
            )
        )

        return {
            "public_ip":
                address.get(
                    "PublicIp"
                ),

            "allocation_id":
                allocation_id,

            "association_id":
                association_id,

            "associated":
                associated,

            "state":
                (
                    "associated"
                    if associated
                    else "idle"
                ),

            "instance_id":
                instance_id,

            "instance_state":
                instance_state,

            "network_interface_id":
                network_interface_id,

            "network_interface_type":
                network_interface_type,

            "network_interface_owner_id":
                requester_id,

            "requester_id":
                requester_id,

            "requester_managed":
                requester_managed,

            "service_managed":
                requester_managed,

            "vpc_id":
                vpc_id,

            "subnet_id":
                subnet_id,

            "availability_zone":
                availability_zone,

            "public_ip_type":
                public_ip_type,

            "address_source":
                "elastic_ip",

            "service_principal":
                requester_id,

            "interface_description":
                interface_description,

            "tags":
                self._tags(
                    address.get(
                        "Tags",
                        [],
                    )
                ),

            "optimization_allowed":
                not requester_managed,

            "release_allowed":
                (
                    not requester_managed
                    and not associated
                ),

            "requires_resource_review":
                bool(
                    associated
                    and instance_id
                ),
        }

    def _collect_eni_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        eni = resource["raw"]

        association = (
            eni.get(
                "Association",
                {},
            )
            or {}
        )

        public_ip = association.get(
            "PublicIp"
        )

        association_id = (
            association.get(
                "AssociationId"
            )
        )

        requester_managed = (
            self._is_requester_managed(
                eni
            )
        )

        instance_id = (
            self._get_instance_id(
                eni
            )
        )

        return {
            "public_ip":
                public_ip,

            "allocation_id":
                None,

            "association_id":
                association_id,

            "associated":
                bool(
                    public_ip
                    and (
                        association_id
                        or eni.get(
                            "NetworkInterfaceId"
                        )
                    )
                ),

            "state":
                "associated",

            "instance_id":
                instance_id,

            "instance_state":
                (
                    self._get_instance_state(
                        instance_id
                    )
                    if instance_id
                    else None
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
                requester_managed,

            "requester_id":
                eni.get(
                    "RequesterId"
                ),

            "service_managed":
                requester_managed,

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

            "public_ip_type":
                self._determine_eni_public_ip_type(
                    eni
                ),

            "address_source":
                "network_interface",

            "service_principal":
                eni.get(
                    "RequesterId"
                ),

            "interface_description":
                eni.get(
                    "Description"
                ),

            "tags":
                self._tags(
                    eni.get(
                        "TagSet",
                        [],
                    )
                ),

            "optimization_allowed":
                not requester_managed,

            "release_allowed":
                False,

            "requires_resource_review":
                True,
        }

    # ==================================================================
    # TOPOLOGY
    # ==================================================================

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

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        vpc_id = configuration.get(
            "vpc_id"
        )

        resource_id = resource.get(
            "id"
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
                self.network_collector.collect(
                    vpc_id=vpc_id,
                    resource_type=self.resource_type,
                    resource_id=resource_id,
                )
            )

        except Exception as exc:

            return {
                "status":
                    "error",

                "reason":
                    str(exc),
            }

        if topology.get(
            "status"
        ) != "ok":

            return topology

        subnet_id = configuration.get(
            "subnet_id"
        )

        subnet_profile = None
        route_table = None

        for profile in topology.get(
            "subnet_profiles",
            [],
        ):

            if (
                profile.get("subnet_id")
                == subnet_id
            ):

                subnet_profile = profile

                route_table_id = (
                    profile.get(
                        "route_table_id"
                    )
                )

                for table in topology.get(
                    "route_tables",
                    [],
                ):

                    if (
                        table.get(
                            "route_table_id"
                        )
                        == route_table_id
                    ):

                        route_table = table
                        break

                break

        return {
            "status":
                "ok",

            "resource": {
                "resource_type":
                    self.resource_type,

                "resource_id":
                    resource_id,
            },

            "vpc":
                topology.get(
                    "vpc"
                ),

            "vpc_id":
                vpc_id,

            "subnet":
                self._find_subnet(
                    topology,
                    subnet_id,
                ),

            "subnet_profile":
                subnet_profile,

            "effective_route_table":
                route_table,

            "network_summary":
                topology.get(
                    "summary",
                    {},
                ),

            "route_targets":
                topology.get(
                    "route_targets",
                    {},
                ),

            "route_tables":
                topology.get(
                    "route_tables",
                    [],
                ),

            "vpc_endpoints":
                topology.get(
                    "vpc_endpoints",
                    [],
                ),
        }

    # ==================================================================
    # HELPERS
    # ==================================================================

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

        except Exception:
            return None

        interfaces = response.get(
            "NetworkInterfaces",
            [],
        )

        return (
            interfaces[0]
            if interfaces
            else None
        )

    def _get_instance_state(
        self,
        instance_id: Optional[str],
    ) -> Optional[str]:

        if not instance_id:
            return None

        try:

            response = (
                self.ec2.describe_instances(
                    InstanceIds=[
                        instance_id
                    ]
                )
            )

        except Exception:
            return None

        for reservation in response.get(
            "Reservations",
            [],
        ):

            for instance in reservation.get(
                "Instances",
                [],
            ):

                if (
                    instance.get(
                        "InstanceId"
                    )
                    != instance_id
                ):
                    continue

                state = (
                    instance.get(
                        "State",
                        {},
                    )
                    or {}
                )

                name = state.get(
                    "Name"
                )

                if name:
                    return str(
                        name
                    ).lower()

        return None

    @staticmethod
    def _get_instance_id(
        eni: Dict[str, Any],
    ) -> Optional[str]:

        attachment = (
            eni.get(
                "Attachment",
                {},
            )
            or {}
        )

        value = attachment.get(
            "InstanceId"
        )

        return (
            str(value)
            if value
            else None
        )

    @staticmethod
    def _is_requester_managed(
        eni: Optional[Dict[str, Any]],
    ) -> bool:

        return bool(
            eni
            and eni.get(
                "RequesterManaged",
                False,
            )
        )

    @staticmethod
    def _classify_eip(
        requester_managed: bool,
        network_interface_type: Optional[str],
    ) -> str:

        if requester_managed:

            if network_interface_type:
                return (
                    "service_managed:"
                    f"{network_interface_type}"
                )

            return "service_managed"

        return "elastic_ip"

    @staticmethod
    def _determine_eni_public_ip_type(
        eni: Dict[str, Any],
    ) -> str:

        interface_type = eni.get(
            "InterfaceType"
        )

        requester_managed = bool(
            eni.get(
                "RequesterManaged",
                False,
            )
        )

        if requester_managed:

            if interface_type:
                return (
                    "service_managed:"
                    f"{interface_type}"
                )

            return "service_managed"

        if interface_type == "nat_gateway":
            return "nat_gateway"

        if interface_type:
            return str(
                interface_type
            )

        return "ec2_public_ipv4"

    @staticmethod
    def _find_subnet(
        topology: Dict[str, Any],
        subnet_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:

        if not subnet_id:
            return None

        for subnet in topology.get(
            "subnets",
            [],
        ):

            if (
                subnet.get(
                    "subnet_id"
                )
                == subnet_id
            ):
                return subnet

        return None

    @staticmethod
    def _tags(
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