"""
AWS Public IPv4 collector.

Collects evidence for public IPv4 cost optimization.

The collector does not decide whether an address should be released,
replaced, or retained.

Evidence includes:

- Elastic IP allocation
- public IPv4 addresses on ENIs
- association state
- EC2 instance
- EC2 instance state
- ENI type
- requester/service-managed status
- VPC
- subnet
- Availability Zone
- address classification
- tags
- billing usage classification

AWS billing distinction:

PublicIPv4IdleAddress
    Address is idle.

PublicIPv4InUseAddress
    Address is associated with an AWS resource.

Billing classification is evidence only.
Resource-level cost attribution remains the responsibility of
the billing/reconciliation layer.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.registry import register


@register
class PublicIPv4Collector(BaseCollector):

    key = "public_ipv4"
    resource_type = "public_ipv4"

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
            raise ValueError(
                "Public IPv4 collector requires a region."
            )

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self._eni_index: dict[
            str,
            dict[str, Any],
        ] = {}

        self._instance_index: dict[
            str,
            dict[str, Any],
        ] = {}

    # ==============================================================
    # DISCOVERY
    # ==============================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: list[
            Dict[str, Any]
        ] = []

        seen_keys: set[str] = set()

        eips = self._discover_eips()

        for address in eips:

            public_ip = address.get(
                "PublicIp"
            )

            if not public_ip:
                continue

            key = f"ip:{public_ip}"

            if key in seen_keys:
                continue

            seen_keys.add(key)

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

        eni_resources = (
            self._discover_eni_public_ips()
        )

        for resource in eni_resources:

            public_ip = (
                resource.get(
                    "public_ip"
                )
            )

            if not public_ip:
                continue

            key = f"ip:{public_ip}"

            if key in seen_keys:
                continue

            seen_keys.add(key)

            resources.append(
                {
                    "id":
                        self._public_ip_resource_id(
                            public_ip
                        ),

                    "raw":
                        resource.get(
                            "raw"
                        ),

                    "source":
                        "network_interface",
                }
            )

        # Batch enrichment.
        self._build_indexes()

        return resources

    # ==============================================================
    # DISCOVERY HELPERS
    # ==============================================================

    def _discover_eips(
        self,
    ) -> list[dict[str, Any]]:

        response = (
            self.ec2.describe_addresses()
        )

        return [
            address
            for address
            in response.get(
                "Addresses",
                [],
            )
            if isinstance(
                address,
                dict,
            )
        ]

    def _discover_eni_public_ips(
        self,
    ) -> list[dict[str, Any]]:

        paginator = (
            self.ec2.get_paginator(
                "describe_network_interfaces"
            )
        )

        result: list[
            dict[str, Any]
        ] = []

        for page in paginator.paginate():

            for eni in page.get(
                "NetworkInterfaces",
                [],
            ):

                if not isinstance(
                    eni,
                    dict,
                ):
                    continue

                association = (
                    eni.get(
                        "Association"
                    )
                    or {}
                )

                public_ip = association.get(
                    "PublicIp"
                )

                if not public_ip:
                    continue

                result.append(
                    {
                        "public_ip":
                            str(public_ip),

                        "raw":
                            eni,
                    }
                )

        return result

    # ==============================================================
    # BATCH ENRICHMENT
    # ==============================================================

    def _build_indexes(
        self,
    ) -> None:

        self._eni_index = {}

        paginator = (
            self.ec2.get_paginator(
                "describe_network_interfaces"
            )
        )

        for page in paginator.paginate():

            for eni in page.get(
                "NetworkInterfaces",
                [],
            ):

                eni_id = (
                    eni.get(
                        "NetworkInterfaceId"
                    )
                )

                if eni_id:
                    self._eni_index[
                        str(eni_id)
                    ] = eni

        instance_ids = sorted(
            {
                self._instance_id_from_eni(
                    eni
                )
                for eni in self._eni_index.values()
                if self._instance_id_from_eni(
                    eni
                )
            }
        )

        self._instance_index = {}

        if not instance_ids:
            return

        for chunk in self._chunks(
            instance_ids,
            100,
        ):

            response = (
                self.ec2.describe_instances(
                    InstanceIds=chunk
                )
            )

            for reservation in response.get(
                "Reservations",
                [],
            ):

                for instance in reservation.get(
                    "Instances",
                    [],
                ):

                    instance_id = (
                        instance.get(
                            "InstanceId"
                        )
                    )

                    if instance_id:
                        self._instance_index[
                            str(instance_id)
                        ] = instance

    # ==============================================================
    # RESOURCE ID
    # ==============================================================

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return str(
            resource.get(
                "id"
            )
            or "unknown"
        )

    @staticmethod
    def _eip_resource_id(
        address: Dict[str, Any],
    ) -> str:

        allocation_id = (
            address.get(
                "AllocationId"
            )
        )

        if allocation_id:
            return str(
                allocation_id
            )

        public_ip = (
            address.get(
                "PublicIp"
            )
        )

        if public_ip:
            return (
                f"public-ip:{public_ip}"
            )

        return "unknown-public-ip"

    @staticmethod
    def _public_ip_resource_id(
        public_ip: str,
    ) -> str:

        return (
            f"public-ip:{public_ip}"
        )

    # ==============================================================
    # IDENTITY
    # ==============================================================

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        if resource.get(
            "source"
        ) == "elastic_ip":

            return self._eip_identity(
                resource
            )

        return self._eni_identity(
            resource
        )

    def _eip_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        address = resource.get(
            "raw"
        ) or {}

        eni = self._eni_for_eip(
            address
        )

        return {
            "name":
                address.get(
                    "PublicIp"
                )
                or address.get(
                    "AllocationId"
                ),

            "public_ip":
                address.get(
                    "PublicIp"
                ),

            "allocation_id":
                address.get(
                    "AllocationId"
                ),

            "association_id":
                address.get(
                    "AssociationId"
                ),

            "resource_id":
                resource.get(
                    "id"
                ),

            "resource_type":
                "elastic_ip",

            "source":
                "elastic_ip",

            "requester_managed":
                self._requester_managed(
                    eni
                ),

            "network_interface_type":
                (
                    eni.get(
                        "InterfaceType"
                    )
                    if eni
                    else None
                ),

            "tags":
                self._tags(
                    address.get(
                        "Tags",
                        [],
                    )
                ),
        }

    def _eni_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        eni = (
            resource.get(
                "raw"
            )
            or {}
        )

        association = (
            eni.get(
                "Association"
            )
            or {}
        )

        public_ip = (
            association.get(
                "PublicIp"
            )
        )

        return {
            "name":
                public_ip
                or eni.get(
                    "NetworkInterfaceId"
                ),

            "public_ip":
                public_ip,

            "network_interface_id":
                eni.get(
                    "NetworkInterfaceId"
                ),

            "resource_id":
                resource.get(
                    "id"
                ),

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

            "tags":
                self._tags(
                    eni.get(
                        "TagSet",
                        [],
                    )
                ),
        }

    # ==============================================================
    # CONFIGURATION
    # ==============================================================

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        if resource.get(
            "source"
        ) == "elastic_ip":

            return self._eip_configuration(
                resource
            )

        return self._eni_configuration(
            resource
        )

    def _eip_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        address = (
            resource.get(
                "raw"
            )
            or {}
        )

        allocation_id = (
            address.get(
                "AllocationId"
            )
        )

        association_id = (
            address.get(
                "AssociationId"
            )
        )

        eni_id = (
            address.get(
                "NetworkInterfaceId"
            )
        )

        eni = self._eni_index.get(
            str(eni_id)
        ) if eni_id else None

        instance_id = (
            address.get(
                "InstanceId"
            )
        )

        if not instance_id and eni:
            instance_id = (
                self._instance_id_from_eni(
                    eni
                )
            )

        instance = (
            self._instance_index.get(
                str(instance_id)
            )
            if instance_id
            else None
        )

        requester_managed = (
            self._requester_managed(
                eni
            )
        )

        associated = bool(
            association_id
            or eni_id
            or instance_id
        )

        instance_state = (
            self._instance_state(
                instance
            )
        )

        subnet_id = (
            eni.get("SubnetId")
            if eni
            else None
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
                self._address_state(
                    associated=associated,
                    instance_state=instance_state,
                ),

            "instance_id":
                instance_id,

            "instance_state":
                instance_state,

            "network_interface_id":
                eni_id,

            "network_interface_type":
                (
                    eni.get(
                        "InterfaceType"
                    )
                    if eni
                    else None
                ),

            "network_interface_owner_id":
                (
                    eni.get(
                        "RequesterId"
                    )
                    if eni
                    else None
                ),

            "requester_managed":
                requester_managed,

            "requester_id":
                (
                    eni.get(
                        "RequesterId"
                    )
                    if eni
                    else None
                ),

            "service_managed":
                requester_managed,

            "vpc_id":
                (
                    eni.get(
                        "VpcId"
                    )
                    if eni
                    else None
                ),

            "subnet_id":
                subnet_id,

            "availability_zone":
                (
                    eni.get(
                        "AvailabilityZone"
                    )
                    if eni
                    else None
                ),

            "public_ip_type":
                self._classify_eip(
                    requester_managed,
                    (
                        eni.get(
                            "InterfaceType"
                        )
                        if eni
                        else None
                    ),
                ),

            "address_type":
                "elastic_ip",

            "address_source":
                "elastic_ip",

            "service_principal":
                (
                    eni.get(
                        "RequesterId"
                    )
                    if eni
                    else None
                ),

            "interface_description":
                (
                    eni.get(
                        "Description"
                    )
                    if eni
                    else None
                ),

            "tags":
                self._tags(
                    address.get(
                        "Tags",
                        [],
                    )
                ),

            "cost_relevant":
                True,

            "billing_usage_type":
                (
                    "PublicIPv4IdleAddress"
                    if (
                        not associated
                        or instance_state
                        in {
                            "stopped",
                            "stopping",
                            "hibernated",
                        }
                    )
                    else
                    "PublicIPv4InUseAddress"
                ),

            "optimization_candidate":
                not requester_managed,

            "release_candidate":
                (
                    not requester_managed
                    and not associated
                ),
        }

    def _eni_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        eni = (
            resource.get(
                "raw"
            )
            or {}
        )

        association = (
            eni.get(
                "Association"
            )
            or {}
        )

        public_ip = (
            association.get(
                "PublicIp"
            )
        )

        requester_managed = (
            bool(
                eni.get(
                    "RequesterManaged",
                    False,
                )
            )
        )

        instance_id = (
            self._instance_id_from_eni(
                eni
            )
        )

        instance = (
            self._instance_index.get(
                str(instance_id)
            )
            if instance_id
            else None
        )

        instance_state = (
            self._instance_state(
                instance
            )
        )

        interface_type = (
            eni.get(
                "InterfaceType"
            )
        )

        public_ip_type = (
            self._classify_eni(
                eni
            )
        )

        return {
            "public_ip":
                public_ip,

            "allocation_id":
                None,

            "association_id":
                association.get(
                    "AssociationId"
                ),

            "associated":
                bool(
                    public_ip
                ),

            "state":
                "associated"
                if public_ip
                else "unknown",

            "instance_id":
                instance_id,

            "instance_state":
                instance_state,

            "network_interface_id":
                eni.get(
                    "NetworkInterfaceId"
                ),

            "network_interface_type":
                interface_type,

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
                public_ip_type,

            "address_type":
                public_ip_type,

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

            "cost_relevant":
                bool(
                    public_ip
                ),

            "billing_usage_type":
                "PublicIPv4InUseAddress",

            "optimization_candidate":
                not requester_managed,

            # A non-EIP dynamically assigned EC2 public IP is
            # automatically released when the instance stops or
            # terminates. It is not something this analyzer should
            # recommend "releasing" manually.
            "release_candidate":
                False,
        }

    # ==============================================================
    # OBSERVATIONS
    # ==============================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "status":
                "not_applicable",

            "summary": {
                "billing_usage_type":
                    (
                        self._safe_configuration(
                            resource
                        ).get(
                            "billing_usage_type"
                        )
                    ),
            },
        }

    # ==============================================================
    # OPTIMIZATION EVIDENCE
    # ==============================================================

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._dict(
            collected_resource.get(
                "identity"
            )
        )

        configuration = self._dict(
            collected_resource.get(
                "configuration"
            )
        )

        return {
            "resource": {
                "id":
                    resource.get(
                        "id"
                    ),

                "name":
                    identity.get(
                        "name"
                    ),

                "resource_type":
                    collected_resource.get(
                        "resource_type"
                    ),

                "region":
                    self.region,
            },

            "address": {
                "public_ip":
                    configuration.get(
                        "public_ip"
                    ),

                "allocation_id":
                    configuration.get(
                        "allocation_id"
                    ),

                "address_source":
                    configuration.get(
                        "address_source"
                    ),

                "address_type":
                    configuration.get(
                        "address_type"
                    ),

                "public_ip_type":
                    configuration.get(
                        "public_ip_type"
                    ),

                "billing_usage_type":
                    configuration.get(
                        "billing_usage_type"
                    ),
            },

            "association": {
                "associated":
                    configuration.get(
                        "associated"
                    ),

                "association_id":
                    configuration.get(
                        "association_id"
                    ),

                "instance_id":
                    configuration.get(
                        "instance_id"
                    ),

                "instance_state":
                    configuration.get(
                        "instance_state"
                    ),

                "network_interface_id":
                    configuration.get(
                        "network_interface_id"
                    ),
            },

            "management": {
                "requester_managed":
                    configuration.get(
                        "requester_managed"
                    ),

                "service_managed":
                    configuration.get(
                        "service_managed"
                    ),

                "requester_id":
                    configuration.get(
                        "requester_id"
                    ),
            },

            "network": {
                "vpc_id":
                    configuration.get(
                        "vpc_id"
                    ),

                "subnet_id":
                    configuration.get(
                        "subnet_id"
                    ),

                "availability_zone":
                    configuration.get(
                        "availability_zone"
                    ),

                "network_interface_type":
                    configuration.get(
                        "network_interface_type"
                    ),
            },

            "eligibility": {
                "optimization_candidate":
                    configuration.get(
                        "optimization_candidate"
                    ),

                "release_candidate":
                    configuration.get(
                        "release_candidate"
                    ),
            },

            "data_quality": {
                "configuration_available":
                    bool(
                        configuration
                    ),

                "public_ip_available":
                    configuration.get(
                        "public_ip"
                    )
                    is not None,

                "association_state_available":
                    configuration.get(
                        "associated"
                    )
                    is not None,

                "instance_state_available":
                    (
                        configuration.get(
                            "instance_state"
                        )
                        is not None
                        or
                        not configuration.get(
                            "instance_id"
                        )
                    ),

                "billing_classification_available":
                    configuration.get(
                        "billing_usage_type"
                    )
                    is not None,

                "management_classification_available":
                    configuration.get(
                        "requester_managed"
                    )
                    is not None,
            },
        }

    # ==============================================================
    # HELPERS
    # ==============================================================

    def _eni_for_eip(
        self,
        address: dict[str, Any],
    ) -> dict[str, Any] | None:

        eni_id = address.get(
            "NetworkInterfaceId"
        )

        if not eni_id:
            return None

        return self._eni_index.get(
            str(eni_id)
        )

    @staticmethod
    def _instance_id_from_eni(
        eni: dict[str, Any],
    ) -> str | None:

        attachment = (
            eni.get(
                "Attachment"
            )
            or {}
        )

        value = (
            attachment.get(
                "InstanceId"
            )
        )

        return (
            str(value)
            if value
            else None
        )

    @staticmethod
    def _instance_state(
        instance: dict[str, Any] | None,
    ) -> str | None:

        if not instance:
            return None

        state = (
            instance.get(
                "State"
            )
            or {}
        )

        name = (
            state.get(
                "Name"
            )
        )

        return (
            str(name).lower()
            if name
            else None
        )

    @staticmethod
    def _requester_managed(
        eni: dict[str, Any] | None,
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
        interface_type: str | None,
    ) -> str:

        if requester_managed:

            return (
                f"service_managed:"
                f"{interface_type}"
                if interface_type
                else "service_managed"
            )

        return "elastic_ip"

    @staticmethod
    def _classify_eni(
        eni: dict[str, Any],
    ) -> str:

        interface_type = (
            eni.get(
                "InterfaceType"
            )
        )

        requester_managed = bool(
            eni.get(
                "RequesterManaged",
                False,
            )
        )

        if requester_managed:

            return (
                f"service_managed:"
                f"{interface_type}"
                if interface_type
                else "service_managed"
            )

        if interface_type == "nat_gateway":
            return "nat_gateway"

        return (
            str(interface_type)
            if interface_type
            else "ec2_public_ipv4"
        )

    @staticmethod
    def _address_state(
        *,
        associated: bool,
        instance_state: str | None,
    ) -> str:

        if not associated:
            return "idle"

        if instance_state in {
            "stopped",
            "stopping",
            "hibernated",
        }:
            return "idle"

        return "associated"

    @staticmethod
    def _safe_configuration(
        resource: dict[str, Any],
    ) -> dict[str, Any]:

        value = resource.get(
            "configuration"
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _chunks(
        values: list[str],
        size: int,
    ) -> list[list[str]]:

        return [
            values[index:index + size]
            for index in range(
                0,
                len(values),
                size,
            )
        ]

    @staticmethod
    def _tags(
        tags: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        return {
            str(tag["Key"]):
                tag.get(
                    "Value"
                )
            for tag in tags
            if (
                isinstance(
                    tag,
                    dict,
                )
                and tag.get(
                    "Key"
                )
            )
        }