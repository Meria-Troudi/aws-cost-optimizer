"""
Reusable EC2 Network Interface evidence collector.

Purpose
-------
Collect ENI evidence required by network topology/resource analysis.

This collector does not determine whether an interface is unused.
It only reports authoritative EC2 state.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client


class NetworkInterfaceCollector:

    MAX_IDS_PER_REQUEST = 100

    def __init__(
        self,
        region: str,
    ) -> None:

        if not region or not str(region).strip():
            raise ValueError("Region is required")

        self.region = str(region).strip()

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

    def collect(
        self,
        interface_ids: List[str],
    ) -> Dict[str, Any]:

        interface_ids = self._normalize_ids(interface_ids)

        if not interface_ids:
            return {
                "status": "empty",
                "region": self.region,
                "interfaces": [],
                "count": 0,
                "requested_count": 0,
                "found_count": 0,
                "missing_ids": [],
                "errors": [],
            }

        interfaces: List[Dict[str, Any]] = []

        errors: List[Dict[str, Any]] = []

        for chunk in self._chunks(
            interface_ids,
            self.MAX_IDS_PER_REQUEST,
        ):

            try:

                response = self.ec2.describe_network_interfaces(
                    NetworkInterfaceIds=chunk
                )

            except Exception as exc:

                errors.append(
                    {
                        "operation": ("describe_network_interfaces"),
                        "interface_ids": list(chunk),
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                )

                continue

            raw_interfaces = response.get(
                "NetworkInterfaces",
                [],
            )

            if not isinstance(
                raw_interfaces,
                list,
            ):
                errors.append(
                    {
                        "operation": ("describe_network_interfaces"),
                        "interface_ids": list(chunk),
                        "error_type": "InvalidResponse",
                        "error": (
                            "AWS response field " "'NetworkInterfaces' is not a list"
                        ),
                    }
                )
                continue

            for interface in raw_interfaces:

                if not isinstance(
                    interface,
                    dict,
                ):
                    errors.append(
                        {
                            "operation": ("describe_network_interfaces"),
                            "interface_ids": list(chunk),
                            "error_type": "InvalidResponse",
                            "error": ("Network interface entry " "is not a mapping"),
                        }
                    )
                    continue

                normalized = self._normalize_interface(interface)

                if normalized:
                    interfaces.append(normalized)

        # Deduplicate defensively in case an API/client response
        deduplicated: Dict[
            str,
            Dict[str, Any],
        ] = {}

        for interface in interfaces:
            interface_id = interface.get("network_interface_id")

            if not interface_id:
                continue

            deduplicated[str(interface_id)] = interface

        interfaces = list(deduplicated.values())

        found_ids = {
            str(interface.get("network_interface_id"))
            for interface in interfaces
            if interface.get("network_interface_id")
        }

        missing_ids = [
            interface_id
            for interface_id in interface_ids
            if interface_id not in found_ids
        ]

        if errors and interfaces:
            status = "partial"
        elif errors and not interfaces:
            status = "error"
        elif missing_ids:
            status = "partial"
        else:
            status = "ok"

        return {
            "status": status,
            "region": self.region,
            "interfaces": interfaces,
            "count": len(interfaces),
            "requested_count": len(interface_ids),
            "found_count": len(found_ids),
            "missing_ids": missing_ids,
            "errors": errors,
        }

    @staticmethod
    def _normalize_interface(
        interface: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        interface_id = interface.get("NetworkInterfaceId")

        if not interface_id:
            return None

        interface_id = str(interface_id).strip()

        if not interface_id:
            return None

        private_ip_addresses: List[Dict[str, Any]] = []

        for address in (
            interface.get(
                "PrivateIpAddresses",
                [],
            )
            or []
        ):

            if not isinstance(
                address,
                dict,
            ):
                continue

            private_ip_addresses.append(
                {
                    "private_ip": address.get("PrivateIpAddress"),
                    "primary": address.get("Primary"),
                    "association": (address.get("Association")),
                }
            )

        ipv6_addresses: List[Dict[str, Any]] = []

        for address in (
            interface.get(
                "Ipv6Addresses",
                [],
            )
            or []
        ):

            if not isinstance(
                address,
                dict,
            ):
                continue

            ipv6_addresses.append(
                {
                    "ipv6_address": address.get("Ipv6Address"),
                    "primary": address.get("PrimaryIpv6"),
                }
            )

        groups: List[Dict[str, Any]] = []

        for group in (
            interface.get(
                "Groups",
                [],
            )
            or []
        ):

            if not isinstance(
                group,
                dict,
            ):
                continue

            groups.append(
                {
                    "group_id": group.get("GroupId"),
                    "group_name": group.get("GroupName"),
                }
            )

        attachment = interface.get("Attachment") or {}

        if not isinstance(
            attachment,
            dict,
        ):
            attachment = {}

        operator = interface.get("Operator")

        if not isinstance(
            operator,
            dict,
        ):
            operator = {}

        association = interface.get("Association")

        if not isinstance(
            association,
            dict,
        ):
            association = {}

        attach_time = attachment.get("AttachTime")

        attach_time_iso: Optional[str] = None

        if attach_time:
            try:
                attach_time_iso = (
                    attach_time.isoformat()
                    if hasattr(
                        attach_time,
                        "isoformat",
                    )
                    else str(attach_time)
                )
            except Exception:
                attach_time_iso = str(attach_time)

        return {
            "network_interface_id": interface_id,
            "subnet_id": interface.get("SubnetId"),
            "vpc_id": interface.get("VpcId"),
            "availability_zone": interface.get("AvailabilityZone"),
            "availability_zone_id": interface.get("AvailabilityZoneId"),
            "description": interface.get("Description"),
            "interface_type": interface.get("InterfaceType"),
            "status": interface.get("Status"),
            "private_dns_name": interface.get("PrivateDnsName"),
            "private_ip_address": interface.get("PrivateIpAddress"),
            "private_ip_addresses": (private_ip_addresses),
            "ipv6_addresses": ipv6_addresses,
            "association": {
                "public_ip": association.get("PublicIp"),
                "association_id": association.get("AssociationId"),
                "public_dns_name": association.get("PublicDnsName"),
                "ip_owner_id": association.get("IpOwnerId"),
                "customer_owned_ip": association.get("CustomerOwnedIp"),
                "customer_owned_ipv4_pool": association.get("CustomerOwnedIpv4Pool"),
            },
            "groups": groups,
            "source_dest_check": interface.get("SourceDestCheck"),
            "requester_managed": interface.get("RequesterManaged"),
            "requester_id": interface.get("RequesterId"),
            "operator": {
                "managed": operator.get("Managed"),
                "principal": operator.get("Principal"),
            },
            "owner_id": interface.get("OwnerId"),
            "attachment": {
                "attachment_id": attachment.get("AttachmentId"),
                "instance_id": attachment.get("InstanceId"),
                "instance_owner_id": attachment.get("InstanceOwnerId"),
                "device_index": attachment.get("DeviceIndex"),
                "network_card_index": attachment.get("NetworkCardIndex"),
                "status": attachment.get("Status"),
                "attach_time": attach_time_iso,
                "delete_on_termination": attachment.get("DeleteOnTermination"),
            },
            "tags": NetworkInterfaceCollector._tags(
                interface.get(
                    "TagSet",
                    [],
                )
            ),
        }

    @staticmethod
    def _normalize_ids(
        interface_ids: List[str],
    ) -> List[str]:

        result: List[str] = []

        seen: set[str] = set()

        for value in interface_ids or []:

            if value is None:
                continue

            value = str(value).strip()

            if not value:
                continue

            if value in seen:
                continue

            seen.add(value)
            result.append(value)

        return result

    @staticmethod
    def _chunks(
        values: List[str],
        size: int,
    ):
        for index in range(
            0,
            len(values),
            size,
        ):
            yield values[index : index + size]

    @staticmethod
    def _tags(
        tags: Any,
    ) -> Dict[str, Any]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        result: Dict[str, Any] = {}

        for tag in tags:

            if not isinstance(
                tag,
                dict,
            ):
                continue

            key = tag.get("Key")

            if key is None:
                continue

            key = str(key).strip()

            if not key:
                continue

            result[key] = tag.get("Value")

        return result
