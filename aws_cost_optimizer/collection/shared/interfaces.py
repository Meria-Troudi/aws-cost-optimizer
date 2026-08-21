"""
Reusable EC2 Network Interface evidence collector.

"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client


class NetworkInterfaceCollector:

    def __init__(
        self,
        region: str,
    ) -> None:

        
        self.region = region

        self.ec2 = get_client(
            "ec2",
            region,
        )
    def collect(
        self,
        interface_ids: List[str],
    ) -> Dict[str, Any]:

        interface_ids = self._normalize_ids(
            interface_ids
        )

        if not interface_ids:
            return {
                "status": "empty",
                "interfaces": [],
                "count": 0,
            }

        interfaces: List[
            Dict[str, Any]
        ] = []

        errors: List[
            Dict[str, Any]
        ] = []

        # EC2 allows a bounded number of IDs per request.
        for chunk in self._chunks(
            interface_ids,
            100,
        ):

            try:

                response = (
                    self.ec2.describe_network_interfaces(
                        NetworkInterfaceIds=chunk
                    )
                )

            except Exception as exc:

                errors.append(
                    {
                        "interface_ids": chunk,
                        "error": str(exc),
                    }
                )

                continue

            for interface in response.get(
                "NetworkInterfaces",
                [],
            ):

                normalized = (
                    self._normalize_interface(
                        interface
                    )
                )

                if normalized:
                    interfaces.append(
                        normalized
                    )

        found_ids = {
            interface.get(
                "network_interface_id"
            )
            for interface in interfaces
        }

        missing_ids = [
            interface_id
            for interface_id in interface_ids
            if interface_id not in found_ids
        ]

        status = "ok"

        if errors and interfaces:
            status = "partial"

        elif errors and not interfaces:
            status = "error"

        elif missing_ids:
            status = "partial"

        return {
            "status": status,

            "interfaces":
                interfaces,

            "count":
                len(interfaces),

            "requested_count":
                len(interface_ids),

            "missing_ids":
                missing_ids,

            "errors":
                errors,
        }
    @staticmethod
    def _normalize_interface(
        interface: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        interface_id = interface.get(
            "NetworkInterfaceId"
        )

        if not interface_id:
            return None

        private_ip_addresses = []

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
                    "private_ip":
                        address.get(
                            "PrivateIpAddress"
                        ),

                    "primary":
                        address.get(
                            "Primary"
                        ),

                    "association":
                        address.get(
                            "Association"
                        ),
                }
            )

        groups = []

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
                    "group_id":
                        group.get(
                            "GroupId"
                        ),

                    "group_name":
                        group.get(
                            "GroupName"
                        ),
                }
            )

        attachment = (
            interface.get(
                "Attachment"
            )
            or {}
        )

        return {
            "network_interface_id":
                interface_id,

            "subnet_id":
                interface.get(
                    "SubnetId"
                ),

            "vpc_id":
                interface.get(
                    "VpcId"
                ),

            "availability_zone":
                interface.get(
                    "AvailabilityZone"
                ),

            "availability_zone_id":
                interface.get(
                    "AvailabilityZoneId"
                ),

            "description":
                interface.get(
                    "Description"
                ),

            "interface_type":
                interface.get(
                    "InterfaceType"
                ),

            "status":
                interface.get(
                    "Status"
                ),

            "private_dns_name":
                interface.get(
                    "PrivateDnsName"
                ),

            "private_ip_address":
                interface.get(
                    "PrivateIpAddress"
                ),

            "private_ip_addresses":
                private_ip_addresses,

            "groups":
                groups,

            "source_dest_check":
                interface.get(
                    "SourceDestCheck"
                ),

            "requester_managed":
                interface.get(
                    "RequesterManaged"
                ),

            "requester_id":
                interface.get(
                    "RequesterId"
                ),

            "operator":
                interface.get(
                    "Operator"
                ),

            "owner_id":
                interface.get(
                    "OwnerId"
                ),

            "attachment": {
                "attachment_id":
                    attachment.get(
                        "AttachmentId"
                    ),

                "instance_id":
                    attachment.get(
                        "InstanceId"
                    ),

                "instance_owner_id":
                    attachment.get(
                        "InstanceOwnerId"
                    ),

                "device_index":
                    attachment.get(
                        "DeviceIndex"
                    ),

                "status":
                    attachment.get(
                        "Status"
                    ),

                "attach_time":
                    (
                        attachment.get(
                            "AttachTime"
                        ).isoformat()
                        if attachment.get(
                            "AttachTime"
                        )
                        else None
                    ),

                "delete_on_termination":
                    attachment.get(
                        "DeleteOnTermination"
                    ),
            },

            "tags":
                NetworkInterfaceCollector._tags(
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

            if not value:
                continue

            value = str(
                value
            ).strip()

            if not value:
                continue

            if value in seen:
                continue

            seen.add(
                value
            )

            result.append(
                value
            )

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
            yield values[
                index:index + size
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
            tag["Key"]:
                tag.get("Value")
            for tag in tags
            if isinstance(
                tag,
                dict,
            )
            and tag.get(
                "Key"
            )
        }