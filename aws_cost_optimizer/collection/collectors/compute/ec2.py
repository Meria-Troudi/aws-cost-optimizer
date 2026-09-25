"""
AWS EC2 instance collector.

Purpose
-------
Collect only evidence required to explain EC2 instance cost and support
defensible cost-optimization findings.

Collection responsibilities
----------------------------
1. Discovery
2. Identity
3. Configuration
4. Profile-controlled relationships
5. CloudWatch observations
6. Optional CloudWatch Agent memory observations
7. Optional CloudTrail lifecycle observations

The collector does NOT make optimization decisions.

Important
---------
The collection profile defines WHAT evidence is collected.
The collector must not silently collect additional evidence that is
disabled in the profile.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from collection.base import BaseCollector
from collection.metrics.cloudwatch import CloudWatchMetricCollector
from collection.registry import register
from collection.shared.interfaces import NetworkInterfaceCollector
from aws_cost_optimizer.config.client import get_client


@register
class EC2Collector(BaseCollector):

    key = "ec2"
    resource_type = "ec2_instance"

    DEFAULT_CLOUDWATCH_PERIOD = 3600

    DEFAULT_CLOUDTRAIL_EVENTS = (
        "RunInstances",
        "StartInstances",
        "StopInstances",
        "TerminateInstances",
        "ModifyInstanceAttribute",
        "ModifyInstanceCreditSpecification",
    )

    # INITIALIZATION

    def __init__(
        self,
        scan,
        region: str | None = None,
        profile: Dict[str, Any] | None = None,
    ):
        super().__init__(
            scan,
            region=region,
            profile=profile,
        )

        if not self.region:
            raise ValueError("EC2Collector requires a region.")

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self.autoscaling = get_client(
            "autoscaling",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.cloudwatch_collector = CloudWatchMetricCollector(self.cloudwatch)

        self._eni_collector = NetworkInterfaceCollector(self.region)

        # Batch caches.
        self._metrics_batch_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._agent_metrics_batch_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._cloudwatch_batch_error: Optional[str] = None
        self._cloudwatch_agent_batch_error: Optional[str] = None

    # PROFILE

    def _observation_config(self) -> Dict[str, Any]:
        return self._safe_dict(self.profile.get("observations"))

    def _cloudwatch_config(self) -> Dict[str, Any]:
        return self._safe_dict(self._observation_config().get("cloudwatch"))

    def _cloudwatch_agent_config(self) -> Dict[str, Any]:
        observations = self._observation_config()

        # "cwagent" is the collection-profile's actual key (see
        # collection_profiles.yaml's ec2_instance.observations.cwagent).
        # "cloudwatch_agent" is kept as a fallback for any older profile
        # still using the previous name.
        config = observations.get("cwagent")

        if isinstance(config, dict):
            return config

        return self._safe_dict(observations.get("cloudwatch_agent"))

    def _relationships_config(self) -> Dict[str, Any]:
        return self._safe_dict(self.profile.get("relationships"))

    def _cloudtrail_config(self) -> Dict[str, Any]:
        # cloudtrail is nested under observations in the collection
        # profile (ec2_instance.observations.cloudtrail), not at the
        # profile root.
        return self._safe_dict(self._observation_config().get("cloudtrail"))

    @staticmethod
    def _config_enabled(
        config: Dict[str, Any],
        default: bool = False,
    ) -> bool:
        """
        Whether a single already-resolved config dict (e.g.
        self._cloudwatch_config()) declares itself enabled.

        Deliberately named differently from BaseCollector._section_enabled
        (self, section_name: str) -- that one looks up a section BY NAME
        in self.profile; this one checks a config dict the caller already
        resolved. They used to share the name "_section_enabled", which
        meant this override silently shadowed the base method for every
        EC2 instance: _safe_collect_section() calls
        self._section_enabled("identity"), and passing that string into
        this method's `config: Dict` parameter crashed on config.get(...)
        with 'str' object has no attribute 'get' -- collection never
        actually failed per-instance, it failed for every single EC2
        instance, unconditionally, on the very first section.
        """
        return (
            config.get(
                "enabled",
                default,
            )
            is True
        )

    def _relationship_enabled(
        self,
        name: str,
    ) -> bool:
        """
        Respect the collection profile.

        Supported profile forms:

            relationships:
              enabled: true
              collect:
                network_interfaces: true

        or:

            relationships:
              network_interfaces:
                enabled: true
        """

        config = self._relationships_config()

        if config.get("enabled") is False:
            return False

        collect = config.get("collect")

        if isinstance(collect, dict):
            if name in collect:
                return collect[name] is True

        item = config.get(name)

        if isinstance(item, dict):
            return (
                item.get(
                    "enabled",
                    False,
                )
                is True
            )

        if isinstance(item, bool):
            return item

        # If relationships are explicitly enabled but no individual
        # selector exists, preserve the historical behavior.
        if config.get("enabled") is True:
            return True

        return False

    # DISCOVERY

    def discover(self) -> list:
        """
        Discover EC2 instances in the configured region.

        Discovery only returns resources. It does not make optimization
        decisions.
        """

        # Reset caches for every discovery execution.
        self._metrics_batch_cache = {}
        self._agent_metrics_batch_cache = {}
        self._cloudwatch_batch_error = None
        self._cloudwatch_agent_batch_error = None

        result: List[Dict[str, Any]] = []

        paginator = self.ec2.get_paginator("describe_instances")

        for page in paginator.paginate():

            reservations = page.get(
                "Reservations",
                [],
            )

            for reservation in reservations:

                if not isinstance(
                    reservation,
                    dict,
                ):
                    continue

                instances = reservation.get(
                    "Instances",
                    [],
                )

                for instance in instances:

                    if not isinstance(
                        instance,
                        dict,
                    ):
                        continue

                    instance_id = instance.get("InstanceId")

                    if not instance_id:
                        continue

                    result.append(instance)

        # CloudWatch is intentionally prefetched once for all resources.
        self._prefetch_metrics_batch(result)

        return result

    def get_resource_id(
        self,
        resource: dict,
    ) -> str:
        return str(resource.get("InstanceId") or "")

    # CLOUDWATCH PREFETCH

    def _prefetch_metrics_batch(
        self,
        instances: List[Dict[str, Any]],
    ) -> None:
        """
        Batch-load standard EC2 and optional CWAgent metrics.

        Only metrics explicitly defined by the profile are requested.
        """

        if not instances:
            return

        try:
            start, end = self.get_analysis_period()
        except Exception:
            return

        observation_config = self._observation_config()

        # STANDARD EC2

        cloudwatch_config = self._cloudwatch_config()

        if self._config_enabled(
            cloudwatch_config,
            default=False,
        ):

            period = cloudwatch_config.get("period") or self.DEFAULT_CLOUDWATCH_PERIOD

            metric_specs = self._normalize_metric_specs(
                cloudwatch_config.get("metrics")
            )

            if metric_specs:

                requests = self._build_metric_requests(
                    instances=instances,
                    namespace=(cloudwatch_config.get("namespace") or "AWS/EC2"),
                    metric_specs=metric_specs,
                    dimensions_config=cloudwatch_config.get("dimensions"),
                )

                if requests:

                    try:
                        response = self.cloudwatch_collector.collect_batch(
                            requests,
                            start=start,
                            end=end,
                            requested_period=int(period),
                        )

                        self._metrics_batch_cache = (
                            response
                            if isinstance(
                                response,
                                dict,
                            )
                            else {}
                        )

                    except Exception as exc:

                        self._metrics_batch_cache = {}

                        self._cloudwatch_batch_error = str(exc)

        # OPTIONAL CLOUDWATCH AGENT

        agent_config = self._cloudwatch_agent_config()

        if not self._config_enabled(
            agent_config,
            default=False,
        ):
            self._agent_metrics_batch_cache = {}
            return

        agent_specs = self._normalize_metric_specs(agent_config.get("metrics"))

        if not agent_specs:
            self._agent_metrics_batch_cache = {}
            return

        agent_period = (
            agent_config.get("period")
            or cloudwatch_config.get("period")
            or self.DEFAULT_CLOUDWATCH_PERIOD
        )

        agent_requests = self._build_metric_requests(
            instances=instances,
            namespace=(agent_config.get("namespace") or "CWAgent"),
            metric_specs=agent_specs,
            dimensions_config=agent_config.get("dimensions"),
        )

        if not agent_requests:
            self._agent_metrics_batch_cache = {}
            return

        try:

            response = self.cloudwatch_collector.collect_batch(
                agent_requests,
                start=start,
                end=end,
                requested_period=int(agent_period),
            )

            self._agent_metrics_batch_cache = (
                response
                if isinstance(
                    response,
                    dict,
                )
                else {}
            )

        except Exception as exc:

            self._agent_metrics_batch_cache = {}

            self._cloudwatch_agent_batch_error = str(exc)

    @staticmethod
    def _resolve_dimensions(
        source: Dict[str, Any],
        dimensions_config: Optional[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        """
        Build CloudWatch dimensions from the profile's `dimensions` map
        (see collection_profiles.yaml's
        ec2_instance.observations.cloudwatch.dimensions: {InstanceId:
        instance_id}) instead of a hardcoded InstanceId dimension, so
        the profile stays the single source of truth for what evidence
        is requested.

        The map's keys are the actual raw AWS API field names (which
        are also the CloudWatch dimension names for EC2, e.g.
        "InstanceId") -- `source` here is the raw boto3 instance dict,
        PascalCase, not the collector's own normalized snake_case
        output, so the lookup must use the key side, not the value
        side (the value side is only a human-readable alias, matching
        the convention used by this profile's `identity.fields`).
        """

        if not isinstance(dimensions_config, dict) or not dimensions_config:
            instance_id = source.get("InstanceId")

            if not instance_id:
                return []

            return [
                {
                    "Name": "InstanceId",
                    "Value": str(instance_id),
                }
            ]

        dimensions: List[Dict[str, str]] = []

        for dimension_name in dimensions_config:

            value = source.get(str(dimension_name))

            if value is None:
                continue

            dimensions.append(
                {
                    "Name": str(dimension_name),
                    "Value": str(value),
                }
            )

        return dimensions

    def _build_metric_requests(
        self,
        instances: List[Dict[str, Any]],
        namespace: str,
        metric_specs: List[Dict[str, Any]],
        dimensions_config: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:

        requests: List[Dict[str, Any]] = []

        seen: set[str] = set()

        for instance in instances:

            instance_id = instance.get("InstanceId")

            if not instance_id:
                continue

            instance_id = str(instance_id)

            if instance_id in seen:
                continue

            seen.add(instance_id)

            dimensions = self._resolve_dimensions(instance, dimensions_config)

            if not dimensions:
                continue

            requests.append(
                {
                    "resource_key": instance_id,
                    "namespace": namespace,
                    "dimensions": dimensions,
                    "metric_specs": metric_specs,
                }
            )

        return requests

    # IDENTITY

    def collect_identity(
        self,
        resource: dict,
    ) -> dict:

        tags = self._tags(
            resource.get(
                "Tags",
                [],
            )
        )

        placement = self._safe_dict(resource.get("Placement"))

        return {
            "instance_id": resource.get("InstanceId"),
            "name": (tags.get("Name") or resource.get("InstanceId")),
            "instance_type": resource.get("InstanceType"),
            "state": self._state_name(resource),
            "image_id": resource.get("ImageId"),
            "architecture": resource.get("Architecture"),
            "platform": resource.get("Platform"),
            "platform_details": resource.get("PlatformDetails"),
            "launch_time": self._iso(resource.get("LaunchTime")),
            "instance_lifecycle": resource.get("InstanceLifecycle"),
            "usage_operation": resource.get("UsageOperation"),
            "tenancy": placement.get("Tenancy"),
            "availability_zone": placement.get("AvailabilityZone"),
            "tags": tags,
        }

    # CONFIGURATION

    def collect_configuration(
        self,
        resource: dict,
    ) -> dict:

        placement = self._safe_dict(resource.get("Placement"))

        monitoring = self._safe_dict(resource.get("Monitoring"))

        security_groups = (
            resource.get(
                "SecurityGroups",
                [],
            )
            or []
        )

        network_interfaces = (
            resource.get(
                "NetworkInterfaces",
                [],
            )
            or []
        )

        security_group_ids = [
            str(group.get("GroupId"))
            for group in security_groups
            if (isinstance(group, dict) and group.get("GroupId"))
        ]

        return {
            "instance_id": resource.get("InstanceId"),
            "instance_type": resource.get("InstanceType"),
            "state": self._state_name(resource),
            "state_code": (self._safe_dict(resource.get("State")).get("Code")),
            "state_reason": (self._safe_dict(resource.get("StateReason"))),
            "launch_time": self._iso(resource.get("LaunchTime")),
            "image_id": resource.get("ImageId"),
            "architecture": resource.get("Architecture"),
            "platform": resource.get("Platform"),
            "platform_details": resource.get("PlatformDetails"),
            "hypervisor": resource.get("Hypervisor"),
            "virtualization_type": resource.get("VirtualizationType"),
            "ena_support": resource.get("EnaSupport"),
            "ebs_optimized": resource.get("EbsOptimized"),
            "monitoring": monitoring.get("State"),
            "availability_zone": placement.get("AvailabilityZone"),
            "tenancy": placement.get("Tenancy"),
            "subnet_id": resource.get("SubnetId"),
            "vpc_id": resource.get("VpcId"),
            "private_ip": resource.get("PrivateIpAddress"),
            "private_dns": resource.get("PrivateDnsName"),
            "public_ip": resource.get("PublicIpAddress"),
            "public_dns": resource.get("PublicDnsName"),
            "ipv6_addresses": self._collect_ipv6_addresses(network_interfaces),
            "security_group_ids": security_group_ids,
            "security_group_count": len(security_group_ids),
            "network_interface_count": len(network_interfaces),
            "iam_instance_profile": (
                self._safe_dict(resource.get("IamInstanceProfile")).get("Arn")
            ),
            "key_name": resource.get("KeyName"),
            "root_device": {
                "device_name": resource.get("RootDeviceName"),
                "device_type": resource.get("RootDeviceType"),
            },
            "root_device_name": resource.get("RootDeviceName"),
            "root_device_type": resource.get("RootDeviceType"),
            "block_device_mappings": (
                self._normalize_block_device_mappings(
                    resource.get(
                        "BlockDeviceMappings",
                        [],
                    )
                )
            ),
            "source_dest_check": resource.get("SourceDestCheck"),
            "hibernation_options": resource.get("HibernationOptions"),
            "cpu_options": resource.get("CpuOptions"),
            "placement_group_name": resource.get("PlacementGroupName"),
            "instance_lifecycle": resource.get("InstanceLifecycle"),
            "capacity_reservation_specification": (
                resource.get("CapacityReservationSpecification")
            ),
            "capacity_reservation_id": (self._capacity_reservation_id(resource)),
            "host_id": resource.get("HostId"),
            "host_resource_group_arn": resource.get("HostResourceGroupArn"),
            "tags": self._tags(
                resource.get(
                    "Tags",
                    [],
                )
            ),
        }

    # RELATIONSHIPS

    def collect_relationships(
        self,
        resource: dict,
    ) -> dict:
        """
        Collect only relationships enabled by the collection profile.
        """

        instance_id = resource.get("InstanceId")

        vpc_id = resource.get("VpcId")

        subnet_id = resource.get("SubnetId")

        network_interfaces: List[Dict[str, Any]] = []

        volumes: List[Dict[str, Any]] = []

        asg: Dict[str, Any] = {"managed": False}

        security_groups: List[Dict[str, Any]] = []

        interface_ids: List[str] = []

        raw_interfaces = (
            resource.get(
                "NetworkInterfaces",
                [],
            )
            or []
        )

        # NETWORK INTERFACES

        if self._relationship_enabled("network_interfaces"):

            interface_ids = [
                str(interface.get("NetworkInterfaceId"))
                for interface in raw_interfaces
                if (isinstance(interface, dict) and interface.get("NetworkInterfaceId"))
            ]

            if interface_ids:

                try:
                    eni_result = self._eni_collector.collect(interface_ids)

                    if isinstance(
                        eni_result,
                        dict,
                    ):
                        network_interfaces = (
                            eni_result.get(
                                "interfaces",
                                [],
                            )
                            or []
                        )

                except Exception:
                    network_interfaces = []

        # EBS

        if self._relationship_enabled("ebs_volumes") or self._relationship_enabled(
            "ebs"
        ):

            volumes = self._collect_volumes(resource)

        # AUTO SCALING

        if self._relationship_enabled(
            "autoscaling_group"
        ) or self._relationship_enabled("autoscaling"):

            asg = self._find_autoscaling_group(instance_id)

        # SECURITY GROUPS

        if self._relationship_enabled("security_groups"):

            security_groups = [
                {
                    "group_id": group.get("GroupId"),
                    "group_name": group.get("GroupName"),
                }
                for group in (
                    resource.get(
                        "SecurityGroups",
                        [],
                    )
                    or []
                )
                if isinstance(
                    group,
                    dict,
                )
            ]

        return {
            "summary": {
                "network_interface_count": len(interface_ids),
                "ebs_volume_count": len(volumes),
                "security_group_count": len(security_groups),
                "autoscaling_group_count": (
                    1 if asg.get("autoscaling_group_name") else 0
                ),
            },
            "network_interfaces": (network_interfaces),
            "ebs_volumes": volumes,
            "autoscaling": asg,
            "subnet": {
                "subnet_id": subnet_id,
                "vpc_id": vpc_id,
            },
            "security_groups": security_groups,
        }

    # OBSERVATIONS

    def collect_observations(
        self,
        resource: dict,
    ) -> dict:
        """
        Collect CloudWatch, optional CloudWatch Agent and optional
        CloudTrail evidence.

        No optimization decision is made here.
        """

        instance_id = resource.get("InstanceId")

        if not instance_id:
            return {
                "status": "error",
                "error": "EC2 instance ID is missing.",
            }

        try:
            start, end = self.get_analysis_period()
        except Exception as exc:
            return {
                "status": "error",
                "error": str(exc),
            }

        observation_config = self._observation_config()

        metrics: Dict[
            str,
            Dict[str, Any],
        ] = {}

        # STANDARD CLOUDWATCH

        cloudwatch_config = self._cloudwatch_config()

        cloudwatch_namespace = cloudwatch_config.get("namespace") or "AWS/EC2"

        cloudwatch_enabled = self._config_enabled(
            cloudwatch_config,
            default=False,
        )

        if cloudwatch_enabled:

            period = cloudwatch_config.get("period") or self.DEFAULT_CLOUDWATCH_PERIOD

            metric_specs = self._normalize_metric_specs(
                cloudwatch_config.get("metrics")
            )

            if not metric_specs:

                return {
                    "status": "incomplete",
                    "period": {
                        "start": start.isoformat(),
                        "end": end.isoformat(),
                        "duration_seconds": (end - start).total_seconds(),
                    },
                    "cloudwatch": {
                        "status": "configuration_error",
                        "namespace": cloudwatch_namespace,
                        "metrics": {},
                        "activity": {},
                    },
                    "cloudtrail": {},
                    "data_quality": {
                        "standard_ec2_metrics_requested": False,
                        "standard_ec2_metrics_available": False,
                        "reason": (
                            "No EC2 CloudWatch metrics are defined "
                            "in the collection profile."
                        ),
                    },
                }

            instance_key = str(instance_id)

            metric_results = self._metrics_batch_cache.get(instance_key)

            # Batch cache is authoritative when present -- but an empty
            # list is a legitimate "the batch query produced nothing for
            # this resource" result, not "not attempted yet". Only a
            # missing/malformed entry should fall through to the direct
            # per-instance call below.
            if not isinstance(metric_results, list) or not metric_results:

                dimensions = self._resolve_dimensions(
                    resource,
                    cloudwatch_config.get("dimensions"),
                )

                try:

                    metric_results = self.cloudwatch_collector.collect(
                        namespace=cloudwatch_namespace,
                        dimensions=dimensions,
                        metric_specs=metric_specs,
                        start=start,
                        end=end,
                        requested_period=int(period),
                    )

                except Exception as exc:

                    metric_results = []

                    if not self._cloudwatch_batch_error:
                        self._cloudwatch_batch_error = str(exc)

            self._merge_metrics(
                metrics,
                metric_results,
            )

        # OPTIONAL CLOUDWATCH AGENT

        agent_config = self._cloudwatch_agent_config()

        agent_namespace = agent_config.get("namespace") or "CWAgent"

        agent_enabled = self._config_enabled(
            agent_config,
            default=False,
        )

        if agent_enabled:

            agent_specs = self._normalize_metric_specs(agent_config.get("metrics"))

            if agent_specs:

                agent_period = (
                    agent_config.get("period")
                    or cloudwatch_config.get("period")
                    or self.DEFAULT_CLOUDWATCH_PERIOD
                )

                instance_key = str(instance_id)

                agent_results = self._agent_metrics_batch_cache.get(instance_key)

                if not isinstance(agent_results, list) or not agent_results:

                    dimensions = self._resolve_dimensions(
                        resource,
                        agent_config.get("dimensions"),
                    )

                    try:

                        agent_results = self.cloudwatch_collector.collect(
                            namespace=agent_namespace,
                            dimensions=dimensions,
                            metric_specs=agent_specs,
                            start=start,
                            end=end,
                            requested_period=int(agent_period),
                        )

                    except Exception as exc:

                        agent_results = []

                        if not self._cloudwatch_agent_batch_error:
                            self._cloudwatch_agent_batch_error = str(exc)

                self._merge_metrics(
                    metrics,
                    agent_results,
                )

        # ACTIVITY SUMMARY

        activity = self._build_activity_summary(
            metrics,
            start,
            end,
        )

        # CLOUDTRAIL

        cloudtrail: Dict[str, Any] = {}

        cloudtrail_config = self._cloudtrail_config()

        if self._config_enabled(
            cloudtrail_config,
            default=False,
        ):

            cloudtrail = self._collect_historical_events(
                str(instance_id),
                start,
                end,
            )

        # DATA QUALITY

        cpu_available = self._metric_ok(metrics.get("cpu_utilization"))

        cpu_max_available = self._metric_ok(metrics.get("cpu_utilization_max"))

        network_in_available = self._metric_ok(metrics.get("network_in"))

        network_out_available = self._metric_ok(metrics.get("network_out"))

        ebs_read_available = self._metric_ok(metrics.get("ebs_read_ops"))

        ebs_write_available = self._metric_ok(metrics.get("ebs_write_ops"))

        memory_average_available = self._metric_ok(metrics.get("mem_used_percent"))

        memory_max_available = self._metric_ok(metrics.get("mem_used_percent_max"))

        memory_available = memory_average_available or memory_max_available

        standard_metric_names = (
            "cpu_utilization",
            "cpu_utilization_max",
            "network_in",
            "network_out",
            "ebs_read_ops",
            "ebs_write_ops",
        )

        standard_metrics_available = any(
            self._metric_ok(metrics.get(name)) for name in standard_metric_names
        )

        standard_metrics_observed_count = sum(
            1 for name in standard_metric_names if self._metric_ok(metrics.get(name))
        )

        data_quality = {
            "standard_ec2_metrics_requested": (cloudwatch_enabled),
            "standard_ec2_metrics_available": (standard_metrics_available),
            "standard_ec2_metrics_observed_count": (standard_metrics_observed_count),
            "cpu_metrics_available": (cpu_available),
            "cpu_max_available": (cpu_max_available),
            "network_in_available": (network_in_available),
            "network_out_available": (network_out_available),
            "network_metrics_available": (
                network_in_available and network_out_available
            ),
            "ebs_read_available": (ebs_read_available),
            "ebs_write_available": (ebs_write_available),
            "ebs_metrics_available": (ebs_read_available and ebs_write_available),
            "memory_metrics_requested": (agent_enabled),
            "memory_metrics_available": (memory_available),
            "memory_average_available": (memory_average_available),
            "memory_max_available": (memory_max_available),
            "cloudwatch_batch_error": (self._cloudwatch_batch_error),
            "cloudwatch_agent_batch_error": (self._cloudwatch_agent_batch_error),
        }

        # STATUS

        # The error branch must be checked before "no_data": a batch/
        # direct CloudWatch call that raised is a genuine error, not
        # merely an absence of data, and the previous ordering made
        # "error" unreachable whenever cloudwatch_enabled was true
        # (which it always is when this code path runs at all).
        if self._cloudwatch_batch_error and not standard_metrics_available:
            observation_status = "error"
        elif cloudwatch_enabled and not standard_metrics_available:
            observation_status = "no_data"
        elif standard_metrics_available:
            observation_status = "ok"
        else:
            observation_status = "disabled"

        return {
            # Previously hardcoded "ok" regardless of what actually
            # happened -- an "error"/"no_data" cloudwatch_status was
            # always masked by a status:"ok" wrapper one level up.
            "status": observation_status,
            "period": {
                "start": start.isoformat(),
                "end": end.isoformat(),
                "duration_seconds": (end - start).total_seconds(),
            },
            "cloudwatch": {
                "status": observation_status,
                "namespace": cloudwatch_namespace,
                "metrics": metrics,
                "agent_enabled": agent_enabled,
                "activity": activity,
            },
            "cloudtrail": cloudtrail,
            "data_quality": data_quality,
        }

    # METRIC MERGING

    @classmethod
    def _merge_metrics(
        cls,
        target: Dict[str, Dict[str, Any]],
        results: Any,
    ) -> None:
        """
        Normalize CloudWatch collector output into:

            {
                "cpu_utilization": {...},
                "network_in": {...}
            }

        The raw metric result is preserved.
        """

        if not isinstance(
            results,
            list,
        ):
            return

        for metric in results:

            if not isinstance(
                metric,
                dict,
            ):
                continue

            key = (
                metric.get("metric_key")
                or metric.get("key")
                or metric.get("metric_name")
            )

            if not key:
                continue

            target[str(key)] = metric

    # EBS

    def _collect_volumes(
        self,
        resource: dict,
    ) -> List[Dict[str, Any]]:
        """
        Resolve attached EBS volume IDs to volume configuration.
        """

        attachment_by_volume: Dict[
            str,
            Dict[str, Any],
        ] = {}

        volume_ids: List[str] = []

        mappings = (
            resource.get(
                "BlockDeviceMappings",
                [],
            )
            or []
        )

        for mapping in mappings:

            if not isinstance(
                mapping,
                dict,
            ):
                continue

            ebs = mapping.get("Ebs")

            if not isinstance(
                ebs,
                dict,
            ):
                continue

            volume_id = ebs.get("VolumeId")

            if not volume_id:
                continue

            volume_id = str(volume_id)

            volume_ids.append(volume_id)

            attachment_by_volume[volume_id] = {
                "device": mapping.get("DeviceName"),
                "delete_on_termination": (ebs.get("DeleteOnTermination")),
                "status": ebs.get("Status"),
            }

        if not volume_ids:
            return []

        unique_ids = list(dict.fromkeys(volume_ids))

        result: List[Dict[str, Any]] = []

        for chunk in self._chunks(
            unique_ids,
            200,
        ):

            try:

                response = self.ec2.describe_volumes(VolumeIds=chunk)

            except Exception as exc:

                result.append(
                    {
                        "status": "error",
                        "volume_ids": chunk,
                        "error": str(exc),
                    }
                )

                continue

            for volume in response.get(
                "Volumes",
                [],
            ):

                if not isinstance(
                    volume,
                    dict,
                ):
                    continue

                volume_id = volume.get("VolumeId")

                if not volume_id:
                    continue

                result.append(
                    {
                        "volume_id": volume_id,
                        "size_gib": volume.get("Size"),
                        "volume_type": volume.get("VolumeType"),
                        "iops": volume.get("Iops"),
                        "throughput_mibps": (volume.get("Throughput")),
                        "state": volume.get("State"),
                        "encrypted": volume.get("Encrypted"),
                        "availability_zone": (volume.get("AvailabilityZone")),
                        "create_time": self._iso(volume.get("CreateTime")),
                        "attachment": (
                            attachment_by_volume.get(
                                volume_id,
                                {},
                            )
                        ),
                    }
                )

        return result

    # AUTO SCALING

    def _find_autoscaling_group(
        self,
        instance_id: str | None,
    ) -> Dict[str, Any]:

        if not instance_id:
            return {"managed": False}

        try:

            response = self.autoscaling.describe_auto_scaling_instances(
                InstanceIds=[instance_id]
            )

        except Exception as exc:

            return {
                "status": "error",
                "managed": False,
                "error": str(exc),
            }

        rows = response.get(
            "AutoScalingInstances",
            [],
        )

        if not rows:
            return {"managed": False}

        item = rows[0]

        asg_name = item.get("AutoScalingGroupName")

        if not asg_name:
            return {"managed": False}

        result: Dict[str, Any] = {
            "managed": True,
            "autoscaling_group_name": (asg_name),
            "launch_configuration_name": (item.get("LaunchConfigurationName")),
            "launch_template": item.get("LaunchTemplate"),
        }

        try:

            group_response = self.autoscaling.describe_auto_scaling_groups(
                AutoScalingGroupNames=[asg_name]
            )

            groups = group_response.get(
                "AutoScalingGroups",
                [],
            )

            if groups:

                group = groups[0]

                result.update(
                    {
                        "min_size": group.get("MinSize"),
                        "max_size": group.get("MaxSize"),
                        "desired_capacity": group.get("DesiredCapacity"),
                    }
                )

        except Exception as exc:

            result["group_error"] = str(exc)

        return result

    # CLOUDTRAIL

    def _collect_historical_events(
        self,
        instance_id: str,
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:

        try:

            event_names = self._cloudtrail_event_names()

            cloudtrail = get_client(
                "cloudtrail",
                self.region,
            )

            events: List[Dict[str, Any]] = []

            next_token: Optional[str] = None

            while True:

                kwargs: Dict[
                    str,
                    Any,
                ] = {
                    "LookupAttributes": [
                        {
                            "AttributeKey": ("ResourceName"),
                            "AttributeValue": (instance_id),
                        }
                    ],
                    "StartTime": start,
                    "EndTime": end,
                    "MaxResults": 50,
                }

                if next_token:
                    kwargs["NextToken"] = next_token

                response = cloudtrail.lookup_events(**kwargs)

                for event in response.get(
                    "Events",
                    [],
                ):

                    if not isinstance(
                        event,
                        dict,
                    ):
                        continue

                    event_name = event.get("EventName")

                    if event_names and event_name not in event_names:
                        continue

                    events.append(
                        {
                            "event_name": event_name,
                            "event_time": self._iso(event.get("EventTime")),
                            "username": event.get("Username"),
                            "event_id": event.get("EventId"),
                        }
                    )

                next_token = response.get("NextToken")

                if not next_token:
                    break

            return {
                "status": "ok",
                "event_count": len(events),
                "events": events,
            }

        except Exception as exc:

            return {
                "status": "error",
                "event_count": 0,
                "events": [],
                "error": str(exc),
            }

    def _cloudtrail_event_names(
        self,
    ) -> set[str]:

        config = self._cloudtrail_config()

        # "events" is the collection-profile's actual key (see
        # collection_profiles.yaml's ec2_instance.observations.cloudtrail).
        # "event_names" is kept as a fallback for any older profile still
        # using the previous name.
        configured = config.get("events")

        if not isinstance(configured, list):
            configured = config.get("event_names")

        if not isinstance(
            configured,
            list,
        ):
            return set(self.DEFAULT_CLOUDTRAIL_EVENTS)

        return {str(value) for value in configured if value}

    # ACTIVITY

    @classmethod
    def _build_activity_summary(
        cls,
        metrics: Dict[str, Any],
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:
        """
        Build raw activity evidence.

        IMPORTANT:
        Missing metrics are represented by None.
        Missing data is never interpreted as zero.

        Network and EBS calculations assume that the CloudWatch collector
        returns the requested Sum over the observation interval.
        """

        duration = max(
            (end - start).total_seconds(),
            1.0,
        )

        network_in = cls._metric_value(
            metrics,
            "network_in",
        )

        network_out = cls._metric_value(
            metrics,
            "network_out",
        )

        ebs_read = cls._metric_value(
            metrics,
            "ebs_read_ops",
        )

        ebs_write = cls._metric_value(
            metrics,
            "ebs_write_ops",
        )

        cpu_average = cls._metric_value(
            metrics,
            "cpu_utilization",
        )

        cpu_max = cls._metric_value(
            metrics,
            "cpu_utilization_max",
        )

        memory_average = cls._metric_value(
            metrics,
            "mem_used_percent",
        )

        memory_max = cls._metric_value(
            metrics,
            "mem_used_percent_max",
        )

        network_bytes = None

        if network_in is not None and network_out is not None:
            network_bytes = network_in + network_out

        network_bps = None

        if network_bytes is not None:
            network_bps = network_bytes / duration

        ebs_operations = None

        if ebs_read is not None and ebs_write is not None:
            ebs_operations = ebs_read + ebs_write

        ebs_iops = None

        if ebs_operations is not None:
            ebs_iops = ebs_operations / duration

        return {
            "cpu_utilization_percent": (cpu_average),
            "cpu_utilization_max_percent": (cpu_max),
            "memory_utilization_percent": (memory_average),
            "memory_utilization_max_percent": (memory_max),
            "network_in_bytes": (network_in),
            "network_out_bytes": (network_out),
            "network_total_bytes": (network_bytes),
            "average_network_bytes_per_second": (network_bps),
            "ebs_read_operations": (ebs_read),
            "ebs_write_operations": (ebs_write),
            "ebs_total_operations": (ebs_operations),
            "ebs_iops": (ebs_iops),
            "traffic_observed": (network_bytes is not None and network_bytes > 0),
            "storage_activity_observed": (
                ebs_operations is not None and ebs_operations > 0
            ),
        }

    # HELPERS

    @staticmethod
    def _normalize_metric_specs(
        specs: Any,
    ) -> List[Dict[str, Any]]:
        """
        Normalize the collection-profile metric definition.

        Profile format (see collection_profiles.yaml's
        ec2_instance.observations.cloudwatch.metrics):

            metrics:
              CPUUtilization:
                statistics:
                  - Average
                  - Maximum
                unit: Percent
                output:
                  Average: cpu_utilization
                  Maximum: cpu_utilization_max

        This is a dict keyed by CloudWatch metric name, not a list --
        one metric can request several statistics, each of which
        CloudWatchMetricCollector needs as its own specification, so:

            CPUUtilization + Average
            CPUUtilization + Maximum

        become two normalized specs here.
        """

        if not isinstance(specs, dict):
            return []

        result: List[Dict[str, Any]] = []

        for metric_name, config in specs.items():

            if not isinstance(config, dict):
                continue

            metric_name = str(metric_name)

            statistics = config.get("statistics")

            if isinstance(statistics, str):
                statistics = [statistics]

            if not isinstance(statistics, list):
                statistics = ["Average"]

            unit = config.get("unit")

            output = config.get("output")

            if not isinstance(output, dict):
                output = {}

            for statistic in statistics:

                if not statistic:
                    continue

                statistic = str(statistic)

                key = output.get(statistic)

                if not key:
                    key = f"{metric_name}_{statistic}".lower()

                result.append(
                    {
                        "name": metric_name,
                        "metric_name": metric_name,
                        "statistic": statistic,
                        "unit": unit,
                        "key": str(key),
                    }
                )

        return result

    @staticmethod
    def _state_name(
        resource: dict,
    ) -> str | None:

        state = resource.get("State")

        if isinstance(
            state,
            dict,
        ):

            value = state.get("Name")

            return str(value) if value is not None else None

        return None

    @staticmethod
    def _safe_dict(
        value: Any,
    ) -> Dict[str, Any]:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _tags(
        tags: Any,
    ) -> Dict[str, str]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        result: Dict[
            str,
            str,
        ] = {}

        for tag in tags:

            if not isinstance(
                tag,
                dict,
            ):
                continue

            key = tag.get("Key")

            if not key:
                continue

            result[str(key)] = str(tag.get("Value") or "")

        return result

    @staticmethod
    def _iso(
        value: Any,
    ) -> str | None:

        if value is None:
            return None

        if isinstance(
            value,
            datetime,
        ):
            return value.isoformat()

        return str(value)

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
    def _normalize_block_device_mappings(
        mappings: Any,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        if not isinstance(
            mappings,
            list,
        ):
            return result

        for mapping in mappings:

            if not isinstance(
                mapping,
                dict,
            ):
                continue

            ebs = mapping.get("Ebs") or {}

            if not isinstance(
                ebs,
                dict,
            ):
                ebs = {}

            result.append(
                {
                    "device_name": (mapping.get("DeviceName")),
                    "volume_id": (ebs.get("VolumeId")),
                    "delete_on_termination": (ebs.get("DeleteOnTermination")),
                    "status": (ebs.get("Status")),
                }
            )

        return result

    @staticmethod
    def _collect_ipv6_addresses(
        network_interfaces: Any,
    ) -> List[str]:

        addresses: List[str] = []

        if not isinstance(
            network_interfaces,
            list,
        ):
            return addresses

        for interface in network_interfaces:

            if not isinstance(
                interface,
                dict,
            ):
                continue

            ipv6s = interface.get(
                "Ipv6Addresses",
                [],
            )

            if not isinstance(
                ipv6s,
                list,
            ):
                continue

            for item in ipv6s:

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                address = item.get("Ipv6Address")

                if address:
                    addresses.append(str(address))

        return list(dict.fromkeys(addresses))

    @staticmethod
    def _capacity_reservation_id(
        resource: dict,
    ) -> str | None:

        specification = resource.get("CapacityReservationSpecification") or {}

        if not isinstance(
            specification,
            dict,
        ):
            return None

        capacity_reservation_id = specification.get("CapacityReservationId")

        if capacity_reservation_id:
            return str(capacity_reservation_id)

        return None

    @staticmethod
    def _metric_ok(
        metric: Any,
    ) -> bool:

        if not isinstance(
            metric,
            dict,
        ):
            return False

        if metric.get("status") != "ok":
            return False

        if metric.get("has_data") is not True:
            return False

        value = metric.get("value")

        return isinstance(
            value,
            (int, float),
        )

    @classmethod
    def _metric_value(
        cls,
        metrics: Dict[str, Any],
        name: str,
    ) -> float | None:

        metric = metrics.get(name)

        if not cls._metric_ok(metric):
            return None

        try:
            return float(metric["value"])
        except (
            TypeError,
            ValueError,
        ):
            return None
