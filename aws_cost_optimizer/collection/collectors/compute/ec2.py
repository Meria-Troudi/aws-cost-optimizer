"""
EC2 instance collector.

Collection responsibilities:

    discovery
        -> identity
        -> configuration
        -> relationships
        -> observations (CloudWatch + optional CloudWatch Agent + CloudTrail)
        -> topology
        -> optimization evidence

Important:

    Cost Explorer billing is NOT treated as an EC2-instance cost here.
    The planner may attach a collection-plan billing context (service,
    usage_type, amount) to each resource's cost_context, but that
    amount can belong to multiple EC2 instances. Whether it may be
    claimed as THIS instance's own cost is decided later, once, by
    analysis/reconciliation.py -- never by this collector or by the
    analyzer that reads it.

    EC2 is also collected as a baseline resource (see
    collection/baseline.py): a scan may collect EC2 instances with no
    billing context at all when EC2 isn't currently a Cost Explorer
    driver. context.billing() legitimately returns {} in that case.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from collection.base import BaseCollector
from collection.metrics.cloudwatch import CloudWatchMetricCollector
from collection.registry import register
from collection.shared.interfaces import NetworkInterfaceCollector
from collection.shared.topology import NetworkTopologyCollector
from aws_cost_optimizer.config.client import get_client


@register
class EC2Collector(BaseCollector):

    key = "ec2"
    resource_type = "ec2_instance"

    DEFAULT_METRICS = [
        {"name": "CPUUtilization", "statistic": "Average", "unit": "Percent", "key": "CPUUtilization"},
        {"name": "CPUUtilization", "statistic": "Maximum", "unit": "Percent", "key": "CPUUtilization_max"},
        {"name": "NetworkIn", "statistic": "Sum", "unit": "Bytes", "key": "NetworkIn"},
        {"name": "NetworkOut", "statistic": "Sum", "unit": "Bytes", "key": "NetworkOut"},
        {"name": "EBSReadOps", "statistic": "Sum", "unit": "Count", "key": "EBSReadOps"},
        {"name": "EBSWriteOps", "statistic": "Sum", "unit": "Count", "key": "EBSWriteOps"},
        {"name": "StatusCheckFailed", "statistic": "Maximum", "unit": "Count", "key": "StatusCheckFailed"},
        {"name": "StatusCheckFailed_Instance", "statistic": "Maximum", "unit": "Count", "key": "StatusCheckFailed_Instance"},
        {"name": "StatusCheckFailed_System", "statistic": "Maximum", "unit": "Count", "key": "StatusCheckFailed_System"},
    ]

    DEFAULT_AGENT_METRICS = [
        {"name": "mem_used_percent", "statistic": "Average", "unit": "Percent", "key": "mem_used_percent"},
        {"name": "mem_used_percent", "statistic": "Maximum", "unit": "Percent", "key": "mem_used_percent_max"},
        {"name": "mem_available_percent", "statistic": "Average", "unit": "Percent", "key": "mem_available_percent"},
    ]

    DEFAULT_CLOUDWATCH_PERIOD = 3600

    DEFAULT_CLOUDTRAIL_EVENTS = (
        "RunInstances",
        "StartInstances",
        "StopInstances",
        "TerminateInstances",
        "ModifyInstanceAttribute",
        "ModifyInstanceCreditSpecification",
    )

    def __init__(
        self,
        scan,
        region: str | None = None,
        profile: Dict[str, Any] | None = None,
    ):
        super().__init__(scan, region=region, profile=profile)

        if not self.region:
            raise ValueError("EC2Collector requires a region.")

        self.ec2 = get_client("ec2", self.region)
        self.cloudwatch = get_client("cloudwatch", self.region)
        self.autoscaling = get_client("autoscaling", self.region)

        self.cloudwatch_collector = CloudWatchMetricCollector(self.cloudwatch)
        self._eni_collector = NetworkInterfaceCollector(self.region)
        self._topology_collector = NetworkTopologyCollector(self.region)

    # ------------------------------------------------------------------
    # DISCOVERY
    # ------------------------------------------------------------------

    def discover(self) -> list:
        result: List[Dict[str, Any]] = []

        paginator = self.ec2.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):

                    if not isinstance(instance, dict):
                        continue

                    if not instance.get("InstanceId"):
                        continue

                    result.append(instance)

        return result

    def get_resource_id(self, resource: dict) -> str:
        return str(resource.get("InstanceId") or "")

    # ------------------------------------------------------------------
    # IDENTITY
    # ------------------------------------------------------------------

    def collect_identity(self, resource: dict) -> dict:

        tags = self._tags(resource.get("Tags", []))
        name = tags.get("Name") or resource.get("InstanceId")
        placement = resource.get("Placement") or {}

        return {
            "instance_id": resource.get("InstanceId"),
            "name": name,
            "instance_type": resource.get("InstanceType"),
            "state": self._state_name(resource),
            "instance_lifecycle": resource.get("InstanceLifecycle"),
            "architecture": resource.get("Architecture"),
            "platform": resource.get("Platform"),
            "platform_details": resource.get("PlatformDetails"),
            "availability_zone": placement.get("AvailabilityZone"),
            "tenancy": placement.get("Tenancy"),
            "tags": tags,
        }

    # ------------------------------------------------------------------
    # CONFIGURATION
    # ------------------------------------------------------------------

    def collect_configuration(self, resource: dict) -> dict:

        placement = resource.get("Placement") or {}
        monitoring = resource.get("Monitoring") or {}
        network_interfaces = resource.get("NetworkInterfaces", []) or []

        security_group_ids = [
            str(group.get("GroupId"))
            for group in (resource.get("SecurityGroups", []) or [])
            if isinstance(group, dict) and group.get("GroupId")
        ]

        return {
            "instance_id": resource.get("InstanceId"),
            "instance_type": resource.get("InstanceType"),
            "state": self._state_name(resource),
            "state_code": (resource.get("State") or {}).get("Code"),
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
            "security_group_ids": security_group_ids,
            "security_group_count": len(security_group_ids),
            "network_interface_count": len(network_interfaces),
            "iam_instance_profile": (resource.get("IamInstanceProfile") or {}).get("Arn"),
            "key_name": resource.get("KeyName"),
            "root_device": {
                "device_name": resource.get("RootDeviceName"),
                "device_type": resource.get("RootDeviceType"),
            },
            "block_device_mappings": self._normalize_block_device_mappings(
                resource.get("BlockDeviceMappings", [])
            ),
            "source_dest_check": resource.get("SourceDestCheck"),
            "hibernation_options": resource.get("HibernationOptions"),
            "cpu_options": resource.get("CpuOptions"),
            "placement_group_name": resource.get("PlacementGroupName"),
        }

    # ------------------------------------------------------------------
    # RELATIONSHIPS
    # ------------------------------------------------------------------

    def collect_relationships(self, resource: dict) -> dict:

        instance_id = resource.get("InstanceId")
        vpc_id = resource.get("VpcId")
        subnet_id = resource.get("SubnetId")

        interface_ids = [
            str(interface.get("NetworkInterfaceId"))
            for interface in (resource.get("NetworkInterfaces", []) or [])
            if isinstance(interface, dict) and interface.get("NetworkInterfaceId")
        ]

        volumes = self._collect_volumes(resource)
        asg = self._find_autoscaling_group(instance_id)

        network_interfaces = (
            self._eni_collector.collect(interface_ids)
            if interface_ids
            else {"status": "empty", "interfaces": [], "count": 0}
        )

        return {
            "summary": {
                "network_interface_count": len(interface_ids),
                "ebs_volume_count": len(volumes),
                "security_group_count": len(resource.get("SecurityGroups", []) or []),
                "autoscaling_group_count": 1 if asg.get("autoscaling_group_name") else 0,
            },
            "network_interfaces": network_interfaces.get("interfaces", []),
            "ebs_volumes": volumes,
            "autoscaling": asg,
            "subnet": {"subnet_id": subnet_id, "vpc_id": vpc_id},
            "security_groups": [
                {"group_id": group.get("GroupId"), "group_name": group.get("GroupName")}
                for group in (resource.get("SecurityGroups", []) or [])
                if isinstance(group, dict)
            ],
        }

    # ------------------------------------------------------------------
    # OBSERVATIONS (CloudWatch + optional CloudWatch Agent + CloudTrail)
    # ------------------------------------------------------------------

    def collect_observations(self, resource: dict) -> dict:

        instance_id = resource.get("InstanceId")

        if not instance_id:
            return {"status": "error", "error": "EC2 instance ID is missing."}

        try:
            start, end = self.get_analysis_period()
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

        observation_config = self.profile.get("observations", {})
        if not isinstance(observation_config, dict):
            observation_config = {}

        cloudwatch_config = observation_config.get("cloudwatch", {})
        if not isinstance(cloudwatch_config, dict):
            cloudwatch_config = {}

        period = cloudwatch_config.get("period") or self.DEFAULT_CLOUDWATCH_PERIOD

        metric_specs = cloudwatch_config.get("metrics")
        if not isinstance(metric_specs, list) or not metric_specs:
            metric_specs = self.DEFAULT_METRICS

        dimensions = [{"Name": "InstanceId", "Value": str(instance_id)}]

        metric_results = self.cloudwatch_collector.collect(
            namespace="AWS/EC2",
            dimensions=dimensions,
            metric_specs=self._normalize_metric_specs(metric_specs),
            start=start,
            end=end,
            requested_period=int(period),
        )

        metrics = {}
        for metric in metric_results:
            key = metric.get("metric_key") or metric.get("metric_name")
            if key:
                metrics[str(key)] = metric

        # Optional CloudWatch Agent evidence (guest memory). These are
        # custom metrics, not standard EC2 metrics -- absence must
        # legitimately mean "unavailable", never a fabricated value.
        agent_config = observation_config.get("cloudwatch_agent", {})
        if not isinstance(agent_config, dict):
            agent_config = {}

        agent_enabled = agent_config.get("enabled", False) is True

        if agent_enabled:

            agent_specs = agent_config.get("metrics")
            if not isinstance(agent_specs, list) or not agent_specs:
                agent_specs = self.DEFAULT_AGENT_METRICS

            agent_results = self.cloudwatch_collector.collect(
                namespace="CWAgent",
                dimensions=dimensions,
                metric_specs=self._normalize_metric_specs(agent_specs),
                start=start,
                end=end,
                requested_period=int(agent_config.get("period") or period),
            )

            for metric in agent_results:
                key = metric.get("metric_key") or metric.get("metric_name")
                if key:
                    metrics[str(key)] = metric

        cloudwatch_status = "ok" if metrics else "no_data"

        # CloudTrail: BaseCollector has no dedicated historical stage,
        # so this rides inside observations, gated by profile config.
        cloudtrail_config = self.profile.get("cloudtrail", {})
        cloudtrail = {}

        if isinstance(cloudtrail_config, dict) and cloudtrail_config.get("enabled", False) is True:
            cloudtrail = self._collect_historical_events(str(instance_id), start, end)

        memory_available = any(
            self._metric_ok(metrics.get(name))
            for name in ("mem_used_percent", "mem_available_percent")
        )

        return {
            "status": "ok",
            "period": {
                "start": start.isoformat(),
                "end": end.isoformat(),
                "duration_seconds": (end - start).total_seconds(),
            },
            "cloudwatch": {
                "status": cloudwatch_status,
                "namespace": "AWS/EC2",
                "metrics": metrics,
                "agent_enabled": agent_enabled,
                "activity": self._build_activity_summary(metrics, start, end),
            },
            "cloudtrail": cloudtrail,
            "data_quality": {
                "standard_ec2_metrics_available": any(
                    self._metric_ok(metrics.get(name))
                    for name in ("CPUUtilization", "NetworkIn", "NetworkOut")
                ),
                "memory_metrics_requested": agent_enabled,
                "memory_metrics_available": memory_available,
            },
        }

    # ------------------------------------------------------------------
    # TOPOLOGY
    # ------------------------------------------------------------------

    def collect_topology(self, resource: dict, collected_resource: dict) -> dict:

        vpc_id = resource.get("VpcId")
        instance_id = resource.get("InstanceId")

        if not vpc_id:
            return {"status": "incomplete", "reason": "EC2 instance is not associated with a VPC."}

        topology = self._topology_collector.collect(
            vpc_id=vpc_id,
            resource_type="ec2_instance",
            resource_id=instance_id,
        )

        if not isinstance(topology, dict):
            return {"status": "incomplete"}

        return topology

    # ------------------------------------------------------------------
    # OPTIMIZATION EVIDENCE
    # ------------------------------------------------------------------

    def build_optimization_evidence(self, resource: dict, collected_resource: dict) -> dict:

        configuration = self._safe_dict(collected_resource.get("configuration"))
        relationships = self._safe_dict(collected_resource.get("relationships"))
        observations = self._safe_dict(collected_resource.get("observations"))
        cloudwatch = self._safe_dict(observations.get("cloudwatch"))
        metrics = self._safe_dict(cloudwatch.get("metrics"))
        identity = self._safe_dict(collected_resource.get("identity"))
        tags = self._safe_dict(identity.get("tags"))
        asg = self._safe_dict(relationships.get("autoscaling"))

        return {
            "workload": {
                "instance_type": configuration.get("instance_type"),
                "architecture": configuration.get("architecture"),
                "platform": configuration.get("platform"),
                "state": configuration.get("state"),
                "instance_lifecycle": identity.get("instance_lifecycle"),
            },
            "activity": {
                "cpu_average": self._metric_value(metrics, "CPUUtilization"),
                "cpu_maximum": self._metric_value(metrics, "CPUUtilization_max"),
                "network_in_bytes": self._metric_value(metrics, "NetworkIn"),
                "network_out_bytes": self._metric_value(metrics, "NetworkOut"),
                "ebs_read_ops": self._metric_value(metrics, "EBSReadOps"),
                "ebs_write_ops": self._metric_value(metrics, "EBSWriteOps"),
                "memory_average_percent": self._metric_value(metrics, "mem_used_percent"),
            },
            "capacity": {
                "ebs_volume_count": len(relationships.get("ebs_volumes", []) or []),
                "network_interface_count": len(relationships.get("network_interfaces", []) or []),
                "autoscaling_managed": bool(asg.get("autoscaling_group_name")),
            },
            "classification": {
                "environment": self._classify_environment(tags),
                "workload_type": self._classify_workload(tags),
            },
            "data_quality": {
                "cloudwatch_available": bool(metrics),
                "memory_available": any(
                    self._metric_ok(metrics.get(name))
                    for name in ("mem_used_percent", "mem_available_percent")
                ),
            },
        }

    # ------------------------------------------------------------------
    # EBS
    # ------------------------------------------------------------------

    def _collect_volumes(self, resource: dict) -> List[Dict[str, Any]]:

        attachment_by_volume: Dict[str, Dict[str, Any]] = {}
        volume_ids: List[str] = []

        for mapping in resource.get("BlockDeviceMappings", []) or []:

            if not isinstance(mapping, dict):
                continue

            ebs = mapping.get("Ebs")
            if not isinstance(ebs, dict):
                continue

            volume_id = ebs.get("VolumeId")
            if not volume_id:
                continue

            volume_id = str(volume_id)
            volume_ids.append(volume_id)

            attachment_by_volume[volume_id] = {
                "device": mapping.get("DeviceName"),
                "delete_on_termination": ebs.get("DeleteOnTermination"),
                "status": ebs.get("Status"),
            }

        if not volume_ids:
            return []

        unique_ids = list(dict.fromkeys(volume_ids))
        result: List[Dict[str, Any]] = []

        for chunk in self._chunks(unique_ids, 200):

            try:
                response = self.ec2.describe_volumes(VolumeIds=chunk)
            except Exception as exc:
                result.append({"status": "error", "volume_ids": chunk, "error": str(exc)})
                continue

            for volume in response.get("Volumes", []):

                if not isinstance(volume, dict):
                    continue

                volume_id = volume.get("VolumeId")
                if not volume_id:
                    continue

                result.append({
                    "volume_id": volume_id,
                    "size_gib": volume.get("Size"),
                    "volume_type": volume.get("VolumeType"),
                    "iops": volume.get("Iops"),
                    "throughput_mibps": volume.get("Throughput"),
                    "state": volume.get("State"),
                    "encrypted": volume.get("Encrypted"),
                    "availability_zone": volume.get("AvailabilityZone"),
                    "create_time": self._iso(volume.get("CreateTime")),
                    "attachment": attachment_by_volume.get(volume_id, {}),
                })

        return result

    # ------------------------------------------------------------------
    # AUTO SCALING
    # ------------------------------------------------------------------

    def _find_autoscaling_group(self, instance_id: str | None) -> Dict[str, Any]:

        if not instance_id:
            return {}

        try:
            response = self.autoscaling.describe_auto_scaling_instances(
                InstanceIds=[instance_id]
            )
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

        rows = response.get("AutoScalingInstances", [])
        if not rows:
            return {"managed": False}

        item = rows[0]
        asg_name = item.get("AutoScalingGroupName")

        if not asg_name:
            return {"managed": False}

        result: Dict[str, Any] = {
            "managed": True,
            "autoscaling_group_name": asg_name,
            "launch_configuration_name": item.get("LaunchConfigurationName"),
            "launch_template": item.get("LaunchTemplate"),
        }

        try:
            group_response = self.autoscaling.describe_auto_scaling_groups(
                AutoScalingGroupNames=[asg_name]
            )
            groups = group_response.get("AutoScalingGroups", [])

            if groups:
                group = groups[0]
                result.update({
                    "min_size": group.get("MinSize"),
                    "max_size": group.get("MaxSize"),
                    "desired_capacity": group.get("DesiredCapacity"),
                })

        except Exception as exc:
            result["group_error"] = str(exc)

        return result

    # ------------------------------------------------------------------
    # CLOUDTRAIL
    # ------------------------------------------------------------------

    def _collect_historical_events(
        self,
        instance_id: str,
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:

        try:
            event_names = self._cloudtrail_event_names()
            cloudtrail = get_client("cloudtrail", self.region)

            events: List[Dict[str, Any]] = []
            next_token: Optional[str] = None

            while True:

                kwargs: Dict[str, Any] = {
                    "LookupAttributes": [
                        {"AttributeKey": "ResourceName", "AttributeValue": instance_id}
                    ],
                    "StartTime": start,
                    "EndTime": end,
                    "MaxResults": 50,
                }

                if next_token:
                    kwargs["NextToken"] = next_token

                response = cloudtrail.lookup_events(**kwargs)

                for event in response.get("Events", []):

                    if not isinstance(event, dict):
                        continue

                    event_name = event.get("EventName")

                    if event_names and event_name not in event_names:
                        continue

                    events.append({
                        "event_name": event_name,
                        "event_time": self._iso(event.get("EventTime")),
                        "username": event.get("Username"),
                        "event_id": event.get("EventId"),
                    })

                next_token = response.get("NextToken")
                if not next_token:
                    break

            return {"status": "ok", "event_count": len(events), "events": events}

        except Exception as exc:
            return {"status": "error", "event_count": 0, "events": [], "error": str(exc)}

    def _cloudtrail_event_names(self) -> set[str]:

        config = self.profile.get("cloudtrail", {})
        if not isinstance(config, dict):
            return set(self.DEFAULT_CLOUDTRAIL_EVENTS)

        configured = config.get("event_names")
        if not isinstance(configured, list):
            return set(self.DEFAULT_CLOUDTRAIL_EVENTS)

        return {str(value) for value in configured if value}

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _normalize_metric_specs(self, specs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        result = []
        for spec in specs:
            if not isinstance(spec, dict):
                continue
            item = dict(spec)
            item.setdefault("statistic", "Average")
            item.setdefault("key", item.get("name"))
            result.append(item)
        return result

    @staticmethod
    def _state_name(resource: dict) -> str | None:
        state = resource.get("State")
        return state.get("Name") if isinstance(state, dict) else None

    @staticmethod
    def _safe_dict(value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _tags(tags: Any) -> Dict[str, str]:
        if not isinstance(tags, list):
            return {}
        return {
            str(tag["Key"]): str(tag.get("Value") or "")
            for tag in tags
            if isinstance(tag, dict) and tag.get("Key")
        }

    @staticmethod
    def _iso(value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    @staticmethod
    def _chunks(values: List[str], size: int):
        for index in range(0, len(values), size):
            yield values[index:index + size]

    @staticmethod
    def _normalize_block_device_mappings(mappings: Any) -> List[Dict[str, Any]]:
        result = []
        for mapping in mappings or []:
            if not isinstance(mapping, dict):
                continue
            ebs = mapping.get("Ebs") or {}
            result.append({
                "device_name": mapping.get("DeviceName"),
                "volume_id": ebs.get("VolumeId"),
                "delete_on_termination": ebs.get("DeleteOnTermination"),
                "status": ebs.get("Status"),
            })
        return result

    @staticmethod
    def _metric_ok(metric: Any) -> bool:
        return (
            isinstance(metric, dict)
            and metric.get("status") == "ok"
            and metric.get("has_data") is True
            and isinstance(metric.get("value"), (int, float))
        )

    @classmethod
    def _metric_value(cls, metrics: Dict[str, Any], name: str) -> float | None:
        metric = metrics.get(name)
        if not cls._metric_ok(metric):
            return None
        return float(metric["value"])

    @classmethod
    def _build_activity_summary(cls, metrics: Dict[str, Any], start, end) -> Dict[str, Any]:

        duration = max((end - start).total_seconds(), 1.0)

        network_in = cls._metric_value(metrics, "NetworkIn")
        network_out = cls._metric_value(metrics, "NetworkOut")
        ebs_read = cls._metric_value(metrics, "EBSReadOps")
        ebs_write = cls._metric_value(metrics, "EBSWriteOps")

        return {
            "average_network_bytes_per_second": (
                (network_in + network_out) / duration
                if network_in is not None and network_out is not None
                else None
            ),
            "ebs_iops": (
                (ebs_read + ebs_write) / duration
                if ebs_read is not None and ebs_write is not None
                else None
            ),
            "traffic_observed": ((network_in or 0) + (network_out or 0)) > 0,
            "storage_activity_observed": ((ebs_read or 0) + (ebs_write or 0)) > 0,
        }

    @staticmethod
    def _classify_environment(tags: Dict[str, str]) -> str:
        values = " ".join(f"{k} {v}".lower() for k, v in tags.items())

        if any(m in values for m in ("prod", "production")):
            return "production"

        if any(m in values for m in ("dev", "development", "test", "testing", "qa", "stage", "staging")):
            return "non_production"

        return "unknown"

    @staticmethod
    def _classify_workload(tags: Dict[str, str]) -> str:
        values = " ".join(f"{k} {v}".lower() for k, v in tags.items())

        if any(m in values for m in ("batch", "worker", "ci", "cd", "cicd", "build", "etl", "ml")):
            return "batch_or_interruptible"

        if any(m in values for m in ("database", "db", "payment", "critical")):
            return "critical"

        return "unknown"
