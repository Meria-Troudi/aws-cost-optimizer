"""
Aurora DB-cluster collector.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from ...base import BaseCollector
from ...registry import register
from ...metrics.cloudwatch import CloudWatchMetricCollector
from ...shared.topology import NetworkTopologyCollector


@register
class AuroraClusterCollector(BaseCollector):

    key = "aurora_cluster"
    resource_type = "aurora_cluster"

    AURORA_ENGINES = {
        "aurora",
        "aurora-mysql",
        "aurora-postgresql",
    }

    READER_AUTOSCALING_NAMESPACE = "rds"
    READER_AUTOSCALING_DIMENSION = "rds:cluster:ReadReplicaCount"

    DEFAULT_CLUSTER_METRICS = (
        "CPUUtilization",
        "DatabaseConnections",
        "VolumeReadIOPs",
        "VolumeWriteIOPs",
        "VolumeBytesUsed",
    )

    DEFAULT_READER_METRICS = (
        "CPUUtilization",
        "DatabaseConnections",
        "NetworkReceiveThroughput",
        "NetworkTransmitThroughput",
    )

    DEFAULT_INSTANCE_METRICS = (
        "CPUUtilization",
        "DatabaseConnections",
        "NetworkReceiveThroughput",
        "NetworkTransmitThroughput",
        "ServerlessDatabaseCapacity",
        "ACUUtilization",
    )

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

        self.rds = get_client(
            "rds",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.application_autoscaling = get_client(
            "application-autoscaling",
            self.region,
        )

        self.cloudtrail = get_client(
            "cloudtrail",
            self.region,
        )

        self.metric_collector = CloudWatchMetricCollector(self.cloudwatch)

        self.topology_collector = NetworkTopologyCollector(self.region)

        self._cluster_metrics_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._role_metrics_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._member_metrics_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._autoscaling_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

        self._snapshot_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

        self._automated_backup_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

        self._cluster_events_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}
        self._subnet_group_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

    # PROFILE

    def _section(
        self,
        name: str,
    ) -> dict[str, Any]:

        value = self.profile.get(name, {}) if isinstance(self.profile, dict) else {}

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _enabled(
        section: dict[str, Any],
        default: bool = False,
    ) -> bool:

        if not isinstance(section, dict):
            return default

        return (
            section.get(
                "enabled",
                default,
            )
            is True
        )

    def _cloudwatch_profile(
        self,
    ) -> dict[str, Any]:

        value = self._section("observations").get(
            "cloudwatch",
            {},
        )

        return value if isinstance(value, dict) else {}

    def _autoscaling_profile(
        self,
    ) -> dict[str, Any]:

        value = self._section("relationships").get(
            "reader_autoscaling",
            {},
        )

        return value if isinstance(value, dict) else {}

    def _specs(
        self,
        name: str,
    ) -> list[dict[str, Any]]:

        value = self._cloudwatch_profile().get(
            name,
            [],
        )

        return value if isinstance(value, list) else []

    def _period(self) -> int:
        return self.cloudwatch_period()

    # DISCOVERY

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: list[Dict[str, Any]] = []

        try:
            paginator = self.rds.get_paginator("describe_db_clusters")

            for page in paginator.paginate():

                clusters = page.get(
                    "DBClusters",
                    [],
                )

                if not isinstance(
                    clusters,
                    list,
                ):
                    continue

                for cluster in clusters:

                    if not isinstance(
                        cluster,
                        dict,
                    ):
                        continue

                    engine = str(cluster.get("Engine") or "").lower()

                    if engine not in self.AURORA_ENGINES:
                        continue

                    cluster_id = cluster.get("DBClusterIdentifier")

                    if not cluster_id:
                        continue

                    resources.append(
                        {
                            "id": str(cluster_id),
                            "raw": cluster,
                        }
                    )

        except Exception:
            raise

        self._prefetch_subnet_groups(resources)

        self._prefetch_metrics(resources)

        self._prefetch_reader_autoscaling(resources)

        self._prefetch_backup_context(resources)

        self._prefetch_cluster_events(resources)

        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        value = resource.get("id")

        if not value:
            raise ValueError("Aurora DB cluster resource ID is missing.")

        return str(value)

    # IDENTITY

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = self._dict(resource.get("raw"))

        return {
            "name": raw.get("DBClusterIdentifier"),
            "db_cluster_identifier": raw.get("DBClusterIdentifier"),
            "db_cluster_arn": raw.get("DBClusterArn"),
            "engine": raw.get("Engine"),
            "engine_version": raw.get("EngineVersion"),
            "status": raw.get("Status"),
            "engine_mode": raw.get("EngineMode"),
            "created_at": self._isoformat(raw.get("ClusterCreateTime")),
            "tags": self._tags(raw.get("TagList", [])),
        }

    # CONFIGURATION

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = self._dict(resource.get("raw"))

        vpc_security_groups = [
            item.get("VpcSecurityGroupId")
            for item in (
                raw.get(
                    "VpcSecurityGroups",
                    [],
                )
                or []
            )
            if (isinstance(item, dict) and item.get("VpcSecurityGroupId"))
        ]

        scaling_v2 = self._dict(raw.get("ServerlessV2ScalingConfiguration"))

        scaling_v1 = self._dict(raw.get("ScalingConfigurationInfo"))

        # raw.get("DBSubnetGroup") is the subnet group's NAME, not an
        # object -- VpcId/subnets come from the prefetch cache, keyed
        # by that name.
        subnet_group_name = raw.get("DBSubnetGroup")

        subnet_group = self._subnet_group_cache.get(
            str(subnet_group_name),
            {},
        )

        return {
            "cluster": {
                "identifier": raw.get("DBClusterIdentifier"),
                "arn": raw.get("DBClusterArn"),
                "status": raw.get("Status"),
                "engine": raw.get("Engine"),
                "engine_version": raw.get("EngineVersion"),
                "engine_mode": raw.get("EngineMode"),
                "database_name": raw.get("DatabaseName"),
                "cluster_create_time": self._isoformat(raw.get("ClusterCreateTime")),
            },
            "storage": {
              
                "storage_type": (
                    str(raw.get("StorageType") or "").strip().lower()
                    if raw.get("StorageType")
                    else "aurora"
                ),
                "storage_type_source": (
                    "aws" if raw.get("StorageType") else "aws_default_aurora"
                ),
                "io_optimized": (
                    str(raw.get("StorageType") or "").strip().lower() == "aurora-iopt1"
                ),
              
                "api_allocated_storage_gib": raw.get("AllocatedStorage"),
                "storage_encrypted": raw.get("StorageEncrypted"),
                "storage_encryption_type": raw.get("StorageEncryptionType"),
                "kms_key_id": raw.get("KmsKeyId"),
                "io_optimized_next_allowed_modification_time": (
                    self._isoformat(raw.get("IOOptimizedNextAllowedModificationTime"))
                ),
            },
            "backup": {
                "backup_retention_days": raw.get("BackupRetentionPeriod"),
                "preferred_backup_window": raw.get("PreferredBackupWindow"),
                "copy_tags_to_snapshot": raw.get("CopyTagsToSnapshot"),
            },
            "availability": {
                "availability_zones": list(
                    raw.get(
                        "AvailabilityZones",
                        [],
                    )
                    or []
                ),
                "multi_az": raw.get("MultiAZ"),
            },
            "endpoints": {
                "writer": raw.get("Endpoint"),
                "reader": raw.get("ReaderEndpoint"),
                "custom": list(
                    raw.get(
                        "CustomEndpoints",
                        [],
                    )
                    or []
                ),
            },
            "network": {
                "vpc_id": subnet_group.get("vpc_id"),
                "vpc_security_group_ids": (vpc_security_groups),
                "db_subnet_group": (
                    subnet_group.get("db_subnet_group_name") or subnet_group_name
                ),
                "subnet_count": subnet_group.get(
                    "subnet_count",
                    0,
                ),
                "subnets": subnet_group.get(
                    "subnets",
                    [],
                ),
                "subnet_group_collection_status": subnet_group.get("status"),
            },
            "serverless_v2": {
                "enabled": bool(scaling_v2),
                "min_capacity": scaling_v2.get("MinCapacity"),
                "max_capacity": scaling_v2.get("MaxCapacity"),
                "seconds_until_auto_pause": (scaling_v2.get("SecondsUntilAutoPause")),
            },
            "serverless_v1": {
                "enabled": bool(scaling_v1),
                "min_capacity": scaling_v1.get("MinCapacity"),
                "max_capacity": scaling_v1.get("MaxCapacity"),
                "auto_pause": scaling_v1.get("AutoPause"),
                "seconds_until_auto_pause": (scaling_v1.get("SecondsUntilAutoPause")),
            },
            "deletion_protection": raw.get("DeletionProtection"),
            "iam_database_authentication_enabled": (
                raw.get("IAMDatabaseAuthenticationEnabled")
            ),
            "global_cluster_identifier": raw.get("GlobalClusterIdentifier"),
            "global_write_forwarding": raw.get("GlobalWriteForwardingStatus"),
            "backtrack_window": raw.get("BacktrackWindow"),
            "enabled_cloudwatch_logs_exports": list(
                raw.get(
                    "EnabledCloudwatchLogsExports",
                    [],
                )
                or []
            ),
            "db_cluster_parameter_group": raw.get("DBClusterParameterGroup"),
            "associated_roles": list(
                raw.get(
                    "AssociatedRoles",
                    [],
                )
                or []
            ),
        }

    # RELATIONSHIPS

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = self._dict(resource.get("raw"))

        members: list[dict[str, Any]] = []

        for member in (
            raw.get(
                "DBClusterMembers",
                [],
            )
            or []
        ):

            if not isinstance(
                member,
                dict,
            ):
                continue

            instance_id = member.get("DBInstanceIdentifier")

            if not instance_id:
                continue

            members.append(
                {
                    "db_instance_identifier": (str(instance_id)),
                    "is_writer": bool(member.get("IsClusterWriter")),
                    "promotion_tier": member.get("PromotionTier"),
                    "parameter_group_status": (
                        member.get("DBClusterParameterGroupStatus")
                    ),
                }
            )

        writers = [
            item["db_instance_identifier"] for item in members if item.get("is_writer")
        ]

        readers = [
            item["db_instance_identifier"]
            for item in members
            if not item.get("is_writer")
        ]

        cluster_id = resource.get("id")

        autoscaling = self._autoscaling_cache.get(
            str(cluster_id),
            {
                "status": "unknown",
                "configured": False,
                "scalable_target": None,
                "policies": [],
                "errors": [],
            },
        )

        return {
            "status": "ok",
            "members": members,
            "writer_instances": writers,
            "reader_instances": readers,
            "writer_count": len(writers),
            "reader_count": len(readers),
            "global_cluster_identifier": raw.get("GlobalClusterIdentifier"),
            "replication_source_identifier": raw.get("ReplicationSourceIdentifier"),
            "read_replica_identifiers": list(
                raw.get(
                    "ReadReplicaIdentifiers",
                    [],
                )
                or []
            ),
            "roles": list(
                raw.get(
                    "AssociatedRoles",
                    [],
                )
                or []
            ),
            "reader_autoscaling": autoscaling,
        }

    # READER AUTO SCALING

    def _prefetch_reader_autoscaling(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        self._autoscaling_cache = {}

        profile = self._autoscaling_profile()

        if (
            profile.get(
                "enabled",
                True,
            )
            is False
        ):
            return

        for resource in resources:

            cluster_id = resource.get("id")

            if not cluster_id:
                continue

            self._autoscaling_cache[str(cluster_id)] = self._collect_reader_autoscaling(
                str(cluster_id)
            )

    def _collect_reader_autoscaling(
        self,
        cluster_id: str,
    ) -> Dict[str, Any]:

        resource_id = f"cluster:{cluster_id}"

        result: Dict[str, Any] = {
            "status": "ok",
            "configured": False,
            "resource_id": resource_id,
            "service_namespace": (self.READER_AUTOSCALING_NAMESPACE),
            "scalable_dimension": (self.READER_AUTOSCALING_DIMENSION),
            "scalable_target": None,
            "policies": [],
            "policy_count": 0,
            "errors": [],
        }

        try:

            targets_response = self.application_autoscaling.describe_scalable_targets(
                ServiceNamespace=(self.READER_AUTOSCALING_NAMESPACE),
                ResourceIds=[resource_id],
                ScalableDimension=(self.READER_AUTOSCALING_DIMENSION),
            )

            targets = (
                targets_response.get(
                    "ScalableTargets",
                    [],
                )
                or []
            )

            if (
                isinstance(
                    targets,
                    list,
                )
                and targets
            ):

                target = targets[0]

                if isinstance(
                    target,
                    dict,
                ):
                    result["configured"] = True

                    result["scalable_target"] = {
                        "resource_id": target.get("ResourceId"),
                        "service_namespace": target.get("ServiceNamespace"),
                        "scalable_dimension": target.get("ScalableDimension"),
                        "min_capacity": target.get("MinCapacity"),
                        "max_capacity": target.get("MaxCapacity"),
                        "role_arn": target.get("RoleARN"),
                    }

            policies_response = self.application_autoscaling.describe_scaling_policies(
                ServiceNamespace=(self.READER_AUTOSCALING_NAMESPACE),
                ResourceId=resource_id,
                ScalableDimension=(self.READER_AUTOSCALING_DIMENSION),
            )

            policies = (
                policies_response.get(
                    "ScalingPolicies",
                    [],
                )
                or []
            )

            if isinstance(
                policies,
                list,
            ):

                for policy in policies:

                    if not isinstance(
                        policy,
                        dict,
                    ):
                        continue

                    configuration = (
                        policy.get("TargetTrackingScalingPolicyConfiguration") or {}
                    )

                    predefined = (
                        configuration.get("PredefinedMetricSpecification") or {}
                    )

                    result["policies"].append(
                        {
                            "policy_name": policy.get("PolicyName"),
                            "policy_type": policy.get("PolicyType"),
                            "status": policy.get("State") or policy.get("Status"),
                            "target_value": configuration.get("TargetValue"),
                            "predefined_metric_type": (
                                predefined.get("PredefinedMetricType")
                            ),
                            "disable_scale_in": (configuration.get("DisableScaleIn")),
                            "scheduled_actions": (policy.get("ScheduledActionARN")),
                        }
                    )

            result["policy_count"] = len(result["policies"])

        except Exception as exc:

            result["status"] = "error"

            result["errors"].append(
                {
                    "operation": ("application_autoscaling.describe"),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )

        return result

    # SUBNET GROUP

    def _prefetch_subnet_groups(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        self._subnet_group_cache = {}

        names: set[str] = set()

        for resource in resources:

            raw = self._dict(resource.get("raw"))

            subnet_group_name = raw.get("DBSubnetGroup")

            if subnet_group_name:
                names.add(str(subnet_group_name))

        for name in names:

            self._subnet_group_cache[name] = self._collect_db_subnet_group(name)

    def _collect_db_subnet_group(
        self,
        subnet_group_name: str,
    ) -> Dict[str, Any]:

        # DescribeDBClusters' DBSubnetGroup field is documented as the
        # subnet group's NAME (e.g. "default"), not the detailed
        # object -- VpcId/Subnets only come from a separate
        # DescribeDBSubnetGroups call.
        result: Dict[str, Any] = {
            "status": "ok",
            "db_subnet_group_name": subnet_group_name,
            "vpc_id": None,
            "subnet_count": 0,
            "subnets": [],
            "errors": [],
        }

        try:

            response = self.rds.describe_db_subnet_groups(
                DBSubnetGroupName=subnet_group_name
            )

            groups = response.get(
                "DBSubnetGroups",
                [],
            )

            if not isinstance(groups, list) or not groups:

                result["status"] = "not_found"

                result["errors"].append(
                    {
                        "operation": "describe_db_subnet_groups",
                        "error": (
                            "No DB subnet group was returned for "
                            f"{subnet_group_name!r}."
                        ),
                    }
                )

                return result

            group = groups[0]

            if not isinstance(group, dict):
                return result

            result["db_subnet_group_name"] = (
                group.get("DBSubnetGroupName") or subnet_group_name
            )

            result["vpc_id"] = group.get("VpcId")

            subnets = []

            for subnet in group.get("Subnets", []) or []:

                if not isinstance(subnet, dict):
                    continue

                subnets.append(
                    {
                        "subnet_identifier": subnet.get("SubnetIdentifier"),
                        "subnet_status": subnet.get("SubnetStatus"),
                        "availability_zone": self._dict(
                            subnet.get("SubnetAvailabilityZone")
                        ).get("Name"),
                    }
                )

            result["subnets"] = subnets

            result["subnet_count"] = len(subnets)

        except Exception as exc:

            result["status"] = "error"

            result["errors"].append(
                {
                    "operation": "describe_db_subnet_groups",
                    "error": str(exc),
                }
            )

        return result

    # BACKUP CONTEXT

    def _prefetch_backup_context(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        self._snapshot_cache = {}
        self._automated_backup_cache = {}

        for resource in resources:

            cluster_id = resource.get("id")

            if not cluster_id:
                continue

            cluster_id = str(cluster_id)

            self._snapshot_cache[cluster_id] = self._collect_cluster_snapshots(
                cluster_id
            )

            self._automated_backup_cache[cluster_id] = self._collect_automated_backups(
                cluster_id
            )

    def _collect_cluster_snapshots(
        self,
        cluster_id: str,
    ) -> Dict[str, Any]:

        result: Dict[str, Any] = {
            "status": "ok",
            "manual": [],
            "automated": [],
            "manual_count": 0,
            "automated_count": 0,
            "errors": [],
        }

        try:

            paginator = self.rds.get_paginator("describe_db_cluster_snapshots")

            for page in paginator.paginate(
                DBClusterIdentifier=cluster_id,
            ):

                for snapshot in (
                    page.get(
                        "DBClusterSnapshots",
                        [],
                    )
                    or []
                ):

                    if not isinstance(
                        snapshot,
                        dict,
                    ):
                        continue

                    snapshot_type = str(
                        snapshot.get(
                            "SnapshotType",
                            "",
                        )
                    ).lower()

                    item = {
                        "snapshot_identifier": (
                            snapshot.get("DBClusterSnapshotIdentifier")
                        ),
                        "snapshot_type": snapshot_type,
                        "status": snapshot.get("Status"),
                        "create_time": (
                            self._isoformat(snapshot.get("SnapshotCreateTime"))
                        ),
                        "allocated_storage": (snapshot.get("AllocatedStorage")),
                        "storage_encrypted": (snapshot.get("StorageEncrypted")),
                    }

                    if snapshot_type == "manual":
                        result["manual"].append(item)

                    elif snapshot_type == "automated":
                        result["automated"].append(item)

        except Exception as exc:

            result["status"] = "error"

            result["errors"].append(
                {
                    "operation": ("describe_db_cluster_snapshots"),
                    "error": str(exc),
                }
            )

        result["manual_count"] = len(result["manual"])

        result["automated_count"] = len(result["automated"])

        return result

    def _collect_automated_backups(
        self,
        cluster_id: str,
    ) -> Dict[str, Any]:

        result: Dict[str, Any] = {
            "status": "ok",
            "backup_count": 0,
            "backups": [],
            "errors": [],
        }

        try:

            paginator = self.rds.get_paginator("describe_db_cluster_automated_backups")

            for page in paginator.paginate(
                DBClusterIdentifier=cluster_id,
            ):

                for backup in (
                    page.get(
                        "DBClusterAutomatedBackups",
                        [],
                    )
                    or []
                ):

                    if not isinstance(
                        backup,
                        dict,
                    ):
                        continue

                    result["backups"].append(
                        {
                            "db_cluster_identifier": (
                                backup.get("DBClusterIdentifier")
                            ),
                            "db_cluster_resource_id": (
                                backup.get("DbClusterResourceId")
                            ),
                            "status": backup.get("Status"),
                            "backup_retention_period": (
                                backup.get("BackupRetentionPeriod")
                            ),
                            "earliest_restorable_time": (
                                self._isoformat(backup.get("EarliestRestorableTime"))
                            ),
                            "latest_restorable_time": (
                                self._isoformat(backup.get("LatestRestorableTime"))
                            ),
                            "allocated_storage": (backup.get("AllocatedStorage")),
                        }
                    )

        except Exception as exc:

            result["status"] = "error"

            result["errors"].append(
                {
                    "operation": ("describe_db_cluster_automated_backups"),
                    "error": str(exc),
                }
            )

        result["backup_count"] = len(result["backups"])

        return result

    # LIFECYCLE EVENTS

    def _prefetch_cluster_events(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        self._cluster_events_cache = {}

        try:

            start, end = self.get_analysis_period()

        except ValueError:

            return

        for resource in resources:

            cluster_id = resource.get("id")

            if not cluster_id:
                continue

            cluster_id = str(cluster_id)

            raw = self._dict(resource.get("raw"))

            cluster_arn = raw.get("DBClusterArn")

            self._cluster_events_cache[cluster_id] = self._collect_cluster_events(
                cluster_id,
                cluster_arn,
                start,
                end,
            )

    # CLOUDWATCH PREFETCH

    def _prefetch_metrics(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        self._cluster_metrics_cache = {}
        self._role_metrics_cache = {}
        self._member_metrics_cache = {}

        profile = self._cloudwatch_profile()

        if not self._enabled(
            profile,
            default=True,
        ):
            return

        cluster_specs = self._specs("cluster_metrics")

        reader_specs = self._specs("reader_metrics")

        instance_specs = self._specs("instance_metrics")

        # Backwards compatibility.
        if not reader_specs:
            reader_specs = self._specs("role_metrics")

        if not cluster_specs:
            cluster_specs = [
                {
                    "name": metric,
                    "statistic": "Average",
                }
                for metric in self.DEFAULT_CLUSTER_METRICS
            ]

        if not reader_specs:
            reader_specs = [
                {
                    "name": metric,
                    "statistic": "Average",
                }
                for metric in self.DEFAULT_READER_METRICS
            ]

        if not instance_specs:
            instance_specs = [
                {
                    "name": metric,
                    "statistic": "Average",
                }
                for metric in self.DEFAULT_INSTANCE_METRICS
            ]

        try:

            start, end = self.get_analysis_period()

        except ValueError:

            return

        namespace = str(profile.get("namespace") or self.cloudwatch_namespace())

        cluster_requests = []
        reader_requests = []
        instance_requests = []

        for resource in resources:

            cluster_id = resource.get("id")

            raw = self._dict(resource.get("raw"))

            if not cluster_id:
                continue

            cluster_requests.append(
                {
                    "resource_key": str(cluster_id),
                    "namespace": namespace,
                    "dimensions": [
                        {
                            "Name": ("DBClusterIdentifier"),
                            "Value": str(cluster_id),
                        }
                    ],
                    "metric_specs": cluster_specs,
                }
            )

            # Aurora Auto Scaling uses the Role=READER
            # dimension for cluster reader workload.
            reader_requests.append(
                {
                    "resource_key": (f"{cluster_id}:READER"),
                    "namespace": namespace,
                    "dimensions": [
                        {
                            "Name": ("DBClusterIdentifier"),
                            "Value": str(cluster_id),
                        },
                        {
                            "Name": "Role",
                            "Value": "READER",
                        },
                    ],
                    "metric_specs": reader_specs,
                }
            )

            for member in (
                raw.get(
                    "DBClusterMembers",
                    [],
                )
                or []
            ):

                if not isinstance(
                    member,
                    dict,
                ):
                    continue

                instance_id = member.get("DBInstanceIdentifier")

                if not instance_id:
                    continue

                instance_requests.append(
                    {
                        "resource_key": str(instance_id),
                        "namespace": namespace,
                        "dimensions": [
                            {
                                "Name": ("DBInstanceIdentifier"),
                                "Value": str(instance_id),
                            }
                        ],
                        "metric_specs": instance_specs,
                    }
                )

        if cluster_requests:

            self._cluster_metrics_cache = (
                self.metric_collector.collect_batch(
                    cluster_requests,
                    start=start,
                    end=end,
                    requested_period=self._period(),
                )
                or {}
            )

        if reader_requests:

            self._role_metrics_cache = (
                self.metric_collector.collect_batch(
                    reader_requests,
                    start=start,
                    end=end,
                    requested_period=self._period(),
                )
                or {}
            )

        if instance_requests:

            self._member_metrics_cache = (
                self.metric_collector.collect_batch(
                    instance_requests,
                    start=start,
                    end=end,
                    requested_period=self._period(),
                )
                or {}
            )

    # OBSERVATIONS

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        profile = self._cloudwatch_profile()

        if not self._enabled(
            profile,
            default=True,
        ):

            return {
                "status": "disabled",
                "cloudwatch": {
                    "status": "disabled",
                    "cluster": {
                        "metrics": {},
                    },
                    "reader": {
                        "metrics": {},
                    },
                    "instances": {},
                },
            }

        cluster_id = resource.get("id")

        if not cluster_id:
            return {"status": "incomplete"}

        try:

            start, end = self.get_analysis_period()

        except ValueError as exc:

            return {
                "status": "error",
                "error": str(exc),
            }

        namespace = str(profile.get("namespace") or self.cloudwatch_namespace())

        cluster_metrics = self._metrics_to_map(
            self._cluster_metrics_cache.get(
                str(cluster_id),
                [],
            )
        )

        reader_metrics = self._metrics_to_map(
            self._role_metrics_cache.get(
                f"{cluster_id}:READER",
                [],
            )
        )

        raw = self._dict(resource.get("raw"))

        member_metrics = {}

        for member in (
            raw.get(
                "DBClusterMembers",
                [],
            )
            or []
        ):

            if not isinstance(
                member,
                dict,
            ):
                continue

            instance_id = member.get("DBInstanceIdentifier")

            if not instance_id:
                continue

            member_metrics[str(instance_id)] = self._metrics_to_map(
                self._member_metrics_cache.get(
                    str(instance_id),
                    [],
                )
            )

        quality = self._quality(
            cluster_metrics,
            reader_metrics,
            member_metrics,
        )

        queried_count = quality.get("queried_metric_count", 0)

        observed_count = quality.get("observed_metric_count", 0)

        no_data_count = quality.get("no_data_metric_count", 0)

        error_count = quality.get("metric_error_count", 0)

        if error_count:
            cloudwatch_status = "error"

        elif observed_count:
            cloudwatch_status = "ok"

        elif queried_count and no_data_count == queried_count:
            cloudwatch_status = "no_data"

        elif queried_count:
            cloudwatch_status = "partial"

        else:
            cloudwatch_status = "not_queried"

        cloudwatch = {
            "status": cloudwatch_status,
            "namespace": namespace,
            "analysis_start": start.isoformat(),
            "analysis_end": end.isoformat(),
            "requested_period": self._period(),
            "cluster": {
                "dimensions": [
                    {
                        "Name": ("DBClusterIdentifier"),
                        "Value": str(cluster_id),
                    }
                ],
                "metrics": cluster_metrics,
            },
            "reader": {
                "dimensions": [
                    {
                        "Name": ("DBClusterIdentifier"),
                        "Value": str(cluster_id),
                    },
                    {
                        "Name": "Role",
                        "Value": "READER",
                    },
                ],
                "metrics": reader_metrics,
            },
            # Backward-compatible role shape.
            "roles": {
                "reader": {
                    "metrics": reader_metrics,
                }
            },
            "instances": {
                instance_id: {"metrics": metrics}
                for (
                    instance_id,
                    metrics,
                ) in member_metrics.items()
            },
            "data_quality": quality,
            "telemetry_diagnostics": {
                "queried_metric_count": queried_count,
                "observed_metric_count": observed_count,
                "no_data_metric_count": no_data_count,
                "error_metric_count": error_count,
                "missing_is_zero": False,
            },
        }

        backup = self._snapshot_cache.get(
            str(cluster_id),
            {
                "status": "unknown",
                "manual": [],
                "automated": [],
                "manual_count": None,
                "automated_count": None,
                "errors": [],
            },
        )

        automated_backup = self._automated_backup_cache.get(
            str(cluster_id),
            {
                "status": "unknown",
                "backup_count": None,
                "backups": [],
                "errors": [],
            },
        )

        cluster_events = self._cluster_events_cache.get(
            str(cluster_id),
            {
                "status": "unknown",
                "events": [],
                "event_count": None,
            },
        )

        lifecycle = {
            "current_status": raw.get("Status"),
            "events": cluster_events.get(
                "events",
                [],
            ),
            "event_count": cluster_events.get("event_count"),
            "event_status": cluster_events.get("status"),
        }

        return {
            "status": cloudwatch_status,
            "cloudwatch": cloudwatch,
            "backup": backup,
            "automated_backup": automated_backup,
            "lifecycle": lifecycle,
        }

    # TOPOLOGY

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = self._dict(resource.get("raw"))

        subnet_group_name = raw.get("DBSubnetGroup")

        subnet_group = self._subnet_group_cache.get(
            str(subnet_group_name),
            {},
        )

        vpc_id = subnet_group.get("vpc_id")

        if not vpc_id:

            return {
                "status": "incomplete",
                "reason": ("Aurora cluster has no VPC ID."),
                "db_subnet_group": subnet_group_name,
                "subnet_group_collection_status": subnet_group.get("status"),
            }

        topology = self.topology_collector.collect(
            vpc_id=str(vpc_id),
            resource_type=self.resource_type,
            resource_id=self.get_resource_id(resource),
        )

        topology = dict(topology)

        members = [
            member
            for member in (
                raw.get(
                    "DBClusterMembers",
                    [],
                )
                or []
            )
            if isinstance(
                member,
                dict,
            )
        ]

        topology["aurora"] = {
            "cluster_id": resource.get("id"),
            "member_count": len(members),
            "writer_count": sum(
                1 for member in members if member.get("IsClusterWriter")
            ),
            "reader_count": sum(
                1 for member in members if not member.get("IsClusterWriter")
            ),
        }

        return topology

    # OPTIMIZATION EVIDENCE

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._dict(collected_resource.get("identity"))

        configuration = self._dict(collected_resource.get("configuration"))

        relationships = self._dict(collected_resource.get("relationships"))

        observations = self._dict(collected_resource.get("observations"))

        topology = self._dict(collected_resource.get("topology"))

        cloudwatch = self._dict(observations.get("cloudwatch"))

        cloudtrail = self._dict(observations.get("cloudtrail"))

        reader_autoscaling = self._dict(relationships.get("reader_autoscaling"))

        backup = self._dict(observations.get("backup"))

        automated_backup = self._dict(observations.get("automated_backup"))

        lifecycle = self._dict(observations.get("lifecycle"))

        return {
            "resource": {
                "id": resource.get("id"),
                "name": identity.get("name"),
                "region": self.region,
                "engine": identity.get("engine"),
                "engine_version": identity.get("engine_version"),
                "status": identity.get("status"),
            },
            "configuration": configuration,
            # Keep existing compatibility.
            "cluster_configuration": configuration,
            "members": relationships,
            "capacity": {
                "serverless_v2": self._dict(configuration.get("serverless_v2")),
                "serverless_v2_enabled": (
                    self._dict(configuration.get("serverless_v2")).get(
                        "enabled",
                        False,
                    )
                ),
                "reader_count": relationships.get("reader_count"),
                "writer_count": relationships.get("writer_count"),
            },
            "utilization": cloudwatch,
            "cloudwatch": cloudwatch,
            "reader_autoscaling": (reader_autoscaling),
            "cloudtrail": cloudtrail,
            "topology": topology,
            "backup": {
                "backup_retention_days": (
                    self._dict(configuration.get("backup")).get("backup_retention_days")
                ),
                "manual_snapshot_count": (backup.get("manual_count")),
                "automated_snapshot_count": (backup.get("automated_count")),
                "manual_snapshots": (
                    backup.get(
                        "manual",
                        [],
                    )
                ),
                "automated_snapshots": (
                    backup.get(
                        "automated",
                        [],
                    )
                ),
                "snapshot_collection_status": (backup.get("status")),
                "automated_backup_resource_count": (
                    automated_backup.get("backup_count")
                ),
                "automated_backup_status": (automated_backup.get("status")),
            },
            "lifecycle": {
                "status": identity.get("status"),
                "current_status": lifecycle.get("current_status"),
                "events": lifecycle.get(
                    "events",
                    [],
                ),
                "event_count": lifecycle.get("event_count"),
                "event_status": lifecycle.get("event_status"),
            },
            "cost_drivers": {
                "storage_type": self._dict(configuration.get("storage")).get(
                    "storage_type"
                ),
                "backup_retention_days": (
                    self._dict(configuration.get("backup")).get("backup_retention_days")
                ),
                "reader_count": relationships.get("reader_count"),
                "writer_count": relationships.get("writer_count"),
                "global_cluster_identifier": (
                    relationships.get("global_cluster_identifier")
                ),
                "global_write_forwarding": (
                    configuration.get("global_write_forwarding")
                ),
                "deletion_protection": (configuration.get("deletion_protection")),
            },
            "data_quality": {
                "cloudwatch_available": (bool(cloudwatch)),
                "cloudtrail_available": (cloudtrail.get("status") == "ok"),
                "topology_available": (topology.get("status") == "ok"),
                "reader_autoscaling_available": (
                    reader_autoscaling.get("status")
                    in {
                        "ok",
                        "not_configured",
                    }
                ),
                "backup_available": (backup.get("status") == "ok"),
                "automated_backup_available": (automated_backup.get("status") == "ok"),
                "lifecycle_events_available": (lifecycle.get("event_status") == "ok"),
            },
        }

    # CLOUDTRAIL

    def _collect_cluster_events(
        self,
        cluster_id: str,
        cluster_arn: Optional[str],
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:

        profile = self._section("cloudtrail")

        event_names = profile.get(
            "event_names",
            [
                "StartDBCluster",
                "StopDBCluster",
                "ModifyDBCluster",
                "ModifyDBInstance",
                "CreateDBCluster",
                "DeleteDBCluster",
            ],
        )

        if not isinstance(
            event_names,
            list,
        ):
            event_names = [
                "StartDBCluster",
                "StopDBCluster",
                "ModifyDBCluster",
                "ModifyDBInstance",
                "CreateDBCluster",
                "DeleteDBCluster",
            ]

        events: list[dict[str, Any]] = []

        seen: set[str] = set()

        try:

            paginator = self.cloudtrail.get_paginator("lookup_events")

            for event_name in event_names:

                if not isinstance(
                    event_name,
                    str,
                ):
                    continue

                for page in paginator.paginate(
                    LookupAttributes=[
                        {
                            "AttributeKey": "EventName",
                            "AttributeValue": event_name,
                        }
                    ],
                    StartTime=start,
                    EndTime=end,
                    MaxResults=min(
                        50,
                        max(
                            1,
                            int(
                                profile.get(
                                    "max_results",
                                    50,
                                )
                            ),
                        ),
                    ),
                ):

                    for event in (
                        page.get(
                            "Events",
                            [],
                        )
                        or []
                    ):

                        if not isinstance(
                            event,
                            dict,
                        ):
                            continue

                        event_id = str(event.get("EventId") or "")

                        if event_id and event_id in seen:
                            continue

                        resources = (
                            event.get(
                                "Resources",
                                [],
                            )
                            or []
                        )

                        matches_resource = any(
                            isinstance(
                                item,
                                dict,
                            )
                            and (
                                item.get("ResourceName") == cluster_id
                                or (
                                    cluster_arn
                                    and item.get("ResourceName") == cluster_arn
                                )
                            )
                            for item in resources
                        )

                        raw_event = event.get("CloudTrailEvent")

                        parsed: dict[str, Any] = {}

                        if raw_event:
                            try:
                                parsed = json.loads(raw_event)
                            except (
                                TypeError,
                                ValueError,
                            ):
                                parsed = {}

                        request = self._dict(parsed.get("requestParameters"))

                        request_cluster = (
                            request.get("dBClusterIdentifier")
                            or request.get("DBClusterIdentifier")
                            or ""
                        )

                        request_matches = cluster_id in str(request_cluster)

                        if not (matches_resource or request_matches):
                            continue

                        if event_id:
                            seen.add(event_id)

                        events.append(
                            {
                                "event_id": event_id,
                                "event_name": event.get("EventName"),
                                "event_time": (self._isoformat(event.get("EventTime"))),
                                "username": event.get("Username"),
                                "event_source": event.get("EventSource"),
                                "read_only": event.get("ReadOnly"),
                                "request_parameters": request,
                            }
                        )

        except Exception as exc:

            return {
                "status": "error",
                "events": [],
                "event_count": 0,
                "error": str(exc),
            }

        events.sort(key=lambda item: (item.get("event_time") or ""))

        return {
            "status": "ok",
            "events": events,
            "event_count": len(events),
        }

    # METRIC HELPERS

    @staticmethod
    def _metrics_to_map(
        results: Any,
    ) -> Dict[str, Any]:

        result: Dict[str, Any] = {}

        values = (
            results
            if isinstance(
                results,
                list,
            )
            else []
        )

        for metric in values:

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

            name = metric.get("metric_name")

            if key:
                result[str(key)] = metric

            if not name:
                continue

            name = str(name)

            existing = result.get(name)

            if existing is None:
                result[name] = dict(metric)
                continue

            statistic = str(metric.get("statistic") or "").strip().lower()

            if statistic == "average":

                existing["average"] = metric.get("average")

                if existing.get("value") is None:
                    existing["value"] = metric.get("value")

                if metric.get("has_data"):
                    existing["has_data"] = True
                    existing["status"] = metric.get("status", existing.get("status"))

            elif statistic == "maximum":

                existing["maximum"] = metric.get("maximum")

                if metric.get("has_data"):
                    existing["has_data"] = existing.get("has_data") or True

            else:
                result[name] = dict(metric)

        return result

    @classmethod
    def _quality(
        cls,
        cluster: Dict[str, Any],
        reader: Dict[str, Any],
        members: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:

        all_metrics: list[dict[str, Any]] = []

        all_metrics.extend(cluster.values())

        all_metrics.extend(reader.values())

        for mapping in members.values():
            all_metrics.extend(mapping.values())

        observed = sum(
            1
            for metric in all_metrics
            if (isinstance(metric, dict) and metric.get("has_data") is True)
        )

        no_data = sum(
            1
            for metric in all_metrics
            if (
                isinstance(metric, dict)
                and metric.get("status")
                in {
                    "no_data",
                    "missing",
                }
            )
        )

        errors = sum(
            1
            for metric in all_metrics
            if (isinstance(metric, dict) and metric.get("status") == "error")
        )

        return {
            "queried_metric_count": len(all_metrics),
            "observed_metric_count": observed,
            "no_data_metric_count": no_data,
            "metric_error_count": errors,
        }

    # HELPERS

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
    def _tags(
        tags: Any,
    ) -> dict[str, Any]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        return {
            str(tag.get("Key")): tag.get("Value")
            for tag in tags
            if (isinstance(tag, dict) and tag.get("Key"))
        }

    @staticmethod
    def _isoformat(
        value: Any,
    ) -> Optional[str]:

        if value is None:
            return None

        if isinstance(
            value,
            datetime,
        ):

            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)

            return value.isoformat()

        if hasattr(
            value,
            "isoformat",
        ):
            return value.isoformat()

        return str(value)
