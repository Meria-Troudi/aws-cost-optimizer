"""
Aurora DB-cluster collector.

Collects cluster-level evidence for:
- Aurora Serverless v2 suitability
- provisioned vs serverless capacity review
- reader utilization / scaling review
- Aurora storage and I/O cost drivers
- backup / retention context
- Global Database context
- cluster lifecycle context

The collector does not select a replacement architecture and does not
estimate savings.
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

    DEFAULT_NAMESPACE = "AWS/RDS"
    DEFAULT_PERIOD = 3600

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

        self.rds = get_client("rds", self.region)
        self.cloudwatch = get_client("cloudwatch", self.region)
        self.cloudtrail = get_client("cloudtrail", self.region)

        self.metric_collector = CloudWatchMetricCollector(
            self.cloudwatch
        )
        self.topology_collector = NetworkTopologyCollector(
            self.region
        )

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

    # ------------------------------------------------------------------
    # Profile
    # ------------------------------------------------------------------

    def _section(
        self,
        name: str,
    ) -> dict[str, Any]:
        value = (
            self.profile.get(name, {})
            if isinstance(self.profile, dict)
            else {}
        )
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _enabled(
        section: dict[str, Any],
        default: bool = False,
    ) -> bool:
        if not isinstance(section, dict):
            return default
        return section.get("enabled", default) is True

    def _cloudwatch_profile(self) -> dict[str, Any]:
        return self._section("observations").get(
            "cloudwatch",
            {},
        )

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
        try:
            return int(
                self._cloudwatch_profile().get(
                    "period",
                    self.DEFAULT_PERIOD,
                )
            )
        except (TypeError, ValueError):
            return self.DEFAULT_PERIOD

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(
        self,
    ) -> List[Dict[str, Any]]:
        resources: list[Dict[str, Any]] = []

        paginator = self.rds.get_paginator(
            "describe_db_clusters"
        )

        for page in paginator.paginate():
            for cluster in page.get(
                "DBClusters",
                [],
            ) or []:
                engine = str(
                    cluster.get("Engine", "")
                    or ""
                ).lower()

                if not engine.startswith("aurora"):
                    continue

                cluster_id = cluster.get(
                    "DBClusterIdentifier"
                )

                if not cluster_id:
                    continue

                resources.append(
                    {
                        "id":
                            cluster_id,
                        "raw":
                            cluster,
                    }
                )

        self._prefetch_metrics(
            resources
        )

        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:
        return str(resource["id"])

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw = self._dict(
            resource.get("raw")
        )

        return {
            "name":
                raw.get("DBClusterIdentifier"),

            "db_cluster_identifier":
                raw.get("DBClusterIdentifier"),

            "db_cluster_arn":
                raw.get("DBClusterArn"),

            "engine":
                raw.get("Engine"),

            "engine_version":
                raw.get("EngineVersion"),

            "status":
                raw.get("Status"),

            "engine_mode":
                raw.get("EngineMode"),

            "created_at":
                self._isoformat(
                    raw.get("ClusterCreateTime")
                ),

            "tags":
                self._tags(
                    raw.get("TagList", [])
                ),
        }

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw = self._dict(
            resource.get("raw")
        )

        vpc_security_groups = [
            item.get("VpcSecurityGroupId")
            for item in (
                raw.get(
                    "VpcSecurityGroups",
                    [],
                )
                or []
            )
            if isinstance(item, dict)
            and item.get("VpcSecurityGroupId")
        ]

        scaling_v2 = self._dict(
            raw.get(
                "ServerlessV2ScalingConfiguration"
            )
        )

        scaling_v1 = self._dict(
            raw.get(
                "ScalingConfigurationInfo"
            )
        )

        subnet_group = raw.get(
            "DBSubnetGroup"
        )

        return {
            "cluster": {
                "identifier":
                    raw.get(
                        "DBClusterIdentifier"
                    ),
                "arn":
                    raw.get(
                        "DBClusterArn"
                    ),
                "status":
                    raw.get("Status"),
                "engine":
                    raw.get("Engine"),
                "engine_version":
                    raw.get("EngineVersion"),
                "engine_mode":
                    raw.get("EngineMode"),
                "database_name":
                    raw.get("DatabaseName"),
                "master_username":
                    raw.get("MasterUsername"),
                "cluster_create_time":
                    self._isoformat(
                        raw.get(
                            "ClusterCreateTime"
                        )
                    ),
            },

            "storage": {
                "storage_type":
                    raw.get("StorageType"),
                "allocated_storage":
                    raw.get("AllocatedStorage"),
                "storage_encrypted":
                    raw.get("StorageEncrypted"),
                "kms_key_id":
                    raw.get("KmsKeyId"),
            },

            "backup": {
                "backup_retention_days":
                    raw.get(
                        "BackupRetentionPeriod"
                    ),
                "preferred_backup_window":
                    raw.get(
                        "PreferredBackupWindow"
                    ),
                "copy_tags_to_snapshot":
                    raw.get(
                        "CopyTagsToSnapshot"
                    ),
            },

            "availability": {
                "availability_zones":
                    list(
                        raw.get(
                            "AvailabilityZones",
                            [],
                        )
                        or []
                    ),
                "multi_az":
                    raw.get("MultiAZ"),
                "promotion_tier_count":
                    len(
                        raw.get(
                            "DBClusterMembers",
                            [],
                        )
                        or []
                    ),
            },

            "endpoints": {
                "writer":
                    raw.get("Endpoint"),
                "reader":
                    raw.get("ReaderEndpoint"),
                "custom":
                    raw.get("CustomEndpoints", []),
            },

            "network": {
                "vpc_security_group_ids":
                    vpc_security_groups,
                "db_subnet_group":
                    subnet_group,
            },

            "serverless_v2": {
                "enabled":
                    bool(scaling_v2),
                "min_capacity":
                    scaling_v2.get(
                        "MinCapacity"
                    ),
                "max_capacity":
                    scaling_v2.get(
                        "MaxCapacity"
                    ),
                "seconds_until_auto_pause":
                    scaling_v2.get(
                        "SecondsUntilAutoPause"
                    ),
            },

            "serverless_v1": {
                "enabled":
                    bool(scaling_v1),
                "min_capacity":
                    scaling_v1.get(
                        "MinCapacity"
                    ),
                "max_capacity":
                    scaling_v1.get(
                        "MaxCapacity"
                    ),
                "auto_pause":
                    scaling_v1.get(
                        "AutoPause"
                    ),
                "seconds_until_auto_pause":
                    scaling_v1.get(
                        "SecondsUntilAutoPause"
                    ),
            },

            "deletion_protection":
                raw.get(
                    "DeletionProtection"
                ),

            "iam_database_authentication_enabled":
                raw.get(
                    "IAMDatabaseAuthenticationEnabled"
                ),

            "global_cluster_identifier":
                raw.get(
                    "GlobalClusterIdentifier"
                ),

            "global_write_forwarding":
                raw.get(
                    "GlobalWriteForwardingStatus"
                ),

            "backtrack_window":
                raw.get(
                    "BacktrackWindow"
                ),

            "enabled_cloudwatch_logs_exports":
                list(
                    raw.get(
                        "EnabledCloudwatchLogsExports",
                        [],
                    )
                    or []
                ),

            "db_cluster_parameter_group":
                raw.get(
                    "DBClusterParameterGroup"
                ),

            "associated_roles":
                raw.get(
                    "AssociatedRoles",
                    [],
                ),
        }

    # ------------------------------------------------------------------
    # Relationships / readers / global DB
    # ------------------------------------------------------------------

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw = self._dict(
            resource.get("raw")
        )

        members: list[dict[str, Any]] = []

        for member in (
            raw.get(
                "DBClusterMembers",
                [],
            )
            or []
        ):
            if not isinstance(member, dict):
                continue

            members.append(
                {
                    "db_instance_identifier":
                        member.get(
                            "DBInstanceIdentifier"
                        ),
                    "is_writer":
                        bool(
                            member.get(
                                "IsClusterWriter"
                            )
                        ),
                    "promotion_tier":
                        member.get(
                            "PromotionTier"
                        ),
                    "parameter_group_status":
                        member.get(
                            "DBClusterParameterGroupStatus"
                        ),
                }
            )

        replicas = [
            item.get(
                "DBInstanceIdentifier"
            )
            for item in members
            if not item.get("is_writer")
            and item.get(
                "db_instance_identifier"
            )
        ]

        writers = [
            item.get(
                "DBInstanceIdentifier"
            )
            for item in members
            if item.get("is_writer")
            and item.get(
                "db_instance_identifier"
            )
        ]

        return {
            "status":
                "ok",

            "vpc_security_group_ids":
                [
                    item.get(
                        "VpcSecurityGroupId"
                    )
                    for item in (
                        raw.get(
                            "VpcSecurityGroups",
                            [],
                        )
                        or []
                    )
                    if isinstance(item, dict)
                    and item.get(
                        "VpcSecurityGroupId"
                    )
                ],

            "db_subnet_group":
                self._dict(
                    raw.get(
                        "DBSubnetGroup"
                    )
                ).get(
                    "DBSubnetGroupName"
                ),

            "members":
                members,

            "writer_instances":
                writers,

            "reader_instances":
                replicas,

            "writer_count":
                len(writers),

            "reader_count":
                len(replicas),

            "global_cluster_identifier":
                raw.get(
                    "GlobalClusterIdentifier"
                ),

            "replication_source_identifier":
                raw.get(
                    "ReplicationSourceIdentifier"
                ),

            "read_replica_identifiers":
                list(
                    raw.get(
                        "ReadReplicaIdentifiers",
                        [],
                    )
                    or []
                ),

            "roles":
                raw.get(
                    "AssociatedRoles",
                    [],
                ),
        }

    # ------------------------------------------------------------------
    # CloudWatch
    # ------------------------------------------------------------------

    def _prefetch_metrics(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:
        profile = self._cloudwatch_profile()

        if not self._enabled(
            profile,
            default=True,
        ):
            return

        cluster_specs = self._specs(
            "cluster_metrics"
        )
        role_specs = self._specs(
            "role_metrics"
        )
        member_specs = self._specs(
            "instance_metrics"
        )

        if (
            not cluster_specs
            and not role_specs
            and not member_specs
        ):
            return

        try:
            start, end = self.get_analysis_period()
        except ValueError:
            return

        namespace = str(
            profile.get(
                "namespace",
                self.DEFAULT_NAMESPACE,
            )
        )

        cluster_requests = []
        role_requests = []
        member_requests = []

        for resource in resources:
            cluster_id = resource.get("id")
            raw = self._dict(
                resource.get("raw")
            )

            if not cluster_id:
                continue

            if cluster_specs:
                cluster_requests.append(
                    {
                        "resource_key":
                            str(cluster_id),
                        "namespace":
                            namespace,
                        "dimensions": [
                            {
                                "Name":
                                    "DBClusterIdentifier",
                                "Value":
                                    str(cluster_id),
                            }
                        ],
                        "metric_specs":
                            cluster_specs,
                    }
                )

            if role_specs:
                for role in (
                    "WRITER",
                    "READER",
                ):
                    role_requests.append(
                        {
                            "resource_key":
                                f"{cluster_id}:{role}",
                            "namespace":
                                namespace,
                            "dimensions": [
                                {
                                    "Name":
                                        "DBClusterIdentifier",
                                    "Value":
                                        str(cluster_id),
                                },
                                {
                                    "Name":
                                        "Role",
                                    "Value":
                                        role,
                                },
                            ],
                            "metric_specs":
                                role_specs,
                        }
                    )

            if member_specs:
                for member in (
                    raw.get(
                        "DBClusterMembers",
                        [],
                    )
                    or []
                ):
                    if not isinstance(member, dict):
                        continue

                    instance_id = member.get(
                        "DBInstanceIdentifier"
                    )

                    if not instance_id:
                        continue

                    member_requests.append(
                        {
                            "resource_key":
                                str(instance_id),
                            "namespace":
                                namespace,
                            "dimensions": [
                                {
                                    "Name":
                                        "DBInstanceIdentifier",
                                    "Value":
                                        str(instance_id),
                                }
                            ],
                            "metric_specs":
                                member_specs,
                        }
                    )

        if cluster_requests:
            values = self.metric_collector.collect_batch(
                cluster_requests,
                start=start,
                end=end,
                requested_period=self._period(),
            )
            self._cluster_metrics_cache = values

        if role_requests:
            values = self.metric_collector.collect_batch(
                role_requests,
                start=start,
                end=end,
                requested_period=self._period(),
            )
            self._role_metrics_cache = values

        if member_requests:
            values = self.metric_collector.collect_batch(
                member_requests,
                start=start,
                end=end,
                requested_period=self._period(),
            )
            self._member_metrics_cache = values

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
                "status":
                    "disabled"
            }

        cluster_id = resource.get("id")

        if not cluster_id:
            return {
                "status":
                    "incomplete"
            }

        start, end = self.get_analysis_period()

        namespace = str(
            profile.get(
                "namespace",
                self.DEFAULT_NAMESPACE,
            )
        )

        cluster = self._metrics_to_map(
            self._cluster_metrics_cache.get(
                str(cluster_id),
                [],
            )
        )

        writer = self._metrics_to_map(
            self._role_metrics_cache.get(
                f"{cluster_id}:WRITER",
                [],
            )
        )

        reader = self._metrics_to_map(
            self._role_metrics_cache.get(
                f"{cluster_id}:READER",
                [],
            )
        )

        member_metrics = {}

        raw = self._dict(
            resource.get("raw")
        )

        for member in (
            raw.get(
                "DBClusterMembers",
                [],
            )
            or []
        ):
            if not isinstance(member, dict):
                continue

            instance_id = member.get(
                "DBInstanceIdentifier"
            )

            if not instance_id:
                continue

            member_metrics[str(instance_id)] = (
                self._metrics_to_map(
                    self._member_metrics_cache.get(
                        str(instance_id),
                        [],
                    )
                )
            )

        cloudwatch = {
            "status":
                "ok",
            "namespace":
                namespace,
            "analysis_start":
                start.isoformat(),
            "analysis_end":
                end.isoformat(),
            "requested_period":
                self._period(),

            "cluster": {
                "dimensions": [
                    {
                        "Name":
                            "DBClusterIdentifier",
                        "Value":
                            str(cluster_id),
                    }
                ],
                "metrics":
                    cluster,
            },

            "roles": {
                "writer": {
                    "metrics":
                        writer,
                },
                "reader": {
                    "metrics":
                        reader,
                },
            },

            "instances": {
                instance_id:
                    {
                        "metrics":
                            metrics
                    }
                for instance_id, metrics
                in member_metrics.items()
            },

            "data_quality":
                self._quality(
                    cluster,
                    writer,
                    reader,
                    member_metrics,
                ),
        }

        observations = {
            "cloudwatch":
                cloudwatch,
        }

        if self._enabled(
            self._section("cloudtrail"),
            default=False,
        ):
            observations["cloudtrail"] = (
                self._collect_cluster_events(
                    cluster_id=str(
                        cluster_id
                    ),
                    cluster_arn=raw.get(
                        "DBClusterArn"
                    ),
                    start=start,
                    end=end,
                )
            )

        return observations

    # ------------------------------------------------------------------
    # Topology
    # ------------------------------------------------------------------

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw = self._dict(
            resource.get("raw")
        )

        subnet_group = self._dict(
            raw.get("DBSubnetGroup")
        )

        vpc_id = subnet_group.get(
            "VpcId"
        )

        if not vpc_id:
            return {
                "status":
                    "incomplete",
                "reason":
                    "Aurora cluster has no VPC ID",
            }

        topology = self.topology_collector.collect(
            vpc_id=str(vpc_id),
            resource_type=self.resource_type,
            resource_id=self.get_resource_id(resource),
        )

        topology = dict(topology)

        topology["aurora"] = {
            "cluster_id":
                resource.get("id"),
            "member_count":
                len(
                    raw.get(
                        "DBClusterMembers",
                        [],
                    )
                    or []
                ),
            "writer_count":
                sum(
                    1
                    for member in (
                        raw.get(
                            "DBClusterMembers",
                            [],
                        )
                        or []
                    )
                    if isinstance(member, dict)
                    and member.get(
                        "IsClusterWriter"
                    )
                ),
        }

        return topology

    # ------------------------------------------------------------------
    # Optimization evidence
    # ------------------------------------------------------------------

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
        relationships = self._dict(
            collected_resource.get(
                "relationships"
            )
        )
        observations = self._dict(
            collected_resource.get(
                "observations"
            )
        )

        cloudwatch = self._dict(
            observations.get(
                "cloudwatch"
            )
        )
        cloudtrail = self._dict(
            observations.get(
                "cloudtrail"
            )
        )

        return {
            "resource": {
                "id":
                    resource.get("id"),
                "name":
                    identity.get("name"),
                "region":
                    self.region,
                "engine":
                    identity.get("engine"),
                "engine_version":
                    identity.get("engine_version"),
                "status":
                    identity.get("status"),
            },

            "cluster_configuration":
                configuration,

            "members":
                relationships,

            "capacity": {
                "serverless_v2":
                    self._dict(
                        configuration.get(
                            "serverless_v2"
                        )
                    ),

                "serverless_v2_enabled":
                    self._dict(
                        configuration.get(
                            "serverless_v2"
                        )
                    ).get(
                        "enabled",
                        False,
                    ),

                "provisioned_member_count":
                    sum(
                        1
                        for member in (
                            relationships.get(
                                "members",
                                [],
                            )
                            or []
                        )
                        if isinstance(member, dict)
                    ),
            },

            "utilization":
                cloudwatch,

            "cloudtrail":
                cloudtrail,

            "cost_drivers": {
                "storage_type":
                    self._dict(
                        configuration.get(
                            "storage"
                        )
                    ).get(
                        "storage_type"
                    ),

                "backup_retention_days":
                    self._dict(
                        configuration.get(
                            "backup"
                        )
                    ).get(
                        "backup_retention_days"
                    ),

                "reader_count":
                    relationships.get(
                        "reader_count"
                    ),

                "writer_count":
                    relationships.get(
                        "writer_count"
                    ),

                "global_cluster_identifier":
                    relationships.get(
                        "global_cluster_identifier"
                    ),

                "global_write_forwarding":
                    configuration.get(
                        "global_write_forwarding"
                    ),

                "deletion_protection":
                    configuration.get(
                        "deletion_protection"
                    ),
            },

            "data_quality": {
                "cloudwatch_available":
                    bool(cloudwatch),
                "cloudtrail_available":
                    cloudtrail.get(
                        "status"
                    ) == "ok",
                "topology_available":
                    self._dict(
                        collected_resource.get(
                            "topology"
                        )
                    ).get(
                        "status"
                    ) == "ok",
            },
        }

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------

    def _collect_cluster_events(
        self,
        cluster_id: str,
        cluster_arn: Optional[str],
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:
        profile = self._section(
            "cloudtrail"
        )

        event_names = profile.get(
            "event_names",
            [
                "ModifyDBCluster",
                "ModifyDBInstance",
                "CreateDBCluster",
                "DeleteDBCluster",
            ],
        )

        if not isinstance(event_names, list):
            event_names = [
                "ModifyDBCluster",
                "ModifyDBInstance",
                "CreateDBCluster",
                "DeleteDBCluster",
            ]

        events: list[dict[str, Any]] = []
        seen: set[str] = set()

        try:
            paginator = self.cloudtrail.get_paginator(
                "lookup_events"
            )

            for event_name in event_names:
                if not isinstance(
                    event_name,
                    str,
                ):
                    continue

                for page in paginator.paginate(
                    LookupAttributes=[
                        {
                            "AttributeKey":
                                "EventName",
                            "AttributeValue":
                                event_name,
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
                    for event in page.get(
                        "Events",
                        [],
                    ) or []:
                        if not isinstance(
                            event,
                            dict,
                        ):
                            continue

                        event_id = str(
                            event.get(
                                "EventId"
                            )
                            or ""
                        )

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
                            isinstance(item, dict)
                            and (
                                item.get(
                                    "ResourceName"
                                ) == cluster_id
                                or (
                                    cluster_arn
                                    and item.get(
                                        "ResourceName"
                                    ) == cluster_arn
                                )
                            )
                            for item in resources
                        )

                        raw_event = event.get(
                            "CloudTrailEvent"
                        )

                        parsed = {}
                        if raw_event:
                            try:
                                parsed = json.loads(
                                    raw_event
                                )
                            except (
                                TypeError,
                                ValueError,
                            ):
                                parsed = {}

                        request = self._dict(
                            parsed.get(
                                "requestParameters"
                            )
                        )

                        request_matches = (
                            cluster_id
                            in str(
                                request.get(
                                    "dBClusterIdentifier"
                                )
                                or request.get(
                                    "DBClusterIdentifier"
                                )
                                or ""
                            )
                        )

                        if not (
                            matches_resource
                            or request_matches
                        ):
                            continue

                        seen.add(event_id)

                        events.append(
                            {
                                "event_id":
                                    event_id,
                                "event_name":
                                    event.get(
                                        "EventName"
                                    ),
                                "event_time":
                                    self._isoformat(
                                        event.get(
                                            "EventTime"
                                        )
                                    ),
                                "username":
                                    event.get(
                                        "Username"
                                    ),
                                "event_source":
                                    event.get(
                                        "EventSource"
                                    ),
                                "read_only":
                                    event.get(
                                        "ReadOnly"
                                    ),
                                "request_parameters":
                                    request,
                            }
                        )

        except Exception as exc:
            return {
                "status":
                    "error",
                "events":
                    [],
                "event_count":
                    0,
                "error":
                    str(exc),
            }

        events.sort(
            key=lambda item:
                item.get(
                    "event_time"
                )
                or ""
        )

        return {
            "status":
                "ok",
            "events":
                events,
            "event_count":
                len(events),
        }

    # ------------------------------------------------------------------
    # Metric helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _metrics_to_map(
        results: Any,
    ) -> Dict[str, Any]:
        result = {}

        for metric in (
            results
            if isinstance(
                results,
                list,
            )
            else []
        ):
            if not isinstance(
                metric,
                dict,
            ):
                continue

            name = (
                metric.get("metric_key")
                or metric.get("metric_name")
            )

            if name:
                result[str(name)] = metric

            metric_name = metric.get(
                "metric_name"
            )

            if metric_name:
                result[str(metric_name)] = metric

        return result

    @classmethod
    def _quality(
        cls,
        cluster: Dict[str, Any],
        writer: Dict[str, Any],
        reader: Dict[str, Any],
        members: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        all_metrics = []

        for mapping in (
            cluster,
            writer,
            reader,
        ):
            all_metrics.extend(
                mapping.values()
            )

        for member in members.values():
            all_metrics.extend(
                member.values()
            )

        return {
            "queried_metric_count":
                len(all_metrics),

            "observed_metric_count":
                sum(
                    1
                    for metric in all_metrics
                    if isinstance(metric, dict)
                    and metric.get("has_data") is True
                ),

            "no_data_metric_count":
                sum(
                    1
                    for metric in all_metrics
                    if isinstance(metric, dict)
                    and metric.get("status")
                    in {"no_data", "missing"}
                ),

            "metric_error_count":
                sum(
                    1
                    for metric in all_metrics
                    if isinstance(metric, dict)
                    and metric.get("status")
                    == "error"
                ),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:
        return (
            value
            if isinstance(value, dict)
            else {}
        )

    @staticmethod
    def _tags(
        tags: Any,
    ) -> dict[str, Any]:
        if not isinstance(tags, list):
            return {}

        return {
            str(tag.get("Key")):
                tag.get("Value")
            for tag in tags
            if isinstance(tag, dict)
            and tag.get("Key")
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
                value = value.replace(
                    tzinfo=timezone.utc
                )
            else:
                value = value.astimezone(
                    timezone.utc
                )

            return value.isoformat()

        if hasattr(
            value,
            "isoformat",
        ):
            return value.isoformat()

        return str(value)