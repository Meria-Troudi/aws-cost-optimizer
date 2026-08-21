"""
RDS DB-instance collector.

Collects evidence required for:
- rightsizing / idle analysis
- read-replica utilization
- storage / IOPS / throughput review
- dev/test scheduling analysis
- pricing / Reserved Instance review
- Aurora cluster context
- network and topology analysis

The collector only collects evidence. It does not decide whether a
resource is wasteful and does not estimate savings.
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
class RDSCollector(BaseCollector):

    key = "rds"
    resource_type = "rds_instance"

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

        self._metrics_batch_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._reserved_cache: Optional[
            List[Dict[str, Any]]
        ] = None

    # ------------------------------------------------------------------
    # Profile
    # ------------------------------------------------------------------

    def _section(self, name: str) -> dict[str, Any]:
        value = (
            self.profile.get(name, {})
            if isinstance(self.profile, dict)
            else {}
        )
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _enabled(section: dict[str, Any], default: bool = False) -> bool:
        if not isinstance(section, dict):
            return default
        return section.get("enabled", default) is True

    def _cloudwatch_profile(self) -> dict[str, Any]:
        return self._section("observations").get("cloudwatch", {})

    def _metric_specs(self) -> list[dict[str, Any]]:
        metrics = self._cloudwatch_profile().get("metrics", [])
        return metrics if isinstance(metrics, list) else []

    def _requested_period(self) -> int:
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
    # Collection lifecycle
    # ------------------------------------------------------------------

    def _collect_resource(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        collected = super()._collect_resource(resource)

        analyzer_config = self._section("analyzer_config")
        if analyzer_config:
            collected["analysis_policy"] = {
                "rds": analyzer_config,
            }

        return collected

    # ------------------------------------------------------------------
    # Discovery / identity
    # ------------------------------------------------------------------

    def discover(self) -> List[Dict[str, Any]]:
        resources: list[Dict[str, Any]] = []

        paginator = self.rds.get_paginator(
            "describe_db_instances"
        )

        for page in paginator.paginate():
            for db in page.get("DBInstances", []) or []:
                identifier = db.get("DBInstanceIdentifier")
                if not identifier:
                    continue

                resources.append(
                    {
                        "id": identifier,
                        "raw": db,
                    }
                )

        self._prefetch_metrics(resources)
        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:
        return str(resource["id"])

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw = self._dict(resource.get("raw"))

        tags = self._tags(raw.get("TagList", []))

        return {
            "name":
                tags.get("Name")
                or raw.get("DBInstanceIdentifier")
                or resource.get("id"),

            "db_instance_identifier":
                raw.get("DBInstanceIdentifier"),

            "db_instance_arn":
                raw.get("DBInstanceArn"),

            "db_instance_resource_id":
                raw.get("DbiResourceId"),

            "engine":
                raw.get("Engine"),

            "engine_version":
                raw.get("EngineVersion"),

            "instance_class":
                raw.get("DBInstanceClass"),

            "status":
                raw.get("DBInstanceStatus"),

            "created_at":
                self._isoformat(raw.get("InstanceCreateTime")),

            "availability_zone":
                raw.get("AvailabilityZone"),

            "preferred_maintenance_window":
                raw.get("PreferredMaintenanceWindow"),

            "preferred_backup_window":
                raw.get("PreferredBackupWindow"),

            "tags":
                tags,
        }

    # ------------------------------------------------------------------
    # Configuration / cost drivers
    # ------------------------------------------------------------------

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw = self._dict(resource.get("raw"))

        subnet_group = self._dict(raw.get("DBSubnetGroup"))
        monitoring = self._dict(raw.get("MonitoringRoleArn"))

        return {
            "status": raw.get("DBInstanceStatus"),
            "instance_class": raw.get("DBInstanceClass"),
            "engine": raw.get("Engine"),
            "engine_version": raw.get("EngineVersion"),

            "deployment": {
                "multi_az": raw.get("MultiAZ"),
                "availability_zone": raw.get("AvailabilityZone"),
                "secondary_availability_zone":
                    raw.get("SecondaryAvailabilityZone"),
                "availability_zone_group":
                    raw.get("AvailabilityZone"),
            },

            "storage": {
                "storage_type": raw.get("StorageType"),
                "allocated_storage_gib": raw.get("AllocatedStorage"),
                "max_allocated_storage_gib":
                    raw.get("MaxAllocatedStorage"),
                "iops": raw.get("Iops"),
                "storage_throughput_mibps":
                    raw.get("StorageThroughput"),
                "storage_encrypted":
                    raw.get("StorageEncrypted"),
                "kms_key_id": raw.get("KmsKeyId"),
            },

            "backup": {
                "backup_retention_days":
                    raw.get("BackupRetentionPeriod"),
                "preferred_backup_window":
                    raw.get("PreferredBackupWindow"),
                "copy_tags_to_snapshot":
                    raw.get("CopyTagsToSnapshot"),
                "delete_automated_backups":
                    raw.get("DeleteAutomatedBackups"),
            },

            "performance": {
                "performance_insights_enabled":
                    raw.get("PerformanceInsightsEnabled"),
                "performance_insights_retention_days":
                    raw.get("PerformanceInsightsRetentionPeriod"),
                "performance_insights_kms_key_id":
                    raw.get("PerformanceInsightsKMSKeyId"),
                "monitoring_interval":
                    raw.get("MonitoringInterval"),
                "monitoring_role_arn":
                    raw.get("MonitoringRoleArn"),
            },

            "network": {
                "publicly_accessible":
                    raw.get("PubliclyAccessible"),
                "subnet_group":
                    subnet_group.get("DBSubnetGroupName"),
                "vpc_id":
                    subnet_group.get("VpcId"),
                "endpoint":
                    self._endpoint(raw.get("Endpoint")),
            },

            "availability": {
                "promotion_tier":
                    raw.get("PromotionTier"),
                "preferred_maintenance_window":
                    raw.get("PreferredMaintenanceWindow"),
            },

            "pricing": {
                "license_model":
                    raw.get("LicenseModel"),
                "storage_type":
                    raw.get("StorageType"),
                "engine":
                    raw.get("Engine"),
                "engine_version":
                    raw.get("EngineVersion"),
                "instance_class":
                    raw.get("DBInstanceClass"),
                "multi_az":
                    raw.get("MultiAZ"),
            },

            "cluster": {
                "db_cluster_identifier":
                    raw.get("DBClusterIdentifier"),
                "read_replica_source":
                    raw.get(
                        "ReadReplicaSourceDBInstanceIdentifier"
                    ),
                "read_replica_identifiers":
                    list(
                        raw.get(
                            "ReadReplicaDBInstanceIdentifiers",
                            [],
                        )
                        or []
                    ),
            },

            "deletion_protection":
                raw.get("DeletionProtection"),

            "iam_database_authentication_enabled":
                raw.get("IAMDatabaseAuthenticationEnabled"),

            "auto_minor_version_upgrade":
                raw.get("AutoMinorVersionUpgrade"),

            "ca_certificate_identifier":
                raw.get("CACertificateIdentifier"),

            "timezone":
                raw.get("Timezone"),

            "character_set_name":
                raw.get("CharacterSetName"),

            "processor_features":
                raw.get("ProcessorFeatures"),

            "db_parameter_groups":
                raw.get("DBParameterGroups", []),

            "option_group_memberships":
                raw.get("OptionGroupMemberships", []),

            "license_model":
                raw.get("LicenseModel"),

            "availability_zone":
                raw.get("AvailabilityZone"),

            "monitoring_role_arn":
                monitoring if monitoring else raw.get(
                    "MonitoringRoleArn"
                ),
        }

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw = self._dict(resource.get("raw"))
        subnet_group = self._dict(raw.get("DBSubnetGroup"))

        cluster_id = raw.get("DBClusterIdentifier")

        result = {
            "status": "ok",

            "vpc_id":
                subnet_group.get("VpcId"),

            "db_subnet_group":
                subnet_group.get("DBSubnetGroupName"),

            "subnet_ids":
                [
                    subnet.get("SubnetIdentifier")
                    for subnet in (
                        subnet_group.get("Subnets", [])
                        or []
                    )
                    if isinstance(subnet, dict)
                    and subnet.get("SubnetIdentifier")
                ],

            "security_group_ids":
                [
                    group.get("VpcSecurityGroupId")
                    for group in (
                        raw.get("VpcSecurityGroups", [])
                        or []
                    )
                    if isinstance(group, dict)
                    and group.get("VpcSecurityGroupId")
                ],

            "db_cluster_identifier":
                cluster_id,

            "read_replica_source":
                raw.get(
                    "ReadReplicaSourceDBInstanceIdentifier"
                ),

            "read_replicas":
                list(
                    raw.get(
                        "ReadReplicaDBInstanceIdentifiers",
                        [],
                    )
                    or []
                ),

            "replicate_source_region":
                raw.get("ReadReplicaSourceDBInstanceIdentifier"),

            "associated_roles":
                raw.get("AssociatedRoles", []),

            "domain_memberships":
                raw.get("DomainMemberships", []),

            "cluster":
                self._collect_cluster_context(cluster_id),
        }

        return result

    # ------------------------------------------------------------------
    # CloudWatch
    # ------------------------------------------------------------------

    def _prefetch_metrics(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:
        profile = self._cloudwatch_profile()

        if not self._enabled(profile, default=True):
            return

        metric_specs = self._metric_specs()
        if not metric_specs:
            return

        namespace = str(
            profile.get("namespace")
            or self.DEFAULT_NAMESPACE
        )

        try:
            start, end = self.get_analysis_period()
        except ValueError:
            return

        requests = []

        for resource in resources:
            identifier = resource.get("id")
            if not identifier:
                continue

            requests.append(
                {
                    "resource_key": str(identifier),
                    "namespace": namespace,
                    "dimensions": [
                        {
                            "Name":
                                "DBInstanceIdentifier",
                            "Value":
                                str(identifier),
                        }
                    ],
                    "metric_specs": metric_specs,
                }
            )

        if not requests:
            return

        self._metrics_batch_cache = (
            self.metric_collector.collect_batch(
                requests,
                start=start,
                end=end,
                requested_period=self._requested_period(),
            )
        )

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        profile = self._cloudwatch_profile()

        if not self._enabled(profile, default=True):
            return {"status": "disabled"}

        identifier = resource.get("id")
        if not identifier:
            return {
                "status": "incomplete",
                "reason": "DB instance identifier unavailable",
            }

        start, end = self.get_analysis_period()

        namespace = str(
            profile.get("namespace")
            or self.DEFAULT_NAMESPACE
        )

        results = self._metrics_batch_cache.get(
            str(identifier),
            [],
        )

        metrics = {
            result.get("metric_name"):
                result
            for result in results
            if isinstance(result, dict)
            and result.get("metric_name")
        }

        cloudwatch = {
            "status": (
                "error"
                if results
                and all(
                    item.get("status") == "error"
                    for item in results
                    if isinstance(item, dict)
                )
                else "ok"
            ),
            "namespace": namespace,
            "dimensions": [
                {
                    "Name":
                        "DBInstanceIdentifier",
                    "Value":
                        str(identifier),
                }
            ],
            "analysis_start":
                start.isoformat(),
            "analysis_end":
                end.isoformat(),
            "start":
                start.isoformat(),
            "end":
                end.isoformat(),
            "requested_period":
                self._requested_period(),
            "metrics":
                metrics,
        }

        result = {
            "cloudwatch": cloudwatch,
        }

        if self._enabled(
            self._section("cloudtrail"),
            default=False,
        ):
            current_class = self._dict(
                resource.get("raw")
            ).get("DBInstanceClass")

            result["cloudtrail"] = (
                self._collect_instance_class_history(
                    identifier=str(identifier),
                    start=start,
                    end=end,
                    current_instance_class=current_class,
                )
            )

        if self._section("pricing").get("reserved_instances", {}).get(
            "enabled",
            False,
        ):
            result["pricing"] = {
                "reserved_instance_context":
                    self._reserved_instance_context(
                        resource
                    )
            }

        result["derived"] = self._build_activity_pattern(
            metrics
        )

        return result

    # ------------------------------------------------------------------
    # Topology
    # ------------------------------------------------------------------

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        configuration = self._dict(
            collected_resource.get("configuration")
        )
        vpc_id = (
            self._dict(
                configuration.get("network")
            ).get("vpc_id")
        )

        if not vpc_id:
            return {
                "status": "incomplete",
                "reason": "RDS instance has no VPC ID",
            }

        topology = self.topology_collector.collect(
            vpc_id=str(vpc_id),
            resource_type=self.resource_type,
            resource_id=self.get_resource_id(resource),
        )

        topology = dict(topology)

        relationships = self._dict(
            collected_resource.get("relationships")
        )

        cluster_id = relationships.get(
            "db_cluster_identifier"
        )

        topology["rds"] = {
            "db_instance_identifier":
                resource.get("id"),
            "db_cluster_identifier":
                cluster_id,
            "db_subnet_group":
                relationships.get(
                    "db_subnet_group"
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
            collected_resource.get("identity")
        )
        configuration = self._dict(
            collected_resource.get("configuration")
        )
        relationships = self._dict(
            collected_resource.get("relationships")
        )
        observations = self._dict(
            collected_resource.get("observations")
        )
        cloudwatch = self._dict(
            observations.get("cloudwatch")
        )
        derived = self._dict(
            observations.get("derived")
        )
        pricing = self._dict(
            observations.get("pricing")
        )
        cloudtrail = self._dict(
            observations.get("cloudtrail")
        )

        return {
            "resource": {
                "id":
                    resource.get("id"),
                "name":
                    identity.get("name"),
                "region":
                    self.region,
                "status":
                    identity.get("status"),
                "engine":
                    identity.get("engine"),
                "instance_class":
                    identity.get("instance_class"),
            },

            "configuration": configuration,

            "relationships": {
                key: value
                for key, value in relationships.items()
                if key != "cluster"
            },

            "cluster": relationships.get(
                "cluster",
                {},
            ),

            "activity": derived,

            "cloudwatch": {
                "namespace":
                    cloudwatch.get("namespace"),
                "analysis_start":
                    cloudwatch.get("analysis_start"),
                "analysis_end":
                    cloudwatch.get("analysis_end"),
                "requested_period":
                    cloudwatch.get("requested_period"),
                "metric_count":
                    len(
                        cloudwatch.get("metrics", {})
                        or {}
                    ),
            },

            "cloudtrail": cloudtrail,

            "pricing": pricing,

            "cost_drivers": {
                "compute":
                    identity.get("instance_class"),
                "storage":
                    self._dict(
                        configuration.get("storage")
                    ),
                "iops":
                    self._dict(
                        configuration.get("storage")
                    ).get("iops"),
                "throughput_mibps":
                    self._dict(
                        configuration.get("storage")
                    ).get("storage_throughput_mibps"),
                "multi_az":
                    self._dict(
                        configuration.get("deployment")
                    ).get("multi_az"),
                "backup_retention_days":
                    self._dict(
                        configuration.get("backup")
                    ).get("backup_retention_days"),
                "performance_insights_enabled":
                    self._dict(
                        configuration.get("performance")
                    ).get("performance_insights_enabled"),
            },

            "data_quality": {
                "cloudwatch_available":
                    bool(
                        cloudwatch.get("metrics")
                    ),
                "cloudtrail_available":
                    cloudtrail.get("status") == "ok",
                "reserved_instance_context_available":
                    bool(pricing),
                "topology_available":
                    self._dict(
                        collected_resource.get(
                            "topology"
                        )
                    ).get("status") == "ok",
            },
        }

    # ------------------------------------------------------------------
    # Aurora cluster context
    # ------------------------------------------------------------------

    def _collect_cluster_context(
        self,
        cluster_id: Optional[str],
    ) -> Dict[str, Any]:
        if not cluster_id:
            return {
                "present": False,
                "status": "not_applicable",
                "cluster_id": None,
            }

        try:
            response = self.rds.describe_db_clusters(
                DBClusterIdentifier=cluster_id
            )
        except Exception as exc:
            return {
                "present": True,
                "status": "error",
                "cluster_id": cluster_id,
                "error": str(exc),
            }

        clusters = response.get(
            "DBClusters",
            [],
        ) or []

        if not clusters:
            return {
                "present": True,
                "status": "not_found",
                "cluster_id": cluster_id,
            }

        cluster = clusters[0]

        scaling_v2 = self._dict(
            cluster.get(
                "ServerlessV2ScalingConfiguration"
            )
        )

        members = []

        for member in cluster.get(
            "DBClusterMembers",
            [],
        ) or []:
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
                    "db_cluster_parameter_group_status":
                        member.get(
                            "DBClusterParameterGroupStatus"
                        ),
                }
            )

        return {
            "present": True,
            "status": "ok",

            "cluster_id":
                cluster.get("DBClusterIdentifier"),

            "cluster_arn":
                cluster.get("DBClusterArn"),

            "engine":
                cluster.get("Engine"),

            "engine_mode":
                cluster.get("EngineMode"),

            "engine_version":
                cluster.get("EngineVersion"),

            "status_value":
                cluster.get("Status"),

            "storage_type":
                cluster.get("StorageType"),

            "allocated_storage":
                cluster.get("AllocatedStorage"),

            "backup_retention_days":
                cluster.get("BackupRetentionPeriod"),

            "preferred_backup_window":
                cluster.get("PreferredBackupWindow"),

            "preferred_maintenance_window":
                cluster.get("PreferredMaintenanceWindow"),

            "deletion_protection":
                cluster.get("DeletionProtection"),

            "storage_encrypted":
                cluster.get("StorageEncrypted"),

            "kms_key_id":
                cluster.get("KmsKeyId"),

            "iam_database_authentication_enabled":
                cluster.get(
                    "IAMDatabaseAuthenticationEnabled"
                ),

            "copy_tags_to_snapshot":
                cluster.get("CopyTagsToSnapshot"),

            "global_cluster_identifier":
                cluster.get(
                    "GlobalClusterIdentifier"
                ),

            "reader_endpoint":
                cluster.get("ReaderEndpoint"),

            "endpoint":
                cluster.get("Endpoint"),

            "scaling_configuration_v1":
                self._dict(
                    cluster.get(
                        "ScalingConfigurationInfo"
                    )
                ),

            "serverless_v2_scaling":
                {
                    "min_capacity":
                        scaling_v2.get("MinCapacity"),
                    "max_capacity":
                        scaling_v2.get("MaxCapacity"),
                    "seconds_until_auto_pause":
                        scaling_v2.get(
                            "SecondsUntilAutoPause"
                        ),
                },

            "serverless_v2_enabled":
                bool(scaling_v2),

            "members":
                members,

            "writer_count":
                sum(
                    1
                    for member in members
                    if member.get("is_writer")
                ),

            "reader_count":
                sum(
                    1
                    for member in members
                    if not member.get("is_writer")
                ),
        }

    # ------------------------------------------------------------------
    # Reserved Instance context
    # ------------------------------------------------------------------

    def _load_reserved_instances(
        self,
    ) -> List[Dict[str, Any]]:
        if self._reserved_cache is not None:
            return self._reserved_cache

        reservations: list[Dict[str, Any]] = []

        try:
            paginator = self.rds.get_paginator(
                "describe_reserved_db_instances"
            )

            for page in paginator.paginate():
                for item in page.get(
                    "ReservedDBInstances",
                    [],
                ) or []:
                    if not isinstance(item, dict):
                        continue

                    reservations.append(
                        {
                            "reserved_db_instance_id":
                                item.get(
                                    "ReservedDBInstanceId"
                                ),
                            "db_instance_class":
                                item.get(
                                    "DBInstanceClass"
                                ),
                            "product_description":
                                item.get(
                                    "ProductDescription"
                                ),
                            "duration":
                                item.get("Duration"),
                            "state":
                                item.get("State"),
                            "fixed_price":
                                item.get("FixedPrice"),
                            "usage_price":
                                item.get("UsagePrice"),
                            "recurring_charges":
                                item.get(
                                    "RecurringCharges"
                                ),
                            "start_time":
                                self._isoformat(
                                    item.get("StartTime")
                                ),
                            "end_time":
                                self._isoformat(
                                    item.get("EndTime")
                                ),
                            "lease_id":
                                item.get("LeaseId"),
                            "offering_type":
                                item.get("OfferingType"),
                            "multi_az":
                                item.get("MultiAZ"),
                            "instance_count":
                                item.get(
                                    "InstanceCount"
                                ),
                        }
                    )

        except Exception as exc:
            self._reserved_cache = [
                {
                    "collection_error":
                        str(exc),
                }
            ]
            return self._reserved_cache

        self._reserved_cache = reservations
        return reservations

    def _reserved_instance_context(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw = self._dict(resource.get("raw"))

        instance_class = raw.get(
            "DBInstanceClass"
        )
        engine = str(
            raw.get(
                "Engine",
                "",
            )
        ).lower()
        multi_az = raw.get("MultiAZ")

        matches = []

        for reservation in self._load_reserved_instances():
            if reservation.get("collection_error"):
                continue

            reserved_class = reservation.get(
                "db_instance_class"
            )

            if (
                instance_class
                and reserved_class
                and reserved_class != instance_class
            ):
                continue

            product = str(
                reservation.get(
                    "product_description",
                    "",
                )
                or ""
            ).lower()

            engine_match = (
                not engine
                or not product
                or engine in product
                or product in engine
            )

            multi_az_value = reservation.get(
                "multi_az"
            )

            deployment_match = (
                multi_az_value is None
                or multi_az_value == multi_az
            )

            if engine_match and deployment_match:
                matches.append(reservation)

        active_matches = [
            item
            for item in matches
            if str(item.get("state", "")).lower()
            == "active"
        ]

        return {
            "status": "ok",
            "current_instance_class":
                instance_class,
            "engine":
                raw.get("Engine"),
            "multi_az":
                multi_az,
            "matching_reservation_count":
                len(matches),
            "active_matching_reservation_count":
                len(active_matches),
            "matching_reservations":
                matches,
        }

    # ------------------------------------------------------------------
    # CloudTrail class-change history
    # ------------------------------------------------------------------

    def _collect_instance_class_history(
        self,
        identifier: str,
        start: datetime,
        end: datetime,
        current_instance_class: Optional[str] = None,
    ) -> Dict[str, Any]:
        cloudtrail_profile = self._section("cloudtrail")

        event_names = cloudtrail_profile.get(
            "event_names",
            ["ModifyDBInstance"],
        )

        if not isinstance(event_names, list):
            event_names = ["ModifyDBInstance"]

        events: list[dict[str, Any]] = []
        seen: set[str] = set()

        try:
            for event_name in event_names:
                if not isinstance(event_name, str):
                    continue

                paginator = self.cloudtrail.get_paginator(
                    "lookup_events"
                )

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
                                cloudtrail_profile.get(
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
                        if not isinstance(event, dict):
                            continue

                        event_id = str(
                            event.get(
                                "EventId"
                            )
                            or ""
                        )

                        if event_id and event_id in seen:
                            continue

                        raw_event = event.get(
                            "CloudTrailEvent"
                        )

                        if not raw_event:
                            continue

                        try:
                            parsed = json.loads(
                                raw_event
                            )
                        except (
                            TypeError,
                            ValueError,
                        ):
                            continue

                        request = self._dict(
                            parsed.get(
                                "requestParameters"
                            )
                        )

                        event_identifier = (
                            request.get(
                                "dBInstanceIdentifier"
                            )
                            or request.get(
                                "DBInstanceIdentifier"
                            )
                        )

                        if str(
                            event_identifier
                            or ""
                        ) != str(identifier):
                            continue

                        target_class = (
                            request.get(
                                "dBInstanceClass"
                            )
                            or request.get(
                                "DBInstanceClass"
                            )
                        )

                        if not target_class:
                            continue

                        seen.add(event_id)

                        events.append(
                            {
                                "event_id":
                                    event_id,
                                "event_time":
                                    self._isoformat(
                                        event.get(
                                            "EventTime"
                                        )
                                    ),
                                "event_name":
                                    event.get(
                                        "EventName"
                                    ),
                                "instance_class":
                                    str(
                                        target_class
                                    ),
                                "previous_instance_class":
                                    self._dict(
                                        parsed.get(
                                            "responseElements"
                                        )
                                    ).get(
                                        "previousDBInstanceClass"
                                    ),
                                "apply_immediately":
                                    request.get(
                                        "applyImmediately"
                                    ),
                                "username":
                                    event.get(
                                        "Username"
                                    ),
                                "source_ip_address":
                                    parsed.get(
                                        "sourceIPAddress"
                                    ),
                            }
                        )

        except Exception as exc:
            return {
                "status": "error",
                "source": "cloudtrail",
                "events": [],
                "change_count": 0,
                "class_changed_during_observation": False,
                "current_instance_class":
                    current_instance_class,
                "error": str(exc),
            }

        events.sort(
            key=lambda item:
                item.get("event_time") or ""
        )

        last_change = (
            events[-1]
            if events
            else None
        )

        days_since_last_change = None

        if last_change and last_change.get(
            "event_time"
        ):
            try:
                changed_at = datetime.fromisoformat(
                    str(
                        last_change["event_time"]
                    ).replace(
                        "Z",
                        "+00:00",
                    )
                )

                if changed_at.tzinfo is None:
                    changed_at = changed_at.replace(
                        tzinfo=timezone.utc
                    )

                end_aware = end
                if end_aware.tzinfo is None:
                    end_aware = end_aware.replace(
                        tzinfo=timezone.utc
                    )

                days_since_last_change = max(
                    0.0,
                    (
                        end_aware - changed_at
                    ).total_seconds()
                    / 86400.0,
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        return {
            "status": "ok",
            "source": "cloudtrail",
            "events": events,
            "event_count": len(events),
            "change_count": len(events),
            "last_change_at":
                last_change.get("event_time")
                if last_change
                else None,
            "last_changed_to_class":
                last_change.get(
                    "instance_class"
                )
                if last_change
                else None,
            "days_since_last_change":
                days_since_last_change,
            "class_changed_during_observation":
                bool(events),
            "current_instance_class":
                current_instance_class,
        }

    # ------------------------------------------------------------------
    # Activity pattern
    # ------------------------------------------------------------------

    @staticmethod
    def _build_activity_pattern(
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build a conservative activity summary.

        It does not decide whether a schedule is safe. It only exposes
        repeated low/high activity patterns for the analyzer.
        """
        candidate_names = (
            "CPUUtilization",
            "DatabaseConnections",
            "ReadIOPS",
            "WriteIOPS",
        )

        observed = []

        for name in candidate_names:
            metric = metrics.get(name)
            if not isinstance(metric, dict):
                continue

            raw = metric.get("raw_datapoints", [])
            if not isinstance(raw, list):
                continue

            for point in raw:
                if not isinstance(point, dict):
                    continue

                value = point.get("value")
                timestamp = point.get("timestamp")

                if value is None or timestamp is None:
                    continue

                try:
                    numeric = float(value)
                except (
                    TypeError,
                    ValueError,
                ):
                    continue

                observed.append(
                    {
                        "metric": name,
                        "timestamp": str(timestamp),
                        "value": numeric,
                    }
                )

        return {
            "status":
                "ok" if observed else "no_data",
            "observed_samples":
                len(observed),
            "samples":
                observed,
            "purpose":
                "scheduling_and_activity_analysis",
            "missing_is_zero":
                False,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _tags(
        tags: Any,
    ) -> dict[str, Any]:
        if not isinstance(tags, list):
            return {}

        return {
            str(item["Key"]):
                item.get("Value")
            for item in tags
            if isinstance(item, dict)
            and item.get("Key")
        }

    @staticmethod
    def _endpoint(
        endpoint: Any,
    ) -> dict[str, Any]:
        if not isinstance(endpoint, dict):
            return {}

        return {
            "address":
                endpoint.get("Address"),
            "port":
                endpoint.get("Port"),
            "hosted_zone_id":
                endpoint.get("HostedZoneId"),
        }

    @staticmethod
    def _isoformat(
        value: Any,
    ) -> Optional[str]:
        if value is None:
            return None

        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(
                    tzinfo=timezone.utc
                )
            else:
                value = value.astimezone(
                    timezone.utc
                )

            return value.isoformat()

        if hasattr(value, "isoformat"):
            return value.isoformat()

        return str(value)