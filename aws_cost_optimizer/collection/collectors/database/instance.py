"""
RDS DB-instance collector.

"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from aws_cost_optimizer.config.client import get_client

from ...base import BaseCollector
from ...registry import register
from ...metrics.cloudwatch import CloudWatchMetricCollector
from ...shared.topology import NetworkTopologyCollector


@register
class RDSCollector(BaseCollector):

    key = "rds"
    resource_type = "rds_instance"

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
            raise ValueError("RDS collector requires a region.")

        self.rds = get_client(
            "rds",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.cloudtrail = get_client(
            "cloudtrail",
            self.region,
        )

        self.metric_collector = CloudWatchMetricCollector(self.cloudwatch)

        self.topology_collector = NetworkTopologyCollector(self.region)

        self._metrics_batch_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._reserved_cache: Optional[List[Dict[str, Any]]] = None

        self._reserved_offerings_cache: Dict[
            Tuple[str, str, bool],
            List[Dict[str, Any]],
        ] = {}

        self._snapshot_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

        self._automated_backup_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

        self._cluster_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

    def _section(
        self,
        name: str,
    ) -> dict[str, Any]:

        value = (
            self.profile.get(
                name,
                {},
            )
            if isinstance(
                self.profile,
                dict,
            )
            else {}
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
    def _enabled(
        section: dict[str, Any],
        default: bool = False,
    ) -> bool:

        if not isinstance(
            section,
            dict,
        ):
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

        return self._section("observations").get(
            "cloudwatch",
            {},
        )

    def _metric_specs(
        self,
    ) -> list[dict[str, Any]]:

        value = self._cloudwatch_profile().get(
            "metrics",
            [],
        )

        if not isinstance(
            value,
            list,
        ):
            return []

        return [
            item
            for item in value
            if isinstance(
                item,
                dict,
            )
        ]

    def _requested_period(
        self,
    ) -> int:

        return self.cloudwatch_period()

    def _cloudtrail_profile(
        self,
    ) -> dict[str, Any]:

        return self._section("cloudtrail")

    def _retirement_profile(
        self,
    ) -> dict[str, Any]:

        return self._section("retirement")

    def _pricing_profile(
        self,
    ) -> dict[str, Any]:

        return self._section("pricing")

    def _environment_profile(
        self,
    ) -> dict[str, Any]:

        return self._section("environment")

    def _collect_resource(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        if self._is_aurora_instance(resource):
            raise ValueError(
                "RDSCollector must not collect Aurora DB instances. "
                "Aurora resources are owned by AuroraClusterCollector."
            )

        collected = super()._collect_resource(resource)

        analyzer_config = self._section("analyzer_config")

        if analyzer_config:

            collected["analysis_policy"] = {
                "rds": analyzer_config,
            }

        return collected

    @staticmethod
    def _is_aurora_instance(
        resource: Dict[str, Any],
    ) -> bool:

        raw = resource.get("raw")

        if not isinstance(
            raw,
            dict,
        ):
            return False

        engine = str(raw.get("Engine") or "").strip().lower()

        return engine.startswith("aurora")

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        self._metrics_batch_cache = {}
        self._cluster_cache = {}
        self._snapshot_cache = {}
        self._automated_backup_cache = {}

        resources: list[Dict[str, Any]] = []

        paginator = self.rds.get_paginator("describe_db_instances")

        for page in paginator.paginate():

            for db in (
                page.get(
                    "DBInstances",
                    [],
                )
                or []
            ):

                if not isinstance(
                    db,
                    dict,
                ):
                    continue

                identifier = db.get("DBInstanceIdentifier")

                if not identifier:
                    continue

                engine = str(db.get("Engine") or "").strip().lower()

                if engine.startswith("aurora"):
                    continue

                resources.append(
                    {
                        "id": str(identifier),
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

        tags = self._tags(
            raw.get(
                "TagList",
                [],
            )
        )

        return {
            "name": (
                tags.get("Name")
                or raw.get("DBInstanceIdentifier")
                or resource.get("id")
            ),
            "db_instance_identifier": raw.get("DBInstanceIdentifier"),
            "db_instance_arn": raw.get("DBInstanceArn"),
            "db_instance_resource_id": raw.get("DbiResourceId"),
            "engine": raw.get("Engine"),
            "engine_version": raw.get("EngineVersion"),
            "instance_class": raw.get("DBInstanceClass"),
            "status": raw.get("DBInstanceStatus"),
            "created_at": self._isoformat(raw.get("InstanceCreateTime")),
            "availability_zone": raw.get("AvailabilityZone"),
            "preferred_maintenance_window": raw.get("PreferredMaintenanceWindow"),
            "preferred_backup_window": raw.get("PreferredBackupWindow"),
            "tags": tags,
        }

    def _derive_environment(
        self,
        tags: dict[str, Any],
        identifier: Optional[str],
    ) -> Dict[str, Any]:

        configured_keys = self._environment_profile().get(
            "tag_keys",
            [
                "Environment",
                "environment",
                "Env",
                "env",
            ],
        )

        if not isinstance(
            configured_keys,
            list,
        ):
            configured_keys = [
                "Environment",
                "environment",
                "Env",
                "env",
            ]

        environment = None
        environment_source = None

        for key in configured_keys:

            if not isinstance(
                key,
                str,
            ):
                continue

            value = tags.get(key)

            if value is None:
                continue

            value = str(value).strip()

            if not value:
                continue

            environment = value
            environment_source = f"tag:{key}"
            break

        normalized = str(environment or "").strip().lower()

        development_values = {
            "dev",
            "development",
            "test",
            "testing",
            "qa",
            "staging",
            "sandbox",
            "nonprod",
            "non-production",
            "preprod",
        }

        if normalized in development_values:
            category = "non_production"

        else:
            category = "unknown"

        # Name is intentionally only a secondary signal.
        name_signal = False

        if identifier:

            lower_name = str(identifier).lower()

            name_tokens = (
                "-dev",
                "-test",
                "-testing",
                "-qa",
                "-sandbox",
                "-staging",
                "_dev",
                "_test",
                "_qa",
                "dev-",
                "test-",
            )

            name_signal = any(token in lower_name for token in name_tokens)

        return {
            "environment": environment,
            "environment_category": category,
            "environment_source": environment_source,
            "name_non_production_signal": name_signal,
            "confidence": (
                "high" if environment_source else ("low" if name_signal else "unknown")
            ),
        }

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = self._dict(resource.get("raw"))

        subnet_group = self._dict(raw.get("DBSubnetGroup"))

        tags = self._tags(
            raw.get(
                "TagList",
                [],
            )
        )

        environment = self._derive_environment(
            tags,
            raw.get("DBInstanceIdentifier"),
        )

        return {
            "status": raw.get("DBInstanceStatus"),
            "instance_class": raw.get("DBInstanceClass"),
            "engine": raw.get("Engine"),
            "engine_version": raw.get("EngineVersion"),
            "instance_create_time": self._isoformat(raw.get("InstanceCreateTime")),
            "deployment": {
                "multi_az": raw.get("MultiAZ"),
                "availability_zone": raw.get("AvailabilityZone"),
                "secondary_availability_zone": raw.get("SecondaryAvailabilityZone"),
                "availability_zone_group": raw.get("AvailabilityZone"),
            },
            "storage": {
                "storage_type": raw.get("StorageType"),
                "allocated_storage_gib": raw.get("AllocatedStorage"),
                "max_allocated_storage_gib": raw.get("MaxAllocatedStorage"),
                "iops": raw.get("Iops"),
                "storage_throughput_mibps": raw.get("StorageThroughput"),
                "storage_encrypted": raw.get("StorageEncrypted"),
                "kms_key_id": raw.get("KmsKeyId"),
            },
            "backup": {
                "backup_retention_days": raw.get("BackupRetentionPeriod"),
                "preferred_backup_window": raw.get("PreferredBackupWindow"),
                "copy_tags_to_snapshot": raw.get("CopyTagsToSnapshot"),
                "delete_automated_backups": raw.get("DeleteAutomatedBackups"),
            },
            "performance": {
                "performance_insights_enabled": raw.get("PerformanceInsightsEnabled"),
                "performance_insights_retention_days": raw.get(
                    "PerformanceInsightsRetentionPeriod"
                ),
                "performance_insights_kms_key_id": raw.get(
                    "PerformanceInsightsKMSKeyId"
                ),
                "monitoring_interval": raw.get("MonitoringInterval"),
                "monitoring_role_arn": raw.get("MonitoringRoleArn"),
            },
            "network": {
                "publicly_accessible": raw.get("PubliclyAccessible"),
                "subnet_group": subnet_group.get("DBSubnetGroupName"),
                "vpc_id": subnet_group.get("VpcId"),
                "endpoint": self._endpoint(raw.get("Endpoint")),
            },
            "availability": {
                "promotion_tier": raw.get("PromotionTier"),
                "preferred_maintenance_window": raw.get("PreferredMaintenanceWindow"),
            },
            "pricing": {
                "license_model": raw.get("LicenseModel"),
                "storage_type": raw.get("StorageType"),
                "engine": raw.get("Engine"),
                "engine_version": raw.get("EngineVersion"),
                "instance_class": raw.get("DBInstanceClass"),
                "multi_az": raw.get("MultiAZ"),
            },
            "cluster": {
                "db_cluster_identifier": raw.get("DBClusterIdentifier"),
                "read_replica_source": raw.get("ReadReplicaSourceDBInstanceIdentifier"),
                "read_replica_identifiers": list(
                    raw.get(
                        "ReadReplicaDBInstanceIdentifiers",
                        [],
                    )
                    or []
                ),
                "is_cluster_member": bool(raw.get("DBClusterIdentifier")),
            },
            "replica": {
                "is_read_replica": bool(
                    raw.get("ReadReplicaSourceDBInstanceIdentifier")
                ),
                "source_instance_identifier": raw.get(
                    "ReadReplicaSourceDBInstanceIdentifier"
                ),
                "replica_count_from_source": len(
                    raw.get(
                        "ReadReplicaDBInstanceIdentifiers",
                        [],
                    )
                    or []
                ),
                "replica_identifiers_from_source": list(
                    raw.get(
                        "ReadReplicaDBInstanceIdentifiers",
                        [],
                    )
                    or []
                ),
            },
            "environment": environment,
            "deletion_protection": raw.get("DeletionProtection"),
            "iam_database_authentication_enabled": raw.get(
                "IAMDatabaseAuthenticationEnabled"
            ),
            "auto_minor_version_upgrade": raw.get("AutoMinorVersionUpgrade"),
            "ca_certificate_identifier": raw.get("CACertificateIdentifier"),
            "timezone": raw.get("Timezone"),
            "character_set_name": raw.get("CharacterSetName"),
            "processor_features": raw.get("ProcessorFeatures"),
            "db_parameter_groups": raw.get(
                "DBParameterGroups",
                [],
            ),
            "option_group_memberships": raw.get(
                "OptionGroupMemberships",
                [],
            ),
            "license_model": raw.get("LicenseModel"),
            "availability_zone": raw.get("AvailabilityZone"),
            "monitoring_role_arn": raw.get("MonitoringRoleArn"),
            "tags": tags,
        }

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = self._dict(resource.get("raw"))

        subnet_group = self._dict(raw.get("DBSubnetGroup"))

        cluster_id = raw.get("DBClusterIdentifier")

        read_replica_source = raw.get("ReadReplicaSourceDBInstanceIdentifier")

        read_replicas = list(
            raw.get(
                "ReadReplicaDBInstanceIdentifiers",
                [],
            )
            or []
        )

        if read_replica_source:
            role = "read_replica"

        elif cluster_id:
            role = "cluster_member"

        elif read_replicas:
            role = "replica_source"

        else:
            role = "standalone"

        return {
            "status": "ok",
            "vpc_id": subnet_group.get("VpcId"),
            "db_subnet_group": subnet_group.get("DBSubnetGroupName"),
            "subnet_ids": [
                subnet.get("SubnetIdentifier")
                for subnet in (
                    subnet_group.get(
                        "Subnets",
                        [],
                    )
                    or []
                )
                if (
                    isinstance(
                        subnet,
                        dict,
                    )
                    and subnet.get("SubnetIdentifier")
                )
            ],
            "security_group_ids": [
                group.get("VpcSecurityGroupId")
                for group in (
                    raw.get(
                        "VpcSecurityGroups",
                        [],
                    )
                    or []
                )
                if (
                    isinstance(
                        group,
                        dict,
                    )
                    and group.get("VpcSecurityGroupId")
                )
            ],
            "db_cluster_identifier": cluster_id,
            "read_replica_source": read_replica_source,
            "read_replicas": read_replicas,
            "replica_role": role,
            "is_read_replica": bool(read_replica_source),
            "is_replica_source": bool(read_replicas),
            "associated_roles": raw.get(
                "AssociatedRoles",
                [],
            ),
            "domain_memberships": raw.get(
                "DomainMemberships",
                [],
            ),
            "cluster": self._collect_cluster_context(cluster_id),
        }

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

        metric_specs = self._metric_specs()

        if not metric_specs:
            return

        namespace = str(profile.get("namespace") or self.cloudwatch_namespace())

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
                            "Name": "DBInstanceIdentifier",
                            "Value": str(identifier),
                        }
                    ],
                    "metric_specs": metric_specs,
                }
            )

        if not requests:
            return

        self._metrics_batch_cache = self.metric_collector.collect_batch(
            requests,
            start=start,
            end=end,
            requested_period=(self._requested_period()),
        )

    # ==================================================================
    # OBSERVATIONS
    # ==================================================================

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
                "cloudwatch": {},
                "derived": {},
            }

        identifier = resource.get("id")

        if not identifier:
            return {
                "status": "incomplete",
                "reason": "DB instance identifier unavailable",
            }

        start, end = self.get_analysis_period()

        namespace = str(profile.get("namespace") or self.cloudwatch_namespace())

        results = self._metrics_batch_cache.get(
            str(identifier),
            [],
        )

        # ----------------------------------------------------------
        # IMPORTANT: this profile deliberately queries some metrics
        # twice under the same metric_name with different statistics
        # (e.g. CPUUtilization/Average + CPUUtilization/Maximum,
        # distinguished only by "key"). A plain metric_name -> result
        # dict comprehension would let the second query silently
        # overwrite the first, destroying one of the two statistics.
        # Merge same-name results into one canonical entry instead,
        # while also keeping each statistic addressable by its own
        # metric_key for callers that want the raw series.
        # ----------------------------------------------------------

        metrics: dict = {}

        for result in results:

            if not (isinstance(result, dict) and result.get("metric_name")):
                continue

            name = result.get("metric_name")

            metric_key = result.get("metric_key")

            if metric_key and metric_key != name:
                metrics[metric_key] = result

            statistic = str(result.get("statistic") or "").strip().lower()

            existing = metrics.get(name)

            if existing is None:
                metrics[name] = dict(result)
                continue

            # Merge this statistic's aggregate fields into the
            # canonical entry rather than replacing it outright.
            if statistic == "average":

                existing["average"] = result.get("average")

                if existing.get("value") is None:
                    existing["value"] = result.get("value")

                if result.get("has_data"):
                    existing["has_data"] = True
                    existing["status"] = result.get("status", existing.get("status"))

            elif statistic == "maximum":

                existing["maximum"] = result.get("maximum")

                if result.get("has_data"):
                    existing["has_data"] = existing.get("has_data") or True

            elif statistic == "minimum":

                existing["minimum"] = result.get("minimum")

                if result.get("has_data"):
                    existing["has_data"] = existing.get("has_data") or True

        expected_metric_names = sorted(
            {
                str(spec.get("name")).strip()
                for spec in metric_specs_or_empty(profile)
                if str(spec.get("name") or "").strip()
            }
        )

        actual_metric_names = set(metrics.keys())

        missing_metrics = sorted(set(expected_metric_names) - actual_metric_names)

        metric_errors = sorted(
            {
                str(metric.get("error"))
                for metric in metrics.values()
                if (
                    isinstance(
                        metric,
                        dict,
                    )
                    and metric.get("status") == "error"
                    and metric.get("error")
                )
            }
        )

        if not results:
            observation_status = "no_data"

        elif metric_errors:
            observation_status = "error"

        elif missing_metrics:
            observation_status = "partial"

        else:
            observation_status = "ok"

        cloudwatch = {
            "status": observation_status,
            "namespace": namespace,
            "dimensions": [
                {
                    "Name": "DBInstanceIdentifier",
                    "Value": str(identifier),
                }
            ],
            "analysis_start": start.isoformat(),
            "analysis_end": end.isoformat(),
            "start": start.isoformat(),
            "end": end.isoformat(),
            "requested_period": self._requested_period(),
            "metrics": metrics,
            "expected_metric_names": expected_metric_names,
            "missing_metric_names": missing_metrics,
            "metric_errors": metric_errors,
        }

        observations = {
            "cloudwatch": cloudwatch,
        }

        cloudtrail_profile = self._cloudtrail_profile()

        if self._enabled(
            cloudtrail_profile,
            default=False,
        ):

            current_class = self._dict(resource.get("raw")).get("DBInstanceClass")
            observations["cloudtrail"] = self._collect_instance_events(
                identifier=str(identifier),
                start=start,
                end=end,
                current_instance_class=current_class,
            )
        retirement_profile = self._retirement_profile()

        retirement_enabled = self._enabled(
            retirement_profile,
            default=True,
        )

        if retirement_enabled:

            observations["retirement"] = self._collect_retirement_context(
                resource=resource,
                analysis_end=end,
            )
        pricing_profile = self._pricing_profile()

        if self._enabled(
            pricing_profile,
            default=False,
        ):
            observations["pricing"] = {
                "reserved_instance_context": self._reserved_instance_context(resource)
            }
        observations["derived"] = self._build_activity_pattern(metrics)
        return observations

    def _collect_retirement_context(
        self,
        resource: Dict[str, Any],
        analysis_end: datetime,
    ) -> Dict[str, Any]:

        raw = self._dict(resource.get("raw"))

        identifier = str(raw.get("DBInstanceIdentifier") or resource.get("id") or "")

        snapshots = self._collect_manual_snapshots(
            identifier=identifier,
            analysis_end=analysis_end,
        )

        automated_backups = self._collect_automated_backups(identifier=identifier)

        tags = self._tags(
            raw.get(
                "TagList",
                [],
            )
        )

        environment = self._derive_environment(
            tags,
            identifier,
        )

        return {
            "status": "ok",
            "instance_status": raw.get("DBInstanceStatus"),
            "engine": raw.get("Engine"),
            "instance_class": raw.get("DBInstanceClass"),
            "cluster_identifier": raw.get("DBClusterIdentifier"),
            "environment": environment,
            "manual_snapshots": snapshots,
            "automated_backups": automated_backups,
            "backup_retention_days": raw.get("BackupRetentionPeriod"),
            "deletion_protection": raw.get("DeletionProtection"),
            "instance_create_time": self._isoformat(raw.get("InstanceCreateTime")),
        }

    def _collect_manual_snapshots(
        self,
        identifier: str,
        analysis_end: datetime,
    ) -> Dict[str, Any]:

        cached = self._snapshot_cache.get(identifier)

        if cached is not None:
            return cached

        if not identifier:
            return {
                "status": "not_available",
                "snapshot_count": 0,
                "snapshots": [],
                "latest_snapshot": None,
            }

        snapshots: list[Dict[str, Any]] = []

        try:

            paginator = self.rds.get_paginator("describe_db_snapshots")

            for page in paginator.paginate(
                DBInstanceIdentifier=identifier,
                SnapshotType="manual",
            ):

                values = page.get(
                    "DBSnapshots",
                    [],
                )

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                for snapshot in values:

                    if not isinstance(
                        snapshot,
                        dict,
                    ):
                        continue

                    snapshot_id = snapshot.get("DBSnapshotIdentifier")

                    if not snapshot_id:
                        continue

                    create_time = snapshot.get("SnapshotCreateTime")

                    age_days = self._age_days(
                        create_time,
                        analysis_end,
                    )

                    snapshots.append(
                        {
                            "snapshot_identifier": snapshot_id,
                            "snapshot_arn": snapshot.get("DBSnapshotArn"),
                            "instance_identifier": snapshot.get("DBInstanceIdentifier"),
                            "snapshot_create_time": self._isoformat(create_time),
                            "age_days": age_days,
                            "status": snapshot.get("Status"),
                            "allocated_storage_gib": snapshot.get("AllocatedStorage"),
                            "storage_type": snapshot.get("StorageType"),
                            "encrypted": snapshot.get("Encrypted"),
                            "engine": snapshot.get("Engine"),
                            "engine_version": snapshot.get("EngineVersion"),
                            "snapshot_type": snapshot.get("SnapshotType"),
                        }
                    )

        except Exception as exc:

            result = {
                "status": "error",
                "snapshot_count": 0,
                "snapshots": [],
                "latest_snapshot": None,
                "error": self._error_text(exc),
            }

            self._snapshot_cache[identifier] = result

            return result

        snapshots.sort(
            key=lambda item: item.get("snapshot_create_time") or "",
            reverse=True,
        )

        latest = snapshots[0] if snapshots else None

        result = {
            "status": "ok",
            "snapshot_count": len(snapshots),
            "snapshots": snapshots,
            "latest_snapshot": latest,
            "manual_snapshot_count": len(snapshots),
            "oldest_snapshot_age_days": (
                max(
                    (
                        item.get("age_days")
                        for item in snapshots
                        if isinstance(
                            item.get("age_days"),
                            (int, float),
                        )
                    ),
                    default=None,
                )
            ),
        }

        self._snapshot_cache[identifier] = result

        return result

    def _collect_automated_backups(
        self,
        identifier: str,
    ) -> Dict[str, Any]:

        cached = self._automated_backup_cache.get(identifier)

        if cached is not None:
            return cached

        if not identifier:
            return {
                "status": "not_available",
                "backup_count": 0,
                "backups": [],
            }

        backups: list[Dict[str, Any]] = []

        try:

            paginator = self.rds.get_paginator("describe_db_instance_automated_backups")

            for page in paginator.paginate(DBInstanceIdentifier=identifier):

                values = page.get(
                    "DBInstanceAutomatedBackups",
                    [],
                )

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                for backup in values:

                    if not isinstance(
                        backup,
                        dict,
                    ):
                        continue

                    backups.append(
                        {
                            "db_instance_identifier": backup.get(
                                "DBInstanceIdentifier"
                            ),
                            "db_instance_automated_backups_arn": backup.get(
                                "DBInstanceAutomatedBackupsArn"
                            ),
                            "status": backup.get("Status"),
                            "restore_window": backup.get("RestoreWindow"),
                            "allocated_storage": backup.get("AllocatedStorage"),
                            "storage_type": backup.get("StorageType"),
                            "engine": backup.get("Engine"),
                            "engine_version": backup.get("EngineVersion"),
                            "region": backup.get("Region"),
                            "instance_create_time": self._isoformat(
                                backup.get("InstanceCreateTime")
                            ),
                            "backup_retention_period": backup.get(
                                "BackupRetentionPeriod"
                            ),
                            "db_instance_resource_id": backup.get("DbiResourceId"),
                        }
                    )

        except Exception as exc:

            result = {
                "status": "error",
                "backup_count": 0,
                "backups": [],
                "error": self._error_text(exc),
            }

            self._automated_backup_cache[identifier] = result

            return result

        result = {
            "status": "ok",
            "backup_count": len(backups),
            "backups": backups,
            "active_count": sum(
                1
                for item in backups
                if str(item.get("status") or "").lower() == "active"
            ),
            "retained_count": sum(
                1
                for item in backups
                if str(item.get("status") or "").lower() == "retained"
            ),
        }

        self._automated_backup_cache[identifier] = result

        return result

    def _collect_instance_events(
        self,
        identifier: str,
        start: datetime,
        end: datetime,
        current_instance_class: Optional[str] = None,
    ) -> Dict[str, Any]:

        profile = self._cloudtrail_profile()

        event_names = profile.get(
            "event_names",
            [
                "ModifyDBInstance",
                "StartDBInstance",
                "StopDBInstance",
                "RebootDBInstance",
                "DeleteDBInstance",
                "RestoreDBInstance",
                "CreateDBInstance",
            ],
        )

        if not isinstance(
            event_names,
            list,
        ):
            event_names = [
                "ModifyDBInstance",
                "StartDBInstance",
                "StopDBInstance",
                "RebootDBInstance",
                "DeleteDBInstance",
                "RestoreDBInstance",
                "CreateDBInstance",
            ]

        max_results = self._safe_int(
            profile.get(
                "max_results",
                50,
            ),
            50,
            minimum=1,
            maximum=50,
        )

        events: list[Dict[str, Any]] = []

        seen: set[str] = set()

        try:

            for event_name in event_names:

                if not isinstance(
                    event_name,
                    str,
                ):
                    continue

                paginator = self.cloudtrail.get_paginator("lookup_events")

                for page in paginator.paginate(
                    LookupAttributes=[
                        {
                            "AttributeKey": "EventName",
                            "AttributeValue": event_name,
                        }
                    ],
                    StartTime=start,
                    EndTime=end,
                    MaxResults=max_results,
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

                        raw_event = event.get("CloudTrailEvent")

                        if not raw_event:
                            continue

                        try:
                            parsed = json.loads(raw_event)

                        except (
                            TypeError,
                            ValueError,
                        ):
                            continue

                        request = self._dict(parsed.get("requestParameters"))

                        event_identifier = request.get(
                            "dBInstanceIdentifier"
                        ) or request.get("DBInstanceIdentifier")

                        if str(event_identifier or "") != str(identifier):
                            continue

                        target_class = request.get("dBInstanceClass") or request.get(
                            "DBInstanceClass"
                        )

                        seen.add(event_id)

                        events.append(
                            {
                                "event_id": event_id,
                                "event_time": self._isoformat(event.get("EventTime")),
                                "event_name": event.get("EventName"),
                                "instance_class": (
                                    str(target_class) if target_class else None
                                ),
                                "previous_instance_class": self._dict(
                                    parsed.get("responseElements")
                                ).get("previousDBInstanceClass"),
                                "apply_immediately": request.get("applyImmediately"),
                                "username": event.get("Username"),
                                "source_ip_address": parsed.get("sourceIPAddress"),
                                "read_only": event.get("ReadOnly"),
                            }
                        )

        except Exception as exc:

            return {
                "status": "error",
                "source": "cloudtrail",
                "events": [],
                "event_count": 0,
                "change_count": 0,
                "resize_count": 0,
                "start_count": 0,
                "stop_count": 0,
                "delete_count": 0,
                "create_count": 0,
                "reboot_count": 0,
                "class_changed_during_observation": False,
                "current_instance_class": current_instance_class,
                "error": self._error_text(exc),
            }

        events.sort(key=lambda item: item.get("event_time") or "")

        resize_events = [
            event
            for event in events
            if event.get("event_name") == "ModifyDBInstance"
            and event.get("instance_class")
        ]

        stop_events = [
            event for event in events if event.get("event_name") == "StopDBInstance"
        ]

        start_events = [
            event for event in events if event.get("event_name") == "StartDBInstance"
        ]

        delete_events = [
            event for event in events if event.get("event_name") == "DeleteDBInstance"
        ]

        create_events = [
            event for event in events if event.get("event_name") == "CreateDBInstance"
        ]

        reboot_events = [
            event for event in events if event.get("event_name") == "RebootDBInstance"
        ]

        last_change = resize_events[-1] if resize_events else None

        days_since_last_change = None

        if last_change and last_change.get("event_time"):

            days_since_last_change = self._event_age_days(
                last_change.get("event_time"),
                end,
            )

        return {
            "status": "ok",
            "source": "cloudtrail",
            "events": events,
            "event_count": len(events),
            "change_count": len(resize_events),
            "resize_count": len(resize_events),
            "start_count": len(start_events),
            "stop_count": len(stop_events),
            "delete_count": len(delete_events),
            "create_count": len(create_events),
            "reboot_count": len(reboot_events),
            "last_change_at": (last_change.get("event_time") if last_change else None),
            "last_changed_to_class": (
                last_change.get("instance_class") if last_change else None
            ),
            "days_since_last_change": days_since_last_change,
            "last_start_at": (
                start_events[-1].get("event_time") if start_events else None
            ),
            "last_stop_at": (
                stop_events[-1].get("event_time") if stop_events else None
            ),
            "last_delete_at": (
                delete_events[-1].get("event_time") if delete_events else None
            ),
            "class_changed_during_observation": bool(resize_events),
            "current_instance_class": current_instance_class,
            "lifecycle_event_count": (
                len(start_events)
                + len(stop_events)
                + len(delete_events)
                + len(create_events)
                + len(reboot_events)
            ),
            "has_start_stop_activity": bool(start_events or stop_events),
        }

    def _load_reserved_instances(
        self,
    ) -> List[Dict[str, Any]]:

        if self._reserved_cache is not None:
            return self._reserved_cache

        reservations: list[Dict[str, Any]] = []

        try:

            paginator = self.rds.get_paginator("describe_reserved_db_instances")

            for page in paginator.paginate():

                values = page.get(
                    "ReservedDBInstances",
                    [],
                )

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                for item in values:

                    if not isinstance(
                        item,
                        dict,
                    ):
                        continue

                    reservations.append(
                        {
                            "reserved_db_instance_id": item.get("ReservedDBInstanceId"),
                            "db_instance_class": item.get("DBInstanceClass"),
                            "product_description": item.get("ProductDescription"),
                            "duration": item.get("Duration"),
                            "state": item.get("State"),
                            "fixed_price": item.get("FixedPrice"),
                            "usage_price": item.get("UsagePrice"),
                            "recurring_charges": item.get("RecurringCharges"),
                            "start_time": self._isoformat(item.get("StartTime")),
                            "end_time": self._isoformat(item.get("EndTime")),
                            "lease_id": item.get("LeaseId"),
                            "offering_type": item.get("OfferingType"),
                            "multi_az": item.get("MultiAZ"),
                            "instance_count": (
                                item.get("DBInstanceCount")
                                if item.get("DBInstanceCount") is not None
                                else item.get("InstanceCount")
                            ),
                            "offering_id": item.get("ReservedDBInstancesOfferingId"),
                        }
                    )

        except Exception as exc:

            self._reserved_cache = [{"collection_error": self._error_text(exc)}]

            return self._reserved_cache

        self._reserved_cache = reservations

        return reservations

    def _load_reserved_offerings(
        self,
        instance_class: Optional[str],
        engine: Optional[str],
        multi_az: Optional[bool],
    ) -> List[Dict[str, Any]]:

        if not instance_class:
            return []

        key = (
            str(instance_class),
            str(engine or "").lower(),
            bool(multi_az),
        )

        cached = self._reserved_offerings_cache.get(key)

        if cached is not None:
            return cached

        offerings: list[Dict[str, Any]] = []

        try:

            paginator = self.rds.get_paginator(
                "describe_reserved_db_instances_offerings"
            )

            for page in paginator.paginate(
                DBInstanceClass=str(instance_class),
                MultiAZ=(multi_az if multi_az is not None else False),
            ):

                values = page.get(
                    "ReservedDBInstancesOfferings",
                    [],
                )

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                for item in values:

                    if not isinstance(
                        item,
                        dict,
                    ):
                        continue

                    product = str(
                        item.get(
                            "ProductDescription",
                            "",
                        )
                        or ""
                    ).lower()

                    if not self._engine_matches_product(
                        engine,
                        product,
                    ):
                        continue

                    offerings.append(
                        {
                            "reserved_db_instances_offering_id": item.get(
                                "ReservedDBInstancesOfferingId"
                            ),
                            "db_instance_class": item.get("DBInstanceClass"),
                            "product_description": item.get("ProductDescription"),
                            "duration": item.get("Duration"),
                            "fixed_price": item.get("FixedPrice"),
                            "usage_price": item.get("UsagePrice"),
                            "recurring_charges": item.get("RecurringCharges"),
                            "multi_az": item.get("MultiAZ"),
                            "offering_type": item.get("OfferingType"),
                            "currency_code": item.get("CurrencyCode"),
                        }
                    )

        except Exception as exc:

            offerings = [{"collection_error": self._error_text(exc)}]

        self._reserved_offerings_cache[key] = offerings

        return offerings

    @staticmethod
    def _engine_matches_product(
        engine: Optional[str],
        product: str,
    ) -> bool:

        if not engine:
            return True

        engine_value = str(engine).lower()

        product_value = str(product or "").lower()

        if not product_value:
            return True

        aliases = {
            "postgres": (
                "postgres",
                "aurora-postgresql",
            ),
            "aurora-postgresql": (
                "aurora-postgresql",
                "postgres",
            ),
            "mysql": (
                "mysql",
                "aurora-mysql",
            ),
            "aurora-mysql": (
                "aurora-mysql",
                "mysql",
            ),
            "mariadb": ("mariadb",),
            "oracle-ee": ("oracle",),
            "oracle-se2": ("oracle",),
            "sqlserver-ee": ("sqlserver",),
            "sqlserver-se": ("sqlserver",),
            "sqlserver-ex": ("sqlserver",),
            "sqlserver-web": ("sqlserver",),
        }

        candidates = aliases.get(
            engine_value,
            (engine_value,),
        )

        return any(candidate in product_value for candidate in candidates)

    def _reserved_instance_context(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = self._dict(resource.get("raw"))

        instance_class = raw.get("DBInstanceClass")

        engine = raw.get("Engine")

        multi_az = raw.get("MultiAZ")

        all_reservations = self._load_reserved_instances()

        matches: list[Dict[str, Any]] = []

        for reservation in all_reservations:

            if reservation.get("collection_error"):
                continue

            reserved_class = reservation.get("db_instance_class")

            if (
                instance_class
                and reserved_class
                and str(reserved_class) != str(instance_class)
            ):
                continue

            product = str(
                reservation.get(
                    "product_description",
                    "",
                )
                or ""
            ).lower()

            if not self._engine_matches_product(
                engine,
                product,
            ):
                continue

            reserved_multi_az = reservation.get("multi_az")

            if (
                reserved_multi_az is not None
                and multi_az is not None
                and reserved_multi_az != multi_az
            ):
                continue

            matches.append(reservation)

        active_matches = [
            item
            for item in matches
            if str(
                item.get(
                    "state",
                    "",
                )
            ).lower()
            == "active"
        ]

        active_reserved_units = 0

        for item in active_matches:

            active_reserved_units += self._safe_int(
                item.get("instance_count"),
                1,
                minimum=1,
            )

        offerings = self._load_reserved_offerings(
            instance_class=instance_class,
            engine=engine,
            multi_az=multi_az,
        )

        valid_offerings = [
            item for item in offerings if not item.get("collection_error")
        ]

        return {
            "status": "ok",
            "region": self.region,
            "current_instance_class": instance_class,
            "engine": engine,
            "multi_az": multi_az,
            "active_reservation_units": active_reserved_units,
            "matching_reservation_count": len(matches),
            "active_matching_reservation_count": len(active_matches),
            "matching_reservations": matches,
            "available_offering_count": len(valid_offerings),
            "available_offerings": valid_offerings,
            "offering_collection_status": (
                "error"
                if any(item.get("collection_error") for item in offerings)
                else "ok"
            ),
            "candidate_for_reservation_review": bool(
                instance_class and engine and valid_offerings
            ),
        }

    @staticmethod
    def _build_activity_pattern(
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:

        candidate_names = (
            "CPUUtilization",
            "DatabaseConnections",
            "ReadIOPS",
            "WriteIOPS",
        )

        samples: list[Dict[str, Any]] = []

        metric_summary: Dict[
            str,
            Dict[str, Any],
        ] = {}

        daily: Dict[
            str,
            Dict[str, Any],
        ] = defaultdict(
            lambda: {
                "sample_count": 0,
                "non_zero_count": 0,
                "metrics": set(),
            }
        )

        for name in candidate_names:

            metric = metrics.get(name)

            if not isinstance(
                metric,
                dict,
            ):
                continue

            raw = metric.get(
                "raw_datapoints",
                [],
            )

            if not isinstance(
                raw,
                list,
            ):
                raw = []

            numeric_values: list[float] = []

            metric_samples = 0
            metric_non_zero = 0

            for point in raw:

                if not isinstance(
                    point,
                    dict,
                ):
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

                numeric_values.append(numeric)

                metric_samples += 1

                if numeric > 0:
                    metric_non_zero += 1

                sample = {
                    "metric": name,
                    "timestamp": str(timestamp),
                    "value": numeric,
                }

                samples.append(sample)

                date_key = str(timestamp)[:10]

                if date_key:

                    daily_entry = daily[date_key]

                    daily_entry["sample_count"] += 1

                    daily_entry["metrics"].add(name)

                    if numeric > 0:

                        daily_entry["non_zero_count"] += 1

            if numeric_values:

                metric_summary[name] = {
                    "sample_count": metric_samples,
                    "non_zero_count": metric_non_zero,
                    "zero_ratio": (
                        1.0 - (metric_non_zero / metric_samples)
                        if metric_samples
                        else None
                    ),
                    "average": (sum(numeric_values) / len(numeric_values)),
                    "maximum": max(numeric_values),
                    "minimum": min(numeric_values),
                }

        normalized_daily = {}

        for date_key, entry in daily.items():

            metric_names = sorted(str(item) for item in entry["metrics"])

            normalized_daily[date_key] = {
                "sample_count": entry["sample_count"],
                "non_zero_count": entry["non_zero_count"],
                "non_zero_ratio": (
                    entry["non_zero_count"] / entry["sample_count"]
                    if entry["sample_count"]
                    else None
                ),
                "metrics": metric_names,
                "low_activity_candidate": (
                    entry["sample_count"] > 0 and entry["non_zero_count"] == 0
                ),
            }

        return {
            "status": ("ok" if samples else "no_data"),
            "observed_samples": len(samples),
            "samples": samples,
            "metric_summary": metric_summary,
            "daily_summary": normalized_daily,
            "days_observed": len(normalized_daily),
            "low_activity_days": [
                date_key
                for date_key, value in normalized_daily.items()
                if value.get("low_activity_candidate")
            ],
            "purpose": "rightsizing_retirement_and_scheduling_activity_analysis",
            "missing_is_zero": False,
            "activity_semantics": (
                "raw CloudWatch datapoints "
                "are preserved; missing data "
                "is never interpreted as zero"
            ),
        }

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = self._dict(collected_resource.get("configuration"))

        network = self._dict(configuration.get("network"))

        vpc_id = network.get("vpc_id")

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

        relationships = self._dict(collected_resource.get("relationships"))

        topology["rds"] = {
            "db_instance_identifier": resource.get("id"),
            "db_cluster_identifier": relationships.get("db_cluster_identifier"),
            "db_subnet_group": relationships.get("db_subnet_group"),
            "replica_role": relationships.get("replica_role"),
        }

        return topology

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._dict(collected_resource.get("identity"))

        configuration = self._dict(collected_resource.get("configuration"))

        relationships = self._dict(collected_resource.get("relationships"))

        observations = self._dict(collected_resource.get("observations"))

        cloudwatch = self._dict(observations.get("cloudwatch"))

        derived = self._dict(observations.get("derived"))

        pricing = self._dict(observations.get("pricing"))

        cloudtrail = self._dict(observations.get("cloudtrail"))

        retirement = self._dict(observations.get("retirement"))

        activity = self._dict(derived)

        return {
            "resource": {
                "id": resource.get("id"),
                "name": identity.get("name"),
                "region": self.region,
                "status": identity.get("status"),
                "engine": identity.get("engine"),
                "instance_class": identity.get("instance_class"),
                "db_instance_identifier": identity.get("db_instance_identifier"),
                "db_instance_arn": identity.get("db_instance_arn"),
            },
            "configuration": configuration,
            "relationships": {
                key: value for key, value in relationships.items() if key != "cluster"
            },
            "cluster": relationships.get(
                "cluster",
                {},
            ),
            "replica": {
                "role": relationships.get("replica_role"),
                "is_read_replica": relationships.get("is_read_replica"),
                "is_replica_source": relationships.get("is_replica_source"),
                "source_instance_identifier": relationships.get("read_replica_source"),
                "replica_identifiers": relationships.get(
                    "read_replicas",
                    [],
                ),
            },
            "environment": configuration.get(
                "environment",
                {},
            ),
            "activity": activity,
            "cloudwatch": {
                "namespace": cloudwatch.get("namespace"),
                "analysis_start": cloudwatch.get("analysis_start"),
                "analysis_end": cloudwatch.get("analysis_end"),
                "requested_period": cloudwatch.get("requested_period"),
                "metric_count": len(
                    cloudwatch.get(
                        "metrics",
                        {},
                    )
                    or {}
                ),
                "metrics": cloudwatch.get(
                    "metrics",
                    {},
                ),
            },
            "cloudtrail": cloudtrail,
            "retirement": retirement,
            "pricing": pricing,
            "cost_drivers": {
                "compute": identity.get("instance_class"),
                "storage": self._dict(configuration.get("storage")),
                "iops": self._dict(configuration.get("storage")).get("iops"),
                "throughput_mibps": self._dict(configuration.get("storage")).get(
                    "storage_throughput_mibps"
                ),
                "multi_az": self._dict(configuration.get("deployment")).get("multi_az"),
                "backup_retention_days": self._dict(configuration.get("backup")).get(
                    "backup_retention_days"
                ),
                "performance_insights_enabled": self._dict(
                    configuration.get("performance")
                ).get("performance_insights_enabled"),
            },
            "data_quality": {
                "cloudwatch_available": bool(cloudwatch.get("metrics")),
                "cloudwatch_status": cloudwatch.get("status"),
                "cloudtrail_available": cloudtrail.get("status") == "ok",
                "retirement_context_available": retirement.get("status") == "ok",
                "manual_snapshot_context_available": self._dict(
                    retirement.get("manual_snapshots")
                ).get("status")
                == "ok",
                "automated_backup_context_available": self._dict(
                    retirement.get("automated_backups")
                ).get("status")
                == "ok",
                "reserved_instance_context_available": bool(pricing),
                "topology_available": self._dict(
                    collected_resource.get("topology")
                ).get("status")
                == "ok",
                "activity_data_available": activity.get("status") == "ok",
                "activity_sample_count": activity.get(
                    "observed_samples",
                    0,
                ),
                "missing_is_zero": False,
            },
        }

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

        cached = self._cluster_cache.get(str(cluster_id))

        if cached is not None:
            return cached

        try:

            response = self.rds.describe_db_clusters(DBClusterIdentifier=cluster_id)

        except Exception as exc:

            result = {
                "present": True,
                "status": "error",
                "cluster_id": cluster_id,
                "error": self._error_text(exc),
            }

            self._cluster_cache[str(cluster_id)] = result

            return result

        clusters = (
            response.get(
                "DBClusters",
                [],
            )
            or []
        )

        if not clusters:

            result = {
                "present": True,
                "status": "not_found",
                "cluster_id": cluster_id,
            }

            self._cluster_cache[str(cluster_id)] = result

            return result

        cluster = clusters[0]

        if not isinstance(
            cluster,
            dict,
        ):

            result = {
                "present": True,
                "status": "invalid_response",
                "cluster_id": cluster_id,
            }

            self._cluster_cache[str(cluster_id)] = result

            return result

        scaling_v2 = self._dict(cluster.get("ServerlessV2ScalingConfiguration"))

        members = []

        for member in (
            cluster.get(
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

            members.append(
                {
                    "db_instance_identifier": member.get("DBInstanceIdentifier"),
                    "is_writer": bool(member.get("IsClusterWriter")),
                    "promotion_tier": member.get("PromotionTier"),
                    "db_cluster_parameter_group_status": member.get(
                        "DBClusterParameterGroupStatus"
                    ),
                }
            )

        result = {
            "present": True,
            "status": "ok",
            "cluster_id": cluster.get("DBClusterIdentifier"),
            "cluster_arn": cluster.get("DBClusterArn"),
            "engine": cluster.get("Engine"),
            "engine_mode": cluster.get("EngineMode"),
            "engine_version": cluster.get("EngineVersion"),
            "status_value": cluster.get("Status"),
            "storage_type": cluster.get("StorageType"),
            "allocated_storage": cluster.get("AllocatedStorage"),
            "backup_retention_days": cluster.get("BackupRetentionPeriod"),
            "preferred_backup_window": cluster.get("PreferredBackupWindow"),
            "preferred_maintenance_window": cluster.get("PreferredMaintenanceWindow"),
            "deletion_protection": cluster.get("DeletionProtection"),
            "storage_encrypted": cluster.get("StorageEncrypted"),
            "kms_key_id": cluster.get("KmsKeyId"),
            "iam_database_authentication_enabled": cluster.get(
                "IAMDatabaseAuthenticationEnabled"
            ),
            "copy_tags_to_snapshot": cluster.get("CopyTagsToSnapshot"),
            "global_cluster_identifier": cluster.get("GlobalClusterIdentifier"),
            "reader_endpoint": cluster.get("ReaderEndpoint"),
            "endpoint": cluster.get("Endpoint"),
            "scaling_configuration_v1": self._dict(
                cluster.get("ScalingConfigurationInfo")
            ),
            "serverless_v2_scaling": {
                "min_capacity": scaling_v2.get("MinCapacity"),
                "max_capacity": scaling_v2.get("MaxCapacity"),
                "seconds_until_auto_pause": scaling_v2.get("SecondsUntilAutoPause"),
            },
            "serverless_v2_enabled": bool(scaling_v2),
            "members": members,
            "writer_count": sum(1 for member in members if member.get("is_writer")),
            "reader_count": sum(1 for member in members if not member.get("is_writer")),
        }

        self._cluster_cache[str(cluster_id)] = result

        return result

    @staticmethod
    def _exception_code(
        exc: Exception,
    ) -> str:

        response = getattr(exc, "response", None)

        if isinstance(
            response,
            dict,
        ):

            error = response.get(
                "Error",
                {},
            )

            if isinstance(
                error,
                dict,
            ):

                code = error.get("Code")

                if code:
                    return str(code)

        return ""

    @staticmethod
    def _error_text(
        exc: Exception,
    ) -> str:

        code = RDSCollector._exception_code(exc)

        message = str(exc)

        return f"{code}: {message}" if code else message

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
            str(item["Key"]): item.get("Value")
            for item in tags
            if (
                isinstance(
                    item,
                    dict,
                )
                and item.get("Key")
            )
        }

    @staticmethod
    def _endpoint(
        endpoint: Any,
    ) -> dict[str, Any]:

        if not isinstance(
            endpoint,
            dict,
        ):
            return {}

        return {
            "address": endpoint.get("Address"),
            "port": endpoint.get("Port"),
            "hosted_zone_id": endpoint.get("HostedZoneId"),
        }

    @staticmethod
    def _safe_int(
        value: Any,
        default: int,
        minimum: int = 0,
        maximum: Optional[int] = None,
    ) -> int:

        try:
            parsed = int(value)

        except (
            TypeError,
            ValueError,
        ):
            parsed = default

        parsed = max(
            parsed,
            minimum,
        )

        if maximum is not None:
            parsed = min(
                parsed,
                maximum,
            )

        return parsed

    @staticmethod
    def _age_days(
        value: Any,
        end: datetime,
    ) -> Optional[float]:

        if value is None:
            return None

        try:

            if isinstance(
                value,
                datetime,
            ):
                dt = value

            else:

                dt = datetime.fromisoformat(
                    str(value).replace(
                        "Z",
                        "+00:00",
                    )
                )

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)

            end_aware = end

            if end_aware.tzinfo is None:
                end_aware = end_aware.replace(tzinfo=timezone.utc)
            else:
                end_aware = end_aware.astimezone(timezone.utc)

            return max(
                0.0,
                (end_aware - dt).total_seconds() / 86400.0,
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    def _event_age_days(
        self,
        event_time: Any,
        end: datetime,
    ) -> Optional[float]:

        return self._age_days(
            event_time,
            end,
        )

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

            try:
                return value.isoformat()

            except Exception:
                pass

        return str(value)


def metric_specs_or_empty(
    profile: dict[str, Any],
) -> list[dict[str, Any]]:
    value = profile.get(
        "metrics",
        [],
    )
    if not isinstance(
        value,
        list,
    ):
        return []

    return [
        item
        for item in value
        if isinstance(
            item,
            dict,
        )
    ]
