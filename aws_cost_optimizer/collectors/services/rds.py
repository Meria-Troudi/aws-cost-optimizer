"""
RDS Collector.

Collects:
- RDS instance identity
- Instance configuration
- Storage configuration
- Availability configuration
- Backup configuration
- Performance configuration
- RDS relationships
- Aurora cluster context
- CloudWatch utilization
- CloudTrail instance-class history
- VPC/network topology
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import (
    get_client,
)

from collectors.base import BaseCollector
from collectors.registry import register

from aws_cost_optimizer.collectors.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)

from aws_cost_optimizer.collectors.network.topology import (
    NetworkTopologyCollector,
)


@register
class RDSCollector(BaseCollector):

    key = "rds"
    resource_type = "rds_instance"

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

        self.metric_collector = (
            CloudWatchMetricCollector(
                self.cloudwatch
            )
        )

        self.topology_collector = (
            NetworkTopologyCollector(
                self.region
            )
        )
    def _profile_section(
        self,
        section: str,
    ) -> Dict[str, Any]:

        if not isinstance(
            self.profile,
            dict,
        ):
            return {}

        value = self.profile.get(
            section,
            {},
        )

        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value

    @staticmethod
    def _enabled(
        section: Dict[str, Any],
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
    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: List[
            Dict[str, Any]
        ] = []

        paginator = (
            self.rds.get_paginator(
                "describe_db_instances"
            )
        )

        for page in paginator.paginate():

            for db in page.get(
                "DBInstances",
                [],
            ):

                identifier = db.get(
                    "DBInstanceIdentifier"
                )

                if not identifier:
                    continue

                resources.append(
                    {
                        "id":
                            identifier,

                        "raw":
                            db,
                    }
                )

        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return str(
            resource["id"]
        )
    @staticmethod
    def _field_definition(
        field: Any,
    ) -> tuple[str, str]:

        if isinstance(
            field,
            str,
        ):
            return (
                field,
                field,
            )

        if isinstance(
            field,
            dict,
        ):

            source = field.get(
                "source"
            )

            if not source:
                raise ValueError(
                    "Collection profile field is missing "
                    f"'source': {field!r}"
                )

            output = field.get(
                "output",
                source,
            )

            return (
                source,
                output,
            )

        raise ValueError(
            "Invalid collection profile field: "
            f"{field!r}"
        )

    @staticmethod
    def _get_nested(
        data: Any,
        path: str,
    ) -> Any:

        current = data

        for part in str(
            path
        ).split("."):

            if not isinstance(
                current,
                dict,
            ):
                return None

            current = current.get(
                part
            )

            if current is None:
                return None

        return current

    def _collect_fields(
        self,
        source: Dict[str, Any],
        section_name: str,
    ) -> Dict[str, Any]:

        section = (
            self._profile_section(
                section_name
            )
        )

        if not self._enabled(
            section
        ):
            return {}

        fields = section.get(
            "fields",
            [],
        )

        if not isinstance(
            fields,
            list,
        ):
            raise ValueError(
                f"'{section_name}.fields' "
                "must be a list"
            )

        result: Dict[
            str,
            Any,
        ] = {}

        for field in fields:

            source_path, output_name = (
                self._field_definition(
                    field
                )
            )

            result[
                output_name
            ] = self._get_nested(
                source,
                source_path,
            )

        return result

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = resource.get(
            "raw",
            {},
        )

        if not isinstance(
            raw,
            dict,
        ):
            raw = {}

        result = self._collect_fields(
            raw,
            "identity",
        )

        result.setdefault(
            "db_instance_identifier",
            resource.get(
                "id"
            ),
        )

        result.setdefault(
            "db_instance_arn",
            raw.get(
                "DBInstanceArn"
            ),
        )

        result.setdefault(
            "db_instance_class",
            raw.get(
                "DBInstanceClass"
            ),
        )

        result.setdefault(
            "engine",
            raw.get(
                "Engine"
            ),
        )

        result.setdefault(
            "engine_version",
            raw.get(
                "EngineVersion"
            ),
        )

        result.setdefault(
            "status",
            raw.get(
                "DBInstanceStatus"
            ),
        )

        return result
    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = resource.get(
            "raw",
            {},
        )

        if not isinstance(
            raw,
            dict,
        ):
            raw = {}

        sections = (
            "configuration",
            "storage",
            "availability",
            "backup",
            "performance",
        )

        result: Dict[
            str,
            Any,
        ] = {}

        for section in sections:

            result.update(
                self._collect_fields(
                    raw,
                    section,
                )
            )
        fallback_fields = {
            "instance_class":
                raw.get(
                    "DBInstanceClass"
                ),

            "engine":
                raw.get(
                    "Engine"
                ),

            "engine_version":
                raw.get(
                    "EngineVersion"
                ),

            "status":
                raw.get(
                    "DBInstanceStatus"
                ),

            "publicly_accessible":
                raw.get(
                    "PubliclyAccessible"
                ),

            "deletion_protection":
                raw.get(
                    "DeletionProtection"
                ),

            "multi_az":
                raw.get(
                    "MultiAZ"
                ),

            "availability_zone":
                raw.get(
                    "AvailabilityZone"
                ),

            "storage_type":
                raw.get(
                    "StorageType"
                ),

            "allocated_storage_gib":
                raw.get(
                    "AllocatedStorage"
                ),

            "max_allocated_storage_gib":
                raw.get(
                    "MaxAllocatedStorage"
                ),

            "iops":
                raw.get(
                    "Iops"
                ),

            "storage_throughput":
                raw.get(
                    "StorageThroughput"
                ),

            "storage_encrypted":
                raw.get(
                    "StorageEncrypted"
                ),

            "kms_key_id":
                raw.get(
                    "KmsKeyId"
                ),

            "backup_retention_days":
                raw.get(
                    "BackupRetentionPeriod"
                ),

            "performance_insights_enabled":
                raw.get(
                    "PerformanceInsightsEnabled"
                ),

            "performance_insights_retention_days":
                raw.get(
                    "PerformanceInsightsRetentionPeriod"
                ),

            "monitoring_interval":
                raw.get(
                    "MonitoringInterval"
                ),

            "promotion_tier":
                raw.get(
                    "PromotionTier"
                ),

            "db_cluster_identifier":
                raw.get(
                    "DBClusterIdentifier"
                ),
        }

        for key, value in (
            fallback_fields.items()
        ):

            if (
                key not in result
                or result[key] is None
            ):
                result[
                    key
                ] = value

        subnet_group = (
            raw.get(
                "DBSubnetGroup"
            )
            or {}
        )

        if isinstance(
            subnet_group,
            dict,
        ):

            result.setdefault(
                "db_subnet_group",
                subnet_group.get(
                    "DBSubnetGroupName"
                ),
            )

            result.setdefault(
                "vpc_id",
                subnet_group.get(
                    "VpcId"
                ),
            )

        return result
    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        raw = resource.get(
            "raw",
            {},
        )

        if not isinstance(
            raw,
            dict,
        ):
            raw = {}

        section = (
            self._profile_section(
                "relationships"
            )
        )

        result: Dict[
            str,
            Any,
        ] = {}

        if self._enabled(
            section
        ):

            fields = section.get(
                "fields",
                [],
            )

            if not isinstance(
                fields,
                list,
            ):
                raise ValueError(
                    "'relationships.fields' "
                    "must be a list"
                )

            for field in fields:

                source_path, output_name = (
                    self._field_definition(
                        field
                    )
                )

                result[
                    output_name
                ] = self._get_nested(
                    raw,
                    source_path,
                )

        subnet_group = (
            raw.get(
                "DBSubnetGroup"
            )
            or {}
        )

        if isinstance(
            subnet_group,
            dict,
        ):

            result.setdefault(
                "db_subnet_group",
                subnet_group.get(
                    "DBSubnetGroupName"
                ),
            )

            result.setdefault(
                "vpc_id",
                subnet_group.get(
                    "VpcId"
                ),
            )

        result.setdefault(
            "db_cluster_identifier",
            raw.get(
                "DBClusterIdentifier"
            ),
        )

        result.setdefault(
            "read_replica_source",
            raw.get(
                "ReadReplicaSourceDBInstanceIdentifier"
            ),
        )

        result.setdefault(
            "read_replicas",
            raw.get(
                "ReadReplicaDBInstanceIdentifiers",
                [],
            )
            or [],
        )

        cluster_id = result.get(
            "db_cluster_identifier"
        )

        cluster_context = (
            self._collect_cluster_context(
                cluster_id
            )
            if cluster_id
            else {}
        )

        result[
            "cluster"
        ] = cluster_context

        return result
    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        topology_profile = (
            self._profile_section(
                "topology"
            )
        )

        network_profile = (
            self._profile_section(
                "network"
            )
        )

        enabled = topology_profile.get(
            "enabled",
            network_profile.get(
                "enabled",
                False,
            ),
        )

        if enabled is not True:
            return {}

        raw = resource.get(
            "raw",
            {},
        )

        if not isinstance(
            raw,
            dict,
        ):
            raw = {}

        vpc_id = self._get_nested(
            raw,
            "DBSubnetGroup.VpcId",
        )

        if not vpc_id:

            vpc_id = (
                collected_resource
                .get(
                    "configuration",
                    {},
                )
                .get(
                    "vpc_id"
                )
            )

        if not vpc_id:

            return {
                "status":
                    "incomplete",

                "reason":
                    "RDS instance has no VPC ID",
            }

        topology = (
            self.topology_collector.collect(
                vpc_id=vpc_id,
                resource_type=self.resource_type,
                resource_id=self.get_resource_id(
                    resource
                ),
            )
        )

        topology = dict(
            topology
        )

        topology[
            "rds"
        ] = {
            "db_instance_identifier":
                resource.get(
                    "id"
                ),

            "db_cluster_identifier":
                raw.get(
                    "DBClusterIdentifier"
                ),

            "db_subnet_group":
                (
                    raw.get(
                        "DBSubnetGroup"
                    )
                    or {}
                ),
        }

        return topology
    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        observations_profile = (
            self._profile_section(
                "observations"
            )
        )

        if not self._enabled(
            observations_profile,
            default=True,
        ):
            return {
                "status":
                    "disabled",
            }

        cloudwatch_profile = (
            observations_profile.get(
                "cloudwatch",
                {},
            )
        )

        if not isinstance(
            cloudwatch_profile,
            dict,
        ):
            return {
                "status":
                    "invalid",
            }

        if not self._enabled(
            cloudwatch_profile,
            default=True,
        ):
            return {
                "cloudwatch": {
                    "status":
                        "disabled",

                    "metrics":
                        {},
                }
            }

        namespace = (
            cloudwatch_profile.get(
                "namespace"
            )
        )

        metrics = (
            cloudwatch_profile.get(
                "metrics",
                [],
            )
        )

        period = (
            cloudwatch_profile.get(
                "period",
                3600,
            )
        )

        if not namespace:
            raise ValueError(
                "CloudWatch profile is missing "
                "'namespace'"
            )

        if not metrics:
            return {
                "cloudwatch": {
                    "status":
                        "no_metrics",

                    "namespace":
                        namespace,

                    "metrics":
                        {},
                }
            }

        identifier = (
            resource
            .get(
                "raw",
                {},
            )
            .get(
                "DBInstanceIdentifier"
            )
        )

        if not identifier:
            return {
                "cloudwatch": {
                    "status":
                        "incomplete",

                    "metrics":
                        {},
                }
            }

        start, end = (
            self.get_analysis_period()
        )

        dimensions = [
            {
                "Name":
                    "DBInstanceIdentifier",

                "Value":
                    identifier,
            }
        ]

        results = (
            self.metric_collector.collect(
                namespace=namespace,
                dimensions=dimensions,
                metric_specs=metrics,
                start=start,
                end=end,
                requested_period=int(
                    period
                ),
            )
        )

        metric_results: Dict[
            str,
            Any,
        ] = {}

        errors: List[
            Dict[str, Any]
        ] = []

        available_count = 0

        for result in results:

            if not isinstance(
                result,
                dict,
            ):
                continue

            metric_name = result.get(
                "metric_name"
            )

            if metric_name:

                metric_results[
                    metric_name
                ] = result

            if result.get(
                "has_data"
            ):
                available_count += 1

            if result.get(
                "status"
            ) == "error":

                errors.append(
                    {
                        "metric_name":
                            metric_name,

                        "error":
                            result.get(
                                "error"
                            ),
                    }
                )

        effective_period = (
            results[0].get(
                "effective_period",
                period,
            )
            if results
            else period
        )

        cloudwatch_result = {
            "status":
                (
                    "error"
                    if (
                        results
                        and all(
                            item.get(
                                "status"
                            ) == "error"
                            for item in results
                            if isinstance(
                                item,
                                dict,
                            )
                        )
                    )
                    else "ok"
                ),

            "namespace":
                namespace,

            "requested_period":
                int(period),

            "effective_period":
                effective_period,

            "start":
                start.isoformat(),

            "end":
                end.isoformat(),

            "dimensions":
                dimensions,

            "metric_count":
                len(
                    metric_results
                ),

            "available_metric_count":
                available_count,

            "error_count":
                len(
                    errors
                ),

            "metrics":
                metric_results,
        }

        if errors:
            cloudwatch_result[
                "errors"
            ] = errors

        result = {
            "cloudwatch":
                cloudwatch_result
        }
        cloudtrail_history = (
            self._collect_instance_class_history(
                identifier=identifier,
                start=start,
                end=end,
            )
        )
        result[
            "cloudtrail"
        ] = cloudtrail_history

        return result


    def _collect_cluster_context(
        self,
        cluster_id: Optional[str],
    ) -> Dict[str, Any]:

        if not cluster_id:
            return {
                "present":
                    False,

                "status":
                    "not_applicable",

                "cluster_id":
                    None,
            }

        try:

            response = (
                self.rds.describe_db_clusters(
                    DBClusterIdentifier=cluster_id
                )
            )

        except Exception as exc:

            return {
                "present":
                    True,

                "status":
                    "error",

                "cluster_id":
                    cluster_id,

                "error":
                    str(exc),
            }

        clusters = response.get(
            "DBClusters",
            [],
        )

        if not clusters:
            return {
                "present":
                    True,

                "status":
                    "not_found",

                "cluster_id":
                    cluster_id,
            }

        cluster = clusters[0]

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
                    "db_instance_identifier":
                        member.get(
                            "DBInstanceIdentifier"
                        ),

                    "is_cluster_writer":
                        bool(
                            member.get(
                                "IsClusterWriter"
                            )
                        ),

                    "promotion_tier":
                        member.get(
                            "PromotionTier"
                        ),
                }
            )

        writer_instances = [
            member[
                "db_instance_identifier"
            ]
            for member in members
            if (
                member.get(
                    "is_cluster_writer"
                )
                and member.get(
                    "db_instance_identifier"
                )
            )
        ]

        reader_instances = [
            member[
                "db_instance_identifier"
            ]
            for member in members
            if (
                not member.get(
                    "is_cluster_writer"
                )
                and member.get(
                    "db_instance_identifier"
                )
            )
        ]

        return {
            "present":
                True,

            "status":
                "ok",

            "cluster_id":
                cluster.get(
                    "DBClusterIdentifier"
                ),

            "engine":
                cluster.get(
                    "Engine"
                ),

            "engine_version":
                cluster.get(
                    "EngineVersion"
                ),

            "status_value":
                cluster.get(
                    "Status"
                ),

            "multi_az":
                cluster.get(
                    "MultiAZ"
                ),

            "availability_zones":
                cluster.get(
                    "AvailabilityZones",
                    [],
                ),

            "backup_retention_days":
                cluster.get(
                    "BackupRetentionPeriod"
                ),

            "storage_type":
                cluster.get(
                    "StorageType"
                ),

            "members":
                members,

            "member_count":
                len(
                    members
                ),

            "writer_count":
                len(
                    writer_instances
                ),

            "reader_count":
                len(
                    reader_instances
                ),

            "writer_instances":
                writer_instances,

            "reader_instances":
                reader_instances,

            "deletion_protection":
                cluster.get(
                    "DeletionProtection"
                ),

            "storage_encrypted":
                cluster.get(
                    "StorageEncrypted"
                ),

            "kms_key_id":
                cluster.get(
                    "KmsKeyId"
                ),
        }

    def _collect_instance_class_history(
        self,
        identifier: str,
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:

        cloudtrail_profile = (
            self._profile_section(
                "cloudtrail"
            )
        )

        if not self._enabled(
            cloudtrail_profile,
            default=False,
        ):
            return {
                "status":
                    "disabled",

                "instance_class_history":
                    [],

                "events":
                    [],

                "source":
                    "cloudtrail",
            }

        events: List[
            Dict[str, Any]
        ] = []

        next_token: Optional[
            str
        ] = None

        try:

            while True:

                params: Dict[
                    str,
                    Any,
                ] = {
                    "LookupAttributes": [
                        {
                            "AttributeKey":
                                "EventName",

                            "AttributeValue":
                                "ModifyDBInstance",
                        }
                    ],

                    "StartTime":
                        start,

                    "EndTime":
                        end,

                    "MaxResults":
                        50,
                }

                if next_token:
                    params[
                        "NextToken"
                    ] = next_token

                response = (
                    self.cloudtrail
                    .lookup_events(
                        **params
                    )
                )

                events.extend(
                    response.get(
                        "Events",
                        [],
                    )
                )

                next_token = (
                    response.get(
                        "NextToken"
                    )
                )

                if not next_token:
                    break

        except Exception as exc:

            return {
                "status":
                    "error",

                "instance_class_history":
                    [],

                "events":
                    [],

                "source":
                    "cloudtrail",

                "error":
                    str(exc),
            }

        history: List[
            Dict[str, Any]
        ] = []

        classes: List[
            str
        ] = []

        for event in events:

            if event.get(
                "EventName"
            ) != "ModifyDBInstance":
                continue

            cloudtrail_event = (
                event.get(
                    "CloudTrailEvent"
                )
            )

            if not cloudtrail_event:
                continue

            try:

                parsed = json.loads(
                    cloudtrail_event
                )

            except (
                TypeError,
                ValueError,
            ):
                continue

            request_parameters = (
                parsed.get(
                    "requestParameters",
                    {},
                )
            )

            if not isinstance(
                request_parameters,
                dict,
            ):
                continue

            event_identifier = (
                request_parameters.get(
                    "dBInstanceIdentifier"
                )
                or
                request_parameters.get(
                    "DBInstanceIdentifier"
                )
            )

            if (
                event_identifier
                and str(
                    event_identifier
                )
                != str(identifier)
            ):
                continue

            instance_class = (
                request_parameters.get(
                    "dBInstanceClass"
                )
                or
                request_parameters.get(
                    "DBInstanceClass"
                )
            )

            if not instance_class:
                continue

            instance_class = str(
                instance_class
            )

            if (
                instance_class
                not in classes
            ):
                classes.append(
                    instance_class
                )

            event_time = event.get(
                "EventTime"
            )

            if hasattr(
                event_time,
                "isoformat",
            ):
                event_time_value = (
                    event_time.isoformat()
                )
            else:
                event_time_value = str(
                    event_time
                )

            history.append(
                {
                    "event_time":
                        event_time_value,

                    "event_name":
                        "ModifyDBInstance",

                    "instance_class":
                        instance_class,

                    "username":
                        event.get(
                            "Username"
                        ),
                }
            )

        history.sort(
            key=lambda item:
                item.get(
                    "event_time",
                    "",
                )
        )

        return {
            "status":
                "ok",

            "instance_class_history":
                classes,

            "events":
                history,

            "event_count":
                len(
                    history
                ),

            "source":
                "cloudtrail",
        }