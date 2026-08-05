"""
RDS Collector

Collects:
- RDS instances
- Configuration
- CloudWatch utilization
- Cluster information
- Snapshot information


"""

from datetime import datetime, timedelta

from aws.client import get_client
from collectors.base import BaseCollector
from collectors.registry import register

from collectors.metric_collector import CloudWatchMetricCollector

from collectors.services.rds_cluster import RDSClusterCollector
from collectors.services.rds_snapshots import RDSSnapshotCollector


@register
class RDSCollector(BaseCollector):

    key = "rds"

    def collect(self):

        rds = get_client(
            "rds",
            self.region
        )

        cloudwatch = get_client(
            "cloudwatch",
            self.region
        )

        instances = []

        paginator = rds.get_paginator(
            "describe_db_instances"
        )

        for page in paginator.paginate():
            instances.extend(
                page["DBInstances"]
            )

        print(
            f"[{self.region}] RDS instances found: {len(instances)}"
        )

        metric_collector = CloudWatchMetricCollector(
            cloudwatch
        )

        snapshot_collector = RDSSnapshotCollector(
            self.region
        )

        cluster_collector = RDSClusterCollector(
            self.region
        )

        start = datetime.utcnow() - timedelta(days=30)
        end = datetime.utcnow()

        resources = []

        for db in instances:

            identifier = db["DBInstanceIdentifier"]

            print(
                f"Collecting RDS {identifier}"
            )

            metrics = metric_collector.collect_fixed(
                namespace="AWS/RDS",
                dimensions=[
                    {
                        "Name": "DBInstanceIdentifier",
                        "Value": identifier
                    }
                ],
                metric_specs=[
                    {"name": "CPUUtilization", "statistic": "Average"},
                    {"name": "DatabaseConnections", "statistic": "Average"},
                    {"name": "FreeableMemory", "statistic": "Average"},
                    {"name": "ReadIOPS", "statistic": "Average"},
                    {"name": "WriteIOPS", "statistic": "Average"},
                    {"name": "ReadLatency", "statistic": "Average"},
                    {"name": "WriteLatency", "statistic": "Average"},
                    {"name": "FreeStorageSpace", "statistic": "Average"},
                ],
                start=start,
                end=end
            )

            cluster = {}

            if db.get("DBClusterIdentifier"):
                cluster = cluster_collector.collect(
                    db["DBClusterIdentifier"]
                )

            snapshots = snapshot_collector.collect_instance_snapshots(
                identifier
            )

            attributes = {
                # Identity
                "identifier": identifier,
                "arn": db.get("DBInstanceArn"),

                # Engine
                "engine": db.get("Engine"),
                "engine_version": db.get("EngineVersion"),

                # Compute
                "instance_class": db.get("DBInstanceClass"),

                # State
                "status": db.get("DBInstanceStatus"),

                # Storage
                "allocated_storage": db.get("AllocatedStorage"),
                "storage_type": db.get("StorageType"),
                "iops": db.get("Iops"),
                "storage_encrypted": db.get("StorageEncrypted"),

                # Availability
                "multi_az": db.get("MultiAZ"),
                "availability_zone": db.get("AvailabilityZone"),

                # Network
                "public_access": db.get("PubliclyAccessible"),
                "subnet_group": db.get(
                    "DBSubnetGroup",
                    {}
                ).get("DBSubnetGroupName"),

                # Backup
                "backup_retention_days": db.get("BackupRetentionPeriod"),

                # Monitoring
                "monitoring_interval": db.get("MonitoringInterval"),
                "performance_insights": db.get("PerformanceInsightsEnabled"),

                # Connections
                "endpoint": db.get("Endpoint", {}).get("Address"),

                # Cluster
                "cluster_id": db.get("DBClusterIdentifier"),
            }

            resources.append({
                "resource_id": identifier,
                "resource_type": "rds_instance",
                "region": self.region,
                "state": db.get("DBInstanceStatus"),
                "name": identifier,
                "tags": {
                    t["Key"]: t["Value"]
                    for t in db.get("TagList", [])
                },
                "attributes": attributes,
                "metrics": metrics,
                "cluster": cluster,
                "snapshots": snapshots,
                "raw": db
            })

        return resources