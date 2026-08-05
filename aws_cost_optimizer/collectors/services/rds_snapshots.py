"""
RDS Snapshot Collector
"""

from datetime import datetime, timezone

from aws.client import get_client


class RDSSnapshotCollector:

    def __init__(self, region):
        self.region = region
        self.client = get_client("rds", region)

    def collect_instance_snapshots(self, db_identifier):
        snapshots = []

        paginator = self.client.get_paginator("describe_db_snapshots")

        for page in paginator.paginate(DBInstanceIdentifier=db_identifier):
            for snap in page["DBSnapshots"]:
                snapshots.append({
                    "identifier": snap.get("DBSnapshotIdentifier"),
                    "status": snap.get("Status"),
                    "allocated_storage": snap.get("AllocatedStorage"),
                    "engine": snap.get("Engine"),
                    "created": (
                        snap.get("SnapshotCreateTime").isoformat()
                        if snap.get("SnapshotCreateTime")
                        else None
                    ),
                    "age_days": (
                        (datetime.now(timezone.utc) - snap["SnapshotCreateTime"]).days
                        if snap.get("SnapshotCreateTime")
                        else None
                    ),
                })

        return snapshots

    def collect_cluster_snapshots(self, cluster_id):
        snapshots = []

        paginator = self.client.get_paginator("describe_db_cluster_snapshots")

        for page in paginator.paginate(DBClusterIdentifier=cluster_id):
            for snap in page["DBClusterSnapshots"]:
                snapshots.append({
                    "identifier": snap.get("DBClusterSnapshotIdentifier"),
                    "status": snap.get("Status"),
                    "allocated_storage": snap.get("AllocatedStorage"),
                    "engine": snap.get("Engine"),
                    "created": (
                        snap.get("SnapshotCreateTime").isoformat()
                        if snap.get("SnapshotCreateTime")
                        else None
                    ),
                    "age_days": (
                        (datetime.now(timezone.utc) - snap["SnapshotCreateTime"]).days
                        if snap.get("SnapshotCreateTime")
                        else None
                    ),
                })

        return snapshots