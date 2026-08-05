"""
RDS Cluster Collector

Collect:
- DB clusters (Aurora)
- Cluster members
- Engine information
"""

from aws.client import get_client
from collectors.base import BaseCollector
from collectors.registry import register


class RDSClusterCollector:
    """Helper class to collect cluster details for a specific cluster ID."""

    def __init__(self, region):
        self.region = region
        self.client = get_client("rds", region)

    def collect(self, cluster_id):
        response = self.client.describe_db_clusters(
            DBClusterIdentifier=cluster_id
        )

        if not response["DBClusters"]:
            return {}

        cluster = response["DBClusters"][0]

        return {
            "identifier": cluster.get("DBClusterIdentifier"),
            "engine": cluster.get("Engine"),
            "status": cluster.get("Status"),
            "members": [
                m["DBInstanceIdentifier"]
                for m in cluster.get("DBClusterMembers", [])
            ],
            "endpoint": cluster.get("Endpoint"),
            "reader_endpoint": cluster.get("ReaderEndpoint"),
            "multi_az": cluster.get("MultiAZ"),
            "backup_retention": cluster.get("BackupRetentionPeriod"),
        }


@register
class RDSClusterServiceCollector(BaseCollector):

    key = "rds_cluster"

    def collect(self):

        rds = get_client(
            "rds",
            self.region
        )

        clusters = []

        paginator = rds.get_paginator(
            "describe_db_clusters"
        )

        for page in paginator.paginate():
            for cluster in page["DBClusters"]:
                clusters.append({
                    "resource_id": cluster["DBClusterIdentifier"],
                    "resource_type": "rds_cluster",
                    "region": self.region,
                    "state": cluster["Status"],
                    "name": cluster["DBClusterIdentifier"],
                    "tags": {
                        t["Key"]: t["Value"]
                        for t in cluster.get("TagList", [])
                    },
                    "attributes": {
                        "engine": cluster["Engine"],
                        "engine_version": cluster["EngineVersion"],
                        "storage_encrypted": cluster["StorageEncrypted"],
                        "members": [
                            m["DBInstanceIdentifier"]
                            for m in cluster["DBClusterMembers"]
                        ],
                        "endpoint": cluster.get("Endpoint"),
                        "reader_endpoint": cluster.get("ReaderEndpoint"),
                        "multi_az": cluster.get("MultiAZ"),
                        "backup_retention": cluster.get("BackupRetentionPeriod"),
                    },
                    "metrics": [],
                    "raw": cluster
                })

        print(
            f"[{self.region}] RDS clusters discovered: {len(clusters)}"
        )

        return clusters