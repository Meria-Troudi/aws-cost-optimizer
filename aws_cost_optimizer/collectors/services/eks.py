"""
EKS Collector

Collect:
- EKS clusters
- Node groups
- Addons
"""

from aws.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register


@register
class EKSCollector(BaseCollector):

    key = "eks"

    def collect(self):

        eks = get_client(
            "eks",
            self.region
        )

        resources = []

        paginator = eks.get_paginator(
            "list_clusters"
        )

        clusters = []

        for page in paginator.paginate():
            clusters.extend(
                page.get(
                    "clusters",
                    []
                )
            )

        print(
            f"[{self.region}] EKS clusters discovered: {len(clusters)}"
        )

        for cluster_name in clusters:

            cluster = (
                eks
                .describe_cluster(
                    name=cluster_name
                )
                ["cluster"]
            )

            nodegroups = (
                eks
                .list_nodegroups(
                    clusterName=cluster_name
                )
                .get(
                    "nodegroups",
                    []
                )
            )

            addons = (
                eks
                .list_addons(
                    clusterName=cluster_name
                )
                .get(
                    "addons",
                    []
                )
            )

            resources.append({
                "resource_id": cluster["arn"],
                "resource_type": "eks_cluster",
                "region": self.region,
                "state": cluster["status"],
                "name": cluster_name,
                "tags": cluster.get("tags", {}),
                "attributes": {
                    "version": cluster.get("version"),
                    "platform_version": cluster.get("platformVersion"),
                    "endpoint": cluster.get("endpoint"),
                    "role": cluster.get("roleArn"),
                    "nodegroups": nodegroups,
                    "addons": addons,
                    "created_at": str(cluster.get("createdAt"))
                },
                "metrics": [],
                "raw": cluster
            })

        return resources