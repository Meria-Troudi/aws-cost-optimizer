"""
Persistence layer
"""

from datetime import datetime
from typing import Optional

from backend.database.repository.resource_repository import (
    get_or_create_resource,
    save_resource_snapshot,
    save_metric,
)


class CollectorPersistence:

    def save(self, db, scan, resource: dict):

        resource_id = resource["resource_id"]

        obj = get_or_create_resource(
            db,
            aws_resource_id=resource_id,
            service=self._infer_service(resource["resource_type"]),
            resource_type=resource["resource_type"],
            region=resource["region"],
            scan_run_id=scan.id,
            state=resource.get("state"),
            name=resource.get("name", resource_id),
            tags=resource.get("tags", {}),
            attributes=resource.get("attributes", {}),
        )

        db.flush()

        # Include cluster and snapshots in the configuration for cost analysis
        configuration = dict(resource.get("attributes", {}))
        if resource.get("cluster"):
            configuration["cluster"] = resource["cluster"]
        if resource.get("snapshots"):
            configuration["snapshots"] = resource["snapshots"]

        save_resource_snapshot(
            db,
            resource_id=obj.id,
            scan_run_id=scan.id,
            source_api="collector",
            configuration=configuration,
            raw_response=resource.get("raw", {}),
        )

        metrics = resource.get("metrics", {})

        # Handle dict format: {metric_name: value}
        if isinstance(metrics, dict):
            for metric_name, value in metrics.items():
                if value is None:
                    continue

                save_metric(
                    db,
                    resource_id=obj.id,
                    scan_run_id=scan.id,
                    namespace="AWS",
                    metric_name=metric_name,
                    statistic="Average",
                    unit="None",
                    value=value,
                    metric_start=datetime.utcnow(),
                    metric_end=datetime.utcnow(),
                )
        else:
            # Backward compatibility: handle list format
            for metric in metrics:
                value = metric.get("value")
                if value is None:
                    continue

                # Parse ISO timestamps to datetime objects
                metric_start = metric.get("start")
                metric_end = metric.get("end")

                if isinstance(metric_start, str):
                    metric_start = datetime.fromisoformat(metric_start)
                elif metric_start is None:
                    metric_start = datetime.utcnow()

                if isinstance(metric_end, str):
                    metric_end = datetime.fromisoformat(metric_end)
                elif metric_end is None:
                    metric_end = datetime.utcnow()

                save_metric(
                    db,
                    resource_id=obj.id,
                    scan_run_id=scan.id,
                    namespace=metric.get("namespace", "AWS"),
                    metric_name=metric.get("metric_name"),
                    statistic=metric.get("statistic", "Average"),
                    unit=metric.get("unit"),
                    value=value,
                    metric_start=metric_start,
                    metric_end=metric_end,
                )

        return obj

    def _infer_service(self, resource_type: str) -> str:
        return {
            "nat_gateway": "Amazon Virtual Private Cloud",
            "rds_instance": "Amazon Relational Database Service",
            "rds_cluster": "Amazon Relational Database Service",
            "ec2_instance": "Amazon Elastic Compute Cloud - Compute",
            "ebs_volume": "Amazon Elastic Compute Cloud - Compute",
            "elastic_ip": "Amazon Elastic Compute Cloud - Compute",
        }.get(resource_type, "Unknown")
