"""
Dynamic CloudWatch metric collector
"""

from datetime import datetime
from typing import List
class CloudWatchMetricCollector:

    def __init__(self, cloudwatch):
        self.cloudwatch = cloudwatch
    def discover_metrics(self, namespace: str, dimensions: list) -> List[str]:
        
        paginator = self.cloudwatch.get_paginator("list_metrics")
        metrics = set()
        for page in paginator.paginate(
            Namespace=namespace,
            Dimensions=dimensions,
        ):
            for metric in page.get("Metrics", []):
                metrics.add(metric["MetricName"])

        return list(metrics)

    def collect(
        self,
        namespace: str,
        dimensions: list,
        start: datetime,
        end: datetime,
        period: int = 86400,
    ) -> dict:
        """
        Collect metrics and return as dict for easy lookup.
        
        Returns:
            dict: {metric_name: value, ...}
        """
        metric_names = self.discover_metrics(namespace, dimensions)

        results = {}

        for name in metric_names:
            response = self.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=name,
                Dimensions=dimensions,
                StartTime=start,
                EndTime=end,
                Period=period,
                Statistics=["Average"],
            )

            datapoints = response.get("Datapoints", [])

            if not datapoints:
                results[name] = None
                continue

            value = sum(x["Average"] for x in datapoints) / len(datapoints)
            results[name] = round(value, 2)

        return results

    def collect_fixed(
        self,
        namespace: str,
        dimensions: list,
        metric_specs: list,
        start: datetime,
        end: datetime,
        period: int = 86400,
    ) -> List[dict]:

        results = []

        for spec in metric_specs:
            metric_name = spec["name"]
            statistic = spec.get("statistic", "Average")

            response = self.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start,
                EndTime=end,
                Period=period,
                Statistics=[statistic],
            )

            datapoints = response.get("Datapoints", [])

            if not datapoints:
                results.append({
                    "metric_name": metric_name,
                    "namespace": namespace,
                    "value": None,
                    "unit": spec.get("unit"),
                    "statistic": statistic,
                    "status": "no_data",
                })
                continue

            # For Sum statistics: total value
            # For Average statistics: average value
            if statistic == "Sum":
                value = sum(x[statistic] for x in datapoints)
            else:
                value = sum(x[statistic] for x in datapoints) / len(datapoints)

            results.append({
                "metric_name": metric_name,
                "namespace": namespace,
                "value": round(value, 2),
                "unit": spec.get("unit"),
                "statistic": statistic,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "status": "ok",
            })

        return results
