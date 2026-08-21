"""
Amazon DynamoDB collector.

Purpose
-------
Collect evidence required for DynamoDB cost optimization: table
identity/configuration, billing mode, provisioned capacity, GSI
inventory, Application Auto Scaling targets, Global Table replicas,
PITR/TTL context, and CloudWatch capacity/throttle metrics.

Semantics
---------
The collector exposes evidence only. It does not decide that a table
is wasteful, choose a new billing mode, pick an RCU/WCU value, or
estimate savings.

Missing CloudWatch data is not zero. API failures are not represented
as successful empty collections.

Important: metric-rate normalization
-------------------------------------
`ConsumedReadCapacityUnits`/`ConsumedWriteCapacityUnits` are collected
with statistic Sum. `CloudWatchMetricCollector` returns, for a Sum
statistic, "value" == the raw total summed across every datapoint in
the query window -- it does NOT normalize that to a per-second rate.
`ProvisionedReadCapacityUnits`/`ProvisionedWriteCapacityUnits` use
statistic Average and are already a capacity-units/second style
value. Comparing the raw consumed total against the provisioned
average directly would produce utilization percentages inflated by
however many seconds are in the analysis window (e.g. a 30-day window
is ~2.6M seconds -- treating a summed total as if it were a rate would
make utilization look enormous). The derived utilization calculation
below normalizes consumed sums to units/second using the actual
analysis-window duration before comparing against provisioned
capacity.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from aws_cost_optimizer.config.client import get_client

from ...base import BaseCollector
from ...registry import register
from ...metrics.cloudwatch import CloudWatchMetricCollector


@register
class DynamoDBCollector(BaseCollector):

    key = "dynamodb"
    resource_type = "dynamodb_table"

    DEFAULT_NAMESPACE = "AWS/DynamoDB"
    DEFAULT_PERIOD = 300

    CONSUMED_READ = "ConsumedReadCapacityUnits"
    CONSUMED_WRITE = "ConsumedWriteCapacityUnits"
    PROVISIONED_READ = "ProvisionedReadCapacityUnits"
    PROVISIONED_WRITE = "ProvisionedWriteCapacityUnits"
    READ_THROTTLES = "ReadThrottleEvents"
    WRITE_THROTTLES = "WriteThrottleEvents"
    SYSTEM_ERRORS = "SystemErrors"

    def __init__(
        self,
        scan,
        region: Optional[str] = None,
        profile: Optional[dict] = None,
    ) -> None:

        super().__init__(
            scan,
            region=region,
            profile=profile,
        )

        if not self.region:
            raise ValueError(
                "DynamoDB collector requires a region."
            )

        self.dynamodb = get_client(
            "dynamodb",
            self.region,
        )

        self.application_autoscaling = get_client(
            "application-autoscaling",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = (
            CloudWatchMetricCollector(
                self.cloudwatch
            )
        )

        self._metrics_batch_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._autoscaling_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

        self._analysis_duration_seconds: Optional[float] = None

    # ==============================================================
    # PROFILE
    # ==============================================================

    def _section(
        self,
        name: str,
    ) -> Dict[str, Any]:

        value = (
            self.profile.get(name, {})
            if isinstance(self.profile, dict)
            else {}
        )

        return value if isinstance(value, dict) else {}

    def _cloudwatch_profile(self) -> Dict[str, Any]:

        return self._section("observations").get(
            "cloudwatch",
            {},
        ) or {}

    def _metric_specs(
        self,
        name: str,
    ) -> List[Dict[str, Any]]:

        value = self._cloudwatch_profile().get(name, [])

        if not isinstance(value, list):
            return []

        return [item for item in value if isinstance(item, dict)]

    def _namespace(self) -> str:

        return str(
            self._cloudwatch_profile().get(
                "namespace",
                self.DEFAULT_NAMESPACE,
            )
        ).strip()

    def _requested_period(self) -> int:

        try:
            value = int(
                self._cloudwatch_profile().get(
                    "period",
                    self.DEFAULT_PERIOD,
                )
            )
        except (TypeError, ValueError):
            value = self.DEFAULT_PERIOD

        return max(60, value)

    # ==============================================================
    # DISCOVERY
    # ==============================================================

    def discover(self) -> List[Dict[str, Any]]:

        resources: List[Dict[str, Any]] = []

        paginator = self.dynamodb.get_paginator(
            "list_tables"
        )

        try:

            for page in paginator.paginate():

                for table_name in page.get("TableNames", []):

                    if not table_name:
                        continue

                    try:

                        response = (
                            self.dynamodb.describe_table(
                                TableName=table_name
                            )
                        )

                    except Exception as exc:

                        raise RuntimeError(
                            "Failed to describe DynamoDB "
                            f"table {table_name}: {exc}"
                        ) from exc

                    table = response.get("Table")

                    if not isinstance(table, dict):
                        continue

                    resources.append(
                        {
                            "id": table_name,
                            "raw": table,
                        }
                    )

        except Exception as exc:

            raise RuntimeError(
                "Failed to discover DynamoDB tables "
                f"in {self.region}: {exc}"
            ) from exc

        # Prefetched together so per-resource collection never issues
        # a repeated Application Auto Scaling or CloudWatch call.
        self._prefetch_autoscaling(resources)
        self._prefetch_metrics(resources)

        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        value = resource.get("id")

        if not value:
            raise ValueError(
                "DynamoDB table name is missing."
            )

        return str(value)

    # ==============================================================
    # IDENTITY
    # ==============================================================

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        table = self._dict(resource.get("raw"))

        return {
            "name": table.get("TableName"),
            "table_name": table.get("TableName"),
            "table_arn": table.get("TableArn"),
            "table_id": table.get("TableId"),
            "status": table.get("TableStatus"),
            "billing_mode": self._billing_mode(table),
            "region": self.region,
            "created_at": self._isoformat(
                table.get("CreationDateTime")
            ),
            "tags": self._collect_tags(
                table.get("TableArn")
            ),
        }

    # ==============================================================
    # CONFIGURATION
    # ==============================================================

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        table = self._dict(resource.get("raw"))

        provisioned = self._dict(
            table.get("ProvisionedThroughput")
        )

        billing_mode_summary = self._dict(
            table.get("BillingModeSummary")
        )

        table_name = table.get("TableName")

        return {
            "table": {
                "name": table.get("TableName"),
                "arn": table.get("TableArn"),
                "id": table.get("TableId"),
                "status": table.get("TableStatus"),
                "creation_time": self._isoformat(
                    table.get("CreationDateTime")
                ),
                "table_size_bytes": table.get(
                    "TableSizeBytes"
                ),
                "item_count": table.get("ItemCount"),
            },
            "capacity": {
                "billing_mode": self._billing_mode(table),
                "provisioned_read": provisioned.get(
                    "ReadCapacityUnits"
                ),
                "provisioned_write": provisioned.get(
                    "WriteCapacityUnits"
                ),
                "billing_mode_last_update": self._isoformat(
                    billing_mode_summary.get(
                        "LastUpdateToPayPerRequestDateTime"
                    )
                ),
            },
            "indexes": self._collect_indexes(table),
            "autoscaling": self._autoscaling_cache.get(
                str(table_name),
                {},
            ),
            "global_table": self._global_table_context(table),
            "backup": {
                "point_in_time_recovery": self._collect_pitr(
                    table_name
                ),
            },
            "ttl": self._collect_ttl(table_name),
            "deletion_protection": table.get(
                "DeletionProtectionEnabled"
            ),
            "stream": {
                "enabled": bool(
                    table.get("StreamSpecification", {})
                ),
                "view_type": self._dict(
                    table.get("StreamSpecification")
                ).get("StreamViewType"),
            },
            "encryption": {
                "enabled": bool(
                    table.get("SSEDescription")
                ),
                "type": self._dict(
                    table.get("SSEDescription")
                ).get("SSEType"),
            },
        }

    # ==============================================================
    # RELATIONSHIPS
    # ==============================================================

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        table = self._dict(resource.get("raw"))

        global_context = self._global_table_context(table)
        indexes = self._collect_indexes(table)

        return {
            "status": "ok",
            "table_name": table.get("TableName"),
            "table_arn": table.get("TableArn"),
            "global_table": global_context,
            "indexes": indexes,
            "gsi_names": [
                index.get("index_name")
                for index in indexes
                if index.get("index_name")
            ],
            "summary": {
                "gsi_count": len(indexes),
                "global_replica_count": global_context.get(
                    "replica_count", 0
                ),
                "is_global_table": global_context.get(
                    "is_global_table", False
                ),
            },
        }

    # ==============================================================
    # CLOUDWATCH PREFETCH
    # ==============================================================

    def _prefetch_metrics(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        table_specs = self._metric_specs("table_metrics")
        gsi_specs = self._metric_specs("gsi_metrics")

        if not table_specs and not gsi_specs:
            return

        try:
            start, end = self.get_analysis_period()
        except ValueError:
            return

        self._analysis_duration_seconds = max(
            (end - start).total_seconds(),
            1.0,
        )

        namespace = self._namespace()
        requests: List[Dict[str, Any]] = []

        for resource in resources:

            table_name = resource.get("id")
            raw = self._dict(resource.get("raw"))

            if not table_name:
                continue

            if table_specs:

                requests.append(
                    {
                        "resource_key": f"table:{table_name}",
                        "namespace": namespace,
                        "dimensions": [
                            {
                                "Name": "TableName",
                                "Value": str(table_name),
                            }
                        ],
                        "metric_specs": table_specs,
                    }
                )

            if gsi_specs:

                for index in (
                    raw.get("GlobalSecondaryIndexes", [])
                    or []
                ):

                    if not isinstance(index, dict):
                        continue

                    index_name = index.get("IndexName")

                    if not index_name:
                        continue

                    requests.append(
                        {
                            "resource_key": (
                                f"gsi:{table_name}:{index_name}"
                            ),
                            "namespace": namespace,
                            "dimensions": [
                                {
                                    "Name": "TableName",
                                    "Value": str(table_name),
                                },
                                {
                                    "Name": "GlobalSecondaryIndexName",
                                    "Value": str(index_name),
                                },
                            ],
                            "metric_specs": gsi_specs,
                        }
                    )

        if not requests:
            return

        results = self.metric_collector.collect_batch(
            requests,
            start=start,
            end=end,
            requested_period=self._requested_period(),
        )

        self._metrics_batch_cache = (
            results if isinstance(results, dict) else {}
        )

    # ==============================================================
    # OBSERVATIONS
    # ==============================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        table_name = resource.get("id")

        if not table_name:
            return {
                "status": "incomplete",
                "reason": "DynamoDB table name unavailable",
            }

        profile = self._cloudwatch_profile()

        if profile.get("enabled", True) is False:
            return {
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                }
            }

        try:
            start, end = self.get_analysis_period()
        except ValueError as exc:
            return {
                "cloudwatch": {
                    "status": "error",
                    "metrics": {},
                    "error": str(exc),
                }
            }

        table_map = self._metrics_to_map(
            self._metrics_batch_cache.get(
                f"table:{table_name}", []
            )
        )

        gsi_map: Dict[str, Dict[str, Any]] = {}

        for index in self._collect_indexes(
            self._dict(resource.get("raw"))
        ):

            index_name = index.get("index_name")

            if not index_name:
                continue

            key = f"gsi:{table_name}:{index_name}"

            gsi_map[str(index_name)] = {
                "metrics": self._metrics_to_map(
                    self._metrics_batch_cache.get(key, [])
                )
            }

        duration_seconds = max(
            (end - start).total_seconds(),
            1.0,
        )

        cloudwatch = {
            "status": self._collection_status(table_map),
            "namespace": self._namespace(),
            "table_name": table_name,
            "analysis_start": start.isoformat(),
            "analysis_end": end.isoformat(),
            "duration_seconds": duration_seconds,
            "requested_period": self._requested_period(),
            "table": {"metrics": table_map},
            "gsis": gsi_map,
            "data_quality": self._quality(table_map, gsi_map),
        }

        return {
            "cloudwatch": cloudwatch,
            "derived": self._build_derived(
                table_map,
                gsi_map,
                duration_seconds,
            ),
        }

    # ==============================================================
    # TOPOLOGY
    # ==============================================================

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        # DynamoDB is a regional managed service; it does not have a
        # direct VPC attachment the way RDS/EC2 do. Keep that explicit
        # rather than inventing a VPC relationship.
        return {
            "status": "not_applicable",
            "reason": (
                "DynamoDB tables are regional managed-service "
                "resources with no direct VPC topology."
            ),
        }

    # ==============================================================
    # OPTIMIZATION EVIDENCE
    # ==============================================================

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
        derived = self._dict(observations.get("derived"))
        capacity = self._dict(configuration.get("capacity"))
        table_info = self._dict(configuration.get("table"))

        return {
            "resource": {
                "id": resource.get("id"),
                "name": identity.get("name"),
                "region": self.region,
                "status": identity.get("status"),
                "billing_mode": identity.get("billing_mode"),
            },
            "capacity": {
                "billing_mode": capacity.get("billing_mode"),
                "provisioned_read": capacity.get(
                    "provisioned_read"
                ),
                "provisioned_write": capacity.get(
                    "provisioned_write"
                ),
                "autoscaling": configuration.get(
                    "autoscaling", {}
                ),
            },
            "indexes": {
                "count": relationships.get("summary", {}).get(
                    "gsi_count", 0
                ),
                "items": configuration.get("indexes", []),
            },
            "global_table": relationships.get(
                "global_table", {}
            ),
            "utilization": cloudwatch,
            "derived": derived,
            "backup": configuration.get("backup", {}),
            "storage": {
                "table_size_bytes": table_info.get(
                    "table_size_bytes"
                ),
                "item_count": table_info.get("item_count"),
            },
            "data_quality": {
                "cloudwatch_available": bool(cloudwatch),
                "table_metrics_available": bool(
                    self._dict(cloudwatch.get("table")).get(
                        "metrics"
                    )
                ),
                "gsi_metrics_available": bool(
                    cloudwatch.get("gsis")
                ),
                "autoscaling_available": bool(
                    configuration.get("autoscaling")
                ),
                "global_table_context_available": bool(
                    relationships.get("global_table")
                ),
            },
        }

    # ==============================================================
    # INDEXES
    # ==============================================================

    def _collect_indexes(
        self,
        table: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        for index in (
            table.get("GlobalSecondaryIndexes", []) or []
        ):

            if not isinstance(index, dict):
                continue

            provisioned = self._dict(
                index.get("ProvisionedThroughput")
            )

            result.append(
                {
                    "index_name": index.get("IndexName"),
                    "index_arn": index.get("IndexArn"),
                    "key_schema": index.get("KeySchema", []),
                    "projection": index.get("Projection", {}),
                    "status": index.get("IndexStatus"),
                    "item_count": index.get("ItemCount"),
                    "index_size_bytes": index.get(
                        "IndexSizeBytes"
                    ),
                    "provisioned_read": provisioned.get(
                        "ReadCapacityUnits"
                    ),
                    "provisioned_write": provisioned.get(
                        "WriteCapacityUnits"
                    ),
                }
            )

        return result

    # ==============================================================
    # GLOBAL TABLE
    # ==============================================================

    @staticmethod
    def _global_table_context(
        table: Dict[str, Any],
    ) -> Dict[str, Any]:

        replicas = table.get("Replicas", []) or []

        if not isinstance(replicas, list):
            replicas = []

        regions = sorted(
            {
                str(replica.get("RegionName"))
                for replica in replicas
                if isinstance(replica, dict)
                and replica.get("RegionName")
            }
        )

        replica_details = [
            {
                "region": replica.get("RegionName"),
                "status": replica.get("ReplicaStatus"),
            }
            for replica in replicas
            if isinstance(replica, dict)
        ]

        return {
            "is_global_table": bool(replicas),
            "replica_count": len(replicas),
            "replica_regions": regions,
            "replicas": replica_details,
        }

    # ==============================================================
    # AUTOSCALING
    # ==============================================================

    def _prefetch_autoscaling(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        for resource in resources:

            table_name = resource.get("id")

            if not table_name:
                continue

            raw = self._dict(resource.get("raw"))
            indexes = self._collect_indexes(raw)

            self._autoscaling_cache[str(table_name)] = (
                self._collect_autoscaling(
                    str(table_name),
                    indexes,
                )
            )

    def _collect_autoscaling(
        self,
        table_name: str,
        indexes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        result: Dict[str, Any] = {
            "status": "ok",
            "table": {
                "read": self._autoscaling_dimension(
                    table_name,
                    "table",
                    "ReadCapacityUnits",
                ),
                "write": self._autoscaling_dimension(
                    table_name,
                    "table",
                    "WriteCapacityUnits",
                ),
            },
            "gsis": {},
        }

        for index in indexes:

            index_name = index.get("index_name")

            if not index_name:
                continue

            result["gsis"][str(index_name)] = {
                "read": self._autoscaling_dimension(
                    table_name,
                    "index",
                    "ReadCapacityUnits",
                    index_name=index_name,
                ),
                "write": self._autoscaling_dimension(
                    table_name,
                    "index",
                    "WriteCapacityUnits",
                    index_name=index_name,
                ),
            }

        return result

    def _autoscaling_dimension(
        self,
        table_name: str,
        resource_type: str,
        dimension: str,
        *,
        index_name: Optional[str] = None,
    ) -> Dict[str, Any]:

        resource_id = (
            f"table/{table_name}"
            if resource_type == "table"
            else f"table/{table_name}/index/{index_name}"
        )

        try:

            paginator = (
                self.application_autoscaling.get_paginator(
                    "describe_scalable_targets"
                )
            )

            targets: List[Dict[str, Any]] = []

            for page in paginator.paginate(
                ServiceNamespace="dynamodb",
                ResourceIds=[resource_id],
                ScalableDimension=(
                    f"dynamodb:{resource_type}:{dimension}"
                ),
            ):

                targets.extend(
                    page.get("ScalableTargets", [])
                )

            if not targets:

                return {
                    "status": "ok",
                    "enabled": False,
                    "target_count": 0,
                }

            target = targets[0]

            return {
                "status": "ok",
                "enabled": True,
                "target_count": len(targets),
                "min_capacity": target.get("MinCapacity"),
                "max_capacity": target.get("MaxCapacity"),
            }

        except Exception as exc:

            return {
                "status": "error",
                "enabled": None,
                "target_count": None,
                "error": str(exc),
            }

    # ==============================================================
    # DERIVED
    # ==============================================================

    @classmethod
    def _build_derived(
        cls,
        table_metrics: Dict[str, Any],
        gsi_metrics: Dict[str, Any],
        duration_seconds: float,
    ) -> Dict[str, Any]:

        consumed_read_rate = cls._consumed_rate(
            table_metrics.get(cls.CONSUMED_READ),
            duration_seconds,
        )

        consumed_write_rate = cls._consumed_rate(
            table_metrics.get(cls.CONSUMED_WRITE),
            duration_seconds,
        )

        provisioned_read = cls._metric_value(
            table_metrics.get(cls.PROVISIONED_READ)
        )

        provisioned_write = cls._metric_value(
            table_metrics.get(cls.PROVISIONED_WRITE)
        )

        return {
            "table": {
                "consumed_read_units_per_second": consumed_read_rate,
                "consumed_write_units_per_second": consumed_write_rate,
                "provisioned_read": provisioned_read,
                "provisioned_write": provisioned_write,
                "read_utilization_percent": cls._utilization(
                    consumed_read_rate,
                    provisioned_read,
                ),
                "write_utilization_percent": cls._utilization(
                    consumed_write_rate,
                    provisioned_write,
                ),
                "traffic_observed": (
                    consumed_read_rate is not None
                    or consumed_write_rate is not None
                ),
            },
            "gsis": {
                str(index_name): cls._gsi_derived(
                    metrics,
                    duration_seconds,
                )
                for index_name, metrics in gsi_metrics.items()
            },
            "semantics": {
                # Consumed capacity is collected with statistic Sum
                # (a total over the whole query window); this
                # normalizes it to a units/second rate using the
                # analysis-window duration before it is compared
                # against Average-statistic provisioned capacity.
                # See the module docstring.
                "consumed_capacity_normalized_to_per_second": True,
                "missing_is_zero": False,
                "utilization_is_operational": True,
                "billing_source": False,
            },
        }

    @classmethod
    def _gsi_derived(
        cls,
        value: Any,
        duration_seconds: float,
    ) -> Dict[str, Any]:

        metrics = (
            value.get("metrics", {})
            if isinstance(value, dict)
            else {}
        )

        consumed_read_rate = cls._consumed_rate(
            metrics.get(cls.CONSUMED_READ),
            duration_seconds,
        )

        consumed_write_rate = cls._consumed_rate(
            metrics.get(cls.CONSUMED_WRITE),
            duration_seconds,
        )

        provisioned_read = cls._metric_value(
            metrics.get(cls.PROVISIONED_READ)
        )

        provisioned_write = cls._metric_value(
            metrics.get(cls.PROVISIONED_WRITE)
        )

        return {
            "consumed_read_units_per_second": consumed_read_rate,
            "consumed_write_units_per_second": consumed_write_rate,
            "provisioned_read": provisioned_read,
            "provisioned_write": provisioned_write,
            "read_utilization_percent": cls._utilization(
                consumed_read_rate,
                provisioned_read,
            ),
            "write_utilization_percent": cls._utilization(
                consumed_write_rate,
                provisioned_write,
            ),
        }

    @staticmethod
    def _metric_value(metric: Any) -> Optional[float]:

        if not isinstance(metric, dict):
            return None

        if metric.get("has_data") is not True:
            return None

        value = metric.get("value")

        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @classmethod
    def _consumed_rate(
        cls,
        metric: Any,
        duration_seconds: float,
    ) -> Optional[float]:
        """
        Convert a Sum-statistic consumed-capacity metric's raw total
        (summed over the whole query window) into a units/second
        rate comparable to the Average-statistic provisioned metric.
        """

        total = cls._metric_value(metric)

        if total is None:
            return None

        if not duration_seconds or duration_seconds <= 0:
            return None

        return total / duration_seconds

    @staticmethod
    def _utilization(
        consumed_rate: Optional[float],
        provisioned: Optional[float],
    ) -> Optional[float]:

        if (
            consumed_rate is None
            or provisioned is None
            or provisioned <= 0
        ):
            return None

        return min(100.0, consumed_rate / provisioned * 100.0)

    # ==============================================================
    # METRIC QUALITY
    # ==============================================================

    @classmethod
    def _metrics_to_map(cls, results: Any) -> Dict[str, Any]:

        result: Dict[str, Any] = {}

        for metric in results if isinstance(results, list) else []:

            if not isinstance(metric, dict):
                continue

            key = metric.get("metric_key") or metric.get(
                "metric_name"
            )

            if key:
                result[str(key)] = metric

            name = metric.get("metric_name")

            if name:
                result[str(name)] = metric

        return result

    @staticmethod
    def _collection_status(metrics: Dict[str, Any]) -> str:

        if not metrics:
            return "not_queried"

        values = list(metrics.values())

        observed = sum(
            1
            for metric in values
            if isinstance(metric, dict)
            and metric.get("status") == "ok"
            and metric.get("has_data") is True
        )

        errors = sum(
            1
            for metric in values
            if isinstance(metric, dict)
            and metric.get("status") == "error"
        )

        if observed > 0 and errors == 0:
            return "ok"

        if observed > 0 and errors > 0:
            return "partial"

        if errors == len(values):
            return "error"

        return "no_data"

    @staticmethod
    def _quality(
        table_metrics: Dict[str, Any],
        gsi_metrics: Dict[str, Any],
    ) -> Dict[str, Any]:

        values = list(table_metrics.values())

        for item in gsi_metrics.values():

            if not isinstance(item, dict):
                continue

            values.extend(
                list(item.get("metrics", {}).values())
            )

        return {
            "queried_metric_count": len(values),
            "observed_metric_count": sum(
                1
                for metric in values
                if isinstance(metric, dict)
                and metric.get("status") == "ok"
                and metric.get("has_data") is True
            ),
            "metric_error_count": sum(
                1
                for metric in values
                if isinstance(metric, dict)
                and metric.get("status") == "error"
            ),
        }

    # ==============================================================
    # TABLE HELPERS
    # ==============================================================

    @staticmethod
    def _billing_mode(table: Dict[str, Any]) -> str:

        summary = table.get("BillingModeSummary")

        if isinstance(summary, dict):

            mode = summary.get("BillingMode")

            if mode:
                return str(mode).upper()

        if isinstance(
            table.get("ProvisionedThroughput"), dict
        ):
            return "PROVISIONED"

        return "UNKNOWN"

    def _collect_pitr(
        self,
        table_name: Optional[str],
    ) -> Dict[str, Any]:

        if not table_name:
            return {"status": "incomplete"}

        try:

            response = (
                self.dynamodb.describe_continuous_backups(
                    TableName=table_name
                )
            )

            description = self._dict(
                response.get(
                    "ContinuousBackupsDescription"
                )
            )

            pitr = self._dict(
                description.get(
                    "PointInTimeRecoveryDescription"
                )
            )

            return {
                "status": "ok",
                "point_in_time_recovery_status": pitr.get(
                    "PointInTimeRecoveryStatus"
                ),
            }

        except Exception as exc:

            return {"status": "error", "error": str(exc)}

    def _collect_ttl(
        self,
        table_name: Optional[str],
    ) -> Dict[str, Any]:

        if not table_name:
            return {"status": "incomplete"}

        try:

            response = self.dynamodb.describe_time_to_live(
                TableName=table_name
            )

            specification = self._dict(
                response.get("TimeToLiveDescription")
            )

            return {
                "status": "ok",
                "enabled": specification.get(
                    "TimeToLiveStatus"
                )
                == "ENABLED",
                "attribute_name": specification.get(
                    "AttributeName"
                ),
            }

        except Exception as exc:

            return {"status": "error", "error": str(exc)}

    def _collect_tags(
        self,
        table_arn: Optional[str],
    ) -> Dict[str, Any]:

        if not table_arn:
            return {}

        try:

            paginator = self.dynamodb.get_paginator(
                "list_tags_of_resource"
            )

            tags: List[Dict[str, Any]] = []

            for page in paginator.paginate(
                ResourceArn=table_arn
            ):
                tags.extend(page.get("Tags", []))

            return {
                str(tag.get("Key")): tag.get("Value")
                for tag in tags
                if isinstance(tag, dict) and tag.get("Key")
            }

        except Exception:

            return {}

    # ==============================================================
    # ISO / DICT
    # ==============================================================

    @staticmethod
    def _dict(value: Any) -> Dict[str, Any]:

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _isoformat(value: Any) -> Optional[str]:

        if value is None:
            return None

        if isinstance(value, datetime):

            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)

            return value.isoformat()

        if hasattr(value, "isoformat"):
            return value.isoformat()

        return str(value)
