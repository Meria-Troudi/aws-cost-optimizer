"""
Persistence layer for normalized resource collection.

Responsibilities
----------------
- Persist normalized AWS resources.
- Persist configuration/topology/relationships snapshots.
- Persist observed CloudWatch metrics.
- Preserve queried/no-data/error metric information in snapshots.
- Never use billing identity to decide whether a resource is persisted.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable

from aws_cost_optimizer.analysis.metrics import (
    count_observed_metrics,
    count_queried_metrics,
    count_missing_metrics,
    count_metric_errors,
    metric_has_observed_data,
)

from backend.database.repository.resource_repository import (
    get_or_create_resource,
    save_resource_snapshot,
)

from backend.database.repository.metric_repository import (
    save_metric,
)


class CollectorPersistence:

    # ==================================================================
    # RESOURCE
    # ==================================================================

    def save(
        self,
        db,
        scan,
        resource: dict,
    ):

        if not isinstance(resource, dict):
            raise TypeError(
                "Collector resource must be a dictionary"
            )

        resource_id = self._required_resource_id(resource)

        resource_type = self._safe_string(
            resource.get("resource_type"),
            default="unknown",
        )

        identity = self._safe_dict(
            resource.get("identity")
        )

        configuration = self._safe_dict(
            resource.get("configuration")
        )

        topology = self._safe_dict(
            resource.get("topology")
        )

        relationships = self._safe_dict(
            resource.get("relationships")
        )

        raw = self._safe_dict(
            resource.get("raw")
        )

        optimization_evidence = self._safe_dict(
            resource.get("optimization_evidence")
        )

        state = (
            identity.get("state")
            or configuration.get("state")
        )

        name = (
            identity.get("name")
            or identity.get("load_balancer_name")
            or identity.get("db_instance_identifier")
            or identity.get("vpc_endpoint_id")
            or identity.get("transit_gateway_id")
            or identity.get("nat_gateway_id")
            or resource_id
        )

        tags = self._safe_dict(
            identity.get("tags")
        )

        account_id = (
            resource.get("account_id")
            or getattr(scan, "account_id", None)
            or "unknown"
        )

        obj = get_or_create_resource(
            db=db,
            account_id=str(account_id),
            aws_resource_id=resource_id,
            service=self._infer_service(
                resource_type
            ),
            resource_type=resource_type,
            region=resource.get("region"),
            name=name,
            tags=tags,
        )

        db.flush()

        snapshot_relationships = dict(
            relationships
        )

        if any(
            (
                bool(identity),
                bool(configuration),
                bool(topology),
                bool(snapshot_relationships),
                bool(raw),
            )
        ):

            save_resource_snapshot(
                db=db,
                resource_id=obj.id,
                scan_run_id=scan.id,
                source_api="collector",
                configuration=configuration,
                raw_response=raw,
                topology=topology,
                relationships=snapshot_relationships,
                optimization_evidence=(
                    optimization_evidence
                    or {}
                ),
                state=state,
                availability_zone=(
                    configuration.get("availability_zone")
                    or identity.get("availability_zone")
                ),
            )

        self._save_observations(
            db=db,
            scan=scan,
            resource_obj=obj,
            resource=resource,
        )

        return obj

    # ==================================================================
    # OBSERVATIONS
    # ==================================================================

    def _save_observations(
        self,
        db,
        scan,
        resource_obj,
        resource: dict,
    ) -> int:

        observations = self._safe_dict(
            resource.get("observations")
        )

        cloudwatch = self._safe_dict(
            observations.get("cloudwatch")
        )

        if not cloudwatch:
            return 0

        metrics = cloudwatch.get("metrics")

        saved = 0

        for metric in self._iter_metrics(metrics):

            # Keep no_data/error results in the resource snapshot.
            #
            # Only confirmed observations become Metric rows.
            if not metric_has_observed_data(metric):
                continue

            saved_metric = save_metric(
                db,
                resource_id=resource_obj.id,
                scan_run_id=scan.id,
                metric=metric,
            )

            if saved_metric is not None:
                saved += 1

        return saved

    # ==================================================================
    # METRIC COUNTS
    # ==================================================================

    def metric_counts(
        self,
        resource: dict,
    ) -> dict[str, int]:

        observations = self._safe_dict(
            resource.get("observations")
        )

        cloudwatch = self._safe_dict(
            observations.get("cloudwatch")
        )

        metrics = cloudwatch.get("metrics")

        return {
            "queried":
                count_queried_metrics(metrics),

            "observed":
                count_observed_metrics(metrics),

            "no_data":
                count_missing_metrics(metrics),

            "errors":
                count_metric_errors(metrics),
        }

    def count_metrics(
        self,
        resource: dict,
    ) -> int:

        return self.metric_counts(
            resource
        )["observed"]

    def count_queried_metrics(
        self,
        resource: dict,
    ) -> int:

        return self.metric_counts(
            resource
        )["queried"]

    def count_missing_metrics(
        self,
        resource: dict,
    ) -> int:

        return self.metric_counts(
            resource
        )["no_data"]

    def count_metric_errors(
        self,
        resource: dict,
    ) -> int:

        return self.metric_counts(
            resource
        )["errors"]

    # ==================================================================
    # NORMALIZATION
    # ==================================================================

    @staticmethod
    def _iter_metrics(
        metrics: Any,
    ) -> Iterable[Dict[str, Any]]:

        if isinstance(metrics, dict):

            for metric in metrics.values():

                if isinstance(metric, dict):
                    yield metric

            return

        if isinstance(metrics, list):

            for metric in metrics:

                if isinstance(metric, dict):
                    yield metric

    # ==================================================================
    # SERVICE
    # ==================================================================

    @staticmethod
    def _infer_service(
        resource_type: str,
    ) -> str:

        return {
            "nat_gateway":
                "Amazon Virtual Private Cloud",

            "transit_gateway":
                "Amazon Virtual Private Cloud",

            "vpc_endpoint":
                "Amazon Virtual Private Cloud",

            "public_ipv4":
                "Amazon Virtual Private Cloud",

            "elastic_ip":
                "Amazon Virtual Private Cloud",

            "vpc_peering":
                "Amazon Virtual Private Cloud",

            "internet_gateway":
                "Amazon Virtual Private Cloud",

            "carrier_gateway":
                "Amazon Virtual Private Cloud",

            "egress_only_internet_gateway":
                "Amazon Virtual Private Cloud",

            "local_gateway":
                "Amazon Virtual Private Cloud",

            "rds_instance":
                "Amazon Relational Database Service",

            "rds_cluster":
                "Amazon Relational Database Service",

            "rds_snapshot":
                "Amazon Relational Database Service",

            "ec2_instance":
                "Amazon Elastic Compute Cloud - Compute",

            "ebs_volume":
                "Amazon Elastic Compute Cloud - Compute",

            "eks_cluster":
                (
                    "Amazon Elastic Container Service "
                    "for Kubernetes"
                ),

            "load_balancer":
                "Amazon Elastic Load Balancing",

            "s3_bucket":
                "Amazon Simple Storage Service",

            "lambda_function":
                "AWS Lambda",
        }.get(
            resource_type,
            "Unknown",
        )

    # ==================================================================
    # HELPERS
    # ==================================================================

    @staticmethod
    def _safe_dict(
        value: Any,
    ) -> Dict[str, Any]:

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _safe_string(
        value: Any,
        default: str = "",
    ) -> str:

        if value is None:
            return default

        value = str(value).strip()

        return value or default

    @staticmethod
    def _required_resource_id(
        resource: Dict[str, Any],
    ) -> str:

        value = (
            resource.get("resource_id")
            or resource.get("id")
        )

        if value is None:
            raise ValueError(
                "Collector resource is missing "
                "'resource_id'"
            )

        value = str(value).strip()

        if not value:
            raise ValueError(
                "Collector resource has an empty "
                "'resource_id'"
            )

        return value