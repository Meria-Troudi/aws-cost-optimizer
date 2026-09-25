"""
AWS S3 collector.

Purpose
-------
Collect only evidence required to explain S3 cost and identify
defensible cost-optimization opportunities.

Evidence domains
----------------
1. Bucket identity and lifecycle
2. Bucket configuration
3. Storage usage evidence
4. Request/activity evidence when available
5. Versioning and delete-marker evidence
6. Lifecycle configuration
7. Intelligent-Tiering configuration
8. Replication configuration
9. Encryption configuration
10. Object-lock / retention configuration
11. Public-access configuration
12. Bucket tagging
13. S3 Inventory configuration
14. Data-quality / evidence availability

The collector does NOT:
- calculate AWS billing cost
- attribute Cost Explorer cost to individual buckets
- calculate savings
- decide that a bucket should be deleted
- decide that a storage class should be changed
- make optimization decisions

Billing attribution is handled separately by Cost Explorer /
billing reconciliation.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.metrics.cloudwatch import CloudWatchMetricCollector
from collection.registry import register

from aws_cost_optimizer.analysis.metrics import (
    metric_has_observed_data,
    metric_is_sum,
    metric_numeric_value,
    metric_sum_value,
)


@register
class S3Collector(BaseCollector):

    key = "s3"
    resource_type = "s3_bucket"

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
            raise ValueError("S3 collector requires a region.")

        self.s3 = get_client("s3", self.region)
        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = CloudWatchMetricCollector(self.cloudwatch)

        self._bucket_region_cache: dict[
            str,
            Optional[str],
        ] = {}

        self._metrics_batch_cache: dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        self._bucket_metadata_cache: dict[
            str,
            Dict[str, Any],
        ] = {}

        self._bucket_by_name: dict[
            str,
            Dict[str, Any],
        ] = {}

    # PROFILE

    def _profile_section(
        self,
        name: str,
    ) -> dict[str, Any]:

        value = self.profile.get(name, {})

        return value if isinstance(value, dict) else {}

    def _cloudwatch_profile(self) -> dict[str, Any]:

        observations = self._profile_section("observations")

        value = observations.get(
            "cloudwatch",
            {},
        )

        return value if isinstance(value, dict) else {}

    def _profile_metric_specs(self) -> list[dict[str, Any]]:

        specs = self._cloudwatch_profile().get(
            "metrics",
            [],
        )

        if not isinstance(specs, list):
            return []

        return [item for item in specs if isinstance(item, dict)]

    def _metric_group(
        self,
        name: str,
    ) -> tuple[str, ...]:

        result: list[str] = []

        for spec in self._profile_metric_specs():

            if str(spec.get("group") or "").strip() != name:
                continue

            metric_name = str(spec.get("name") or "").strip()

            if metric_name and metric_name not in result:
                result.append(metric_name)

        return tuple(result)

    def _storage_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group("storage")

    def _request_metrics(
        self,
    ) -> tuple[str, ...]:

        return self._metric_group("request")

    # DISCOVERY

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        self._metrics_batch_cache = {}
        self._bucket_metadata_cache = {}
        self._bucket_by_name = {}

        response = self.s3.list_buckets()

        buckets = response.get(
            "Buckets",
            [],
        )

        resources: list[Dict[str, Any]] = []

        for bucket in buckets:

            if not isinstance(bucket, dict):
                continue

            bucket_name = bucket.get("Name")

            if not bucket_name:
                continue

            bucket_name = str(bucket_name)

            bucket_region = self._get_bucket_region(bucket_name)

            if not self._bucket_matches_region(bucket_region):
                continue

            raw = {
                "Name": bucket_name,
                "CreationDate": bucket.get("CreationDate"),
                "Region": bucket_region,
            }

            resource = {
                "id": bucket_name,
                "raw": raw,
            }

            resources.append(resource)

            self._bucket_by_name[bucket_name] = raw

        self._prefetch_metrics_batch(resources)

        return resources

    def _bucket_matches_region(
        self,
        bucket_region: Optional[str],
    ) -> bool:

        if not bucket_region:
            return False

        region = str(bucket_region)

        # AWS returns us-east-1 for the legacy
        # empty LocationConstraint.
        if region == "us-east-1" and self.region == "us-east-1":
            return True

        return region == self.region

    # CLOUDWATCH

    def _prefetch_metrics_batch(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        profile = self._cloudwatch_profile()

        if not profile:
            return

        if (
            profile.get(
                "enabled",
                True,
            )
            is False
        ):
            return

        metric_specs = profile.get(
            "metrics",
            [],
        )

        if (
            not isinstance(
                metric_specs,
                list,
            )
            or not metric_specs
        ):
            return

        namespace = self.cloudwatch_namespace()

        requested_period = self._safe_period(profile.get("period"))

        try:
            start, end = self.get_analysis_period()
        except ValueError:
            return

        requests: list[Dict[str, Any]] = []
        request_metadata: dict[
            str,
            Dict[str, Any],
        ] = {}

        for resource in resources:

            bucket_name = resource.get("id")

            if not bucket_name:
                continue

            bucket_name = str(bucket_name)

            query_key = bucket_name

            dimensions = [
                {
                    "Name": "BucketName",
                    "Value": bucket_name,
                }
            ]

            requests.append(
                {
                    "resource_key": query_key,
                    "namespace": namespace,
                    "dimensions": dimensions,
                    "metric_specs": metric_specs,
                }
            )

            request_metadata[query_key] = {
                "bucket_name": bucket_name,
            }

        if not requests:
            return

        raw_results = self.metric_collector.collect_batch(
            requests,
            start=start,
            end=end,
            requested_period=requested_period,
        )

        self._metrics_batch_cache = self._normalize_metric_batch_results(
            raw_results,
            request_metadata,
        )

    # RESULT NORMALIZATION

    def _normalize_metric_batch_results(
        self,
        raw_results: Dict[
            str,
            List[Dict[str, Any]],
        ],
        request_metadata: Dict[
            str,
            Dict[str, Any],
        ],
    ) -> Dict[
        str,
        List[Dict[str, Any]],
    ]:

        grouped: dict[
            str,
            list[Dict[str, Any]],
        ] = defaultdict(list)

        for query_key, results in (raw_results or {}).items():

            metadata = request_metadata.get(query_key)

            if not metadata:
                continue

            bucket_name = metadata.get("bucket_name")

            if not bucket_name:
                continue

            for result in results or []:

                if isinstance(
                    result,
                    dict,
                ):
                    grouped[str(bucket_name)].append(result)

        return dict(grouped)

    # RESOURCE ID

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return str(resource["id"])

    # IDENTITY

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        bucket_name = str(resource["id"])

        raw = resource.get("raw")

        raw = raw if isinstance(raw, dict) else {}

        tags = self._get_bucket_tags(bucket_name)

        return {
            "name": (tags.get("Name") or bucket_name),
            "bucket_name": bucket_name,
            "region": (self._get_bucket_region(bucket_name)),
            "creation_date": (
                raw.get("CreationDate").isoformat() if raw.get("CreationDate") else None
            ),
            "tags": tags,
        }

    # CONFIGURATION

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        bucket_name = str(resource["id"])

        versioning = self._get_versioning(bucket_name)

        lifecycle = self._get_lifecycle(bucket_name)

        encryption = self._get_encryption(bucket_name)

        replication = self._get_replication(bucket_name)

        public_access = self._get_public_access(bucket_name)

        object_lock = self._get_object_lock(bucket_name)

        intelligent_tiering = self._get_intelligent_tiering(bucket_name)

        inventory = self._get_inventory(bucket_name)

        notification = self._get_notification(bucket_name)

        logging = self._get_logging(bucket_name)

        ownership = self._get_ownership(bucket_name)

        acl = self._get_acl(bucket_name)

        tags = self._get_bucket_tags(bucket_name)

        return {
            "bucket_name": bucket_name,
            "region": (self._get_bucket_region(bucket_name)),
            "versioning": versioning,
            "versioning_enabled": (versioning.get("status") == "Enabled"),
            "versioning_status": (versioning.get("status")),
            "mfa_delete": versioning.get("mfa_delete"),
            "lifecycle": lifecycle,
            "lifecycle_enabled": lifecycle.get("enabled"),
            "lifecycle_rule_count": lifecycle.get(
                "rule_count",
                0,
            ),
            "lifecycle_rules": lifecycle.get(
                "rules",
                [],
            ),
            "encryption": encryption,
            "encryption_enabled": encryption.get("enabled"),
            "encryption_algorithm": encryption.get("algorithm"),
            "replication": replication,
            "replication_enabled": replication.get("enabled"),
            "replication_rule_count": replication.get(
                "rule_count",
                0,
            ),
            "public_access": public_access,
            "block_public_access": public_access.get("block_public_access"),
            "object_lock": object_lock,
            "object_lock_enabled": object_lock.get("enabled"),
            "object_lock_mode": object_lock.get("default_retention_mode"),
            "object_lock_days": object_lock.get("default_retention_days"),
            "object_lock_years": object_lock.get("default_retention_years"),
            "intelligent_tiering": (intelligent_tiering),
            "intelligent_tiering_enabled": (intelligent_tiering.get("enabled")),
            "intelligent_tiering_configuration_count": (
                intelligent_tiering.get(
                    "configuration_count",
                    0,
                )
            ),
            "inventory": inventory,
            "inventory_enabled": inventory.get("enabled"),
            "inventory_configuration_count": (
                inventory.get(
                    "configuration_count",
                    0,
                )
            ),
            "logging": logging,
            "logging_enabled": logging.get("enabled"),
            "ownership": ownership,
            "object_ownership": ownership.get("object_ownership"),
            "acl": acl,
            "notification": notification,
            "notification_enabled": notification.get("enabled"),
            "tags": tags,
        }

    # OBSERVATIONS

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        profile = self._cloudwatch_profile()

        if not profile:
            raise ValueError("S3 profile must define " "observations.cloudwatch.")

        if (
            profile.get(
                "enabled",
                True,
            )
            is False
        ):

            return {
                "status": "disabled",
                "cloudwatch": {},
                "derived": {},
            }

        metric_specs = profile.get(
            "metrics",
            [],
        )

        if (
            not isinstance(
                metric_specs,
                list,
            )
            or not metric_specs
        ):

            raise ValueError("S3 profile must define " "CloudWatch metrics.")

        namespace = self.cloudwatch_namespace()

        requested_period = self._safe_period(profile.get("period"))

        start, end = self.get_analysis_period()

        bucket_name = str(resource["id"])

        results = self._metrics_batch_cache.get(
            bucket_name,
            [],
        )

        metrics: Dict[str, Any] = {}

        for result in results:

            metric_name = result.get("metric_name")

            if metric_name:
                metrics[str(metric_name)] = result

        effective_periods = sorted(
            {
                result.get("effective_period")
                for result in results
                if result.get("effective_period") is not None
            }
        )

        effective_period = effective_periods[0] if len(effective_periods) == 1 else None

        return {
            "status": "ok",
            "cloudwatch": {
                "namespace": namespace,
                "requested_period": (requested_period),
                "effective_period": (effective_period),
                "effective_periods": (effective_periods),
                "start": start.isoformat(),
                "end": end.isoformat(),
                "dimensions": [
                    {
                        "Name": "BucketName",
                        "Value": bucket_name,
                    }
                ],
                "metrics": metrics,
            },
            "derived": (self._build_derived_data(metrics)),
        }

    # DERIVED ACTIVITY

    def _build_derived_data(
        self,
        metrics_dict: Dict[str, Any],
    ) -> Dict[str, Any]:

        storage_metrics = self._storage_metrics()

        request_metrics = self._request_metrics()

        storage_values = {
            name: metric_sum_value(metrics_dict.get(name)) for name in storage_metrics
        }

        storage_observed = {
            name: metric_has_observed_data(metrics_dict.get(name))
            for name in storage_metrics
        }

        request_values = {
            name: metric_sum_value(metrics_dict.get(name)) for name in request_metrics
        }

        request_observed = {
            name: metric_has_observed_data(metrics_dict.get(name))
            for name in request_metrics
        }

        storage_available = any(storage_observed.values())

        request_available = any(request_observed.values())

        storage_complete = bool(storage_metrics) and all(storage_observed.values())

        request_complete = bool(request_metrics) and all(request_observed.values())

        storage_semantics_valid = all(
            (not storage_observed[name] or metric_is_sum(metrics_dict.get(name)))
            for name in storage_metrics
        )

        request_semantics_valid = all(
            (not request_observed[name] or metric_is_sum(metrics_dict.get(name)))
            for name in request_metrics
        )

        bucket_size_bytes = storage_values.get("BucketSizeBytes")

        number_of_objects = storage_values.get("NumberOfObjects")

        total_requests = request_values.get("AllRequests")

        get_requests = request_values.get("GetRequests")

        put_requests = request_values.get("PutRequests")

        delete_requests = request_values.get("DeleteRequests")

        bytes_downloaded = request_values.get("BytesDownloaded")

        bytes_uploaded = request_values.get("BytesUploaded")

        storage_positive = (
            bucket_size_bytes is not None and bucket_size_bytes > 0
        ) or (number_of_objects is not None and number_of_objects > 0)

        request_positive = any(
            value is not None and value > 0
            for value in (
                total_requests,
                get_requests,
                put_requests,
                delete_requests,
                bytes_downloaded,
                bytes_uploaded,
            )
        )

        storage_zero = (
            storage_complete
            and storage_semantics_valid
            and all(
                value == 0 for value in storage_values.values() if value is not None
            )
            and all(value is not None for value in storage_values.values())
        )

        request_zero = (
            request_complete
            and request_semantics_valid
            and all(
                value == 0 for value in request_values.values() if value is not None
            )
            and all(value is not None for value in request_values.values())
        )

        return {
            "profile_metric_groups": {
                "storage": list(storage_metrics),
                "request": list(request_metrics),
            },
            "storage": {
                "bucket_size_bytes": (bucket_size_bytes),
                "number_of_objects": (number_of_objects),
                "available": (storage_available),
                "complete": (storage_complete),
                "observed": (storage_positive if storage_available else None),
                "zero": storage_zero,
                "metric_observation": (storage_observed),
            },
            "requests": {
                "total": total_requests,
                "get": get_requests,
                "put": put_requests,
                "delete": delete_requests,
                "bytes_downloaded": (bytes_downloaded),
                "bytes_uploaded": (bytes_uploaded),
                "available": (request_available),
                "complete": (request_complete),
                "observed": (request_positive if request_available else None),
                "zero": request_zero,
                "metric_observation": (request_observed),
            },
            "activity": {
                "observed": (
                    storage_positive
                    if storage_available
                    else (request_positive if request_available else None)
                ),
                "storage_observed": (storage_positive if storage_available else None),
                "request_observed": (request_positive if request_available else None),
                "available": (storage_available or request_available),
            },
            "semantics": {
                "storage_source": ("CloudWatch"),
                "request_source": ("CloudWatch"),
                "storage_is_billing_usage": False,
                "request_is_billing_usage": False,
                "storage_requires_sum_statistic": True,
                "request_requires_sum_statistic": True,
                "storage_semantics_valid": (storage_semantics_valid),
                "request_semantics_valid": (request_semantics_valid),
                "storage_indicator": ("s3_storage_usage_evidence"),
                "request_indicator": ("s3_request_activity_evidence"),
                "missing_is_zero": False,
            },
        }

    # OPTIMIZATION EVIDENCE

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = self._dict(collected_resource.get("identity"))

        configuration = self._dict(collected_resource.get("configuration"))

        observations = self._dict(collected_resource.get("observations"))

        derived = self._dict(observations.get("derived"))

        storage = self._dict(derived.get("storage"))

        requests = self._dict(derived.get("requests"))

        semantics = self._dict(derived.get("semantics"))

        cloudwatch = self._dict(observations.get("cloudwatch"))

        lifecycle = self._dict(configuration.get("lifecycle"))

        versioning = self._dict(configuration.get("versioning"))

        replication = self._dict(configuration.get("replication"))

        intelligent_tiering = self._dict(configuration.get("intelligent_tiering"))

        inventory = self._dict(configuration.get("inventory"))

        return {
            "resource": {
                "id": resource.get("id"),
                "name": identity.get("name"),
                "region": identity.get("region"),
            },
            "configuration": {
                "bucket_name": configuration.get("bucket_name"),
                "region": configuration.get("region"),
                "versioning_enabled": configuration.get("versioning_enabled"),
                "versioning_status": configuration.get("versioning_status"),
                "mfa_delete": configuration.get("mfa_delete"),
                "lifecycle_enabled": configuration.get("lifecycle_enabled"),
                "lifecycle_rule_count": configuration.get(
                    "lifecycle_rule_count",
                    0,
                ),
                "encryption_enabled": configuration.get("encryption_enabled"),
                "encryption_algorithm": configuration.get("encryption_algorithm"),
                "replication_enabled": configuration.get("replication_enabled"),
                "replication_rule_count": configuration.get(
                    "replication_rule_count",
                    0,
                ),
                "block_public_access": configuration.get("block_public_access"),
                "object_lock_enabled": configuration.get("object_lock_enabled"),
                "object_lock_mode": configuration.get("object_lock_mode"),
                "object_lock_days": configuration.get("object_lock_days"),
                "object_lock_years": configuration.get("object_lock_years"),
                "intelligent_tiering_enabled": configuration.get(
                    "intelligent_tiering_enabled"
                ),
                "intelligent_tiering_configuration_count": (
                    configuration.get(
                        "intelligent_tiering_configuration_count",
                        0,
                    )
                ),
                "inventory_enabled": configuration.get("inventory_enabled"),
                "inventory_configuration_count": (
                    configuration.get(
                        "inventory_configuration_count",
                        0,
                    )
                ),
                "logging_enabled": configuration.get("logging_enabled"),
                "object_ownership": configuration.get("object_ownership"),
                "notification_enabled": configuration.get("notification_enabled"),
            },
            "storage": {
                "bucket_size_bytes": storage.get("bucket_size_bytes"),
                "number_of_objects": storage.get("number_of_objects"),
                "available": storage.get("available"),
                "complete": storage.get("complete"),
                "observed": storage.get("observed"),
                "zero": storage.get("zero"),
                "metric_observation": storage.get(
                    "metric_observation",
                    {},
                ),
            },
            "requests": {
                "total": requests.get("total"),
                "get": requests.get("get"),
                "put": requests.get("put"),
                "delete": requests.get("delete"),
                "bytes_downloaded": requests.get("bytes_downloaded"),
                "bytes_uploaded": requests.get("bytes_uploaded"),
                "available": requests.get("available"),
                "complete": requests.get("complete"),
                "observed": requests.get("observed"),
                "zero": requests.get("zero"),
                "metric_observation": requests.get(
                    "metric_observation",
                    {},
                ),
            },
            "lifecycle": {
                "enabled": lifecycle.get("enabled"),
                "rule_count": lifecycle.get(
                    "rule_count",
                    0,
                ),
                "rules": lifecycle.get(
                    "rules",
                    [],
                ),
            },
            "versioning": {
                "enabled": (versioning.get("status") == "Enabled"),
                "status": versioning.get("status"),
                "mfa_delete": versioning.get("mfa_delete"),
            },
            "replication": {
                "enabled": replication.get("enabled"),
                "rule_count": replication.get(
                    "rule_count",
                    0,
                ),
                "rules": replication.get(
                    "rules",
                    [],
                ),
            },
            "intelligent_tiering": {
                "enabled": intelligent_tiering.get("enabled"),
                "configuration_count": (
                    intelligent_tiering.get(
                        "configuration_count",
                        0,
                    )
                ),
                "configurations": (
                    intelligent_tiering.get(
                        "configurations",
                        [],
                    )
                ),
            },
            "inventory": {
                "enabled": inventory.get("enabled"),
                "configuration_count": (
                    inventory.get(
                        "configuration_count",
                        0,
                    )
                ),
            },
            "data_quality": {
                "cloudwatch_available": bool(cloudwatch.get("metrics", {})),
                "storage_available": storage.get("available"),
                "storage_complete": storage.get("complete"),
                "request_data_available": requests.get("available"),
                "request_data_complete": requests.get("complete"),
                "storage_semantics_valid": semantics.get("storage_semantics_valid"),
                "request_semantics_valid": semantics.get("request_semantics_valid"),
                "missing_is_zero": False,
            },
            "semantics": {
                "storage_is_billing_usage": False,
                "request_is_billing_usage": False,
                "storage_indicator": ("s3_storage_usage_evidence"),
                "request_indicator": ("s3_request_activity_evidence"),
                "billing_attribution": ("handled_by_cost_reconciliation"),
            },
        }

    # S3 CONFIGURATION API HELPERS

    def _get_bucket_region(
        self,
        bucket_name: str,
    ) -> Optional[str]:

        if bucket_name in self._bucket_region_cache:
            return self._bucket_region_cache[bucket_name]

        try:
            response = self.s3.get_bucket_location(Bucket=bucket_name)

            location = response.get("LocationConstraint")

            if location in (
                None,
                "",
            ):
                region = "us-east-1"

            elif location == "EU":
                region = "eu-west-1"

            else:
                region = str(location)

        except Exception:
            region = None

        self._bucket_region_cache[bucket_name] = region

        return region

    def _get_versioning(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_versioning(Bucket=bucket_name)

            return {
                "status": response.get("Status"),
                "mfa_delete": response.get("MFADelete"),
            }

        except Exception as exc:

            return {
                "status": "unknown",
                "mfa_delete": None,
                "error": self._error_text(exc),
            }

    def _get_lifecycle(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)

            rules = response.get(
                "Rules",
                [],
            )

            if not isinstance(
                rules,
                list,
            ):
                rules = []

            normalized = [
                self._normalize_lifecycle_rule(rule)
                for rule in rules
                if isinstance(
                    rule,
                    dict,
                )
            ]

            return {
                "enabled": bool(normalized),
                "rule_count": len(normalized),
                "rules": normalized,
            }

        except Exception as exc:

            error_code = self._exception_code(exc)

            if error_code in {
                "NoSuchLifecycleConfiguration",
                "404",
            }:

                return {
                    "enabled": False,
                    "rule_count": 0,
                    "rules": [],
                }

            return {
                "enabled": None,
                "rule_count": 0,
                "rules": [],
                "error": self._error_text(exc),
            }

    def _normalize_lifecycle_rule(
        self,
        rule: Dict[str, Any],
    ) -> Dict[str, Any]:

        transitions = rule.get(
            "Transitions",
            [],
        )

        noncurrent_transitions = rule.get(
            "NoncurrentVersionTransitions",
            [],
        )

        expirations = rule.get(
            "Expiration",
            {},
        )

        abort_multipart = rule.get(
            "AbortIncompleteMultipartUpload",
            {},
        )

        return {
            "id": rule.get("ID"),
            "status": rule.get("Status"),
            "filter": rule.get("Filter"),
            "prefix": rule.get("Prefix"),
            "transitions": (
                transitions
                if isinstance(
                    transitions,
                    list,
                )
                else []
            ),
            "noncurrent_version_transitions": (
                noncurrent_transitions
                if isinstance(
                    noncurrent_transitions,
                    list,
                )
                else []
            ),
            "expiration": (
                expirations
                if isinstance(
                    expirations,
                    dict,
                )
                else {}
            ),
            "noncurrent_version_expiration": (rule.get("NoncurrentVersionExpiration")),
            "abort_incomplete_multipart_upload": (
                abort_multipart
                if isinstance(
                    abort_multipart,
                    dict,
                )
                else {}
            ),
        }

    def _get_encryption(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_encryption(Bucket=bucket_name)

            configuration = response.get(
                "ServerSideEncryptionConfiguration",
                {},
            )

            rules = configuration.get(
                "Rules",
                [],
            )

            if not isinstance(
                rules,
                list,
            ):
                rules = []

            default_rule = (
                rules[0]
                if rules
                and isinstance(
                    rules[0],
                    dict,
                )
                else {}
            )

            default_encryption = default_rule.get(
                "ApplyServerSideEncryptionByDefault",
                {},
            )

            if not isinstance(
                default_encryption,
                dict,
            ):
                default_encryption = {}

            return {
                "enabled": bool(rules),
                "algorithm": (default_encryption.get("SSEAlgorithm")),
                "kms_key_id": (default_encryption.get("KMSMasterKeyID")),
                "bucket_key_enabled": (default_rule.get("BucketKeyEnabled")),
                "rules": rules,
            }

        except Exception as exc:

            code = self._exception_code(exc)

            if code in {
                "ServerSideEncryptionConfigurationNotFoundError",
                "404",
            }:

                return {
                    "enabled": False,
                    "algorithm": None,
                    "kms_key_id": None,
                    "bucket_key_enabled": None,
                    "rules": [],
                }

            return {
                "enabled": None,
                "algorithm": None,
                "kms_key_id": None,
                "bucket_key_enabled": None,
                "rules": [],
                "error": self._error_text(exc),
            }

    def _get_replication(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_replication(Bucket=bucket_name)

            configuration = response.get(
                "ReplicationConfiguration",
                {},
            )

            rules = configuration.get(
                "Rules",
                [],
            )

            if not isinstance(
                rules,
                list,
            ):
                rules = []

            return {
                "enabled": bool(rules),
                "role": configuration.get("Role"),
                "rule_count": len(rules),
                "rules": rules,
            }

        except Exception as exc:

            code = self._exception_code(exc)

            if code in {
                "ReplicationConfigurationNotFoundError",
                "ReplicationConfigurationNotFound",
                "404",
            }:

                return {
                    "enabled": False,
                    "role": None,
                    "rule_count": 0,
                    "rules": [],
                }

            return {
                "enabled": None,
                "role": None,
                "rule_count": 0,
                "rules": [],
                "error": self._error_text(exc),
            }

    def _get_public_access(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)

            configuration = response.get(
                "PublicAccessBlockConfiguration",
                {},
            )

            if not isinstance(
                configuration,
                dict,
            ):
                configuration = {}

            values = [
                configuration.get("BlockPublicAcls"),
                configuration.get("IgnorePublicAcls"),
                configuration.get("BlockPublicPolicy"),
                configuration.get("RestrictPublicBuckets"),
            ]

            return {
                "block_public_access": (
                    all(value is True for value in values) if values else None
                ),
                "block_public_acls": (configuration.get("BlockPublicAcls")),
                "ignore_public_acls": (configuration.get("IgnorePublicAcls")),
                "block_public_policy": (configuration.get("BlockPublicPolicy")),
                "restrict_public_buckets": (configuration.get("RestrictPublicBuckets")),
            }

        except Exception as exc:

            code = self._exception_code(exc)

            if code in {
                "NoSuchPublicAccessBlockConfiguration",
                "404",
            }:

                return {
                    "block_public_access": False,
                    "block_public_acls": False,
                    "ignore_public_acls": False,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                }

            return {
                "block_public_access": None,
                "block_public_acls": None,
                "ignore_public_acls": None,
                "block_public_policy": None,
                "restrict_public_buckets": None,
                "error": self._error_text(exc),
            }

    def _get_object_lock(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_object_lock_configuration(Bucket=bucket_name)

            configuration = response.get(
                "ObjectLockConfiguration",
                {},
            )

            if not isinstance(
                configuration,
                dict,
            ):
                configuration = {}

            rule = configuration.get(
                "Rule",
                {},
            )

            if not isinstance(
                rule,
                dict,
            ):
                rule = {}

            retention = rule.get(
                "DefaultRetention",
                {},
            )

            if not isinstance(
                retention,
                dict,
            ):
                retention = {}

            return {
                "enabled": (configuration.get("ObjectLockEnabled") == "Enabled"),
                "default_retention_mode": (retention.get("Mode")),
                "default_retention_days": (retention.get("Days")),
                "default_retention_years": (retention.get("Years")),
            }

        except Exception as exc:

            code = self._exception_code(exc)

            if code in {
                "ObjectLockConfigurationNotFoundError",
                "ObjectLockConfigurationNotFound",
                "404",
            }:

                return {
                    "enabled": False,
                    "default_retention_mode": None,
                    "default_retention_days": None,
                    "default_retention_years": None,
                }

            return {
                "enabled": None,
                "default_retention_mode": None,
                "default_retention_days": None,
                "default_retention_years": None,
                "error": self._error_text(exc),
            }

    def _get_intelligent_tiering(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            paginator = self.s3.get_paginator(
                "list_bucket_intelligent_tiering_configurations"
            )

            configurations = []

            for page in paginator.paginate(Bucket=bucket_name):

                values = page.get(
                    "IntelligentTieringConfigurations",
                    [],
                )

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                configurations.extend(values)

            return {
                "enabled": bool(configurations),
                "configuration_count": len(configurations),
                "configurations": configurations,
            }

        except Exception as exc:

            return {
                "enabled": None,
                "configuration_count": 0,
                "configurations": [],
                "error": self._error_text(exc),
            }

    def _get_inventory(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            paginator = self.s3.get_paginator("list_bucket_inventory_configurations")

            configurations = []

            for page in paginator.paginate(Bucket=bucket_name):

                values = page.get(
                    "InventoryConfigurations",
                    [],
                )

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                configurations.extend(values)

            return {
                "enabled": bool(configurations),
                "configuration_count": len(configurations),
                "configurations": configurations,
            }

        except Exception as exc:

            return {
                "enabled": None,
                "configuration_count": 0,
                "configurations": [],
                "error": self._error_text(exc),
            }

    def _get_notification(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_notification_configuration(Bucket=bucket_name)

            configuration = {
                key: value
                for key, value in response.items()
                if key
                in {
                    "TopicConfigurations",
                    "QueueConfigurations",
                    "LambdaFunctionConfigurations",
                    "EventBridgeConfiguration",
                }
            }

            enabled = any(bool(value) for value in configuration.values())

            return {
                "enabled": enabled,
                "configuration": configuration,
            }

        except Exception as exc:

            return {
                "enabled": None,
                "configuration": {},
                "error": self._error_text(exc),
            }

    def _get_logging(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_logging(Bucket=bucket_name)

            logging_enabled = bool(response.get("LoggingEnabled"))

            return {
                "enabled": logging_enabled,
                "configuration": (response.get("LoggingEnabled") or {}),
            }

        except Exception as exc:

            return {
                "enabled": None,
                "configuration": {},
                "error": self._error_text(exc),
            }

    def _get_ownership(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_ownership_controls(Bucket=bucket_name)

            rules = response.get(
                "OwnershipControls",
                {},
            ).get(
                "Rules",
                [],
            )

            if not isinstance(
                rules,
                list,
            ):
                rules = []

            ownership = (
                rules[0].get("ObjectOwnership")
                if rules
                and isinstance(
                    rules[0],
                    dict,
                )
                else None
            )

            return {
                "object_ownership": ownership,
                "rules": rules,
            }

        except Exception as exc:

            code = self._exception_code(exc)

            if code in {
                "OwnershipControlsNotFoundError",
                "404",
            }:

                return {
                    "object_ownership": None,
                    "rules": [],
                }

            return {
                "object_ownership": None,
                "rules": [],
                "error": self._error_text(exc),
            }

    def _get_acl(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_acl(Bucket=bucket_name)

            grants = response.get(
                "Grants",
                [],
            )

            if not isinstance(
                grants,
                list,
            ):
                grants = []

            public_grants = []

            for grant in grants:

                if not isinstance(
                    grant,
                    dict,
                ):
                    continue

                grantee = grant.get(
                    "Grantee",
                    {},
                )

                if not isinstance(
                    grantee,
                    dict,
                ):
                    continue

                uri = grantee.get("URI")

                if uri and ("AllUsers" in str(uri) or "AuthenticatedUsers" in str(uri)):

                    public_grants.append(grant)

            return {
                "owner": response.get("Owner"),
                "grant_count": len(grants),
                "public_grant_count": len(public_grants),
                "has_public_grants": bool(public_grants),
            }

        except Exception as exc:

            return {
                "owner": None,
                "grant_count": 0,
                "public_grant_count": 0,
                "has_public_grants": None,
                "error": self._error_text(exc),
            }

    def _get_bucket_tags(
        self,
        bucket_name: str,
    ) -> Dict[str, Any]:

        try:
            response = self.s3.get_bucket_tagging(Bucket=bucket_name)

            tag_set = response.get(
                "TagSet",
                [],
            )

            if not isinstance(
                tag_set,
                list,
            ):
                return {}

            return {
                str(tag["Key"]): tag.get("Value")
                for tag in tag_set
                if (
                    isinstance(
                        tag,
                        dict,
                    )
                    and tag.get("Key")
                )
            }

        except Exception as exc:

            code = self._exception_code(exc)

            if code in {
                "NoSuchTagSet",
                "404",
            }:

                return {}

            return {}

    # ERROR HELPERS

    @staticmethod
    def _exception_code(
        exc: Exception,
    ) -> str:

        response = getattr(
            exc,
            "response",
            None,
        )

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

        code = S3Collector._exception_code(exc)

        message = str(exc)

        if code:
            return f"{code}: {message}"

        return message

    # HELPERS

    @staticmethod
    def _safe_period(
        value: Any,
    ) -> int:

        try:
            period = int(value)

        except (
            TypeError,
            ValueError,
        ):

            from aws_cost_optimizer.collection.metrics.cloudwatch import (
                DEFAULT_CLOUDWATCH_PERIOD,
            )

            period = DEFAULT_CLOUDWATCH_PERIOD

        return max(
            period,
            60,
        )

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
