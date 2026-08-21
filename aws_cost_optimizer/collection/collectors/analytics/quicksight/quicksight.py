"""
Amazon QuickSight collector.

Collects enough account and asset information to support
cross-account FinOps analysis.

Collected asset types:
- QuickSight account/subscription
- dashboards
- analyses
- datasets
- data sources
- users

Additional evidence:
- dashboard -> dataset relationships
- analysis -> dataset relationships when available
- dataset import mode
- dataset SPICE consumption
- data source status/type
- CloudTrail QuickSight activity
- account-level SPICE capacity
- CloudWatch QuickSight aggregate metrics

The collector is intentionally read-only.
It does not delete, modify, disable, or publish QuickSight resources.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.registry import register

from aws_cost_optimizer.collection.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)


@register
class QuickSightCollector(BaseCollector):

    key = "quicksight"
    resource_type = "quicksight_asset"

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

        self.quicksight = get_client(
            "quicksight",
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

        self.sts = get_client(
            "sts",
            self.region,
        )

        self.metric_collector = (
            CloudWatchMetricCollector(
                self.cloudwatch
            )
        )

        self.account_id = self._get_account_id()

        self._asset_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

        # Populated once, lazily, by _quicksight_cloudtrail_events()
        # -- the CloudTrail query is identical (same EventSource,
        # same scan time window) for every asset, so it is fetched
        # once per scan and filtered per-asset locally instead of
        # being re-queried per asset.
        self._cloudtrail_events_cache: (
            List[Dict[str, Any]] | None
        ) = None

        # Populated once by _prefetch_metrics_batch() (called from
        # discover(), before per-resource collection begins) --
        # every asset's CloudWatch metrics are fetched in as few
        # batched GetMetricData calls as possible instead of one
        # GetMetricStatistics call per metric per asset.
        self._metrics_batch_cache: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}
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
    def _get_account_id(self) -> Optional[str]:

        try:

            response = (
                self.sts.get_caller_identity()
            )

            account_id = response.get(
                "Account"
            )

            if account_id:
                return str(
                    account_id
                )

        except Exception:
            pass

        return None
    def _paginate(
        self,
        operation: str,
        result_key: str,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:

        results: List[
            Dict[str, Any]
        ] = []

        method = getattr(
            self.quicksight,
            operation,
        )

        next_token: Optional[
            str
        ] = None

        while True:

            params = dict(
                kwargs
            )

            if next_token:
                params[
                    "NextToken"
                ] = next_token

            response = method(
                **params
            )

            values = response.get(
                result_key,
                [],
            )

            if isinstance(
                values,
                list,
            ):
                results.extend(
                    item
                    for item in values
                    if isinstance(
                        item,
                        dict,
                    )
                )

            next_token = (
                response.get(
                    "NextToken"
                )
            )

            if not next_token:
                break

        return results
    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: List[
            Dict[str, Any]
        ] = []
        account_resource = {
            "id": (
                f"account:{self.account_id}"
                if self.account_id
                else "account"
            ),

            "asset_type":
                "account",

            "raw": {},

            "account_id":
                self.account_id,

            "region":
                self.region,
        }

        resources.append(
            account_resource
        )
        try:

            dashboards = self._paginate(
                "list_dashboards",
                "DashboardSummaryList",
                AwsAccountId=self.account_id,
                MaxResults=100,
            )

        except Exception:

            dashboards = []

        for summary in dashboards:

            dashboard_id = summary.get(
                "DashboardId"
            )

            if not dashboard_id:
                continue

            raw = dict(
                summary
            )

            try:

                detail_response = (
                    self.quicksight
                    .describe_dashboard(
                        AwsAccountId=self.account_id,
                        DashboardId=dashboard_id,
                    )
                )

                detail = detail_response.get(
                    "Dashboard"
                )

                if isinstance(
                    detail,
                    dict,
                ):
                    raw.update(
                        detail
                    )

            except Exception as exc:

                raw[
                    "_describe_error"
                ] = str(
                    exc
                )

            resource = {
                "id":
                    dashboard_id,

                "asset_type":
                    "dashboard",

                "raw":
                    raw,

                "account_id":
                    self.account_id,

                "region":
                    self.region,
            }

            resources.append(
                resource
            )

            self._asset_cache[
                f"dashboard:{dashboard_id}"
            ] = resource
        try:

            analyses = self._paginate(
                "list_analyses",
                "AnalysisSummaryList",
                AwsAccountId=self.account_id,
                MaxResults=100,
            )

        except Exception:

            analyses = []

        for summary in analyses:

            analysis_id = summary.get(
                "AnalysisId"
            )

            if not analysis_id:
                continue

            raw = dict(
                summary
            )

            try:

                response = (
                    self.quicksight
                    .describe_analysis(
                        AwsAccountId=self.account_id,
                        AnalysisId=analysis_id,
                    )
                )

                detail = response.get(
                    "Analysis"
                )

                if isinstance(
                    detail,
                    dict,
                ):
                    raw.update(
                        detail
                    )

            except Exception as exc:

                raw[
                    "_describe_error"
                ] = str(
                    exc
                )

            resource = {
                "id":
                    analysis_id,

                "asset_type":
                    "analysis",

                "raw":
                    raw,

                "account_id":
                    self.account_id,

                "region":
                    self.region,
            }

            resources.append(
                resource
            )

            self._asset_cache[
                f"analysis:{analysis_id}"
            ] = resource
        try:

            datasets = self._paginate(
                "list_data_sets",
                "DataSetSummaries",
                AwsAccountId=self.account_id,
                MaxResults=100,
            )

        except Exception:

            datasets = []

        for summary in datasets:

            dataset_id = summary.get(
                "DataSetId"
            )

            if not dataset_id:
                continue

            raw = dict(
                summary
            )

            try:

                response = (
                    self.quicksight
                    .describe_data_set(
                        AwsAccountId=self.account_id,
                        DataSetId=dataset_id,
                    )
                )

                detail = response.get(
                    "DataSet"
                )

                if isinstance(
                    detail,
                    dict,
                ):
                    raw.update(
                        detail
                    )

            except Exception as exc:

                raw[
                    "_describe_error"
                ] = str(
                    exc
                )

            resource = {
                "id":
                    dataset_id,

                "asset_type":
                    "dataset",

                "raw":
                    raw,

                "account_id":
                    self.account_id,

                "region":
                    self.region,
            }

            resources.append(
                resource
            )

            self._asset_cache[
                f"dataset:{dataset_id}"
            ] = resource
        try:

            data_sources = self._paginate(
                "list_data_sources",
                "DataSources",
                AwsAccountId=self.account_id,
                MaxResults=100,
            )

        except Exception:

            data_sources = []

        for summary in data_sources:

            data_source_id = summary.get(
                "DataSourceId"
            )

            if not data_source_id:
                continue

            raw = dict(
                summary
            )

            try:

                response = (
                    self.quicksight
                    .describe_data_source(
                        AwsAccountId=self.account_id,
                        DataSourceId=data_source_id,
                    )
                )

                detail = response.get(
                    "DataSource"
                )

                if isinstance(
                    detail,
                    dict,
                ):
                    raw.update(
                        detail
                    )

            except Exception as exc:

                raw[
                    "_describe_error"
                ] = str(
                    exc
                )

            resource = {
                "id":
                    data_source_id,

                "asset_type":
                    "data_source",

                "raw":
                    raw,

                "account_id":
                    self.account_id,

                "region":
                    self.region,
            }

            resources.append(
                resource
            )

            self._asset_cache[
                f"data_source:{data_source_id}"
            ] = resource

        self._prefetch_metrics_batch(
            resources
        )

        return resources

    def _prefetch_metrics_batch(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:
        """
        Fetch every asset's CloudWatch metrics in one batched pass
        (see CloudWatchMetricCollector.collect_batch()) instead of
        one GetMetricStatistics call per metric per asset. Results
        are cached by asset id and consumed by _collect_cloudwatch()
        later, per asset.
        """

        observations_profile = (
            self._profile_section(
                "observations"
            )
        )

        if not self._enabled(
            observations_profile,
            default=True,
        ):
            return

        cloudwatch_profile = (
            observations_profile.get(
                "cloudwatch",
                {},
            )
        )

        if not isinstance(
            cloudwatch_profile,
            dict,
        ) or not self._enabled(
            cloudwatch_profile,
            default=True,
        ):
            return

        namespace = (
            cloudwatch_profile.get(
                "namespace",
                "AWS/QuickSight/Aggregate Metrics",
            )
        )

        period = int(
            cloudwatch_profile.get(
                "period",
                3600,
            )
        )

        metrics = cloudwatch_profile.get(
            "metrics",
            [],
        )

        if not isinstance(
            metrics,
            list,
        ) or not metrics:
            return

        try:
            start, end = (
                self.get_analysis_period()
            )
        except ValueError:
            return

        requests: List[Dict[str, Any]] = []

        for resource in resources:

            resource_id = resource.get(
                "id"
            )

            if not resource_id:
                continue

            asset_type = (
                resource.get(
                    "asset_type"
                )
                or "asset"
            )

            dimensions: List[
                Dict[str, str]
            ] = []

            if asset_type == "dashboard":

                dimensions.append(
                    {
                        "Name":
                            "DashboardId",
                        "Value":
                            str(resource_id),
                    }
                )

            elif asset_type == "dataset":

                dimensions.append(
                    {
                        "Name":
                            "DatasetId",
                        "Value":
                            str(resource_id),
                    }
                )

            requests.append(
                {
                    "resource_key": resource_id,
                    "namespace": namespace,
                    "dimensions": dimensions,
                    "metric_specs": metrics,
                }
            )

        if not requests:
            return

        self._metrics_batch_cache = (
            self.metric_collector.collect_batch(
                requests,
                start=start,
                end=end,
                requested_period=period,
            )
        )

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        asset_type = (
            resource.get(
                "asset_type"
            )
            or "asset"
        )

        resource_id = (
            resource.get(
                "id"
            )
            or "unknown"
        )

        return (
            f"{asset_type}:{resource_id}"
        )
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

        asset_type = (
            resource.get(
                "asset_type"
            )
            or "asset"
        )

        result = {
            "asset_type":
                asset_type,

            "resource_id":
                resource.get(
                    "id"
                ),

            "account_id":
                resource.get(
                    "account_id"
                )
                or self.account_id,

            "region":
                resource.get(
                    "region"
                )
                or self.region,
        }

        if asset_type == "dashboard":

            result.update(
                {
                    "dashboard_id":
                        raw.get(
                            "DashboardId"
                        ),

                    "dashboard_arn":
                        raw.get(
                            "Arn"
                        ),

                    "name":
                        raw.get(
                            "Name"
                        ),
                }
            )

        elif asset_type == "analysis":

            result.update(
                {
                    "analysis_id":
                        raw.get(
                            "AnalysisId"
                        ),

                    "analysis_arn":
                        raw.get(
                            "Arn"
                        ),

                    "name":
                        raw.get(
                            "Name"
                        ),
                }
            )

        elif asset_type == "dataset":

            result.update(
                {
                    "dataset_id":
                        raw.get(
                            "DataSetId"
                        ),

                    "dataset_arn":
                        raw.get(
                            "Arn"
                        ),

                    "name":
                        raw.get(
                            "Name"
                        ),
                }
            )

        elif asset_type == "data_source":

            result.update(
                {
                    "data_source_id":
                        raw.get(
                            "DataSourceId"
                        ),

                    "data_source_arn":
                        raw.get(
                            "Arn"
                        ),

                    "name":
                        raw.get(
                            "Name"
                        ),

                    "type":
                        raw.get(
                            "Type"
                        ),
                }
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

        asset_type = (
            resource.get(
                "asset_type"
            )
            or "asset"
        )

        if asset_type == "account":

            return self._collect_account_configuration()

        if asset_type == "dashboard":

            version = raw.get(
                "Version"
            )

            if not isinstance(
                version,
                dict,
            ):
                version = {}

            return {
                "dashboard_id":
                    raw.get(
                        "DashboardId"
                    ),

                "dashboard_arn":
                    raw.get(
                        "Arn"
                    ),

                "name":
                    raw.get(
                        "Name"
                    ),

                "created_time":
                    self._serialize(
                        raw.get(
                            "CreatedTime"
                        )
                    ),

                "last_updated_time":
                    self._serialize(
                        raw.get(
                            "LastUpdatedTime"
                        )
                    ),

                "last_published_time":
                    self._serialize(
                        raw.get(
                            "LastPublishedTime"
                        )
                    ),

                "published_version_number":
                    raw.get(
                        "PublishedVersionNumber"
                    ),

                "version_number":
                    version.get(
                        "VersionNumber"
                    ),

                "version_status":
                    version.get(
                        "Status"
                    ),

                "version_created_time":
                    self._serialize(
                        version.get(
                            "CreatedTime"
                        )
                    ),

                "version_errors":
                    version.get(
                        "Errors",
                        [],
                    )
                    or [],

                "dataset_arns":
                    version.get(
                        "DataSetArns",
                        [],
                    )
                    or [],

                "sheet_count":
                    len(
                        version.get(
                            "Sheets",
                            [],
                        )
                        or []
                    ),
            }

        if asset_type == "analysis":

            return {
                "analysis_id":
                    raw.get(
                        "AnalysisId"
                    ),

                "analysis_arn":
                    raw.get(
                        "Arn"
                    ),

                "name":
                    raw.get(
                        "Name"
                    ),

                "status":
                    raw.get(
                        "Status"
                    ),

                "created_time":
                    self._serialize(
                        raw.get(
                            "CreatedTime"
                        )
                    ),

                "last_updated_time":
                    self._serialize(
                        raw.get(
                            "LastUpdatedTime"
                        )
                    ),

                "last_published_time":
                    self._serialize(
                        raw.get(
                            "LastPublishedTime"
                        )
                    ),
            }

        if asset_type == "dataset":

            return {
                "dataset_id":
                    raw.get(
                        "DataSetId"
                    ),

                "dataset_arn":
                    raw.get(
                        "Arn"
                    ),

                "name":
                    raw.get(
                        "Name"
                    ),

                "created_time":
                    self._serialize(
                        raw.get(
                            "CreatedTime"
                        )
                    ),

                "last_updated_time":
                    self._serialize(
                        raw.get(
                            "LastUpdatedTime"
                        )
                    ),

                "import_mode":
                    raw.get(
                        "ImportMode"
                    ),

                "consumed_spice_capacity_bytes":
                    raw.get(
                        "ConsumedSpiceCapacityInBytes"
                    ),

                "physical_table_count":
                    self._count_dict(
                        raw.get(
                            "PhysicalTableMap"
                        )
                    ),

                "logical_table_count":
                    self._count_dict(
                        raw.get(
                            "LogicalTableMap"
                        )
                    ),

                "output_column_count":
                    len(
                        raw.get(
                            "OutputColumns",
                            [],
                        )
                        or []
                    ),

                "disable_direct_query_source":
                    (
                        raw.get(
                            "DataSetUsageConfiguration",
                            {},
                        )
                        or {}
                    ).get(
                        "DisableUseAsDirectQuerySource"
                    ),

                "disable_imported_source":
                    (
                        raw.get(
                            "DataSetUsageConfiguration",
                            {},
                        )
                        or {}
                    ).get(
                        "DisableUseAsImportedSource"
                    ),
            }

        if asset_type == "data_source":

            parameters = raw.get(
                "DataSourceParameters",
                {},
            )

            if not isinstance(
                parameters,
                dict,
            ):
                parameters = {}

            return {
                "data_source_id":
                    raw.get(
                        "DataSourceId"
                    ),

                "data_source_arn":
                    raw.get(
                        "Arn"
                    ),

                "name":
                    raw.get(
                        "Name"
                    ),

                "type":
                    raw.get(
                        "Type"
                    ),

                "status":
                    raw.get(
                        "Status"
                    ),

                "created_time":
                    self._serialize(
                        raw.get(
                            "CreatedTime"
                        )
                    ),

                "last_updated_time":
                    self._serialize(
                        raw.get(
                            "LastUpdatedTime"
                        )
                    ),

                "parameter_types":
                    sorted(
                        parameters.keys()
                    ),

                "ssl_properties":
                    raw.get(
                        "SslProperties"
                    ),

                "vpc_connection_properties":
                    raw.get(
                        "VpcConnectionProperties"
                    ),
            }

        return {}
    def _collect_account_configuration(
        self,
    ) -> Dict[str, Any]:

        result: Dict[
            str,
            Any,
        ] = {
            "account_id":
                self.account_id,

            "region":
                self.region,
        }

        try:

            response = (
                self.quicksight
                .describe_account_settings(
                    AwsAccountId=self.account_id
                )
            )

            settings = response.get(
                "AccountSettings",
                {},
            )

            if isinstance(
                settings,
                dict,
            ):

                result.update(
                    {
                        "account_name":
                            settings.get(
                                "AccountName"
                            ),

                        "edition":
                            settings.get(
                                "Edition"
                            ),

                        "default_namespace":
                            settings.get(
                                "DefaultNamespace"
                            ),
                    }
                )

        except Exception as exc:

            result[
                "account_settings_error"
            ] = str(
                exc
            )

        # SPICE account-level CloudWatch
        # metrics are collected separately.
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

        asset_type = (
            resource.get(
                "asset_type"
            )
            or "asset"
        )

        if asset_type == "dashboard":

            version = raw.get(
                "Version",
                {},
            )

            if not isinstance(
                version,
                dict,
            ):
                version = {}

            dataset_arns = (
                version.get(
                    "DataSetArns",
                    [],
                )
                or []
            )

            return {
                "dataset_arns":
                    dataset_arns,

                "dataset_ids":
                    [
                        self._extract_resource_id(
                            arn
                        )
                        for arn in dataset_arns
                        if arn
                    ],

                "source_entity_arn":
                    version.get(
                        "SourceEntityArn"
                    ),

                "theme_arn":
                    version.get(
                        "ThemeArn"
                    ),

                "link_entities":
                    raw.get(
                        "LinkEntities",
                        [],
                    )
                    or [],
            }

        if asset_type == "analysis":

            return {
                "dataset_arns":
                    self._extract_dataset_arns(
                        raw
                    ),

                "dashboard_links":
                    self._extract_dashboard_links(
                        raw
                    ),
            }

        if asset_type == "dataset":

            return {
                "data_source_ids":
                    self._extract_dataset_data_sources(
                        raw
                    ),
            }

        return {}
    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        asset_type = (
            resource.get(
                "asset_type"
            )
            or "asset"
        )

        if asset_type == "account":

            return {
                "type":
                    "quicksight_account",

                "region":
                    self.region,

                "account_id":
                    self.account_id,
            }

        return {
            "type":
                "quicksight_asset",

            "asset_type":
                asset_type,

            "region":
                self.region,

            "account_id":
                self.account_id,
        }
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

        asset_type = (
            resource.get(
                "asset_type"
            )
            or "asset"
        )

        result: Dict[
            str,
            Any,
        ] = {}
        cloudwatch_profile = (
            observations_profile.get(
                "cloudwatch",
                {},
            )
        )

        if (
            isinstance(
                cloudwatch_profile,
                dict,
            )
            and self._enabled(
                cloudwatch_profile,
                default=True,
            )
        ):

            result[
                "cloudwatch"
            ] = self._collect_cloudwatch(
                resource,
                cloudwatch_profile,
            )
        else:

            result[
                "cloudwatch"
            ] = {
                "status":
                    "disabled",

                "metrics":
                    {},
            }
        cloudtrail_profile = (
            observations_profile.get(
                "cloudtrail",
                self._profile_section(
                    "cloudtrail"
                ),
            )
        )

        if not isinstance(
            cloudtrail_profile,
            dict,
        ):
            cloudtrail_profile = {}

        if self._enabled(
            cloudtrail_profile,
            default=True,
        ):

            result[
                "cloudtrail"
            ] = (
                self._collect_cloudtrail_activity(
                    resource
                )
            )

        else:

            result[
                "cloudtrail"
            ] = {
                "status":
                    "disabled",

                "events":
                    [],
            }
        if asset_type == "account":

            result[
                "users"
            ] = self._collect_users()

        return result
    def _collect_cloudwatch(
        self,
        resource: Dict[str, Any],
        profile: Dict[str, Any],
    ) -> Dict[str, Any]:

        namespace = (
            profile.get(
                "namespace",
                "AWS/QuickSight/Aggregate Metrics",
            )
        )

        period = int(
            profile.get(
                "period",
                3600,
            )
        )

        metrics = profile.get(
            "metrics",
            [],
        )

        if not isinstance(
            metrics,
            list,
        ):
            metrics = []

        start, end = (
            self.get_analysis_period()
        )

        asset_type = (
            resource.get(
                "asset_type"
            )
            or "asset"
        )

        dimensions: List[
            Dict[str, str]
        ] = []

        if asset_type == "dashboard":

            dashboard_id = (
                resource.get(
                    "id"
                )
            )

            if dashboard_id:

                dimensions.append(
                    {
                        "Name":
                            "DashboardId",

                        "Value":
                            str(
                                dashboard_id
                            ),
                    }
                )

        elif asset_type == "dataset":

            dataset_id = (
                resource.get(
                    "id"
                )
            )

            if dataset_id:

                dimensions.append(
                    {
                        "Name":
                            "DatasetId",

                        "Value":
                            str(
                                dataset_id
                            ),
                    }
                )

        # Account-level SPICE metrics do not need
        # an asset dimension.
        if asset_type == "account":
            dimensions = []

        if not metrics:

            return {
                "status":
                    "no_metrics",

                "namespace":
                    namespace,

                "metrics":
                    {},
            }

        # Fetched once for every asset by _prefetch_metrics_batch()
        # (called from discover(), before per-resource collection
        # begins) -- see that method for the batched GetMetricData
        # call this replaces.
        results = (
            self._metrics_batch_cache.get(
                resource.get("id"),
                [],
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

        for item in results:

            if not isinstance(
                item,
                dict,
            ):
                continue

            metric_name = item.get(
                "metric_name"
            )

            if metric_name:

                metric_results[
                    metric_name
                ] = item

            if item.get(
                "has_data"
            ):
                available_count += 1

            if item.get(
                "status"
            ) == "error":

                errors.append(
                    {
                        "metric_name":
                            metric_name,

                        "error":
                            item.get(
                                "error"
                            ),
                    }
                )

        return {
            "status":
                (
                    "error"
                    if (
                        results
                        and all(
                            isinstance(
                                item,
                                dict,
                            )
                            and item.get(
                                "status"
                            ) == "error"
                            for item in results
                        )
                    )
                    else "ok"
                ),

            "namespace":
                namespace,

            "requested_period":
                period,

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

            **(
                {
                    "errors":
                        errors,
                }
                if errors
                else {}
            ),
        }
    def _fetch_quicksight_cloudtrail_events(
        self,
        start,
        end,
    ) -> Dict[str, Any]:
        """
        Fetch every quicksight.amazonaws.com CloudTrail event for
        the scan's time window ONCE. Every asset's LookupAttributes
        query (EventSource=quicksight.amazonaws.com, same StartTime/
        EndTime) is identical regardless of which asset is being
        analyzed, so this must only ever run a single time per scan.
        """

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
                                "EventSource",

                            "AttributeValue":
                                "quicksight.amazonaws.com",
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

                "events":
                    [],

                "error":
                    str(
                        exc
                    ),
            }

        return {
            "status":
                "ok",

            "events":
                events,
        }

    def _get_quicksight_cloudtrail_events(
        self,
        start,
        end,
    ) -> Dict[str, Any]:

        if self._cloudtrail_events_cache is None:

            fetched = (
                self._fetch_quicksight_cloudtrail_events(
                    start,
                    end,
                )
            )

            if fetched["status"] != "ok":
                return fetched

            self._cloudtrail_events_cache = (
                fetched["events"]
            )

        return {
            "status":
                "ok",

            "events":
                self._cloudtrail_events_cache,
        }

    def _collect_cloudtrail_activity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        start, end = (
            self.get_analysis_period()
        )

        asset_type = (
            resource.get(
                "asset_type"
            )
            or "asset"
        )

        resource_id = (
            resource.get(
                "id"
            )
        )

        fetched = (
            self._get_quicksight_cloudtrail_events(
                start,
                end,
            )
        )

        if fetched["status"] != "ok":

            return {
                "status":
                    "error",

                "events":
                    [],

                "event_count":
                    0,

                "source":
                    "cloudtrail",

                "error":
                    fetched.get(
                        "error"
                    ),
            }

        events = fetched["events"]

        relevant_events: List[
            Dict[str, Any]
        ] = []

        for event in events:

            if not isinstance(
                event,
                dict,
            ):
                continue

            parsed = self._parse_cloudtrail_event(
                event
            )

            if parsed is None:
                continue

            if self._event_matches_resource(
                parsed,
                asset_type,
                resource_id,
            ):

                relevant_events.append(
                    parsed
                )

        relevant_events.sort(
            key=lambda item:
                item.get(
                    "event_time",
                    "",
                )
        )

        return {
            "status":
                "ok",

            "source":
                "cloudtrail",

            "event_count":
                len(
                    relevant_events
                ),

            "events":
                relevant_events,

            "analysis_start":
                start.isoformat(),

            "analysis_end":
                end.isoformat(),

            "coverage_note":
                (
                    "CloudTrail activity is evidence of observed "
                    "API/non-API activity. Absence of an event does "
                    "not by itself prove that a QuickSight asset is "
                    "unused."
                ),
        }
    def _parse_cloudtrail_event(
        self,
        event: Dict[str, Any],
    ) -> Optional[
        Dict[str, Any]
    ]:

        event_name = event.get(
            "EventName"
        )

        event_time = event.get(
            "EventTime"
        )

        cloudtrail_event = event.get(
            "CloudTrailEvent"
        )

        parsed: Dict[
            str,
            Any
        ] = {}

        if cloudtrail_event:

            try:

                loaded = json.loads(
                    cloudtrail_event
                )

                if isinstance(
                    loaded,
                    dict,
                ):
                    parsed = loaded

            except (
                TypeError,
                ValueError,
            ):
                parsed = {}

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

        user_identity = (
            parsed.get(
                "userIdentity",
                {},
            )
        )

        if not isinstance(
            user_identity,
            dict,
        ):
            user_identity = {}

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
            request_parameters = {}

        return {
            "event_id":
                event.get(
                    "EventId"
                ),

            "event_name":
                event_name,

            "event_time":
                event_time_value,

            "username":
                event.get(
                    "Username"
                ),

            "read_only":
                parsed.get(
                    "readOnly"
                ),

            "event_source":
                parsed.get(
                    "eventSource"
                ),

            "aws_region":
                parsed.get(
                    "awsRegion"
                ),

            "user_type":
                user_identity.get(
                    "type"
                ),

            "principal_id":
                user_identity.get(
                    "principalId"
                ),

            "request_parameters":
                request_parameters,
        }

    def _event_matches_resource(
        self,
        event: Dict[str, Any],
        asset_type: str,
        resource_id: Optional[str],
    ) -> bool:

        if asset_type == "account":
            return True

        if not resource_id:
            return False

        text = json.dumps(
            event.get(
                "request_parameters",
                {},
            ),
            default=str,
        )

        return (
            str(
                resource_id
            )
            in text
        )
    def _collect_users(
        self,
    ) -> Dict[str, Any]:

        namespace = (
            self._profile_section(
                "users"
            ).get(
                "namespace",
                "default",
            )
        )

        try:

            users = self._paginate(
                "list_users",
                "UserList",
                AwsAccountId=self.account_id,
                Namespace=namespace,
                MaxResults=100,
            )

        except Exception as exc:

            return {
                "status":
                    "error",

                "namespace":
                    namespace,

                "users":
                    [],

                "error":
                    str(
                        exc
                    ),
            }

        normalized: List[
            Dict[str, Any]
        ] = []

        for user in users:

            normalized.append(
                {
                    "user_name":
                        user.get(
                            "UserName"
                        ),

                    "email":
                        user.get(
                            "Email"
                        ),

                    "role":
                        user.get(
                            "Role"
                        ),

                    "active":
                        user.get(
                            "Active"
                        ),

                    "identity_type":
                        user.get(
                            "IdentityType"
                        ),

                    "principal_id":
                        user.get(
                            "PrincipalId"
                        ),
                }
            )

        return {
            "status":
                "ok",

            "namespace":
                namespace,

            "user_count":
                len(
                    normalized
                ),

            "users":
                normalized,
        }
    @staticmethod
    def _extract_dataset_arns(
        raw: Dict[str, Any],
    ) -> List[str]:

        arns: Set[str] = set()

        def walk(
            value: Any,
        ) -> None:

            if isinstance(
                value,
                dict,
            ):

                for key, item in value.items():

                    if key in {
                        "DataSetArn",
                        "DatasetArn",
                        "DataSetARN",
                        "DatasetARN",
                    }:

                        if isinstance(
                            item,
                            str,
                        ):
                            arns.add(
                                item
                            )

                    elif key in {
                        "DataSetArns",
                        "DatasetArns",
                        "DataSetARNs",
                        "DatasetARNs",
                    }:

                        if isinstance(
                            item,
                            list,
                        ):

                            for arn in item:

                                if isinstance(
                                    arn,
                                    str,
                                ):
                                    arns.add(
                                        arn
                                    )

                    walk(
                        item
                    )

            elif isinstance(
                value,
                list,
            ):

                for item in value:
                    walk(
                        item
                    )

        walk(
            raw
        )

        return sorted(
            arns
        )

    @staticmethod
    def _extract_dashboard_links(
        raw: Dict[str, Any],
    ) -> List[str]:

        links: Set[str] = set()

        def walk(
            value: Any,
        ) -> None:

            if isinstance(
                value,
                dict,
            ):

                for key, item in value.items():

                    if (
                        "Dashboard"
                        in key
                        and isinstance(
                            item,
                            str,
                        )
                        and item.startswith(
                            "arn:"
                        )
                    ):
                        links.add(
                            item
                        )

                    walk(
                        item
                    )

            elif isinstance(
                value,
                list,
            ):

                for item in value:
                    walk(
                        item
                    )

        walk(
            raw
        )

        return sorted(
            links
        )

    @staticmethod
    def _extract_dataset_data_sources(
        raw: Dict[str, Any],
    ) -> List[str]:

        values: Set[str] = set()

        def walk(
            value: Any,
        ) -> None:

            if isinstance(
                value,
                dict,
            ):

                for key, item in value.items():

                    if (
                        "DataSource"
                        in key
                        and isinstance(
                            item,
                            str,
                        )
                    ):

                        values.add(
                            item
                        )

                    walk(
                        item
                    )

            elif isinstance(
                value,
                list,
            ):

                for item in value:
                    walk(
                        item
                    )

        walk(
            raw
        )

        return sorted(
            values
        )
    @staticmethod
    def _extract_resource_id(
        arn: str,
    ) -> str:

        if not isinstance(
            arn,
            str,
        ):
            return ""

        return arn.rsplit(
            "/",
            1,
        )[-1]

    @staticmethod
    def _serialize(
        value: Any,
    ) -> Any:

        if hasattr(
            value,
            "isoformat",
        ):
            return value.isoformat()

        return value

    @staticmethod
    def _count_dict(
        value: Any,
    ) -> int:

        if not isinstance(
            value,
            dict,
        ):
            return 0

        return len(
            value
        )