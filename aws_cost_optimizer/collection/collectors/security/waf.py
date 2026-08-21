"""
AWS WAF Web ACL collector.

Purpose
-------
Collect the configuration and operational evidence required to explain
AWS WAF cost drivers.

Cost drivers represented by this collector:

- Web ACL count
- rule count
- managed rule groups
- WCU consumption
- request volume
- CAPTCHA / Challenge usage
- Bot Control / Fraud Control / premium managed features
- body inspection configuration
- associations
- logging configuration
- rule-level CloudWatch metrics

This collector intentionally does NOT build VPC/network topology.

WAF relationships are represented through:
    Web ACL -> protected resources
    Web ACL -> rules
    Web ACL -> managed rule groups

CloudFront WAF:
    AWS WAF CloudFront scope is global and must be queried through
    us-east-1.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.registry import register
from collection.metrics.cloudwatch import CloudWatchMetricCollector

from aws_cost_optimizer.analysis.metrics import (
    metric_has_observed_data,
    metric_numeric_value,
    metric_sum_value,
)


@register
class WAFCollector(BaseCollector):

    key = "waf"
    resource_type = "waf_web_acl"

    DEFAULT_NAMESPACE = "AWS/WAFV2"
    DEFAULT_PERIOD = 3600

    DEFAULT_ACL_METRICS = (
        "AllowedRequests",
        "BlockedRequests",
        "CountedRequests",
        "CaptchaRequests",
        "ChallengeRequests",
    )

    DEFAULT_RULE_METRICS = (
        "AllowedRequests",
        "BlockedRequests",
        "CountedRequests",
        "CaptchaRequests",
        "ChallengeRequests",
    )

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

        self.waf = get_client(
            "wafv2",
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
            Dict[str, Any],
        ] = {}

    # ------------------------------------------------------------------
    # Profile helpers
    # ------------------------------------------------------------------

    def _profile_section(
        self,
        name: str,
    ) -> Dict[str, Any]:

        value = self.profile.get(
            name,
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def _cloudwatch_profile(
        self,
    ) -> Dict[str, Any]:

        return self._profile_section(
            "observations"
        ).get(
            "cloudwatch",
            {},
        ) or {}

    def _analyzer_profile(
        self,
    ) -> Dict[str, Any]:

        return self._profile_section(
            "analyzer_config"
        )

    def _metric_specs(
        self,
        group_name: str,
        defaults: tuple[str, ...],
    ) -> List[Dict[str, Any]]:

        groups = self._profile_section(
            "metric_groups"
        )

        configured = groups.get(
            group_name
        )

        if not isinstance(
            configured,
            list,
        ):
            configured = list(defaults)

        specs = []

        for name in configured:

            text = str(
                name
            ).strip()

            if not text:
                continue

            specs.append(
                {
                    "name": text,
                    "statistic": "Sum",
                    "unit": "Count",
                }
            )

        return specs

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        scopes = self._profile_section(
            "scopes"
        ).get(
            "enabled",
            ["REGIONAL"],
        )

        if not isinstance(
            scopes,
            list,
        ):
            scopes = ["REGIONAL"]

        resources: List[
            Dict[str, Any]
        ] = []

        for scope in scopes:

            scope = str(
                scope
            ).upper().strip()

            if scope == "REGIONAL":

                resources.extend(
                    self._discover_scope(
                        scope="REGIONAL",
                        region=self.region,
                    )
                )

            elif scope == "CLOUDFRONT":

                # CloudFront WAF is global and the AWS WAF API must
                # be called through us-east-1.
                if self.region != "us-east-1":
                    continue

                resources.extend(
                    self._discover_scope(
                        scope="CLOUDFRONT",
                        region="us-east-1",
                    )
                )

        self._prefetch_metrics(
            resources
        )

        return resources

    def _discover_scope(
        self,
        *,
        scope: str,
        region: str,
    ) -> List[Dict[str, Any]]:

        client = (
            self.waf
            if region == self.region
            else get_client(
                "wafv2",
                region,
            )
        )

        resources: List[
            Dict[str, Any]
        ] = []

        next_marker: Optional[str] = None

        while True:

            kwargs = {
                "Scope": scope,
                "Limit": 100,
            }

            if next_marker:
                kwargs["NextMarker"] = (
                    next_marker
                )

            response = client.list_web_acls(
                **kwargs
            )

            for summary in response.get(
                "WebACLs",
                [],
            ):

                name = summary.get(
                    "Name"
                )

                acl_id = summary.get(
                    "Id"
                )

                arn = summary.get(
                    "ARN"
                )

                if not name or not acl_id:
                    continue

                try:
                    acl_response = client.get_web_acl(
                        Name=name,
                        Id=acl_id,
                        Scope=scope,
                    )
                except Exception as exc:

                    resources.append(
                        {
                            "id": arn or acl_id,
                            "scope": scope,
                            "region": region,
                            "raw": summary,
                            "collection_error":
                                str(exc),
                        }
                    )

                    continue

                web_acl = (
                    acl_response.get(
                        "WebACL"
                    )
                    or {}
                )

                resources.append(
                    {
                        "id":
                            arn
                            or web_acl.get(
                                "ARN"
                            )
                            or acl_id,

                        "name":
                            name,

                        "web_acl_id":
                            acl_id,

                        "scope":
                            scope,

                        "region":
                            region,

                        "arn":
                            (
                                web_acl.get(
                                    "ARN"
                                )
                                or arn
                            ),

                        "raw":
                            web_acl,
                    }
                )

            next_marker = response.get(
                "NextMarker"
            )

            if not next_marker:
                break

        return resources

    # ------------------------------------------------------------------
    # Metric collection
    # ------------------------------------------------------------------

    def _prefetch_metrics(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        cloudwatch_profile = (
            self._cloudwatch_profile()
        )

        if (
            not cloudwatch_profile
            or cloudwatch_profile.get(
                "enabled",
                True,
            )
            is False
        ):
            return

        try:

            start, end = (
                self.get_analysis_period()
            )

        except ValueError:

            return

        requested_period = int(
            cloudwatch_profile.get(
                "period",
                self.DEFAULT_PERIOD,
            )
        )

        namespace = str(
            cloudwatch_profile.get(
                "namespace",
                self.DEFAULT_NAMESPACE,
            )
        ).strip()

        acl_specs = self._metric_specs(
            "acl",
            self.DEFAULT_ACL_METRICS,
        )

        rule_specs = self._metric_specs(
            "rule",
            self.DEFAULT_RULE_METRICS,
        )

        requests: List[
            Dict[str, Any]
        ] = []

        for resource in resources:

            web_acl = (
                resource.get(
                    "raw"
                )
                or {}
            )

            visibility = (
                web_acl.get(
                    "VisibilityConfig"
                )
                or {}
            )

            web_acl_metric_name = (
                visibility.get(
                    "MetricName"
                )
                or resource.get(
                    "name"
                )
            )

            if not web_acl_metric_name:
                continue

            scope = resource.get(
                "scope"
            )

            dimensions = []

            if scope != "CLOUDFRONT":

                dimensions.append(
                    {
                        "Name": "Region",
                        "Value": resource.get(
                            "region"
                        )
                        or self.region,
                    }
                )

            dimensions.append(
                {
                    "Name": "WebACL",
                    "Value":
                        str(
                            web_acl_metric_name
                        ),
                }
            )

            requests.append(
                {
                    "resource_key":
                        resource["id"],

                    "metric_group":
                        "acl",

                    "namespace":
                        namespace,

                    "dimensions":
                        dimensions,

                    "metric_specs":
                        acl_specs,
                }
            )

            for rule in (
                web_acl.get(
                    "Rules",
                    [],
                )
                or []
            ):

                if not isinstance(
                    rule,
                    dict,
                ):
                    continue

                rule_visibility = (
                    rule.get(
                        "VisibilityConfig"
                    )
                    or {}
                )

                rule_metric_name = (
                    rule_visibility.get(
                        "MetricName"
                    )
                    or rule.get(
                        "Name"
                    )
                )

                if not rule_metric_name:
                    continue

                rule_dimensions = list(
                    dimensions
                )

                rule_dimensions.append(
                    {
                        "Name": "Rule",
                        "Value":
                            str(
                                rule_metric_name
                            ),
                    }
                )

                requests.append(
                    {
                        "resource_key":
                            resource["id"],

                        "metric_group":
                            "rule",

                        "rule_metric_name":
                            str(
                                rule_metric_name
                            ),

                        "namespace":
                            namespace,

                        "dimensions":
                            rule_dimensions,

                        "metric_specs":
                            rule_specs,
                    }
                )

        if not requests:
            return

        raw_results = (
            self.metric_collector.collect_batch(
                requests=[
                    {
                        "resource_key":
                            request["resource_key"]
                            if request.get(
                                "metric_group"
                            ) == "acl"
                            else (
                                f'{request["resource_key"]}'
                                f'::rule::'
                                f'{request.get("rule_metric_name")}'
                            ),

                        "namespace":
                            request["namespace"],

                        "dimensions":
                            request["dimensions"],

                        "metric_specs":
                            request["metric_specs"],
                    }
                    for request in requests
                ],
                start=start,
                end=end,
                requested_period=requested_period,
            )
        )

        self._metrics_batch_cache = {
            "results":
                raw_results
        }

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return str(
            resource.get(
                "id"
            )
        )

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        web_acl = resource.get(
            "raw"
        ) or {}

        return {
            "name":
                web_acl.get(
                    "Name"
                )
                or resource.get(
                    "name"
                ),

            "web_acl_id":
                resource.get(
                    "web_acl_id"
                ),

            "arn":
                (
                    web_acl.get(
                        "ARN"
                    )
                    or resource.get(
                        "arn"
                    )
                ),

            "scope":
                resource.get(
                    "scope"
                ),

            "region":
                resource.get(
                    "region"
                ),

            "description":
                web_acl.get(
                    "Description"
                ),

            "tags":
                self._tags(
                    resource
                ),
        }

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        web_acl = resource.get(
            "raw"
        ) or {}

        rules = [
            rule
            for rule in (
                web_acl.get(
                    "Rules",
                    [],
                )
                or []
            )
            if isinstance(
                rule,
                dict,
            )
        ]

        rule_details = []

        managed_rule_groups = []
        custom_rules = []
        rule_groups = []

        premium_features = set()

        captcha_rule_count = 0
        challenge_rule_count = 0

        body_inspection_limits = []

        for rule in rules:

            detail = (
                self._normalize_rule(
                    rule
                )
            )

            rule_details.append(
                detail
            )

            statement = (
                rule.get(
                    "Statement"
                )
                or {}
            )

            statement_info = (
                self._inspect_statement(
                    statement
                )
            )

            if statement_info[
                "managed_rule_group"
            ]:
                managed_rule_groups.append(
                    statement_info[
                        "managed_rule_group"
                    ]
                )

                name = str(
                    statement_info[
                        "managed_rule_group"
                    ].get(
                        "name"
                    )
                    or ""
                ).lower()

                if "botcontrol" in name:
                    premium_features.add(
                        "bot_control"
                    )

                if (
                    "atpruleset" in name
                    or "accounttakeover" in name
                ):
                    premium_features.add(
                        "account_takeover_prevention"
                    )

                if (
                    "acfpruleset" in name
                    or "accountcreation" in name
                ):
                    premium_features.add(
                        "account_creation_fraud_prevention"
                    )

            elif statement_info[
                "rule_group"
            ]:

                rule_groups.append(
                    statement_info[
                        "rule_group"
                    ]
                )

            else:

                custom_rules.append(
                    rule.get(
                        "Name"
                    )
                )

            if statement_info[
                "captcha"
            ]:

                captcha_rule_count += 1
                premium_features.add(
                    "captcha"
                )

            if statement_info[
                "challenge"
            ]:

                challenge_rule_count += 1
                premium_features.add(
                    "challenge"
                )

            body_limits = (
                self._find_body_limits(
                    statement
                )
            )

            body_inspection_limits.extend(
                body_limits
            )

        association_config = (
            web_acl.get(
                "AssociationConfig"
            )
            or {}
        )

        visibility = (
            web_acl.get(
                "VisibilityConfig"
            )
            or {}
        )

        capacity = self._number(
            web_acl.get(
                "Capacity"
            )
        )

        associations = (
            self._collect_associations(
                resource
            )
        )

        logging = (
            self._collect_logging(
                resource
            )
        )

        return {
            "web_acl_id":
                resource.get(
                    "web_acl_id"
                ),

            "name":
                resource.get(
                    "name"
                ),

            "arn":
                resource.get(
                    "arn"
                ),

            "scope":
                resource.get(
                    "scope"
                ),

            "default_action":
                self._normalize_default_action(
                    web_acl.get(
                        "DefaultAction"
                    )
                ),

            "rule_count":
                len(rules),

            "custom_rule_count":
                len(
                    [
                        rule
                        for rule in custom_rules
                        if rule
                    ]
                ),

            "managed_rule_group_count":
                len(
                    managed_rule_groups
                ),

            "customer_rule_group_count":
                len(
                    rule_groups
                ),

            "managed_rule_groups":
                managed_rule_groups,

            "rule_groups":
                rule_groups,

            "custom_rules":
                [
                    value
                    for value
                    in custom_rules
                    if value
                ],

            "rules":
                rule_details,

            "capacity_wcu":
                capacity,

            "capacity_over_1500":
                (
                    capacity is not None
                    and capacity > 1500
                ),

            "visibility":
                visibility,

            "sampled_requests_enabled":
                visibility.get(
                    "SampledRequestsEnabled"
                ),

            "cloudwatch_metrics_enabled":
                visibility.get(
                    "CloudWatchMetricsEnabled"
                ),

            "association_config":
                self._normalize_association_config(
                    association_config
                ),

            "associations":
                associations,

            "association_count":
                len(associations),

            "logging":
                logging,

            "logging_enabled":
                logging.get(
                    "enabled",
                    False,
                ),

            "premium_features":
                sorted(
                    premium_features
                ),

            "captcha_rule_count":
                captcha_rule_count,

            "challenge_rule_count":
                challenge_rule_count,

            "body_inspection":
                {
                    "configured_limits_kb":
                        body_inspection_limits,

                    "maximum_configured_kb":
                        (
                            max(
                                body_inspection_limits
                            )
                            if body_inspection_limits
                            else None
                        ),
                },
        }

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "protected_resources":
                self._collect_associations(
                    resource
                ),

            "rules":
                (
                    resource.get(
                        "raw",
                        {},
                    ).get(
                        "Rules",
                        [],
                    )
                    or []
                ),
        }

    # ------------------------------------------------------------------
    # No topology
    # ------------------------------------------------------------------

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "status":
                "not_applicable",

            "reason":
                "AWS WAF optimization does not require "
                "VPC network topology.",
        }

    # ------------------------------------------------------------------
    # Optimization evidence
    # ------------------------------------------------------------------

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = (
            collected_resource.get(
                "identity"
            )
            or {}
        )

        configuration = (
            collected_resource.get(
                "configuration"
            )
            or {}
        )

        observations = (
            collected_resource.get(
                "observations"
            )
            or {}
        )

        relationships = (
            collected_resource.get(
                "relationships"
            )
            or {}
        )

        return {
            "resource": {
                "id":
                    resource.get(
                        "id"
                    ),

                "name":
                    identity.get(
                        "name"
                    ),

                "scope":
                    identity.get(
                        "scope"
                    ),

                "region":
                    identity.get(
                        "region"
                    ),
            },

            "configuration": {
                key: value
                for key, value
                in configuration.items()
                if key not in {
                    "rules",
                    "managed_rule_groups",
                    "rule_groups",
                    "custom_rules",
                }
            },

            "rules": {
                "count":
                    configuration.get(
                        "rule_count"
                    ),

                "managed_rule_group_count":
                    configuration.get(
                        "managed_rule_group_count"
                    ),

                "customer_rule_group_count":
                    configuration.get(
                        "customer_rule_group_count"
                    ),

                "rules":
                    configuration.get(
                        "rules",
                        [],
                    ),

                "managed_rule_groups":
                    configuration.get(
                        "managed_rule_groups",
                        [],
                    ),

                "rule_groups":
                    configuration.get(
                        "rule_groups",
                        [],
                    ),
            },

            "relationships": {
                "protected_resource_count":
                    configuration.get(
                        "association_count"
                    ),

                "protected_resources":
                    relationships.get(
                        "protected_resources",
                        [],
                    ),
            },

            "features": {
                "premium_features":
                    configuration.get(
                        "premium_features",
                        [],
                    ),

                "captcha_rule_count":
                    configuration.get(
                        "captcha_rule_count"
                    ),

                "challenge_rule_count":
                    configuration.get(
                        "challenge_rule_count"
                    ),

                "logging_enabled":
                    configuration.get(
                        "logging_enabled"
                    ),

                "body_inspection":
                    configuration.get(
                        "body_inspection",
                        {},
                    ),
            },

            "traffic": self._build_traffic_summary(
                observations
            ),

            "data_quality": {
                "cloudwatch_available":
                    bool(
                        (
                            observations.get(
                                "cloudwatch"
                            )
                            or {}
                        ).get(
                            "metrics"
                        )
                    ),

                "configuration_available":
                    bool(
                        configuration
                    ),

                "relationship_available":
                    bool(
                        relationships
                    ),

                "topology_available":
                    False,
            },
        }

    # ------------------------------------------------------------------
    # Observations
    # ------------------------------------------------------------------

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        cloudwatch_profile = (
            self._cloudwatch_profile()
        )

        if (
            not cloudwatch_profile
            or cloudwatch_profile.get(
                "enabled",
                True,
            )
            is False
        ):
            return {
                "status":
                    "disabled",

                "cloudwatch":
                    {
                        "metrics":
                            {}
                    },
            }

        try:

            start, end = (
                self.get_analysis_period()
            )

        except ValueError as exc:

            return {
                "status":
                    "error",

                "error":
                    str(exc),

                "cloudwatch":
                    {
                        "metrics":
                            {}
                    },
            }

        cache = (
            self._metrics_batch_cache.get(
                "results",
                {}
            )
        )

        resource_id = resource.get(
            "id"
        )

        acl_results = cache.get(
            resource_id,
            [],
        )

        metrics: Dict[
            str,
            Dict[str, Any],
        ] = {}

        for result in acl_results:

            metric_name = (
                result.get(
                    "metric_name"
                )
            )

            if metric_name:
                stored = dict(
                    result
                )

                stored[
                    "metric_scope"
                ] = "web_acl"

                stored[
                    "original_metric_name"
                ] = metric_name

                stored[
                    "metric_name"
                ] = (
                    f"acl:{metric_name}"
                )

                metrics[
                    f"acl:{metric_name}"
                ] = stored

        rule_results = {}

        for key, values in cache.items():

            if not str(
                key
            ).startswith(
                f"{resource_id}::rule::"
            ):
                continue

            rule_metric_name = str(
                key
            ).split(
                "::rule::",
                1,
            )[-1]

            rule_results[
                rule_metric_name
            ] = []

            for result in values:

                metric_name = result.get(
                    "metric_name"
                )

                if not metric_name:
                    continue

                stored = dict(
                    result
                )

                stored[
                    "metric_scope"
                ] = "rule"

                stored[
                    "rule_metric_name"
                ] = rule_metric_name

                stored[
                    "original_metric_name"
                ] = metric_name

                stored[
                    "metric_name"
                ] = (
                    f"rule:{rule_metric_name}:"
                    f"{metric_name}"
                )

                metrics[
                    stored[
                        "metric_name"
                    ]
                ] = stored

                rule_results[
                    rule_metric_name
                ].append(
                    stored
                )

        return {
            "status":
                "ok",

            "cloudwatch": {
                "namespace":
                    cloudwatch_profile.get(
                        "namespace",
                        self.DEFAULT_NAMESPACE,
                    ),

                "requested_period":
                    int(
                        cloudwatch_profile.get(
                            "period",
                            self.DEFAULT_PERIOD,
                        )
                    ),

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "metrics":
                    metrics,

                "acl_metrics":
                    {
                        key: value
                        for key, value
                        in metrics.items()
                        if key.startswith(
                            "acl:"
                        )
                    },

                "rule_metrics":
                    rule_results,
            },

            "derived":
                self._build_traffic_summary(
                    {
                        "cloudwatch": {
                            "metrics":
                                metrics
                        }
                    }
                ),
        }

    # ------------------------------------------------------------------
    # Associations
    # ------------------------------------------------------------------

    def _collect_associations(
        self,
        resource: Dict[str, Any],
    ) -> List[str]:

        scope = resource.get(
            "scope"
        )

        if scope != "REGIONAL":
            return []

        web_acl_id = resource.get(
            "web_acl_id"
        )

        if not web_acl_id:
            return []

        try:

            response = (
                self.waf.list_resources_for_web_acl(
                    WebACLId=web_acl_id
                )
            )

        except Exception:

            return []

        values = (
            response.get(
                "ResourceArns",
                [],
            )
            or []
        )

        return [
            str(value)
            for value in values
            if value
        ]

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _collect_logging(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        arn = resource.get(
            "arn"
        )

        if not arn:
            return {
                "enabled": False,
            }

        try:

            response = (
                self.waf.get_logging_configuration(
                    ResourceArn=arn
                )
            )

        except Exception:

            return {
                "enabled": False,
            }

        config = (
            response.get(
                "LoggingConfiguration"
            )
        )

        if not isinstance(
            config,
            dict,
        ):
            return {
                "enabled": False,
            }

        return {
            "enabled": True,

            "destination_count":
                len(
                    config.get(
                        "LogDestinationConfigs",
                        [],
                    )
                    or []
                ),

            "destinations":
                list(
                    config.get(
                        "LogDestinationConfigs",
                        [],
                    )
                    or []
                ),

            "logging_filter":
                config.get(
                    "LoggingFilter"
                ),

            "redacted_fields":
                config.get(
                    "RedactedFields",
                    [],
                )
                or [],

            "log_scope":
                config.get(
                    "LogScope"
                ),

            "managed_by_firewall_manager":
                config.get(
                    "ManagedByFirewallManager"
                ),
        }

    # ------------------------------------------------------------------
    # Rule normalization
    # ------------------------------------------------------------------

    def _normalize_rule(
        self,
        rule: Dict[str, Any],
    ) -> Dict[str, Any]:

        statement = (
            rule.get(
                "Statement"
            )
            or {}
        )

        statement_info = (
            self._inspect_statement(
                statement
            )
        )

        return {
            "name":
                rule.get(
                    "Name"
                ),

            "priority":
                rule.get(
                    "Priority"
                ),

            "action":
                self._rule_action(
                    rule
                ),

            "override_action":
                rule.get(
                    "OverrideAction"
                ),

            "metric_name":
                (
                    (
                        rule.get(
                            "VisibilityConfig"
                        )
                        or {}
                    ).get(
                        "MetricName"
                    )
                ),

            "cloudwatch_metrics_enabled":
                (
                    (
                        rule.get(
                            "VisibilityConfig"
                        )
                        or {}
                    ).get(
                        "CloudWatchMetricsEnabled"
                    )
                ),

            "sampled_requests_enabled":
                (
                    (
                        rule.get(
                            "VisibilityConfig"
                        )
                        or {}
                    ).get(
                        "SampledRequestsEnabled"
                    )
                ),

            "statement_type":
                statement_info[
                    "statement_type"
                ],

            "managed_rule_group":
                statement_info[
                    "managed_rule_group"
                ],

            "rule_group":
                statement_info[
                    "rule_group"
                ],

            "contains_captcha":
                statement_info[
                    "captcha"
                ],

            "contains_challenge":
                statement_info[
                    "challenge"
                ],
        }

    # ------------------------------------------------------------------
    # Statement inspection
    # ------------------------------------------------------------------

    def _inspect_statement(
        self,
        statement: Dict[str, Any],
    ) -> Dict[str, Any]:

        result = {
            "statement_type":
                None,

            "managed_rule_group":
                None,

            "rule_group":
                None,

            "captcha":
                False,

            "challenge":
                False,
        }

        if not isinstance(
            statement,
            dict,
        ):
            return result

        for key, value in statement.items():

            if key == "ManagedRuleGroupStatement":

                result[
                    "statement_type"
                ] = "managed_rule_group"

                if isinstance(
                    value,
                    dict,
                ):

                    result[
                        "managed_rule_group"
                    ] = {
                        "name":
                            value.get(
                                "Name"
                            ),

                        "vendor_name":
                            value.get(
                                "VendorName"
                            ),

                        "version":
                            value.get(
                                "Version"
                            ),

                        "excluded_rules":
                            [
                                item.get(
                                    "Name"
                                )
                                for item
                                in (
                                    value.get(
                                        "ExcludedRules",
                                        [],
                                    )
                                    or []
                                )
                                if isinstance(
                                    item,
                                    dict,
                                )
                                and item.get(
                                    "Name"
                                )
                            ],

                        "scope_down":
                            bool(
                                value.get(
                                    "ScopeDownStatement"
                                )
                            ),
                    }

            elif key == "RuleGroupReferenceStatement":

                result[
                    "statement_type"
                ] = "rule_group"

                if isinstance(
                    value,
                    dict,
                ):

                    result[
                        "rule_group"
                    ] = {
                        "arn":
                            value.get(
                                "ARN"
                            ),

                        "excluded_rules":
                            [
                                item.get(
                                    "Name"
                                )
                                for item
                                in (
                                    value.get(
                                        "ExcludedRules",
                                        [],
                                    )
                                    or []
                                )
                                if isinstance(
                                    item,
                                    dict,
                                )
                                and item.get(
                                    "Name"
                                )
                            ],
                    }

            else:

                if result[
                    "statement_type"
                ] is None:

                    result[
                        "statement_type"
                    ] = key

        serialized = str(
            statement
        ).lower()

        result[
            "captcha"
        ] = "captcha" in serialized

        result[
            "challenge"
        ] = "challenge" in serialized

        return result

    def _find_body_limits(
        self,
        value: Any,
    ) -> List[float]:

        values: List[float] = []

        if isinstance(
            value,
            dict,
        ):

            for key, child in value.items():

                if (
                    key
                    in {
                        "Body",
                        "JsonBody",
                    }
                    and isinstance(
                        child,
                        dict,
                    )
                ):

                    # OversizeHandling is not itself a size.
                    # The actual configured body limit is generally
                    # represented at the association configuration
                    # level, so this traversal is intentionally only
                    # structural.

                    nested = child.get(
                        "Size"
                    )

                    number = self._number(
                        nested
                    )

                    if number is not None:
                        values.append(
                            number
                        )

                values.extend(
                    self._find_body_limits(
                        child
                    )
                )

        elif isinstance(
            value,
            list,
        ):

            for item in value:
                values.extend(
                    self._find_body_limits(
                        item
                    )
                )

        return values

    # ------------------------------------------------------------------
    # Default action / rule action
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_default_action(
        action: Any,
    ) -> Optional[str]:

        if not isinstance(
            action,
            dict,
        ):
            return None

        for key in (
            "Allow",
            "Block",
            "Count",
            "Captcha",
            "Challenge",
        ):

            if key in action:
                return key.lower()

        return None

    @staticmethod
    def _normalize_association_config(
        association_config: Any,
    ) -> Dict[str, Any]:

        # The analyzer reads this by its raw AWS API shape
        # (e.g. AssociationConfig["RequestBody"][...]), so this
        # only needs to guarantee a plain dict -- never a
        # non-dict/None value reaching the analyzer.
        if not isinstance(
            association_config,
            dict,
        ):
            return {}

        return association_config

    @staticmethod
    def _rule_action(
        rule: Dict[str, Any],
    ) -> Optional[str]:

        action = (
            rule.get(
                "Action"
            )
            or {}
        )

        if isinstance(
            action,
            dict,
        ):

            for key in (
                "Allow",
                "Block",
                "Count",
                "Captcha",
                "Challenge",
            ):

                if key in action:
                    return key.lower()

        override_action = (
            rule.get(
                "OverrideAction"
            )
            or {}
        )

        if isinstance(
            override_action,
            dict,
        ):

            if "None" in override_action:
                return "managed_rule_group_default"

            if "Count" in override_action:
                return "count"

        return None

    # ------------------------------------------------------------------
    # Traffic summary
    # ------------------------------------------------------------------

    def _build_traffic_summary(
        self,
        observations: Dict[str, Any],
    ) -> Dict[str, Any]:

        cloudwatch = (
            observations.get(
                "cloudwatch",
                {}
            )
            if isinstance(
                observations,
                dict,
            )
            else {}
        )

        metrics = (
            cloudwatch.get(
                "metrics",
                {}
            )
            if isinstance(
                cloudwatch,
                dict,
            )
            else {}
        )

        if not isinstance(
            metrics,
            dict,
        ):
            metrics = {}

        terminal_metrics = (
            "AllowedRequests",
            "BlockedRequests",
            "CaptchaRequests",
            "ChallengeRequests",
        )

        values: Dict[
            str,
            Optional[float],
        ] = {}

        observed = {}

        for metric_name in (
            terminal_metrics
        ):

            matching = [
                metric
                for key, metric
                in metrics.items()
                if (
                    str(key).startswith(
                        "acl:"
                    )
                    and metric.get(
                        "original_metric_name"
                    ) == metric_name
                )
            ]

            metric = (
                matching[0]
                if matching
                else {}
            )

            values[
                metric_name
            ] = metric_sum_value(
                metric
            )

            observed[
                metric_name
            ] = metric_has_observed_data(
                metric
            )

        observed_values = [
            value
            for value in values.values()
            if value is not None
        ]

        request_indicator = (
            sum(
                observed_values
            )
            if observed_values
            else None
        )

        requests_millions = (
            request_indicator / 1_000_000
            if request_indicator is not None
            else None
        )

        return {
            "allowed_requests":
                values[
                    "AllowedRequests"
                ],

            "blocked_requests":
                values[
                    "BlockedRequests"
                ],

            "captcha_requests":
                values[
                    "CaptchaRequests"
                ],

            "challenge_requests":
                values[
                    "ChallengeRequests"
                ],

            "terminal_request_indicator":
                request_indicator,

            "terminal_request_indicator_millions":
                requests_millions,

            "metric_observation":
                observed,

            "available":
                bool(observed_values),
        }

    # ------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------

    def _tags(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, str]:

        arn = (
            resource.get(
                "arn"
            )
        )

        if not arn:
            return {}

        try:

            response = (
                self.waf.list_tags_for_resource(
                    ResourceARN=arn
                )
            )

        except Exception:

            return {}

        tags = (
            response.get(
                "TagInfoForResource",
                {},
            ).get(
                "TagList",
                [],
            )
            or []
        )

        return {
            tag.get("Key"):
                tag.get("Value")
            for tag in tags
            if isinstance(
                tag,
                dict,
            )
            and tag.get(
                "Key"
            )
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _number(
        value: Any,
    ) -> Optional[float]:

        if value is None:
            return None

        if isinstance(
            value,
            bool,
        ):
            return None

        try:
            return float(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return None