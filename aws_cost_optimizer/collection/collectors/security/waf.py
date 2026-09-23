"""
AWS WAF Web ACL collector.

"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.registry import register
from collection.metrics.cloudwatch import CloudWatchMetricCollector


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


@register
class WAFCollector(BaseCollector):

    key = "waf"
    resource_type = "waf_web_acl"

    DEFAULT_ASSOCIATION_RESOURCE_TYPES = (
        "APPLICATION_LOAD_BALANCER",
        "API_GATEWAY",
    )

    DEFAULT_CLOUDFRONT_REGION = "us-east-1"

    BODY_LIMIT_KB = {
        "KB_16": 16,
        "KB_32": 32,
        "KB_48": 48,
        "KB_64": 64,
    }

    DEFAULT_BODY_LIMIT_KB = 16

    AWS_BOT_CONTROL_RULE_GROUPS = {
        "AWSManagedRulesBotControlRuleSet",
    }

    AWS_ATP_RULE_GROUPS = {
        "AWSManagedRulesATPRuleSet",
    }

    AWS_ACFP_RULE_GROUPS = {
        "AWSManagedRulesACFPRuleSet",
    }

    WEB_ACL_METRICS = (
        "AllowedRequests",
        "BlockedRequests",
        "CountedRequests",
        "CaptchaRequests",
        "RequestsWithValidCaptchaToken",
        "CaptchasAttempted",
        "CaptchasSolved",
        "ChallengeRequests",
        "RequestsWithValidChallengeToken",
        "ChallengesAttempted",
        "ChallengesSolved",
        "MonetizeRequests",
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

        if not self.region:
            raise ValueError("WAF collector requires a region.")

        self.waf = get_client(
            "wafv2",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = CloudWatchMetricCollector(self.cloudwatch)

        self._cloudfront_waf = None
        self._cloudfront = None

        self._metrics_batch_cache: Dict[str, Any] = {
            "status": "not_queried",
            "results": {},
        }

        self._cloudwatch_request_diagnostics: Dict[
            str,
            Dict[str, Any],
        ] = {}

        self._association_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

    # PROFILE

    def _profile_section(
        self,
        name: str,
    ) -> Dict[str, Any]:
        value = self.profile.get(name, {})

        return value if isinstance(value, dict) else {}

    def _cloudwatch_profile(
        self,
    ) -> Dict[str, Any]:

        value = self._profile_section("observations").get(
            "cloudwatch",
            {},
        )

        return value if isinstance(value, dict) else {}

    def _metric_specs(
        self,
    ) -> List[Dict[str, Any]]:

        configured = self._cloudwatch_profile().get("metrics")

        if not isinstance(configured, list) or not configured:
            raise ValueError(
                "WAF profile must define " "observations.cloudwatch.metrics."
            )

        result: List[Dict[str, Any]] = []

        for item in configured:

            if isinstance(item, str):

                name = item.strip()

                if name:
                    result.append(
                        {
                            "name": name,
                            "statistic": "Sum",
                            "unit": "Count",
                        }
                    )

                continue

            if not isinstance(item, dict):
                continue

            name = str(item.get("name", "")).strip()

            if not name:
                continue

            statistic = str(
                item.get(
                    "statistic",
                    "Sum",
                )
            ).strip()

            unit = str(
                item.get(
                    "unit",
                    "Count",
                )
            ).strip()

            spec = {
                "name": name,
                "statistic": statistic,
                "unit": unit,
            }

            key = item.get("key")

            if key:
                spec["key"] = str(key)

            result.append(spec)

        if not result:
            raise ValueError(
                "WAF profile contains no valid " "CloudWatch metric specs."
            )

        return result

    def _association_resource_types(
        self,
    ) -> List[str]:

        configured = self._profile_section("relationships").get("resource_types")

        if not isinstance(
            configured,
            list,
        ):
            return list(self.DEFAULT_ASSOCIATION_RESOURCE_TYPES)

        values: List[str] = []

        for value in configured:

            text = str(value).strip().upper()

            if text:
                values.append(text)

        return values or list(self.DEFAULT_ASSOCIATION_RESOURCE_TYPES)

    # CLIENTS

    def _get_cloudfront_waf_client(self):
        if self._cloudfront_waf is None:

            self._cloudfront_waf = get_client(
                "wafv2",
                self.DEFAULT_CLOUDFRONT_REGION,
            )

        return self._cloudfront_waf

    def _get_cloudfront_client(self):

        if self._cloudfront is None:

            self._cloudfront = get_client(
                "cloudfront",
                self.DEFAULT_CLOUDFRONT_REGION,
            )

        return self._cloudfront

    # DISCOVERY

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        self._association_cache = {}

        configured_scopes = self._profile_section("scopes").get(
            "enabled",
            ["REGIONAL"],
        )

        if not isinstance(
            configured_scopes,
            list,
        ):
            configured_scopes = ["REGIONAL"]

        resources: List[Dict[str, Any]] = []

        for raw_scope in configured_scopes:

            scope = str(raw_scope).strip().upper()

            if scope == "REGIONAL":

                resources.extend(
                    self._discover_scope(
                        scope="REGIONAL",
                        region=self.region,
                    )
                )

            elif scope == "CLOUDFRONT":

                resources.extend(
                    self._discover_scope(
                        scope="CLOUDFRONT",
                        region=(self.DEFAULT_CLOUDFRONT_REGION),
                    )
                )

        self._prefetch_metrics(resources)

        return resources

    def _discover_scope(
        self,
        *,
        scope: str,
        region: str,
    ) -> List[Dict[str, Any]]:

        client = (
            self._get_cloudfront_waf_client() if scope == "CLOUDFRONT" else self.waf
        )

        resources: List[Dict[str, Any]] = []

        next_marker: Optional[str] = None

        while True:

            kwargs: Dict[str, Any] = {
                "Scope": scope,
                "Limit": 100,
            }

            if next_marker:
                kwargs["NextMarker"] = next_marker

            try:

                response = client.list_web_acls(**kwargs)

            except Exception as exc:

                resources.append(
                    {
                        "id": ("waf-discovery-error:" f"{scope}:{region}"),
                        "scope": scope,
                        "region": region,
                        "collection_error": str(exc),
                    }
                )

                break

            for summary in (
                response.get(
                    "WebACLs",
                    [],
                )
                or []
            ):

                if not isinstance(
                    summary,
                    dict,
                ):
                    continue

                name = summary.get("Name")

                acl_id = summary.get("Id")

                arn = summary.get("ARN")

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
                            "id": (arn or acl_id),
                            "name": name,
                            "web_acl_id": acl_id,
                            "scope": scope,
                            "region": region,
                            "arn": arn,
                            "raw": summary,
                            "collection_error": str(exc),
                        }
                    )

                    continue

                web_acl = acl_response.get("WebACL") or {}

                resolved_arn = web_acl.get("ARN") or arn or acl_id

                resources.append(
                    {
                        "id": resolved_arn,
                        "name": (web_acl.get("Name") or name),
                        "web_acl_id": acl_id,
                        "scope": scope,
                        "region": region,
                        "arn": (web_acl.get("ARN") or arn),
                        "raw": web_acl,
                    }
                )

            next_marker = response.get("NextMarker")

            if not next_marker:
                break

        return resources

    # CLOUDWATCH PREFETCH

    def _prefetch_metrics(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        self._metrics_batch_cache = {
            "status": "not_queried",
            "results": {},
        }

        self._cloudwatch_request_diagnostics = {}

        profile = self._cloudwatch_profile()

        if (
            not profile
            or profile.get(
                "enabled",
                True,
            )
            is False
        ):
            return

        try:

            start, end = self.get_analysis_period()

        except ValueError as exc:

            self._metrics_batch_cache = {
                "status": "error",
                "results": {},
                "error": str(exc),
            }

            return

        try:

            requested_period = self._safe_period(profile.get("period"))

            namespace = str(profile.get("namespace") or "AWS/WAFV2").strip()

            metric_specs = self._metric_specs()

        except Exception as exc:

            self._metrics_batch_cache = {
                "status": "error",
                "results": {},
                "error": str(exc),
            }

            return

        requests: List[Dict[str, Any]] = []

        for resource in resources:

            if resource.get("collection_error"):
                continue

            resource_id = resource.get("id")

            if not resource_id:
                continue

            web_acl = resource.get("raw") or {}

            visibility = web_acl.get("VisibilityConfig") or {}

            acl_metric_name = visibility.get("MetricName") or resource.get("name")

            metrics_enabled = visibility.get("CloudWatchMetricsEnabled") is True

            diagnostic = {
                "resource_id": str(resource_id),
                "scope": resource.get("scope"),
                "region": resource.get("region"),
                "acl_metric_name": (acl_metric_name),
                "web_acl_cloudwatch_metrics_enabled": (metrics_enabled),
                "acl_requests_generated": 0,
                "rule_requests_generated": 0,
                "managed_rule_group_requests_generated": 0,
                "rule_requests_skipped_metrics_disabled": 0,
                "requests_generated": [],
            }

            # Web ACL metrics

            if metrics_enabled and acl_metric_name:

                dimensions = self._web_acl_dimensions(
                    resource=resource,
                    web_acl_metric_name=(str(acl_metric_name)),
                )

                request = {
                    "resource_key": str(resource_id),
                    "scope": "web_acl",
                    "namespace": namespace,
                    "dimensions": dimensions,
                    "metric_specs": metric_specs,
                }

                requests.append(request)

                diagnostic["acl_requests_generated"] += 1

                diagnostic["requests_generated"].append(
                    {
                        "scope": "web_acl",
                        "resource_key": str(resource_id),
                        "dimensions": dimensions,
                        "metric_names": [spec["name"] for spec in metric_specs],
                    }
                )

            # Rule metrics + managed rule group metrics

            for rule in _list(web_acl.get("Rules")):

                if not isinstance(
                    rule,
                    dict,
                ):
                    continue

                rule_visibility = rule.get("VisibilityConfig") or {}

                rule_metrics_enabled = (
                    rule_visibility.get("CloudWatchMetricsEnabled") is True
                )

                if not rule_metrics_enabled:

                    diagnostic["rule_requests_skipped_metrics_disabled"] += 1

                    continue

                rule_metric_name = rule_visibility.get("MetricName") or rule.get("Name")

                if not rule_metric_name:
                    continue

                statement = rule.get("Statement") or {}

                managed = self._extract_managed_rule_group(statement)

                if managed:

                    managed_name = managed.get("name")

                    if managed_name:

                        request = self._build_managed_rule_group_request(
                            resource=resource,
                            web_acl_metric_name=(str(acl_metric_name)),
                            managed_rule_group_name=(str(managed_name)),
                            namespace=namespace,
                            metric_specs=metric_specs,
                            resource_id=str(resource_id),
                        )

                        requests.append(request)

                        diagnostic["managed_rule_group_requests_generated"] += 1

                        diagnostic["requests_generated"].append(
                            {
                                "scope": ("managed_rule_group"),
                                "resource_key": (request["resource_key"]),
                                "managed_rule_group_name": (managed_name),
                                "dimensions": (request["dimensions"]),
                                "metric_names": [spec["name"] for spec in metric_specs],
                            }
                        )

                else:

                    dimensions = self._rule_dimensions(
                        resource=resource,
                        web_acl_metric_name=(str(acl_metric_name)),
                        rule_metric_name=(str(rule_metric_name)),
                    )

                    rule_resource_key = (
                        f"{resource_id}" "::rule::" f"{rule_metric_name}"
                    )

                    request = {
                        "resource_key": (rule_resource_key),
                        "scope": "rule",
                        "namespace": namespace,
                        "dimensions": dimensions,
                        "metric_specs": metric_specs,
                    }

                    requests.append(request)

                    diagnostic["rule_requests_generated"] += 1

                    diagnostic["requests_generated"].append(
                        {
                            "scope": "rule",
                            "resource_key": (rule_resource_key),
                            "rule_metric_name": (str(rule_metric_name)),
                            "dimensions": dimensions,
                            "metric_names": [spec["name"] for spec in metric_specs],
                        }
                    )

            self._cloudwatch_request_diagnostics[str(resource_id)] = diagnostic

        if not requests:

            self._metrics_batch_cache = {
                "status": "not_queried",
                "results": {},
                "error": (
                    "No CloudWatch WAF metric requests "
                    "were generated. Check WebACL "
                    "CloudWatchMetricsEnabled and "
                    "the configured metric profile."
                ),
            }

            return

        try:

            raw_results = (
                self.metric_collector.collect_batch(
                    requests=requests,
                    start=start,
                    end=end,
                    requested_period=(requested_period),
                )
                or {}
            )

        except Exception as exc:

            self._metrics_batch_cache = {
                "status": "error",
                "results": {},
                "error": str(exc),
            }

            self._finalize_cloudwatch_diagnostics(
                requests=requests,
                raw_results={},
                batch_error=str(exc),
            )

            return

        if not isinstance(
            raw_results,
            dict,
        ):
            raw_results = {}

        self._metrics_batch_cache = {
            "status": "ok",
            "results": raw_results,
        }

        self._finalize_cloudwatch_diagnostics(
            requests=requests,
            raw_results=raw_results,
            batch_error=None,
        )

    # CLOUDWATCH DIMENSIONS

    def _web_acl_dimensions(
        self,
        *,
        resource: Dict[str, Any],
        web_acl_metric_name: str,
    ) -> List[Dict[str, str]]:

        dimensions: List[Dict[str, str]] = []

        if resource.get("scope") != "CLOUDFRONT":

            dimensions.append(
                {
                    "Name": "Region",
                    "Value": str(resource.get("region") or self.region),
                }
            )

        dimensions.append(
            {
                "Name": "WebACL",
                "Value": (web_acl_metric_name),
            }
        )

        return dimensions

    def _rule_dimensions(
        self,
        *,
        resource: Dict[str, Any],
        web_acl_metric_name: str,
        rule_metric_name: str,
    ) -> List[Dict[str, str]]:

        dimensions = self._web_acl_dimensions(
            resource=resource,
            web_acl_metric_name=(web_acl_metric_name),
        )

        dimensions.append(
            {
                "Name": "Rule",
                "Value": rule_metric_name,
            }
        )

        return dimensions

    def _managed_rule_group_dimensions(
        self,
        *,
        resource: Dict[str, Any],
        web_acl_metric_name: str,
        managed_rule_group_name: str,
    ) -> List[Dict[str, str]]:

        dimensions = self._web_acl_dimensions(
            resource=resource,
            web_acl_metric_name=(web_acl_metric_name),
        )

        dimensions.append(
            {
                "Name": "ManagedRuleGroup",
                "Value": (managed_rule_group_name),
            }
        )

        return dimensions

    def _build_managed_rule_group_request(
        self,
        *,
        resource: Dict[str, Any],
        web_acl_metric_name: str,
        managed_rule_group_name: str,
        namespace: str,
        metric_specs: List[Dict[str, Any]],
        resource_id: str,
    ) -> Dict[str, Any]:

        key = f"{resource_id}" "::managed-rule-group::" f"{managed_rule_group_name}"

        return {
            "resource_key": key,
            "scope": "managed_rule_group",
            "namespace": namespace,
            "dimensions": (
                self._managed_rule_group_dimensions(
                    resource=resource,
                    web_acl_metric_name=(web_acl_metric_name),
                    managed_rule_group_name=(managed_rule_group_name),
                )
            ),
            "metric_specs": metric_specs,
        }

    # CLOUDWATCH DIAGNOSTICS

    def _finalize_cloudwatch_diagnostics(
        self,
        *,
        requests: List[Dict[str, Any]],
        raw_results: Dict[str, Any],
        batch_error: Optional[str],
    ) -> None:

        for request in requests:

            resource_key = str(request.get("resource_key"))

            owner_resource_id = (
                resource_key.split(
                    "::rule::",
                    1,
                )[0]
                if "::rule::" in resource_key
                else (
                    resource_key.split(
                        "::managed-rule-group::",
                        1,
                    )[0]
                    if "::managed-rule-group::" in resource_key
                    else resource_key
                )
            )

            diagnostic = self._cloudwatch_request_diagnostics.setdefault(
                owner_resource_id,
                {
                    "resource_id": (owner_resource_id),
                    "requests_generated": [],
                },
            )

            result = raw_results.get(resource_key)

            if not isinstance(
                result,
                list,
            ):

                diagnostic.setdefault(
                    "not_returned_request_keys",
                    [],
                ).append(resource_key)

                continue

            diagnostic.setdefault(
                "returned_request_keys",
                [],
            ).append(resource_key)

            diagnostic["returned_request_count"] = (
                diagnostic.get(
                    "returned_request_count",
                    0,
                )
                + 1
            )

            for metric in result:

                if not isinstance(
                    metric,
                    dict,
                ):
                    continue

                metric_name = metric.get("metric_name")

                status = str(
                    metric.get(
                        "status",
                        "",
                    )
                ).lower()

                has_data = metric.get("has_data") is True

                if status == "error":

                    diagnostic.setdefault(
                        "error_metrics",
                        [],
                    ).append(metric_name)

                elif status == "no_data" or not has_data:

                    diagnostic.setdefault(
                        "no_data_metrics",
                        [],
                    ).append(metric_name)

                elif status == "ok" and has_data:

                    diagnostic.setdefault(
                        "observed_metrics",
                        [],
                    ).append(metric_name)

            diagnostic["returned_metric_count"] = diagnostic.get(
                "returned_metric_count",
                0,
            ) + len(result)

            diagnostic["batch_error"] = batch_error

        for diagnostic in self._cloudwatch_request_diagnostics.values():

            diagnostic["observed_metrics"] = self._unique_strings(
                diagnostic.get(
                    "observed_metrics",
                    [],
                )
            )

            diagnostic["no_data_metrics"] = self._unique_strings(
                diagnostic.get(
                    "no_data_metrics",
                    [],
                )
            )

            diagnostic["error_metrics"] = self._unique_strings(
                diagnostic.get(
                    "error_metrics",
                    [],
                )
            )

            diagnostic["returned_request_keys"] = self._unique_strings(
                diagnostic.get(
                    "returned_request_keys",
                    [],
                )
            )

            diagnostic["not_returned_request_keys"] = self._unique_strings(
                diagnostic.get(
                    "not_returned_request_keys",
                    [],
                )
            )

            diagnostic["requests_generated_count"] = len(
                diagnostic.get(
                    "requests_generated",
                    [],
                )
            )

            diagnostic["returned_request_count"] = len(
                diagnostic.get(
                    "returned_request_keys",
                    [],
                )
            )

            diagnostic["not_returned_request_count"] = len(
                diagnostic.get(
                    "not_returned_request_keys",
                    [],
                )
            )

            diagnostic["observed_metric_count"] = len(
                diagnostic.get(
                    "observed_metrics",
                    [],
                )
            )

            diagnostic["no_data_metric_count"] = len(
                diagnostic.get(
                    "no_data_metrics",
                    [],
                )
            )

            diagnostic["error_metric_count"] = len(
                diagnostic.get(
                    "error_metrics",
                    [],
                )
            )

            diagnostic["request_generation_successful"] = (
                diagnostic["requests_generated_count"] > 0
            )

            diagnostic["metric_results_returned_successfully"] = (
                diagnostic["requests_generated_count"] > 0
                and diagnostic["not_returned_request_count"] == 0
                and batch_error is None
            )

            diagnostic["metric_results_reached_resource"] = (
                diagnostic["requests_generated_count"] > 0
                and diagnostic["not_returned_request_count"] == 0
                and diagnostic["error_metric_count"] == 0
                and batch_error is None
            )

    # OBSERVATIONS

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        profile = self._cloudwatch_profile()

        if (
            not profile
            or profile.get(
                "enabled",
                True,
            )
            is False
        ):

            return {
                "status": "disabled",
                "cloudwatch": {
                    "status": "disabled",
                    "metrics": {},
                    "acl_metrics": {},
                    "rule_metrics": {},
                    "managed_rule_group_metrics": {},
                    "telemetry_diagnostics": {},
                },
                "derived": {
                    "available": False,
                },
            }

        try:

            start, end = self.get_analysis_period()

        except ValueError as exc:

            return {
                "status": "error",
                "error": str(exc),
                "cloudwatch": {
                    "status": "error",
                    "metrics": {},
                    "acl_metrics": {},
                    "rule_metrics": {},
                    "managed_rule_group_metrics": {},
                    "telemetry_diagnostics": {},
                },
                "derived": {
                    "available": False,
                },
            }

        resource_id = str(resource.get("id"))

        cache = self._metrics_batch_cache.get(
            "results",
            {},
        )

        if not isinstance(
            cache,
            dict,
        ):
            cache = {}

        metrics: Dict[
            str,
            Dict[str, Any],
        ] = {}

        acl_results = cache.get(
            resource_id,
            [],
        )

        acl_metrics: Dict[
            str,
            Dict[str, Any],
        ] = {}

        if isinstance(
            acl_results,
            list,
        ):

            for result in acl_results:

                if not isinstance(
                    result,
                    dict,
                ):
                    continue

                metric_name = result.get("metric_name")

                if not metric_name:
                    continue

                stored = dict(result)

                stored["metric_scope"] = "web_acl"

                stored["original_metric_name"] = metric_name

                stored["metric_name"] = f"acl:{metric_name}"

                acl_metrics[stored["metric_name"]] = stored

                metrics[stored["metric_name"]] = stored

        rule_metrics: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        managed_rule_group_metrics: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        rule_prefix = f"{resource_id}::rule::"

        managed_prefix = f"{resource_id}" "::managed-rule-group::"

        for key, values in cache.items():

            key_text = str(key)

            if key_text.startswith(rule_prefix):

                rule_metric_name = key_text.split(
                    "::rule::",
                    1,
                )[-1]

                rule_metrics[rule_metric_name] = []

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                for result in values:

                    if not isinstance(
                        result,
                        dict,
                    ):
                        continue

                    metric_name = result.get("metric_name")

                    if not metric_name:
                        continue

                    stored = dict(result)

                    stored["metric_scope"] = "rule"

                    stored["rule_metric_name"] = rule_metric_name

                    stored["original_metric_name"] = metric_name

                    stored["metric_name"] = (
                        f"rule:" f"{rule_metric_name}:" f"{metric_name}"
                    )

                    metrics[stored["metric_name"]] = stored

                    rule_metrics[rule_metric_name].append(stored)

            elif key_text.startswith(managed_prefix):

                managed_name = key_text.split(
                    "::managed-rule-group::",
                    1,
                )[-1]

                managed_rule_group_metrics[managed_name] = []

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                for result in values:

                    if not isinstance(
                        result,
                        dict,
                    ):
                        continue

                    metric_name = result.get("metric_name")

                    if not metric_name:
                        continue

                    stored = dict(result)

                    stored["metric_scope"] = "managed_rule_group"

                    stored["managed_rule_group_name"] = managed_name

                    stored["original_metric_name"] = metric_name

                    stored["metric_name"] = (
                        f"managed_rule_group:" f"{managed_name}:" f"{metric_name}"
                    )

                    metrics[stored["metric_name"]] = stored

                    managed_rule_group_metrics[managed_name].append(stored)

        telemetry = self._cloudwatch_request_diagnostics.get(
            resource_id,
            {},
        )

        observed_count = (
            telemetry.get(
                "observed_metric_count",
                0,
            )
            or 0
        )

        no_data_count = (
            telemetry.get(
                "no_data_metric_count",
                0,
            )
            or 0
        )

        error_count = (
            telemetry.get(
                "error_metric_count",
                0,
            )
            or 0
        )

        request_count = (
            telemetry.get(
                "requests_generated_count",
                0,
            )
            or 0
        )

        not_returned_count = (
            telemetry.get(
                "not_returned_request_count",
                0,
            )
            or 0
        )

        batch_status = self._metrics_batch_cache.get("status")

        if batch_status == "error":

            status = "error"

        elif request_count > 0 and not_returned_count > 0:

            status = "incomplete"

        elif request_count > 0 and error_count > 0:

            status = "error"

        elif observed_count > 0:

            status = "ok"

        elif request_count == 0:

            status = "not_queried"

        elif no_data_count > 0:

            # Important:
            # WAF may publish only non-zero metrics.
            # Therefore this is NOT equivalent to zero traffic.
            status = "no_observed_data"

        else:

            status = "incomplete"

        cloudwatch = {
            "status": status,
            "namespace": (profile.get("namespace") or "AWS/WAFV2"),
            "requested_period": (self._safe_period(profile.get("period"))),
            "start": start.isoformat(),
            "end": end.isoformat(),
            "metrics": metrics,
            "acl_metrics": acl_metrics,
            "rule_metrics": rule_metrics,
            "managed_rule_group_metrics": (managed_rule_group_metrics),
            "telemetry_diagnostics": {
                **telemetry,
                "requests_generated_count": (request_count),
                "observed_metric_count": (observed_count),
                "no_data_metric_count": (no_data_count),
                "error_metric_count": (error_count),
                "not_returned_request_count": (not_returned_count),
                "returned_request_groups": (
                    telemetry.get(
                        "returned_request_count",
                        0,
                    )
                    or 0
                ),
                "returned_metric_results": (
                    telemetry.get(
                        "returned_metric_count",
                        0,
                    )
                    or 0
                ),
                "cloudwatch_errors": (error_count),
                "unmapped_requests": (not_returned_count),
                "request_generation_successful": (request_count > 0),
                "metric_results_returned_successfully": (
                    request_count > 0
                    and not_returned_count == 0
                    and telemetry.get("batch_error") is None
                ),
                "metric_results_reached_resource": (
                    request_count > 0
                    and not_returned_count == 0
                    and error_count == 0
                    and telemetry.get("batch_error") is None
                ),
            },
            "semantics": {
                "namespace": "AWS/WAFV2",
                "metrics_publish_nonzero_only": True,
                "missing_datapoint_is_confirmed_zero": (False),
                "activity_is_evidence": True,
                "request_volume_must_not_be_derived_by_adding_action_metrics": (True),
            },
        }

        observations = {
            "status": status,
            "cloudwatch": cloudwatch,
            "derived": {},
        }

        observations["derived"] = self._build_traffic_summary(observations)

        if self._metrics_batch_cache.get("error"):

            observations["error"] = self._metrics_batch_cache.get("error")

        return observations

    # TRAFFIC SUMMARY

    def _build_traffic_summary(
        self,
        observations: Dict[str, Any],
    ) -> Dict[str, Any]:

        cloudwatch = _dict(observations.get("cloudwatch"))

        metrics = _dict(cloudwatch.get("acl_metrics"))

        values: Dict[
            str,
            Optional[float],
        ] = {}

        observed: Dict[
            str,
            bool,
        ] = {}

        for metric_name in self.WEB_ACL_METRICS:

            matching = [
                metric
                for metric in metrics.values()
                if (
                    isinstance(
                        metric,
                        dict,
                    )
                    and metric.get("original_metric_name") == metric_name
                )
            ]

            metric = matching[0] if matching else {}

            has_data = metric.get("has_data") is True

            observed[metric_name] = has_data

            if has_data:

                value = (
                    metric.get("total")
                    if metric.get("total") is not None
                    else metric.get("value")
                )

                values[metric_name] = self._number(value)

            else:

                values[metric_name] = None

        return {
            "allowed_requests": (values.get("AllowedRequests")),
            "blocked_requests": (values.get("BlockedRequests")),
            "counted_requests": (values.get("CountedRequests")),
            "captcha_requests": (values.get("CaptchaRequests")),
            "challenge_requests": (values.get("ChallengeRequests")),
            "monetize_requests": (values.get("MonetizeRequests")),
            "valid_captcha_tokens": (values.get("RequestsWithValidCaptchaToken")),
            "captcha_attempts": (values.get("CaptchasAttempted")),
            "captcha_solved": (values.get("CaptchasSolved")),
            "valid_challenge_tokens": (values.get("RequestsWithValidChallengeToken")),
            "challenge_attempts": (values.get("ChallengesAttempted")),
            "challenge_solved": (values.get("ChallengesSolved")),
            # Deliberately not calculated.
            "request_volume": None,
            "request_volume_millions": None,
            "terminating_request_volume": None,
            "request_volume_exact": False,
            "complete": (all(observed.values()) if observed else False),
            "available": any(observed.values()),
            "metric_observation": observed,
            "semantics": {
                "metrics_publish_nonzero_only": True,
                "missing_is_zero": False,
                "request_volume_calculation": ("not_derived"),
                "reason_request_volume_not_derived": (
                    "AWS WAF action metrics are not "
                    "mutually exclusive additive buckets. "
                    "They therefore must not be summed "
                    "to manufacture total request volume."
                ),
                "billing_request_volume_source": ("billing_or_cost_explorer"),
                "cloudwatch_metrics_are_activity_evidence": (True),
            },
        }

    # ASSOCIATIONS

    def _collect_associations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        resource_id = str(resource.get("id") or "")

        if resource_id and resource_id in self._association_cache:

            return self._association_cache[resource_id]

        if resource.get("scope") == "CLOUDFRONT":

            result = self._collect_cloudfront_associations(resource)

        else:

            result = self._collect_regional_associations(resource)

        if resource_id:

            self._association_cache[resource_id] = result

        return result

    def _collect_regional_associations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        arn = resource.get("arn")

        if not arn:

            return {
                "status": "unknown",
                "complete": False,
                "evidence_state": "unavailable",
                "resources": [],
                "count": None,
                "known_resource_count": 0,
                "errors": [{"reason": ("web_acl_arn_unavailable")}],
                "ignored_not_applicable": [],
                "queried_resource_types": [],
                "completeness_reason": (
                    "The Web ACL ARN was unavailable; "
                    "association evidence could not "
                    "be collected."
                ),
            }

        associated: List[str] = []

        errors: List[Dict[str, Any]] = []

        ignored_not_applicable: List[Dict[str, Any]] = []

        queried_types: List[str] = []

        for resource_type in self._association_resource_types():

            queried_types.append(resource_type)

            try:

                response = self.waf.list_resources_for_web_acl(
                    WebACLArn=arn,
                    ResourceType=(resource_type),
                )

            except Exception as exc:

                error_text = str(exc)

                if self._is_not_applicable_association_error(error_text):

                    ignored_not_applicable.append(
                        {
                            "resource_type": (resource_type),
                            "reason": error_text,
                        }
                    )

                else:

                    errors.append(
                        {
                            "resource_type": (resource_type),
                            "error": error_text,
                        }
                    )

                continue

            for value in (
                response.get(
                    "ResourceArns",
                    [],
                )
                or []
            ):

                text = str(value).strip()

                if text and text not in associated:

                    associated.append(text)

        if errors:

            if associated:

                status = "partial"

                completeness_reason = (
                    "Some WAF association resource "
                    "types could not be queried. "
                    "The observed associations are "
                    "only a partial view; the "
                    "remaining result cannot be "
                    "interpreted as proof that the "
                    "Web ACL is unused."
                )

            else:

                status = "error"

                completeness_reason = (
                    "One or more configured WAF "
                    "association resource types could "
                    "not be queried. An empty result "
                    "cannot be interpreted as proof "
                    "that the Web ACL is unused."
                )

            complete = False
            evidence_state = "incomplete"

        else:

            status = "ok"
            complete = True
            evidence_state = "complete"

            completeness_reason = (
                "All configured applicable WAF "
                "association resource types were "
                "queried successfully."
            )

        count = len(associated)

        return {
            "status": status,
            "complete": complete,
            "evidence_state": evidence_state,
            "resources": associated,
            "count": count,
            "known_resource_count": count,
            "errors": errors,
            "ignored_not_applicable": (ignored_not_applicable),
            "queried_resource_types": (queried_types),
            "completeness_reason": (completeness_reason),
        }

    @staticmethod
    def _is_not_applicable_association_error(
        error_text: str,
    ) -> bool:

        text = (error_text or "").lower()

        return any(
            token in text
            for token in (
                "unsupported resource type",
                "resource type is not supported",
                "invalid resource type",
                "not supported",
            )
        )

    def _collect_cloudfront_associations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        arn = resource.get("arn")

        if not arn:

            return {
                "status": "unknown",
                "complete": False,
                "evidence_state": "unavailable",
                "resources": [],
                "count": None,
                "known_resource_count": 0,
                "errors": [{"reason": ("web_acl_arn_unavailable")}],
                "ignored_not_applicable": [],
                "queried_resource_types": ["CLOUDFRONT"],
                "completeness_reason": (
                    "The CloudFront Web ACL ARN " "was unavailable."
                ),
            }

        client = self._get_cloudfront_client()

        distributions: List[str] = []

        try:

            response = client.list_distributions_by_web_acl_id(WebACLId=arn)

            while True:

                distribution_list = (
                    response.get(
                        "DistributionList",
                        {},
                    )
                    or {}
                )

                for item in (
                    distribution_list.get(
                        "Items",
                        [],
                    )
                    or []
                ):

                    if not isinstance(
                        item,
                        dict,
                    ):
                        continue

                    distribution_arn = item.get("ARN") or item.get("Id")

                    if distribution_arn and str(distribution_arn) not in distributions:

                        distributions.append(str(distribution_arn))

                if not response.get(
                    "IsTruncated",
                    False,
                ):
                    break

                marker = response.get("NextMarker")

                if not marker:
                    break

                response = client.list_distributions_by_web_acl_id(
                    WebACLId=arn,
                    Marker=marker,
                )

        except Exception as exc:

            return {
                "status": "error",
                "complete": False,
                "evidence_state": "unavailable",
                "resources": [],
                "count": None,
                "known_resource_count": 0,
                "errors": [
                    {
                        "resource_type": ("CLOUDFRONT"),
                        "error": str(exc),
                    }
                ],
                "ignored_not_applicable": [],
                "queried_resource_types": ["CLOUDFRONT"],
                "completeness_reason": (
                    "The CloudFront association "
                    "query failed. Empty results "
                    "must not be interpreted as "
                    "proof that the Web ACL is unused."
                ),
            }

        return {
            "status": "ok",
            "complete": True,
            "evidence_state": "complete",
            "resources": distributions,
            "count": len(distributions),
            "known_resource_count": len(distributions),
            "errors": [],
            "ignored_not_applicable": [],
            "queried_resource_types": ["CLOUDFRONT"],
            "completeness_reason": (
                "CloudFront distributions "
                "associated with the Web ACL "
                "were queried successfully."
            ),
        }

    # IDENTITY

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        value = resource.get("id")

        if not value:
            raise ValueError("WAF Web ACL resource ID is missing.")

        return str(value)

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        web_acl = resource.get("raw") or {}

        return {
            "name": (web_acl.get("Name") or resource.get("name")),
            "web_acl_id": (resource.get("web_acl_id")),
            "arn": (web_acl.get("ARN") or resource.get("arn")),
            "scope": (resource.get("scope")),
            "region": (resource.get("region")),
            "description": (web_acl.get("Description")),
            "tags": self._tags(resource),
        }

    # CONFIGURATION

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        web_acl = resource.get("raw") or {}

        rules = [
            rule
            for rule in _list(web_acl.get("Rules"))
            if isinstance(
                rule,
                dict,
            )
        ]

        rule_details: List[Dict[str, Any]] = []

        managed_rule_groups: List[Dict[str, Any]] = []

        customer_rule_groups: List[Dict[str, Any]] = []

        custom_rules: List[str] = []

        premium_features: Set[str] = set()

        captcha_rule_count = 0
        challenge_rule_count = 0

        for rule in rules:

            detail = self._normalize_rule(rule)

            rule_details.append(detail)

            statement = rule.get("Statement") or {}

            info = self._inspect_statement(statement)

            managed = info.get("managed_rule_group")

            customer_group = info.get("rule_group")

            if isinstance(
                managed,
                dict,
            ):

                managed_rule_groups.append(managed)

                premium_features.update(
                    self._premium_features_for_managed_group(managed)
                )

            elif isinstance(
                customer_group,
                dict,
            ):

                customer_rule_groups.append(customer_group)

            else:

                name = rule.get("Name")

                if name:
                    custom_rules.append(str(name))

            if info.get("captcha"):
                captcha_rule_count += 1

            if info.get("challenge"):
                challenge_rule_count += 1

        if captcha_rule_count:
            premium_features.add("captcha")

        if challenge_rule_count:
            premium_features.add("challenge")

        association_config = web_acl.get("AssociationConfig") or {}

        visibility = web_acl.get("VisibilityConfig") or {}

        capacity = self._number(web_acl.get("Capacity"))

        associations = self._collect_associations(resource)

        logging = self._collect_logging(resource)

        body_inspection = self._normalize_body_inspection(association_config)

        return {
            "web_acl_id": (resource.get("web_acl_id")),
            "name": (resource.get("name")),
            "arn": (resource.get("arn")),
            "scope": (resource.get("scope")),
            "default_action": (
                self._normalize_default_action(web_acl.get("DefaultAction"))
            ),
            "rule_count": len(rules),
            "custom_rule_count": len(custom_rules),
            "managed_rule_group_count": len(managed_rule_groups),
            "customer_rule_group_count": len(customer_rule_groups),
            "managed_rule_groups": (managed_rule_groups),
            "rule_groups": (customer_rule_groups),
            "custom_rules": (custom_rules),
            "rules": (rule_details),
            "capacity_wcu": (capacity),
            "visibility": (visibility),
            "sampled_requests_enabled": (visibility.get("SampledRequestsEnabled")),
            "cloudwatch_metrics_enabled": (visibility.get("CloudWatchMetricsEnabled")),
            "association_config": (
                self._normalize_association_config(association_config)
            ),
            "associations": (
                associations.get(
                    "resources",
                    [],
                )
            ),
            "association_count": (associations.get("count")),
            "association_status": (associations.get("status")),
            "association_complete": (associations.get("complete")),
            "association_evidence_state": (associations.get("evidence_state")),
            "association_known_resource_count": (
                associations.get("known_resource_count")
            ),
            "association_completeness_reason": (
                associations.get("completeness_reason")
            ),
            "association_errors": (
                associations.get(
                    "errors",
                    [],
                )
            ),
            "association_ignored_not_applicable": (
                associations.get(
                    "ignored_not_applicable",
                    [],
                )
            ),
            "logging": (logging),
            "logging_enabled": (logging.get("enabled")),
            "premium_features": sorted(premium_features),
            "captcha_rule_count": (captcha_rule_count),
            "challenge_rule_count": (challenge_rule_count),
            "body_inspection": (body_inspection),
        }

    # RELATIONSHIPS

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        association_info = self._collect_associations(resource)

        return {
            "protected_resources": (
                association_info.get(
                    "resources",
                    [],
                )
            ),
            "protected_resource_count": (association_info.get("count")),
            "protected_resource_count_known": (
                association_info.get("known_resource_count")
            ),
            "association_status": (association_info.get("status")),
            "association_complete": (association_info.get("complete")),
            "association_evidence_state": (association_info.get("evidence_state")),
            "association_completeness_reason": (
                association_info.get("completeness_reason")
            ),
            "association_errors": (
                association_info.get(
                    "errors",
                    [],
                )
            ),
            "association_ignored_not_applicable": (
                association_info.get(
                    "ignored_not_applicable",
                    [],
                )
            ),
            "queried_resource_types": (
                association_info.get(
                    "queried_resource_types",
                    [],
                )
            ),
        }

    # TOPOLOGY

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "status": "not_applicable",
            "reason": (
                "WAF cost analysis does not require "
                "VPC topology. Protected resources "
                "are collected through WAF associations."
            ),
        }

    # LOGGING

    def _collect_logging(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        arn = resource.get("arn")

        if not arn:

            return {
                "enabled": False,
                "status": "unknown",
                "error": ("web_acl_arn_unavailable"),
            }

        client = (
            self._get_cloudfront_waf_client()
            if resource.get("scope") == "CLOUDFRONT"
            else self.waf
        )

        try:

            response = client.get_logging_configuration(ResourceArn=arn)

        except Exception as exc:

            if self._is_logging_not_configured_error(exc):

                return {
                    "enabled": False,
                    "status": "not_configured",
                    "destination_count": 0,
                    "destinations": [],
                }

            return {
                "enabled": False,
                "status": "error",
                "error": str(exc),
            }

        config = response.get("LoggingConfiguration")

        if not isinstance(
            config,
            dict,
        ):

            return {
                "enabled": False,
                "status": "not_configured",
                "destination_count": 0,
                "destinations": [],
            }

        destinations = (
            config.get(
                "LogDestinationConfigs",
                [],
            )
            or []
        )

        return {
            "enabled": True,
            "status": "ok",
            "destination_count": len(destinations),
            "destinations": list(destinations),
            "logging_filter": (config.get("LoggingFilter")),
            "redacted_fields": (
                config.get(
                    "RedactedFields",
                    [],
                )
                or []
            ),
            "log_scope": (config.get("LogScope")),
            "managed_by_firewall_manager": (config.get("ManagedByFirewallManager")),
        }

    @staticmethod
    def _is_logging_not_configured_error(
        exc: Exception,
    ) -> bool:

        text = str(exc).lower()

        return any(
            token in text
            for token in (
                "wafnonexistentitemexception",
                "resource doesn't exist",
                "resource does not exist",
                "not found",
            )
        )

    # RULE NORMALIZATION

    def _normalize_rule(
        self,
        rule: Dict[str, Any],
    ) -> Dict[str, Any]:

        statement = rule.get("Statement") or {}

        statement_info = self._inspect_statement(statement)

        visibility = rule.get("VisibilityConfig") or {}

        managed = statement_info.get("managed_rule_group")

        return {
            "name": (rule.get("Name")),
            "priority": (rule.get("Priority")),
            "action": (self._rule_action(rule)),
            "override_action": (rule.get("OverrideAction")),
            "metric_name": (visibility.get("MetricName")),
            "cloudwatch_metrics_enabled": (visibility.get("CloudWatchMetricsEnabled")),
            "sampled_requests_enabled": (visibility.get("SampledRequestsEnabled")),
            "statement_type": (statement_info.get("statement_type")),
            "managed_rule_group": (managed),
            "rule_group": (statement_info.get("rule_group")),
            "contains_captcha": (statement_info.get("captcha")),
            "contains_challenge": (statement_info.get("challenge")),
        }

    def _inspect_statement(
        self,
        statement: Dict[str, Any],
    ) -> Dict[str, Any]:

        result = {
            "statement_type": None,
            "managed_rule_group": None,
            "rule_group": None,
            "captcha": False,
            "challenge": False,
        }

        if not isinstance(
            statement,
            dict,
        ):
            return result

        self._inspect_statement_recursive(
            statement,
            result,
        )

        return result

    def _inspect_statement_recursive(
        self,
        value: Any,
        result: Dict[str, Any],
    ) -> None:

        if isinstance(
            value,
            dict,
        ):

            for key, child in value.items():

                key_text = str(key)

                if result["statement_type"] is None and key_text.endswith("Statement"):

                    result["statement_type"] = key_text

                if key_text == "ManagedRuleGroupStatement":

                    if isinstance(
                        child,
                        dict,
                    ):

                        result["managed_rule_group"] = {
                            "name": child.get("Name"),
                            "vendor_name": child.get("VendorName"),
                            "version": child.get("Version"),
                            "excluded_rules": [
                                item.get("Name")
                                for item in _list(child.get("ExcludedRules"))
                                if (
                                    isinstance(
                                        item,
                                        dict,
                                    )
                                    and item.get("Name")
                                )
                            ],
                            "scope_down": bool(child.get("ScopeDownStatement")),
                            "rule_action_overrides": (
                                child.get(
                                    "RuleActionOverrides",
                                    [],
                                )
                                or []
                            ),
                            "managed_rule_group_configs": (
                                child.get(
                                    "ManagedRuleGroupConfigs",
                                    [],
                                )
                                or []
                            ),
                        }

                        result["statement_type"] = "managed_rule_group"

                elif key_text == "RuleGroupReferenceStatement":

                    if isinstance(
                        child,
                        dict,
                    ):

                        result["rule_group"] = {
                            "arn": child.get("ARN"),
                            "excluded_rules": [
                                item.get("Name")
                                for item in _list(child.get("ExcludedRules"))
                                if (
                                    isinstance(
                                        item,
                                        dict,
                                    )
                                    and item.get("Name")
                                )
                            ],
                        }

                        result["statement_type"] = "rule_group"

                if key_text in {
                    "Captcha",
                    "CaptchaConfig",
                }:

                    result["captcha"] = True

                if key_text in {
                    "Challenge",
                    "ChallengeConfig",
                }:

                    result["challenge"] = True

                self._inspect_statement_recursive(
                    child,
                    result,
                )

        elif isinstance(
            value,
            list,
        ):

            for item in value:

                self._inspect_statement_recursive(
                    item,
                    result,
                )

    @staticmethod
    def _extract_managed_rule_group(
        statement: Any,
    ) -> Optional[Dict[str, Any]]:

        if not isinstance(
            statement,
            dict,
        ):
            return None

        managed = statement.get("ManagedRuleGroupStatement")

        if isinstance(
            managed,
            dict,
        ):
            return managed

        return None

    def _premium_features_for_managed_group(
        self,
        managed: Dict[str, Any],
    ) -> List[str]:

        name = str(managed.get("name") or "")

        result: List[str] = []

        if name in (self.AWS_BOT_CONTROL_RULE_GROUPS):

            result.append("bot_control")

        if name in (self.AWS_ATP_RULE_GROUPS):

            result.append("account_takeover_prevention")

        if name in (self.AWS_ACFP_RULE_GROUPS):

            result.append("account_creation_fraud_prevention")

        return result

    # BODY INSPECTION

    def _normalize_body_inspection(
        self,
        association_config: Any,
    ) -> Dict[str, Any]:

        if not isinstance(
            association_config,
            dict,
        ):

            return {
                "configured": False,
                "default_limit_kb": (self.DEFAULT_BODY_LIMIT_KB),
                "resources": {},
                "maximum_configured_kb": (self.DEFAULT_BODY_LIMIT_KB),
                "above_default": False,
            }

        request_body = association_config.get("RequestBody") or {}

        if not isinstance(
            request_body,
            dict,
        ):
            request_body = {}

        resources: Dict[
            str,
            Any,
        ] = {}

        for (
            resource_type,
            config,
        ) in request_body.items():

            if not isinstance(
                config,
                dict,
            ):
                continue

            value = config.get("DefaultSizeInspectionLimit")

            text = str(value or "").upper().strip()

            kb = self.BODY_LIMIT_KB.get(text)

            resources[str(resource_type)] = {
                "configured_value": value,
                "limit_kb": kb,
                "above_default": (kb is not None and kb > self.DEFAULT_BODY_LIMIT_KB),
            }

        limits = [
            item["limit_kb"]
            for item in resources.values()
            if item.get("limit_kb") is not None
        ]

        maximum = max(limits) if limits else self.DEFAULT_BODY_LIMIT_KB

        return {
            "configured": bool(resources),
            "default_limit_kb": (self.DEFAULT_BODY_LIMIT_KB),
            "resources": resources,
            "maximum_configured_kb": (maximum),
            "above_default": (maximum > self.DEFAULT_BODY_LIMIT_KB),
        }

    # ACTION NORMALIZATION

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
            "CustomResponse",
            "Monetize",
        ):

            if key in action:
                return key.lower()

        return None

    @staticmethod
    def _rule_action(
        rule: Dict[str, Any],
    ) -> Optional[str]:

        action = rule.get("Action") or {}

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
                "CustomResponse",
                "Monetize",
            ):

                if key in action:
                    return key.lower()

        override = rule.get("OverrideAction") or {}

        if isinstance(
            override,
            dict,
        ):

            if "None" in override:
                return "managed_rule_group_default"

            if "Count" in override:
                return "count"

        return None

    @staticmethod
    def _normalize_association_config(
        association_config: Any,
    ) -> Dict[str, Any]:

        return (
            association_config
            if isinstance(
                association_config,
                dict,
            )
            else {}
        )

    # TAGS

    def _tags(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, str]:

        arn = resource.get("arn")

        if not arn:
            return {}

        client = (
            self._get_cloudfront_waf_client()
            if resource.get("scope") == "CLOUDFRONT"
            else self.waf
        )

        try:

            response = client.list_tags_for_resource(ResourceARN=arn)

        except Exception:
            return {}

        tag_info = response.get("TagInfoForResource") or {}

        tags = (
            tag_info.get(
                "TagList",
                [],
            )
            or []
        )

        return {
            str(tag.get("Key")): str(tag.get("Value"))
            for tag in tags
            if (
                isinstance(
                    tag,
                    dict,
                )
                and tag.get("Key")
            )
        }

    # OPTIMIZATION EVIDENCE

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        identity = _dict(collected_resource.get("identity"))

        configuration = _dict(collected_resource.get("configuration"))

        observations = _dict(collected_resource.get("observations"))

        relationships = _dict(collected_resource.get("relationships"))

        cloudwatch = _dict(observations.get("cloudwatch"))

        traffic = _dict(observations.get("derived"))

        telemetry = _dict(cloudwatch.get("telemetry_diagnostics"))

        return {
            "resource": {
                "id": resource.get("id"),
                "name": identity.get("name"),
                "scope": identity.get("scope"),
                "region": identity.get("region"),
                "arn": identity.get("arn"),
            },
            "configuration": {
                key: value for key, value in configuration.items() if key != "tags"
            },
            "rules": {
                "count": configuration.get("rule_count"),
                "custom_rule_count": (configuration.get("custom_rule_count")),
                "managed_rule_group_count": (
                    configuration.get("managed_rule_group_count")
                ),
                "customer_rule_group_count": (
                    configuration.get("customer_rule_group_count")
                ),
                "rules": configuration.get(
                    "rules",
                    [],
                ),
                "managed_rule_groups": (
                    configuration.get(
                        "managed_rule_groups",
                        [],
                    )
                ),
                "rule_groups": (
                    configuration.get(
                        "rule_groups",
                        [],
                    )
                ),
            },
            "relationships": {
                "protected_resource_count": (
                    relationships.get("protected_resource_count")
                ),
                "protected_resource_count_known": (
                    relationships.get("protected_resource_count_known")
                ),
                "association_evidence_state": (
                    relationships.get("association_evidence_state")
                ),
                "association_completeness_reason": (
                    relationships.get("association_completeness_reason")
                ),
                "protected_resources": (
                    relationships.get(
                        "protected_resources",
                        [],
                    )
                ),
                "association_status": (relationships.get("association_status")),
                "association_complete": (relationships.get("association_complete")),
                "association_errors": (
                    relationships.get(
                        "association_errors",
                        [],
                    )
                ),
                "association_ignored_not_applicable": (
                    relationships.get(
                        "association_ignored_not_applicable",
                        [],
                    )
                ),
                "queried_resource_types": (
                    relationships.get(
                        "queried_resource_types",
                        [],
                    )
                ),
            },
            "features": {
                "premium_features": (
                    configuration.get(
                        "premium_features",
                        [],
                    )
                ),
                "captcha_rule_count": (configuration.get("captcha_rule_count")),
                "challenge_rule_count": (configuration.get("challenge_rule_count")),
                "logging_enabled": (configuration.get("logging_enabled")),
                "body_inspection": (
                    configuration.get(
                        "body_inspection",
                        {},
                    )
                ),
            },
            "traffic": traffic,
            "cloudwatch": {
                "metrics": cloudwatch.get(
                    "metrics",
                    {},
                ),
                "acl_metrics": cloudwatch.get(
                    "acl_metrics",
                    {},
                ),
                "rule_metrics": cloudwatch.get(
                    "rule_metrics",
                    {},
                ),
                "managed_rule_group_metrics": (
                    cloudwatch.get(
                        "managed_rule_group_metrics",
                        {},
                    )
                ),
                "status": cloudwatch.get("status"),
                "start": cloudwatch.get("start"),
                "end": cloudwatch.get("end"),
                "telemetry_diagnostics": (telemetry),
            },
            "data_quality": {
                "configuration_available": bool(configuration),
                "relationship_available": bool(relationships),
                "association_complete": (
                    relationships.get("association_complete") is True
                ),
                "association_status": (relationships.get("association_status")),
                "association_evidence_state": (
                    relationships.get("association_evidence_state")
                ),
                "association_completeness_reason": (
                    relationships.get("association_completeness_reason")
                ),
                "protected_resource_count_known": (
                    relationships.get("protected_resource_count_known")
                ),
                "association_errors": (
                    relationships.get(
                        "association_errors",
                        [],
                    )
                ),
                "cloudwatch_status": (cloudwatch.get("status")),
                "cloudwatch_metrics_requested": (
                    telemetry.get(
                        "requests_generated_count",
                        0,
                    )
                    > 0
                ),
                "cloudwatch_metric_results_reached_resource": (
                    telemetry.get("metric_results_reached_resource") is True
                ),
                "cloudwatch_request_groups_returned": (
                    telemetry.get(
                        "returned_request_groups",
                        0,
                    )
                ),
                "cloudwatch_metric_results_returned": (
                    telemetry.get(
                        "returned_metric_results",
                        0,
                    )
                ),
                "cloudwatch_errors": (
                    telemetry.get(
                        "cloudwatch_errors",
                        0,
                    )
                ),
                "cloudwatch_unmapped_requests": (
                    telemetry.get(
                        "unmapped_requests",
                        0,
                    )
                ),
                "cloudwatch_request_generation_successful": (
                    telemetry.get("request_generation_successful") is True
                ),
                "cloudwatch_metric_results_returned_successfully": (
                    telemetry.get("metric_results_returned_successfully") is True
                ),
                "traffic_available": (traffic.get("available") is True),
                "traffic_complete": (traffic.get("complete") is True),
                "request_volume_exact": False,
                "missing_is_zero": False,
                "waf_metric_missing_semantics": (
                    "AWS WAF core metrics are generally "
                    "published only for non-zero values; "
                    "missing datapoints must not be "
                    "converted into confirmed zero traffic."
                ),
            },
        }

    @staticmethod
    def _unique_strings(
        values: Any,
    ) -> List[str]:

        if not isinstance(
            values,
            list,
        ):
            return []

        result: List[str] = []

        seen: Set[str] = set()

        for value in values:

            if value is None:
                continue

            text = str(value)

            if text in seen:
                continue

            seen.add(text)

            result.append(text)

        return result

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
            return float(value)

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _safe_period(
        value: Any,
    ) -> int:

        if value is None:
            return 300

        try:

            return max(
                int(value),
                60,
            )

        except (
            TypeError,
            ValueError,
        ):

            return 300
