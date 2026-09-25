"""
AWS WAF cost-optimization analyzer.

Purpose
-------
Generate evidence-based AWS WAF findings.

Analyzer responsibilities
-------------------------
1. Web ACL association state
2. Request-volume exposure
3. WCU-based request pricing exposure
4. Customer rule-count cost exposure
5. Explicitly observed rule activity
6. Managed rule-group cost exposure
7. CAPTCHA cost exposure
8. Challenge cost exposure
9. Request-body inspection cost exposure
10. Bot Control cost exposure
11. Fraud Control cost exposure

Important semantics
-------------------
The analyzer separates:

    configuration exposure

from:

    observed usage exposure

Configuration alone does not prove that a usage-based charge
was incurred.

Missing CloudWatch datapoints are NEVER interpreted as zero traffic.

Successful telemetry with zero datapoints means:

    telemetry request succeeded
    + request/metric correlation succeeded
    + metric response succeeded
    + no observable datapoints

It does NOT mean:

    zero traffic

Association semantics
---------------------
Association count is authoritative only when discovery is complete.

    count == 0 + complete == True
        -> zero associations confirmed

    count == 0 + complete == False
        -> association state unknown

    count > 0
        -> associations observed

Pricing semantics
-----------------
Pricing constants represent AWS WAF public pricing assumptions.

The analyzer does not infer:

- Marketplace seller pricing
- billable Challenge responses from ChallengeRequests
- oversized-body requests from total request volume
- Bot Control billable requests without exact telemetry
- Fraud Control request charges without exact usage evidence

Rule pricing semantics
-----------------------
AWS WAF charges:

- $5/month per Web ACL
- $1/month per customer-created rule
- $1/month per rule group / managed rule group added to the ACL

Rules contained inside AWS-managed rule groups are not treated as
customer-created rules.

Therefore:

    customer_rule_count

is preferred over a generic:

    rule_count

when calculating customer rule charges.

Bot Control pricing semantics
-----------------------------
Common Bot Control:

    $10/month per Web ACL
    first 10,000,000 requests/month free
    $1.00/million additional requests

Targeted Bot Control:

    $10/month per Web ACL
    first 1,000,000 requests/month free
    $10.00/million additional requests

Fraud Control
-------------
Fraud Control has:

    $10/month subscription per enabled feature/Web ACL

Request charges are tiered and require exact request telemetry.
The analyzer therefore reports configuration exposure unless
the collector supplies exact usage and pricing evidence.

Challenge
---------
AWS bills Challenge responses, not simply ChallengeRequests.

Therefore ChallengeRequests are treated as usage evidence only,
not as an exact billable quantity.
"""

from __future__ import annotations

import math
from typing import Any, Optional

from ...base import Analyzer
from ...condition import EvidenceStatement
from ...context import AnalysisContext
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
from ...registry import register

# AWS WAF PRICING CONSTANTS

AWS_WAF_WEB_ACL_MONTHLY_PRICE = 5.00

AWS_WAF_CUSTOMER_RULE_MONTHLY_PRICE = 1.00
AWS_WAF_RULE_GROUP_MONTHLY_PRICE = 1.00

AWS_WAF_INCLUDED_WCU = 1500
AWS_WAF_WCU_BLOCK = 500
AWS_WAF_WCU_PRICE_PER_MILLION = 0.20

AWS_WAF_REQUEST_PRICE_PER_MILLION = 0.60

AWS_WAF_EXTRA_BODY_BLOCK_KB = 16
AWS_WAF_EXTRA_BODY_PRICE_PER_MILLION = 0.30

AWS_WAF_CAPTCHA_PRICE_PER_1000 = 0.40

AWS_WAF_CHALLENGE_PRICE_PER_1000 = 0.40

AWS_WAF_BOT_CONTROL_MONTHLY_PRICE = 10.00

AWS_WAF_COMMON_BOT_FREE_REQUESTS = 10_000_000
AWS_WAF_COMMON_BOT_PRICE_PER_MILLION = 1.00

AWS_WAF_TARGETED_BOT_FREE_REQUESTS = 1_000_000
AWS_WAF_TARGETED_BOT_PRICE_PER_MILLION = 10.00

AWS_WAF_FRAUD_CONTROL_MONTHLY_PRICE = 10.00


# DEFAULT ANALYSIS THRESHOLDS

DEFAULT_HIGH_REQUESTS = 10_000_000
DEFAULT_HIGH_WCU = 1500
DEFAULT_MAX_RULE_COUNT = 20

DEFAULT_MIN_CAPTCHA_REQUESTS = 1_000
DEFAULT_MIN_CHALLENGE_REQUESTS = 1_000


# FINDING TITLES

TITLES = {
    "waf_unused_web_acl": "Unused WAF Web ACL",
    "waf_high_request_volume": "High WAF Request Volume",
    "waf_high_wcu": "WAF WCU Cost Exposure",
    "waf_high_rule_count": "High WAF Customer Rule Count",
    "waf_rule_no_observed_activity": "WAF Rule With No Observed Activity",
    "waf_managed_rule_group_cost_exposure": ("WAF Managed Rule Group Cost Exposure"),
    "waf_captcha_cost_exposure": "WAF CAPTCHA Cost Exposure",
    "waf_challenge_cost_exposure": "WAF Challenge Cost Exposure",
    "waf_body_inspection_cost_exposure": (
        "Oversized WAF Body Inspection Cost Exposure"
    ),
    "waf_bot_control_cost_exposure": "WAF Bot Control Cost Exposure",
    "waf_fraud_control_cost_exposure": "WAF Fraud Control Cost Exposure",
    "waf_cloudwatch_no_observed_metrics": (
        "AWS WAF Has No Observed CloudWatch Request Metrics"
    ),
}


# GENERIC HELPERS


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _statement(
    *,
    name: str,
    value: Any,
    description: str,
    source: list[str],
    unit: str | None = None,
) -> EvidenceStatement:

    return EvidenceStatement(
        name=name,
        value=value,
        description=description,
        source=list(source),
        unit=unit,
    )


# ANALYZER


@register
class WAFAnalyzer(Analyzer):

    name = "waf"

    version = "7.0"

    SUPPORTED_RESOURCE_TYPES = {
        "waf_web_acl",
    }

    # SUPPORT

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return context.resource_type in self.SUPPORTED_RESOURCE_TYPES

    # MAIN ANALYSIS

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        evidence = _dict(context.optimization_evidence())

        if not evidence:
            return []

        findings: list[Finding] = []

        detectors = (
            self._detect_unused_web_acl,
            self._detect_high_request_volume,
            self._detect_high_wcu,
            self._detect_high_rule_count,
            self._detect_rule_no_observed_activity,
            self._detect_managed_rule_group_cost,
            self._detect_captcha_cost,
            self._detect_challenge_cost,
            self._detect_body_inspection_cost,
            self._detect_bot_control_cost,
            self._detect_fraud_control_cost,
        )

        for detector in detectors:

            try:
                finding = detector(
                    context,
                    evidence,
                )

            except Exception as exc:

                print(
                    "[ERROR] WAF analyzer detector "
                    f"{detector.__name__} failed for "
                    f"{context.resource_id}: {exc}"
                )

                continue

            if finding is not None:
                findings.append(finding)

        return findings

    # EVIDENCE DOMAINS

    @staticmethod
    def _configuration(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("configuration"))

    @staticmethod
    def _relationships(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("relationships"))

    @staticmethod
    def _traffic(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("traffic"))

    @staticmethod
    def _cloudwatch(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("cloudwatch"))

    @staticmethod
    def _quality(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(evidence.get("data_quality"))

    # TELEMETRY SEMANTICS

    _METRIC_OBSERVATION_KEYS = {
        "captcha_attempts": "CaptchasAttempted",
        "challenge_requests": "ChallengeRequests",
    }

    @classmethod
    def _telemetry_complete(
        cls,
        traffic: dict[str, Any],
        *,
        metric_key: str | None = None,
    ) -> bool:

        # Specific metric

        if metric_key is not None:

            raw_metric_name = cls._METRIC_OBSERVATION_KEYS.get(metric_key)

            if raw_metric_name is None:
                return False

            observation = _dict(traffic.get("metric_observation"))

            return observation.get(raw_metric_name) is True

        # Overall telemetry

        return traffic.get("available") is True and traffic.get("complete") is True

    # UNUSED WEB ACL

    def _detect_unused_web_acl(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        relationships = self._relationships(evidence)

        protected_count = _number(relationships.get("protected_resource_count"))

        association_complete = relationships.get("association_complete") is True

        if protected_count is None:
            return None

        if not association_complete:
            return None

        if protected_count != 0:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_unused_web_acl",
            severity="medium",
            confidence="high",
            recommendation_eligible=True,
            cost_optimization_type="elimination",
            reason=(
                "The Web ACL has zero confirmed protected resources "
                "and association discovery completed successfully. "
                "The Web ACL should be reviewed for removal if it is "
                "no longer required."
            ),
            statements=[
                _statement(
                    name="protected_resource_count",
                    value=0,
                    description=(
                        "Number of resources confirmed as protected " "by this Web ACL."
                    ),
                    source=["AWS WAF associations"],
                    unit="resources",
                ),
                _statement(
                    name="association_complete",
                    value=True,
                    description=("Association discovery completed successfully."),
                    source=["AWS WAF"],
                    unit="boolean",
                ),
                _statement(
                    name="web_acl_monthly_charge_exposure",
                    value=AWS_WAF_WEB_ACL_MONTHLY_PRICE,
                    description=(
                        "Gross recurring AWS WAF Web ACL charge "
                        "exposure. This is not a confirmed savings "
                        "amount."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD/month",
                ),
            ],
            metadata={
                "web_acl_monthly_charge_exposure": (AWS_WAF_WEB_ACL_MONTHLY_PRICE),
            },
        )

    # REQUEST VOLUME

    def _detect_high_request_volume(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        traffic = self._traffic(evidence)

        request_volume = _number(traffic.get("request_volume"))

        if request_volume is None:
            return None

        if not self._telemetry_complete(traffic):
            return None

        threshold = self._threshold(
            context,
            "high_request_threshold",
            DEFAULT_HIGH_REQUESTS,
        )

        if request_volume < threshold:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_high_request_volume",
            severity="medium",
            confidence="high",
            recommendation_eligible=False,
            reason=(
                f"The Web ACL processed {request_volume:,.0f} "
                "confirmed requests during the observation period, "
                f"exceeding the configured review threshold of "
                f"{threshold:,.0f}. This is a request-processing "
                "cost-exposure signal and not a savings estimate."
            ),
            statements=[
                _statement(
                    name="request_volume",
                    value=round(request_volume),
                    description=("Complete observed Web ACL request volume."),
                    source=["CloudWatch"],
                    unit="requests",
                ),
                _statement(
                    name="threshold",
                    value=round(threshold),
                    description=("Configured request-volume review threshold."),
                    source=["Analysis profile"],
                    unit="requests",
                ),
                _statement(
                    name="base_request_price_per_million",
                    value=AWS_WAF_REQUEST_PRICE_PER_MILLION,
                    description=(
                        "Base AWS WAF request charge per million " "requests."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD / million requests",
                ),
            ],
        )

    # WCU

    def _detect_high_wcu(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        traffic = self._traffic(evidence)

        capacity = _number(configuration.get("capacity_wcu"))

        request_volume = _number(traffic.get("request_volume"))

        if capacity is None:
            return None

        if capacity <= AWS_WAF_INCLUDED_WCU:
            return None

        if not self._telemetry_complete(traffic):
            return None

        if request_volume is None or request_volume <= 0:
            return None

        threshold = self._threshold(
            context,
            "wcu_threshold",
            DEFAULT_HIGH_WCU,
        )

        excess_wcu = max(
            0.0,
            capacity - AWS_WAF_INCLUDED_WCU,
        )

        charge_blocks = math.ceil(excess_wcu / AWS_WAF_WCU_BLOCK)

        incremental_price_per_million = charge_blocks * AWS_WAF_WCU_PRICE_PER_MILLION

        estimated_incremental_charge = (
            request_volume / 1_000_000
        ) * incremental_price_per_million

        severity = "medium" if capacity > threshold else "low"

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_high_wcu",
            severity=severity,
            confidence="high",
            recommendation_eligible=False,
            reason=(
                f"The Web ACL requires {capacity:g} WCU, above "
                f"the {AWS_WAF_INCLUDED_WCU:g} WCU included "
                "allocation, and complete request telemetry "
                "confirms traffic. This creates incremental "
                "WCU-based request cost exposure."
            ),
            statements=[
                _statement(
                    name="capacity_wcu",
                    value=capacity,
                    description=("Current Web ACL WCU requirement."),
                    source=["AWS WAF"],
                    unit="WCU",
                ),
                _statement(
                    name="included_wcu",
                    value=AWS_WAF_INCLUDED_WCU,
                    description=(
                        "WCU allocation before additional WCU "
                        "request pricing applies."
                    ),
                    source=["AWS WAF pricing"],
                    unit="WCU",
                ),
                _statement(
                    name="excess_wcu",
                    value=excess_wcu,
                    description=("WCU above the included allocation."),
                    source=["AWS WAF"],
                    unit="WCU",
                ),
                _statement(
                    name="charge_blocks",
                    value=charge_blocks,
                    description=(
                        "500-WCU pricing blocks above the " "included allocation."
                    ),
                    source=["AWS WAF pricing"],
                    unit="blocks",
                ),
                _statement(
                    name="incremental_price_per_million",
                    value=round(
                        incremental_price_per_million,
                        4,
                    ),
                    description=(
                        "Additional WAF request charge per "
                        "million requests caused by the "
                        "current WCU tier."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD / million requests",
                ),
                _statement(
                    name="observed_request_volume",
                    value=round(request_volume),
                    description=(
                        "Complete observed request volume used "
                        "to contextualize WCU exposure."
                    ),
                    source=["CloudWatch"],
                    unit="requests",
                ),
                _statement(
                    name="estimated_incremental_charge",
                    value=round(
                        estimated_incremental_charge,
                        4,
                    ),
                    description=(
                        "Approximate incremental WCU charge "
                        "for the observed request volume."
                    ),
                    source=[
                        "CloudWatch",
                        "AWS WAF pricing",
                    ],
                    unit="USD",
                ),
            ],
            metadata={
                "capacity_wcu": capacity,
                "included_wcu": AWS_WAF_INCLUDED_WCU,
                "excess_wcu": excess_wcu,
                "charge_blocks": charge_blocks,
                "incremental_price_per_million": (incremental_price_per_million),
                "estimated_incremental_charge": (estimated_incremental_charge),
            },
        )

    # CUSTOMER RULE COUNT

    def _detect_high_rule_count(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        customer_rule_count = _number(configuration.get("customer_rule_count"))

        # Do NOT use generic rule_count for pricing unless the collector
        # explicitly declares that it represents customer-created rules.
        if customer_rule_count is None:

            rule_count = _number(configuration.get("rule_count"))

            rule_count_semantics = (
                str(configuration.get("rule_count_semantics") or "").strip().lower()
            )

            if rule_count is not None and rule_count_semantics in {
                "customer_rules",
                "customer_created_rules",
                "billable_customer_rules",
            }:
                customer_rule_count = rule_count

        if customer_rule_count is None:
            return None

        threshold = self._threshold(
            context,
            "max_rule_count",
            DEFAULT_MAX_RULE_COUNT,
        )

        if customer_rule_count <= threshold:
            return None

        monthly_rule_charge = customer_rule_count * AWS_WAF_CUSTOMER_RULE_MONTHLY_PRICE

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_high_rule_count",
            severity="low",
            confidence="high",
            recommendation_eligible=False,
            reason=(
                f"The Web ACL contains {customer_rule_count:g} "
                "customer-created rules, above the configured "
                f"review threshold of {threshold:g}. Each "
                "customer-created rule carries a recurring AWS "
                "WAF rule charge. This finding does not prove "
                "that any specific rule is unnecessary."
            ),
            statements=[
                _statement(
                    name="customer_rule_count",
                    value=int(customer_rule_count),
                    description=(
                        "Customer-created rules in the Web ACL. "
                        "Managed-rule-group internal rules are "
                        "not included."
                    ),
                    source=["AWS WAF"],
                    unit="rules",
                ),
                _statement(
                    name="threshold",
                    value=int(threshold),
                    description=("Configured customer-rule-count " "review threshold."),
                    source=["Analysis profile"],
                    unit="rules",
                ),
                _statement(
                    name="customer_rule_monthly_charge_exposure",
                    value=round(
                        monthly_rule_charge,
                        2,
                    ),
                    description=(
                        "Gross monthly AWS WAF charge associated "
                        "with the customer-created rule count."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD/month",
                ),
            ],
            metadata={
                "customer_rule_count": int(customer_rule_count),
                "customer_rule_monthly_charge_exposure": (monthly_rule_charge),
            },
        )

    # RULE ACTIVITY

    def _detect_rule_no_observed_activity(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        cloudwatch = self._cloudwatch(evidence)

        rules = _list(configuration.get("rules"))

        rule_metrics = cloudwatch.get("rule_metrics")

        if not isinstance(
            rule_metrics,
            dict,
        ):
            return None

        candidates: list[dict[str, Any]] = []

        for rule in rules:

            if not isinstance(
                rule,
                dict,
            ):
                continue

            if rule.get("cloudwatch_metrics_enabled") is not True:
                continue

            rule_name = str(rule.get("name") or "").strip()

            metric_name = str(rule.get("metric_name") or rule_name or "").strip()

            if not metric_name:
                continue

            metric_values = rule_metrics.get(metric_name)

            if not isinstance(
                metric_values,
                list,
            ):
                continue

            observed_values: list[float] = []

            for item in metric_values:

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                if item.get("has_data") is not True:
                    continue

                value = _number(
                    item.get("value")
                    if item.get("value") is not None
                    else item.get("total")
                )

                if value is None:
                    continue

                observed_values.append(value)

            if not observed_values:
                continue

            if not all(value == 0 for value in observed_values):
                continue

            candidates.append(
                {
                    "name": rule_name,
                    "metric_name": metric_name,
                    "statement_type": rule.get("statement_type"),
                    "action": rule.get("action"),
                    "cloudwatch_metrics_enabled": True,
                    "observed_datapoints": len(observed_values),
                }
            )

        if not candidates:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_rule_no_observed_activity",
            severity="low",
            confidence="medium",
            recommendation_eligible=False,
            reason=(
                f"{len(candidates)} WAF rule(s) have explicit "
                "rule-level metric datapoints whose values were "
                "zero throughout the returned observation data. "
                "Rules with disabled, missing, or unavailable "
                "metrics were excluded. Zero observed rule "
                "activity does not by itself prove that a rule "
                "is unnecessary."
            ),
            statements=[
                _statement(
                    name="inactive_rule_candidates",
                    value=candidates,
                    description=(
                        "Rules with explicit zero-valued "
                        "CloudWatch rule-level datapoints."
                    ),
                    source=["CloudWatch rule metrics"],
                )
            ],
        )

    # MANAGED RULE GROUP

    def _detect_managed_rule_group_cost(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        managed_count = _number(configuration.get("managed_rule_group_count"))

        groups = _list(configuration.get("managed_rule_groups"))

        if managed_count is None:

            managed_count = sum(
                1
                for group in groups
                if isinstance(
                    group,
                    dict,
                )
            )

        if managed_count <= 0:
            return None

        names: list[str] = []
        marketplace_groups: list[str] = []
        aws_managed_groups: list[str] = []

        for group in groups:

            if not isinstance(
                group,
                dict,
            ):
                continue

            name = str(group.get("name") or "").strip()

            if name:
                names.append(name)

            source = str(group.get("source") or "").strip().lower()

            if source == "aws_marketplace" or group.get("marketplace") is True:
                if name:
                    marketplace_groups.append(name)

            if source in {
                "aws",
                "aws_managed",
                "aws_managed_rules",
            }:
                if name:
                    aws_managed_groups.append(name)

        monthly_rule_group_charge = managed_count * AWS_WAF_RULE_GROUP_MONTHLY_PRICE

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_managed_rule_group_cost_exposure",
            severity="low",
            confidence="high",
            recommendation_eligible=True,
            reason=(
                f"The Web ACL contains {managed_count:g} managed "
                "rule group(s). Each added managed rule group "
                "creates a recurring AWS WAF rule-group charge. "
                "Marketplace seller pricing is separate and is "
                "not inferred by this analyzer."
            ),
            statements=[
                _statement(
                    name="managed_rule_group_count",
                    value=int(managed_count),
                    description=("Managed rule groups configured " "on the Web ACL."),
                    source=["AWS WAF"],
                    unit="rule groups",
                ),
                _statement(
                    name="managed_rule_groups",
                    value=names,
                    description=("Configured managed rule-group names."),
                    source=["AWS WAF"],
                ),
                _statement(
                    name="base_rule_group_charge_exposure",
                    value=round(
                        monthly_rule_group_charge,
                        2,
                    ),
                    description=(
                        "Gross monthly AWS WAF rule-group "
                        "charge associated with the configured "
                        "managed rule groups."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD/month",
                ),
                _statement(
                    name="aws_managed_groups",
                    value=aws_managed_groups,
                    description=("Managed rule groups identified as " "AWS-provided."),
                    source=["AWS WAF configuration"],
                ),
                _statement(
                    name="marketplace_groups_detected",
                    value=marketplace_groups,
                    description=(
                        "Managed rule groups identified as "
                        "Marketplace groups. Seller pricing "
                        "is deliberately not estimated."
                    ),
                    source=["AWS WAF configuration"],
                ),
            ],
            metadata={
                "managed_rule_group_count": int(managed_count),
                "monthly_rule_group_charge": (monthly_rule_group_charge),
                "marketplace_groups_detected": (marketplace_groups),
            },
        )

    # CAPTCHA

    def _detect_captcha_cost(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        traffic = self._traffic(evidence)

        rule_count = _number(configuration.get("captcha_rule_count"))

        attempts = _number(traffic.get("captcha_attempts"))

        if rule_count is None or rule_count <= 0:
            return None

        if attempts is None or attempts <= 0:
            return None

        if not self._telemetry_complete(
            traffic,
            metric_key="captcha_attempts",
        ):
            return None

        threshold = self._threshold(
            context,
            "captcha_attempt_threshold",
            DEFAULT_MIN_CAPTCHA_REQUESTS,
        )

        if attempts < threshold:
            return None

        estimated_charge = (attempts / 1000.0) * AWS_WAF_CAPTCHA_PRICE_PER_1000

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_captcha_cost_exposure",
            severity="medium",
            confidence="high",
            recommendation_eligible=False,
            reason=(
                f"The Web ACL contains {rule_count:g} CAPTCHA "
                f"rule(s), and complete telemetry confirms "
                f"{attempts:,.0f} CAPTCHA attempts during the "
                "observation period. AWS WAF charges per CAPTCHA "
                "attempt."
            ),
            statements=[
                _statement(
                    name="captcha_rule_count",
                    value=int(rule_count),
                    description=("CAPTCHA rules configured in the Web ACL."),
                    source=["AWS WAF"],
                    unit="rules",
                ),
                _statement(
                    name="captcha_attempts",
                    value=round(attempts),
                    description=("Complete observed CAPTCHA attempts."),
                    source=["CloudWatch"],
                    unit="attempts",
                ),
                _statement(
                    name="price_per_1000_attempts",
                    value=AWS_WAF_CAPTCHA_PRICE_PER_1000,
                    description=("AWS WAF CAPTCHA charge per 1,000 attempts."),
                    source=["AWS WAF pricing"],
                    unit="USD / 1,000 attempts",
                ),
                _statement(
                    name="estimated_period_charge",
                    value=round(
                        estimated_charge,
                        4,
                    ),
                    description=(
                        "Approximate CAPTCHA charge implied "
                        "by the observed attempt count."
                    ),
                    source=[
                        "CloudWatch",
                        "AWS WAF pricing",
                    ],
                    unit="USD",
                ),
            ],
        )

    # CHALLENGE

    def _detect_challenge_cost(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        traffic = self._traffic(evidence)

        rule_count = _number(configuration.get("challenge_rule_count"))

        requests = _number(traffic.get("challenge_requests"))

        if rule_count is None or rule_count <= 0:
            return None

        if requests is None or requests <= 0:
            return None

        if not self._telemetry_complete(
            traffic,
            metric_key="challenge_requests",
        ):
            return None

        threshold = self._threshold(
            context,
            "challenge_request_threshold",
            DEFAULT_MIN_CHALLENGE_REQUESTS,
        )

        if requests < threshold:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_challenge_cost_exposure",
            severity="medium",
            confidence="medium",
            recommendation_eligible=False,
            reason=(
                f"The Web ACL contains {rule_count:g} Challenge "
                f"rule(s), and complete telemetry confirms "
                f"{requests:,.0f} ChallengeRequests during the "
                "observation period. ChallengeRequests are "
                "usage evidence but are not treated as an exact "
                "count of billable Challenge responses."
            ),
            statements=[
                _statement(
                    name="challenge_rule_count",
                    value=int(rule_count),
                    description=("Challenge rules configured in the Web ACL."),
                    source=["AWS WAF"],
                    unit="rules",
                ),
                _statement(
                    name="challenge_requests",
                    value=round(requests),
                    description=(
                        "Observed CloudWatch ChallengeRequests. "
                        "This is not necessarily the exact "
                        "billable Challenge-response count."
                    ),
                    source=["CloudWatch"],
                    unit="requests",
                ),
                _statement(
                    name="estimated_charge",
                    value=None,
                    description=(
                        "No Challenge charge is estimated because "
                        "ChallengeRequests are not treated as the "
                        "exact billable Challenge-response count."
                    ),
                    source=["WAF analyzer semantics"],
                    unit="USD",
                ),
            ],
        )

    # BODY INSPECTION

    def _detect_body_inspection_cost(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        traffic = self._traffic(evidence)

        body = _dict(configuration.get("body_inspection"))

        maximum_kb = _number(body.get("maximum_configured_kb"))

        default_kb = _number(body.get("default_inspection_kb"))

        if default_kb is None:
            default_kb = _number(configuration.get("default_body_inspection_kb"))

        if maximum_kb is None or default_kb is None:
            return None

        if maximum_kb <= default_kb:
            return None

        if not self._telemetry_complete(traffic):
            return None

        request_volume = _number(traffic.get("request_volume"))

        if request_volume is None or request_volume <= 0:
            return None

        additional_kb = maximum_kb - default_kb

        additional_blocks = math.ceil(additional_kb / AWS_WAF_EXTRA_BODY_BLOCK_KB)

        price_per_million = additional_blocks * AWS_WAF_EXTRA_BODY_PRICE_PER_MILLION

        oversized_requests = _number(traffic.get("oversized_body_request_volume"))

        oversized_exact = traffic.get("oversized_body_request_volume_exact") is True

        estimated_period_charge: Optional[float] = None

        if (
            oversized_requests is not None
            and oversized_requests > 0
            and oversized_exact
        ):

            estimated_period_charge = oversized_requests / 1_000_000 * price_per_million

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_body_inspection_cost_exposure",
            severity="medium",
            confidence="high",
            recommendation_eligible=False,
            reason=(
                f"The Web ACL allows request-body inspection up "
                f"to {maximum_kb:g} KiB, above the effective "
                f"default of {default_kb:g} KiB. This creates "
                "potential additional request-analysis cost. "
                "The analyzer does not assume that all requests "
                "use the additional inspection range."
            ),
            statements=[
                _statement(
                    name="maximum_configured_kb",
                    value=maximum_kb,
                    description=("Maximum configured request-body " "inspection size."),
                    source=["AWS WAF"],
                    unit="KiB",
                ),
                _statement(
                    name="default_inspection_kb",
                    value=default_kb,
                    description=(
                        "Effective default body-inspection "
                        "size supplied by collector evidence."
                    ),
                    source=["AWS WAF configuration"],
                    unit="KiB",
                ),
                _statement(
                    name="additional_inspection_kb",
                    value=additional_kb,
                    description=(
                        "Additional body inspection range "
                        "permitted by configuration."
                    ),
                    source=["AWS WAF"],
                    unit="KiB",
                ),
                _statement(
                    name="additional_price_per_million",
                    value=round(
                        price_per_million,
                        4,
                    ),
                    description=(
                        "Potential additional charge per "
                        "million requests if the additional "
                        "inspection range is actually analyzed."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD / million requests",
                ),
                _statement(
                    name="oversized_request_volume",
                    value=oversized_requests,
                    description=(
                        "Observed requests using the additional "
                        "body inspection range when exact "
                        "collector telemetry is available."
                    ),
                    source=["CloudWatch"],
                    unit="requests",
                ),
                _statement(
                    name="oversized_request_volume_exact",
                    value=oversized_exact,
                    description=(
                        "Whether oversized request volume " "is complete and exact."
                    ),
                    source=["WAF collector"],
                    unit="boolean",
                ),
                _statement(
                    name="estimated_period_charge",
                    value=(
                        round(
                            estimated_period_charge,
                            4,
                        )
                        if estimated_period_charge is not None
                        else None
                    ),
                    description=(
                        "Estimated additional body-inspection "
                        "charge only when exact oversized-request "
                        "telemetry is available."
                    ),
                    source=[
                        "CloudWatch",
                        "AWS WAF pricing",
                    ],
                    unit="USD",
                ),
            ],
            metadata={
                "additional_inspection_kb": additional_kb,
                "additional_blocks": additional_blocks,
                "additional_price_per_million": (price_per_million),
                "oversized_request_volume": (oversized_requests),
                "oversized_request_volume_exact": (oversized_exact),
                "estimated_period_charge": (estimated_period_charge),
            },
        )

    # BOT CONTROL

    def _detect_bot_control_cost(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        traffic = self._traffic(evidence)

        premium = {
            str(value).strip().lower()
            for value in _list(configuration.get("premium_features"))
        }

        managed_groups = _list(configuration.get("managed_rule_groups"))

        bot_groups = [
            group
            for group in managed_groups
            if (
                isinstance(
                    group,
                    dict,
                )
                and str(group.get("name") or "").strip()
                == "AWSManagedRulesBotControlRuleSet"
            )
        ]

        if "bot_control" not in premium and not bot_groups:
            return None

        # Determine Bot Control level

        bot_mode = str(configuration.get("bot_control_level") or "").strip().lower()

        if bot_mode not in {
            "common",
            "targeted",
        }:

            for group in bot_groups:

                if not isinstance(
                    group,
                    dict,
                ):
                    continue

                level = (
                    str(
                        group.get("inspection_level")
                        or group.get("bot_control_level")
                        or ""
                    )
                    .strip()
                    .lower()
                )

                if level in {
                    "common",
                    "targeted",
                }:
                    bot_mode = level
                    break

        if bot_mode not in {
            "common",
            "targeted",
        }:
            bot_mode = "unknown"

        # Determine AWS pricing

        free_requests: Optional[float] = None
        request_price: Optional[float] = None

        if bot_mode == "common":

            free_requests = AWS_WAF_COMMON_BOT_FREE_REQUESTS

            request_price = AWS_WAF_COMMON_BOT_PRICE_PER_MILLION

        elif bot_mode == "targeted":

            free_requests = AWS_WAF_TARGETED_BOT_FREE_REQUESTS

            request_price = AWS_WAF_TARGETED_BOT_PRICE_PER_MILLION

        # Exact usage evidence

        bot_requests = _number(traffic.get("bot_control_requests"))

        bot_requests_exact = traffic.get("bot_control_requests_exact") is True

        billable_requests: Optional[float] = None
        estimated_request_charge: Optional[float] = None

        if (
            free_requests is not None
            and request_price is not None
            and bot_requests is not None
            and bot_requests_exact
        ):

            billable_requests = max(
                0.0,
                bot_requests - free_requests,
            )

            estimated_request_charge = billable_requests / 1_000_000 * request_price

        # Severity

        severity = "low"

        if estimated_request_charge is not None and estimated_request_charge >= 100:
            severity = "medium"

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_bot_control_cost_exposure",
            severity=severity,
            confidence="high",
            recommendation_eligible=False,
            reason=(
                "AWS WAF Bot Control is configured on this Web ACL. "
                "Bot Control adds a monthly subscription charge and "
                "request-based charges after the applicable free "
                "request allowance. The request charge is estimated "
                "only when exact Bot Control request telemetry and "
                "the applicable inspection level are available."
            ),
            statements=[
                _statement(
                    name="bot_control_rule_group_count",
                    value=len(bot_groups),
                    description=(
                        "Bot Control managed rule groups " "configured on the Web ACL."
                    ),
                    source=["AWS WAF"],
                    unit="rule groups",
                ),
                _statement(
                    name="bot_control_level",
                    value=bot_mode,
                    description=("Bot Control inspection level."),
                    source=["AWS WAF"],
                ),
                _statement(
                    name="monthly_subscription_price",
                    value=AWS_WAF_BOT_CONTROL_MONTHLY_PRICE,
                    description=(
                        "Bot Control monthly subscription " "charge per Web ACL."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD/month",
                ),
                _statement(
                    name="free_requests",
                    value=free_requests,
                    description=("Applicable free-request allowance."),
                    source=["AWS WAF pricing"],
                    unit="requests/month",
                ),
                _statement(
                    name="request_price_per_million",
                    value=request_price,
                    description=(
                        "Bot Control request price after "
                        "the applicable free allowance."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD / million requests",
                ),
                _statement(
                    name="bot_control_requests",
                    value=bot_requests,
                    description=(
                        "Observed Bot Control request volume "
                        "when supplied by exact telemetry."
                    ),
                    source=["CloudWatch"],
                    unit="requests",
                ),
                _statement(
                    name="bot_control_requests_exact",
                    value=bot_requests_exact,
                    description=(
                        "Whether Bot Control request volume " "is complete and exact."
                    ),
                    source=["WAF collector"],
                    unit="boolean",
                ),
                _statement(
                    name="billable_requests",
                    value=billable_requests,
                    description=(
                        "Requests above the applicable free "
                        "allowance when exact telemetry exists."
                    ),
                    source=[
                        "CloudWatch",
                        "AWS WAF pricing",
                    ],
                    unit="requests",
                ),
                _statement(
                    name="estimated_request_charge",
                    value=(
                        round(
                            estimated_request_charge,
                            4,
                        )
                        if estimated_request_charge is not None
                        else None
                    ),
                    description=(
                        "Approximate Bot Control request charge "
                        "when exact usage and pricing evidence "
                        "are available."
                    ),
                    source=[
                        "CloudWatch",
                        "AWS WAF pricing",
                    ],
                    unit="USD",
                ),
            ],
            metadata={
                "bot_control_level": bot_mode,
                "bot_control_requests": bot_requests,
                "bot_control_requests_exact": (bot_requests_exact),
                "free_requests": free_requests,
                "request_price_per_million": request_price,
                "billable_requests": billable_requests,
                "estimated_request_charge": (estimated_request_charge),
            },
        )

    # FRAUD CONTROL

    def _detect_fraud_control_cost(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(evidence)

        premium = {
            str(value).strip().lower()
            for value in _list(configuration.get("premium_features"))
        }

        fraud_features = sorted(
            premium.intersection(
                {
                    "account_takeover_prevention",
                    "account_creation_fraud_prevention",
                }
            )
        )

        if not fraud_features:
            return None

        # Exact request telemetry may optionally be supplied by collector.
        #
        # We intentionally do not implement a local tier calculation
        # unless the collector provides the exact pricing basis.
        # Fraud Control pricing is tiered and should not be guessed.

        fraud_requests = _number(self._traffic(evidence).get("fraud_control_requests"))

        fraud_requests_exact = (
            self._traffic(evidence).get("fraud_control_requests_exact") is True
        )

        request_charge = _number(configuration.get("fraud_control_request_charge"))

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_fraud_control_cost_exposure",
            severity="medium",
            confidence="high",
            recommendation_eligible=False,
            reason=(
                "The Web ACL uses AWS WAF Fraud Control "
                "functionality. Each enabled Fraud Control "
                "feature introduces a recurring subscription "
                "charge, and Fraud Control request processing "
                "can create substantial additional usage cost. "
                "Request charges are not estimated unless exact "
                "collector-provided pricing evidence is available."
            ),
            statements=[
                _statement(
                    name="fraud_control_features",
                    value=fraud_features,
                    description=("Fraud Control features detected " "in the Web ACL."),
                    source=["AWS WAF"],
                ),
                _statement(
                    name="monthly_subscription_price_per_feature",
                    value=AWS_WAF_FRAUD_CONTROL_MONTHLY_PRICE,
                    description=(
                        "Monthly Fraud Control subscription "
                        "charge per enabled feature/Web ACL."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD/month",
                ),
                _statement(
                    name="subscription_charge_exposure",
                    value=(len(fraud_features) * AWS_WAF_FRAUD_CONTROL_MONTHLY_PRICE),
                    description=(
                        "Gross recurring subscription charge "
                        "associated with the detected Fraud "
                        "Control features."
                    ),
                    source=["AWS WAF pricing"],
                    unit="USD/month",
                ),
                _statement(
                    name="fraud_control_requests",
                    value=fraud_requests,
                    description=(
                        "Fraud Control request volume when "
                        "provided by collector telemetry."
                    ),
                    source=["WAF collector"],
                    unit="requests",
                ),
                _statement(
                    name="fraud_control_requests_exact",
                    value=fraud_requests_exact,
                    description=(
                        "Whether Fraud Control request volume " "is complete and exact."
                    ),
                    source=["WAF collector"],
                    unit="boolean",
                ),
                _statement(
                    name="request_charge",
                    value=request_charge,
                    description=(
                        "Collector-provided exact request charge "
                        "when available. The analyzer does not "
                        "derive Fraud Control tier pricing itself."
                    ),
                    source=["WAF collector"],
                    unit="USD",
                ),
            ],
            metadata={
                "fraud_control_features": fraud_features,
                "subscription_charge_exposure": (
                    len(fraud_features) * AWS_WAF_FRAUD_CONTROL_MONTHLY_PRICE
                ),
                "fraud_control_requests": fraud_requests,
                "fraud_control_requests_exact": (fraud_requests_exact),
                "request_charge": request_charge,
            },
        )

    # THRESHOLD RESOLUTION

    @staticmethod
    def _threshold(
        context: AnalysisContext,
        name: str,
        default: float,
    ) -> float:

        candidates = (
            context.resource.get("analyzer_config"),
            context.resource.get("analysis_profile"),
            context.resource.get("optimization_profile"),
        )

        for candidate in candidates:

            if not isinstance(
                candidate,
                dict,
            ):
                continue

            direct = _number(candidate.get(name))

            if direct is not None and direct >= 0:
                return direct

            waf = candidate.get("waf")

            if isinstance(
                waf,
                dict,
            ):

                nested = _number(waf.get(name))

                if nested is not None and nested >= 0:
                    return nested

        return default

    # FINDING BUILDER

    def _finding(
        self,
        *,
        context: AnalysisContext,
        evidence: dict[str, Any],
        finding_type: str,
        severity: str,
        confidence: str,
        reason: str,
        statements: list[EvidenceStatement],
        recommendation_eligible: bool = False,
        cost_optimization_type: str = "review",
        metadata: Optional[dict[str, Any]] = None,
    ) -> Finding:

        return Finding(
            finding_type=finding_type,
            title=TITLES.get(
                finding_type,
                finding_type,
            ),
            resource_type=(context.resource_type or "waf_web_acl"),
            resource_id=(context.resource_id or "unknown"),
            analyzer=self.name,
            analyzer_version=self.version,
            severity=str(severity).lower(),
            confidence=str(confidence).lower(),
            reason=reason,
            conditions=statements,
            evidence=self._build_evidence(
                context,
                evidence,
            ),
            observation_period=(self._observation_period(context)),
            metadata={
                "region": context.region,
                "recommendation_eligible": (recommendation_eligible),
                **(
                    metadata
                    if isinstance(
                        metadata,
                        dict,
                    )
                    else {}
                ),
            },
            recommendation_eligible=(recommendation_eligible),
            cost_optimization_type=(cost_optimization_type),
            impact={},
        )

    # OBSERVATION PERIOD

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        try:

            cloudwatch = _dict(context.cloudwatch())

        except Exception:

            cloudwatch = {}

        start = cloudwatch.get("start") or cloudwatch.get("metric_start")

        end = cloudwatch.get("end") or cloudwatch.get("metric_end")

        if start or end:

            return ObservationPeriod(
                start=start,
                end=end,
            )

        value = context.observation_period

        if isinstance(
            value,
            dict,
        ):

            return ObservationPeriod(
                start=value.get("start"),
                end=value.get("end"),
                duration_seconds=value.get("duration_seconds"),
            )

        return None

    # EVIDENCE BUILDER

    def _build_evidence(
        self,
        context: AnalysisContext,
        optimization_evidence: dict[str, Any],
    ) -> Evidence:

        try:

            source = context.metrics()

        except Exception:

            source = {}

        metrics: dict[str, Any] = {}

        if isinstance(
            source,
            dict,
        ):

            names = source.keys()

        elif isinstance(
            source,
            list,
        ):

            names = source

        else:

            names = []

        for name in names:

            try:

                metrics[str(name)] = context.metric_summary(name)

            except Exception:

                metrics[str(name)] = None

        return Evidence(
            metrics=metrics,
            configuration=_dict(optimization_evidence.get("configuration")),
            topology={},
            resource=_dict(optimization_evidence.get("resource")),
            derived={
                "traffic": self._traffic(optimization_evidence),
                "cloudwatch": self._cloudwatch(optimization_evidence),
            },
            billing=_dict(context.billing()),
            data_quality=self._quality(optimization_evidence),
        )
