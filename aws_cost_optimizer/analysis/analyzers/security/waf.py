"""
AWS WAF cost optimization analyzer.

Cost-oriented findings:

    waf_unused_web_acl
    waf_high_request_volume
    waf_many_rules
    waf_high_wcu
    waf_managed_rule_groups
    waf_captcha_activity
    waf_challenge_activity
    waf_large_body_inspection

Important:

The analyzer does NOT recommend weakening security simply because
a rule has low match volume.

A WAF finding represents a cost/configuration review opportunity.
The final action must be validated against security requirements.

No resource-level savings are invented unless the billing context
explicitly provides an amount attributable to the Web ACL.
"""

from __future__ import annotations

from typing import Any, Optional

from ...base import Analyzer
from ...condition import EvidenceStatement
from ...context import AnalysisContext
from ...evidence import Evidence
from ...finding import (
    Finding,
    ObservationPeriod,
)
from ...registry import register


DEFAULT_MIN_REQUESTS = 10_000_000
DEFAULT_MAX_RULES = 20
DEFAULT_WCU_THRESHOLD = 1500
DEFAULT_MIN_MANAGED_GROUPS = 3
DEFAULT_MIN_CAPTCHA_REQUESTS = 1000
DEFAULT_MIN_CHALLENGE_REQUESTS = 1000
DEFAULT_BODY_INSPECTION_BYTES = 16 * 1024


TITLES = {
    "waf_unused_web_acl":
        "Review unused WAF Web ACL",

    "waf_high_request_volume":
        "Review high WAF request volume",

    "waf_many_rules":
        "Review WAF rule configuration",

    "waf_high_wcu":
        "Review high WAF capacity usage",

    "waf_managed_rule_groups":
        "Review WAF managed rule groups",

    "waf_captcha_activity":
        "Review WAF CAPTCHA activity",

    "waf_challenge_activity":
        "Review WAF Challenge activity",

    "waf_large_body_inspection":
        "Review WAF body inspection configuration",
}


LIMITATIONS = {
    "waf_unused_web_acl": [
        "No observed requests during the analysis period does not "
        "prove that the Web ACL is permanently unused.",
        "Validate scheduled, seasonal and failover traffic.",
        "Validate security requirements before removing protection.",
    ],

    "waf_high_request_volume": [
        "High request volume is a cost exposure indicator, not "
        "proof that traffic is unnecessary.",
        "Requests may be business-critical or security-related.",
        "The analyzer does not estimate savings from blocking traffic.",
    ],

    "waf_many_rules": [
        "Rule count alone does not prove that a rule should be removed.",
        "Security coverage and managed-rule requirements must be reviewed.",
        "Rule-level traffic metrics are not currently persisted because "
        "the metric database identity does not include dimensions.",
    ],

    "waf_high_wcu": [
        "High WCU indicates configuration complexity and possible "
        "additional request charges above the included allocation.",
        "Reducing WCU must not weaken required protections.",
    ],

    "waf_managed_rule_groups": [
        "Managed rule groups can provide important security coverage.",
        "Do not remove a managed rule group solely because it has "
        "low observed matches.",
        "Review actual coverage and subscription requirements.",
    ],

    "waf_captcha_activity": [
        "CAPTCHA can be intentionally used for security controls.",
        "The finding does not recommend removing CAPTCHA automatically.",
        "Validate the matching population and security intent.",
    ],

    "waf_challenge_activity": [
        "Challenge actions can be intentionally used for security controls.",
        "The finding does not recommend removing Challenge automatically.",
        "Validate traffic and security intent.",
    ],

    "waf_large_body_inspection": [
        "Large request-body inspection can be security-sensitive.",
        "Do not reduce inspection limits without confirming application "
        "and security requirements.",
    ],
}


def _dict(
    value: Any,
) -> dict[str, Any]:

    return (
        value
        if isinstance(value, dict)
        else {}
    )


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


@register
class WAFAnalyzer(Analyzer):

    name = "waf"
    version = "1.0"

    SUPPORTED_RESOURCE_TYPES = {
        "waf_web_acl",
    }

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            in self.SUPPORTED_RESOURCE_TYPES
        )

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        evidence = _dict(
            context.optimization_evidence()
        )

        if not evidence:
            return []

        if not self._usable(
            evidence
        ):
            return []

        findings: list[Finding] = []

        detectors = (
            self._detect_unused,
            self._detect_high_requests,
            self._detect_many_rules,
            self._detect_high_wcu,
            self._detect_managed_rule_groups,
            self._detect_captcha,
            self._detect_challenge,
            self._detect_large_body_inspection,
        )

        for detector in detectors:

            finding = detector(
                context,
                evidence,
            )

            if finding:
                findings.append(
                    finding
                )

        return findings

    # ---------------------------------------------------------------
    # Evidence access
    # ---------------------------------------------------------------

    @staticmethod
    def _resource(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "resource"
            )
        )

    @staticmethod
    def _configuration(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "configuration"
            )
        )

    @staticmethod
    def _relationships(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "relationships"
            )
        )

    @staticmethod
    def _requests(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "requests"
            )
        )

    @staticmethod
    def _derived(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "derived"
            )
        )

    @staticmethod
    def _quality(
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(
            evidence.get(
                "data_quality"
            )
        )

    def _usable(
        self,
        evidence: dict[str, Any],
    ) -> bool:

        configuration = self._configuration(
            evidence
        )

        return bool(
            configuration
        )

    # ---------------------------------------------------------------
    # Detection 1
    # ---------------------------------------------------------------

    def _detect_unused(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        relationships = self._relationships(
            evidence
        )

        derived = self._derived(
            evidence
        )

        traffic = _dict(
            derived.get(
                "traffic"
            )
        )

        protected_count = _number(
            relationships.get(
                "protected_resource_count"
            )
        )

        request_count = _number(
            traffic.get(
                "total_core_requests"
            )
        )

        if (
            protected_count is None
            or protected_count > 0
        ):
            return None

        if (
            request_count is not None
            and request_count > 0
        ):
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_unused_web_acl",
            severity="medium",
            confidence="medium",
            reason=(
                "The Web ACL has no discovered protected resource "
                "association and no observed WAF requests during "
                "the analysis period."
            ),
            statements=[
                _statement(
                    name="protected_resource_count",
                    value=protected_count,
                    description=(
                        "Resources associated with the Web ACL."
                    ),
                    source=["AWS WAF"],
                ),
                _statement(
                    name="total_core_requests",
                    value=request_count,
                    description=(
                        "Observed WAF request activity."
                    ),
                    source=["CloudWatch"],
                    unit="requests",
                ),
            ],
            limitations=LIMITATIONS[
                "waf_unused_web_acl"
            ],
        )

    # ---------------------------------------------------------------
    # Detection 2
    # ---------------------------------------------------------------

    def _detect_high_requests(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        threshold = self._threshold(
            context,
            "high_request_threshold",
            DEFAULT_MIN_REQUESTS,
        )

        traffic = _dict(
            self._derived(
                evidence
            ).get(
                "traffic"
            )
        )

        requests = _number(
            traffic.get(
                "total_core_requests"
            )
        )

        if requests is None:
            return None

        if requests < threshold:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_high_request_volume",
            severity="medium",
            confidence="medium",
            reason=(
                f"The Web ACL processed approximately "
                f"{requests:,.0f} observed requests during the "
                f"analysis period, exceeding the configured "
                f"threshold of {threshold:,.0f}."
            ),
            statements=[
                _statement(
                    name="total_core_requests",
                    value=round(
                        requests
                    ),
                    description=(
                        "Observed Web ACL request volume."
                    ),
                    source=["CloudWatch"],
                    unit="requests",
                ),
                _statement(
                    name="threshold",
                    value=round(
                        threshold
                    ),
                    description=(
                        "Configured request-volume threshold."
                    ),
                    source=["Analysis profile"],
                    unit="requests",
                ),
            ],
            limitations=LIMITATIONS[
                "waf_high_request_volume"
            ],
        )

    # ---------------------------------------------------------------
    # Detection 3
    # ---------------------------------------------------------------

    def _detect_many_rules(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        rule_summary = _dict(
            self._configuration(
                evidence
            ).get(
                "rule_summary"
            )
        )

        rule_count = _number(
            rule_summary.get(
                "rule_count"
            )
        )

        threshold = self._threshold(
            context,
            "max_rule_count",
            DEFAULT_MAX_RULES,
        )

        if (
            rule_count is None
            or rule_count <= threshold
        ):
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_many_rules",
            severity="low",
            confidence="medium",
            reason=(
                f"The Web ACL contains {rule_count:g} rules, "
                f"above the configured review threshold of "
                f"{threshold:g}."
            ),
            statements=[
                _statement(
                    name="rule_count",
                    value=rule_count,
                    description=(
                        "Rules configured in the Web ACL."
                    ),
                    source=["AWS WAF"],
                    unit="rules",
                ),
                _statement(
                    name="custom_rule_count",
                    value=rule_summary.get(
                        "custom_rule_count"
                    ),
                    description=(
                        "Custom rules configured in the Web ACL."
                    ),
                    source=["AWS WAF"],
                    unit="rules",
                ),
            ],
            limitations=LIMITATIONS[
                "waf_many_rules"
            ],
        )

    # ---------------------------------------------------------------
    # Detection 4
    # ---------------------------------------------------------------

    def _detect_high_wcu(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(
            evidence
        )

        capacity = _number(
            configuration.get(
                "capacity_wcu"
            )
        )

        threshold = self._threshold(
            context,
            "wcu_threshold",
            DEFAULT_WCU_THRESHOLD,
        )

        if (
            capacity is None
            or capacity <= threshold
        ):
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_high_wcu",
            severity="medium",
            confidence="high",
            reason=(
                f"The Web ACL uses approximately "
                f"{capacity:g} WCU, exceeding the default "
                f"included allocation threshold of "
                f"{threshold:g} WCU."
            ),
            statements=[
                _statement(
                    name="capacity_wcu",
                    value=capacity,
                    description=(
                        "Web ACL capacity requirement."
                    ),
                    source=["AWS WAF"],
                    unit="WCU",
                ),
                _statement(
                    name="wcu_threshold",
                    value=threshold,
                    description=(
                        "Configured WCU threshold."
                    ),
                    source=["Analysis profile"],
                    unit="WCU",
                ),
            ],
            limitations=LIMITATIONS[
                "waf_high_wcu"
            ],
        )

    # ---------------------------------------------------------------
    # Detection 5
    # ---------------------------------------------------------------

    def _detect_managed_rule_groups(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        rule_summary = _dict(
            self._configuration(
                evidence
            ).get(
                "rule_summary"
            )
        )

        count = _number(
            rule_summary.get(
                "managed_rule_group_count"
            )
        )

        threshold = self._threshold(
            context,
            "managed_rule_group_threshold",
            DEFAULT_MIN_MANAGED_GROUPS,
        )

        if (
            count is None
            or count < threshold
        ):
            return None

        names = (
            rule_summary.get(
                "managed_rule_group_names",
                [],
            )
        )

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_managed_rule_groups",
            severity="low",
            confidence="medium",
            reason=(
                f"The Web ACL contains {count:g} managed rule "
                f"groups. Review whether each group remains "
                f"required for the protected workload."
            ),
            statements=[
                _statement(
                    name="managed_rule_group_count",
                    value=count,
                    description=(
                        "Managed rule groups attached to the Web ACL."
                    ),
                    source=["AWS WAF"],
                    unit="rule groups",
                ),
                _statement(
                    name="managed_rule_groups",
                    value=names,
                    description=(
                        "Managed rule group names."
                    ),
                    source=["AWS WAF"],
                ),
            ],
            limitations=LIMITATIONS[
                "waf_managed_rule_groups"
            ],
        )

    # ---------------------------------------------------------------
    # Detection 6
    # ---------------------------------------------------------------

    def _detect_captcha(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        threshold = self._threshold(
            context,
            "captcha_request_threshold",
            DEFAULT_MIN_CAPTCHA_REQUESTS,
        )

        captcha_rules = _number(
            _dict(
                self._configuration(
                    evidence
                ).get(
                    "rule_summary"
                )
            ).get(
                "captcha_rule_count"
            )
        )

        requests = _number(
            _dict(
                self._requests(
                    evidence
                ).get(
                    "CaptchaRequests"
                )
            ).get(
                "total"
            )
        )

        if not captcha_rules:
            return None

        if (
            requests is None
            or requests < threshold
        ):
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_captcha_activity",
            severity="medium",
            confidence="medium",
            reason=(
                f"The Web ACL has {captcha_rules:g} CAPTCHA "
                f"rule(s) and observed approximately "
                f"{requests:,.0f} CAPTCHA requests during the "
                f"analysis period."
            ),
            statements=[
                _statement(
                    name="captcha_rule_count",
                    value=captcha_rules,
                    description=(
                        "CAPTCHA rules configured in the Web ACL."
                    ),
                    source=["AWS WAF"],
                    unit="rules",
                ),
                _statement(
                    name="captcha_requests",
                    value=round(
                        requests
                    ),
                    description=(
                        "Requests that matched CAPTCHA controls."
                    ),
                    source=["CloudWatch"],
                    unit="requests",
                ),
            ],
            limitations=LIMITATIONS[
                "waf_captcha_activity"
            ],
        )

    # ---------------------------------------------------------------
    # Detection 7
    # ---------------------------------------------------------------

    def _detect_challenge(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        threshold = self._threshold(
            context,
            "challenge_request_threshold",
            DEFAULT_MIN_CHALLENGE_REQUESTS,
        )

        challenge_rules = _number(
            _dict(
                self._configuration(
                    evidence
                ).get(
                    "rule_summary"
                )
            ).get(
                "challenge_rule_count"
            )
        )

        requests = _number(
            _dict(
                self._requests(
                    evidence
                ).get(
                    "ChallengeRequests"
                )
            ).get(
                "total"
            )
        )

        if not challenge_rules:
            return None

        if (
            requests is None
            or requests < threshold
        ):
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_challenge_activity",
            severity="medium",
            confidence="medium",
            reason=(
                f"The Web ACL has {challenge_rules:g} "
                f"Challenge rule(s) and observed approximately "
                f"{requests:,.0f} Challenge requests during the "
                f"analysis period."
            ),
            statements=[
                _statement(
                    name="challenge_rule_count",
                    value=challenge_rules,
                    description=(
                        "Challenge rules configured in the Web ACL."
                    ),
                    source=["AWS WAF"],
                    unit="rules",
                ),
                _statement(
                    name="challenge_requests",
                    value=round(
                        requests
                    ),
                    description=(
                        "Requests that matched Challenge controls."
                    ),
                    source=["CloudWatch"],
                    unit="requests",
                ),
            ],
            limitations=LIMITATIONS[
                "waf_challenge_activity"
            ],
        )

    # ---------------------------------------------------------------
    # Detection 8
    # ---------------------------------------------------------------

    def _detect_large_body_inspection(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Optional[Finding]:

        configuration = self._configuration(
            evidence
        )

        association_config = _dict(
            configuration.get(
                "association_config"
            )
        )

        if not association_config:
            return None

        body_size = self._find_body_size(
            association_config
        )

        if body_size is None:
            return None

        if body_size <= DEFAULT_BODY_INSPECTION_BYTES:
            return None

        return self._finding(
            context=context,
            evidence=evidence,
            finding_type="waf_large_body_inspection",
            severity="low",
            confidence="high",
            reason=(
                f"The Web ACL association configuration "
                f"allows inspection of request bodies larger "
                f"than the default 16 KiB baseline "
                f"({body_size:,} bytes)."
            ),
            statements=[
                _statement(
                    name="body_inspection_bytes",
                    value=body_size,
                    description=(
                        "Configured maximum request-body inspection "
                        "size."
                    ),
                    source=["AWS WAF"],
                    unit="bytes",
                ),
            ],
            limitations=LIMITATIONS[
                "waf_large_body_inspection"
            ],
        )

    # ---------------------------------------------------------------
    # Utilities
    # ---------------------------------------------------------------

    @staticmethod
    def _find_body_size(
        association_config: dict[str, Any],
    ) -> Optional[float]:

        request_body = _dict(
            association_config.get(
                "RequestBody"
            )
        )

        # AWS structures this by protected resource type.
        for value in request_body.values():

            if not isinstance(
                value,
                dict,
            ):
                continue

            candidate = (
                value.get(
                    "OversizeHandling"
                )
            )

            # OversizeHandling is qualitative rather than a byte
            # value. The actual configured size is not represented
            # reliably enough across integrations to fabricate one.
            #
            # Keep this detector disabled when an actual numeric
            # configured size is unavailable.
            if isinstance(
                candidate,
                (int, float),
            ):
                return float(candidate)

            size = (
                value.get(
                    "MaxBodySize"
                )
                or value.get(
                    "BodySize"
                )
            )

            number = _number(
                size
            )

            if number is not None:
                return number

        return None

    @staticmethod
    def _threshold(
        context: AnalysisContext,
        name: str,
        default: float,
    ) -> float:

        candidates = (
            context.resource.get(
                "analysis_profile"
            ),
            context.resource.get(
                "optimization_profile"
            ),
        )

        for candidate in candidates:

            if not isinstance(
                candidate,
                dict,
            ):
                continue

            number = _number(
                candidate.get(
                    name
                )
            )

            if (
                number is not None
                and number >= 0
            ):
                return number

        return default

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
        limitations: list[str],
    ) -> Finding:

        return Finding(
            finding_type=finding_type,

            title=TITLES.get(
                finding_type,
                finding_type,
            ),

            resource_type=(
                context.resource_type
                or "waf_web_acl"
            ),

            resource_id=(
                context.resource_id
                or "unknown"
            ),

            analyzer=self.name,
            analyzer_version=self.version,

            severity=str(
                severity
            ).lower(),

            confidence=str(
                confidence
            ).lower(),

            reason=reason,

            conditions=statements,

            evidence=self._build_evidence(
                context,
                evidence,
            ),

            observation_period=(
                self._observation_period(
                    context
                )
            ),

            limitations=list(
                limitations
            ),

            metadata={
                "region":
                    context.region,
            },

            recommendation_eligible=True,

            impact={},
        )

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        cloudwatch = _dict(
            context.cloudwatch()
        )

        start = (
            cloudwatch.get(
                "start"
            )
            or cloudwatch.get(
                "metric_start"
            )
        )

        end = (
            cloudwatch.get(
                "end"
            )
            or cloudwatch.get(
                "metric_end"
            )
        )

        if start or end:

            return ObservationPeriod(
                start=start,
                end=end,
            )

        return None

    def _build_evidence(
        self,
        context: AnalysisContext,
        optimization_evidence: dict[str, Any],
    ) -> Evidence:

        metrics = {
            name:
                context.metric_summary(
                    name
                )
            for name in context.metrics()
        }

        return Evidence(
            metrics=metrics,

            configuration=_dict(
                self._configuration(
                    optimization_evidence
                )
            ),

            topology={},

            resource=_dict(
                optimization_evidence.get(
                    "resource"
                )
            ),

            derived={
                "requests":
                    self._requests(
                        optimization_evidence
                    ),

                "derived":
                    self._derived(
                        optimization_evidence
                    ),
            },

            billing=_dict(
                context.billing()
            ),

            data_quality=self._quality(
                optimization_evidence
            ),
        )