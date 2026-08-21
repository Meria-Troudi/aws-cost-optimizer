"""
Elastic Load Balancer cost optimization analyzer.

The collector supplies evidence.

This analyzer only evaluates rules.

Rules
-----
1. No observed activity.
2. Low observed traffic.
3. No registered targets.
4. Idle target group.
5. No healthy targets + no traffic.

Important
--------
- Missing CloudWatch data is never zero.
- Unhealthy targets alone are never an optimization finding.
- Incomplete target-health data never becomes zero targets.
- No savings are invented.
- Findings are review recommendations, not deletion commands.
"""

from __future__ import annotations

from typing import Any

from ...base import Analyzer
from ...condition import EvidenceStatement
from ...context import AnalysisContext
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
from ...metrics import (
    metric_has_observed_data,
    metric_summary,
)
from ...registry import register


# ======================================================================
# DEFAULT POLICY
# ======================================================================

DEFAULT_POLICY = {
    "activity": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
    },

    "low_traffic": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "request_count_max": 100.0,
        "processed_gib_max": 1.0,
    },

    "target_groups": {
        "enabled": True,
        "minimum_health_completeness": True,
    },

    "healthy_targets": {
        "enabled": True,
        "minimum_health_completeness": True,
    },
}


ELB_CONFIGURATION_FIELDS = (
    "load_balancer_arn",
    "load_balancer_name",
    "type",
    "scheme",
    "state",
    "state_reason",
    "created_time",
    "vpc_id",
    "dns_name",
    "canonical_hosted_zone_id",
    "ip_address_type",
    "availability_zones",
    "availability_zone_count",
    "subnet_ids",
    "subnet_count",
    "security_groups",
    "security_group_count",
    "service_managed",
    "optimization_allowed",
    "release_allowed",
)


TRAFFIC_METRICS = (
    "request_count",
    "processed_bytes",
)

CONNECTION_METRICS = (
    "active_connections",
    "new_connections",
)


@register
class ElbAnalyzer(Analyzer):

    name = "elb"
    version = "3.0"

    SUPPORTED_RESOURCE_TYPES = {
        "load_balancer",
        "elb",
    }

    DEFAULT_RESOURCE_TYPE = (
        "load_balancer"
    )

    # ==================================================================
    # SUPPORT
    # ==================================================================

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return (
            context.resource_type
            in self.SUPPORTED_RESOURCE_TYPES
        )

    # ==================================================================
    # ANALYZE
    # ==================================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(
            context
        ):
            return []

        if not self._eligible(
            context
        ):
            return []

        findings: list[Finding] = []

        checks = (
            self._check_no_observed_activity,
            self._check_low_traffic,
            self._check_no_registered_targets,
            self._check_idle_target_groups,
            self._check_no_healthy_targets_no_traffic,
            self._check_idle_with_cost,
        )

        for check in checks:

            finding = check(
                context
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    # ==================================================================
    # POLICY
    # ==================================================================

    @classmethod
    def _policy(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        policy = {
            key: (
                value.copy()
                if isinstance(
                    value,
                    dict,
                )
                else value
            )
            for key, value
            in DEFAULT_POLICY.items()
        }

        for root_name in (
            "analyzer_config",
            "analysis_config",
            "config",
        ):

            root = context.resource.get(
                root_name
            )

            if not isinstance(
                root,
                dict,
            ):
                continue

            configured = root.get(
                "elb"
            )

            if not isinstance(
                configured,
                dict,
            ):
                continue

            for category, values in (
                configured.items()
            ):

                if isinstance(
                    values,
                    dict,
                ):

                    default = policy.get(
                        category,
                        {},
                    )

                    if not isinstance(
                        default,
                        dict,
                    ):
                        default = {}

                    policy[
                        category
                    ] = {
                        **default,
                        **values,
                    }

                else:

                    policy[
                        category
                    ] = values

            break

        return policy

    # ==================================================================
    # ELIGIBILITY
    # ==================================================================

    @staticmethod
    def _configuration(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = (
            context.configuration()
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @classmethod
    def _eligible(
        cls,
        context: AnalysisContext,
    ) -> bool:

        configuration = (
            cls._configuration(
                context
            )
        )

        allowed = configuration.get(
            "optimization_allowed"
        )

        if allowed is False:
            return False

        state = str(
            configuration.get(
                "state"
            )
            or ""
        ).strip().lower()

        if state and state != "active":
            return False

        return True

    # ==================================================================
    # METRIC HELPERS
    # ==================================================================

    @staticmethod
    def _metric(
        context: AnalysisContext,
        name: str,
    ) -> dict[str, Any]:

        try:
            value = (
                context.metric_summary(
                    name
                )
            )
        except Exception:
            return {}

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @classmethod
    def _metric_ready(
        cls,
        context: AnalysisContext,
        name: str,
        minimum_coverage: float,
    ) -> bool:

        metric = cls._metric(
            context,
            name,
        )

        if not metric_has_observed_data(
            metric
        ):
            return False

        coverage = metric.get(
            "coverage_ratio"
        )

        if not isinstance(
            coverage,
            (int, float),
        ):
            return False

        return (
            float(coverage)
            >= minimum_coverage
        )

    @classmethod
    def _all_metrics_ready(
        cls,
        context: AnalysisContext,
        names: tuple[str, ...],
        minimum_coverage: float,
    ) -> bool:

        return all(
            cls._metric_ready(
                context,
                name,
                minimum_coverage,
            )
            for name in names
        )

    @classmethod
    def _any_metrics_ready(
        cls,
        context: AnalysisContext,
        names: tuple[str, ...],
        minimum_coverage: float,
    ) -> bool:

        return any(
            cls._metric_ready(
                context,
                name,
                minimum_coverage,
            )
            for name in names
        )

    @classmethod
    def _metric_value(
        cls,
        context: AnalysisContext,
        name: str,
    ) -> float | None:

        metric = cls._metric(
            context,
            name,
        )

        if not metric_has_observed_data(
            metric
        ):
            return None

        value = metric.get(
            "value"
        )

        if isinstance(
            value,
            (int, float),
        ):
            return float(value)

        return None

    # ==================================================================
    # TRAFFIC EVIDENCE
    # ==================================================================

    @classmethod
    def _traffic_state(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        policy = (
            cls._policy(
                context
            )
        )

        activity_policy = (
            policy.get(
                "activity",
                {},
            )
        )

        minimum_coverage = float(
            activity_policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        request_ready = (
            cls._metric_ready(
                context,
                "request_count",
                minimum_coverage,
            )
        )

        bytes_ready = (
            cls._metric_ready(
                context,
                "processed_bytes",
                minimum_coverage,
            )
        )

        active_ready = (
            cls._metric_ready(
                context,
                "active_connections",
                minimum_coverage,
            )
        )

        new_ready = (
            cls._metric_ready(
                context,
                "new_connections",
                minimum_coverage,
            )
        )

        request_count = (
            cls._metric_value(
                context,
                "request_count",
            )
            if request_ready
            else None
        )

        processed_bytes = (
            cls._metric_value(
                context,
                "processed_bytes",
            )
            if bytes_ready
            else None
        )

        active_connections = (
            cls._metric_value(
                context,
                "active_connections",
            )
            if active_ready
            else None
        )

        new_connections = (
            cls._metric_value(
                context,
                "new_connections",
            )
            if new_ready
            else None
        )

        active_flow_ready = (
            cls._metric_ready(
                context,
                "active_flow_count",
                minimum_coverage,
            )
        )

        new_flow_ready = (
            cls._metric_ready(
                context,
                "new_flow_count",
                minimum_coverage,
            )
        )

        active_flows = (
            cls._metric_value(
                context,
                "active_flow_count",
            )
            if active_flow_ready
            else None
        )

        new_flows = (
            cls._metric_value(
                context,
                "new_flow_count",
            )
            if new_flow_ready
            else None
        )

        lb_type = str(
            cls._configuration(
                context
            ).get("type")
            or ""
        ).strip().lower()

        # Different ELB families expose different primary traffic
        # metrics (AWS/ApplicationELB has RequestCount; AWS/NetworkELB
        # and AWS/GatewayELB do not). Requiring RequestCount
        # universally makes NLB/GWLB traffic evidence permanently
        # unreadable. Branch the readiness/observed requirement by
        # LB type instead, and always accept ProcessedBytes as
        # evidence since every family publishes it.
        primary_values: list[float] = []

        if processed_bytes is not None:
            primary_values.append(
                processed_bytes
            )

        if lb_type == "application":

            if request_count is not None:
                primary_values.append(
                    request_count
                )

        elif lb_type == "network":

            if active_flows is not None:
                primary_values.append(
                    active_flows
                )

            if new_flows is not None:
                primary_values.append(
                    new_flows
                )

            if active_connections is not None:
                primary_values.append(
                    active_connections
                )

            if new_connections is not None:
                primary_values.append(
                    new_connections
                )

        elif lb_type == "gateway":

            if active_flows is not None:
                primary_values.append(
                    active_flows
                )

            if new_flows is not None:
                primary_values.append(
                    new_flows
                )

        else:

            # Unknown/unclassified LB type: fall back to the
            # original ALB-oriented requirement rather than
            # guessing at a family-specific metric set.
            if (
                request_count is not None
                and processed_bytes is not None
            ):
                primary_values.append(
                    request_count
                )

        if not primary_values:

            return {
                "ready":
                    False,

                "observed":
                    None,

                "request_count":
                    request_count,

                "processed_bytes":
                    processed_bytes,

                "processed_gib":
                    (
                        processed_bytes
                        / (1024 ** 3)
                        if processed_bytes is not None
                        else None
                    ),

                "active_connections":
                    active_connections,

                "new_connections":
                    new_connections,

                "active_flows":
                    active_flows,

                "new_flows":
                    new_flows,

                "lb_type":
                    lb_type,
            }

        traffic_positive = any(
            value > 0
            for value in primary_values
        )

        return {
            "ready":
                True,

            "observed":
                traffic_positive,

            "request_count":
                request_count,

            "processed_bytes":
                processed_bytes,

            "processed_gib":
                (
                    processed_bytes
                    / (1024 ** 3)
                    if processed_bytes is not None
                    else None
                ),

            "active_connections":
                active_connections,

            "new_connections":
                new_connections,

            "active_flows":
                active_flows,

            "new_flows":
                new_flows,

            "lb_type":
                lb_type,
        }

    # ==================================================================
    # RELATIONSHIPS
    # ==================================================================

    @staticmethod
    def _relationships(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = (
            context.resource.get(
                "relationships",
                {},
            )
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @classmethod
    def _summary(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        summary = (
            cls._relationships(
                context
            ).get(
                "summary",
                {},
            )
        )

        return (
            summary
            if isinstance(
                summary,
                dict,
            )
            else {}
        )

    @classmethod
    def _target_groups(
        cls,
        context: AnalysisContext,
    ) -> list[dict[str, Any]]:

        groups = (
            cls._relationships(
                context
            ).get(
                "target_groups",
                [],
            )
        )

        if not isinstance(
            groups,
            list,
        ):
            return []

        return [
            group
            for group in groups
            if isinstance(
                group,
                dict,
            )
        ]

    # ==================================================================
    # RULE 1 — NO OBSERVED ACTIVITY
    # ==================================================================

    def _check_no_observed_activity(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = (
            self._policy(
                context
            ).get(
                "activity",
                {},
            )
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        traffic = (
            self._traffic_state(
                context
            )
        )

        if not traffic.get(
            "ready"
        ):
            return None

        if traffic.get(
            "observed"
        ) is not False:
            return None

        active_connections = (
            traffic.get(
                "active_connections"
            )
        )

        new_connections = (
            traffic.get(
                "new_connections"
            )
        )

        # If connection metrics were available and positive,
        # do not classify the resource as inactive.
        if (
            isinstance(
                active_connections,
                (int, float),
            )
            and active_connections > 0
        ):
            return None

        if (
            isinstance(
                new_connections,
                (int, float),
            )
            and new_connections > 0
        ):
            return None

        statements = [
            self._statement(
                name="traffic_observed",
                value=False,
                description=(
                    "No request or processed-byte "
                    "activity was observed during "
                    "the analysis period."
                ),
                source=[
                    "CloudWatch.RequestCount",
                    "CloudWatch.ProcessedBytes",
                ],
                observed=True,
            ),
        ]

        if active_connections is not None:

            statements.append(
                self._statement(
                    name="active_connections",
                    value=active_connections,
                    description=(
                        "No active connections were "
                        "observed."
                    ),
                    source=[
                        "CloudWatch.ActiveConnectionCount"
                    ],
                    observed=True,
                )
            )

        if new_connections is not None:

            statements.append(
                self._statement(
                    name="new_connections",
                    value=new_connections,
                    description=(
                        "No new connections were "
                        "observed."
                    ),
                    source=[
                        "CloudWatch.NewConnectionCount"
                    ],
                    observed=True,
                )
            )

        return self._finding(
            context=context,
            finding_type=(
                "elb_no_observed_activity"
            ),
            title=(
                "Load balancer with no observed activity"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "The load balancer had sufficient "
                "traffic observations, but no request "
                "or processed-byte activity was observed."
            ),
            statements=statements,
            metadata={
                "category":
                    "unused_resource",

                "finding_family":
                    "elb_inactivity",

                "request_count":
                    traffic.get(
                        "request_count"
                    ),

                "processed_bytes":
                    traffic.get(
                        "processed_bytes"
                    ),

                "processed_gib":
                    traffic.get(
                        "processed_gib"
                    ),
            },
            limitations=[
                (
                    "No observed activity does not prove "
                    "that the load balancer is unnecessary."
                ),
                (
                    "Scheduled or intermittent workloads "
                    "may not appear in the selected window."
                ),
                (
                    "Validate DNS, listeners, target groups, "
                    "dependencies and workload schedules."
                ),
            ],
        )

    # ==================================================================
    # RULE 2 — LOW TRAFFIC
    # ==================================================================

    def _check_low_traffic(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = (
            self._policy(
                context
            ).get(
                "low_traffic",
                {},
            )
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        minimum_coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        request_ready = (
            self._metric_ready(
                context,
                "request_count",
                minimum_coverage,
            )
        )

        bytes_ready = (
            self._metric_ready(
                context,
                "processed_bytes",
                minimum_coverage,
            )
        )

        if not (
            request_ready
            and bytes_ready
        ):
            return None

        request_count = (
            self._metric_value(
                context,
                "request_count",
            )
        )

        processed_bytes = (
            self._metric_value(
                context,
                "processed_bytes",
            )
        )

        if (
            request_count is None
            or processed_bytes is None
        ):
            return None

        processed_gib = (
            processed_bytes
            / (1024 ** 3)
        )

        if (
            request_count <= 0
            and processed_bytes <= 0
        ):
            return None

        request_limit = float(
            policy.get(
                "request_count_max",
                100.0,
            )
        )

        gib_limit = float(
            policy.get(
                "processed_gib_max",
                1.0,
            )
        )

        if not (
            request_count <= request_limit
            and processed_gib <= gib_limit
        ):
            return None

        statements = [
            self._statement(
                name="request_count",
                value=request_count,
                description=(
                    "Observed request volume is "
                    "within the configured low-traffic "
                    "review range."
                ),
                source=[
                    "CloudWatch.RequestCount"
                ],
                observed=True,
            ),

            self._statement(
                name="processed_gib",
                value=round(
                    processed_gib,
                    6,
                ),
                description=(
                    "Observed processed traffic is "
                    "within the configured low-traffic "
                    "review range."
                ),
                source=[
                    "CloudWatch.ProcessedBytes"
                ],
                unit="GiB",
                observed=True,
            ),
        ]

        return self._finding(
            context=context,
            finding_type="elb_low_traffic",
            title=(
                "Load balancer with low observed traffic"
            ),
            severity="low",
            confidence="medium",
            reason=(
                "The load balancer is active and both "
                "observed request volume and processed "
                "traffic are within the configured "
                "low-traffic review range."
            ),
            statements=statements,
            metadata={
                "category":
                    "unused_resource",

                "finding_family":
                    "elb_low_traffic",

                "request_count":
                    request_count,

                "processed_gib":
                    processed_gib,

                "request_count_threshold":
                    request_limit,

                "processed_gib_threshold":
                    gib_limit,
            },
            limitations=[
                (
                    "Low traffic does not prove that the "
                    "load balancer is unnecessary."
                ),
                (
                    "Traffic may be seasonal or intermittent."
                ),
                (
                    "Validate workload schedules and "
                    "application dependencies."
                ),
            ],
        )

    # ==================================================================
    # RULE 3 — NO REGISTERED TARGETS
    # ==================================================================

    def _check_no_registered_targets(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = (
            self._policy(
                context
            ).get(
                "target_groups",
                {},
            )
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        summary = (
            self._summary(
                context
            )
        )

        target_count = summary.get(
            "target_count"
        )

        health_complete = summary.get(
            "target_health_complete"
        )

        if health_complete is not True:
            return None

        if not isinstance(
            target_count,
            int,
        ):
            return None

        if target_count != 0:
            return None

        traffic = (
            self._traffic_state(
                context
            )
        )

        if traffic.get(
            "ready"
        ) and traffic.get(
            "observed"
        ) is True:
            return None

        statements = [
            self._statement(
                name="target_count",
                value=target_count,
                description=(
                    "No registered targets were "
                    "observed across the load "
                    "balancer target groups."
                ),
                source=[
                    "ELB.TargetGroups.TargetHealth"
                ],
                observed=True,
            ),

            self._statement(
                name="target_health_complete",
                value=True,
                description=(
                    "Target-health collection "
                    "completed successfully."
                ),
                source=[
                    "ELB.TargetGroups.TargetHealth"
                ],
                observed=True,
            ),
        ]

        # Traffic evidence is only claimed when it was actually
        # observed and confirmed at zero -- "ready" being False
        # (insufficient coverage, metrics not requested for this LB
        # type, etc.) means traffic is unknown, not zero, and this
        # finding must not assert a claim it never checked.
        if (
            traffic.get("ready")
            and traffic.get("observed")
            is False
        ):
            reason = (
                "The load balancer has no registered "
                "targets and observed traffic was "
                "confirmed at zero."
            )
        else:
            reason = (
                "The load balancer has no registered "
                "targets."
            )

        return self._finding(
            context=context,
            finding_type=(
                "elb_no_registered_targets"
            ),
            title=(
                "Load balancer with no registered targets"
            ),
            severity="medium",
            confidence="high",
            reason=reason,
            statements=statements,
            metadata={
                "category":
                    "unused_resource",

                "finding_family":
                    "elb_inactivity",

                "target_count":
                    target_count,

                "target_group_count":
                    summary.get(
                        "target_group_count"
                    ),
            },
            limitations=[
                (
                    "A load balancer can temporarily have "
                    "no targets during deployment or scaling."
                ),
                (
                    "Validate listeners, target groups, "
                    "DNS records and deployment state."
                ),
            ],
        )

    # ==================================================================
    # RULE 4 — IDLE TARGET GROUPS
    # ==================================================================

    def _check_idle_target_groups(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = (
            self._policy(
                context
            ).get(
                "target_groups",
                {},
            )
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        traffic = (
            self._traffic_state(
                context
            )
        )

        if not traffic.get(
            "ready"
        ):
            return None

        target_groups = (
            self._target_groups(
                context
            )
        )

        idle_groups = []

        for group in target_groups:

            if group.get(
                "target_health_status"
            ) != "ok":
                continue

            target_count = group.get(
                "target_count"
            )

            if target_count == 0:
                idle_groups.append(
                    group
                )

        if not idle_groups:
            return None

        statements = [
            self._statement(
                name="idle_target_group_count",
                value=len(
                    idle_groups
                ),
                description=(
                    "Target groups with successful "
                    "target-health collection and "
                    "zero registered targets were "
                    "identified."
                ),
                source=[
                    "ELB.TargetGroups.TargetHealth"
                ],
                observed=True,
            ),
        ]

        for group in idle_groups:

            statements.append(
                self._statement(
                    name="target_group",
                    value={
                        "arn":
                            group.get(
                                "target_group_arn"
                            ),

                        "name":
                            group.get(
                                "target_group_name"
                            ),

                        "target_count":
                            group.get(
                                "target_count"
                            ),
                    },
                    description=(
                        "Target group contains no "
                        "registered targets and "
                        "target-health collection "
                        "completed successfully."
                    ),
                    source=[
                        "ELB.TargetGroups.TargetHealth"
                    ],
                    observed=True,
                )
            )

        return self._finding(
            context=context,
            finding_type=(
                "elb_idle_target_group"
            ),
            title=(
                "Load balancer target group with no targets"
            ),
            severity="low",
            confidence="high",
            reason=(
                f"{len(idle_groups)} target group(s) "
                "have no registered targets."
            ),
            statements=statements,
            metadata={
                "category":
                    "unused_resource",

                "finding_family":
                    "elb_target_group",

                "idle_target_group_count":
                    len(idle_groups),

                "idle_target_groups":
                    idle_groups,
            },
            limitations=[
                (
                    "An empty target group can be intentional "
                    "during deployment or failover."
                ),
                (
                    "Review listener rules and deployment "
                    "configuration before changing it."
                ),
            ],
        )

    # ==================================================================
    # RULE 5 — NO HEALTHY TARGETS + NO TRAFFIC
    # ==================================================================

    def _check_no_healthy_targets_no_traffic(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = (
            self._policy(
                context
            ).get(
                "healthy_targets",
                {},
            )
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        summary = (
            self._summary(
                context
            )
        )

        target_count = summary.get(
            "target_count"
        )

        healthy_count = summary.get(
            "healthy_target_count"
        )

        health_complete = summary.get(
            "target_health_complete"
        )

        if health_complete is not True:
            return None

        if not isinstance(
            target_count,
            int,
        ):
            return None

        if not isinstance(
            healthy_count,
            int,
        ):
            return None

        if target_count <= 0:
            return None

        if healthy_count != 0:
            return None

        traffic = (
            self._traffic_state(
                context
            )
        )

        if not traffic.get(
            "ready"
        ):
            return None

        if traffic.get(
            "observed"
        ) is not False:
            return None

        statements = [
            self._statement(
                name="target_count",
                value=target_count,
                description=(
                    "Registered targets exist."
                ),
                source=[
                    "ELB.TargetGroups.TargetHealth"
                ],
                observed=True,
            ),

            self._statement(
                name="healthy_target_count",
                value=healthy_count,
                description=(
                    "No healthy targets were observed."
                ),
                source=[
                    "ELB.TargetGroups.TargetHealth"
                ],
                observed=True,
            ),

            self._statement(
                name="traffic_observed",
                value=False,
                description=(
                    "No request or processed-byte "
                    "activity was observed."
                ),
                source=[
                    "CloudWatch.RequestCount",
                    "CloudWatch.ProcessedBytes",
                ],
                observed=True,
            ),
        ]

        return self._finding(
            context=context,
            finding_type=(
                "elb_no_healthy_targets_no_traffic"
            ),
            title=(
                "Load balancer has no healthy targets and no traffic"
            ),
            severity="medium",
            confidence="medium",
            reason=(
                "The load balancer has registered "
                "targets but none are healthy, while "
                "no traffic was observed."
            ),
            statements=statements,
            metadata={
                "category":
                    "unused_resource",

                "finding_family":
                    "elb_inactivity",

                "target_count":
                    target_count,

                "healthy_target_count":
                    healthy_count,

                "unhealthy_target_count":
                    summary.get(
                        "unhealthy_target_count"
                    ),
            },
            limitations=[
                (
                    "This does not prove that the load "
                    "balancer should be removed."
                ),
                (
                    "The condition can be caused by an "
                    "application deployment or health-check "
                    "configuration."
                ),
                (
                    "Validate application and target health "
                    "configuration before changing resources."
                ),
            ],
        )

    # ==================================================================
    # RULE 6 — IDLE + CONFIRMED ZERO TRAFFIC + COST
    # ==================================================================

    def _check_idle_with_cost(
        self,
        context: AnalysisContext,
    ) -> Finding | None:
        """
        The strongest version of "this load balancer is unused": no
        registered targets, traffic was actually observed (not
        merely unavailable) and confirmed at zero, and cost evidence
        is present. Unlike _check_no_registered_targets, this rule
        requires positive proof on every dimension, so it is the one
        finding allowed to state a concrete recurring-cost figure.
        """

        policy = (
            self._policy(
                context
            ).get(
                "target_groups",
                {},
            )
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        summary = (
            self._summary(
                context
            )
        )

        target_count = summary.get(
            "target_count"
        )

        health_complete = summary.get(
            "target_health_complete"
        )

        if health_complete is not True:
            return None

        if not isinstance(
            target_count,
            int,
        ):
            return None

        if target_count != 0:
            return None

        traffic = (
            self._traffic_state(
                context
            )
        )

        if not traffic.get(
            "ready"
        ):
            return None

        if traffic.get(
            "observed"
        ) is not False:
            return None

        billing = context.billing()

        if not isinstance(
            billing,
            dict,
        ):
            billing = {}

        # Reconciliation is the sole cost-attribution authority --
        # a positive billing amount must never be treated as this
        # resource's own cost unless reconciliation has explicitly
        # proven resource-level attribution.
        if billing.get(
            "attribution_scope"
        ) != "resource":
            return None

        if billing.get(
            "resource_cost_attributed"
        ) is not True:
            return None

        cost = billing.get("amount")

        if not isinstance(
            cost,
            (int, float),
        ) or cost <= 0:
            return None

        statements = [
            self._statement(
                name="target_count",
                value=target_count,
                description=(
                    "No registered targets were "
                    "observed across the load "
                    "balancer target groups."
                ),
                source=[
                    "ELB.TargetGroups.TargetHealth"
                ],
                observed=True,
            ),

            self._statement(
                name="request_count",
                value=traffic.get(
                    "request_count"
                ),
                description=(
                    "Observed request count during "
                    "the analysis period."
                ),
                source=[
                    "CloudWatch.RequestCount"
                ],
                observed=True,
            ),

            self._statement(
                name="processed_bytes",
                value=traffic.get(
                    "processed_bytes"
                ),
                description=(
                    "Observed processed bytes during "
                    "the analysis period."
                ),
                source=[
                    "CloudWatch.ProcessedBytes"
                ],
                observed=True,
            ),

            self._statement(
                name="observed_cost",
                value=cost,
                description=(
                    "Billing amount evidenced for this "
                    "load balancer during the analysis "
                    "period."
                ),
                source=[
                    "CostExplorer"
                ],
                unit=str(
                    billing.get(
                        "currency"
                    )
                    or "USD"
                ),
                observed=True,
            ),
        ]

        return self._finding(
            context=context,
            finding_type=(
                "elb_idle_with_cost"
            ),
            title=(
                "Idle load balancer incurring recurring cost"
            ),
            severity="high",
            confidence="high",
            cost_optimization_type="elimination",
            reason=(
                "The load balancer has no registered "
                "targets, observed traffic was confirmed "
                "at zero, and it is incurring "
                f"{billing.get('currency') or 'USD'} "
                f"{cost:,.2f} of billed cost during the "
                "analysis period."
            ),
            statements=statements,
            metadata={
                "category":
                    "unused_resource",

                "finding_family":
                    "elb_inactivity",

                "target_count":
                    target_count,

                "observed_cost":
                    cost,

                "currency":
                    billing.get(
                        "currency"
                    ),

                "cost_attribution":
                    billing.get(
                        "attribution_scope"
                    ),
            },
            limitations=[
                (
                    "A load balancer can temporarily have "
                    "no targets during deployment or scaling."
                ),
                (
                    "Validate listeners, target groups, "
                    "DNS records and deployment state "
                    "before removal."
                ),
                (
                    "The cost figure reflects this "
                    "resource's own billed usage only when "
                    "attribution is resource-scoped; check "
                    "the finding's billing evidence before "
                    "reporting it as a guaranteed saving."
                ),
            ],
        )

    # ==================================================================
    # FINDING BUILDER
    # ==================================================================

    @classmethod
    def _finding(
        cls,
        *,
        context: AnalysisContext,
        finding_type: str,
        title: str,
        severity: str,
        confidence: str,
        reason: str,
        statements: list[
            EvidenceStatement
        ],
        metadata: dict[str, Any],
        limitations: list[str],
        cost_optimization_type: str = "review",
    ) -> Finding:

        metrics = context.metrics()

        metric_evidence = {
            name:
                context.metric_summary(
                    name
                )
            for name in metrics
            if isinstance(
                metrics.get(name),
                dict,
            )
        }

        configuration = (
            cls._configuration(
                context
            )
        )

        filtered_configuration = {
            key:
                configuration.get(key)
            for key in ELB_CONFIGURATION_FIELDS
            if key in configuration
        }

        topology = (
            context.topology()
        )

        if not isinstance(
            topology,
            dict,
        ):
            topology = {}

        billing = (
            context.billing()
        )

        if not isinstance(
            billing,
            dict,
        ):
            billing = {}

        relationships = (
            cls._relationships(
                context
            )
        )

        evidence = Evidence(
            metrics=metric_evidence,

            configuration=(
                filtered_configuration
            ),

            topology=dict(
                topology
            ),

            billing=dict(
                billing
            ),

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,

                "load_balancer_name":
                    configuration.get(
                        "load_balancer_name"
                    ),

                "load_balancer_type":
                    configuration.get(
                        "type"
                    ),

                "scheme":
                    configuration.get(
                        "scheme"
                    ),
            },

            derived={
                "analysis_category":
                    metadata.get(
                        "category"
                    ),

                "finding_family":
                    metadata.get(
                        "finding_family"
                    ),

                "relationships":
                    relationships,
            },

            data_quality={
                **(
                    context.collector_data_quality()
                    if hasattr(
                        context,
                        "collector_data_quality",
                    )
                    else {}
                ),

                "metric_count":
                    len(
                        metric_evidence
                    ),

                "relationship_data_available":
                    bool(
                        relationships
                    ),

                "topology_available":
                    bool(
                        topology
                    ),
            },
        )

        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or cls.DEFAULT_RESOURCE_TYPE
            ),

            resource_id=(
                context.resource_id
                or "unknown"
            ),

            analyzer=cls.name,

            analyzer_version=cls.version,

            severity=(
                str(
                    severity
                ).lower()
            ),

            confidence=(
                str(
                    confidence
                ).lower()
            ),

            reason=reason,

            conditions=statements,

            evidence=evidence,

            observation_period=(
                cls._observation_period(
                    context
                )
            ),

            limitations=list(
                limitations
            ),

            metadata=metadata,

            recommendation_eligible=True,

            aggregation_scope="resource",

            cost_optimization_type=cost_optimization_type,
        )

    # ==================================================================
    # EVIDENCE STATEMENT
    # ==================================================================

    @staticmethod
    def _statement(
        *,
        name: str,
        value: Any,
        description: str,
        source: list[str],
        unit: str | None = None,
        observed: bool | None = None,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=list(
                source
            ),
            unit=unit,
            observed=observed,
        )

    # ==================================================================
    # OBSERVATION PERIOD
    # ==================================================================

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        value = (
            context.observation_period
        )

        if isinstance(
            value,
            dict,
        ):

            return ObservationPeriod(
                start=value.get(
                    "start"
                ),
                end=value.get(
                    "end"
                ),
                duration_seconds=value.get(
                    "duration_seconds"
                ),
            )

        try:

            cloudwatch = (
                context.cloudwatch()
            )

        except Exception:

            cloudwatch = {}

        if not isinstance(
            cloudwatch,
            dict,
        ):
            return None

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

        if not start and not end:
            return None

        return ObservationPeriod(
            start=start,
            end=end,
        )