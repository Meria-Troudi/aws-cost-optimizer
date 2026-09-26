"""
Elastic Load Balancer cost optimization analyzer.

The collector supplies evidence.

This analyzer only evaluates rules.

Cost-oriented rules
-------------------
A single load balancer is reported at most ONCE, with one canonical
optimization finding.

CANONICAL idle condition (targets == 0, complete observation, no
traffic):
- elb_idle_with_cost  -> cost resource-attributed (elimination)
- elb_idle            -> cost not resource-attributed (review)

Otherwise the granular rules below run in priority order and only the
FIRST qualifying finding is returned:
1. No observed activity.
2. Low observed traffic.
3. No registered targets.
4. No healthy targets + no traffic.

The overlapping granular rules (no activity / no targets / empty target
groups) all describe the same idle condition and must never produce
duplicate "Review Load Balancer Removal" recommendations for one ELB.

Important
---------
- Missing CloudWatch data is never zero.
- Unhealthy targets alone are never an optimization finding.
- Incomplete target-health data never becomes zero targets.
- No savings are invented.
- Billing amounts are used only when resource-level attribution
  has explicitly been established by reconciliation.
- Findings are review recommendations, not deletion commands.
"""

from __future__ import annotations

from typing import Any

from ...base import Analyzer
from ...condition import EvidenceStatement
from ...context import AnalysisContext
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
from ...metrics import metric_has_observed_data
from ...registry import register

# DEFAULT POLICY

DEFAULT_POLICY = {
    "activity": {
        "enabled": True,
    },
    "low_traffic": {
        "enabled": True,
        # ALB
        "application_request_count_max": 100.0,
        # All ELB families
        "processed_gib_max": 1.0,
        # NLB / GWLB
        "network_new_flow_count_max": 100.0,
        "gateway_new_flow_count_max": 100.0,
    },
    "target_groups": {
        "enabled": True,
    },
    "healthy_targets": {
        "enabled": True,
    },
    "idle_with_cost": {
        "enabled": True,
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


@register
class ElbAnalyzer(Analyzer):

    name = "elb"
    version = "4.0"

    SUPPORTED_RESOURCE_TYPES = {
        "load_balancer",
        "elb",
    }

    DEFAULT_RESOURCE_TYPE = "load_balancer"

    # SUPPORT

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        return context.resource_type in self.SUPPORTED_RESOURCE_TYPES

    # ANALYZE

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        if not self._eligible(context):
            return []

        # One LB yields at most ONE canonical finding: overlapping idle checks
        # (no activity / no targets) all describe the same condition, so emit
        # elb_idle when detected, else only the first qualifying granular check.
        signals = self._signals(context)

        canonical = self._canonical_idle_finding(
            context,
            signals,
        )

        if canonical is not None:
            return [canonical]

        for check in (
            self._check_no_observed_activity,
            self._check_low_traffic,
            self._check_no_registered_targets,
            self._check_no_healthy_targets_no_traffic,
        ):

            finding = check(context)

            if finding is not None:
                return [finding]

        return []

    # POLICY

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
            for key, value in DEFAULT_POLICY.items()
        }

        for root_name in (
            "analyzer_config",
            "analysis_config",
            "config",
        ):

            root = context.resource.get(root_name)

            if not isinstance(
                root,
                dict,
            ):
                continue

            configured = root.get("elb")

            if not isinstance(
                configured,
                dict,
            ):
                continue

            for category, values in configured.items():

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

                    policy[category] = {
                        **default,
                        **values,
                    }

                else:

                    policy[category] = values

            break

        return policy

    # ELIGIBILITY

    @staticmethod
    def _configuration(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = context.configuration()

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

        configuration = cls._configuration(context)

        if configuration.get("optimization_allowed") is False:

            return False

        state = str(configuration.get("state") or "").strip().lower()

        if state and state != "active":
            return False

        return True

    # RESOURCE FAMILY

    @classmethod
    def _lb_type(
        cls,
        context: AnalysisContext,
    ) -> str:

        return str(cls._configuration(context).get("type") or "").strip().lower()

    # METRICS

    @staticmethod
    def _metric(
        context: AnalysisContext,
        name: str,
    ) -> dict[str, Any]:

        try:

            value = context.metric_summary(name)

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
    ) -> bool:

        metric = cls._metric(
            context,
            name,
        )

        if not metric_has_observed_data(metric):
            return False

        return isinstance(
            metric.get("value"),
            (int, float),
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

        if not metric_has_observed_data(metric):
            return None

        value = metric.get("value")

        if isinstance(
            value,
            (int, float),
        ):
            return float(value)

        return None

    # TRAFFIC STATE

    @classmethod
    def _traffic_state(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        lb_type = cls._lb_type(context)

        processed_bytes = cls._metric_value(
            context,
            "processed_bytes",
        )

        request_count = None
        active_connections = None
        new_connections = None
        active_flow_count = None
        new_flow_count = None

        if lb_type == "application":

            request_count = cls._metric_value(
                context,
                "request_count",
            )

            required = (
                request_count,
                processed_bytes,
            )

        elif lb_type == "network":

            active_connections = cls._metric_value(
                context,
                "active_connections",
            )

            new_connections = cls._metric_value(
                context,
                "new_connections",
            )

            active_flow_count = cls._metric_value(
                context,
                "active_flow_count",
            )

            new_flow_count = cls._metric_value(
                context,
                "new_flow_count",
            )

            required = (
                processed_bytes,
                active_connections,
                new_connections,
                active_flow_count,
                new_flow_count,
            )

        elif lb_type == "gateway":

            active_flow_count = cls._metric_value(
                context,
                "active_flow_count",
            )

            new_flow_count = cls._metric_value(
                context,
                "new_flow_count",
            )

            required = (
                processed_bytes,
                active_flow_count,
                new_flow_count,
            )

        else:

            request_count = cls._metric_value(
                context,
                "request_count",
            )

            required = (
                request_count,
                processed_bytes,
            )

        # Every metric relevant to this LB type must be observed --
        # a single observed-zero metric alongside unqueried/no-data
        # siblings is not proof the others are also zero.
        ready = all(value is not None for value in required)

        return {
            "ready": ready,
            "observed": (any(value > 0 for value in required) if ready else None),
            "lb_type": lb_type,
            "request_count": request_count,
            "processed_bytes": processed_bytes,
            "processed_gib": (
                processed_bytes / (1024**3) if processed_bytes is not None else None
            ),
            "active_connections": (active_connections),
            "new_connections": (new_connections),
            "active_flow_count": (active_flow_count),
            "new_flow_count": (new_flow_count),
        }

    # RELATIONSHIPS

    @staticmethod
    def _relationships(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = context.resource.get(
            "relationships",
            {},
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

        value = cls._relationships(context).get(
            "summary",
            {},
        )

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    # SIGNALS + CANONICAL IDLE

    @classmethod
    def _signals(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        summary = cls._summary(context)

        traffic = cls._traffic_state(context)

        target_count = summary.get("target_count")

        target_group_count = summary.get("target_group_count")

        processed_bytes = traffic.get("processed_bytes")

        observation_complete = traffic.get("ready") is True

        return {
            "no_registered_targets": (
                isinstance(
                    target_count,
                    int,
                )
                and target_count == 0
            ),
            "no_observed_requests": (traffic.get("observed") is False),
            "no_processed_bytes": (
                isinstance(
                    processed_bytes,
                    (int, float),
                )
                and not isinstance(
                    processed_bytes,
                    bool,
                )
                and processed_bytes == 0
            ),
            "target_group_count": target_group_count,
            "empty_target_group_count": (cls._empty_target_group_count(context)),
            "observation_complete": observation_complete,
        }

    @classmethod
    def _empty_target_group_count(
        cls,
        context: AnalysisContext,
    ) -> int | None:

        relationships = cls._relationships(context)

        groups = relationships.get("target_groups")

        if not isinstance(
            groups,
            list,
        ):
            return None

        count = 0

        for group in groups:

            if not isinstance(
                group,
                dict,
            ):
                continue

            target_count = group.get("target_count")

            if (
                isinstance(
                    target_count,
                    int,
                )
                and target_count == 0
            ):
                count += 1

        return count

    def _canonical_idle_finding(
        self,
        context: AnalysisContext,
        signals: dict[str, Any],
    ) -> Finding | None:

        # 1. Fully attributed idle -> elb_idle_with_cost (elimination).
        idle_with_cost = self._check_idle_with_cost(context)

        if idle_with_cost is not None:

            metadata = dict(idle_with_cost.metadata)
            metadata.setdefault(
                "signals",
                signals,
            )
            idle_with_cost.metadata = metadata

            return idle_with_cost

        # 2. Structural idle without attributable cost -> elb_idle
        #    (removal review, no savings claimed).
        return self._elb_idle_finding(
            context,
            signals,
        )

    def _elb_idle_finding(
        self,
        context: AnalysisContext,
        signals: dict[str, Any],
    ) -> Finding | None:

        policy = self._policy(context).get(
            "idle_with_cost",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        summary = self._summary(context)

        target_count = summary.get("target_count")

        health_complete = summary.get("target_health_complete")

        if health_complete is not True:
            return None

        if not isinstance(
            target_count,
            int,
        ):
            return None

        if target_count != 0:
            return None

        traffic = self._traffic_state(context)

        if traffic.get("ready") is not True:
            return None

        if traffic.get("observed") is not False:
            return None

        return self._finding(
            context=context,
            finding_type=("elb_idle"),
            title=("Idle load balancer"),
            severity="high",
            confidence="high",
            reason=(
                "The load balancer is idle: it has no registered "
                "targets, no observed traffic, and the target-health "
                "and traffic observation evidence is complete. It is "
                "a candidate for removal review, but its cost is not "
                "resource-attributed, so no savings are claimed."
            ),
            statements=[
                self._statement(
                    name="target_count",
                    value=0,
                    description=(
                        "No registered targets were observed across "
                        "the load balancer target groups."
                    ),
                    source=["ELB.TargetGroups.TargetHealth"],
                    observed=True,
                ),
                self._statement(
                    name="target_health_complete",
                    value=True,
                    description=("Target-health collection completed " "successfully."),
                    source=["ELB.TargetGroups.TargetHealth"],
                    observed=True,
                ),
                self._statement(
                    name="traffic_observed",
                    value=False,
                    description=(
                        "No positive ELB activity was observed "
                        "during the analysis period."
                    ),
                    source=["CloudWatch"],
                    observed=True,
                ),
            ],
            metadata={
                "category": ("unused_resource"),
                "finding_family": ("elb_inactivity"),
                "lb_type": traffic.get("lb_type"),
                "target_count": 0,
                "target_group_count": summary.get("target_group_count"),
                "cost_attribution": (context.billing().get("attribution_scope")),
                "signals": signals,
            },
        )

    # RULE 1 — NO OBSERVED ACTIVITY

    def _check_no_observed_activity(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "activity",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        traffic = self._traffic_state(context)

        if traffic.get("ready") is not True:
            return None

        if traffic.get("observed") is not False:
            return None

        statements = []

        self._append_metric_statement(
            statements,
            context,
            "processed_bytes",
            "No processed bytes were observed.",
            "CloudWatch.ProcessedBytes",
            unit="Bytes",
        )

        self._append_metric_statement(
            statements,
            context,
            "request_count",
            "No requests were observed.",
            "CloudWatch.RequestCount",
            unit="Count",
        )

        self._append_metric_statement(
            statements,
            context,
            "active_connections",
            "No active connections were observed.",
            "CloudWatch.ActiveConnectionCount",
            unit="Count",
        )

        self._append_metric_statement(
            statements,
            context,
            "new_connections",
            "No new connections were observed.",
            "CloudWatch.NewConnectionCount",
            unit="Count",
        )

        self._append_metric_statement(
            statements,
            context,
            "active_flow_count",
            "No active flows were observed.",
            "CloudWatch.ActiveFlowCount",
            unit="Count",
        )

        self._append_metric_statement(
            statements,
            context,
            "new_flow_count",
            "No new flows were observed.",
            "CloudWatch.NewFlowCount",
            unit="Count",
        )

        statements.append(
            self._statement(
                name="traffic_observed",
                value=False,
                description=(
                    "No positive traffic or connection "
                    "activity was observed during the "
                    "analysis period."
                ),
                source=[
                    "CloudWatch",
                ],
                observed=True,
            )
        )

        return self._finding(
            context=context,
            finding_type=("elb_no_observed_activity"),
            title=("Load balancer with no observed activity"),
            severity="medium",
            confidence="high",
            reason=(
                "The available ELB-family-specific "
                "CloudWatch activity evidence was "
                "successfully observed and contained "
                "no positive traffic or connection "
                "activity during the analysis period."
            ),
            statements=statements,
            metadata={
                "category": "unused_resource",
                "finding_family": "elb_inactivity",
                "lb_type": traffic.get("lb_type"),
            },
        )

    # RULE 2 — LOW TRAFFIC

    def _check_low_traffic(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "low_traffic",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        traffic = self._traffic_state(context)

        if traffic.get("ready") is not True:

            return None

        if traffic.get("observed") is not True:

            return None

        processed_gib = traffic.get("processed_gib")

        if processed_gib is None:
            return None

        gib_limit = float(
            policy.get(
                "processed_gib_max",
                1.0,
            )
        )

        if processed_gib > gib_limit:
            return None

        lb_type = traffic.get("lb_type")

        # ALB

        if lb_type == "application":

            request_count = traffic.get("request_count")

            if request_count is None:
                return None

            request_limit = float(
                policy.get(
                    "application_request_count_max",
                    100.0,
                )
            )

            if request_count > request_limit:
                return None

            statements = [
                self._statement(
                    name="request_count",
                    value=request_count,
                    description=(
                        "Observed ALB request volume "
                        "is within the configured "
                        "low-traffic review threshold."
                    ),
                    source=["CloudWatch.RequestCount"],
                    unit="Count",
                    observed=True,
                ),
                self._statement(
                    name="processed_gib",
                    value=round(
                        processed_gib,
                        6,
                    ),
                    description=(
                        "Observed processed traffic "
                        "is within the configured "
                        "low-traffic review threshold."
                    ),
                    source=["CloudWatch.ProcessedBytes"],
                    unit="GiB",
                    observed=True,
                ),
            ]

            thresholds = {
                "request_count_max": request_limit,
                "processed_gib_max": gib_limit,
            }

        # NLB

        elif lb_type == "network":

            new_flow_count = traffic.get("new_flow_count")

            if new_flow_count is None:
                return None

            flow_limit = float(
                policy.get(
                    "network_new_flow_count_max",
                    100.0,
                )
            )

            if new_flow_count > flow_limit:
                return None

            statements = [
                self._statement(
                    name="new_flow_count",
                    value=new_flow_count,
                    description=(
                        "Observed NLB new-flow volume "
                        "is within the configured "
                        "low-traffic review threshold."
                    ),
                    source=["CloudWatch.NewFlowCount"],
                    unit="Count",
                    observed=True,
                ),
                self._statement(
                    name="processed_gib",
                    value=round(
                        processed_gib,
                        6,
                    ),
                    description=(
                        "Observed processed traffic "
                        "is within the configured "
                        "low-traffic review threshold."
                    ),
                    source=["CloudWatch.ProcessedBytes"],
                    unit="GiB",
                    observed=True,
                ),
            ]

            thresholds = {
                "new_flow_count_max": flow_limit,
                "processed_gib_max": gib_limit,
            }

        # GWLB

        elif lb_type == "gateway":

            new_flow_count = traffic.get("new_flow_count")

            if new_flow_count is None:
                return None

            flow_limit = float(
                policy.get(
                    "gateway_new_flow_count_max",
                    100.0,
                )
            )

            if new_flow_count > flow_limit:
                return None

            statements = [
                self._statement(
                    name="new_flow_count",
                    value=new_flow_count,
                    description=(
                        "Observed GWLB new-flow volume "
                        "is within the configured "
                        "low-traffic review threshold."
                    ),
                    source=["CloudWatch.NewFlowCount"],
                    unit="Count",
                    observed=True,
                ),
                self._statement(
                    name="processed_gib",
                    value=round(
                        processed_gib,
                        6,
                    ),
                    description=(
                        "Observed processed traffic "
                        "is within the configured "
                        "low-traffic review threshold."
                    ),
                    source=["CloudWatch.ProcessedBytes"],
                    unit="GiB",
                    observed=True,
                ),
            ]

            thresholds = {
                "new_flow_count_max": flow_limit,
                "processed_gib_max": gib_limit,
            }

        else:

            return None

        return self._finding(
            context=context,
            finding_type="elb_low_traffic",
            title=("Load balancer with low observed traffic"),
            severity="low",
            confidence="medium",
            reason=(
                "The load balancer is active and its "
                "ELB-family-specific traffic metrics "
                "are within the configured low-traffic "
                "review thresholds."
            ),
            statements=statements,
            metadata={
                "category": "unused_resource",
                "finding_family": "elb_low_traffic",
                "lb_type": lb_type,
                "processed_gib": processed_gib,
                "thresholds": thresholds,
            },
        )

    # RULE 3 — NO REGISTERED TARGETS

    def _check_no_registered_targets(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "target_groups",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        summary = self._summary(context)

        target_count = summary.get("target_count")

        health_complete = summary.get("target_health_complete")

        if health_complete is not True:
            return None

        if not isinstance(
            target_count,
            int,
        ):
            return None

        if target_count != 0:
            return None

        statements = [
            self._statement(
                name="target_count",
                value=0,
                description=(
                    "No registered targets were "
                    "observed across the load balancer "
                    "target groups."
                ),
                source=["ELB.TargetGroups.TargetHealth"],
                observed=True,
            ),
            self._statement(
                name="target_health_complete",
                value=True,
                description=("Target-health collection " "completed successfully."),
                source=["ELB.TargetGroups.TargetHealth"],
                observed=True,
            ),
        ]

        return self._finding(
            context=context,
            finding_type=("elb_no_registered_targets"),
            title=("Load balancer with no registered targets"),
            severity="medium",
            confidence="high",
            reason=(
                "The load balancer has no registered "
                "targets and target-health collection "
                "completed successfully. Review whether "
                "the load balancer is still required."
            ),
            statements=statements,
            metadata={
                "category": "unused_resource",
                "finding_family": "elb_inactivity",
                "target_count": 0,
                "target_group_count": summary.get("target_group_count"),
            },
        )

    # RULE 4 — NO HEALTHY TARGETS + NO TRAFFIC

    def _check_no_healthy_targets_no_traffic(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "healthy_targets",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        summary = self._summary(context)

        target_count = summary.get("target_count")

        healthy_count = summary.get("healthy_target_count")

        health_complete = summary.get("target_health_complete")

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

        traffic = self._traffic_state(context)

        if traffic.get("ready") is not True:
            return None

        if traffic.get("observed") is not False:
            return None

        statements = [
            self._statement(
                name="target_count",
                value=target_count,
                description=("Registered targets exist."),
                source=["ELB.TargetGroups.TargetHealth"],
                observed=True,
            ),
            self._statement(
                name="healthy_target_count",
                value=healthy_count,
                description=("No healthy targets were observed."),
                source=["ELB.TargetGroups.TargetHealth"],
                observed=True,
            ),
            self._statement(
                name="traffic_observed",
                value=False,
                description=(
                    "No positive traffic or connection " "activity was observed."
                ),
                source=["CloudWatch"],
                observed=True,
            ),
        ]

        return self._finding(
            context=context,
            finding_type=("elb_no_healthy_targets_no_traffic"),
            title=("Load balancer has no healthy targets " "and no traffic"),
            severity="medium",
            confidence="medium",
            reason=(
                "The load balancer has registered "
                "targets but none are healthy, while "
                "the available ELB-family-specific "
                "activity evidence shows no observed "
                "traffic."
            ),
            statements=statements,
            metadata={
                "category": "unused_resource",
                "finding_family": "elb_inactivity",
                "lb_type": traffic.get("lb_type"),
                "target_count": target_count,
                "healthy_target_count": healthy_count,
                "unhealthy_target_count": summary.get("unhealthy_target_count"),
            },
        )

    # RULE 5 — IDLE + ZERO TRAFFIC + RECONCILED COST

    def _check_idle_with_cost(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = self._policy(context).get(
            "idle_with_cost",
            {},
        )

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        summary = self._summary(context)

        target_count = summary.get("target_count")

        health_complete = summary.get("target_health_complete")

        if health_complete is not True:
            return None

        if not isinstance(
            target_count,
            int,
        ):
            return None

        if target_count != 0:
            return None

        traffic = self._traffic_state(context)

        if traffic.get("ready") is not True:
            return None

        if traffic.get("observed") is not False:
            return None

        billing = context.billing()

        if not isinstance(
            billing,
            dict,
        ):
            return None

        if billing.get("attribution_scope") != "resource":
            return None

        if billing.get("resource_cost_attributed") is not True:
            return None

        cost = billing.get("claimable_resource_cost")

        if not isinstance(
            cost,
            (int, float),
        ):
            return None

        if cost <= 0:
            return None

        currency = str(billing.get("currency") or "USD")

        statements = [
            self._statement(
                name="target_count",
                value=0,
                description=("No registered targets were " "observed."),
                source=["ELB.TargetGroups.TargetHealth"],
                observed=True,
            ),
            self._statement(
                name="traffic_observed",
                value=False,
                description=(
                    "No positive ELB activity was "
                    "observed during the analysis "
                    "period."
                ),
                source=["CloudWatch"],
                observed=True,
            ),
            self._statement(
                name="observed_cost",
                value=cost,
                description=(
                    "Billing cost explicitly "
                    "attributed to this load balancer "
                    "by the reconciliation layer."
                ),
                source=[
                    "CostExplorer",
                    "Reconciliation",
                ],
                unit=currency,
                observed=True,
            ),
        ]

        return self._finding(
            context=context,
            finding_type=("elb_idle_with_cost"),
            title=("Idle load balancer with attributed cost"),
            severity="high",
            confidence="high",
            cost_optimization_type="elimination",
            reason=(
                "The load balancer has no registered "
                "targets, available activity evidence "
                "confirms zero observed activity, and "
                "the reconciliation layer explicitly "
                "attributes "
                f"{currency} {cost:,.2f} of cost to "
                "this resource during the analysis "
                "period."
            ),
            statements=statements,
            metadata={
                "category": "unused_resource",
                "finding_family": "elb_inactivity",
                "lb_type": traffic.get("lb_type"),
                "target_count": 0,
                "observed_cost": cost,
                "currency": currency,
                "cost_attribution": (billing.get("attribution_scope")),
            },
        )

    # METRIC STATEMENT HELPER

    @classmethod
    def _append_metric_statement(
        cls,
        statements: list[EvidenceStatement],
        context: AnalysisContext,
        metric_name: str,
        description: str,
        source: str,
        unit: str | None = None,
    ) -> None:

        value = cls._metric_value(
            context,
            metric_name,
        )

        if value is None:
            return

        statements.append(
            cls._statement(
                name=metric_name,
                value=value,
                description=description,
                source=[source],
                unit=unit,
                observed=True,
            )
        )

    # FINDING BUILDER

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
        statements: list[EvidenceStatement],
        metadata: dict[str, Any],
        cost_optimization_type: str = "review",
    ) -> Finding:

        metrics = context.metrics()

        metric_evidence = {
            name: context.metric_summary(name)
            for name in metrics
            if isinstance(
                metrics.get(name),
                dict,
            )
        }

        configuration = cls._configuration(context)

        filtered_configuration = {
            key: configuration.get(key)
            for key in ELB_CONFIGURATION_FIELDS
            if key in configuration
        }

        topology = context.topology()

        if not isinstance(
            topology,
            dict,
        ):
            topology = {}

        billing = context.billing()

        if not isinstance(
            billing,
            dict,
        ):
            billing = {}

        relationships = cls._relationships(context)

        collector_quality = {}

        if hasattr(
            context,
            "collector_data_quality",
        ):

            try:

                value = context.collector_data_quality()

                if isinstance(
                    value,
                    dict,
                ):

                    collector_quality = value

            except Exception:

                collector_quality = {}

        evidence = Evidence(
            metrics=metric_evidence,
            configuration=filtered_configuration,
            topology=dict(topology),
            billing=dict(billing),
            resource={
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "region": context.region,
                "load_balancer_name": (configuration.get("load_balancer_name")),
                "load_balancer_type": (configuration.get("type")),
                "scheme": configuration.get("scheme"),
            },
            derived={
                "analysis_category": metadata.get("category"),
                "finding_family": metadata.get("finding_family"),
                "relationships": relationships,
            },
            data_quality={
                **collector_quality,
                "metric_count": len(metric_evidence),
                "relationship_data_available": bool(relationships),
                "topology_available": bool(topology),
            },
        )

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=(context.resource_type or cls.DEFAULT_RESOURCE_TYPE),
            resource_id=(context.resource_id or "unknown"),
            analyzer=cls.name,
            analyzer_version=cls.version,
            severity=str(severity).lower(),
            confidence=str(confidence).lower(),
            reason=reason,
            conditions=statements,
            evidence=evidence,
            observation_period=(cls._observation_period(context)),
            metadata=metadata,
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type=(cost_optimization_type),
        )

    # EVIDENCE STATEMENT

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
            source=list(source),
            unit=unit,
            observed=observed,
        )

    # OBSERVATION PERIOD

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

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

        try:

            cloudwatch = context.cloudwatch()

        except Exception:

            cloudwatch = {}

        if not isinstance(
            cloudwatch,
            dict,
        ):
            return None

        start = cloudwatch.get("start") or cloudwatch.get("metric_start")

        end = cloudwatch.get("end") or cloudwatch.get("metric_end")

        if not start and not end:
            return None

        return ObservationPeriod(
            start=start,
            end=end,
        )
