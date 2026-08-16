"""
Elastic Load Balancer cost optimization analyzer.

Design
------
- Resource-oriented.
- Evidence-first.
- No analyzer-level aggregation.
- No fabricated savings.
- Missing telemetry never becomes zero.
- Collection errors never become valid resource state.

Supported:
- Application Load Balancer
- Network Load Balancer
- Gateway Load Balancer

The analyzer distinguishes:

    observed zero
    observed value
    unavailable
    collection failure

Only the evidence required by a particular rule is required for that rule.
"""

from __future__ import annotations

from typing import Any

from ..base import Analyzer
from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from ..metrics import metric_summary
from ..registry import register


DEFAULT_LOW_REQUESTS_PER_HOUR = 10.0
DEFAULT_LOW_PROCESSED_GIB_PER_HOUR = 0.01


def _metric(
    metrics: dict[str, Any],
    key: str,
) -> dict[str, Any] | None:

    value = metrics.get(key)

    return (
        value
        if isinstance(value, dict)
        else None
    )


def _metric_value(
    metrics: dict[str, Any],
    key: str,
) -> float | None:

    metric = _metric(
        metrics,
        key,
    )

    if not metric:
        return None

    if metric.get("status") != "ok":
        return None

    if metric.get("has_data") is not True:
        return None

    value = metric.get("value")

    if isinstance(
        value,
        (int, float),
    ):
        return float(value)

    return None


def _metric_observed(
    metrics: dict[str, Any],
    key: str,
) -> bool:

    return (
        _metric_value(
            metrics,
            key,
        )
        is not None
    )


def _metric_keys(
    metrics: dict[str, Any],
    prefix: str,
) -> list[str]:

    return [
        key
        for key in metrics
        if (
            key == prefix
            or key.startswith(
                f"{prefix}["
            )
        )
    ]


def _duration_hours(
    context: AnalysisContext,
) -> float | None:

    value = context.observation_period

    if isinstance(
        value,
        dict,
    ):

        duration = value.get(
            "duration_seconds"
        )

        if (
            isinstance(
                duration,
                (int, float),
            )
            and duration > 0
        ):

            return (
                float(duration)
                / 3600.0
            )

    cloudwatch = context.cloudwatch()

    if not isinstance(
        cloudwatch,
        dict,
    ):
        return None

    start = (
        cloudwatch.get("start")
        or cloudwatch.get("analysis_start")
    )

    end = (
        cloudwatch.get("end")
        or cloudwatch.get("analysis_end")
    )

    if not start or not end:
        return None

    try:

        from datetime import datetime

        start_dt = datetime.fromisoformat(
            str(start).replace(
                "Z",
                "+00:00",
            )
        )

        end_dt = datetime.fromisoformat(
            str(end).replace(
                "Z",
                "+00:00",
            )
        )

        seconds = (
            end_dt - start_dt
        ).total_seconds()

        if seconds <= 0:
            return None

        return (
            seconds / 3600.0
        )

    except (
        TypeError,
        ValueError,
    ):

        return None


@register
class ElbAnalyzer(Analyzer):

    name = "elb"
    version = "3.0"

    resource_type = "load_balancer"

    SUPPORTED_TYPES = {
        "application",
        "network",
        "gateway",
    }

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        if (
            context.resource_type
            != self.resource_type
        ):
            return False

        configuration = (
            context.configuration()
        )

        if not isinstance(
            configuration,
            dict,
        ):
            return True

        lb_type = (
            configuration.get(
                "type"
            )
            or configuration.get(
                "load_balancer_type"
            )
        )

        if lb_type is None:
            return True

        return (
            str(lb_type).lower()
            in self.SUPPORTED_TYPES
        )

    # ==================================================================
    # MAIN
    # ==================================================================

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(
            context
        ):
            return []

        data = self._collect_data(
            context
        )

        findings = []

        for detector in (
            self._check_no_activity,
            self._check_low_traffic,
            self._check_no_targets,
            self._check_idle_target_groups,
            self._check_no_healthy_targets,
        ):

            finding = detector(
                context,
                data,
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    # ==================================================================
    # DATA
    # ==================================================================

    def _collect_data(
        self,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        configuration = (
            context.configuration()
        )

        relationships = (
            context.resource.get(
                "relationships",
                {},
            )
        )

        topology = (
            context.topology()
        )

        observations = (
            context.observations()
        )

        metrics = context.metrics()

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        if not isinstance(
            relationships,
            dict,
        ):
            relationships = {}

        if not isinstance(
            topology,
            dict,
        ):
            topology = {}

        if not isinstance(
            observations,
            dict,
        ):
            observations = {}

        if not isinstance(
            metrics,
            dict,
        ):
            metrics = {}

        summary = relationships.get(
            "summary",
            {},
        )

        if not isinstance(
            summary,
            dict,
        ):
            summary = {}

        target_groups = (
            relationships.get(
                "target_groups"
            )
        )

        target_group_data_available = (
            isinstance(
                target_groups,
                list,
            )
        )

        if not target_group_data_available:
            target_groups = []

        request_count = _metric_value(
            metrics,
            "request_count",
        )

        processed_bytes = _metric_value(
            metrics,
            "processed_bytes",
        )

        active_connections = _metric_value(
            metrics,
            "active_connections",
        )

        new_connections = _metric_value(
            metrics,
            "new_connections",
        )

        duration_hours = (
            _duration_hours(
                context
            )
        )

        request_rate = (
            request_count / duration_hours
            if (
                request_count is not None
                and duration_hours
                and duration_hours > 0
            )
            else None
        )

        processed_gib = (
            processed_bytes
            / (1024 ** 3)
            if processed_bytes is not None
            else None
        )

        processed_gib_rate = (
            processed_gib / duration_hours
            if (
                processed_gib is not None
                and duration_hours
                and duration_hours > 0
            )
            else None
        )

        activity_core_available = (
            request_count is not None
            and processed_bytes is not None
        )

        activity_core_zero = (
            activity_core_available
            and request_count == 0
            and processed_bytes == 0
        )

        target_count = self._optional_int(
            summary.get(
                "target_count"
            )
        )

        healthy_target_count = (
            self._optional_int(
                summary.get(
                    "healthy_target_count"
                )
            )
        )

        unhealthy_target_count = (
            self._optional_int(
                summary.get(
                    "unhealthy_target_count"
                )
            )
        )

        listener_count = (
            self._optional_int(
                summary.get(
                    "listener_count"
                )
            )
        )

        referenced_target_groups = (
            self._referenced_target_groups(
                relationships
            )
        )

        target_health_complete = (
            self._target_health_complete(
                target_groups
            )
        )

        idle_target_groups = (
            self._find_idle_target_groups(
                target_groups,
                metrics,
            )
        )

        return {
            "configuration":
                configuration,

            "relationships":
                relationships,

            "topology":
                topology,

            "observations":
                observations,

            "metrics":
                metrics,

            "load_balancer_type":
                str(
                    configuration.get(
                        "type"
                    )
                    or ""
                ).lower(),

            "state":
                str(
                    configuration.get(
                        "state"
                    )
                    or ""
                ).lower(),

            "request_count":
                request_count,

            "processed_bytes":
                processed_bytes,

            "processed_gib":
                processed_gib,

            "active_connections":
                active_connections,

            "new_connections":
                new_connections,

            "duration_hours":
                duration_hours,

            "request_rate":
                request_rate,

            "processed_gib_per_hour":
                processed_gib_rate,

            "activity_core_available":
                activity_core_available,

            "activity_core_zero":
                activity_core_zero,

            "target_groups":
                target_groups,

            "target_group_data_available":
                target_group_data_available,

            "target_health_complete":
                target_health_complete,

            "target_count":
                target_count,

            "healthy_target_count":
                healthy_target_count,

            "unhealthy_target_count":
                unhealthy_target_count,

            "target_group_count":
                (
                    len(target_groups)
                    if target_group_data_available
                    else None
                ),

            "listener_count":
                listener_count,

            "referenced_target_group_ids":
                referenced_target_groups,

            "idle_target_groups":
                idle_target_groups,
        }

    # ==================================================================
    # RULE 1 — NO ACTIVITY
    # ==================================================================

    def _check_no_activity(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != "active":
            return None

        # RequestCount + ProcessedBytes are the core
        # application-traffic evidence.
        if not data[
            "activity_core_available"
        ]:
            return None

        if not data[
            "activity_core_zero"
        ]:
            return None

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
                "RequestCount and ProcessedBytes were both "
                "observed at zero throughout the analysis "
                "period."
            ),
            statements=[
                EvidenceStatement(
                    name="request_count",
                    value=data[
                        "request_count"
                    ],
                    description=(
                        "Observed load balancer request count."
                    ),
                    source=[
                        "CloudWatch.RequestCount"
                    ],
                    observed=True,
                ),
                EvidenceStatement(
                    name="processed_bytes",
                    value=data[
                        "processed_bytes"
                    ],
                    description=(
                        "Observed load balancer processed bytes."
                    ),
                    source=[
                        "CloudWatch.ProcessedBytes"
                    ],
                    observed=True,
                ),
            ],
            metadata={
                "request_count":
                    data[
                        "request_count"
                    ],

                "processed_bytes":
                    data[
                        "processed_bytes"
                    ],

                "target_count":
                    data[
                        "target_count"
                    ],
            },
            limitations=[
                (
                    "The observation window does not exclude "
                    "future, scheduled, intermittent, or "
                    "failover traffic."
                )
            ],
        )

    # ==================================================================
    # RULE 2 — LOW TRAFFIC
    # ==================================================================

    def _check_low_traffic(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        # Require both core workload metrics.
        if not data[
            "activity_core_available"
        ]:
            return None

        if data[
            "activity_core_zero"
        ]:
            return None

        request_rate = data[
            "request_rate"
        ]

        processed_rate = data[
            "processed_gib_per_hour"
        ]

        if (
            request_rate is None
            or processed_rate is None
        ):
            return None

        low_requests = (
            request_rate
            <= DEFAULT_LOW_REQUESTS_PER_HOUR
        )

        low_processed = (
            processed_rate
            <= DEFAULT_LOW_PROCESSED_GIB_PER_HOUR
        )

        if not (
            low_requests
            and low_processed
        ):
            return None

        return self._finding(
            context=context,
            finding_type=(
                "elb_low_traffic"
            ),
            title=(
                "Load balancer with low traffic"
            ),
            severity="low",
            confidence="medium",
            reason=(
                f"Observed traffic was "
                f"{request_rate:.2f} requests/hour and "
                f"{processed_rate:.6f} GiB/hour, both below "
                "the configured review thresholds."
            ),
            statements=[
                EvidenceStatement(
                    name="request_rate",
                    value={
                        "requests_per_hour":
                            request_rate,

                        "threshold":
                            DEFAULT_LOW_REQUESTS_PER_HOUR,
                    },
                    description=(
                        "Observed request rate is low."
                    ),
                    source=[
                        "CloudWatch.RequestCount",
                        "analysis observation period",
                    ],
                    observed=True,
                ),
                EvidenceStatement(
                    name="processed_traffic",
                    value={
                        "gib_per_hour":
                            processed_rate,

                        "threshold":
                            DEFAULT_LOW_PROCESSED_GIB_PER_HOUR,
                    },
                    description=(
                        "Observed processed traffic is low."
                    ),
                    source=[
                        "CloudWatch.ProcessedBytes",
                        "analysis observation period",
                    ],
                    observed=True,
                ),
            ],
            metadata={
                "request_rate_per_hour":
                    request_rate,

                "processed_gib_per_hour":
                    processed_rate,
            },
            limitations=[
                (
                    "Low traffic is a heuristic signal and "
                    "does not prove that the load balancer "
                    "can be removed."
                )
            ],
        )

    # ==================================================================
    # RULE 3 — NO TARGETS
    # ==================================================================

    def _check_no_targets(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if data["state"] != "active":
            return None

        if not data[
            "target_group_data_available"
        ]:
            return None

        if data["target_count"] is None:
            return None

        if data["target_count"] != 0:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "elb_no_registered_targets"
            ),
            title=(
                "Load balancer has no registered targets"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "The active load balancer has no registered "
                "targets in the collected target groups."
            ),
            statements=[
                EvidenceStatement(
                    name="target_groups",
                    value={
                        "count":
                            data[
                                "target_group_count"
                            ],
                    },
                    description=(
                        "Collected target-group configuration."
                    ),
                    source=[
                        "ELB target group configuration"
                    ],
                    observed=True,
                ),
                EvidenceStatement(
                    name="target_count",
                    value=0,
                    description=(
                        "No registered targets were discovered."
                    ),
                    source=[
                        "ELB target health"
                    ],
                    observed=True,
                ),
            ],
            metadata={
                "target_group_count":
                    data[
                        "target_group_count"
                    ],

                "target_count":
                    0,
            },
        )

    # ==================================================================
    # RULE 4 — IDLE TARGET GROUP
    # ==================================================================

    def _check_idle_target_groups(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data[
            "target_group_data_available"
        ]:
            return None

        if not data[
            "idle_target_groups"
        ]:
            return None

        return self._finding(
            context=context,
            finding_type=(
                "elb_idle_target_group"
            ),
            title=(
                "Target group with no observed traffic"
            ),
            severity="low",
            confidence="medium",
            reason=(
                f"{len(data['idle_target_groups'])} "
                "target group(s) had observed zero "
                "RequestCount during the analysis period."
            ),
            statements=[
                EvidenceStatement(
                    name="idle_target_groups",
                    value=data[
                        "idle_target_groups"
                    ],
                    description=(
                        "Target groups with complete zero "
                        "request observations."
                    ),
                    source=[
                        "CloudWatch.RequestCount",
                        "ELB target group configuration",
                    ],
                    observed=True,
                )
            ],
            metadata={
                "idle_target_groups":
                    data[
                        "idle_target_groups"
                    ]
            },
            limitations=[
                (
                    "The target group may serve scheduled, "
                    "intermittent, migration, or failover traffic."
                )
            ],
        )

    # ==================================================================
    # RULE 5 — NO HEALTHY TARGETS
    # ==================================================================

    def _check_no_healthy_targets(
        self,
        context: AnalysisContext,
        data: dict[str, Any],
    ) -> Finding | None:

        if not data[
            "target_group_data_available"
        ]:
            return None

        if not data[
            "target_health_complete"
        ]:
            return None

        if (
            data["target_count"] is None
            or data["target_count"] <= 0
        ):
            return None

        if (
            data["healthy_target_count"]
            is None
            or data[
                "healthy_target_count"
            ] > 0
        ):
            return None

        # This finding should not be used to infer
        # cost waste. It is primarily operational.
        return self._finding(
            context=context,
            finding_type=(
                "elb_no_healthy_targets"
            ),
            title=(
                "Load balancer has no healthy targets"
            ),
            severity="medium",
            confidence="high",
            recommendation_eligible=False,
            reason=(
                "Registered targets were collected, but none "
                "were reported healthy in the current target "
                "health snapshot."
            ),
            statements=[
                EvidenceStatement(
                    name="target_health",
                    value={
                        "target_count":
                            data[
                                "target_count"
                            ],

                        "healthy_target_count":
                            data[
                                "healthy_target_count"
                            ],

                        "unhealthy_target_count":
                            data[
                                "unhealthy_target_count"
                            ],
                    },
                    description=(
                        "Complete target-health evidence."
                    ),
                    source=[
                        "ELB target health"
                    ],
                    observed=True,
                )
            ],
            metadata={
                "target_count":
                    data[
                        "target_count"
                    ],

                "healthy_target_count":
                    data[
                        "healthy_target_count"
                    ],

                "unhealthy_target_count":
                    data[
                        "unhealthy_target_count"
                    ],
            },
            limitations=[
                (
                    "This is primarily an availability and "
                    "operational signal, not direct evidence "
                    "of a cost-saving action."
                )
            ],
        )

    # ==================================================================
    # TARGET GROUP ANALYSIS
    # ==================================================================

    def _find_idle_target_groups(
        self,
        target_groups: list[dict[str, Any]],
        metrics: dict[str, Any],
    ) -> list[dict[str, Any]]:

        results = []

        for target_group in target_groups:

            arn = target_group.get(
                "target_group_arn"
            )

            if not arn:
                continue

            dimension = (
                self._cloudwatch_target_group_dimension(
                    arn
                )
            )

            if not dimension:
                continue

            candidate_keys = [
                key
                for key in metrics
                if (
                    key.startswith(
                        "request_count["
                    )
                    and dimension in key
                )
            ]

            if not candidate_keys:
                continue

            values = [
                _metric_value(
                    metrics,
                    key,
                )
                for key in candidate_keys
            ]

            if not values:
                continue

            if not all(
                value is not None
                for value in values
            ):
                continue

            if not all(
                value == 0
                for value in values
            ):
                continue

            results.append(
                {
                    "target_group_arn":
                        arn,

                    "target_group_name":
                        target_group.get(
                            "target_group_name"
                        ),

                    "target_count":
                        target_group.get(
                            "target_count"
                        ),

                    "healthy_target_count":
                        target_group.get(
                            "healthy_target_count"
                        ),

                    "request_metric_keys":
                        candidate_keys,
                }
            )

        return results

    # ==================================================================
    # TARGET HEALTH
    # ==================================================================

    @staticmethod
    def _target_health_complete(
        target_groups: list[dict[str, Any]],
    ) -> bool:

        if not target_groups:
            return True

        for target_group in target_groups:

            status = target_group.get(
                "target_health_status"
            )

            if status != "ok":
                return False

            targets = target_group.get(
                "targets"
            )

            if not isinstance(
                targets,
                list,
            ):
                return False

            for target in targets:

                if not isinstance(
                    target,
                    dict,
                ):
                    return False

        return True

    # ==================================================================
    # RELATIONSHIPS
    # ==================================================================

    @staticmethod
    def _referenced_target_groups(
        relationships: dict[str, Any],
    ) -> set[str]:

        result = set()

        for listener in (
            relationships.get(
                "listeners",
                [],
            )
            or []
        ):

            if not isinstance(
                listener,
                dict,
            ):
                continue

            for target_group_id in (
                listener.get(
                    "default_target_group_ids",
                    [],
                )
                or []
            ):

                if target_group_id:
                    result.add(
                        str(target_group_id)
                    )

        for rule in (
            relationships.get(
                "rules",
                [],
            )
            or []
        ):

            if not isinstance(
                rule,
                dict,
            ):
                continue

            for target_group_id in (
                rule.get(
                    "target_group_ids",
                    [],
                )
                or []
            ):

                if target_group_id:
                    result.add(
                        str(target_group_id)
                    )

        return result

    # ==================================================================
    # FINDING BUILDER
    # ==================================================================

    def _finding(
        self,
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
        recommendation_eligible: bool = True,
    ) -> Finding:

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=(
                context.resource_type
                or self.resource_type
            ),
            resource_id=(
                context.resource_id
                or "unknown"
            ),
            analyzer=self.name,
            analyzer_version=self.version,
            severity=severity,
            confidence=confidence,
            reason=reason,
            conditions=statements,
            evidence=self._build_evidence(
                context,
                metadata,
            ),
            observation_period=(
                self._observation_period(
                    context
                )
            ),
            limitations=list(
                limitations
            ),
            metadata=dict(
                metadata
            ),
            recommendation_eligible=(
                recommendation_eligible
            ),
        )

    # ==================================================================
    # EVIDENCE
    # ==================================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: dict[str, Any],
    ) -> Evidence:

        configuration = context.configuration()
        metrics = context.metrics()

        return Evidence(
            metrics={
                key:
                    metric_summary(
                        metric
                    )
                for key, metric in metrics.items()
                if isinstance(
                    metric,
                    dict,
                )
            },

            configuration={
                key:
                    configuration.get(
                        key
                    )
                for key in (
                    "load_balancer_name",
                    "type",
                    "scheme",
                    "state",
                    "vpc_id",
                    "ip_address_type",
                    "availability_zone_count",
                    "subnet_count",
                )
                if key in configuration
            },

            topology=context.topology(),

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,
            },

            derived=dict(
                metadata
            ),

            data_quality={
                **context.data_quality(),

                "activity_core_available":
                    metadata.get(
                        "request_count"
                    )
                    is not None
                    and metadata.get(
                        "processed_bytes"
                    )
                    is not None,
            },
        )

    # ==================================================================
    # PERIOD
    # ==================================================================

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

        cloudwatch = context.cloudwatch()

        if not isinstance(
            cloudwatch,
            dict,
        ):
            return None

        return ObservationPeriod(
            start=(
                cloudwatch.get(
                    "start"
                )
                or cloudwatch.get(
                    "analysis_start"
                )
            ),

            end=(
                cloudwatch.get(
                    "end"
                )
                or cloudwatch.get(
                    "analysis_end"
                )
            ),
        )

    # ==================================================================
    # HELPERS
    # ==================================================================

    @staticmethod
    def _optional_int(
        value: Any,
    ) -> int | None:

        if value is None:
            return None

        try:
            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _cloudwatch_target_group_dimension(
        arn: str,
    ) -> str:

        marker = "targetgroup/"

        if marker not in arn:
            return ""

        return arn.split(
            marker,
            1,
        )[1]

