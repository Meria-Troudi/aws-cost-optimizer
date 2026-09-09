"""
Amazon RDS cost-optimization analyzer.

Primary recommendation opportunities
-------------------------------------
1. Right-size database instances.
2. Delete unused databases.
3. Remove unnecessary read replicas.
4. Purchase Reserved Instances.
5. Schedule development/test databases.

Design contract
---------------
The analyzer only produces a recommendation-eligible finding when
the collected evidence supports the corresponding optimization.

Current resource-level cost is mandatory for cost recommendations.

Historical billing, service-level billing, and collection-plan cost
are never treated as current resource cost.

The analyzer never:
- invents savings;
- invents replacement instance classes;
- claims deletion is safe;
- chooses a Reserved Instance term;
- chooses a schedule;
- chooses exact stop/start times;
- assumes production is safe to stop;
- treats historical mismatched billing as current resource cost;
- recommends changes to Aurora-specific capacity models.

Aurora capacity decisions are handled by AuroraAnalyzer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...base import Analyzer
from ...condition import EvidenceStatement
from ...context import AnalysisContext
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
from ...registry import register

DEFAULT_POLICY: dict[str, Any] = {
    "rightsizing": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "minimum_observation_days": 14.0,
        "minimum_monthly_cost": 20.0,
        "average_cpu_max_percent": 15.0,
        "maximum_cpu_max_percent": 70.0,
        "connections_max": 2.0,
        "read_iops_max": 10.0,
        "write_iops_max": 10.0,
        "read_throughput_max_bytes_per_second": 5_000_000.0,
        "write_throughput_max_bytes_per_second": 5_000_000.0,
        "require_memory_evidence": True,
        "cloudtrail": {
            "enabled": True,
            "required": True,
            "minimum_stable_days": 14.0,
            "suppress_if_recent_resize": True,
            "suppress_if_multiple_resizes": True,
            "max_resizes_in_window": 1,
            "require_class_stability": True,
        },
    },
    "unused": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "minimum_observation_days": 14.0,
        "minimum_monthly_cost": 5.0,
        "average_cpu_max_percent": 5.0,
        "maximum_cpu_max_percent": 25.0,
        "connections_max": 0.0,
        "read_iops_max": 1.0,
        "write_iops_max": 1.0,
        "require_no_child_replicas": True,
        "require_not_deletion_protected": True,
        "require_retirement_context": True,
        "suppress_if_recent_start": True,
        "recent_start_days": 3.0,
    },
    "read_replica": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "minimum_observation_days": 14.0,
        "minimum_monthly_cost": 10.0,
        "connections_max": 2.0,
        "network_receive_bytes_per_second_max": 1024.0,
        "network_transmit_bytes_per_second_max": 1024.0,
        "read_iops_max": 1.0,
        "write_iops_max": 1.0,
        "require_no_important_replica_evidence": False,
        "recommendation_eligible": True,
    },
    "reserved_instances": {
        "enabled": True,
        "minimum_observation_days": 30.0,
        "minimum_monthly_cost": 30.0,
        "minimum_metric_coverage": 0.80,
        "minimum_cpu_average_percent": 5.0,
        "require_stable_class": True,
        "minimum_stable_days": 30.0,
        "require_no_active_matching_reservation": True,
        "require_available_offering": True,
        "recommendation_eligible": True,
    },
    "scheduling": {
        "enabled": True,
        "minimum_observation_days": 14.0,
        "minimum_metric_coverage": 0.80,
        "minimum_monthly_cost": 10.0,
        "minimum_observed_days": 7,
        "minimum_off_hours_low_activity_ratio": 0.70,
        "minimum_daytime_activity_ratio": 0.40,
        "low_cpu_percent": 5.0,
        "low_connections": 0.0,
        "low_iops": 1.0,
        "maximum_metric_period_seconds": 3600,
        "recommendation_eligible": True,
    },
    "multi_az": {
        "enabled": True,
    },
    "backup_retention": {
        "enabled": True,
        "minimum_days": 14,
    },
    "performance_insights": {
        "enabled": True,
    },
    "old_generation": {
        "enabled": True,
    },
    "public_accessibility": {
        "enabled": True,
    },
    "io_pressure": {
        "enabled": True,
        "minimum_metric_coverage": 0.80,
        "high_iops": 1000.0,
    },
}

OLD_INSTANCE_FAMILIES = (
    "db.t2.",
    "db.m3.",
    "db.m4.",
    "db.r3.",
    "db.r4.",
)
TITLES = {
    "rds_instance_possible_oversized": "Right-size Database Instance — Amazon RDS",
    "rds_no_activity": "Delete Unused Database — Amazon RDS",
    "rds_underused_read_replica": "Remove Unnecessary Read Replica — Amazon RDS",
    "rds_reserved_instance_candidate": "Purchase Reserved Instance — Amazon RDS",
    "rds_dev_test_scheduling_candidate": "Schedule Dev/Test Database — Amazon RDS",
    "rds_stopped_instance": "Stopped Database — Amazon RDS",
    "rds_multi_az_cost_review": "RDS Multi-AZ Configuration",
    "rds_backup_retention_review": "RDS Backup Retention",
    "rds_performance_insights_review": "Performance Insights Configuration",
    "rds_old_instance_generation": "Older RDS Instance Generation",
    "rds_public_accessibility": "Public RDS Accessibility",
    "rds_io_pressure": "RDS I/O Capacity",
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> float | None:

    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        return float(value)

    except (
        TypeError,
        ValueError,
    ):
        return None


def _bool(value: Any) -> bool | None:

    if isinstance(value, bool):
        return value

    return None


@register
class RDSAnalyzer(Analyzer):

    name = "rds"
    version = "5.0"

    resource_type = "rds_instance"

    # SUPPORT

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        if context.resource_type not in {
            "rds_instance",
            "rds",
        }:
            return False

        # Aurora is cluster-owned and must be analyzed only by
        # AuroraAnalyzer. Reject it before any detector executes.
        if self._is_aurora(context):
            return False

        return True

    # MAIN

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        if not self._is_rds_resource(context.resource):
            return []

        findings: list[Finding] = []

        # -------------------------------------------------------------
        # COST OPPORTUNITIES
        # -------------------------------------------------------------

        if self._is_standard_rds_instance(context) and self._has_current_resource_cost(
            context
        ):

            recommendation_checks = (
                self._check_unused_database,
                self._check_oversized_instance,
                self._check_read_replica,
                self._check_reserved_instance_candidate,
                self._check_dev_test_scheduling,
            )

            for check in recommendation_checks:

                try:
                    finding = check(context)

                except Exception as exc:

                    print(
                        "[ERROR] RDS recommendation detector "
                        f"{check.__name__} failed for "
                        f"{context.resource_id}: {exc}"
                    )

                    continue

                if finding is not None:
                    findings.append(finding)

        # -------------------------------------------------------------
        # DIAGNOSTICS
        # -------------------------------------------------------------

        diagnostic_checks = (
            self._check_stopped_instance,
            self._check_multi_az,
            self._check_backup_retention,
            self._check_performance_insights,
            self._check_old_generation,
            self._check_public_accessibility,
            self._check_io_pressure,
        )

        for check in diagnostic_checks:

            try:
                finding = check(context)

            except Exception as exc:

                print(
                    "[ERROR] RDS diagnostic "
                    f"{check.__name__} failed for "
                    f"{context.resource_id}: {exc}"
                )

                continue

            if finding is not None:
                findings.append(finding)

        return findings

    # POLICY

    @classmethod
    def _policy(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        policy = {
            key: (
                dict(value)
                if isinstance(
                    value,
                    dict,
                )
                else value
            )
            for key, value in DEFAULT_POLICY.items()
        }

        resource_policy = context.resource.get(
            "analysis_policy",
            {},
        )

        if not isinstance(
            resource_policy,
            dict,
        ):
            return policy

        configured = resource_policy.get(
            "rds",
            {},
        )

        if not isinstance(
            configured,
            dict,
        ):
            return policy

        for category, values in configured.items():

            if isinstance(
                values,
                dict,
            ):

                current = policy.get(
                    category,
                    {},
                )

                if not isinstance(
                    current,
                    dict,
                ):
                    current = {}

                policy[category] = {
                    **current,
                    **values,
                }

            else:
                policy[category] = values

        return policy

    # RESOURCE

    @classmethod
    def _is_rds_resource(
        cls,
        resource: dict[str, Any],
    ) -> bool:

        if not isinstance(
            resource,
            dict,
        ):
            return False

        if (
            resource.get("resource_type")
            not in {
                "rds_instance",
                "rds",
            }
            and resource.get("type") != "rds_instance"
        ):
            return False

        engine = (
            str(
                cls._configuration(resource).get("engine")
                or resource.get("engine")
                or ""
            )
            .strip()
            .lower()
        )

        # Aurora is not a generic RDS instance from this analyzer's
        # optimization-ownership perspective.
        if engine.startswith("aurora"):
            return False

        return True

    @staticmethod
    def _configuration(
        resource: dict[str, Any],
    ) -> dict[str, Any]:

        return _dict(resource.get("configuration"))

    @classmethod
    def _engine(
        cls,
        context: AnalysisContext,
    ) -> str:

        return (
            str(cls._configuration(context.resource).get("engine") or "")
            .strip()
            .lower()
        )

    @classmethod
    def _is_aurora(
        cls,
        context: AnalysisContext,
    ) -> bool:

        return cls._engine(context).startswith("aurora")

    @classmethod
    def _is_standard_rds_instance(
        cls,
        context: AnalysisContext,
    ) -> bool:

        return not cls._is_aurora(context)

    @classmethod
    def _instance_status(
        cls,
        context: AnalysisContext,
    ) -> str:

        configuration = cls._configuration(context.resource)

        value = (
            configuration.get("status")
            or context.resource.get("status")
            or context.resource.get("DBInstanceStatus")
            or ""
        )

        return str(value).strip().lower()

    # OBSERVATIONS

    @staticmethod
    def _observations(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        value = context.observations()

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @classmethod
    def _cloudwatch(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return _dict(cls._observations(context).get("cloudwatch"))

    @classmethod
    def _cloudtrail(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return _dict(cls._observations(context).get("cloudtrail"))

    @classmethod
    def _retirement(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return _dict(cls._observations(context).get("retirement"))

    @classmethod
    def _pricing_context(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        pricing = _dict(cls._observations(context).get("pricing"))

        return _dict(pricing.get("reserved_instance_context"))

    @classmethod
    def _activity(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return _dict(cls._observations(context).get("derived"))

    # METRICS

    @staticmethod
    def _metric(
        context: AnalysisContext,
        name: str,
    ) -> dict[str, Any]:

        value = context.metric_summary(name)

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _metric_observed(
        metric: dict[str, Any],
    ) -> bool:

        if not isinstance(
            metric,
            dict,
        ):
            return False

        if metric.get("observed") is True:

            value = metric.get("value")

            if isinstance(
                value,
                (int, float),
            ):
                return True

        if metric.get("has_data") is True:

            value = (
                metric.get("average")
                if metric.get("average") is not None
                else metric.get("value")
            )

            return isinstance(
                value,
                (int, float),
            )

        return False

    @classmethod
    def _metric_average(
        cls,
        metric: dict[str, Any],
    ) -> float | None:

        if not cls._metric_observed(metric):
            return None

        value = (
            metric.get("average")
            if metric.get("average") is not None
            else metric.get("value")
        )

        return _number(value)

    @staticmethod
    def _metric_maximum(
        metric: dict[str, Any],
    ) -> float | None:

        return _number(metric.get("maximum"))

    @staticmethod
    def _metric_minimum(
        metric: dict[str, Any],
    ) -> float | None:

        return _number(metric.get("minimum"))

    @staticmethod
    def _metric_period(
        metric: dict[str, Any],
    ) -> int | None:

        for key in (
            "effective_period",
            "period",
            "requested_period",
        ):

            value = _number(metric.get(key))

            if value is not None:
                return int(value)

        return None

    @classmethod
    def _metric_coverage(
        cls,
        metric: dict[str, Any],
    ) -> float:

        ratio = _number(metric.get("coverage_ratio"))

        if ratio is not None:

            if ratio > 1:
                return ratio / 100.0

            return max(
                0.0,
                min(
                    ratio,
                    1.0,
                ),
            )

        percent = _number(metric.get("coverage_percent"))

        if percent is not None:

            return max(
                0.0,
                min(
                    percent / 100.0,
                    1.0,
                ),
            )

        return 0.0

    @classmethod
    def _metric_ready(
        cls,
        context: AnalysisContext,
        name: str,
        minimum_coverage: float,
        require_maximum: bool = False,
    ) -> bool:

        metric = cls._metric(
            context,
            name,
        )

        if not cls._metric_observed(metric):
            return False

        if cls._metric_average(metric) is None:
            return False

        if require_maximum:

            if cls._metric_maximum(metric) is None:
                return False

        return cls._metric_coverage(metric) >= minimum_coverage

    @classmethod
    def _usable_metric_set(
        cls,
        context: AnalysisContext,
        names: tuple[str, ...],
        minimum_coverage: float,
        require_maximum: bool = False,
    ) -> bool:

        return all(
            cls._metric_ready(
                context,
                name,
                minimum_coverage,
                require_maximum=require_maximum,
            )
            for name in names
        )

    # BILLING

    @staticmethod
    def _billing(
        context: AnalysisContext,
    ) -> dict[str, Any]:

        return _dict(context.billing())

    @classmethod
    def _billing_attribution(
        cls,
        context: AnalysisContext,
    ) -> tuple[str, float | None]:

        billing = cls._billing(context)

        scope = str(billing.get("attribution_scope") or "").strip().lower()

        resource_attributed = billing.get("resource_cost_attributed")

        claimable = _number(billing.get("claimable_resource_cost"))

        amount = _number(billing.get("amount"))

        # Only explicit resource attribution is acceptable.
        if (
            scope == "resource"
            and resource_attributed is True
            and claimable is not None
        ):
            return (
                "resource_attributed",
                claimable,
            )

        if scope == "resource" and resource_attributed is True and amount is not None:
            return (
                "resource_attributed",
                amount,
            )

        if scope in {
            "historical",
            "historical_resource",
        }:
            return (
                "historical",
                None,
            )

        if scope in {
            "service",
            "service_level",
        }:
            return (
                "service_level",
                None,
            )

        if scope in {
            "collection_plan",
            "plan",
        }:
            return (
                "collection_plan",
                None,
            )

        return (
            "unavailable",
            None,
        )

    @classmethod
    def _current_resource_cost(
        cls,
        context: AnalysisContext,
    ) -> float | None:

        scope, amount = cls._billing_attribution(context)

        if scope != "resource_attributed":
            return None

        if amount is None:
            return None

        if amount < 0:
            return None

        return amount

    @classmethod
    def _has_current_resource_cost(
        cls,
        context: AnalysisContext,
    ) -> bool:

        scope, amount = cls._billing_attribution(context)

        return scope == "resource_attributed" and amount is not None and amount >= 0.0

    # OBSERVATION PERIOD

    @classmethod
    def _observation_period(
        cls,
        context: AnalysisContext,
    ) -> ObservationPeriod | None:

        observation = context.observation_period

        if isinstance(
            observation,
            dict,
        ):

            return ObservationPeriod(
                start=observation.get("start"),
                end=observation.get("end"),
                duration_seconds=observation.get("duration_seconds"),
            )

        cloudwatch = cls._cloudwatch(context)

        start = (
            cloudwatch.get("analysis_start")
            or cloudwatch.get("start")
            or cloudwatch.get("metric_start")
        )

        end = (
            cloudwatch.get("analysis_end")
            or cloudwatch.get("end")
            or cloudwatch.get("metric_end")
        )

        if not start and not end:
            return None

        return ObservationPeriod(
            start=start,
            end=end,
        )

    @classmethod
    def _observation_days(
        cls,
        context: AnalysisContext,
    ) -> float | None:

        observation = cls._observation_period(context)

        if observation is None:
            return None

        start = observation.start
        end = observation.end

        if not start or not end:
            return None

        try:

            start_dt = (
                start
                if isinstance(
                    start,
                    datetime,
                )
                else datetime.fromisoformat(
                    str(start).replace(
                        "Z",
                        "+00:00",
                    )
                )
            )

            end_dt = (
                end
                if isinstance(
                    end,
                    datetime,
                )
                else datetime.fromisoformat(
                    str(end).replace(
                        "Z",
                        "+00:00",
                    )
                )
            )

            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)

            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)

            return max(
                0.0,
                (end_dt - start_dt).total_seconds() / 86400.0,
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    # CLOUDTRAIL STABILITY

    @classmethod
    def _rightsizing_history(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any]:

        policy = _dict(cls._policy(context).get("rightsizing"))

        cloudtrail_policy = _dict(policy.get("cloudtrail"))

        if not cloudtrail_policy.get(
            "enabled",
            True,
        ):

            return {
                "allowed": True,
                "status": "disabled_by_policy",
                "history": {},
                "reason": None,
            }

        history = cls._cloudtrail(context)

        status = str(
            history.get(
                "status",
                "missing",
            )
        ).lower()

        required = bool(
            cloudtrail_policy.get(
                "required",
                True,
            )
        )

        if status != "ok":

            return {
                "allowed": not required,
                "status": status,
                "history": history,
                "reason": (
                    None
                    if not required
                    else "CloudTrail resize history is unavailable."
                ),
            }

        change_count = int(
            history.get(
                "change_count",
                history.get(
                    "event_count",
                    0,
                ),
            )
            or 0
        )

        max_changes = int(
            cloudtrail_policy.get(
                "max_resizes_in_window",
                1,
            )
        )

        if (
            cloudtrail_policy.get(
                "suppress_if_multiple_resizes",
                True,
            )
            and change_count > max_changes
        ):

            return {
                "allowed": False,
                "status": status,
                "history": history,
                "reason": (
                    f"CloudTrail recorded {change_count} "
                    "instance-class changes in the "
                    "observation window."
                ),
            }

        days_since_last_change = _number(history.get("days_since_last_change"))

        minimum_stable_days = float(
            cloudtrail_policy.get(
                "minimum_stable_days",
                14.0,
            )
        )

        if (
            cloudtrail_policy.get(
                "suppress_if_recent_resize",
                True,
            )
            and days_since_last_change is not None
            and days_since_last_change < minimum_stable_days
        ):

            return {
                "allowed": False,
                "status": status,
                "history": history,
                "reason": (
                    f"The instance class changed "
                    f"{days_since_last_change:.1f} days ago."
                ),
            }

        current_class = cls._configuration(context.resource).get("instance_class")

        latest_class = history.get("last_changed_to_class")

        if (
            cloudtrail_policy.get(
                "require_class_stability",
                True,
            )
            and current_class
            and latest_class
            and str(current_class) != str(latest_class)
        ):

            return {
                "allowed": False,
                "status": status,
                "history": history,
                "reason": (
                    "The latest CloudTrail target "
                    "class differs from the current "
                    "RDS instance class."
                ),
            }

        return {
            "allowed": True,
            "status": status,
            "history": history,
            "reason": None,
        }

    # ENVIRONMENT

    @classmethod
    def _environment(
        cls,
        context: AnalysisContext,
    ) -> str | None:

        # Prefer collector-derived environment evidence.
        configuration = cls._configuration(context.resource)

        environment = _dict(configuration.get("environment"))

        direct_environment = environment.get("environment")

        if direct_environment:
            return str(direct_environment).strip().lower()

        tags = {}

        identity = context.identity()

        if isinstance(
            identity,
            dict,
        ):

            identity_tags = identity.get("tags")

            if isinstance(
                identity_tags,
                dict,
            ):
                tags = identity_tags

        if not tags:

            resource_tags = context.resource.get("tags")

            if isinstance(
                resource_tags,
                dict,
            ):
                tags = resource_tags

        for key in (
            "Environment",
            "environment",
            "Env",
            "env",
            "Stage",
            "stage",
        ):

            value = tags.get(key)

            if value:

                normalized = str(value).strip().lower()

                if normalized:
                    return normalized

        return None

    # REPLICA

    @classmethod
    def _replica_source(
        cls,
        context: AnalysisContext,
    ) -> str | None:

        configuration = cls._configuration(context.resource)

        value = configuration.get("read_replica_source") or configuration.get(
            "replica_source_identifier"
        )

        if value:
            return str(value)

        relationships = _dict(context.resource.get("relationships"))

        value = relationships.get("read_replica_source")

        if value:
            return str(value)

        return None

    @classmethod
    def _child_read_replicas(
        cls,
        context: AnalysisContext,
    ) -> list[str]:

        configuration = cls._configuration(context.resource)

        values = configuration.get("read_replica_identifiers")

        if not isinstance(
            values,
            list,
        ):

            relationships = _dict(context.resource.get("relationships"))

            values = relationships.get(
                "read_replicas",
                [],
            )

        return [str(value) for value in _list(values) if value]

    # ACTIVITY SUMMARY

    @classmethod
    def _activity_metric_summary(
        cls,
        context: AnalysisContext,
        name: str,
    ) -> dict[str, Any]:

        activity = cls._activity(context)

        metric_summary = _dict(activity.get("metric_summary"))

        return _dict(metric_summary.get(name))

    @classmethod
    def _recent_start_detected(
        cls,
        context: AnalysisContext,
        policy: dict[str, Any],
    ) -> bool:

        cloudtrail = cls._cloudtrail(context)

        last_start_at = cloudtrail.get("last_start_at")

        if not last_start_at:
            return False

        observation = cls._observation_period(context)

        if observation is None or not observation.end:
            return False

        end = observation.end

        try:

            end_dt = (
                end
                if isinstance(
                    end,
                    datetime,
                )
                else datetime.fromisoformat(
                    str(end).replace(
                        "Z",
                        "+00:00",
                    )
                )
            )

            start_dt = datetime.fromisoformat(
                str(last_start_at).replace(
                    "Z",
                    "+00:00",
                )
            )

            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)

            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)

            age_days = (end_dt - start_dt).total_seconds() / 86400.0

            return age_days >= 0 and age_days < float(
                policy.get(
                    "recent_start_days",
                    3.0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            return False

    # COST FINDING 1
    # UNUSED DATABASE

    @classmethod
    def _check_unused_database(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("unused"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        if cls._is_aurora(context):
            return None

        if cls._instance_status(context) != "available":
            return None

        current_cost = cls._current_resource_cost(context)

        if current_cost is None or current_cost < float(
            policy.get(
                "minimum_monthly_cost",
                5.0,
            )
        ):
            return None

        observation_days = cls._observation_days(context)

        if observation_days is None or observation_days < float(
            policy.get(
                "minimum_observation_days",
                14.0,
            )
        ):
            return None

        coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        required = (
            "CPUUtilization",
            "DatabaseConnections",
            "ReadIOPS",
            "WriteIOPS",
        )

        if not cls._usable_metric_set(
            context,
            required,
            coverage,
            require_maximum=True,
        ):
            return None

        cpu = cls._metric(
            context,
            "CPUUtilization",
        )

        connections = cls._metric(
            context,
            "DatabaseConnections",
        )

        read_iops = cls._metric(
            context,
            "ReadIOPS",
        )

        write_iops = cls._metric(
            context,
            "WriteIOPS",
        )

        cpu_avg = cls._metric_average(cpu)
        cpu_max = cls._metric_maximum(cpu)

        connection_avg = cls._metric_average(connections)

        read_avg = cls._metric_average(read_iops)

        write_avg = cls._metric_average(write_iops)

        if any(
            value is None
            for value in (
                cpu_avg,
                cpu_max,
                connection_avg,
                read_avg,
                write_avg,
            )
        ):
            return None

        if cpu_avg > float(
            policy.get(
                "average_cpu_max_percent",
                5.0,
            )
        ):
            return None

        if cpu_max > float(
            policy.get(
                "maximum_cpu_max_percent",
                25.0,
            )
        ):
            return None

        if connection_avg > float(
            policy.get(
                "connections_max",
                0.0,
            )
        ):
            return None

        if read_avg > float(
            policy.get(
                "read_iops_max",
                1.0,
            )
        ):
            return None

        if write_avg > float(
            policy.get(
                "write_iops_max",
                1.0,
            )
        ):
            return None

        if policy.get(
            "suppress_if_recent_start",
            True,
        ) and cls._recent_start_detected(
            context,
            policy,
        ):
            return None

        child_replicas = cls._child_read_replicas(context)

        if (
            policy.get(
                "require_no_child_replicas",
                True,
            )
            and child_replicas
        ):
            return None

        configuration = cls._configuration(context.resource)

        if (
            policy.get(
                "require_not_deletion_protected",
                True,
            )
            and configuration.get("deletion_protection") is True
        ):
            return None

        retirement = cls._retirement(context)

        if (
            policy.get(
                "require_retirement_context",
                True,
            )
            and not retirement
        ):
            return None

        environment = cls._environment(context)

        manual_snapshots = _dict(retirement.get("manual_snapshots"))

        automated_backups = _dict(retirement.get("automated_backups"))

        cloudtrail = cls._cloudtrail(context)

        statements = [
            cls._cost_statement(current_cost),
            cls._statement(
                "cpu",
                {
                    "average_percent": round(
                        cpu_avg,
                        2,
                    ),
                    "maximum_percent": round(
                        cpu_max,
                        2,
                    ),
                },
                "CPU utilization remained very low during the observation period.",
                ["CloudWatch.CPUUtilization"],
            ),
            cls._statement(
                "database_connections",
                round(
                    connection_avg,
                    2,
                ),
                "Observed database connections remained at or near zero.",
                ["CloudWatch.DatabaseConnections"],
            ),
            cls._statement(
                "io",
                {
                    "read_iops": round(
                        read_avg,
                        2,
                    ),
                    "write_iops": round(
                        write_avg,
                        2,
                    ),
                },
                "Observed database I/O remained very low.",
                [
                    "CloudWatch.ReadIOPS",
                    "CloudWatch.WriteIOPS",
                ],
            ),
            cls._statement(
                "environment",
                environment,
                "Environment classification available for retirement review.",
                ["RDS tags"],
            ),
            cls._statement(
                "retirement_context",
                {
                    "manual_snapshot_count": manual_snapshots.get(
                        "manual_snapshot_count",
                        manual_snapshots.get(
                            "snapshot_count",
                            0,
                        ),
                    ),
                    "automated_backup_count": automated_backups.get(
                        "backup_count",
                        0,
                    ),
                    "deletion_protection": configuration.get("deletion_protection"),
                },
                "Snapshot and backup context is exposed before a retirement decision.",
                [
                    "RDS.DescribeDBSnapshots",
                    "RDS.DescribeDBInstanceAutomatedBackups",
                    "RDS configuration",
                ],
            ),
        ]

        if cloudtrail:
            statements.append(
                cls._statement(
                    "lifecycle",
                    {
                        "start_count": cloudtrail.get(
                            "start_count",
                            0,
                        ),
                        "stop_count": cloudtrail.get(
                            "stop_count",
                            0,
                        ),
                        "last_start_at": cloudtrail.get("last_start_at"),
                        "last_stop_at": cloudtrail.get("last_stop_at"),
                    },
                    "RDS lifecycle activity was checked before classifying the database as unused.",
                    ["CloudTrail"],
                )
            )

        return cls._build_finding(
            context=context,
            finding_type="rds_no_activity",
            title=TITLES["rds_no_activity"],
            severity="high",
            confidence="high",
            reason=(
                f"The RDS instance has approximately "
                f"${current_cost:,.2f} of current "
                "resource-attributed monthly cost and "
                "shows sustained near-zero workload over "
                f"{observation_days:.0f} days. Review "
                "whether the database is still required "
                "before retiring it."
            ),
            statements=statements,
            metadata={
                "category": "unused_resource",
                "optimization": "delete_unused_database",
                "current_monthly_resource_cost": current_cost,
                "observation_days": observation_days,
                "instance_class": configuration.get("instance_class"),
                "engine": configuration.get("engine"),
                "environment": environment,
                "cpu_average_percent": cpu_avg,
                "cpu_maximum_percent": cpu_max,
                "database_connections": connection_avg,
                "read_iops": read_avg,
                "write_iops": write_avg,
                "child_read_replica_count": len(child_replicas),
                "manual_snapshot_count": manual_snapshots.get(
                    "manual_snapshot_count",
                    manual_snapshots.get(
                        "snapshot_count",
                        0,
                    ),
                ),
                "automated_backup_count": automated_backups.get(
                    "backup_count",
                    0,
                ),
            },
            recommendation_eligible=True,
            # Deleting the instance ends 100% of its current
            # resource-attributed cost -- a math fact, not a claim
            # that deletion is safe (limitations/never_invent still
            # forbid asserting that).
            cost_optimization_type="elimination",
        )

    # COST FINDING 2
    # RIGHT-SIZING

    @classmethod
    def _check_oversized_instance(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("rightsizing"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        if cls._is_aurora(context):
            return None

        if cls._instance_status(context) != "available":
            return None

        current_cost = cls._current_resource_cost(context)

        if current_cost is None or current_cost < float(
            policy.get(
                "minimum_monthly_cost",
                20.0,
            )
        ):
            return None

        observation_days = cls._observation_days(context)

        if observation_days is None or observation_days < float(
            policy.get(
                "minimum_observation_days",
                14.0,
            )
        ):
            return None

        history_guard = cls._rightsizing_history(context)

        if not history_guard.get("allowed"):
            return None

        coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        required = (
            "CPUUtilization",
            "DatabaseConnections",
            "ReadIOPS",
            "WriteIOPS",
            "ReadThroughput",
            "WriteThroughput",
        )

        if not cls._usable_metric_set(
            context,
            required,
            coverage,
            require_maximum=True,
        ):
            return None

        if policy.get(
            "require_memory_evidence",
            True,
        ):

            memory_metric = cls._metric(
                context,
                "FreeableMemory",
            )

            if not cls._metric_ready(
                context,
                "FreeableMemory",
                coverage,
            ):
                return None

        else:
            memory_metric = {}

        cpu = cls._metric(
            context,
            "CPUUtilization",
        )

        connections = cls._metric(
            context,
            "DatabaseConnections",
        )

        read_iops = cls._metric(
            context,
            "ReadIOPS",
        )

        write_iops = cls._metric(
            context,
            "WriteIOPS",
        )

        read_throughput = cls._metric(
            context,
            "ReadThroughput",
        )

        write_throughput = cls._metric(
            context,
            "WriteThroughput",
        )

        cpu_avg = cls._metric_average(cpu)

        cpu_max = cls._metric_maximum(cpu)

        connection_avg = cls._metric_average(connections)

        connection_max = cls._metric_maximum(connections)

        read_iops_avg = cls._metric_average(read_iops)

        write_iops_avg = cls._metric_average(write_iops)

        read_throughput_avg = cls._metric_average(read_throughput)

        write_throughput_avg = cls._metric_average(write_throughput)

        if any(
            value is None
            for value in (
                cpu_avg,
                cpu_max,
                connection_avg,
                read_iops_avg,
                write_iops_avg,
                read_throughput_avg,
                write_throughput_avg,
            )
        ):
            return None

        idle_policy = _dict(cls._policy(context).get("unused"))

        idle_metrics = {
            "cpu_average": cpu_avg,
            "cpu_maximum": cpu_max,
            "connections": connection_avg,
            "read_iops": read_iops_avg,
            "write_iops": write_iops_avg,
        }

        if (
            cpu_avg
            <= float(
                idle_policy.get(
                    "average_cpu_max_percent",
                    5.0,
                )
            )
            and cpu_max
            <= float(
                idle_policy.get(
                    "maximum_cpu_max_percent",
                    25.0,
                )
            )
            and connection_avg
            <= float(
                idle_policy.get(
                    "connections_max",
                    0.0,
                )
            )
            and read_iops_avg
            <= float(
                idle_policy.get(
                    "read_iops_max",
                    1.0,
                )
            )
            and write_iops_avg
            <= float(
                idle_policy.get(
                    "write_iops_max",
                    1.0,
                )
            )
        ):
            return None

        if cpu_avg > float(
            policy.get(
                "average_cpu_max_percent",
                15.0,
            )
        ):
            return None

        if cpu_max > float(
            policy.get(
                "maximum_cpu_max_percent",
                70.0,
            )
        ):
            return None

        if connection_avg > float(
            policy.get(
                "connections_max",
                2.0,
            )
        ):
            return None

        if read_iops_avg > float(
            policy.get(
                "read_iops_max",
                10.0,
            )
        ) or write_iops_avg > float(
            policy.get(
                "write_iops_max",
                10.0,
            )
        ):
            return None

        if read_throughput_avg > float(
            policy.get(
                "read_throughput_max_bytes_per_second",
                5_000_000.0,
            )
        ) or write_throughput_avg > float(
            policy.get(
                "write_throughput_max_bytes_per_second",
                5_000_000.0,
            )
        ):
            return None

        configuration = cls._configuration(context.resource)

        instance_class = configuration.get("instance_class") or "current instance"

        freeable_memory_avg = (
            cls._metric_average(memory_metric) if memory_metric else None
        )

        freeable_memory_max = (
            cls._metric_maximum(memory_metric) if memory_metric else None
        )

        statements = [
            cls._cost_statement(current_cost),
            cls._rightsizing_history_statement(context),
            cls._statement(
                "cpu",
                {
                    "average_percent": round(
                        cpu_avg,
                        2,
                    ),
                    "maximum_percent": round(
                        cpu_max,
                        2,
                    ),
                },
                "CPU utilization remained below the configured rightsizing review limits.",
                ["CloudWatch.CPUUtilization"],
            ),
            cls._statement(
                "connections",
                {
                    "average": round(
                        connection_avg,
                        2,
                    ),
                    "maximum": (
                        round(
                            connection_max,
                            2,
                        )
                        if connection_max is not None
                        else None
                    ),
                },
                "Database connection pressure remained low.",
                ["CloudWatch.DatabaseConnections"],
            ),
            cls._statement(
                "io",
                {
                    "read_iops": round(
                        read_iops_avg,
                        2,
                    ),
                    "write_iops": round(
                        write_iops_avg,
                        2,
                    ),
                },
                "Read and write I/O remained low.",
                [
                    "CloudWatch.ReadIOPS",
                    "CloudWatch.WriteIOPS",
                ],
            ),
            cls._statement(
                "throughput",
                {
                    "read_bytes_per_second": round(
                        read_throughput_avg,
                        2,
                    ),
                    "write_bytes_per_second": round(
                        write_throughput_avg,
                        2,
                    ),
                },
                "Read and write throughput remained low.",
                [
                    "CloudWatch.ReadThroughput",
                    "CloudWatch.WriteThroughput",
                ],
            ),
            cls._statement(
                "memory",
                {
                    "average_freeable_bytes": (
                        round(
                            freeable_memory_avg,
                            2,
                        )
                        if freeable_memory_avg is not None
                        else None
                    ),
                    "maximum_freeable_bytes": (
                        round(
                            freeable_memory_max,
                            2,
                        )
                        if freeable_memory_max is not None
                        else None
                    ),
                },
                "Freeable memory evidence was collected. It is exposed as a capacity guard but is not converted into a hard class recommendation.",
                ["CloudWatch.FreeableMemory"],
            ),
        ]

        return cls._build_finding(
            context=context,
            finding_type="rds_instance_possible_oversized",
            title=TITLES["rds_instance_possible_oversized"],
            severity="high",
            confidence="high",
            reason=(
                f"The {instance_class} RDS instance has "
                f"approximately ${current_cost:,.2f} of "
                "current resource-attributed monthly cost "
                "and shows sustained low CPU, connection, "
                "I/O, and throughput pressure over "
                f"{observation_days:.0f} days. A smaller "
                "compatible configuration should be evaluated."
            ),
            statements=statements,
            metadata={
                "category": "rightsizing",
                "optimization": "rightsize_database_instance",
                "current_monthly_resource_cost": current_cost,
                "observation_days": observation_days,
                "instance_class": instance_class,
                "engine": configuration.get("engine"),
                **idle_metrics,
                "read_throughput_bytes_per_second": read_throughput_avg,
                "write_throughput_bytes_per_second": write_throughput_avg,
                "freeable_memory_average_bytes": freeable_memory_avg,
                "freeable_memory_maximum_bytes": freeable_memory_max,
                "cloudtrail_resize_change_count": cls._cloudtrail(context).get(
                    "change_count",
                    0,
                ),
            },
            recommendation_eligible=True,
        )

    # COST FINDING 3
    # READ REPLICA

    @classmethod
    def _check_read_replica(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("read_replica"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        if cls._is_aurora(context):
            return None

        source_identifier = cls._replica_source(context)

        if not source_identifier:
            return None

        if cls._instance_status(context) != "available":
            return None

        current_cost = cls._current_resource_cost(context)

        if current_cost is None or current_cost < float(
            policy.get(
                "minimum_monthly_cost",
                10.0,
            )
        ):
            return None

        observation_days = cls._observation_days(context)

        if observation_days is None or observation_days < float(
            policy.get(
                "minimum_observation_days",
                14.0,
            )
        ):
            return None

        coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        required = (
            "DatabaseConnections",
            "NetworkReceiveThroughput",
            "NetworkTransmitThroughput",
            "ReadIOPS",
            "WriteIOPS",
        )

        if not cls._usable_metric_set(
            context,
            required,
            coverage,
        ):
            return None

        connections = cls._metric_average(
            cls._metric(
                context,
                "DatabaseConnections",
            )
        )

        network_rx = cls._metric_average(
            cls._metric(
                context,
                "NetworkReceiveThroughput",
            )
        )

        network_tx = cls._metric_average(
            cls._metric(
                context,
                "NetworkTransmitThroughput",
            )
        )

        read_iops = cls._metric_average(
            cls._metric(
                context,
                "ReadIOPS",
            )
        )

        write_iops = cls._metric_average(
            cls._metric(
                context,
                "WriteIOPS",
            )
        )

        if any(
            value is None
            for value in (
                connections,
                network_rx,
                network_tx,
                read_iops,
                write_iops,
            )
        ):
            return None

        if connections > float(
            policy.get(
                "connections_max",
                2.0,
            )
        ):
            return None

        if network_rx > float(
            policy.get(
                "network_receive_bytes_per_second_max",
                1024.0,
            )
        ) or network_tx > float(
            policy.get(
                "network_transmit_bytes_per_second_max",
                1024.0,
            )
        ):
            return None

        if read_iops > float(
            policy.get(
                "read_iops_max",
                1.0,
            )
        ) or write_iops > float(
            policy.get(
                "write_iops_max",
                1.0,
            )
        ):
            return None

        configuration = cls._configuration(context.resource)

        return cls._build_finding(
            context=context,
            finding_type="rds_underused_read_replica",
            title=TITLES["rds_underused_read_replica"],
            severity="high",
            confidence="high",
            reason=(
                f"The RDS read replica has approximately "
                f"${current_cost:,.2f} of current "
                "resource-attributed monthly cost and "
                "shows sustained low connection, I/O, and "
                "network workload over "
                f"{observation_days:.0f} days. Review "
                "whether the replica is still required."
            ),
            statements=[
                cls._cost_statement(current_cost),
                cls._statement(
                    "replica_source",
                    source_identifier,
                    "Source RDS instance for this read replica.",
                    ["RDS configuration"],
                ),
                cls._statement(
                    "database_connections",
                    round(
                        connections,
                        2,
                    ),
                    "Observed replica connections remained low.",
                    ["CloudWatch.DatabaseConnections"],
                ),
                cls._statement(
                    "network",
                    {
                        "receive_bytes_per_second": round(
                            network_rx,
                            2,
                        ),
                        "transmit_bytes_per_second": round(
                            network_tx,
                            2,
                        ),
                    },
                    "Observed replica network activity remained low.",
                    [
                        "CloudWatch.NetworkReceiveThroughput",
                        "CloudWatch.NetworkTransmitThroughput",
                    ],
                ),
                cls._statement(
                    "io",
                    {
                        "read_iops": round(
                            read_iops,
                            2,
                        ),
                        "write_iops": round(
                            write_iops,
                            2,
                        ),
                    },
                    "Observed replica I/O remained low.",
                    [
                        "CloudWatch.ReadIOPS",
                        "CloudWatch.WriteIOPS",
                    ],
                ),
            ],
            metadata={
                "category": "replica_utilization",
                "optimization": "remove_unnecessary_read_replica",
                "current_monthly_resource_cost": current_cost,
                "observation_days": observation_days,
                "replica_source": source_identifier,
                "instance_class": configuration.get("instance_class"),
                "database_connections": connections,
                "network_receive_bytes_per_second": network_rx,
                "network_transmit_bytes_per_second": network_tx,
                "read_iops": read_iops,
                "write_iops": write_iops,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
        )

    # COST FINDING 4
    # RESERVED INSTANCE

    @classmethod
    def _check_reserved_instance_candidate(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("reserved_instances"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        if cls._is_aurora(context):
            return None

        if cls._instance_status(context) != "available":
            return None

        current_cost = cls._current_resource_cost(context)

        if current_cost is None or current_cost < float(
            policy.get(
                "minimum_monthly_cost",
                30.0,
            )
        ):
            return None

        observation_days = cls._observation_days(context)

        if observation_days is None or observation_days < float(
            policy.get(
                "minimum_observation_days",
                30.0,
            )
        ):
            return None

        coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        if not cls._metric_ready(
            context,
            "CPUUtilization",
            coverage,
        ):
            return None

        cpu_avg = cls._metric_average(
            cls._metric(
                context,
                "CPUUtilization",
            )
        )

        if cpu_avg is None:
            return None

        if cpu_avg < float(
            policy.get(
                "minimum_cpu_average_percent",
                5.0,
            )
        ):
            # Extremely low utilization may indicate that rightsizing
            # or retirement should be evaluated before commitment.
            return None

        history = cls._cloudtrail(context)

        history_status = str(
            history.get(
                "status",
                "missing",
            )
        ).lower()

        change_count = int(
            history.get(
                "change_count",
                history.get(
                    "event_count",
                    0,
                ),
            )
            or 0
        )

        if (
            policy.get(
                "require_stable_class",
                True,
            )
            and history_status != "ok"
        ):
            return None

        if change_count > 1:
            return None

        stable_days = _number(history.get("days_since_last_change"))

        if (
            policy.get(
                "require_stable_class",
                True,
            )
            and stable_days is not None
            and stable_days
            < float(
                policy.get(
                    "minimum_stable_days",
                    30.0,
                )
            )
        ):
            return None

        pricing = cls._pricing_context(context)

        if not pricing:
            return None

        if (
            policy.get(
                "require_no_active_matching_reservation",
                True,
            )
            and (_number(pricing.get("active_reservation_units")) or 0.0) > 0
        ):
            return None

        if (
            policy.get(
                "require_available_offering",
                True,
            )
            and int(
                pricing.get(
                    "available_offering_count",
                    0,
                )
                or 0
            )
            <= 0
        ):
            return None

        configuration = cls._configuration(context.resource)

        instance_class = configuration.get("instance_class")

        engine = configuration.get("engine")

        multi_az = _dict(configuration.get("deployment")).get("multi_az")

        return cls._build_finding(
            context=context,
            finding_type="rds_reserved_instance_candidate",
            title=TITLES["rds_reserved_instance_candidate"],
            severity="medium",
            confidence="high",
            reason=(
                f"The RDS instance has approximately "
                f"${current_cost:,.2f} of current "
                "resource-attributed monthly cost, "
                f"has been observed for {observation_days:.0f} "
                "days, has no active matching reservation, "
                "and has compatible Reserved DB Instance "
                "offering evidence. Evaluate a Reserved "
                "Instance for the steady-state workload."
            ),
            statements=[
                cls._cost_statement(current_cost),
                cls._statement(
                    "instance_class",
                    instance_class,
                    "Current RDS instance class.",
                    ["RDS configuration"],
                ),
                cls._statement(
                    "engine",
                    engine,
                    "Current RDS database engine.",
                    ["RDS configuration"],
                ),
                cls._statement(
                    "multi_az",
                    multi_az,
                    "Current deployment mode.",
                    ["RDS configuration"],
                ),
                cls._statement(
                    "cpu_average_percent",
                    round(
                        cpu_avg,
                        2,
                    ),
                    "Observed workload utilization for commitment review.",
                    ["CloudWatch.CPUUtilization"],
                ),
                cls._statement(
                    "reserved_instance_context",
                    pricing,
                    "Existing reservations and available offering evidence.",
                    [
                        "RDS.DescribeReservedDBInstances",
                        "RDS.DescribeReservedDBInstancesOfferings",
                    ],
                ),
            ],
            metadata={
                "category": "commitment",
                "optimization": "purchase_reserved_instance",
                "current_monthly_resource_cost": current_cost,
                "observation_days": observation_days,
                "instance_class": instance_class,
                "engine": engine,
                "multi_az": multi_az,
                "cpu_average_percent": cpu_avg,
                "active_matching_reservation_units": pricing.get(
                    "active_reservation_units",
                    0,
                ),
                "available_offering_count": pricing.get(
                    "available_offering_count",
                    0,
                ),
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
        )

    # COST FINDING 5
    # DEV / TEST SCHEDULING

    @classmethod
    def _check_dev_test_scheduling(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("scheduling"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        if cls._is_aurora(context):
            return None

        if cls._instance_status(context) != "available":
            return None

        environment = cls._environment(context)

        if environment not in {
            "dev",
            "development",
            "test",
            "testing",
            "qa",
            "staging",
            "sandbox",
            "nonprod",
            "non-production",
            "preprod",
        }:
            return None

        current_cost = cls._current_resource_cost(context)

        if current_cost is None or current_cost < float(
            policy.get(
                "minimum_monthly_cost",
                10.0,
            )
        ):
            return None

        observation_days = cls._observation_days(context)

        if observation_days is None or observation_days < float(
            policy.get(
                "minimum_observation_days",
                14.0,
            )
        ):
            return None

        pattern = cls._scheduling_pattern(context)

        if pattern is None:
            return None

        return cls._build_finding(
            context=context,
            finding_type="rds_dev_test_scheduling_candidate",
            title=TITLES["rds_dev_test_scheduling_candidate"],
            severity="medium",
            confidence="high",
            reason=(
                f"The RDS instance is classified as "
                f"{environment}, has approximately "
                f"${current_cost:,.2f} of current "
                "resource-attributed monthly cost, and "
                "shows recurring low-activity periods. "
                "Evaluate automated scheduling."
            ),
            statements=[
                cls._cost_statement(current_cost),
                cls._statement(
                    "environment",
                    environment,
                    "Non-production environment classification derived from tags or collector evidence.",
                    ["RDS tags"],
                ),
                cls._statement(
                    "activity_pattern",
                    pattern,
                    "Observed activity pattern used to identify scheduling potential.",
                    ["CloudWatch"],
                ),
            ],
            metadata={
                "category": "scheduling",
                "optimization": "schedule_dev_test_database",
                "current_monthly_resource_cost": current_cost,
                "environment": environment,
                "observation_days": observation_days,
                **pattern,
            },
            recommendation_eligible=bool(
                policy.get(
                    "recommendation_eligible",
                    True,
                )
            ),
        )

    # SCHEDULING PATTERN

    @classmethod
    def _scheduling_pattern(
        cls,
        context: AnalysisContext,
    ) -> dict[str, Any] | None:

        policy = _dict(cls._policy(context).get("scheduling"))

        metric_names = (
            "CPUUtilization",
            "DatabaseConnections",
            "ReadIOPS",
            "WriteIOPS",
        )

        metrics: dict[
            str,
            dict[str, Any],
        ] = {}

        for name in metric_names:

            metric = cls._metric(
                context,
                name,
            )

            if not cls._metric_observed(metric):
                return None

            coverage = cls._metric_coverage(metric)

            if coverage < float(
                policy.get(
                    "minimum_metric_coverage",
                    0.80,
                )
            ):
                return None

            period = cls._metric_period(metric)

            if period is not None and period > int(
                policy.get(
                    "maximum_metric_period_seconds",
                    3600,
                )
            ):
                return None

            metrics[name] = metric

        cpu_points = cls._raw_points(metrics["CPUUtilization"])

        connection_points = cls._raw_points(metrics["DatabaseConnections"])

        read_points = cls._raw_points(metrics["ReadIOPS"])

        write_points = cls._raw_points(metrics["WriteIOPS"])

        if not (cpu_points and connection_points and read_points and write_points):
            return None

        points_by_timestamp: dict[
            str,
            dict[str, float],
        ] = {}

        for metric_name, points in (
            (
                "cpu",
                cpu_points,
            ),
            (
                "connections",
                connection_points,
            ),
            (
                "read_iops",
                read_points,
            ),
            (
                "write_iops",
                write_points,
            ),
        ):

            for point in points:

                timestamp = point.get("timestamp")

                value = _number(point.get("value"))

                if not timestamp or value is None:
                    continue

                bucket = points_by_timestamp.setdefault(
                    str(timestamp),
                    {},
                )

                bucket[metric_name] = value

        if not points_by_timestamp:
            return None

        off_hours_total = 0
        off_hours_low = 0

        daytime_total = 0
        daytime_active = 0

        observed_dates: set[str] = set()

        for timestamp, values in points_by_timestamp.items():

            if len(values) < 4:
                continue

            try:

                parsed = datetime.fromisoformat(
                    timestamp.replace(
                        "Z",
                        "+00:00",
                    )
                )

            except (
                TypeError,
                ValueError,
            ):
                continue

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            else:
                parsed = parsed.astimezone(timezone.utc)

            observed_dates.add(parsed.date().isoformat())

            cpu_value = values.get("cpu")

            connection_value = values.get("connections")

            read_value = values.get("read_iops")

            write_value = values.get("write_iops")

            if any(
                value is None
                for value in (
                    cpu_value,
                    connection_value,
                    read_value,
                    write_value,
                )
            ):
                continue

            low = (
                cpu_value
                <= float(
                    policy.get(
                        "low_cpu_percent",
                        5.0,
                    )
                )
                and connection_value
                <= float(
                    policy.get(
                        "low_connections",
                        0.0,
                    )
                )
                and read_value
                <= float(
                    policy.get(
                        "low_iops",
                        1.0,
                    )
                )
                and write_value
                <= float(
                    policy.get(
                        "low_iops",
                        1.0,
                    )
                )
            )
            is_off_hours = parsed.hour < 7 or parsed.hour >= 19

            if is_off_hours:

                off_hours_total += 1

                if low:
                    off_hours_low += 1

            else:

                daytime_total += 1

                if not low:
                    daytime_active += 1

        minimum_days = int(
            policy.get(
                "minimum_observed_days",
                7,
            )
        )

        if len(observed_dates) < minimum_days:
            return None

        if off_hours_total == 0:
            return None

        off_hours_ratio = off_hours_low / off_hours_total

        daytime_activity_ratio = (
            daytime_active / daytime_total if daytime_total else 0.0
        )

        if off_hours_ratio < float(
            policy.get(
                "minimum_off_hours_low_activity_ratio",
                0.70,
            )
        ):
            return None

        if daytime_activity_ratio < float(
            policy.get(
                "minimum_daytime_activity_ratio",
                0.40,
            )
        ):
            return None

        return {
            "observed_days": len(observed_dates),
            "off_hours_low_activity_ratio": round(
                off_hours_ratio,
                3,
            ),
            "daytime_activity_ratio": round(
                daytime_activity_ratio,
                3,
            ),
            "off_hours_sample_count": off_hours_total,
            "daytime_sample_count": daytime_total,
            "pattern": "recurring_off_hours_low_activity",
            "timezone_assumption": "UTC",
        }

    @staticmethod
    def _raw_points(
        metric: dict[str, Any],
    ) -> list[dict[str, Any]]:

        raw = metric.get(
            "raw_datapoints",
            [],
        )

        if not isinstance(
            raw,
            list,
        ):
            return []

        return [
            point
            for point in raw
            if isinstance(
                point,
                dict,
            )
        ]

    # DIAGNOSTIC: STOPPED

    @classmethod
    def _check_stopped_instance(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        if cls._instance_status(context) != "stopped":
            return None

        configuration = cls._configuration(context.resource)

        retirement = cls._retirement(context)

        return cls._build_finding(
            context=context,
            finding_type="rds_stopped_instance",
            title=TITLES["rds_stopped_instance"],
            severity="medium",
            confidence="high",
            reason=(
                "The RDS instance is currently stopped. "
                "Review whether the database is still "
                "required or should be permanently retired."
            ),
            statements=[
                cls._statement(
                    "status",
                    "stopped",
                    "Current RDS instance state.",
                    ["RDS configuration"],
                ),
                cls._statement(
                    "instance_class",
                    configuration.get("instance_class"),
                    "Configured DB instance class.",
                    ["RDS configuration"],
                ),
                cls._statement(
                    "retirement_context",
                    {
                        "environment": cls._environment(context),
                        "manual_snapshot_count": _dict(
                            retirement.get("manual_snapshots")
                        ).get(
                            "snapshot_count",
                            0,
                        ),
                        "automated_backup_count": _dict(
                            retirement.get("automated_backups")
                        ).get(
                            "backup_count",
                            0,
                        ),
                    },
                    "Backup, snapshot, and environment evidence available for retirement review.",
                    [
                        "RDS",
                        "CloudTrail",
                    ],
                ),
            ],
            metadata={
                "category": "unused_resource",
                "status": "stopped",
                "instance_class": configuration.get("instance_class"),
                "engine": configuration.get("engine"),
                "environment": cls._environment(context),
            },
            recommendation_eligible=False,
        )

    @classmethod
    def _check_multi_az(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("multi_az"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        deployment = _dict(cls._configuration(context.resource).get("deployment"))

        if deployment.get("multi_az") is not True:
            return None

        return cls._build_finding(
            context=context,
            finding_type="rds_multi_az_cost_review",
            title=TITLES["rds_multi_az_cost_review"],
            severity="info",
            confidence="high",
            reason=(
                "Multi-AZ is enabled. Review whether the "
                "current availability requirement justifies "
                "the additional deployment cost."
            ),
            statements=[
                cls._statement(
                    "multi_az",
                    True,
                    "Multi-AZ is enabled.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category": "configuration_review",
                "multi_az": True,
            },
            recommendation_eligible=False,
        )

    @classmethod
    def _check_backup_retention(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("backup_retention"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        backup = _dict(cls._configuration(context.resource).get("backup"))

        retention = _number(backup.get("backup_retention_days"))

        if retention is None:
            return None

        minimum = int(
            policy.get(
                "minimum_days",
                14,
            )
        )

        if retention <= minimum:
            return None

        return cls._build_finding(
            context=context,
            finding_type="rds_backup_retention_review",
            title=TITLES["rds_backup_retention_review"],
            severity="low",
            confidence="high",
            reason=(f"Backup retention is configured for " f"{int(retention)} days."),
            statements=[
                cls._statement(
                    "backup_retention_days",
                    int(retention),
                    "Configured backup retention period.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category": "backup_configuration",
                "backup_retention_days": int(retention),
            },
            recommendation_eligible=False,
        )

    @classmethod
    def _check_performance_insights(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("performance_insights"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        performance = _dict(cls._configuration(context.resource).get("performance"))

        if performance.get("performance_insights_enabled") is not True:
            return None

        return cls._build_finding(
            context=context,
            finding_type="rds_performance_insights_review",
            title=TITLES["rds_performance_insights_review"],
            severity="info",
            confidence="high",
            reason=(
                "Performance Insights is enabled. "
                "Review whether the monitoring capability "
                "is still required."
            ),
            statements=[
                cls._statement(
                    "performance_insights_enabled",
                    True,
                    "Performance Insights is enabled.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category": "configuration_review",
            },
            recommendation_eligible=False,
        )

    @classmethod
    def _check_old_generation(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("old_generation"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        instance_class = cls._configuration(context.resource).get("instance_class")

        if not instance_class:
            return None

        if not any(
            str(instance_class).startswith(family) for family in OLD_INSTANCE_FAMILIES
        ):
            return None

        return cls._build_finding(
            context=context,
            finding_type="rds_old_instance_generation",
            title=TITLES["rds_old_instance_generation"],
            severity="low",
            confidence="high",
            reason=(
                f"{instance_class} belongs to an older "
                "RDS instance generation. Review newer "
                "compatible generations."
            ),
            statements=[
                cls._statement(
                    "instance_class",
                    instance_class,
                    "Current RDS instance class.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category": "generation_review",
                "instance_class": instance_class,
            },
            recommendation_eligible=False,
        )

    # DIAGNOSTIC: PUBLIC ACCESS

    @classmethod
    def _check_public_accessibility(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("public_accessibility"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        network = _dict(cls._configuration(context.resource).get("network"))

        if network.get("publicly_accessible") is not True:
            return None

        return cls._build_finding(
            context=context,
            finding_type="rds_public_accessibility",
            title=TITLES["rds_public_accessibility"],
            severity="low",
            confidence="high",
            reason=(
                "The RDS instance is publicly accessible. "
                "Review whether public accessibility is required."
            ),
            statements=[
                cls._statement(
                    "publicly_accessible",
                    True,
                    "RDS public accessibility is enabled.",
                    ["RDS configuration"],
                )
            ],
            metadata={
                "category": "security_review",
            },
            recommendation_eligible=False,
        )

    @classmethod
    def _check_io_pressure(
        cls,
        context: AnalysisContext,
    ) -> Finding | None:

        policy = _dict(cls._policy(context).get("io_pressure"))

        if not policy.get(
            "enabled",
            True,
        ):
            return None

        coverage = float(
            policy.get(
                "minimum_metric_coverage",
                0.80,
            )
        )

        if not cls._usable_metric_set(
            context,
            (
                "ReadIOPS",
                "WriteIOPS",
            ),
            coverage,
        ):
            return None

        read_value = cls._metric_average(
            cls._metric(
                context,
                "ReadIOPS",
            )
        )

        write_value = cls._metric_average(
            cls._metric(
                context,
                "WriteIOPS",
            )
        )

        if read_value is None or write_value is None:
            return None

        total = read_value + write_value

        threshold = float(
            policy.get(
                "high_iops",
                1000.0,
            )
        )

        if total < threshold:
            return None

        return cls._build_finding(
            context=context,
            finding_type="rds_io_pressure",
            title=TITLES["rds_io_pressure"],
            severity="medium",
            confidence="medium",
            reason=(
                "Observed RDS I/O activity is high enough "
                "that storage performance should be reviewed "
                "before reducing capacity."
            ),
            statements=[
                cls._statement(
                    "io",
                    {
                        "read_iops": round(
                            read_value,
                            2,
                        ),
                        "write_iops": round(
                            write_value,
                            2,
                        ),
                        "total_iops": round(
                            total,
                            2,
                        ),
                    },
                    "Observed RDS I/O activity.",
                    [
                        "CloudWatch.ReadIOPS",
                        "CloudWatch.WriteIOPS",
                    ],
                )
            ],
            metadata={
                "category": "capacity_review",
                "read_iops": read_value,
                "write_iops": write_value,
                "total_iops": total,
            },
            recommendation_eligible=False,
        )

    @staticmethod
    def _statement(
        name: str,
        value: Any,
        description: str,
        source: list[str],
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,
            value=value,
            description=description,
            source=list(source),
        )

    @classmethod
    def _cost_statement(
        cls,
        amount: float | None,
    ) -> EvidenceStatement:

        return cls._statement(
            "current_monthly_resource_cost",
            (
                round(
                    amount,
                    2,
                )
                if amount is not None
                else None
            ),
            "Current cost explicitly attributed to this RDS resource by billing reconciliation.",
            ["Billing"],
        )

    @classmethod
    def _rightsizing_history_statement(
        cls,
        context: AnalysisContext,
    ) -> EvidenceStatement:

        history = cls._cloudtrail(context)

        return cls._statement(
            "cloudtrail_resize_history",
            {
                "status": history.get("status"),
                "change_count": history.get(
                    "change_count",
                    history.get(
                        "event_count",
                        0,
                    ),
                ),
                "last_change_at": history.get("last_change_at"),
                "last_changed_to_class": history.get("last_changed_to_class"),
                "days_since_last_change": history.get("days_since_last_change"),
            },
            "CloudTrail resize history used to verify configuration stability.",
            ["CloudTrail.ModifyDBInstance"],
        )

    # FINDING BUILDER

    @classmethod
    def _build_finding(
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
        recommendation_eligible: bool,
        cost_optimization_type: str = "review",
    ) -> Finding:

        if cls._is_aurora(context):
            raise ValueError(
                "RDSAnalyzer cannot build findings for Aurora "
                "resources. Aurora findings must be produced by "
                "AuroraAnalyzer."
            )

        if recommendation_eligible and not cls._has_current_resource_cost(context):
            recommendation_eligible = False

        metric_names = context.metrics()

        metric_evidence = {
            name: context.metric_summary(name)
            for name in metric_names
            if isinstance(
                context.metric_summary(name),
                dict,
            )
        }

        configuration = cls._configuration(context.resource)

        relationships = _dict(context.resource.get("relationships"))

        derived = context.derived()

        if not isinstance(
            derived,
            dict,
        ):
            derived = {}

        billing = context.billing()

        if not isinstance(
            billing,
            dict,
        ):
            billing = {}

        identity = context.identity()

        if not isinstance(
            identity,
            dict,
        ):
            identity = {}

        db_instance_identifier = (
            identity.get("db_instance_identifier") or context.resource_id
        )

        # Keep the evidence gate predictable and machine-readable.
        evidence_configuration = {
            key: configuration.get(key)
            for key in (
                "status",
                "instance_class",
                "engine",
                "engine_version",
                "multi_az",
                "availability_zone",
                "allocated_storage_gib",
                "storage_type",
                "storage_throughput_mibps",
                "db_cluster_identifier",
                "promotion_tier",
                "backup_retention_days",
                "publicly_accessible",
                "deletion_protection",
            )
            if key in configuration
        }

        if db_instance_identifier:
            evidence_configuration["db_instance_identifier"] = str(
                db_instance_identifier
            )

        # Include nested configuration for recommendation consumers.
        for nested_key in (
            "storage",
            "backup",
            "performance",
            "network",
            "deployment",
            "environment",
            "replica",
        ):

            if nested_key in configuration:
                evidence_configuration[nested_key] = configuration.get(nested_key)

        observation_data = cls._observations(context)

        evidence_derived = {
            **derived,
            "relationships": relationships,
            "observations": observation_data,
            **metadata,
        }

        billing_scope, _ = cls._billing_attribution(context)

        data_quality = {}

        try:
            collector_quality = context.collector_data_quality()

            if isinstance(
                collector_quality,
                dict,
            ):
                data_quality.update(collector_quality)

        except Exception:
            pass

        data_quality.update(
            {
                "metric_count": len(metric_evidence),
                "billing_attribution": billing_scope,
                "current_resource_cost_available": billing_scope == "resource",
                "cloudwatch_available": bool(metric_evidence),
                "cloudtrail_available": cls._cloudtrail(context).get("status") == "ok",
                "retirement_context_available": bool(cls._retirement(context)),
                "pricing_context_available": bool(cls._pricing_context(context)),
                "activity_context_available": bool(cls._activity(context)),
            }
        )

        evidence = Evidence(
            metrics=metric_evidence,
            configuration=evidence_configuration,
            topology=dict(context.topology() or {}),
            billing=dict(billing),
            resource={
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "region": context.region,
                "db_instance_identifier": db_instance_identifier,
                "instance_class": configuration.get("instance_class"),
                "engine": configuration.get("engine"),
            },
            derived=evidence_derived,
            data_quality=data_quality,
        )

        return Finding(
            finding_type=finding_type,
            title=title,
            resource_type=(context.resource_type or cls.resource_type),
            resource_id=(context.resource_id or "unknown"),
            analyzer=cls.name,
            analyzer_version=cls.version,
            severity=str(severity).lower(),
            confidence=str(confidence).lower(),
            reason=reason,
            conditions=statements,
            evidence=evidence,
            observation_period=(cls._observation_period(context)),
            metadata={
                **metadata,
                "region": context.region,
                "recommendation_eligible": recommendation_eligible,
                "billing_attribution": billing_scope,
            },
            recommendation_eligible=(recommendation_eligible),
            impact={},
            cost_optimization_type=cost_optimization_type,
            aggregation_scope="resource",
        )
