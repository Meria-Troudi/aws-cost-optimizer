"""
Amazon QuickSight FinOps analyzer.

The analyzer identifies evidence-backed optimization opportunities
without assuming account-specific pricing, usage patterns, or business
requirements.

Important:
- Lack of CloudTrail activity is not proof of unused status.
- QuickSight SPICE capacity is regional and account-level.
- Asset relationships are used to distinguish potentially orphaned
  resources from resources that are referenced by dashboards/analyses.
- No deletion recommendation is automatically generated.
"""

from __future__ import annotations

from datetime import datetime
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
DEFAULT_STALE_DAYS = 180

DEFAULT_SPICE_HIGH_UTILIZATION_RATIO = 0.90

DEFAULT_FAILED_STATUS_VALUES = {
    "CREATION_FAILED",
    "UPDATE_FAILED",
    "FAILED",
}
SPICE_LIMIT_METRIC = "SPICECapacityLimitInMB"
SPICE_CONSUMED_METRIC = "SPICECapacityConsumedInMB"
def _analyzer_config(
    context: AnalysisContext,
) -> dict[str, Any]:

    resource = context.resource

    for root_name in (
        "analyzer_config",
        "analysis_config",
        "config",
    ):

        root = resource.get(
            root_name
        )

        if not isinstance(
            root,
            dict,
        ):
            continue

        value = root.get(
            "quicksight"
        )

        if isinstance(
            value,
            dict,
        ):
            return value

    return {}


def _threshold(
    context: AnalysisContext,
    key: str,
    default: float | int | None,
) -> float | None:

    value = _analyzer_config(
        context
    ).get(
        key
    )

    if value is None:

        return (
            float(default)
            if default is not None
            else None
        )

    try:

        value = float(
            value
        )

        if value < 0:
            return (
                float(default)
                if default is not None
                else None
            )

        return value

    except (
        TypeError,
        ValueError,
    ):

        return (
            float(default)
            if default is not None
            else None
        )
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


def _relationships(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = context.relationships()

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


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


def _cloudwatch(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = _observations(
        context
    ).get(
        "cloudwatch",
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


def _cloudtrail(
    context: AnalysisContext,
) -> dict[str, Any]:

    value = _observations(
        context
    ).get(
        "cloudtrail",
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


def _asset_type(
    context: AnalysisContext,
) -> str:

    configuration = _configuration(
        context
    )

    value = (
        configuration.get(
            "asset_type"
        )
        or context.resource.get(
            "asset_type"
        )
        or ""
    )

    return str(
        value
    ).strip().lower()


def _metric_value(
    context: AnalysisContext,
    name: str,
) -> float | None:

    return context.metric_value(
        name
    )


def _metric_ready(
    context: AnalysisContext,
    name: str,
) -> bool:

    metric = context.metric(
        name
    )

    return metric_has_observed_data(
        metric
    )


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

    cloudwatch = _cloudwatch(
        context
    )

    start = cloudwatch.get(
        "start"
    )

    end = cloudwatch.get(
        "end"
    )

    if not start and not end:
        return None

    return ObservationPeriod(
        start=start,
        end=end,
    )
def _parse_datetime(
    value: Any,
) -> datetime | None:

    if isinstance(
        value,
        datetime,
    ):
        return value

    if not value:
        return None

    text = str(
        value
    ).strip()

    if not text:
        return None

    try:

        return datetime.fromisoformat(
            text.replace(
                "Z",
                "+00:00",
            )
        )

    except ValueError:

        return None


def _age_days(
    value: Any,
    now: datetime | None = None,
) -> float | None:

    timestamp = _parse_datetime(
        value
    )

    if timestamp is None:
        return None

    if now is None:
        now = datetime.now(
            timestamp.tzinfo
        )

    try:

        return max(
            0.0,
            (
                now - timestamp
            ).total_seconds()
            / 86400.0,
        )

    except TypeError:

        return None
@register
class QuickSightAnalyzer(Analyzer):

    name = "quicksight"
    version = "1.0"

    SUPPORTED_RESOURCE_TYPES = {
        "quicksight_asset",
        "quicksight",
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

        if not self.supports(
            context
        ):
            return []

        findings: list[
            Finding
        ] = []

        asset_type = _asset_type(
            context
        )
        if asset_type == "account":

            finding = (
                self._check_spice_capacity(
                    context
                )
            )

            if finding:
                findings.append(
                    finding
                )

            return findings
        if asset_type == "dashboard":

            finding = (
                self._check_stale_dashboard(
                    context
                )
            )

            if finding:
                findings.append(
                    finding
                )

            finding = (
                self._check_dashboard_errors(
                    context
                )
            )

            if finding:
                findings.append(
                    finding
                )

            return findings
        if asset_type == "dataset":

            finding = (
                self._check_orphaned_dataset(
                    context
                )
            )

            if finding:
                findings.append(
                    finding
                )

            finding = (
                self._check_unused_spice_dataset(
                    context
                )
            )

            if finding:
                findings.append(
                    finding
                )

            return findings
        if asset_type == "data_source":

            finding = (
                self._check_data_source_failure(
                    context
                )
            )

            if finding:
                findings.append(
                    finding
                )

            return findings
        if asset_type == "analysis":

            finding = (
                self._check_stale_analysis(
                    context
                )
            )

            if finding:
                findings.append(
                    finding
                )

            return findings

        return findings
    def _check_spice_capacity(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        if not (
            _metric_ready(
                context,
                SPICE_LIMIT_METRIC,
            )
            and _metric_ready(
                context,
                SPICE_CONSUMED_METRIC,
            )
        ):
            return None

        limit_mb = _metric_value(
            context,
            SPICE_LIMIT_METRIC,
        )

        consumed_mb = _metric_value(
            context,
            SPICE_CONSUMED_METRIC,
        )

        if (
            limit_mb is None
            or consumed_mb is None
            or limit_mb <= 0
        ):
            return None

        ratio = (
            consumed_mb
            / limit_mb
        )

        if ratio < (
            _threshold(
                context,
                "spice_high_utilization_ratio",
                DEFAULT_SPICE_HIGH_UTILIZATION_RATIO,
            )
            or DEFAULT_SPICE_HIGH_UTILIZATION_RATIO
        ):
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "quicksight_spice_capacity_pressure"
            ),
            title=(
                "QuickSight SPICE capacity is highly utilized"
            ),
            severity="medium",
            confidence="high",
            reason=(
                f"Observed SPICE consumption is approximately "
                f"{ratio * 100:.1f}% of the available regional "
                "SPICE capacity. Review dataset sizes, refresh "
                "requirements and capacity purchasing before "
                "increasing capacity."
            ),
            statements=[
                self._metric_evidence(
                    context,
                    SPICE_LIMIT_METRIC,
                ),
                self._metric_evidence(
                    context,
                    SPICE_CONSUMED_METRIC,
                ),
            ],
            metadata={
                "spice_capacity_limit_mb":
                    limit_mb,

                "spice_capacity_consumed_mb":
                    consumed_mb,

                "spice_utilization_ratio":
                    round(
                        ratio,
                        4,
                    ),

                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )
    def _check_stale_dashboard(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        configuration = _configuration(
            context
        )

        last_published = configuration.get(
            "last_published_time"
        )

        age = _age_days(
            last_published
        )

        threshold = _threshold(
            context,
            "stale_days",
            DEFAULT_STALE_DAYS,
        )

        if (
            age is None
            or threshold is None
            or age < threshold
        ):
            return None

        activity = _cloudtrail(
            context
        )

        events = activity.get(
            "events",
            [],
        )

        if not isinstance(
            events,
            list,
        ):
            events = []

        # We only create a stronger stale finding if the observation
        # period actually contains no observed activity.
        if events:
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "quicksight_stale_dashboard"
            ),
            title=(
                "QuickSight dashboard appears stale"
            ),
            severity="low",
            confidence="medium",
            reason=(
                f"The dashboard has not been published for "
                f"approximately {age:.0f} days and no relevant "
                "QuickSight activity was observed in the collected "
                "CloudTrail window. This is a review signal, not "
                "proof that the dashboard is unused."
            ),
            statements=[
                self._configuration_evidence(
                    context,
                    "last_published_time",
                    last_published,
                ),
                self._cloudtrail_evidence(
                    context,
                    events,
                ),
            ],
            metadata={
                "last_published_time":
                    last_published,

                "age_days":
                    round(
                        age,
                        1,
                    ),

                "cloudtrail_event_count":
                    len(
                        events
                    ),

                "review_threshold_days":
                    threshold,

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )
    def _check_dashboard_errors(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        configuration = _configuration(
            context
        )

        errors = configuration.get(
            "version_errors",
            [],
        )

        if not isinstance(
            errors,
            list,
        ):
            return None

        errors = [
            error
            for error in errors
            if isinstance(
                error,
                dict,
            )
        ]

        if not errors:
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "quicksight_dashboard_errors"
            ),
            title=(
                "QuickSight dashboard has configuration errors"
            ),
            severity="medium",
            confidence="high",
            reason=(
                "The latest collected dashboard version contains "
                "errors. Broken dashboards can indicate stale "
                "dependencies, missing datasets or configuration "
                "problems that should be resolved before considering "
                "the asset for continued operation."
            ),
            statements=[
                self._configuration_evidence(
                    context,
                    "version_errors",
                    errors,
                )
            ],
            metadata={
                "error_count":
                    len(
                        errors
                    ),

                "errors":
                    errors,

                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )
    def _check_orphaned_dataset(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        relationships = _relationships(
            context
        )

        dashboard_arns = (
            relationships.get(
                "dashboard_arns",
                [],
            )
        )

        if dashboard_arns:
            return None

        # CloudTrail activity can prove that the dataset itself has
        # been modified/refreshed, but it does not prove dashboard use.
        activity = _cloudtrail(
            context
        )

        events = activity.get(
            "events",
            [],
        )

        if not isinstance(
            events,
            list,
        ):
            events = []

        dataset_id = _configuration(
            context
        ).get(
            "dataset_id"
        )

        return self._build_finding(
            context=context,
            finding_type=(
                "quicksight_potentially_orphaned_dataset"
            ),
            title=(
                "QuickSight dataset has no discovered dashboard dependency"
            ),
            severity="low",
            confidence="medium",
            reason=(
                "The collected QuickSight relationships do not show "
                "the dataset being referenced by a dashboard in the "
                "available resource metadata. The dataset may still "
                "be used by analyses, APIs, embedded applications, "
                "or other workflows, so deletion is not recommended "
                "without additional validation."
            ),
            statements=[
                self._configuration_evidence(
                    context,
                    "dataset_id",
                    dataset_id,
                ),
                self._configuration_evidence(
                    context,
                    "dashboard_dependencies",
                    dashboard_arns,
                ),
                self._cloudtrail_evidence(
                    context,
                    events,
                ),
            ],
            metadata={
                "dataset_id":
                    dataset_id,

                "dashboard_dependencies":
                    dashboard_arns,

                "cloudtrail_event_count":
                    len(
                        events
                    ),

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )
    def _check_unused_spice_dataset(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        configuration = _configuration(
            context
        )

        import_mode = str(
            configuration.get(
                "import_mode",
                "",
            )
        ).upper()

        if import_mode != "SPICE":
            return None

        consumed = configuration.get(
            "consumed_spice_capacity_bytes"
        )

        try:
            consumed = float(
                consumed
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

        if consumed <= 0:
            return None

        relationships = _relationships(
            context
        )

        dashboard_arns = relationships.get(
            "dashboard_arns",
            [],
        )

        activity = _cloudtrail(
            context
        )

        events = activity.get(
            "events",
            [],
        )

        if not isinstance(
            events,
            list,
        ):
            events = []

        # A dataset that is actively referenced should not be called
        # unused merely because its CloudTrail events are sparse.
        if dashboard_arns:
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "quicksight_spice_dataset_review"
            ),
            title=(
                "QuickSight SPICE dataset may be consuming "
                "unnecessary capacity"
            ),
            severity="low",
            confidence="medium",
            reason=(
                "The dataset is stored in SPICE and consumes "
                f"approximately {consumed / (1024 ** 3):.2f} GiB, "
                "while no dashboard dependency was discovered in "
                "the collected metadata. Review whether the dataset "
                "is still required before removing it from SPICE."
            ),
            statements=[
                self._configuration_evidence(
                    context,
                    "import_mode",
                    import_mode,
                ),
                self._configuration_evidence(
                    context,
                    "consumed_spice_capacity_bytes",
                    consumed,
                ),
                self._configuration_evidence(
                    context,
                    "dashboard_dependencies",
                    dashboard_arns,
                ),
                self._cloudtrail_evidence(
                    context,
                    events,
                ),
            ],
            metadata={
                "consumed_spice_capacity_bytes":
                    consumed,

                "consumed_spice_capacity_gib":
                    round(
                        consumed
                        / (1024 ** 3),
                        3,
                    ),

                "dashboard_dependency_count":
                    len(
                        dashboard_arns
                    ),

                "cloudtrail_event_count":
                    len(
                        events
                    ),

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )
    def _check_data_source_failure(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        configuration = _configuration(
            context
        )

        status = str(
            configuration.get(
                "status",
                "",
            )
        ).upper()

        if status not in (
            DEFAULT_FAILED_STATUS_VALUES
        ):
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "quicksight_data_source_failure"
            ),
            title=(
                "QuickSight data source is in a failed state"
            ),
            severity="medium",
            confidence="high",
            reason=(
                f"The QuickSight data source is currently reported "
                f"with status '{status}'. Investigate the source "
                "connection before relying on the associated "
                "datasets."
            ),
            statements=[
                self._configuration_evidence(
                    context,
                    "status",
                    status,
                )
            ],
            metadata={
                "status":
                    status,

                "data_source_type":
                    configuration.get(
                        "type"
                    ),

                "region":
                    context.region,
            },
            recommendation_eligible=False,
        )
    def _check_stale_analysis(
        self,
        context: AnalysisContext,
    ) -> Finding | None:

        configuration = _configuration(
            context
        )

        last_updated = configuration.get(
            "last_updated_time"
        )

        age = _age_days(
            last_updated
        )

        threshold = _threshold(
            context,
            "stale_days",
            DEFAULT_STALE_DAYS,
        )

        if (
            age is None
            or threshold is None
            or age < threshold
        ):
            return None

        activity = _cloudtrail(
            context
        )

        events = activity.get(
            "events",
            [],
        )

        if not isinstance(
            events,
            list,
        ):
            events = []

        if events:
            return None

        return self._build_finding(
            context=context,
            finding_type=(
                "quicksight_stale_analysis"
            ),
            title=(
                "QuickSight analysis appears stale"
            ),
            severity="low",
            confidence="medium",
            reason=(
                f"The analysis has not been updated for approximately "
                f"{age:.0f} days and no relevant CloudTrail activity "
                "was observed in the collected period. Review whether "
                "it remains part of the reporting workflow."
            ),
            statements=[
                self._configuration_evidence(
                    context,
                    "last_updated_time",
                    last_updated,
                ),
                self._cloudtrail_evidence(
                    context,
                    events,
                ),
            ],
            metadata={
                "age_days":
                    round(
                        age,
                        1,
                    ),

                "cloudtrail_event_count":
                    len(
                        events
                    ),

                "region":
                    context.region,
            },
            recommendation_eligible=True,
        )
    def _build_finding(
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
        recommendation_eligible: bool,
    ) -> Finding:

        return Finding(
            finding_type=finding_type,

            title=title,

            resource_type=(
                context.resource_type
                or "quicksight_asset"
            ),

            resource_id=(
                context.resource_id
                or "unknown"
            ),

            analyzer=self.name,

            analyzer_version=self.version,

            severity=severity.lower(),

            confidence=confidence.lower(),

            reason=reason,

            conditions=statements,

            evidence=self._build_evidence(
                context,
                metadata,
            ),

            observation_period=(
                _observation_period(
                    context
                )
            ),

            limitations=[
                (
                    "QuickSight CloudTrail activity is evidence of "
                    "observed API or service activity, but absence "
                    "of an event does not prove that an asset is "
                    "unused."
                ),

                (
                    "Business, compliance, disaster-recovery and "
                    "reporting requirements are not inferred by "
                    "this analyzer."
                ),
            ],

            metadata=dict(
                metadata
            ),

            recommendation_eligible=(
                recommendation_eligible
            ),
        )
    def _build_evidence(
        self,
        context: AnalysisContext,
        metadata: dict[str, Any],
    ) -> Evidence:

        configuration = _configuration(
            context
        )

        metrics = {
            name:
                context.metric_summary(
                    name
                )
            for name in (
                context.metrics()
                or {}
            )
        }

        return Evidence(
            metrics=metrics,

            configuration=dict(
                configuration
            ),

            topology=context.topology(),

            resource={
                "resource_id":
                    context.resource_id,

                "resource_type":
                    context.resource_type,

                "region":
                    context.region,

                "asset_type":
                    _asset_type(
                        context
                    ),
            },

            derived=dict(
                metadata
            ),

            data_quality={
                **context.data_quality(),

                "cloudwatch_metrics":
                    len(
                        metrics
                    ),

                "cloudtrail_available":
                    bool(
                        _cloudtrail(
                            context
                        )
                    ),

                "observation_period_available":
                    (
                        _observation_period(
                            context
                        )
                        is not None
                    ),
            },
        )
    @staticmethod
    def _configuration_evidence(
        context: AnalysisContext,
        name: str,
        value: Any,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,

            value=value,

            description=(
                "Current QuickSight configuration: "
                f"{name}={value}."
            ),

            source=[
                "QuickSight configuration"
            ],
        )

    @staticmethod
    def _metric_evidence(
        context: AnalysisContext,
        name: str,
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name=name,

            value=context.metric_summary(
                name
            ),

            description=(
                f"CloudWatch QuickSight metric "
                f"{name}."
            ),

            source=[
                f"CloudWatch.{name}"
            ],
        )

    @staticmethod
    def _cloudtrail_evidence(
        context: AnalysisContext,
        events: list[Any],
    ) -> EvidenceStatement:

        return EvidenceStatement(
            name="cloudtrail_activity",

            value={
                "event_count":
                    len(
                        events
                    ),

                "events":
                    events,
            },

            description=(
                "Observed QuickSight CloudTrail activity "
                "during the collected analysis period."
            ),

            source=[
                "CloudTrail.quicksight.amazonaws.com"
            ],
        )