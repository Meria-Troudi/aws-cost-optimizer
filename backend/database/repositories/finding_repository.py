"""
Finding persistence.

"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from aws_cost_optimizer.analysis.ranking import (
    SEVERITY_RANK as SEVERITY_ORDER,
)
from backend.database.models.finding import Finding
from backend.database.utils import json_dumps, json_loads


def save_findings(
    db: Session,
    scan_run_id: int,
    findings: list[dict[str, Any]],
) -> list[Finding]:

    saved: list[Finding] = []

    for data in findings:

        if not isinstance(
            data,
            dict,
        ):
            continue

        resource_id = (
            data.get(
                "resource_id"
            )
        )

        if not resource_id:

            resource_ids = data.get(
                "resource_ids"
            )
        if resource_id is None and isinstance(resource_ids, list):
            if len(resource_ids) == 1:
                resource_id = resource_ids[0]

            elif len(resource_ids) > 1:
                raise ValueError(
                    "Raw finding contains multiple resource_ids. "
            "Persist one resource-level finding per resource."
        )
        if not resource_id:
            raise ValueError(
                "Raw finding is missing resource_id."
    )


        resource_type = str(
            data.get(
                "resource_type"
            )
            or "unknown"
        ).strip()

        finding_type = str(
            data.get(
                "finding_type"
            )
            or data.get(
                "finding_key"
            )
            or "unknown"
        ).strip()

        finding_key = str(
            data.get(
                "finding_key"
            )
            or finding_type
        ).strip()

        category = str(
            data.get(
                "category"
            )
            or "optimization"
        ).strip().lower()

        severity = str(
            data.get(
                "severity"
            )
            or "info"
        ).strip().lower()

        confidence = str(
            data.get(
                "confidence"
            )
            or "medium"
        ).strip().lower()

        status = str(
            data.get(
                "status"
            )
            or "active"
        ).strip().lower()
        finding = Finding(
                scan_run_id=scan_run_id,

                resource_type=resource_type,

                resource_id=str(
                    resource_id
                ),

                finding_key=finding_key,

                finding_type=finding_type,

                category=category,

                # The analyzer's real aggregation scope (None means
                # "use FindingAggregator's default", currently
                # "region") -- NOT hardcoded, so re-hydrating this
                # row later and re-aggregating it produces the same
                # grouping the analyzer/exporter path already does.
                aggregation_scope=str(
                    data.get(
                        "aggregation_scope"
                    )
                    or "region"
                ).strip().lower(),

                analyzer=str(
                    data.get("analyzer")
                    or "unknown"
                ),

                analyzer_version=str(
                    data.get("analyzer_version")
                    or "1.0"
                ),

                severity=severity,

                confidence=confidence,

                reason=str(
                    data.get("reason")
                    or ""
                ),

                recommendation_eligible=bool(
                    data.get(
                        "recommendation_eligible",
                        False,
                    )
                ),

                status=status,

                conditions=json_dumps(
                    data.get(
                        "conditions",
                        [],
                    )
                ),

                evidence=json_dumps(
                    data.get(
                        "evidence",
                        {},
                    )
                ),

                evidence_summary=json_dumps(
                    data.get(
                        "evidence_summary",
                        [],
                    )
                ),

                impact=json_dumps(
                    data.get(
                        "impact",
                        {},
                    )
                ),

                limitations=json_dumps(
                    data.get(
                        "limitations",
                        [],
                    )
                ),

                account_id=(
                    str(
                        data.get("account_id")
                    )
                    if data.get("account_id")
                    else None
                ),

                region=(
                    str(
                        data.get("region")
                    )
                    if data.get("region")
                    else None
                ),

                observation_period=json_dumps(
                    data.get(
                        "observation_period"
                    )
                    if data.get(
                        "observation_period"
                    )
                    else None
                ),
            )

        db.add(
            finding
        )

        saved.append(
            finding
        )

    if saved:
        db.flush()

    return saved


def get_findings_by_scan(
    db: Session,
    scan_run_id: int,
) -> list[Finding]:

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_run_id
            == scan_run_id
        )
        .all()
    )

    findings.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(
                item.severity,
                0,
            ),

            item.id,
        )
    )

    return findings


def hydrate_findings(
    rows: list[Finding],
):
    """
    Reconstruct the aws_cost_optimizer.analysis.finding.Finding
    dataclass (the one FindingAggregator.aggregate() expects) from
    persisted DB rows -- the inverse of save_findings(). Lets API
    routes reuse the canonical aggregator instead of re-deriving
    grouping from scratch on every request.
    """

    from aws_cost_optimizer.analysis.condition import (
        EvidenceStatement,
    )
    from aws_cost_optimizer.analysis.evidence import Evidence
    from aws_cost_optimizer.analysis.finding import (
        Finding as AnalysisFinding,
        ObservationPeriod,
    )

    hydrated = []

    for row in rows:

        evidence_data = (
            json_loads(row.evidence)
            or {}
        )

        if not isinstance(
            evidence_data,
            dict,
        ):
            evidence_data = {}

        conditions_data = (
            json_loads(row.conditions)
            or []
        )

        observation_period_data = (
            json_loads(
                row.observation_period
            )
        )

        impact_data = (
            json_loads(row.impact)
            or {}
        )

        if not isinstance(
            impact_data,
            dict,
        ):
            impact_data = {}

        limitations_data = (
            json_loads(row.limitations)
            or []
        )

        evidence_summary_data = (
            json_loads(
                row.evidence_summary
            )
            or []
        )

        title = (
            str(
                row.finding_type
                or "finding"
            )
            .replace("_", " ")
            .title()
        )

        hydrated.append(
            AnalysisFinding(
                finding_type=row.finding_type,
                title=title,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                analyzer=row.analyzer,
                analyzer_version=row.analyzer_version,
                severity=row.severity,
                confidence=row.confidence,
                reason=row.reason,
                conditions=[
                    EvidenceStatement(
                        **item
                    )
                    for item in conditions_data
                    if isinstance(
                        item,
                        dict,
                    )
                ],
                evidence=Evidence(
                    **evidence_data
                ),
                observation_period=(
                    ObservationPeriod(
                        **observation_period_data
                    )
                    if isinstance(
                        observation_period_data,
                        dict,
                    )
                    else None
                ),
                limitations=(
                    limitations_data
                    if isinstance(
                        limitations_data,
                        list,
                    )
                    else []
                ),
                database_id=row.id,
                recommendation_eligible=bool(
                    row.recommendation_eligible
                ),
                aggregation_scope=row.aggregation_scope,
                category=row.category,
                status=row.status,
                finding_key=row.finding_key,
                evidence_summary=(
                    evidence_summary_data
                    if isinstance(
                        evidence_summary_data,
                        list,
                    )
                    else []
                ),
                impact=impact_data,
                account_id=row.account_id,
            )
        )

    return hydrated