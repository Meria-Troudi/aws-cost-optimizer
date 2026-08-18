"""
Finding persistence.

"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from backend.database.models.finding import Finding
from backend.database.utils import json_dumps


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

                aggregation_scope="resource",

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

    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

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
            -severity_order.get(
                item.severity,
                0,
            ),

            item.id,
        )
    )

    return findings


def get_findings_by_resource(
    db: Session,
    resource_id: str,
) -> list[Finding]:

    return (
        db.query(Finding)
        .filter(
            Finding.resource_id
            == str(resource_id)
        )
        .all()
    )