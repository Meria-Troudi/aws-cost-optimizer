"""
Finding persistence.
"""

from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy.orm import Session

from backend.database.models.finding import Finding
from backend.database.utils import json_dumps


def save_findings(
    db: Session,
    scan_run_id: int,
    findings: List[Dict[str, Any]],
) -> List[Finding]:

    saved = []

    for data in findings:

        if not isinstance(data, dict):
            continue

        resource_id = data.get("resource_id")

        if not resource_id:
            resource_ids = data.get("resource_ids", [])
            if resource_ids:
                resource_id = resource_ids[0]

        if not resource_id:
            affected = data.get("affected_resources", [])
            if affected and isinstance(affected[0], dict):
                resource_id = affected[0].get("resource_id")

        evidence = data.get("evidence", {})
        presentation = {
            "resource_ids": data.get("resource_ids") or [],
            "resource_count": data.get("resource_count"),
            "scope": data.get("scope"),
            "aggregate_evidence": data.get("aggregate_evidence"),
            "metadata": data.get("metadata"),
            "observation_periods": data.get("observation_periods"),
        }
        if any(presentation.values()):
            if isinstance(evidence, list):
                evidence = {
                    "items": evidence,
                    "_presentation": presentation,
                }
            elif isinstance(evidence, dict):
                evidence = {
                    **evidence,
                    "_presentation": presentation,
                }
            else:
                evidence = {"_presentation": presentation}

        finding = Finding(
            scan_run_id=scan_run_id,
            analyzer=data.get("analyzer"),
            analyzer_version=data.get("analyzer_version"),
            resource_type=data.get("resource_type"),
            resource_id=resource_id,
            finding_type=data.get("finding_type"),
            recommendation_eligible=data.get(
                "recommendation_eligible",
                False,
            ),
            severity=data.get("severity"),
            confidence=data.get("confidence"),
            reason=data.get("reason"),
            conditions=json_dumps(
                data.get("conditions", [])
            ),
            evidence=json_dumps(
                evidence
            ),
            limitations=json_dumps(
                data.get("limitations", [])
            ),
        )

        db.add(
            finding
        )

        saved.append(
            finding
        )

    db.flush()

    return saved


def get_findings_by_scan(
    db: Session,
    scan_run_id: int,
):

    return (
        db.query(Finding)
        .filter(
            Finding.scan_run_id
            == scan_run_id
        )
        .order_by(
            Finding.severity.desc()
        )
        .all()
    )


def get_findings_by_resource(
    db: Session,
    resource_id: str,
):

    return (
        db.query(Finding)
        .filter(
            Finding.resource_id
            == resource_id
        )
        .all()
    )