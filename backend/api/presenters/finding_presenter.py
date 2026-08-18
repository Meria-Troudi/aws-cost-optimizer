"""
Present findings from DB to frontend.
"""

from __future__ import annotations

from typing import Any

from backend.database.models.finding import Finding
from backend.api.presenters.utils import parse_json_field


def _to_float(value: Any) -> float | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        number = float(value)
    except (TypeError, ValueError):
        return None

    return round(number, 2)


def _parse_evidence(evidence: Any) -> dict[str, Any]:
    if isinstance(evidence, dict):
        return evidence

    parsed = parse_json_field(evidence, default={})
    return parsed if isinstance(parsed, dict) else {}


def _parse_list_field(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value

    parsed = parse_json_field(value, default=[])

    if isinstance(parsed, list):
        return parsed

    if parsed in (None, ""):
        return []

    return [parsed]


def _first_numeric(*values: Any) -> float | None:
    for value in values:
        parsed = _to_float(value)
        if parsed is not None:
            return parsed

    return None


def _extract_cost(
    evidence: dict[str, Any],
    impact: dict[str, Any],
) -> tuple[float | None, dict[str, Any]]:
    billing = evidence.get("billing")

    if not isinstance(billing, dict):
        billing = {}

    financial = evidence.get("financial_impact")

    if not isinstance(financial, dict):
        financial = {}

    cost = _first_numeric(
        billing.get("amount"),
        billing.get("cost"),
        billing.get("period_cost"),
        evidence.get("period_cost"),
        evidence.get("cost"),
        impact.get("period_cost"),
        impact.get("cost"),
        impact.get("analysis_period_cost"),
        financial.get("period_cost"),
        financial.get("cost"),
    )

    if cost is None:
        cost = 0.0 if (
            "billing" in evidence
            and isinstance(billing, dict)
            and billing
        ) else None

    if billing:
        billing = dict(billing)

        if cost is not None:
            billing.setdefault("amount", cost)

        billing.setdefault(
            "currency",
            "USD",
        )

    return cost, billing


def _extract_service(
    finding: Finding,
    evidence: dict[str, Any],
) -> str | None:
    service = evidence.get("service")

    if service:
        return str(service)

    billing = evidence.get("billing")

    if isinstance(billing, dict):
        service = billing.get("service")
        if service:
            return str(service)

    resource_type = str(
        finding.resource_type or ""
    ).strip()

    if resource_type:
        normalized = resource_type.replace("_", " ").strip()

        aliases = {
            "nat gateway": "NAT Gateway",
            "rds instance": "RDS",
            "transit gateway": "Transit Gateway",
            "vpc endpoint": "VPC Endpoint",
            "public ipv4": "Public IPv4",
            "load balancer": "Load Balancer",
            "eks": "EKS",
            "s3": "S3",
            "lambda": "Lambda",
        }

        return aliases.get(
            normalized.lower(),
            normalized.title(),
        )

    return None


def present_finding(
    finding: Finding,
) -> dict[str, Any]:
    evidence = _parse_evidence(
        finding.evidence
    )

    impact = parse_json_field(
        finding.impact,
        default={},
    )

    if not isinstance(impact, dict):
        impact = {}

    cost, billing = _extract_cost(
        evidence,
        impact,
    )

    limitations = _parse_list_field(
        finding.limitations
    )

    conditions = _parse_list_field(
        finding.conditions
    )

    evidence_summary = _parse_list_field(
        finding.evidence_summary
    )

    observation_period = parse_json_field(
        finding.observation_period,
        default=None,
    )

    service = _extract_service(
        finding,
        evidence,
    )

    category = (
        str(finding.category).strip()
        if finding.category
        else None
    )

    finding_type = (
        str(finding.finding_type).strip()
        if finding.finding_type
        else "finding"
    )

    title = finding_type.replace(
        "_",
        " ",
    ).title()

    return {
        "id": finding.id,
        "scan_id": finding.scan_run_id,

        "finding_type": finding_type,
        "finding_key": finding.finding_key,

        "resource_type": finding.resource_type,
        "resource_id": finding.resource_id,

        "service": service,

        "analyzer": finding.analyzer,
        "analyzer_version": finding.analyzer_version,

        "severity": finding.severity,
        "confidence": finding.confidence,

        "category": category,

        "title": title,

        "reason": finding.reason,

        "cost": cost,

        "cost_currency": (
            billing.get("currency", "USD")
            if billing
            else "USD"
        ),

        "cost_scope": (
            billing.get("scope")
            or billing.get("attribution_scope")
            if billing
            else None
        ),

        "billing_details": (
            billing
            if billing
            else None
        ),

        "impact": impact,

        "recommendation_eligible": bool(
            finding.recommendation_eligible
        ),

        "conditions": conditions,

        "evidence": evidence,

        "evidence_summary": [
            str(item)
            for item in evidence_summary
        ],

        "limitations": [
            str(item)
            for item in limitations
        ],

        "region": finding.region,

        "account_id": finding.account_id,

        "status": finding.status,

        "aggregation_scope": (
            finding.aggregation_scope
        ),

        "observation_period": observation_period,

        "created_at": (
            finding.created_at.isoformat()
            if finding.created_at
            else None
        ),
    }


def present_findings(
    findings: list[Finding],
    region: str | None = None,
) -> list[dict[str, Any]]:
    output = []

    for finding in findings:
        item = present_finding(finding)

        if (
            region
            and not item.get("region")
        ):
            item["region"] = region

        output.append(item)

    return output