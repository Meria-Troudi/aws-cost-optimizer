"""
Presentation-ready finding DTOs for the UI.

Translates raw rule-engine output into human-readable fields so the
frontend does not need to understand internal condition/evidence shapes.
"""

from __future__ import annotations

import json
import re
from typing import Any


def _finding_title(raw: dict[str, Any]) -> str:
    presentation = _extract_presentation_meta(raw.get("evidence"))
    title = (
        raw.get("title")
        or presentation.get("title")
        or raw.get("name")
    )

    if title:
        return str(title)

    finding_type = raw.get("finding_type")
    if finding_type:
        return str(finding_type).replace("_", " ").title()

    return "Unknown finding"

SERVICE_LABELS: dict[str, str] = {
    "nat_gateway": "NAT Gateway",
    "rds_instance": "RDS",
    "rds": "RDS",
    "eks_cluster": "EKS",
    "vpc_endpoint": "VPC Endpoint",
    "transit_gateway": "Transit Gateway",
    "elastic_ip": "Elastic IP",
    "elb": "Load Balancer",
    "load_balancer": "Load Balancer",
    "eks": "EKS",
}

CONDITION_LABELS: dict[str, str] = {
    "traffic": "Traffic",
    "connections": "Connections",
    "network_dependency": "Network dependency",
    "billing_resource_match": "Billing/resource match",
    "traffic_data_available": "CloudWatch metrics available",
    "traffic_observed": "Traffic observed",
    "connection_activity": "Connection activity observed",
    "traffic_gib": "Traffic volume",
}


def _parse_json(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return fallback
    return fallback


def _format_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    if value is None:
        return "N/A"
    return str(value)


def _format_actual(name: str, actual: Any) -> str:
    if actual is None:
        return "Not available"
    if isinstance(actual, bool):
        if name in ("traffic_observed", "connection_activity"):
            return "None observed" if not actual else "Observed"
        return "Yes" if actual else "No"
    if isinstance(actual, (int, float)):
        if name in ("traffic_gib",):
            return f"{actual:.4f} GiB"
        if "bytes" in name.lower() or name == "traffic_observed":
            return f"{actual:,.0f} B" if actual else "0 B"
        return str(actual)
    return str(actual)


def _statement_fields(statement: dict[str, Any]) -> dict[str, Any]:
    value = statement.get("value")
    expected = statement.get("expected")
    actual = statement.get("actual")
    status = statement.get("status")

    if isinstance(value, dict):
        expected = value.get("expected", expected)
        actual = value.get("actual", actual)
        status = value.get("status", status)
    elif value is not None and actual is None:
        actual = value

    if status is None:
        if statement.get("passed") is True:
            status = "PASS"
        elif statement.get("passed") is False:
            status = "FAIL"

    name = statement.get("name") or "condition"
    label = CONDITION_LABELS.get(name, name.replace("_", " ").title())

    return {
        "name": name,
        "label": label,
        "expected": expected,
        "actual": actual,
        "status": status,
        "description": statement.get("description") or "",
        "source": statement.get("source") or [],
        "supports_finding": (
            statement.get("passed")
            if statement.get("passed") is not None
            else status not in ("FAIL",)
        ),
    }


def _build_condition_groups(raw: Any) -> list[dict[str, Any]]:
    blocks = _parse_json(raw, [])
    if not isinstance(blocks, list):
        return []

    groups: list[dict[str, Any]] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue

        resource_id = block.get("resource_id")
        statements_raw = block.get("evidence")
        if not isinstance(statements_raw, list):
            if "conditions" in block:
                statements_raw = block.get("conditions") or []
            else:
                statements_raw = [block]

        statements = [
            _statement_fields(statement)
            for statement in statements_raw
            if isinstance(statement, dict)
        ]
        if not statements:
            continue

        groups.append(
            {
                "resource_id": resource_id,
                "statements": statements,
            }
        )

    return groups


def _flatten_conditions(raw: Any) -> list[dict[str, Any]]:
    groups = _build_condition_groups(raw)
    flat: list[dict[str, Any]] = []
    for group in groups:
        for statement in group.get("statements") or []:
            flat.append(statement)
    return flat


def _evidence_items(raw: Any) -> list[dict[str, Any]]:
    evidence = _parse_json(raw, {})
    if isinstance(evidence, list):
        return evidence
    if isinstance(evidence, dict) and isinstance(evidence.get("items"), list):
        return evidence["items"]
    return []


def _extract_presentation_meta(evidence: Any) -> dict[str, Any]:
    evidence = _parse_json(evidence, {})
    if isinstance(evidence, dict) and "_presentation" in evidence:
        return evidence.get("_presentation") or {}
    return {}


def _extract_billing_details(evidence_raw: Any) -> dict[str, Any] | None:
    for item in _evidence_items(evidence_raw):
        if not isinstance(item, dict):
            continue
        inner = item.get("evidence") or item
        if not isinstance(inner, dict):
            continue

        data_quality = inner.get("data_quality") or {}
        match = data_quality.get("billing_resource_match")
        if isinstance(match, dict) and match.get("status") == "mismatch":
            return match

        derived = inner.get("derived") or {}
        billing_class = derived.get("billing_instance_class")
        actual_class = derived.get("actual_instance_class")
        if billing_class and actual_class and billing_class != actual_class:
            return {
                "status": "unmatched",
                "billing_class": billing_class,
                "resource_class": actual_class,
            }

        matching = inner.get("matching") or {}
        if matching.get("status") == "unmatched":
            return matching

        billing = inner.get("billing") or {}
        if billing.get("expected_instance_class"):
            return {
                "status": "unmatched",
                "billing_class": billing.get("expected_instance_class"),
                "usage_type": billing.get("usage_type"),
                "cost": billing.get("cost"),
            }

    return None


def _extract_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    presentation = _extract_presentation_meta(raw.get("evidence"))
    metadata = presentation.get("metadata") or raw.get("metadata")

    if isinstance(metadata, list):
        merged: dict[str, Any] = {}
        for item in metadata:
            if isinstance(item, dict):
                merged.update(item)
        return merged

    if isinstance(metadata, dict):
        return metadata

    return {}


def _extract_observation_period(raw: dict[str, Any]) -> dict[str, Any] | None:
    presentation = _extract_presentation_meta(raw.get("evidence"))
    periods = presentation.get("observation_periods") or raw.get(
        "observation_periods"
    )
    if isinstance(periods, list):
        for period in periods:
            if isinstance(period, dict) and period.get("start"):
                return period
    single = raw.get("observation_period")
    if isinstance(single, dict):
        return single
    return None


def _collect_resource_ids(raw: dict[str, Any]) -> list[str]:
    ids: list[str] = []

    for group in _build_condition_groups(raw.get("conditions")):
        resource_id = group.get("resource_id")
        if resource_id and str(resource_id) not in ids:
            ids.append(str(resource_id))

    if raw.get("resource_id"):
        rid = str(raw["resource_id"])
        if rid not in ids:
            ids.append(rid)

    for rid in raw.get("resource_ids") or []:
        if rid and str(rid) not in ids:
            ids.append(str(rid))

    presentation = _extract_presentation_meta(raw.get("evidence"))
    for rid in presentation.get("resource_ids") or []:
        if rid and str(rid) not in ids:
            ids.append(str(rid))

    for entry in _evidence_items(raw.get("evidence")):
        if isinstance(entry, dict) and entry.get("resource_id"):
            rid = str(entry["resource_id"])
            if rid not in ids:
                ids.append(rid)

    return ids


def _parse_resource_count(raw: dict[str, Any], resource_ids: list[str]) -> int:
    presentation = _extract_presentation_meta(raw.get("evidence"))
    presented_count = presentation.get("resource_count")
    if presented_count is not None:
        return int(presented_count)

    if raw.get("resource_count") is not None:
        return int(raw["resource_count"])

    if resource_ids:
        return len(resource_ids)

    groups = _build_condition_groups(raw.get("conditions"))
    if groups:
        return len(groups)

    agg = raw.get("aggregate_evidence") or presentation.get("aggregate_evidence")
    if isinstance(agg, dict) and agg.get("affected_resource_count"):
        return int(agg["affected_resource_count"])

    return max(len(resource_ids), 1)


def _extract_region(raw: dict[str, Any], fallback: str | None) -> str:
    scope = raw.get("scope")
    if scope and scope not in ("account", "unknown", "—"):
        return str(scope)

    for entry in _evidence_items(raw.get("evidence")):
        inner = entry.get("evidence") if isinstance(entry, dict) else None
        if isinstance(inner, dict):
            region = (inner.get("resource") or {}).get("region")
            if region:
                return str(region)

    if fallback:
        return fallback
    return "All regions"


def _human_reason(
    finding_type: str,
    reason: str,
    resource_count: int,
    title: str,
) -> str:
    if not reason:
        return title

    boilerplate = (
        "resources satisfy" in reason.lower()
        or "resource-specific evidence is preserved" in reason.lower()
        or reason.strip() == finding_type
    )

    if not boilerplate:
        return reason

    if finding_type in (
        "nat_gateway_no_observed_activity",
        "nat_gateway_no_activity",
    ):
        if resource_count > 1:
            return (
                "These NAT Gateways have no observed traffic or connection "
                f"activity during the analysis period ({resource_count} affected)."
            )
        return (
            "This NAT Gateway has no observed traffic or connection activity "
            "during the analysis period."
        )

    service = title.split(" with ")[0] if " with " in title else "Resource"
    if resource_count > 1:
        return (
            f"These {service}s match the optimization condition "
            f"({resource_count} resources affected)."
        )

    return reason or title


def _build_evidence_items(
    condition_groups: list[dict[str, Any]],
    evidence_raw: Any,
    aggregate_evidence: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    for group in condition_groups:
        resource_id = group.get("resource_id")
        for statement in group.get("statements") or []:
            label = statement.get("label") or statement.get("name")
            if resource_id:
                label = f"{label} ({resource_id})"

            observed_parts = []
            if statement.get("actual") is not None:
                observed_parts.append(
                    _format_actual(statement.get("name", ""), statement.get("actual"))
                )
            if statement.get("status"):
                observed_parts.append(f"status={statement['status']}")

            items.append(
                {
                    "label": label,
                    "expected": _format_value(statement.get("expected")),
                    "actual": _format_value(statement.get("actual")),
                    "status": statement.get("status"),
                    "observed": " · ".join(observed_parts) or "Not available",
                    "description": statement.get("description") or "",
                    "source": statement.get("source") or [],
                    "supports_finding": statement.get("supports_finding", True),
                }
            )

    agg = aggregate_evidence or {}
    if agg.get("traffic_bytes_total") is not None:
        items.append(
            {
                "label": "Total traffic processed",
                "expected": None,
                "actual": f"{agg['traffic_bytes_total']:,.0f} B",
                "status": None,
                "observed": f"{agg['traffic_bytes_total']:,.0f} B",
                "description": "Aggregated across affected resources",
                "source": [],
                "supports_finding": True,
            }
        )

    billing = _extract_billing_details(evidence_raw)
    if billing:
        items.append(
            {
                "label": "Billing/resource match",
                "expected": "match",
                "actual": billing.get("resource_class") or billing.get("billing_class"),
                "status": billing.get("status", "mismatch"),
                "observed": (
                    f"billing={billing.get('billing_class')} · "
                    f"discovered={billing.get('resource_class')}"
                ),
                "description": "Billing usage type does not match discovered configuration.",
                "source": ["cost_context.usage_type", "configuration.instance_class"],
                "supports_finding": True,
            }
        )

    return items


def _build_metrics(
    evidence_raw: Any,
    aggregate_evidence: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    agg = aggregate_evidence or {}

    if agg.get("traffic_bytes_total") is not None:
        metrics.append(
            {
                "name": "Bytes processed (aggregate)",
                "value": f"{agg['traffic_bytes_total']:,.0f} B",
                "status": None,
                "datapoints": agg.get("datapoints"),
            }
        )

    for item in _evidence_items(evidence_raw):
        if not isinstance(item, dict):
            continue
        inner = item.get("evidence") or {}
        if not isinstance(inner, dict):
            continue

        resource_id = item.get("resource_id")
        metric_map = inner.get("metrics") or {}
        if not isinstance(metric_map, dict):
            continue

        for metric_name, payload in metric_map.items():
            if not isinstance(payload, dict):
                continue
            prefix = f"{resource_id}: " if resource_id else ""
            metrics.append(
                {
                    "name": f"{prefix}{metric_name}",
                    "value": payload.get("value"),
                    "status": payload.get("status"),
                    "has_data": payload.get("has_data"),
                    "datapoints": payload.get("datapoints"),
                }
            )

    return metrics


def _service_label(
    finding_type: str,
    resource_type: str,
    metadata: dict[str, Any],
) -> str:
    if finding_type in (
        "historical_unmatched",
        "collection_no_matching_resources",
        "billing_resource_current",
        "billing_resource_mismatch",
        "billing_no_cost",
        "billing_reconciliation_unknown",
    ):
        billing_service = metadata.get("service")
        if billing_service:
            return str(billing_service)
    return SERVICE_LABELS.get(
        resource_type,
        resource_type.replace("_", " ").title(),
    )


def present_finding(raw: dict[str, Any], region: str | None = None) -> dict[str, Any]:
    finding_type = raw.get("finding_type") or "unknown"
    resource_type = (raw.get("resource_type") or "unknown").lower()
    title = _finding_title(raw)
    metadata = _extract_metadata(raw)
    service = _service_label(finding_type, resource_type, metadata)

    resource_ids = _collect_resource_ids(raw)
    resource_count = _parse_resource_count(raw, resource_ids)
    condition_groups = _build_condition_groups(raw.get("conditions"))

    evidence_raw = raw.get("evidence")
    presentation = _extract_presentation_meta(evidence_raw)
    aggregate_evidence = raw.get("aggregate_evidence") or presentation.get(
        "aggregate_evidence"
    )
    if isinstance(aggregate_evidence, str):
        aggregate_evidence = _parse_json(aggregate_evidence, None)

    reason = _human_reason(
        finding_type,
        raw.get("reason") or "",
        resource_count,
        title,
    )

    limitations = _parse_json(raw.get("limitations"), [])
    if not isinstance(limitations, list):
        limitations = []

    billing_details = _extract_billing_details(evidence_raw)
    observation_period = _extract_observation_period(raw)

    category = metadata.get("category")
    if not category and finding_type in (
        "historical_unmatched",
        "collection_no_matching_resources",
        "billing_resource_current",
        "billing_resource_mismatch",
        "billing_no_cost",
        "billing_reconciliation_unknown",
    ):
        category = "RECONCILIATION"
    if not category and billing_details:
        category = "DATA_QUALITY"

    return {
        "id": raw.get("id"),
        "title": title,
        "summary": title,
        "finding_type": finding_type,
        "service": service,
        "resource_type": resource_type,
        "severity": (raw.get("severity") or "low").lower(),
        "confidence": raw.get("confidence") or "medium",
        "reason": reason,
        "resource_count": resource_count,
        "resource_ids": resource_ids,
        "primary_resource_id": resource_ids[0] if resource_ids else raw.get("resource_id"),
        "region": _extract_region(raw, region),
        "condition_groups": condition_groups,
        "evidence_items": _build_evidence_items(
            condition_groups,
            evidence_raw,
            aggregate_evidence if isinstance(aggregate_evidence, dict) else None,
        ),
        "metrics": _build_metrics(
            evidence_raw,
            aggregate_evidence if isinstance(aggregate_evidence, dict) else None,
        ),
        "limitations": limitations,
        "metadata": metadata,
        "billing_details": billing_details,
        "observation_period": observation_period,
        "category": category,
        "cost": None,
        "cost_label": "Not estimated",
        "recommendation_eligible": bool(raw.get("recommendation_eligible")),
        "blocks_optimization": bool(
            metadata.get("blocks_optimization")
            or metadata.get("blocks_rightsizing")
        ),
    }


def present_findings(
    findings: list[Any],
    region: str | None = None,
) -> list[dict[str, Any]]:
    result = []
    for finding in findings:
        if hasattr(finding, "__dict__") and not isinstance(finding, dict):
            data = {
                "id": finding.id,
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
                "finding_type": finding.finding_type,
                "title": getattr(finding, "title", None),
                "analyzer": finding.analyzer,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "reason": finding.reason,
                "recommendation_eligible": finding.recommendation_eligible,
                "conditions": finding.conditions,
                "evidence": finding.evidence,
                "limitations": finding.limitations,
            }
        else:
            data = dict(finding)
        result.append(present_finding(data, region=region))
    return result
