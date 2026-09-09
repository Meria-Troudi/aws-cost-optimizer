"""
Recommendation priority scoring.

"""

from __future__ import annotations

from typing import Any

from aws_cost_optimizer.analysis.ranking import CONFIDENCE_RANK, SEVERITY_RANK

_PRIORITY_ORDER = ("info", "low", "medium", "high", "critical")

ESCALATE_ABOVE_MONTHLY_COST = 500.0
DEESCALATE_BELOW_MONTHLY_COST = 5.0


def _step(priority: str, direction: int) -> str:
    index = _PRIORITY_ORDER.index(priority)
    index = max(0, min(len(_PRIORITY_ORDER) - 1, index + direction))
    return _PRIORITY_ORDER[index]


def _resource_attributed_cost(finding: dict[str, Any]) -> float | None:
    impact = finding.get("impact")

    if not isinstance(impact, dict):
        return None

    cost = impact.get("observed_monthly_cost")

    if isinstance(cost, bool) or not isinstance(cost, (int, float)):
        return None

    return float(cost)


def score(
    finding: dict[str, Any],
    default_priority: str,
) -> tuple[str, str]:

    confidence = (
        str(
            finding.get(
                "confidence",
                "low",
            )
            or "low"
        )
        .strip()
        .lower()
    )

    if confidence not in CONFIDENCE_RANK:
        confidence = "low"

    severity = str(finding.get("severity") or "").strip().lower()

    if severity in SEVERITY_RANK:
        priority = severity
    else:
        priority = str(default_priority or "medium").strip().lower()

        if priority not in SEVERITY_RANK:
            priority = "medium"

    cost = _resource_attributed_cost(finding)

    if cost is not None:

        if cost >= ESCALATE_ABOVE_MONTHLY_COST:
            priority = _step(priority, 1)

        elif cost < DEESCALATE_BELOW_MONTHLY_COST:
            priority = _step(priority, -1)

    return priority, confidence
