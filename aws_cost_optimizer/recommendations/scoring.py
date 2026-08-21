"""
Recommendation priority scoring.

Two factors only for this pass, deliberately not more: financial
value is primary, confidence is a tiebreaker used at sort time (see
engine.py's sort key). A third "evidence completeness" factor is
left out until there is real recommendation data to justify how it
should be weighted -- adding it now would just be an unvalidated
guess dressed up as a formula.

Reuses analysis/ranking.py's shared severity/confidence ordering
rather than redefining a second ranking system.
"""

from __future__ import annotations

from typing import Any

from aws_cost_optimizer.analysis.ranking import CONFIDENCE_RANK

# Monthly financial value -> priority label. Checked highest-first;
# the first threshold the value clears wins. These are this
# project's own FinOps policy, not AWS facts -- plain constants for
# now rather than YAML config, since there's no data yet to justify
# exposing them as tunable.
FINANCIAL_PRIORITY_THRESHOLDS: tuple[
    tuple[float, str], ...
] = (
    (500.0, "critical"),
    (100.0, "high"),
    (25.0, "medium"),
)


def _financial_value(
    finding: dict[str, Any],
) -> float | None:
    """
    Only ever reads cost that is confirmed as THIS resource's own --
    never shared/collection-plan/service-level cost. A NAT gateway's
    $350.40 collection-plan bill must never move this resource's
    priority just because it happens to sit on the same billing line
    as two other gateways.
    """

    evidence = finding.get("evidence")

    if not isinstance(
        evidence,
        dict,
    ):
        return None

    billing = evidence.get("billing")

    if not isinstance(
        billing,
        dict,
    ):
        return None

    if billing.get(
        "attribution_scope"
    ) != "resource":
        return None

    impact = finding.get("impact")

    if not isinstance(
        impact,
        dict,
    ):
        impact = {}

    savings = impact.get(
        "estimated_monthly_savings"
    )

    if (
        isinstance(savings, (int, float))
        and not isinstance(savings, bool)
        and savings > 0
    ):
        return float(savings)

    cost = impact.get(
        "observed_monthly_cost"
    )

    if (
        isinstance(cost, (int, float))
        and not isinstance(cost, bool)
    ):
        return float(cost)

    return None


def score(
    finding: dict[str, Any],
    default_priority: str,
) -> tuple[str, str]:
    """
    Returns (priority, confidence). `default_priority` is the
    catalog definition's static priority, used as the fallback when
    there is no resource-attributed financial signal to rank by.
    """

    confidence = str(
        finding.get(
            "confidence",
            "low",
        )
        or "low"
    ).strip().lower()

    if confidence not in CONFIDENCE_RANK:
        confidence = "low"

    financial_value = _financial_value(
        finding
    )

    if financial_value is None:
        return default_priority, confidence

    for threshold, label in (
        FINANCIAL_PRIORITY_THRESHOLDS
    ):

        if financial_value >= threshold:
            return label, confidence

    if financial_value > 0:
        return "low", confidence

    return default_priority, confidence
