"""
Financial impact helpers.

Rules:
- Observed cost and savings are different concepts.
- Collection-plan/service/account cost is NOT automatically
  resource-level cost.
- Savings are only quantified when the cost is explicitly
  attributed to the affected resource, or when a future
  deterministic target_cost is supplied.
"""

from __future__ import annotations

from typing import Any


CONFIDENCE_LEVELS = {
    "high",
    "medium",
    "low",
}

ATTRIBUTION_SCOPES = {
    "resource",
    "collection_plan",
    "service",
    "historical",
    "unknown",
}


def calculate_savings(
    current_cost: float | None,
    *,
    confidence: str | None,
    attribution_scope: str | None = None,
    target_cost: float | None = None,
) -> dict[str, float | str | None]:
    """
    Calculate a conservative financial impact.

    Rules
    -----
    1. No cost:
        all financial values are None.

    2. Resource-attributed cost + target cost:
        savings = current - target.

    3. Resource-attributed cost + high confidence:
        savings may equal current cost.

    4. Non-resource-attributed cost:
        savings remain unquantified.

    This prevents collection-plan spend from being presented
    as savings for one individual resource.
    """

    normalized_confidence = (
        str(confidence).strip().lower()
        if confidence is not None
        else None
    )

    if normalized_confidence not in CONFIDENCE_LEVELS:
        normalized_confidence = None

    normalized_scope = (
        str(attribution_scope).strip().lower()
        if attribution_scope is not None
        else "unknown"
    )

    if normalized_scope not in ATTRIBUTION_SCOPES:
        normalized_scope = "unknown"

    if current_cost is None:
        return {
            "observed_monthly_cost": None,
            "estimated_monthly_savings": None,
            "savings_confidence": None,
            "savings_basis": "cost_unknown",
        }

    try:
        current = max(
            float(current_cost),
            0.0,
        )
    except (
        TypeError,
        ValueError,
    ):
        return {
            "observed_monthly_cost": None,
            "estimated_monthly_savings": None,
            "savings_confidence": None,
            "savings_basis": "cost_invalid",
        }

    # --------------------------------------------------------------
    # Cost exists, but it is not attributed to the affected
    # resource.
    #
    # Example:
    #
    #   NAT Gateway usage = $500
    #   3 NAT Gateways discovered
    #
    # We cannot claim that one NAT Gateway is responsible for $500.
    # --------------------------------------------------------------

    if normalized_scope != "resource":
        return {
            "observed_monthly_cost": round(
                current,
                2,
            ),
            "estimated_monthly_savings": None,
            "savings_confidence": None,
            "savings_basis": "cost_not_resource_attributed",
        }

    # --------------------------------------------------------------
    # Future rightsizing / target-based calculation.
    # --------------------------------------------------------------

    if target_cost is not None:
        try:
            target = max(
                float(target_cost),
                0.0,
            )
        except (
            TypeError,
            ValueError,
        ):
            target = None

        if target is not None:
            savings = max(
                current - target,
                0.0,
            )

            return {
                "observed_monthly_cost": round(
                    current,
                    2,
                ),
                "estimated_monthly_savings": round(
                    savings,
                    2,
                ),
                "savings_confidence": (
                    normalized_confidence
                ),
                "savings_basis": "target_cost",
            }

    # --------------------------------------------------------------
    # Whole-cost savings are only allowed when:
    #
    #   resource-attributed
    #   +
    #   high confidence
    #
    # This is still conservative compared with blindly using
    # collection-plan cost.
    # --------------------------------------------------------------

    if normalized_confidence == "high":
        savings = current

    else:
        savings = 0.0

    return {
        "observed_monthly_cost": round(
            current,
            2,
        ),
        "estimated_monthly_savings": round(
            savings,
            2,
        ),
        "savings_confidence": (
            normalized_confidence
        ),
        "savings_basis": (
            "resource_attributed"
        ),
    }


def normalize_financial_impact(
    value: Any,
) -> dict[str, Any]:
    """
    Normalize financial impact into one canonical format.

    Canonical fields:

        observed_monthly_cost
        estimated_monthly_savings
        savings_confidence
        savings_basis
        currency
    """

    if not isinstance(value, dict):
        return {
            "observed_monthly_cost": None,
            "estimated_monthly_savings": None,
            "savings_confidence": None,
            "savings_basis": "unknown",
            "currency": "USD",
        }

    observed_cost = value.get(
        "observed_monthly_cost"
    )

    savings = value.get(
        "estimated_monthly_savings"
    )

    confidence = value.get(
        "savings_confidence"
    )

    basis = value.get(
        "savings_basis"
    )

    currency = (
        value.get("currency")
        or "USD"
    )

    def _number(
        candidate: Any,
    ) -> float | None:

        if candidate is None:
            return None

        try:
            return round(
                float(candidate),
                2,
            )
        except (
            TypeError,
            ValueError,
        ):
            return None

    normalized_confidence = (
        str(confidence).strip().lower()
        if confidence is not None
        else None
    )

    if normalized_confidence not in CONFIDENCE_LEVELS:
        normalized_confidence = None

    return {
        "observed_monthly_cost":
            _number(observed_cost),

        "estimated_monthly_savings":
            _number(savings),

        "savings_confidence":
            normalized_confidence,

        "savings_basis":
            str(
                basis or "unknown"
            ).strip(),

        "currency":
            str(currency).strip()
            or "USD",
    }