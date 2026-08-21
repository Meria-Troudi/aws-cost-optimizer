"""
Finding -> recommendation resolution.

Answers exactly one question: which recommendation definition (if
any) applies to this finding? No scoring, no grouping, no policy
enforcement -- see scoring.py / policy.py for those.
"""

from __future__ import annotations

from typing import Any

from .catalog import (
    RecommendationDefinition,
    get_definition,
    recommendation_route_for_finding,
)


def resolve_recommendation(
    finding: dict[str, Any],
) -> RecommendationDefinition | None:

    if not isinstance(
        finding,
        dict,
    ):
        return None

    route = recommendation_route_for_finding(
        finding
    )

    if route is None:
        return None

    return get_definition(
        route.recommendation_key
    )


def resolve_persistence_scope(
    *,
    recommendation_scope: str,
    finding: dict[str, Any],
) -> str:
    """
    Turn a recommendation's abstract scope (resource/region/service/
    account) into the concrete identity string persisted in the DB's
    `scope` column.

    This is the fix for the unique-constraint collision: for
    resource-scoped recommendations, `scope` must be the resource's
    own ID, not the region -- otherwise 3 same-region NAT gateways
    would all persist with the exact same
    (recommendation_key, recommendation_variant, resource_type, scope)
    tuple and collide.

    Raises ValueError when the finding is missing the field the
    requested scope needs. Callers must catch this per-finding (a
    single malformed finding must not abort recommendation generation
    for the rest of a scan).
    """

    scope = str(
        recommendation_scope
        or "resource"
    ).strip().lower()

    if scope == "resource":

        resource_id = finding.get(
            "resource_id"
        )

        if not resource_id:
            raise ValueError(
                "Resource-scoped recommendation requires "
                "resource_id."
            )

        return f"resource:{resource_id}"

    if scope == "region":

        region = finding.get(
            "region"
        )

        if not region:
            raise ValueError(
                "Region-scoped recommendation requires region."
            )

        return f"region:{region}"

    if scope == "service":

        service = finding.get(
            "service"
        )

        if not service:
            raise ValueError(
                "Service-scoped recommendation requires service."
            )

        return f"service:{service}"

    if scope == "account":

        account_id = finding.get(
            "account_id"
        )

        if not account_id:
            raise ValueError(
                "Account-scoped recommendation requires "
                "account_id."
            )

        return f"account:{account_id}"

    raise ValueError(
        f"Unsupported recommendation scope: {scope!r}"
    )
