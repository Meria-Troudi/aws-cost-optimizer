"""Presentation-ready recommendation DTOs."""

from __future__ import annotations

import json
from typing import Any


def _parse_explanation(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        return {"reason": value}
    return {}


def present_recommendation(
    rec: dict[str, Any],
    *,
    resource_count: int | None = None,
    affected_resources: list[str] | None = None,
) -> dict[str, Any]:
    payload = _parse_explanation(rec.get("explanation") or rec.get("reason"))
    reason = payload.get("reason") or rec.get("reason") or rec.get("explanation") or ""

    resources = (
        affected_resources
        or payload.get("affected_resources")
        or rec.get("affected_resources")
        or []
    )
    count = resource_count or len(resources) or 0

    if count > 1:
        meta = f"{count} resources affected"
    elif resources:
        rid = str(resources[0])
        meta = rid if len(rid) <= 24 else f"{rid[:20]}…"
    elif rec.get("primary_resource_id"):
        rid = str(rec["primary_resource_id"])
        meta = rid if len(rid) <= 24 else f"{rid[:20]}…"
    else:
        meta = "Review required"

 

    return {
        **rec,
        "reason": reason,
        "rationale": reason,
        "explanation": reason,
        "meta": meta,
         "affected_resources": [str(r) for r in resources if r],
        "affected_resource_count": count or len(resources),
    }
