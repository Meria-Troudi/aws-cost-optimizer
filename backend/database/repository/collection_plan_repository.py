"""
Collection plan persistence.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..models.collection_plan import CollectionPlan
from ..utils import json_dumps


def save_collection_plan(
    db: Session,
    data: dict[str, Any],
) -> CollectionPlan:

    plan = CollectionPlan(**data)
    db.add(plan)
    db.flush()
    return plan


def get_collection_plans_for_scan(
    db: Session,
    scan_run_id: int,
):
    return (
        db.query(CollectionPlan)
        .filter(CollectionPlan.scan_run_id == scan_run_id)
        .all()
    )