"""
CollectionPlan repository - persistence layer for planner output.
"""

from sqlalchemy.orm import Session

from backend.database.models.collection_plan import CollectionPlan


def save_collection_plan(db: Session, data: dict) -> CollectionPlan:
    existing = (
        db.query(CollectionPlan)
        .filter(
            CollectionPlan.scan_run_id == data["scan_run_id"],
            CollectionPlan.service == data["service"],
            CollectionPlan.region == data.get("region"),
            CollectionPlan.usage_type == data["usage_type"],
        )
        .first()
    )

    if existing:
        for key, value in data.items():
            setattr(existing, key, value)
        db.flush()
        return existing

    obj = CollectionPlan(**data)
    db.add(obj)
    db.flush()
    return obj

