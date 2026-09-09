"""
CollectionPlanner
"""

from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database.models.cost_record import CostRecord
from backend.database.repositories.collection_plan_repository import (
    save_collection_plan,
)
from aws_cost_optimizer.planner.resource_catalog import ResourceCatalog
from aws_cost_optimizer.planner.resolver import CatalogResolver
from aws_cost_optimizer.planner.collection_profile import CollectionProfile


def _priority_for(total_cost: float) -> str:
    if total_cost >= 500:
        return "high"
    elif total_cost >= 100:
        return "medium"
    return "low"


class CollectionPlanner:
    def __init__(self):
        self.catalog = ResourceCatalog()
        self.resolver = CatalogResolver(self.catalog.all())
        self.profile_loader = CollectionProfile()

    def plan(self, db: Session, scan) -> List[Dict[str, Any]]:

        cost_aggregates = (
            db.query(
                CostRecord.service,
                CostRecord.usage_type,
                CostRecord.region,
                func.sum(CostRecord.amount).label("total_cost"),
            )
            .filter(CostRecord.scan_run_id == scan.id)
            .group_by(CostRecord.service, CostRecord.usage_type, CostRecord.region)
            .having(func.sum(CostRecord.amount) >= scan.cost_threshold)
            .order_by(func.sum(CostRecord.amount).desc())
            .all()
        )

        # Aggregate fully in memory first, then persist each final plan
        # exactly once. A resource type's cost is often split across
        # several billing usage types that all map to the same collector
        # (e.g. NAT Gateway hours + bytes) -- persisting on first sight of
        # each plan_key discarded every later, smaller usage-type line
        # entirely (save_collection_plan() only ever inserts, it never
        # upserts), silently undercounting the resource type's true total
        # cost. cost_context must be the SUM across every merged usage
        # type; service/usage_type stay the single largest-cost line, as
        # a representative identity for downstream billing-identity
        # inference, which already only ever consumed a single string.
        plan_map = {}
        for aggregate in cost_aggregates:
            service = aggregate.service
            usage_type = aggregate.usage_type
            region = aggregate.region
            total_cost = aggregate.total_cost
            if scan.region and region != scan.region:
                continue
            resolved = self.resolver.resolve(service, usage_type)
            if not resolved:
                save_collection_plan(
                    db,
                    {
                        "scan_run_id": scan.id,
                        "service": service,
                        "region": region,
                        "usage_type": usage_type,
                        "resource_type": "unmatched",
                        "collector_name": "none",
                        "priority": _priority_for(total_cost),
                        "cost_context": total_cost,
                        "status": "unmatched",
                    },
                )
                continue

            plan_key = (resolved["collector"], region, resolved["resource_type"])

            if plan_key in plan_map:
                entry = plan_map[plan_key]
                entry["cost_context"] += total_cost
                entry["priority"] = _priority_for(entry["cost_context"])
                if total_cost > entry["_driving_cost"]:
                    entry["_driving_cost"] = total_cost
                    entry["service"] = service
                    entry["usage_type"] = usage_type
                continue

            plan_map[plan_key] = {
                "service": service,
                "region": region,
                "usage_type": usage_type,
                "resource_type": resolved["resource_type"],
                "collector": resolved["collector"],
                "priority": _priority_for(total_cost),
                "cost_context": total_cost,
                "_driving_cost": total_cost,
            }

        plans = []
        for entry in plan_map.values():
            entry.pop("_driving_cost", None)
            save_collection_plan(
                db,
                {
                    "scan_run_id": scan.id,
                    "service": entry["service"],
                    "region": entry["region"],
                    "usage_type": entry["usage_type"],
                    "resource_type": entry["resource_type"],
                    "collector_name": entry["collector"],
                    "priority": entry["priority"],
                    "cost_context": entry["cost_context"],
                    "status": "planned",
                },
            )
            plans.append(entry)

        db.flush()
        return sorted(plans, key=lambda x: x["cost_context"], reverse=True)
