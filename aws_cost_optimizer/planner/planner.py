"""
CollectionPlanner
"""
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database.models.cost_record import CostRecord
from backend.database.repositories.collection_plan_repository import save_collection_plan
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

    def plan(
        self,
        db: Session,
        scan
    ) -> List[Dict[str, Any]]:
        
        cost_aggregates = (
            db.query(
                CostRecord.service,
                CostRecord.usage_type,
                CostRecord.region,
                func.sum(CostRecord.amount).label('total_cost')
            )
            .filter(CostRecord.scan_run_id == scan.id)
            .group_by(
                CostRecord.service,
                CostRecord.usage_type,
                CostRecord.region
            )
            .having(func.sum(CostRecord.amount) >= scan.cost_threshold)
            .order_by(func.sum(CostRecord.amount).desc())
            .all()
        )

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
                save_collection_plan(db, {
                    "scan_run_id": scan.id,
                    "service": service,
                    "region": region,
                    "usage_type": usage_type,
                    "resource_type": "unmatched",
                    "collector_name": "none",
                    "priority": _priority_for(total_cost),
                    "cost_context": total_cost,
                    "status": "unmatched",
                })
                continue

            plan_key = (resolved["collector"], region, resolved["resource_type"])

            if plan_key in plan_map:
                if total_cost > plan_map[plan_key]["cost_context"]:
                    plan_map[plan_key]["cost_context"] = total_cost
                    plan_map[plan_key]["priority"] = _priority_for(total_cost)
                    plan_map[plan_key]["service"] = service
                    plan_map[plan_key]["usage_type"] = usage_type
                continue

            priority = _priority_for(total_cost)
            plan_data = {
                "scan_run_id": scan.id,
                "service": service,
                "region": region,
                "usage_type": usage_type,
                "resource_type": resolved["resource_type"],
                "collector_name": resolved["collector"],
                "priority": priority,
                "cost_context": total_cost,
                "status": "planned",
            }
            save_collection_plan(db, plan_data)
            plan_map[plan_key] = {
                "service": service,
                "region": region,
                "usage_type": usage_type,
                "resource_type": resolved["resource_type"],
                "collector": resolved["collector"],
                "priority": priority,
                "cost_context": total_cost,
            }

        plans = list(plan_map.values())
        db.flush()
        return sorted(
            plans,
            key=lambda x: x["cost_context"],
            reverse=True
        )