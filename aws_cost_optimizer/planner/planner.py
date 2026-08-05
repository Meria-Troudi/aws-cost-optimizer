"""
CollectionPlanner
"""

from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database.models.cost_record import CostRecord
from backend.database.repository.collection_plan_repository import save_collection_plan

from aws_cost_optimizer.planner.resource_catalog import ResourceCatalog
from aws_cost_optimizer.planner.resolver import CatalogResolver


class CollectionPlanner:

    def __init__(self):
        self.catalog = ResourceCatalog()
        self.resolver = CatalogResolver(self.catalog.all())

    def plan(
        self,
        db: Session,
        scan
    ) -> List[Dict[str, Any]]:
        # Get aggregated cost records grouped by service, usage_type, region
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

        plans = []

        for aggregate in cost_aggregates:
            service = aggregate.service
            usage_type = aggregate.usage_type
            region = aggregate.region
            total_cost = aggregate.total_cost

            # Region filter
            if scan.region and region != scan.region:
                continue

            # Resolve to collector
            resolved = self.resolver.resolve(
                service,
                usage_type
            )

            if not resolved:
                continue

            # Determine priority based on cost
            if total_cost >= 500:
                priority = "high"
            elif total_cost >= 200:
                priority = "medium"
            else:
                priority = "low"

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

            # Persist to database
            save_collection_plan(db, plan_data)

            # Also return as dict for backward compatibility
            plans.append({
                "service": service,
                "region": region,
                "usage_type": usage_type,
                "resource_type": resolved["resource_type"],
                "collector": resolved["collector"],
                "priority": priority,
                "cost_context": total_cost,
            })

        db.flush()

        # Sort by cost descending
        return sorted(
            plans,
            key=lambda x: x["cost_context"],
            reverse=True
        )
