"""
Collector execution manager.
1. Load collectors
2. Resolve collection profile
3. Execute collector
4. Persist normalized results
"""
import traceback

from collectors.registry import (
    load_collectors,
    get_collector,
)
from collectors.persistence import (
    CollectorPersistence,
)
from aws_cost_optimizer.analysis.billing_consistency import (
    should_attach_rds_billing_context,
)
from aws_cost_optimizer.planner.collection_profile import (
    CollectionProfile,
)


class CollectorManager:

    def __init__(self):
        
        load_collectors()
        self.persistence = CollectorPersistence()
        self.profile_loader = CollectionProfile()

    def execute(
        self,
        db,
        scan,
        collector_name: str,
        region: str = None,
        cost_context: dict | None = None,
    ) -> dict:

        region = region or scan.region

        if not region:
            return {
                "collector": collector_name,
                "region": region,
                "status": "failed",
                "error": "Collector requires a region",
            }

        print(
            f"\nExecuting collector: {collector_name} [{region}]"
        )

        collector_class = get_collector(collector_name)

        if not collector_class:
            return {
                "collector": collector_name,
                "region": region,
                "status": "failed",
                "error": f"Collector not found: {collector_name}",
            }

        profile = self.profile_loader.get(
            collector_class.resource_type
        )

        try:
            collector = collector_class(
                scan,
                region=region,
                profile=profile,
            )
            resources = collector.collect()

            if cost_context:
                for resource in resources:
                    if should_attach_rds_billing_context(
                        resource,
                        cost_context,
                    ):
                        resource["cost_context"] = cost_context

            resource_ids = [
                str(resource.get("resource_id"))
                for resource in resources
                if resource.get("resource_id")
            ]

            print(
                f"[{collector_name}] Resources returned: {len(resources)}"
            )

        except Exception as e:
            print(f"Collector failed: {collector_name}")
            traceback.print_exc()
            return {
                "collector": collector_name,
                "region": region,
                "status": "failed",
                "error": str(e),
            }

        saved_resources = 0
        saved_metrics = 0
        topology_count = 0

        for resource in resources:
            try:
                self.persistence.save(db, scan, resource)
                saved_resources += 1
                saved_metrics += self.persistence.count_metrics(resource)
                if resource.get("topology"):
                    topology_count += 1
            except Exception as e:
                db.rollback()
                print(
                    f"ERROR saving resource {resource.get('resource_id')}: {e}"
                )
                traceback.print_exc()
                continue

        try:
            db.commit()
        except Exception as e:
            db.rollback()
            traceback.print_exc()
            return {
                "collector": collector_name,
                "region": region,
                "status": "failed",
                "error": f"Commit failed: {e}",
            }

        print(
            f"{collector_name}: {saved_resources} resources, "
            f"{saved_metrics} metrics, {topology_count} topology"
        )

        return {
            "collector": collector_name,
            "region": region,
            "resource_type": collector_class.resource_type,
            "status": "completed",
            "resources": saved_resources,
            "resource_count": len(resources),
            "resource_ids": resource_ids,
            "metrics": saved_metrics,
            "topology_resources": topology_count,
            "resource_data": resources,
        }