"""
Collector manager
"""

import traceback
from collectors.registry import load_collectors, get_collector
from collectors.persistence import CollectorPersistence


class CollectorManager:

    def __init__(self):
        load_collectors()
        self.persistence = CollectorPersistence()

    def execute(self, db, scan, collector_name: str, region: str = None) -> dict:
        # Use plan region if provided, otherwise fall back to scan region
        if region is None:
            region = scan.region
        
        print(f"\nExecuting collector: {collector_name} [{region}]")

        # Validate region
        if not region:
            return {
                "collector": collector_name,
                "region": region,
                "status": "failed",
                "error": f"Collector '{collector_name}' requires a region"
            }

        collector_class = get_collector(collector_name)

        if not collector_class:
            return {
                "collector": collector_name,
                "region": region,
                "status": "failed",
                "error": f"Collector not found: {collector_name}"
            }

        # Execute collector
        try:
            collector = collector_class(scan, region=region)
            resources = collector.collect()
            print(f"[{collector_name}] Resources returned from collector: {len(resources)}")
        except Exception as e:
            print(f"Collector failed: {collector_name}")
            traceback.print_exc()
            return {
                "collector": collector_name,
                "region": region,
                "status": "failed",
                "error": str(e)
            }

        # Save resources with error isolation
        saved_resources = 0
        saved_metrics = 0

        for resource in resources:
            try:
                obj = self.persistence.save(
                    db,
                    scan,
                    resource,
                )
                saved_resources += 1
                saved_metrics += len(resource.get("metrics", []))
            except Exception as e:
                # Rollback transaction on error, but continue with other resources
                db.rollback()
                print(f"ERROR saving resource {resource.get('resource_id', 'unknown')}: {e}")
                traceback.print_exc()
                continue

        # Commit all successful saves
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"ERROR committing transaction: {e}")
            traceback.print_exc()
            return {
                "collector": collector_name,
                "region": region,
                "status": "failed",
                "error": f"Commit failed: {str(e)}"
            }

        print(f"{collector_name}: {saved_resources} resources, {saved_metrics} metrics")

        return {
            "collector": collector_name,
            "region": region,
            "status": "completed",
            "resources": saved_resources,
            "metrics": saved_metrics
        }
