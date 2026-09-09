"""
Collector execution manager.
"""

from __future__ import annotations

import traceback

from collection.registry import (
    get_collector,
    load_collectors,
)

from collection.persistence import (
    CollectorPersistence,
)

from aws_cost_optimizer.planner.collection_profile import (
    CollectionProfile,
)

VALID_COLLECTION_STATUSES = frozenset({"completed", "partial", "failed"})

COLLECTION_STATUS_ALIASES = {
    "complete": "completed",
    "ok": "completed",
    "success": "completed",
}


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
        region: str | None = None,
        collection_plan_id: int | str | None = None,
    ) -> dict:

        region = region or scan.region

        if not region:
            return {
                "collector": collector_name,
                "collection_plan_id": collection_plan_id,
                "region": region,
                "status": "failed",
                "error": "Collector requires a region",
            }

        print(f"\nExecuting collector: " f"{collector_name} [{region}]")

        collector_class = get_collector(collector_name)

        if not collector_class:
            return {
                "collector": collector_name,
                "collection_plan_id": collection_plan_id,
                "region": region,
                "status": "failed",
                "error": (f"Collector not found: " f"{collector_name}"),
            }

        profile = self.profile_loader.get(collector_class.resource_type)

        if not profile:

            print(
                "[WARNING] No collection_profiles.yaml "
                f"entry resolves for "
                f"resource_type="
                f"{collector_class.resource_type!r} "
                f"(collector={collector_name!r})."
            )

        try:

            collector = collector_class(
                scan,
                region=region,
                profile=profile,
            )
            resources = collector.collect()
            if not isinstance(resources, list):
                raise TypeError("Collector.collect() " "must return a list")
            discovered_resource_ids = [
                str(resource.get("resource_id"))
                for resource in resources
                if (isinstance(resource, dict) and resource.get("resource_id"))
            ]

            print(f"[{collector_name}] " f"Resources returned: " f"{len(resources)}")

        except Exception as exc:

            print(f"Collector failed: " f"{collector_name}")

            traceback.print_exc()

            return {
                "collector": collector_name,
                "collection_plan_id": collection_plan_id,
                "region": region,
                "status": "failed",
                "error": str(exc),
            }

        saved_resources = 0
        saved_observed_metrics = 0
        queried_metrics = 0
        no_data_metrics = 0
        metric_errors = 0
        topology_count = 0
        partial_resources = 0
        collection_failed_resources = 0
        persistence_failed_resources = 0

        persisted_resource_ids = []

        usable_resources = []

        resource_summaries = []
        for resource in resources:
            if not isinstance(resource, dict):
                continue

            rid = resource.get("resource_id")
            rtyp = resource.get("resource_type")
            if not rid or not rtyp:
                print(
                    f"  SKIP resource missing identity: "
                    f"resource_id={rid!r}, resource_type={rtyp!r}"
                )
                collection_failed_resources += 1
                continue

            # Guard against collector emitting uncontrolled status strings.
            raw_status = str(resource.get("collection_status") or "").strip().lower()
            raw_status = COLLECTION_STATUS_ALIASES.get(
                raw_status,
                raw_status,
            )
            safe_status = (
                raw_status if raw_status in VALID_COLLECTION_STATUSES else "failed"
            )
            resource["collection_status"] = safe_status

            metric_counts = self.persistence.metric_counts(resource)

            queried_metrics += metric_counts["queried"]
            saved_observed_metrics += metric_counts["observed"]

            no_data_metrics += metric_counts["no_data"]
            metric_errors += metric_counts["errors"]
            if resource.get("topology"):
                topology_count += 1

            collection_status = resource.get("collection_status")
            if collection_status == "failed":
                collection_failed_resources += 1
                continue

            if collection_status == "partial":
                partial_resources += 1

            try:

                with db.begin_nested():
                    self.persistence.save(
                        db,
                        scan,
                        resource,
                    )

                saved_resources += 1

                usable_resources.append(resource)

                persisted_resource_ids.append(str(resource.get("resource_id")))

                resource_summaries.append(
                    {
                        "resource_id": resource.get("resource_id"),
                        "collection_status": (collection_status),
                        "metric_counts": metric_counts,
                        "topology_available": (
                            resource.get(
                                "topology",
                                {},
                            ).get("status")
                            == "ok"
                            if isinstance(
                                resource.get("topology"),
                                dict,
                            )
                            else False
                        ),
                    }
                )

            except Exception as exc:

                print(
                    f"ERROR saving resource "
                    f"{resource.get('resource_id')}: "
                    f"{exc}"
                )

                traceback.print_exc()

                persistence_failed_resources += 1

                continue

        try:

            db.commit()

        except Exception as exc:

            db.rollback()

            traceback.print_exc()

            return {
                "collector": collector_name,
                "collection_plan_id": collection_plan_id,
                "region": region,
                "status": "failed",
                "error": (f"Commit failed: {exc}"),
            }

        if (
            collection_failed_resources > 0
            or persistence_failed_resources > 0
            or partial_resources > 0
        ):
            collection_status = "partial"

        else:
            collection_status = "completed"

        print(
            f"{collector_name}: "
            f"{saved_resources} resources, "
            f"queried={queried_metrics}, "
            f"observed={saved_observed_metrics}, "
            f"no_data={no_data_metrics}, "
            f"errors={metric_errors}, "
            f"topology={topology_count}"
        )

        return {
            "collector": collector_name,
            "collection_plan_id": collection_plan_id,
            "region": region,
            "resource_type": (collector_class.resource_type),
            "status": collection_status,
            "discovered_count": len(resources),
            "persisted_count": saved_resources,
            "discovered_resource_ids": discovered_resource_ids,
            "persisted_resource_ids": persisted_resource_ids,
            "discovered_resource_data": resources,
            "resource_data": usable_resources,
            "queried_metrics": queried_metrics,
            "observed_metrics": saved_observed_metrics,
            "no_data_metrics": no_data_metrics,
            "metric_errors": metric_errors,
            "topology_resources": topology_count,
            "partial_resources": partial_resources,
            "collection_failed_resources": (collection_failed_resources),
            "persistence_failed_resources": (persistence_failed_resources),
            "resource_summaries": resource_summaries,
        }
