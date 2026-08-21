"""
Collector execution manager.

"""

from __future__ import annotations

import traceback

from collection.registry import (
    load_collectors,
    get_collector,
)

from collection.persistence import (
    CollectorPersistence,
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
        region: str | None = None,
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
            f"\nExecuting collector: "
            f"{collector_name} [{region}]"
        )

        collector_class = get_collector(
            collector_name
        )

        if not collector_class:

            return {
                "collector":
                    collector_name,

                "region":
                    region,

                "status":
                    "failed",

                "error":
                    f"Collector not found: "
                    f"{collector_name}",
            }

        profile = self.profile_loader.get(
            collector_class.resource_type
        )

        if not profile:

            print(
                f"[WARNING] No collection_profiles.yaml entry "
                f"resolves for resource_type="
                f"{collector_class.resource_type!r} "
                f"(collector={collector_name!r}). The collector "
                f"will run with an empty profile -- identity/"
                f"configuration/observations config that should "
                f"come from the YAML will silently fall back to "
                f"collector-side defaults (or collect nothing). "
            )

        try:

            collector = collector_class(
                scan,
                region=region,
                profile=profile,
            )

            resources = collector.collect()

            if not isinstance(resources, list):
                raise TypeError(
                    "Collector.collect() must return a list"
                )

            # Billing is context only, and reconciliation (run per
            # resource, after this) writes an attribution verdict
            # onto each resource's own cost_context -- so every
            # resource must get its own copy. Sharing one dict
            # object here would mean promoting one resource to
            # resource-scoped cost silently promotes every sibling
            # resource in this same collector run too.
            if cost_context:

                for resource in resources:

                    if isinstance(resource, dict):
                        resource["cost_context"] = dict(
                            cost_context
                        )

            resource_ids = [
                str(resource.get("resource_id"))
                for resource in resources
                if (
                    isinstance(resource, dict)
                    and resource.get("resource_id")
                )
            ]

            print(
                f"[{collector_name}] "
                f"Resources returned: "
                f"{len(resources)}"
            )

        except Exception as exc:

            print(
                f"Collector failed: "
                f"{collector_name}"
            )

            traceback.print_exc()

            return {
                "collector":
                    collector_name,

                "region":
                    region,

                "status":
                    "failed",

                "error":
                    str(exc),
            }

        saved_resources = 0
        saved_observed_metrics = 0
        queried_metrics = 0
        no_data_metrics = 0
        metric_errors = 0
        topology_count = 0
        partial_resources = 0
        failed_resources = 0

        resource_summaries = []

        for resource in resources:

            if not isinstance(resource, dict):
                continue

            metric_counts = (
                self.persistence.metric_counts(
                    resource
                )
            )

            queried_metrics += (
                metric_counts["queried"]
            )

            saved_observed_metrics += (
                metric_counts["observed"]
            )

            no_data_metrics += (
                metric_counts["no_data"]
            )

            metric_errors += (
                metric_counts["errors"]
            )

            if resource.get(
                "topology"
            ):
                topology_count += 1

            if resource.get(
                "collection_status"
            ) == "partial":
                partial_resources += 1

            if resource.get(
                "collection_status"
            ) == "failed":
                failed_resources += 1

            try:

                self.persistence.save(
                    db,
                    scan,
                    resource,
                )

                saved_resources += 1

                resource_summaries.append(
                    {
                        "resource_id":
                            resource.get(
                                "resource_id"
                            ),

                        "collection_status":
                            resource.get(
                                "collection_status"
                            ),

                        "metric_counts":
                            metric_counts,

                        "topology_available":
                            (
                                resource.get(
                                    "topology",
                                    {}
                                ).get(
                                    "status"
                                )
                                == "ok"
                                if isinstance(
                                    resource.get(
                                        "topology"
                                    ),
                                    dict,
                                )
                                else False
                            ),
                    }
                )

            except Exception as exc:

                db.rollback()

                print(
                    f"ERROR saving resource "
                    f"{resource.get('resource_id')}: "
                    f"{exc}"
                )

                traceback.print_exc()

                failed_resources += 1

                continue

        try:

            db.commit()

        except Exception as exc:

            db.rollback()

            traceback.print_exc()

            return {
                "collector":
                    collector_name,

                "region":
                    region,

                "status":
                    "failed",

                "error":
                    f"Commit failed: {exc}",
            }

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
            "collector":
                collector_name,

            "region":
                region,

            "resource_type":
                collector_class.resource_type,

            "status":
                "completed",

            "resources":
                saved_resources,

            "resource_count":
                len(resources),

            "resource_ids":
                resource_ids,

            # Backwards-compatible observed count.
            "metrics":
                saved_observed_metrics,

            # Explicit counts.
            "queried_metrics":
                queried_metrics,

            "observed_metrics":
                saved_observed_metrics,

            "no_data_metrics":
                no_data_metrics,

            "metric_errors":
                metric_errors,

            "topology_resources":
                topology_count,

            "partial_resources":
                partial_resources,

            "failed_resources":
                failed_resources,

            "resource_summaries":
                resource_summaries,

            "resource_data":
                resources,
        }