"""
Scan service.

Runs the complete AWS cost optimization scan pipeline.

Pipeline:
1. Receive existing ScanRun
2. Collect Cost Explorer data
3. Analyze cosats
4. Create collection plan
5. Collect resources and metrics
6. Evaluate optimization rules
7. Generate recommendations
8. Persist everything in the database
"""

from __future__ import annotations

import time
from typing import Any

from backend.bootstrap import ensure_project_paths

ensure_project_paths()

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database.init_db import init_db
from backend.database.models.cost_record import CostRecord
from backend.database.repository.scan_run_repository import (
    complete_scan_run,
)

from aws_cost_optimizer.collectors.cost.collector import CostCollector
from aws_cost_optimizer.collectors.manager import CollectorManager

from aws_cost_optimizer.planner.planner import CollectionPlanner

from aws_cost_optimizer.recommendations.optimization import (
    OptimizationPipeline,
)


class ScanService:

    def __init__(self) -> None:
        init_db()

    def run_scan(
        self,
        db: Session,
        scan,
    ) -> dict[str, Any]:

        total_start = time.time()

        scan_id = scan.id
        account_id = scan.account_id

        start = scan.start_date
        end = scan.end_date

        region = scan.region
        cost_threshold = scan.cost_threshold

        try:

            cost_collector = CostCollector()

            cost_validation_result = cost_collector.collect(
                db,
                scan,
            )

            cost_records = (
                db.query(func.count(CostRecord.id))
                .filter(
                    CostRecord.scan_run_id == scan.id
                )
                .scalar()
                or 0
            )

            cost_collected = cost_validation_result.get(
                "collected_total",
                0.0,
            )

            cost_validation = (
                "OK"
                if cost_validation_result.get("matches")
                else "FAILED"
            )


            planner = CollectionPlanner()

            plans = planner.plan(
                db,
                scan,
            )

            collection_plans = len(plans)

            manager = CollectorManager()

            results: list[dict[str, Any]] = []

            resources_collected = 0
            metrics_collected = 0
            topology_collected = 0

            for plan in plans:

                cost_context = {
                    "service": plan.get("service"),
                    "usage_type": plan.get("usage_type"),
                    "region": plan.get("region"),
                    "cost": {
                        "value": plan.get(
                            "cost_context",
                            0,
                        ),
                        "currency": "USD",
                        "scope": "usage_type_region",
                        "resource_level_attribution": False,
                    },
                }

                try:

                    result = manager.execute(
                        db=db,
                        scan=scan,
                        collector_name=plan["collector"],
                        region=plan["region"],
                        cost_context=cost_context,
                    )

                    results.append(result)

                    resources_collected += result.get(
                        "resources",
                        0,
                    )

                    metrics_collected += result.get(
                        "metrics",
                        0,
                    )

                    topology_collected += result.get(
                        "topology_resources",
                        0,
                    )

                except Exception as exc:

                    results.append(
                        {
                            "collector": plan["collector"],
                            "region": plan["region"],
                            "resources": 0,
                            "metrics": 0,
                            "status": "failed",
                            "error": str(exc),
                        }
                    )

            db.flush()

            from aws_cost_optimizer.collection.validation import (
                resources_for_analysis,
                validate_collection_results,
            )

            collection_validation = validate_collection_results(
                plans,
                results,
            )
            results = collection_validation["results"]

            all_resources = resources_for_analysis(results)

            pipeline = OptimizationPipeline()

            optimization_result = pipeline.run(
                db=db,
                scan=scan,
                resources=all_resources,
                enriched_results=results,
                collection_plans=plans,
            )

            all_findings = optimization_result.get(
                "findings",
                [],
            )

            all_recommendations = optimization_result.get(
                "recommendations",
                [],
            )

            db.flush()


            duration = time.time() - total_start

            complete_scan_run(
                db,
                scan.id,
            )

            db.commit()


            return {
                "scan_id": scan.id,
                "account_id": account_id,
                "start_date": start.isoformat(),
                "end_date": end.isoformat(),
                "region": region,
                "cost_threshold": cost_threshold,
                "status": "completed",

                "metrics": {
                    "duration_seconds": round(
                        duration,
                        2,
                    ),
                    "cost_records": cost_records,
                    "cost_collected": float(
                        cost_collected
                    ),
                    "cost_validation": cost_validation,
                    "collection_plans": collection_plans,
                    "resources_collected": resources_collected,
                    "metrics_collected": metrics_collected,
                    "topology_collected": topology_collected,
                    "contexts": len(all_resources),
                    "findings": len(all_findings),
                    "recommendations": len(
                        all_recommendations
                    ),
                },
            }

        except Exception:

            scan.status = "failed"

            db.commit()

            raise
