"""
AWS Cost Optimizer - Scan Orchestrator

Pipeline stages:
1. SCAN                - Create ScanRun
2. COST COLLECTION     - CostCollector → CostRecord
3. COST ANALYSIS       - CostRecord aggregations
4. COLLECTION PLAN     - CollectionPlanner → CollectionPlan
5. RESOURCE COLLECTION - CollectorManager → Resources/Metrics/Topology
6. VALIDATION           - Billing/resource reconciliation → findings
7. FINDINGS             - Service analyzers + reconciliation findings
8. RECOMMENDATIONS      - RecommendationEngine
9. SUMMARY              - ScanExporter
"""

import os
import sys
import time

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    ),
)

from datetime import date

from sqlalchemy import func

from config.settings import (
    CE_REGION,
    DEFAULT_START_DATE,
    DEFAULT_END_DATE,
    DEFAULT_COST_THRESHOLD,
)

from aws_cost_optimizer.config.client import get_client

from backend.database.connection import (
    SessionLocal,
)

from backend.database.init_db import (
    init_db as init_database,
)

from backend.database.models.cost_record import (
    CostRecord,
)

from backend.database.repositories.scan_run_repository import (
    create_scan_run,
    complete_scan_run,
)

from collectors.cost.collector import (
    CostCollector,
)

from collectors.manager import (
    CollectorManager
)

from aws_cost_optimizer.planner.planner import (
    CollectionPlanner,
)

from inspection.exporter import (
    ScanExporter,
)


def main(
    region=None,
    cost_threshold=None,
    start_date=None,
    end_date=None,
):

    if cost_threshold is None:
        cost_threshold = (
            DEFAULT_COST_THRESHOLD
        )

    init_database()

    db = SessionLocal()

    scan_metrics = {
    "stage_durations": {},
    "cost_records": 0,
    "cost_collected": 0.0,
    "cost_validation": "N/A",
    "collection_plans": 0,

    "resources_collected": 0,

    "metrics_collected": 0,
    "metrics_queried": 0,
    "metrics_observed": 0,
    "metrics_no_data": 0,
    "metric_errors": 0,

    "topology_collected": 0,

    "contexts": 0,
    "findings": 0,
    "collection_not_found": 0,
}

    total_start = time.time()

    exporter = None

    try:

        sts = get_client(
            "sts",
            CE_REGION,
        )

        account_id = (
            sts.get_caller_identity()
            .get("Account")
        )

        start = date.fromisoformat(
            start_date
            or DEFAULT_START_DATE
        )

        end = date.fromisoformat(
            end_date
            or DEFAULT_END_DATE
        )

        scan = create_scan_run(
            db,

            account_id=account_id,

            start_date=start,

            end_date=end,

            region=region,

            cost_threshold=cost_threshold,
        )

        exporter = ScanExporter(
            scan
        )
        stage_start = time.time()

        collector = CostCollector()

        cost_validation = (
            collector.collect(
                db,
                scan,
            )
        )

        scan_metrics[
            "stage_durations"
        ][
            "cost_collection"
        ] = time.time() - stage_start

        scan_metrics[
            "cost_records"
        ] = (
            db.query(
                func.count(
                    CostRecord.id
                )
            )
            .filter(
                CostRecord.scan_run_id
                == scan.id
            )
            .scalar()
            or 0
        )

        scan_metrics[
            "cost_collected"
        ] = cost_validation.get(
            "collected_total",
            0.0,
        )

        scan_metrics[
            "cost_validation"
        ] = (
            "OK"
            if cost_validation.get(
                "matches"
            )
            else "FAILED"
        )

 
        stage_start = time.time()

        planner = CollectionPlanner()

        plans = planner.plan(
            db,
            scan,
        )

        scan_metrics[
            "stage_durations"
        ][
            "collection_plan"
        ] = time.time() - stage_start

        scan_metrics[
            "collection_plans"
        ] = len(plans)

        stage_start = time.time()

        manager = CollectorManager()

        results = []

        for plan in plans:

            cost_context = {
                "service":
                    plan.get("service"),

                "usage_type":
                    plan.get(
                        "usage_type"
                    ),

                "region":
                    plan.get("region"),

                "cost": {
                    "value":
                        plan.get(
                            "cost_context",
                            0,
                        ),

                    "currency":
                        "USD",

                    "scope":
                        "usage_type_region",

                    "resource_level_attribution":
                        False,
                },
            }

            try:

                result = manager.execute(
                    db=db,

                    scan=scan,

                    collector_name=plan[
                        "collector"
                    ],

                    region=plan[
                        "region"
                    ],

                    cost_context=cost_context,
                )

                results.append(
                    result
                )

                scan_metrics[
                    "resources_collected"
                ] += result.get(
                    "resources",
                    0,
                )

                scan_metrics[
                    "metrics_collected"
                ] += result.get(
                    "observed_metrics",
                    result.get("metrics", 0),
                )

                scan_metrics[
                    "metrics_queried"
                ] += result.get(
                    "queried_metrics",
                    0,
                )

                scan_metrics[
                    "metrics_observed"
                ] += result.get(
                    "observed_metrics",
                    result.get("metrics", 0),
                )

                scan_metrics[
                    "metrics_no_data"
                ] += result.get(
                    "no_data_metrics",
                    0,
                )

                scan_metrics[
                    "metric_errors"
                ] += result.get(
                    "metric_errors",
                    0,
                )

                scan_metrics[
                    "topology_collected"
                ] += result.get(
                    "topology_resources",
                    0,
                )

            except Exception as exc:

                results.append(
                    {
                        "collector":
                            plan[
                                "collector"
                            ],

                        "region":
                            plan[
                                "region"
                            ],

                        "resources":
                            0,

                        "metrics":
                            0,

                        "topology_resources":
                            0,

                        "status":
                            "failed",

                        "error":
                            str(exc),
                    }
                )

        db.commit()

        scan_metrics[
            "stage_durations"
        ][
            "resource_collection"
        ] = (
            time.time()
            - stage_start
        )

        from aws_cost_optimizer.collection.validation import (
            resources_for_analysis,
            validate_collection_results,
        )

        collection_validation = (
            validate_collection_results(
                plans,
                results,
            )
        )

        results = (
            collection_validation[
                "results"
            ]
        )
        reconciliation_findings = (
            collection_validation.get(
                "reconciliation_findings",
                [],
            )
        )

        scan_metrics[
            "collection_not_found"
        ] = (
            collection_validation.get(
                "not_found_count",
                0,
            )
        )

   
        stage_start = time.time()

        from aws_cost_optimizer.recommendations.optimization import (
            OptimizationPipeline,
        )

        pipeline = (
            OptimizationPipeline()
        )

        all_resources = (
            resources_for_analysis(
                results
            )
        )

        optimization_result = (
            pipeline.run(
                db=db,

                scan=scan,

                resources=all_resources,

                collection_plans=plans,
                pre_findings=
                    reconciliation_findings,
            )
        )

        all_findings = (
            optimization_result.get(
                "findings",
                [],
            )
        )

        all_recommendations = (
            optimization_result.get(
                "recommendations",
                [],
            )
        )

        scan_metrics[
            "stage_durations"
        ][
            "optimization"
        ] = (
            time.time()
            - stage_start
        )

        scan_metrics[
            "contexts"
        ] = len(
            all_resources
        )

        scan_metrics[
            "findings"
        ] = len(
            all_findings
        )

        db.commit()

        scan_metrics[
            "total_duration"
        ] = (
            time.time()
            - total_start
        )

        contexts = []

        for result in results:

            if result.get(
                "status"
            ) != "completed":

                continue

            contexts.append(
                {
                    "service":
                        result.get(
                            "service",
                            "",
                        ),

                    "region":
                        result.get(
                            "region",
                            "",
                        ),

                    "usage_type":
                        result.get(
                            "usage_type",
                            "",
                        ),

                    "cost":
                        result.get(
                            "cost",
                            0,
                        ),

                    "resource_type":
                        result.get(
                            "resource_type",
                            "",
                        ),

                    "resource_count":
                        result.get(
                            "resource_count",
                            0,
                        ),

                    "not_found":
                        result.get(
                            "not_found",
                            False,
                        ),

                    "recommendation_allowed":
                        result.get(
                            "recommendation_allowed",
                            True,
                        ),

                    "reconciliation_status":
                        result.get(
                            "reconciliation_status"
                        ),

                    "expected_identity":
                        result.get(
                            "reconciliation",
                            {},
                        ).get(
                            "expected_identity",
                            {},
                        ),

                    "evidence": {
                        "resources":
                            result.get(
                                "resource_data",
                                [],
                            ),
                    },
                }
            )

        summary_path = exporter.export(
            validation=
                cost_validation,

            plans=
                plans,

            results=
                results,

            contexts=
                contexts,

            scan_metrics=
                scan_metrics,

            findings=
                all_findings,

            recommendations=
                all_recommendations,
        )

        complete_scan_run(
            db,
            scan.id,
        )

        return summary_path

    except Exception:

        raise

    finally:

        db.close()


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(
        description=
            "AWS Cost Optimizer Scanner"
    )

    parser.add_argument(
        "--region",

        help=(
            "AWS region to scan "
            "(default: all regions)"
        ),

        default=None,
    )

    parser.add_argument(
        "--threshold",

        type=float,

        help=(
            "Cost threshold for collection "
            f"plan (default: "
            f"${DEFAULT_COST_THRESHOLD:.2f})"
        ),

        default=None,
    )

    parser.add_argument(
        "--start-date",

        help=(
            "Start date for cost analysis "
            f"(YYYY-MM-DD, default: "
            f"{DEFAULT_START_DATE})"
        ),

        default=None,
    )

    parser.add_argument(
        "--end-date",

        help=(
            "End date for cost analysis "
            f"(YYYY-MM-DD, default: "
            f"{DEFAULT_END_DATE})"
        ),

        default=None,
    )

    args = parser.parse_args()

    summary_path = main(
        region=args.region,

        cost_threshold=args.threshold,

        start_date=args.start_date,

        end_date=args.end_date,
    )

    if summary_path:

        print(
            summary_path
        )