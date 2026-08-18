"""
Scan execution service.

"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func

from aws_cost_optimizer.collectors.cost.collector import CostCollector
from aws_cost_optimizer.planner.planner import CollectionPlanner
from aws_cost_optimizer.collectors.manager import CollectorManager

from aws_cost_optimizer.collection.validation import (
    resources_for_analysis,
    validate_collection_results,
)

from aws_cost_optimizer.recommendations.optimization import (
    OptimizationPipeline,
)

from backend.database.models.cost_record import CostRecord
from backend.database.repositories.scan_run_repository import update_scan_progress


class ScanService:

    def __init__(self, db):
        self.db = db

 
    def run(self, scan) -> dict[str, Any]:
      

        total_start = time.time()

        scan_metrics: dict[str, Any] = {
            "stage_durations": {},

            # Cost
            "cost_records": 0,
            "cost_collected": 0.0,
            "cost_validation": "N/A",

            # Planning
            "collection_plans": 0,

            # Resources
            "resources_collected": 0,
            "resource_attempted": 0,

            # Metrics
            "metrics_collected": 0,
            "metrics_queried": 0,
            "metrics_observed": 0,
            "metrics_no_data": 0,
            "metric_errors": 0,

            # Topology
            "topology_collected": 0,

            # Optimization
            "contexts": 0,
            "findings": 0,
            "recommendations": 0,

            # Collection validation
            "collection_not_found": 0,
            "failed_collectors": 0,
            "partial_collectors": 0,

            # Overall
            "total_duration": 0.0,
        }

        plans: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        reconciliation_findings: list[dict[str, Any]] = []

        cost_validation: dict[str, Any] = {}
        all_findings: list[dict[str, Any]] = []
        all_recommendations: list[dict[str, Any]] = []

        try:
    
            self._set_status(
                scan,
                "running",
            )

            self._safe_commit()

            self._report_progress(scan, 5)

            stage_start = time.time()

            cost_collector = CostCollector()

            cost_validation = cost_collector.collect(
                self.db,
                scan,
            )

            self._report_progress(scan, 15)

            scan_metrics["stage_durations"][
                "cost_collection"
            ] = time.time() - stage_start

            scan_metrics["cost_records"] = (
                self.db.query(
                    func.count(CostRecord.id)
                )
                .filter(
                    CostRecord.scan_run_id == scan.id
                )
                .scalar()
                or 0
            )

            scan_metrics["cost_collected"] = float(
                cost_validation.get(
                    "collected_total",
                    0.0,
                )
                or 0.0
            )

            scan_metrics["cost_validation"] = (
                "OK"
                if cost_validation.get("matches")
                else "FAILED"
            )

            if not cost_validation:
                raise RuntimeError(
                    "Cost collection returned no validation result."
                )

            stage_start = time.time()

            planner = CollectionPlanner()

            raw_plans = planner.plan(
                self.db,
                scan,
            )

            plans = self._normalize_plans(
                raw_plans
            )

            scan_metrics["stage_durations"][
                "collection_plan"
            ] = time.time() - stage_start

            scan_metrics["collection_plans"] = len(
                plans
            )

            self._report_progress(scan, 25)

            stage_start = time.time()

            manager = CollectorManager()

            total_plans = len(plans) or 1

            for plan_index, plan in enumerate(
                plans,
                start=1,
            ):

                scan_metrics["resource_attempted"] += 1

                collector_name = (
                    plan.get("collector")
                    or plan.get("collector_name")
                )

                region = (
                    plan.get("region")
                    or getattr(
                        scan,
                        "region",
                        None,
                    )
                )

                service = plan.get(
                    "service",
                    "",
                )

                usage_type = plan.get(
                    "usage_type",
                    "",
                )

                cost_value = float(
                    plan.get(
                        "cost_context",
                        0.0,
                    )
                    or 0.0
                )

                # ------------------------------------------
                # Invalid plan
                # ------------------------------------------

                if not collector_name:
                    result = {
                        "collector": None,
                        "service": service,
                        "usage_type": usage_type,
                        "region": region,
                        "resources": 0,
                        "resource_count": 0,
                        "metrics": 0,
                        "queried_metrics": 0,
                        "observed_metrics": 0,
                        "no_data_metrics": 0,
                        "metric_errors": 0,
                        "topology_resources": 0,
                        "status": "failed",
                        "error": (
                            "Collection plan does not contain "
                            "a collector name."
                        ),
                    }

                    results.append(result)

                    scan_metrics[
                        "failed_collectors"
                    ] += 1

                    continue

                if not region:
                    result = {
                        "collector": collector_name,
                        "service": service,
                        "usage_type": usage_type,
                        "region": region,
                        "resources": 0,
                        "resource_count": 0,
                        "metrics": 0,
                        "queried_metrics": 0,
                        "observed_metrics": 0,
                        "no_data_metrics": 0,
                        "metric_errors": 0,
                        "topology_resources": 0,
                        "status": "failed",
                        "error": (
                            "Collector requires a region."
                        ),
                    }

                    results.append(result)

                    scan_metrics[
                        "failed_collectors"
                    ] += 1

                    continue

                # ------------------------------------------
                # Billing context
                # ------------------------------------------

                cost_context = {
                    "service": service,
                    "usage_type": usage_type,
                    "region": region,
                    "cost": {
                        "value": cost_value,
                        "currency": "USD",
                        "scope": "usage_type_region",
                        "resource_level_attribution": False,
                    },
                }

                try:

                    result = manager.execute(
                        db=self.db,
                        scan=scan,
                        collector_name=collector_name,
                        region=region,
                        cost_context=cost_context,
                    )

                    if not isinstance(
                        result,
                        dict,
                    ):
                        raise TypeError(
                            "CollectorManager.execute() "
                            "must return a dictionary."
                        )

                except Exception as exc:

                    result = {
                        "collector": collector_name,
                        "service": service,
                        "usage_type": usage_type,
                        "region": region,
                        "resources": 0,
                        "resource_count": 0,
                        "metrics": 0,
                        "queried_metrics": 0,
                        "observed_metrics": 0,
                        "no_data_metrics": 0,
                        "metric_errors": 0,
                        "topology_resources": 0,
                        "status": "failed",
                        "error": str(exc),
                    }

                # Make sure planner context is retained.
                result.setdefault(
                    "service",
                    service,
                )

                result.setdefault(
                    "usage_type",
                    usage_type,
                )

                result.setdefault(
                    "region",
                    region,
                )

                result.setdefault(
                    "collector",
                    collector_name,
                )

                results.append(result)

                status = str(
                    result.get(
                        "status",
                        "unknown",
                    )
                ).lower()

                if status == "failed":
                    scan_metrics[
                        "failed_collectors"
                    ] += 1

                elif (
                    result.get(
                        "partial_resources",
                        0,
                    )
                    or 0
                ):
                    scan_metrics[
                        "partial_collectors"
                    ] += 1

                # Returned resources
                resources_count = self._safe_int(
                    result.get(
                        "resources",
                        result.get(
                            "resource_count",
                            0,
                        ),
                    )
                )

                scan_metrics[
                    "resources_collected"
                ] += resources_count

                # Metrics queried
                scan_metrics[
                    "metrics_queried"
                ] += self._safe_int(
                    result.get(
                        "queried_metrics",
                        0,
                    )
                )

                # Metrics observed
                observed = self._safe_int(
                    result.get(
                        "observed_metrics",
                        result.get(
                            "metrics",
                            0,
                        ),
                    )
                )

                scan_metrics[
                    "metrics_observed"
                ] += observed

                # Explicit no-data metrics
                scan_metrics[
                    "metrics_no_data"
                ] += self._safe_int(
                    result.get(
                        "no_data_metrics",
                        0,
                    )
                )

                # Metric errors
                scan_metrics[
                    "metric_errors"
                ] += self._safe_int(
                    result.get(
                        "metric_errors",
                        0,
                    )
                )

                # Topology
                scan_metrics[
                    "topology_collected"
                ] += self._safe_int(
                    result.get(
                        "topology_resources",
                        0,
                    )
                )

            self._safe_commit()

            self._report_progress(scan, 55)

            scan_metrics["metrics_collected"] = (
                scan_metrics["metrics_observed"]
            )

            scan_metrics["stage_durations"][
                "resource_collection"
            ] = time.time() - stage_start

            stage_start = time.time()

            collection_validation = (
                validate_collection_results(
                    plans,
                    results,
                )
            )

            if not isinstance(
                collection_validation,
                dict,
            ):
                collection_validation = {
                    "results": results,
                    "reconciliation_findings": [],
                    "not_found_count": 0,
                }

            validated_results = collection_validation.get(
                "results",
                results,
            )

            if not isinstance(
                validated_results,
                list,
            ):
                validated_results = results

            results = validated_results

            reconciliation_findings = (
                collection_validation.get(
                    "reconciliation_findings",
                    [],
                )
            )

            if not isinstance(
                reconciliation_findings,
                list,
            ):
                reconciliation_findings = []

            scan_metrics[
                "collection_not_found"
            ] = self._safe_int(
                collection_validation.get(
                    "not_found_count",
                    0,
                )
            )

            scan_metrics["stage_durations"][
                "collection_validation"
            ] = time.time() - stage_start

            self._report_progress(scan, 65)

            stage_start = time.time()

            all_resources = resources_for_analysis(
                results
            )

            if all_resources is None:
                all_resources = []

            optimization_result = (
                OptimizationPipeline().run(
                    db=self.db,
                    scan=scan,
                    resources=all_resources,
                    collection_plans=plans,
                    pre_findings=reconciliation_findings,
                )
            )

            if not isinstance(
                optimization_result,
                dict,
            ):
                raise TypeError(
                    "OptimizationPipeline.run() "
                    "must return a dictionary."
                )

            all_findings = optimization_result.get(
                "findings",
                [],
            )

            all_recommendations = (
                optimization_result.get(
                    "recommendations",
                    [],
                )
            )

            if not isinstance(
                all_findings,
                list,
            ):
                all_findings = []

            if not isinstance(
                all_recommendations,
                list,
            ):
                all_recommendations = []

            scan_metrics["stage_durations"][
                "optimization"
            ] = time.time() - stage_start

            self._report_progress(scan, 90)

            scan_metrics["contexts"] = len(
                all_resources
            )

            scan_metrics["findings"] = len(
                all_findings
            )

            scan_metrics["recommendations"] = len(
                all_recommendations
            )

            scan_metrics["total_duration"] = (
                time.time() - total_start
            )

            self._report_progress(scan, 100)

            self._set_status(
                scan,
                "completed",
            )

            self._set_outcome(
                scan,
                {
                    "status": "completed",
                    "metrics": scan_metrics,
                },
            )

            self._safe_commit()

            return {
                "scan_id": scan.id,
                "status": "completed",

                "cost_validation": cost_validation,

                "plans": plans,

                "collection_results": results,

                "reconciliation_findings":
                    reconciliation_findings,

                "findings":
                    all_findings,

                "recommendations":
                    all_recommendations,

                "metrics":
                    scan_metrics,
            }

        except Exception as exc:

            error_message = str(exc)

            scan_metrics["total_duration"] = (
                time.time() - total_start
            )

            self._safe_rollback()

            try:


                try:
                    self.db.refresh(scan)
                except Exception:
                    pass

                self._set_status(
                    scan,
                    "failed",
                )

                self._set_error(
                    scan,
                    error_message,
                )

                self._set_outcome(
                    scan,
                    {
                        "status": "failed",
                        "error": error_message,
                        "metrics": scan_metrics,
                    },
                )

                self._safe_commit()

            except Exception:
                self._safe_rollback()

            raise

    @staticmethod
    def _normalize_plans(
        raw_plans: Any,
    ) -> list[dict[str, Any]]:


        if raw_plans is None:
            return []

        if not isinstance(
            raw_plans,
            list,
        ):
            try:
                raw_plans = list(raw_plans)
            except TypeError:
                raise TypeError(
                    "CollectionPlanner.plan() must return "
                    "a list of plans."
                )

        normalized: list[dict[str, Any]] = []

        for plan in raw_plans:

            if isinstance(
                plan,
                dict,
            ):
                item = dict(plan)

            else:
            
                item = {}

                for field in (
                    "service",
                    "region",
                    "usage_type",
                    "resource_type",
                    "collector",
                    "collector_name",
                    "priority",
                    "cost_context",
                    "status",
                ):
                    if hasattr(
                        plan,
                        field,
                    ):
                        item[field] = getattr(
                            plan,
                            field,
                        )

            collector = (
                item.get("collector")
                or item.get("collector_name")
            )

            item["collector"] = collector

            item.setdefault(
                "service",
                "",
            )

            item.setdefault(
                "region",
                None,
            )

            item.setdefault(
                "usage_type",
                "",
            )

            item.setdefault(
                "resource_type",
                "",
            )

            item.setdefault(
                "cost_context",
                0.0,
            )

            normalized.append(item)

        return normalized

    def _report_progress(
        self,
        scan,
        progress_percent: float,
    ) -> None:
        """
        Persist scan progress so the dashboard can show
        live status without coupling frontend state.
        """

        try:
            update_scan_progress(
                self.db,
                scan.id,
                progress_percent,
            )

            self._safe_commit()
        except Exception:
            self._safe_rollback()

    @staticmethod
    def _set_status(
        scan,
        status: str,
    ) -> None:
       

        scan.status = status

        if status in {
            "completed",
            "failed",
        }:

            if hasattr(
                scan,
                "finished_at",
            ):
                scan.finished_at = datetime.now(
                    timezone.utc
                ).replace(
                    tzinfo=None
                )

    @staticmethod
    def _set_error(
        scan,
        message: str,
    ) -> None:
       

        if hasattr(
            scan,
            "error_message",
        ):
            scan.error_message = str(
                message
            )

    @staticmethod
    def _set_outcome(
        scan,
        outcome: Any,
    ) -> None:
       

        if not hasattr(
            scan,
            "outcome",
        ):
            return

        try:
            import json

            scan.outcome = json.dumps(
                outcome,
                default=str,
            )

        except Exception:
            scan.outcome = str(
                outcome
            )

    def _safe_commit(self) -> None:
        

        self.db.commit()

    def _safe_rollback(self) -> None:
       

        try:
            self.db.rollback()
        except Exception:
            pass

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int:
       

        if value is None:
            return 0

        try:
            return int(value)

        except (
            TypeError,
            ValueError,
        ):
            return 0

    def build_summary(
        self,
        result: dict[str, Any],
    ) -> dict[str, Any]:
       
        metrics = result.get(
            "metrics",
            {},
        )

        if not isinstance(
            metrics,
            dict,
        ):
            metrics = {}

        findings = result.get(
            "findings",
            [],
        )

        recommendations = result.get(
            "recommendations",
            [],
        )

        if not isinstance(
            findings,
            list,
        ):
            findings = []

        if not isinstance(
            recommendations,
            list,
        ):
            recommendations = []

        return {
            "scan_id": result.get(
                "scan_id"
            ),

            "status": result.get(
                "status"
            ),

            "total_cost": float(
                metrics.get(
                    "cost_collected",
                    0.0,
                )
                or 0.0
            ),

            "resources": self._safe_int(
                metrics.get(
                    "resources_collected",
                    0,
                )
            ),

            "metrics_queried": self._safe_int(
                metrics.get(
                    "metrics_queried",
                    0,
                )
            ),

            "metrics_observed": self._safe_int(
                metrics.get(
                    "metrics_observed",
                    0,
                )
            ),

            "metrics_no_data": self._safe_int(
                metrics.get(
                    "metrics_no_data",
                    0,
                )
            ),

            "metric_errors": self._safe_int(
                metrics.get(
                    "metric_errors",
                    0,
                )
            ),

            "collection_plans": self._safe_int(
                metrics.get(
                    "collection_plans",
                    0,
                )
            ),

            "collection_not_found": self._safe_int(
                metrics.get(
                    "collection_not_found",
                    0,
                )
            ),

            "failed_collectors": self._safe_int(
                metrics.get(
                    "failed_collectors",
                    0,
                )
            ),

            "partial_collectors": self._safe_int(
                metrics.get(
                    "partial_collectors",
                    0,
                )
            ),

            "topology_collected": self._safe_int(
                metrics.get(
                    "topology_collected",
                    0,
                )
            ),

            "findings": len(
                findings
            ),

            "recommendations": len(
                recommendations
            ),

            "duration_seconds": round(
                float(
                    metrics.get(
                        "total_duration",
                        0.0,
                    )
                    or 0.0
                ),
                2,
            ),
        }