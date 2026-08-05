"""
AWS Cost Optimizer - Scan Orchestrator

Pipeline stages:
1. SCAN              - Create ScanRun
2. COST COLLECTION   - CostCollector → CostRecord (raw Cost Explorer data)
3. COST ANALYSIS     - Query CostRecord for service/usage type aggregations
4. COLLECTION PLAN   - CollectionPlanner → CollectionPlan
5. RESOURCE COLLECTION - CollectorManager → Resource + ResourceSnapshot + Metric
6. FINDINGS          - FindingBuilder → evidence findings
"""

import sys
import os

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from datetime import date
from sqlalchemy import func

from config.settings import CE_REGION
from aws.client import get_client

from backend.database.session import SessionLocal

from backend.database.models.cost_record import CostRecord
from backend.database.models.resource import Resource
from backend.database.models.metric import Metric

from backend.database.repository.scan_run_repository import (
    create_scan_run,
    finish_scan_run,
)

from collectors.cost.collector import CostCollector
from collectors.manager import CollectorManager

from aws_cost_optimizer.planner.planner import CollectionPlanner
from backend.services.finding_builder import FindingBuilder
from aws_cost_optimizer.rules.engine import RuleEngine

from inspection.exporter import ScanExporter


def box(title, width=70):
    print("\n┌" + "─"*width + "┐")
    print("│ " + title.ljust(width-2) + "│")
    print("└" + "─"*width + "┘")


def separator():
    print("-"*70)


def show_header(scan):
    box(f"SCAN #{scan.id}")
    print(f" Account      : {scan.account_id}")
    print(f" Period       : {scan.start_date} → {scan.end_date}")
    region_display = scan.region if scan.region else "all regions"
    print(f" Region       : {region_display}")
    print(f" Threshold    : ${scan.cost_threshold:,.2f}")
    print(f" Started      : {date.today()}")
    separator()


def show_cost_analysis(db, scan):
    box("COST ANALYSIS")

    # Query CostRecord for service aggregations with rank and share_pct
    from backend.database.repository.service_cost_repository import get_service_costs_with_rank
    services = get_service_costs_with_rank(db, scan.id)

    raw_total = (
        db.query(func.sum(CostRecord.amount))
        .filter(CostRecord.scan_run_id == scan.id)
        .scalar()
        or 0
    )
    considered_total = sum(s["cost"] for s in services)
    print(f"Raw Cost Explorer total : ${float(raw_total):,.2f}")
    print(f"Cost considered         : ${float(considered_total):,.2f}\n")

    for svc in services:
        print(
            f"{svc['rank']:2}. "
            f"{svc['service']:<52}"
            f"${svc['cost']:>8.2f}"
            f" ({svc['share_pct']:.2f}%)"
            f"  [{svc.get('trend', 'N/A')}]"
        )

    separator()


def show_resources(db, scan):
    box("DISCOVERED RESOURCES")

    resources = (
        db.query(Resource)
        .filter(Resource.scan_run_id == scan.id)
        .all()
    )

    for r in resources:
        metrics = (
            db.query(Metric)
            .filter(
                Metric.resource_id == r.id,
                Metric.scan_run_id == scan.id
            )
            .count()
        )

        print(
            f"{r.resource_type:<20}"
            f"{r.aws_resource_id:<40}"
            f"{r.region:<15}"
            f"metrics={metrics}"
        )

    separator()


def main(region=None, cost_threshold=100.0, start_date=None, end_date=None):

    db = SessionLocal()

    try:
        sts = get_client("sts", CE_REGION)
        account_id = sts.get_caller_identity().get("Account")

        # ── Scan parameters ──
        if start_date is None:
            start = date(2026, 4, 1)
        else:
            start = date.fromisoformat(start_date)
        
        if end_date is None:
            end = date(2026, 7, 1)
        else:
            end = date.fromisoformat(end_date)

        scan = create_scan_run(
            db,
            account_id=account_id,
            start_date=start,
            end_date=end,
            region=region,
            cost_threshold=cost_threshold,
        )

        show_header(scan)

        exporter = ScanExporter(scan)

        # ── Stage 1: COST COLLECTION ──
        print("\nCollecting AWS Cost Explorer...")
        collector = CostCollector()
        validation = collector.collect(db, scan)

        if validation["matches"]:
            print("Cost validation : OK")
        else:
            print("Cost validation : FAILED")

        # ── Stage 2: COST ANALYSIS ──
        # Cost analysis is now performed on-the-fly from CostRecord
        exporter.export_cost(db)
        show_cost_analysis(db, scan)

        # Show service breakdown
        print("\nService cost analysis...")
        from backend.database.repository.service_cost_repository import get_service_costs_with_rank
        from backend.database.repository.usage_type_cost_repository import get_usage_types_by_service
        services = get_service_costs_with_rank(db, scan.id)

        for svc in services:
            print(f"\n  {svc['service']:<52} ${svc['cost']:>10.2f} [{svc['trend']}]")

            usage_types = get_usage_types_by_service(db, scan.id, svc["service"])
            for ut in usage_types:
                print(f"    {ut['usage_type']:<40} ${ut['cost']:>8.2f} ({ut['percentage']:.1f}%)")

        separator()

        # ── Stage 3: COLLECTION PLAN ──
        print("\nCreating collection plan...")
        planner = CollectionPlanner()
        plans = planner.plan(db, scan)

        print(f"Collection plans created: {len(plans)}")
        for plan in plans:
            print(f"  {plan['collector']:<20} {plan['region']:<15} ${plan['cost_context']:>8.2f} [{plan['priority']}]")

        exporter.export_plan(plans)

        # ── Stage 4: RESOURCE COLLECTION ──
        print("\nExecuting collectors...")
        manager = CollectorManager()
        results = []
        for plan in plans:
            try:
                result = manager.execute(
                    db=db,
                    scan=scan,
                    collector_name=plan["collector"],
                    region=plan["region"],
                )
                results.append(result)
            except Exception as e:
                print(f"ERROR: {plan['collector']} in {plan['region']}: {e}")
                results.append({
                    "collector": plan["collector"],
                    "region": plan["region"],
                    "resources": 0,
                    "metrics": 0,
                    "success": False,
                    "error": str(e)
                })

        db.commit()
        exporter.export_collectors(db, results)

        show_resources(db, scan)

        # ── Stage 5: EVIDENCE FINDINGS (recommendations come later) ──
        print("\nBuilding evidence findings...")
        builder = FindingBuilder()
        contexts = builder.build(db, scan)
        print(f"Evaluation contexts created: {len(contexts)}")
        
        # Run rule engine to generate findings
        print("\nEvaluating rules...")
        rule_engine = RuleEngine()
        findings = rule_engine.run(db, contexts)
        print(f"Findings created: {len(findings)}")

        exporter.export_summary(db, validation, plans, results, contexts)

        finish_scan_run(db, scan.id, "completed")

        print("\nSCAN COMPLETE")
        print(f"Review folder: scans/scan_{scan.id}")

    except Exception as e:
        print("\nSCAN FAILED", e)
        raise

    finally:
        db.close()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AWS Cost Optimizer Scanner")
    parser.add_argument(
        "--region",
        help="AWS region to scan (default: all regions)",
        default=None
    )
    parser.add_argument(
        "--threshold",
        type=float,
        help="Cost threshold for collection plan (default: $100.00)",
        default=100.0
    )
    parser.add_argument(
        "--start-date",
        help="Start date for cost analysis (YYYY-MM-DD, default: 2026-04-01)",
        default=None
    )
    parser.add_argument(
        "--end-date",
        help="End date for cost analysis (YYYY-MM-DD, default: 2026-07-01)",
        default=None
    )

    args = parser.parse_args()

    main(
        region=args.region,
        cost_threshold=args.threshold,
        start_date=args.start_date,
        end_date=args.end_date
    )
