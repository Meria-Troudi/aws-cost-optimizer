"""
Scan exporter
Creates human-readable and machine-readable scan evidence.
Used for: manual analysis, debugging collectors, future dashboard.
"""

import csv
from pathlib import Path
from datetime import datetime


class ScanExporter:

    def __init__(self, scan):
        self.scan = scan
        self.scan_id = scan.id
        self.base = Path(f"scans/scan_{self.scan_id}")
        self.base.mkdir(parents=True, exist_ok=True)

    def write_csv(self, path, data, fieldnames=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        if not data:
            return
        if fieldnames is None:
            fieldnames = data[0].keys()
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

    def write_txt(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def export_cost(self, db, threshold=None):
        from backend.database.models.cost_record import CostRecord
        from backend.database.repository.service_cost_repository import get_service_costs_with_rank
        from backend.database.repository.usage_type_cost_repository import get_usage_types_by_service

        if threshold is None:
            threshold = self.scan.cost_threshold

        scan_id = self.scan_id

        # Export one row per service, aggregated across regions.
        services = get_service_costs_with_rank(db, scan_id)

        service_data = [
            {
                "rank": s["rank"],
                "service": s["service"],
                "cost": s["cost"],
                "share_pct": s["share_pct"],
                "trend": s["trend"],
                "change_percentage": s["change_percentage"],
            }
            for s in services
            if s["cost"] > threshold
        ]

        self.write_csv(self.base / "cost" / "service_costs.csv", service_data)

        # Export usage type costs
        usage_data = []
        for svc in services:
            if svc["cost"] > threshold:
                usage_types = get_usage_types_by_service(db, scan_id, svc["service"])
                for ut in usage_types:
                    usage_data.append({
                        "service": svc["service"],
                        "usage_type": ut["usage_type"],
                        "cost": ut["cost"],
                        "percentage": ut["percentage"],
                    })

        self.write_csv(self.base / "cost" / "usage_type_costs.csv", usage_data)

    def export_plan(self, plans):
        if plans:
            fieldnames = [
                "service", "region", "usage_type", "resource_type",
                "collector", "priority", "cost_context"
            ]
            self.write_csv(self.base / "collectors" / "collection_plan.csv", plans, fieldnames)

    def export_collectors(self, db, results):
        from backend.database.models.resource import Resource
        from backend.database.models.metric import Metric

        scan_id = self.scan_id

        output = []

        resources = (
            db.query(Resource)
            .filter(Resource.scan_run_id == scan_id)
            .all()
        )

        for r in resources:
            metrics = (
                db.query(Metric)
                .filter(
                    Metric.resource_id == r.id,
                    Metric.scan_run_id == scan_id,
                )
                .all()
            )

            # Build metrics dict for this resource
            metrics_dict = {}
            for m in metrics:
                metrics_dict[m.metric_name] = m.value
            
            output.append({
                "resource_id": r.aws_resource_id,
                "type": r.resource_type,
                "region": r.region,
                "state": r.state,
                "tags": r.tags,
                "attributes": r.attributes or {},
                "metrics": metrics_dict,
            })

        # Export resources as CSV (exclude metrics - they have their own file)
        if output:
            # Create clean resource data without metrics
            resource_data = []
            for r in output:
                resource_data.append({
                    "resource_id": r["resource_id"],
                    "type": r["type"],
                    "region": r["region"],
                    "state": r["state"],
                    "tags": r["tags"],
                    "attributes": r.get("attributes", {}),
                })
            
            resource_fieldnames = [
                "resource_id", "type", "region", "state", "tags", "attributes"
            ]
            self.write_csv(self.base / "collectors" / "resources.csv", resource_data, resource_fieldnames)
            
            # Export metrics as separate CSV
            metrics_data = []
            for r in output:
                metrics = r.get("metrics", {})
                # Handle dict format: {metric_name: value}
                if isinstance(metrics, dict):
                    for metric_name, value in metrics.items():
                        metrics_data.append({
                            "resource_id": r["resource_id"],
                            "resource_type": r["type"],
                            "region": r["region"],
                            "metric_name": metric_name,
                            "value": value,
                            "unit": "None",
                            "statistic": "Average",
                        })
            
            if metrics_data:
                metric_fieldnames = [
                    "resource_id", "resource_type", "region",
                    "metric_name", "value", "unit", "statistic"
                ]
                self.write_csv(self.base / "collectors" / "metrics.csv", metrics_data, metric_fieldnames)

    def export_summary(self, db, validation, plans, results, contexts=None):
        """Export a human-readable summary report with metric details."""
        from backend.database.models.resource import Resource
        from backend.database.models.finding import Finding
        from backend.database.models.recommendation import Recommendation

        scan_id = self.scan_id

        lines = []
        lines.append("=" * 70)
        lines.append(f"SCAN #{scan_id} SUMMARY")
        lines.append(f"Generated: {datetime.utcnow()}")
        lines.append("=" * 70)
        lines.append("")

        # Cost validation
        lines.append("COST COLLECTION")
        lines.append("-" * 40)
        lines.append(f"Collected total:  ${validation['collected_total']:,.2f}")
        lines.append(f"Monthly total:    ${validation['monthly_total']:,.2f}")
        lines.append(f"Difference:       ${validation['difference']:.2f}")
        lines.append(f"Match:            {validation['matches']}")
        lines.append("")

        # Collection plan
        lines.append("COLLECTION PLAN")
        lines.append("-" * 40)
        for plan in plans:
            lines.append(
                f"  {plan.get('collector', ''):<15s} "
                f"{plan.get('region', ''):<15s} "
                f"${plan.get('estimated_cost', 0):,.2f}  "
                f"{plan.get('service', '')} - {plan.get('usage_type', '')}"
            )
        lines.append("")

        # Collection results
        lines.append("COLLECTOR RESULTS")
        lines.append("-" * 40)
        for res in results:
            lines.append(
                f"  {res.get('collector', ''):<15s} "
                f"resources={res.get('resources', 0):>3d} "
                f"metrics={res.get('metrics', 0):>3d}"
            )
        lines.append("")

        # Resources
        lines.append("RESOURCES")
        lines.append("-" * 40)
        resources = (
            db.query(Resource)
            .filter(Resource.scan_run_id == scan_id)
            .all()
        )
        for r in resources:
            lines.append(f"  {r.aws_resource_id:<40s} [{r.resource_type:<15s}] {r.region}")
        lines.append("")

        # Findings
        lines.append("=" * 70)
        lines.append("FINDINGS")
        lines.append("=" * 70)
        findings = (
            db.query(Finding)
            .filter(Finding.scan_run_id == scan_id)
            .all()
        )
        for f in findings:
            lines.append(f"\n  [{f.severity.upper()}] {f.title}")
            lines.append(f"  Service: {f.service}")
            if f.description:
                lines.append(f"  Description: {f.description}")

            # Get recommendations for this finding
            recs = (
                db.query(Recommendation)
                .filter(Recommendation.finding_id == f.id)
                .all()
            )
            for rec in recs:
                lines.append(f"  → {rec.title}")
                if rec.description:
                    lines.append(f"    {rec.description}")
                if rec.estimated_savings:
                    lines.append(f"    Estimated savings: ${rec.estimated_savings:,.2f}/month")
                lines.append(f"    Priority: {rec.priority} | Confidence: {rec.confidence}")
            lines.append("")

        # NAT Gateway metric details
        lines.append("=" * 70)
        lines.append("NAT GATEWAY METRIC DETAILS")
        lines.append("=" * 70)
        if contexts:
            for ctx in contexts:
                resources = ctx.evidence.get("resources", [])
                nat_resources = [
                    r for r in resources
                    if r.get("resource_type") == "nat_gateway"
                ]
                if not nat_resources:
                    continue

                lines.append(f"\n  Service: {ctx.service}")
                lines.append(f"  Region: {ctx.region}")
                lines.append(f"  Usage Type: {ctx.usage_type}")
                lines.append(f"  Cost: ${ctx.cost or 0:,.2f}")
                lines.append(f"  Resources: {len(nat_resources)} NAT Gateways")
                lines.append("")

                for res in nat_resources:
                    lines.append(f"  --- {res.get('resource_id', 'unknown')} ---")
                    config = res.get("configuration", {})
                    lines.append(f"    VPC: {config.get('vpc_id', 'N/A')}")
                    lines.append(f"    Subnet: {config.get('subnet_id', 'N/A')}")
                    lines.append(f"    Connectivity: {config.get('connectivity_type', 'N/A')}")

                    metrics = res.get("metrics", {})
                    if metrics:
                        lines.append(f"    Metrics ({len(metrics)}):")
                        for mname, mval in sorted(metrics.items()):
                            if isinstance(mval, (int, float)):
                                lines.append(f"      {mname:<35} {mval:>15.2f}")
                            else:
                                lines.append(f"      {mname:<35} {mval}")
                    else:
                        lines.append("    Metrics: (none - no_data)")
                    lines.append("")
        lines.append("")

        # RDS metric details
        lines.append("=" * 70)
        lines.append("RDS INSTANCE METRIC DETAILS")
        lines.append("=" * 70)
        if contexts:
            for ctx in contexts:
                resources = ctx.evidence.get("resources", [])
                rds_resources = [
                    r for r in resources
                    if r.get("resource_type") == "rds_instance"
                ]
                if not rds_resources:
                    continue

                lines.append(f"\n  Service: {ctx.service}")
                lines.append(f"  Region: {ctx.region}")
                lines.append(f"  Usage Type: {ctx.usage_type}")
                lines.append(f"  Cost: ${ctx.cost or 0:,.2f}")
                lines.append(f"  Resources: {len(rds_resources)} RDS Instances")
                lines.append("")

                for res in rds_resources:
                    lines.append(f"  --- {res.get('resource_id', 'unknown')} ---")
                    config = res.get("configuration", {})
                    lines.append(f"    Engine: {config.get('engine', 'N/A')}")
                    lines.append(f"    Instance Class: {config.get('instance_class', 'N/A')}")
                    lines.append(f"    Multi-AZ: {config.get('multi_az', 'N/A')}")
                    lines.append(f"    Cluster: {config.get('cluster_identifier', 'N/A')}")

                    metrics = res.get("metrics", {})
                    if metrics:
                        lines.append(f"    Metrics ({len(metrics)}):")
                        for mname, mval in sorted(metrics.items()):
                            if isinstance(mval, (int, float)):
                                lines.append(f"      {mname:<35} {mval:>15.2f}")
                            else:
                                lines.append(f"      {mname:<35} {mval}")
                    else:
                        lines.append("    Metrics: (none - no_data)")
                    lines.append("")

        self.write_txt(self.base / "summary.txt", "\n".join(lines))
