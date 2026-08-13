"""
Scan summary writer — single summary.txt output for each scan run.
"""
from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

from backend.database.utils import json_loads


def _box(title: str, width: int = 40) -> list[str]:
    return [
        "",
        "┌" + "─" * width + "┐",
        "│ " + title.ljust(width - 2) + "│",
        "└" + "─" * width + "┘",
    ]


def _sep(width: int = 70) -> str:
    return "-" * width


FINDING_TITLES = {
    "nat_gateway_no_observed_activity": "NAT Gateway with no observed activity",
    "nat_gateway_no_activity": "NAT Gateway with no observed activity",
    "nat_gateway_low_utilization": "NAT Gateway with low utilization",
    "nat_gateway_low_traffic": "NAT Gateway with low traffic",
    "nat_gateway_aws_service_traffic": "NAT Gateway routing AWS service traffic",
    "nat_gateway_cross_az": "NAT Gateway with cross-AZ traffic",
    "nat_gateway_endpoint_opportunity": "NAT Gateway VPC endpoint opportunity",
    "rds_instance_possible_oversized": "Potentially oversized RDS instance",
    "rds_billing_resource_mismatch": "RDS billing/resource mismatch",
    "rds_unmatched_billing_usage": "Unmatched RDS billing usage",
    "collection_no_matching_resources": "No matching resources found during collection",
}


def _finding_title(finding_type: str) -> str:
    return FINDING_TITLES.get(
        finding_type,
        finding_type.replace("_", " ").title(),
    )


def _format_export_value(value) -> str:
    if isinstance(value, (dict, list)):
        import json
        return json.dumps(value, default=str)
    if value is None:
        return "N/A"
    return str(value)


def _iter_metric_entries(metrics) -> list[tuple[str, dict]]:
    if not metrics:
        return []

    if isinstance(metrics, dict):
        return [
            (name, payload)
            for name, payload in metrics.items()
            if isinstance(payload, dict)
        ]

    if isinstance(metrics, list):
        entries: list[tuple[str, dict]] = []
        for item in metrics:
            if not isinstance(item, dict):
                continue
            name = item.get("metric_name") or item.get("name") or "unknown"
            entries.append((name, item))
        return entries

    return []


def _metric_datapoint_count(payload: dict) -> str:
    count = payload.get("datapoint_count", payload.get("datapoints"))
    return "N/A" if count is None else str(count)


def _metric_period(payload: dict) -> str:
    period = payload.get("period", payload.get("effective_period"))
    return "N/A" if period is None else str(period)


class ScanExporter:
    def __init__(self, scan):
        self.scan = scan
        self.scan_id = scan.id
        self.base = Path(f"scans/scan_{self.scan_id}")
        self.base.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        db,
        *,
        validation,
        plans,
        results,
        contexts=None,
        scan_metrics=None,
        findings=None,
        recommendations=None,
    ) -> Path:
        lines: list[str] = []
        lines.extend(self._section_header())
        lines.extend(self._section_scan_header())
        lines.extend(self._section_cost_collection(validation))
        lines.extend(self._section_cost_analysis(db))
        lines.extend(self._section_collection_plan(plans))
        lines.extend(self._section_collector_results(results))
        lines.extend(self._section_findings(findings))
        lines.extend(self._section_recommendations(recommendations))
        lines.extend(self._section_resource_details(db, contexts))

        path = self.base / "summary.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def _section_header(self) -> list[str]:
        return [
            "=" * 70,
            f"SCAN #{self.scan_id} SUMMARY",
            f"Generated: {datetime.utcnow().isoformat()} UTC",
            "=" * 70,
        ]

    def _section_scan_header(self) -> list[str]:
        region_display = self.scan.region if self.scan.region else "all regions"
        lines = _box(f"SCAN #{self.scan_id}")
        lines.extend([
            f" Account      : {self.scan.account_id}",
            f" Period       : {self.scan.start_date} → {self.scan.end_date}",
            f" Region       : {region_display}",
            f" Threshold    : ${self.scan.cost_threshold:,.2f}",
            f" Started      : {date.today().isoformat()}",
        ])
        return lines

    


    def _section_cost_collection(self, validation) -> list[str]:
        lines = _box("COST COLLECTION")
        if not validation:
            lines.append(" No cost validation data available.")
            return lines
        lines.extend([
            f" Collected total : ${validation.get('collected_total', 0):,.2f}",
            f" Monthly total   : ${validation.get('monthly_total', 0):,.2f}",
            f" Difference      : ${validation.get('difference', 0):.2f}",
            f" Match           : {validation.get('matches', 'N/A')}",
        ])
        return lines

    def _section_cost_analysis(self, db) -> list[str]:
        from sqlalchemy import func

        from backend.database.models.cost_record import CostRecord
        from backend.database.repository.service_cost_repository import get_service_costs_with_rank
        from backend.database.repository.usage_type_cost_repository import get_usage_types_by_service

        services = get_service_costs_with_rank(db, self.scan_id)
        raw_total = (
            db.query(func.sum(CostRecord.amount))
            .filter(CostRecord.scan_run_id == self.scan_id)
            .scalar()
            or 0
        )
        considered_total = sum(s["cost"] for s in services)

        lines = _box("COST ANALYSIS")
        lines.extend([
            f" Raw Cost Explorer total : ${float(raw_total):,.2f}",
            f" Cost considered         : ${float(considered_total):,.2f}",
            "",
            f" {'Rank':<4} {'Service':<52} {'Cost':>10}  {'Share':>7}  Trend",
            _sep(),
        ])
        for svc in services:
            lines.append(
                f" {svc['rank']:2}. "
                f"{svc['service']:<52}"
                f"${svc['cost']:>8.2f}"
                f" ({svc['share_pct']:>5.2f}%)"
                f"  [{svc.get('trend', 'N/A')}]"
            )

        lines.append("")
        lines.append(" Usage type breakdown by service:")
        lines.append(_sep())
        for svc in services:
            lines.append("")
            lines.append(
                f" {svc['service']:<52} ${svc['cost']:>10.2f} [{svc.get('trend', 'N/A')}]"
            )
            usage_types = get_usage_types_by_service(db, self.scan_id, svc["service"])
            for ut in usage_types:
                lines.append(
                    f"   {ut['usage_type']:<40} ${ut['cost']:>8.2f} ({ut['percentage']:.1f}%)"
                )
        return lines

    def _section_collection_plan(self, plans) -> list[str]:
        lines = _box("COLLECTION PLAN")
        if not plans:
            lines.append(" No collection plans created.")
            return lines
        for plan in plans:
            lines.append(
                f" {plan.get('collector', ''):<20}"
                f"{plan.get('region', ''):<15}"
                f"${plan.get('cost_context', 0):>8,.2f}"
                f"  [{plan.get('priority', '')}]"
                f"  {plan.get('service', '')} / {plan.get('usage_type', '')}"
                f"  ({plan.get('resource_type', '')})"
            )
        return lines

    def _section_collector_results(self, results) -> list[str]:
        lines = _box("COLLECTOR RESULTS")
        if not results:
            lines.append(" No collector results.")
            return lines
        for res in results:
            status = res.get("status", "completed")
            resource_count = res.get(
                "resource_count",
                res.get("resources", 0),
            )
            line = (
                f" {res.get('collector', ''):<20}"
                f"{res.get('region', ''):<15}"
                f"resources={resource_count:>3d} "
                f"metrics={res.get('metrics', 0):>3d} "
                f"topology={res.get('topology_resources', 0):>3d} "
                f"[{status}]"
            )
            lines.append(line)
            if res.get("cost") is not None:
                lines.append(
                    f"   Cost: ${float(res.get('cost') or 0):,.2f} · "
                    f"resource_type={res.get('resource_type', 'N/A')}"
                )
            if res.get("not_found"):
                lines.append(
                    "   No matching resources were found during collection. "
                    "Recommendation analysis skipped."
                )
            elif res.get("resource_ids"):
                lines.append(
                    f"   Resource IDs: {', '.join(res.get('resource_ids', []))}"
                )
            if res.get("error"):
                lines.append(f"   ERROR: {res['error']}")
            cw = self._extract_cloudwatch_observation(res)
            if cw:
                lines.append(
                    f"   CloudWatch window: {cw.get('start', 'N/A')} → {cw.get('end', 'N/A')}"
                )
                lines.append(
                    f"   requested_period={cw.get('requested_period', 'N/A')}s "
                    f"effective_period={cw.get('effective_period', 'N/A')}s"
                )
        return lines
 

    def _section_findings(self, findings) -> list[str]:
        lines = _box("FINDINGS")
        findings_list = findings or []
        if not findings_list:
            lines.append(" No findings generated.")
            return lines

        for finding in findings_list:
            lines.extend(self._format_finding(finding))
        return lines

    def _format_finding(self, finding) -> list[str]:
        lines: list[str] = []
        if isinstance(finding, dict):
            severity = finding.get("severity", "INFO").upper()
            finding_type = finding.get("finding_type", finding.get("title", ""))
            confidence = finding.get("confidence", "medium").upper()
            reason = finding.get("reason", "")
            resource_ids = finding.get("resource_ids", [])
            conditions = finding.get("conditions", [])
            observation = finding.get("observation_period")
            limitations = finding.get("limitations", [])

            lines.append("")
            lines.append(
                f" [{severity}] {_finding_title(str(finding_type))}"
            )
            lines.append(f" Confidence: {confidence}")
            lines.append(f" Affected resources: {len(resource_ids)}")
            if resource_ids:
                lines.append(" Affected resource IDs:")
                for res_id in resource_ids:
                    lines.append(f"   - {res_id}")
            if reason:
                lines.append(f" Reason: {reason}")
            lines.extend(self._format_conditions(conditions))
            if observation:
                lines.append(" Observation period (CloudWatch):")
                lines.append(f"   start      : {observation.get('start', 'N/A')}")
                lines.append(f"   end        : {observation.get('end', 'N/A')}")
                coverage = observation.get("coverage")
                if coverage is not None:
                    lines.append(f"   coverage   : {coverage * 100:.1f}%")
                datapoints = observation.get("datapoints")
                if datapoints is not None:
                    lines.append(f"   datapoints : {datapoints}")
                if observation.get("requested_period") is not None:
                    lines.append(
                        f"   requested_period : {observation.get('requested_period')}s"
                    )
                if observation.get("effective_period") is not None:
                    lines.append(
                        f"   effective_period : {observation.get('effective_period')}s"
                    )

            evidence = finding.get("evidence") if isinstance(finding, dict) else None
            if isinstance(evidence, dict):
                metrics = evidence.get("metrics") or {}
                metric_entries = _iter_metric_entries(metrics)
                if metric_entries:
                    lines.append(" Metrics:")
                    for name, payload in metric_entries:
                        lines.append(
                            f"   {name}: status={payload.get('status')} "
                            f"has_data={payload.get('has_data')} "
                            f"value={payload.get('value')} "
                            f"datapoints={_metric_datapoint_count(payload)}"
                        )

                data_quality = evidence.get("data_quality") or {}
                billing_match = data_quality.get("billing_resource_match")
                if billing_match:
                    lines.append(" Billing/resource match:")
                    for key, value in billing_match.items():
                        lines.append(f"   {key}: {value}")
            if limitations:
                lines.append(" Limitations:")
                for lim in limitations:
                    lines.append(f"   - {lim}")
            return lines

        lines.append("")
        lines.append(f" [{finding.severity.upper()}] {finding.title}")
        lines.append(f" Service: {finding.service}")
        if finding.description:
            lines.append(f" Description: {finding.description}")
        if finding.evidence:
            resources = finding.evidence.get("resources", [])
            lines.append(f" Evidence resources ({len(resources)}):")
            for res in resources:
                lines.append(
                    f"   - {res.get('resource_id', 'unknown')} "
                    f"[{res.get('resource_type', 'unknown')}]"
                )
        if finding.recommendation:
            lines.append(f" Recommendation: {finding.recommendation}")
        return lines

    @classmethod
    def _format_conditions(cls, conditions: list) -> list[str]:
        if not conditions:
            return []

        lines = [" Conditions:"]

        for cond in conditions:
            if not isinstance(cond, dict):
                continue

            if isinstance(cond.get("evidence"), list):
                resource_id = cond.get("resource_id")
                if resource_id:
                    lines.append(f"   Resource: {resource_id}")
                for statement in cond["evidence"]:
                    if isinstance(statement, dict):
                        lines.extend(
                            cls._format_evidence_statement(
                                statement,
                                indent="     " if resource_id else "   ",
                            )
                        )
                continue

            if isinstance(cond.get("conditions"), list):
                resource_id = cond.get("resource_id", "unknown")
                for item in cond["conditions"]:
                    if isinstance(item, dict):
                        lines.extend(
                            cls._format_legacy_condition(
                                item,
                                resource_id=resource_id,
                            )
                        )
                continue

            if "value" in cond and "expected" not in cond:
                lines.extend(cls._format_evidence_statement(cond))
                continue

            lines.extend(cls._format_legacy_condition(cond))

        return lines

    @classmethod
    def _format_evidence_statement(
        cls,
        statement: dict,
        *,
        indent: str = "   ",
    ) -> list[str]:
        name = statement.get("name") or "statement"
        value = statement.get("value")
        lines: list[str] = []

        if isinstance(value, dict) and (
            "expected" in value or "actual" in value
        ):
            lines.append(f"{indent}{name}:")
            if "expected" in value:
                lines.append(
                    f"{indent}  expected: "
                    f"{_format_export_value(value.get('expected'))}"
                )
            if "actual" in value:
                lines.append(
                    f"{indent}  actual: "
                    f"{_format_export_value(value.get('actual'))}"
                )
            if value.get("status") is not None:
                lines.append(
                    f"{indent}  status: {value.get('status')}"
                )
        else:
            lines.append(
                f"{indent}{name}: {_format_export_value(value)}"
            )

        description = statement.get("description")
        if description:
            lines.append(f"{indent}  {description}")

        sources = statement.get("source") or []
        if sources:
            joined = ", ".join(str(source) for source in sources)
            lines.append(f"{indent}  source: {joined}")

        return lines

    @classmethod
    def _format_legacy_condition(
        cls,
        cond: dict,
        *,
        resource_id: str | None = None,
    ) -> list[str]:
        status = cond.get("status")
        if status is None:
            status = "PASS" if cond.get("passed") else "FAIL"
        line = (
            f"   {cond.get('name', '')}: "
            f"expected={cond.get('expected', '')}, "
            f"actual={cond.get('actual', '')} [{status}]"
        )
        if resource_id:
            line += f" (Resource: {resource_id})"

        lines = [line]
        description = cond.get("description")
        if description:
            lines.append(f"     {description}")
        return lines

    def _section_recommendations(self, recommendations) -> list[str]:
        lines = _box("RECOMMENDATIONS")
        recs_list = recommendations or []
        if not recs_list:
            lines.append(" No recommendations generated.")
            return lines

        for rec in recs_list:
            if not isinstance(rec, dict):
                continue
            lines.append("")
            lines.append(f" [{rec.get('priority', 'medium').upper()}] {rec.get('title', '')}")
            lines.append(f" ID: {rec.get('id', '')}")
            lines.append(f" Resource type: {rec.get('resource_type', '')}")
            lines.append(f" Confidence: {rec.get('confidence', 'medium').upper()}")
            affected_ids = rec.get("affected_resources", [])
            lines.append(f" Affected resources: {len(affected_ids)}")
            if affected_ids:
                lines.append(" Affected resource IDs:")
                for res_id in affected_ids:
                    lines.append(f"   - {res_id}")
            if rec.get("reason"):
                lines.append(f" Reason: {rec['reason']}")
            if rec.get("action"):
                lines.append(f" Action: {rec['action']}")
        return lines

    def _section_resource_details(self, db, contexts) -> list[str]:
        from backend.database.models.metric import Metric
        from backend.database.models.resource import Resource as ResourceModel

        lines = _box("RESOURCE DETAILS")
        if not contexts:
            lines.append(" No evaluation contexts.")
            return lines

        for ctx in contexts:
            resources = ctx.get("evidence", {}).get("resources", [])
            if not resources:
                continue
            lines.append("")
            lines.append(f" Service    : {ctx.get('service', '')}")
            lines.append(f" Region     : {ctx.get('region', '')}")
            lines.append(f" Usage type : {ctx.get('usage_type', '')}")
            lines.append(f" Cost       : ${ctx.get('cost', 0) or 0:,.2f}")
            lines.append(
                f" Resources  : {len(resources)} {ctx.get('resource_type', '')}"
            )

            for res in resources:
                lines.append("")
                lines.append(f" --- {res.get('resource_id', 'unknown')} ---")
                config = res.get("configuration", {})
                if config:
                    lines.append(" Configuration:")
                    for key, value in config.items():
                        if value is not None:
                            lines.append(f"   {key}: {value}")

                topology = res.get("topology", {})
                if topology:
                    lines.append(" Topology:")
                    self._append_topology(lines, topology)

                  
                   
                    metrics =  {}
                    metric_entries = _iter_metric_entries(metrics)
                    if metric_entries:
                        lines.append("   metrics:")
                        for name, payload in metric_entries:
                            lines.append(
                                f"     {name}: value={payload.get('value', 'N/A')} "
                                f"period={_metric_period(payload)}s "
                                f"datapoints={_metric_datapoint_count(payload)}"
                            )

                aws_id = res.get("resource_id") or res.get("id") or res.get("aws_resource_id")
                metric_rows = []
                if aws_id:
                    db_resource = (
                        db.query(ResourceModel)
                        .filter(
                            ResourceModel.aws_resource_id == aws_id,
                            ResourceModel.scan_run_id == self.scan_id,
                        )
                        .first()
                    )
                    if db_resource:
                        metric_rows = (
                            db.query(Metric)
                            .filter(
                                Metric.resource_id == db_resource.id,
                                Metric.scan_run_id == self.scan_id,
                            )
                            .all()
                        )
                tags = res.get("tags")
                if tags:
                    lines.append(f" Tags: {json_loads(tags) if isinstance(tags, str) else tags}")
        return lines

    @staticmethod
    def _append_topology(lines: list[str], topology: dict) -> None:
        route_tables = topology.get("route_tables", [])
        if route_tables:
            if isinstance(route_tables[0], dict):
                rt_ids = [rt.get("route_table_id", "unknown") for rt in route_tables]
            else:
                rt_ids = route_tables
            lines.append(f"   Route tables ({len(rt_ids)}): {', '.join(rt_ids)}")

        subnets = topology.get("subnets", [])
        if subnets:
            if isinstance(subnets[0], dict):
                subnet_ids = [s.get("subnet_id", "unknown") for s in subnets]
            else:
                subnet_ids = subnets
            lines.append(f"   Subnets ({len(subnet_ids)}): {', '.join(subnet_ids)}")

        vpc_endpoints = topology.get("vpc_endpoints", [])
        if vpc_endpoints:
            endpoint_info = [
                f"{ep.get('service_name') or ep.get('service') or 'unknown'}"
                for ep in vpc_endpoints
            ]
            lines.append(
                f"   VPC endpoints ({len(vpc_endpoints)}): {', '.join(endpoint_info)}"
            )

    @staticmethod
    def _extract_cloudwatch_observation(payload: dict) -> dict | None:
        observations = payload.get("observations") or {}
        cloudwatch = observations.get("cloudwatch")
        if isinstance(cloudwatch, dict) and cloudwatch:
            return cloudwatch

        resource_data = payload.get("resource_data") or []
        for resource in resource_data:
            obs = (resource.get("observations") or {}).get("cloudwatch")
            if isinstance(obs, dict) and obs:
                return obs
        return None
