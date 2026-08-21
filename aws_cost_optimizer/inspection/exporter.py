"""
Professional scan summary exporter.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Any

from aws_cost_optimizer.collection.cost.periods import period_label

def _box(title: str, width: int = 72) -> list[str]:
    title = str(title)

    return [
        "",
        "┌" + "─" * width + "┐",
        "│ " + title.ljust(width - 2) + "│",
        "└" + "─" * width + "┘",
    ]


def _separator(width: int = 72) -> str:
    return "─" * width


def _format_value(value: Any) -> str:
    if value is None:
        return "N/A"

    if isinstance(value, (dict, list, tuple)):
        return json.dumps(
            value,
            default=str,
            ensure_ascii=False,
        )

    return str(value)


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _finding_title(finding: dict) -> str:

    return str(
        finding.get("title")
        or finding.get("name")
        or finding.get("finding_type", "Unknown finding")
        .replace("_", " ")
        .title()
    )



class ScanExporter:

    def __init__(self, scan):

        self.scan = scan
        self.scan_id = scan.id

        self.base = Path(
            f"scans/scan_{self.scan_id}"
        )

        self.base.mkdir(
            parents=True,
            exist_ok=True,
        )

    def export(
        self,
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

        lines.extend(
            self._section_header()
        )

        lines.extend(
            self._section_scan_info()
        )

        lines.extend(
            self._section_cost_summary(
                validation
            )
        )

        lines.extend(
            self._section_cost_drivers()
        )

        lines.extend(
            self._section_collection_summary(
                results
            )
        )

        lines.extend(
            self._section_findings(
                findings
            )
        )

        lines.extend(
            self._section_recommendations(
                recommendations
            )
        )

        lines.extend(
            self._section_resource_details(
                contexts
            )
        )

        path = self.base / "summary.txt"

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(
                "\n".join(lines)
            )

        return path

 
    def _section_header(self) -> list[str]:

        now = datetime.now(
            timezone.utc
        ).isoformat()

        return [
            "=" * 72,
            f"AWS COST OPTIMIZER — SCAN #{self.scan_id}",
            f"Generated: {now}",
            "=" * 72,
        ]
    def _section_scan_info(self) -> list[str]:

        region = (
            self.scan.region
            or "all regions"
        )

        lines = _box(
            "SCAN INFORMATION"
        )

        lines.extend(
            [
                f" Account        : {self.scan.account_id}",

                " Period         : "
                + period_label(
                    self.scan.start_date,
                    self.scan.end_date,
                ),

                f" Region         : {region}",

                f" Cost threshold : "
                f"${self.scan.cost_threshold:,.2f}",
            ]
        )

        return lines

    def _section_cost_summary(
        self,
        validation,
    ) -> list[str]:

        lines = _box(
            "COST SUMMARY"
        )

        if not validation:

            lines.append(
                " No billing validation data available."
            )

            return lines

        scope = (
            validation.get(
                "billing_scope"
            )
            or "all regions"
        )

        total = float(
            validation.get(
                "collected_total",
                0,
            )
            or 0
        )

        monthly_total = float(
            validation.get(
                "monthly_total",
                0,
            )
            or 0
        )

        difference = float(
            validation.get(
                "difference",
                0,
            )
            or 0
        )

        matches = validation.get(
            "matches",
            "N/A",
        )

        lines.extend(
            [
                f" Billing scope  : {scope}",

                f" Period total   : ${total:,.2f}",

                f" Monthly total  : ${monthly_total:,.2f}",

                f" Validation     : "
                f"{'PASS' if matches else 'FAIL'}",

                f" Difference     : ${difference:,.2f}",
            ]
        )

        months = _safe_list(
            validation.get(
                "months_included"
            )
        )

        if months:

            lines.append(
                " Months         : "
                + ", ".join(
                    str(month)
                    for month in months
                )
            )

        breakdown = _safe_list(
            validation.get(
                "monthly_breakdown"
            )
        )

        if breakdown:

            lines.extend(
                [
                    "",
                    " Monthly spend:",
                ]
            )

            for row in breakdown:

                lines.append(
                    f"   {row.get('month', '?'):<10}"
                    f"${float(row.get('cost', 0) or 0):>10,.2f}"
                )

        return lines

 
    def _section_cost_drivers(self) -> list[str]:

        from backend.database.connection import SessionLocal
        from backend.database.repositories.cost.service_costs import (
            get_period_cost_total,
            get_service_costs_with_rank,
        )
        from backend.database.repositories.cost.usage_types import (
            get_usage_types_by_service,
        )

        db = SessionLocal()

        try:

            services = get_service_costs_with_rank(
                db,
                self.scan_id,
            )

            period_total = get_period_cost_total(
                db,
                self.scan_id,
            )

            lines = _box(
                "COST DRIVERS"
            )

            if not services:

                lines.append(
                    " No service cost data available."
                )

                return lines

            lines.append(
                f" Period total: ${period_total:,.2f}"
            )

            lines.append("")

            for service in services:

                lines.append(
                    f"{service['rank']:>2}. "
                    f"{service['service']} "
                    f"— ${service['cost']:,.2f} "
                    f"({service['share_pct']:.1f}%)"
                )

                usage_types = (
                    get_usage_types_by_service(
                        db,
                        self.scan_id,
                        service["service"],
                    )
                )

                if not usage_types:
                    continue

                for usage in usage_types:

                    if float(
                        usage.get("cost", 0) or 0
                    ) <= 0:
                        continue

                    lines.append(
                        f"    {usage['usage_type']} "
                        f"— ${usage['cost']:,.2f} "
                        f"({usage['percentage']:.1f}%)"
                    )

            return lines

        finally:
            db.close()

    def _section_collection_summary(
        self,
        results,
    ) -> list[str]:

        lines = _box(
            "COLLECTION SUMMARY"
        )

        results = results or []

        if not results:

            lines.append(
                " No collectors executed."
            )

            return lines

        lines.extend(
            [
                " Collector             Region          "
                "Resources    Reconciliation",

                _separator(),
            ]
        )

        for result in results:

            collector = str(
                result.get(
                    "collector",
                    "",
                )
            )

            region = str(
                result.get(
                    "region",
                    "",
                )
            )

            resources = int(
                result.get(
                    "resource_count",
                    result.get(
                        "resources",
                        0,
                    ),
                )
                or 0
            )

            reconciliation = (
                result.get(
                    "reconciliation_status"
                )
                or result.get(
                    "match_status"
                )
                or result.get(
                    "status",
                    "unknown",
                )
            )

            lines.append(
                f" {collector:<20}"
                f"{region:<15}"
                f"{resources:>5}          "
                f"{reconciliation}"
            )

            cost = result.get(
                "cost"
            )

            if cost is not None:

                usage_type = result.get(
                    "usage_type",
                    "N/A",
                )

                lines.append(
                    f"   Billing: "
                    f"{usage_type} "
                    f"(${float(cost or 0):,.2f})"
                )

            if result.get(
                "match_reason"
            ):

                lines.append(
                    "   Note: "
                    + str(
                        result["match_reason"]
                    )
                )

            if result.get("error"):

                lines.append(
                    "   ERROR: "
                    + str(
                        result["error"]
                    )
                )

        return lines

    def _section_findings(
        self,
        findings,
    ) -> list[str]:

        lines = _box(
            "OPTIMIZATION FINDINGS"
        )

        findings = findings or []

        optimization = [
            finding
            for finding in findings
            if self._finding_category(finding) == "optimization"
        ]

        data_quality = [
            finding
            for finding in findings
            if self._finding_category(finding) != "optimization"
        ]

        if not optimization:
            lines.append(" No optimization findings.")
        else:
            for finding in optimization:
                lines.extend(self._format_user_finding(finding))

        if data_quality:
            lines.extend(["", "DATA QUALITY", "-" * 70])
            for finding in data_quality:
                lines.extend(self._format_data_quality_finding(finding))

        return lines

    @staticmethod
    def _finding_category(finding) -> str:
        if not isinstance(finding, dict):
            return "optimization"
        return str(finding.get("category", "optimization")).lower()

    def _format_user_finding(self, finding) -> list[str]:
        if not isinstance(finding, dict):
            return []

        lines: list[str] = []

        severity = str(finding.get("severity", "info")).upper()
        confidence = str(finding.get("confidence", "medium")).capitalize()
        title = str(finding.get("title", "Finding"))
        reason = str(finding.get("reason", "")).strip()

        resource_ids = _safe_list(finding.get("resource_ids"))
        resource_evidence = finding.get("resource_evidence")

        impact = finding.get("impact", {})
        if not isinstance(impact, dict):
            impact = {}

        lines.append("")
        lines.append(f"[{severity}] {title}")
        lines.append(f"Confidence: {confidence}")

        if resource_ids:
            lines.append(f"Resources: {len(resource_ids)}")

        if reason:
            lines.append(f"Reason: {reason}")
        if isinstance(resource_evidence, list) and resource_evidence:

            for resource in resource_evidence:

                if not isinstance(resource, dict):
                    continue

                resource_id = str(
                    resource.get("resource_id")
                    or "unknown"
                )

                lines.append("")
                lines.append(f"Resource: {resource_id}")

                evidence_summary = _safe_list(
                    resource.get("evidence_summary")
                )

                evidence = self._clean_evidence_summary(
                    evidence_summary
                )

                for item in evidence:
                    lines.append(f"  • {item}")

        else:

            # Fallback for legacy finding dicts without resource_evidence.
            evidence_summary = _safe_list(
                finding.get("evidence_summary")
            )

            evidence = self._clean_evidence_summary(
                evidence_summary
            )

            if evidence:
                lines.append("Evidence:")
                for item in evidence:
                    lines.append(f"  • {item}")

        period_cost = impact.get("period_cost")
        currency = impact.get("currency") or "USD"
        if isinstance(period_cost, (int, float)):
            lines.append(f"Cost: {currency} {period_cost:,.2f}")

        return lines

    def _format_data_quality_finding(self, finding) -> list[str]:
        if not isinstance(finding, dict):
            return []

        lines: list[str] = []

        title = str(finding.get("title", "Data quality issue"))
        reason = str(finding.get("reason", "")).strip()

        lines.append("")
        lines.append(f"[INFO] {title}")

        if reason:
            lines.append(reason)

        limitations = _safe_list(finding.get("limitations"))
        if limitations:
            first = str(limitations[0]).strip()
            if first:
                lines.append(f"Note: {first}")

        return lines

    @staticmethod
    def _clean_evidence_summary(values) -> list[str]:
        result: list[str] = []

        for value in values or []:
            text = str(value).strip()
            if not text:
                continue

            lower = text.lower()
            if (
                "datapoint" in lower
                or "has_data=" in lower
                or "status=" in lower
                or "coverage_" in lower
                or "requested_period" in lower
            ):
                continue

            if text not in result:
                result.append(text)

        return result

    def _section_recommendations(
        self,
        recommendations,
    ) -> list[str]:

        lines = _box(
            "RECOMMENDATIONS"
        )

        # The frontend reads recommendations from the database via
        # get_recommendations_by_scan + present_recommendations, so it
        # always shows every persisted recommendation for the scan.
        # The in-memory list passed to export() only contains the
        # recommendations generated during the current run, which can
        # be a subset. Read from the DB the same way the frontend does
        # so the summary always matches the frontend.
        from backend.database.connection import SessionLocal
        from backend.database.repositories.recommendation_repository import (
            get_recommendations_by_scan,
        )
        from backend.api.presenters.recommendation_presenter import (
            present_recommendations,
        )

        db = SessionLocal()

        try:

            presented = present_recommendations(
                get_recommendations_by_scan(
                    db,
                    self.scan_id,
                )
            )

        finally:
            db.close()

        if not presented:

            lines.append(
                " No recommendations generated."
            )

            return lines

        for recommendation in presented:

            if not isinstance(
                recommendation,
                dict,
            ):
                continue

            lines.extend(
                self._format_user_recommendation(
                    recommendation
                )
            )

        return lines

    def _format_user_recommendation(
        self,
        recommendation,
    ) -> list[str]:

        lines: list[str] = []

        priority = str(
            recommendation.get(
                "priority",
                "medium",
            )
        ).upper()

        title = str(
            recommendation.get(
                "title",
                "Recommendation",
            )
        )

        resource_ids = _safe_list(
            recommendation.get(
                "affected_resources",
                recommendation.get(
                    "resource_ids",
                    [],
                ),
            )
        )

        reason = str(
            recommendation.get(
                "reason",
                "",
            )
        ).strip()

        action = str(
            recommendation.get(
                "action",
                "",
            )
        ).strip()

        confidence = str(
            recommendation.get(
                "confidence",
                "",
            )
        ).strip()

        status = str(
            recommendation.get(
                "status",
                "",
            )
        ).strip()

        financial_impact = _safe_dict(
            recommendation.get(
                "financial_impact"
            )
        )

        lines.append("")
        lines.append(f"[{priority}] {title}")

        if resource_ids:
            lines.append(f"Resources: {len(resource_ids)}")

        if confidence:
            lines.append(f"Confidence: {confidence}")

        if reason:
            lines.append(f"Why: {reason}")

        if action:
            lines.append(f"Action: {action}")

        observed_cost = financial_impact.get(
            "observed_monthly_cost"
        )

        if isinstance(
            observed_cost,
            (int, float),
        ):
            lines.append(
                f"Observed cost: ${observed_cost:,.2f}"
            )

        estimated_savings = financial_impact.get(
            "estimated_monthly_savings"
        )

        if isinstance(
            estimated_savings,
            (int, float),
        ):
            lines.append(
                f"Potential savings: ${estimated_savings:,.2f}"
            )

        if status:
            lines.append(
                f"Status: {status.replace('_', ' ').title()}"
            )

        return lines

    def _section_resource_details(
        self,
        contexts,
    ) -> list[str]:

        lines = _box(
            "RESOURCE DETAILS"
        )

        contexts = contexts or []

        if not contexts:

            lines.append(
                " No resource details available."
            )

            return lines

        for context in contexts:

            resources = (
                _safe_dict(
                    context.get(
                        "evidence"
                    )
                ).get(
                    "resources",
                    []
                )
            )

            if not resources:
                continue

            service = context.get(
                "service",
                ""
            )

            region = context.get(
                "region",
                ""
            )

            usage_type = context.get(
                "usage_type",
                ""
            )

            resource_type = context.get(
                "resource_type",
                ""
            )

            cost = float(
                context.get(
                    "cost",
                    0,
                )
                or 0
            )

            lines.extend(
                [
                    "",
                    f"{service}",
                    f" Region     : {region}",
                    f" Usage type : {usage_type}",
                    f" Cost       : ${cost:,.2f}",
                    f" Resources  : {len(resources)} "
                    f"{resource_type}",
                ]
            )

            for resource in resources:

                self._append_resource(
                    lines,
                    resource,
                )

        return lines

    def _append_resource(
        self,
        lines: list[str],
        resource: dict,
    ) -> None:

        resource_id = (
            resource.get(
                "resource_id"
            )
            or resource.get(
                "id"
            )
            or "unknown"
        )

        lines.extend(
            [
                "",
                f"  Resource: {resource_id}",
            ]
        )

        configuration = _safe_dict(
            resource.get(
                "configuration"
            )
        )

        if configuration:

            lines.append(
                "  Configuration:"
            )

            for key, value in configuration.items():

                if value is None:
                    continue

                # Avoid enormous raw fields in the summary.
                if key in {
                    "tags",
                    "availability_zones",
                    "security_groups",
                }:
                    continue

                lines.append(
                    f"    {key}: "
                    f"{_format_value(value)}"
                )

        self._append_relationships(
            lines,
            resource.get(
                "relationships"
            ),
        )

        self._append_observations(
            lines,
            resource.get(
                "observations"
            ),
        )

        self._append_topology(
            lines,
            resource.get(
                "topology"
            ),
        )

        tags = resource.get(
            "tags"
        )

        if tags:

            lines.append(
                "  Tags: "
                + _format_value(tags)
            )

    @staticmethod
    def _append_relationships(
        lines: list[str],
        relationships,
    ) -> None:

        relationships = _safe_dict(
            relationships
        )

        if not relationships:
            return

        summary = _safe_dict(
            relationships.get(
                "summary"
            )
        )

        if not summary:
            return

        lines.append(
            "  Relationships:"
        )

        preferred = (
            "listener_count",
            "rule_count",
            "target_group_count",
            "target_count",
            "healthy_target_count",
            "unhealthy_target_count",
            "vpc_attachment_count",
            "other_attachment_count",
            "peering_attachment_count",
            "route_table_count",
            "route_count",
            "blackhole_route_count",
        )

        for key in preferred:

            if key not in summary:
                continue

            lines.append(
                f"    {key}: "
                f"{summary[key]}"
            )

    @staticmethod
    def _append_observations(
        lines: list[str],
        observations,
    ) -> None:

        observations = _safe_dict(
            observations
        )

        cloudwatch = _safe_dict(
            observations.get(
                "cloudwatch"
            )
        ) 


        if not cloudwatch:
            return

        lines.append(
            "  Observations:"
        )

        status = cloudwatch.get(
            "status"
        )

        if status:

            lines.append(
                f"    CloudWatch: {status}"
            )

        metrics = _safe_dict(
            cloudwatch.get(
                "metrics"
            )
        )

        observed = sum(
            1
            for metric in metrics.values()
            if (
                isinstance(metric, dict)
                and metric.get("status") == "ok"
                and metric.get("has_data") is True
            )
        )

        no_data = sum(
            1
            for metric in metrics.values()
            if (
                isinstance(metric, dict)
                and metric.get("status")
                in {"no_data", "missing"}
            )
        )
    

        errors = sum(
            1
            for metric in metrics.values()
            if (
                isinstance(metric, dict)
                and metric.get("status") == "error"
            )
        )

        if metrics:

            lines.append(
                "    Metrics: "
                f"{observed} observed"
                f", {no_data} no-data"
                f", {errors} errors"
            )

        # Print only useful derived activity data.
        activity = _safe_dict(
            cloudwatch.get(
                "activity"
            )
        )

        if activity:

            useful = {}

            for key in (
                "request_count",
                "processed_gib",
                "active_connections",
                "new_connections",
                "consumed_lcus",
                "traffic_observed",
            ):

                value = activity.get(
                    key
                )

                if value is not None:
                    useful[key] = value

            for key, value in useful.items():

                lines.append(
                    f"    {key}: "
                    f"{_format_value(value)}"
                )
    @staticmethod
    def _append_topology(
        lines: list[str],
        topology,
    ) -> None:

        topology = _safe_dict(
            topology
        )

        if not topology:
            return

        lines.append(
            "  Topology:"
        )

        summary = _safe_dict(
            topology.get(
                "summary"
            )
        )

        for key in (
            "load_balancer_subnet_count",
            "load_balancer_route_count",
            "load_balancer_network_interface_count",
            "load_balancer_uses_nat",
            "load_balancer_uses_transit_gateway",
            "load_balancer_uses_internet_gateway",
            "load_balancer_uses_vpc_peering",
            "tgw_subnet_count",
            "tgw_vpc_route_count",
            "active_tgw_vpc_route_count",
            "blackhole_tgw_vpc_route_count",
            "vpc_endpoint_count",
        ):

            if key not in summary:
                continue

            lines.append(
                f"    {key}: "
                f"{summary[key]}"
            )

        route_tables = _safe_list(
            topology.get(
                "route_tables"
            )
        )

        if route_tables:

            ids = []

            for route_table in route_tables:

                if isinstance(
                    route_table,
                    dict,
                ):

                    value = (
                        route_table.get(
                            "route_table_id"
                        )
                        or route_table.get(
                            "transit_gateway_route_table_id"
                        )
                    )

                    if value:
                        ids.append(
                            str(value)
                        )

                else:

                    ids.append(
                        str(route_table)
                    )

            if ids:

                lines.append(
                    "    Route tables: "
                    + ", ".join(ids)
                )

        subnets = _safe_list(
            topology.get(
                "subnets"
            )
        )

        if subnets:

            ids = []

            for subnet in subnets:

                if isinstance(
                    subnet,
                    dict,
                ):

                    value = subnet.get(
                        "subnet_id"
                    )

                    if value:
                        ids.append(
                            str(value)
                        )

                else:

                    ids.append(
                        str(subnet)
                    )

            if ids:

                lines.append(
                    "    Subnets: "
                    + ", ".join(ids)
                )

        endpoints = _safe_list(
            topology.get(
                "vpc_endpoints"
            )
        )

        if endpoints:

            names = []

            for endpoint in endpoints:

                if not isinstance(
                    endpoint,
                    dict,
                ):
                    continue

                name = (
                    endpoint.get(
                        "service_name"
                    )
                    or endpoint.get(
                        "service"
                    )
                    or endpoint.get(
                        "vpc_endpoint_id"
                    )
                )

                if name:
                    names.append(
                        str(name)
                    )

            if names:

                lines.append(
                    "    VPC endpoints: "
                    + ", ".join(names)
                )