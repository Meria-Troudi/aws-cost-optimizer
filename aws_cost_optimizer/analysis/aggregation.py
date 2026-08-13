"""
Finding aggregation.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .finding import Finding


class FindingAggregator:

    def aggregate(self,findings: list[Finding],) -> list[dict[str, Any]]:
        groups: dict[
            tuple[str, str, str],
            list[Finding],
        ] = defaultdict(list)

        for finding in findings:

            key = (
                finding.finding_type,
                finding.resource_type,
                self._scope(finding),
            )

            groups[key].append(finding)
        return [self._build_group(group)for group in groups.values()]

    def _build_group(
        self,
        findings: list[Finding],
    ) -> dict[str, Any]:

        first = findings[0]

        return {
            "finding_id":self._aggregate_id(findings),
            "finding_type":first.finding_type,
            "resource_type":first.resource_type,
            "analyzer":first.analyzer,
            "analyzer_version":first.analyzer_version,

            "severity":self._highest(findings,"severity"),
            "confidence":
                self._highest(
                    findings,
                    "confidence",
                ),

            "reason":self._aggregate_reason(findings),
            "resource_count":len(findings),
            "resource_ids": [finding.resource_id
                for finding in findings
            ],
            "conditions": [
                {
                    "resource_id":finding.resource_id,
                    "evidence": [
                        statement.to_dict()
                        for statement
                        in finding.conditions
                    ],
                }
                for finding in findings
            ],

            "evidence": [
                {
                    "resource_id":finding.resource_id,
                    "evidence":finding.evidence.to_dict(),
                }
                for finding in findings
            ],

            "observation_periods": [
                (
                    finding.observation_period.to_dict()
                    if finding.observation_period
                    else None
                )
                for finding in findings
            ],

            "limitations": [],
            "metadata": [finding.metadata
                for finding in findings
            ],

            "affected_resources": [
                self._resource_summary( finding)
                for finding in findings
            ],
            "aggregate_evidence":self._aggregate_evidence( findings),
            "scope":self._scope(first),
        }

  
    @staticmethod
    def _aggregate_reason(findings: list[Finding]) -> str:

        if len(findings) == 1:
            return findings[0].reason

        # Keep the real resource-level reasoning.
        reasons = [
            finding.reason
            for finding in findings
        ]

        unique = list(dict.fromkeys(reasons))
        if len(unique) == 1:
            return unique[0]
        return " ".join(unique)

  
    @staticmethod
    def _resource_summary(
        finding: Finding,
    ) -> dict[str, Any]:

        return {
            "resource_id":finding.resource_id,
            "resource_type":finding.resource_type,
            "severity":finding.severity,
            "confidence":finding.confidence,
            "reason": finding.reason,
            "evidence": [
                statement.to_dict()
                for statement
                in finding.conditions
            ],
            "observation_period": (
                finding.observation_period.to_dict()
                if finding.observation_period
                else None
            ),
        }
    @staticmethod
    def _aggregate_evidence(findings: list[Finding]) -> dict[str, Any]:

        result = {
            "affected_resource_count": len(findings),
            "traffic_bytes_total": 0.0,
            "traffic_gib_total":  0.0,
            "resources_with_traffic": 0,
            "resources_without_traffic":0,
            "resources_without_traffic_data":0,
        }

        for finding in findings:
            derived = (finding.evidence.derived)
            traffic_bytes = derived.get( "traffic_bytes")

            traffic_gib = derived.get( "traffic_gib" )

            traffic_available = derived.get(
                "traffic_available"
            )

            if isinstance(traffic_bytes, (int, float)):
                result[ "traffic_bytes_total"] += traffic_bytes

            if isinstance(traffic_gib, (int, float)):
                result["traffic_gib_total"] += traffic_gib

            if traffic_available is False:
                result[ "resources_without_traffic_data"] += 1

            elif (derived.get("traffic_observed" )is True):
                result[ "resources_with_traffic"] += 1
            else:
                result[ "resources_without_traffic"] += 1

        result[ "traffic_bytes_total"] = round(
            result[ "traffic_bytes_total"], 2,)
        result[ "traffic_gib_total"] = round( result["traffic_gib_total" ],  6,)

        return result

  
    @staticmethod
    def _scope(
        finding: Finding,
    ) -> str:

        region = (
            finding.evidence.resource.get(
                "region"
            )
        )

        return (
            str(region)
            if region
            else "account"
        )

  
    @staticmethod
    def _aggregate_id(
        findings: list[Finding],
    ) -> str:

        return findings[0].finding_id

  
    @staticmethod
    def _highest(
        findings: list[Finding],
        field: str,
    ) -> str:

        ranking = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }

        if field == "confidence":

            ranking = {
                "high": 3,
                "medium": 2,
                "low": 1,
            }

        return max(
            (
                getattr(
                    finding,
                    field,
                )
                for finding in findings
            ),
            key=lambda value:
                ranking.get(
                    str(value).lower(),
                    0,
                ),
        )