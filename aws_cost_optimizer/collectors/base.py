"""
Base collector.

Common lifecycle for AWS resource collectors:

    discover
        ↓
    identity
        ↓
    configuration
        ↓
    relationships
        ↓
    observations
        ↓
    topology
        ↓
    optimization evidence
        
    normalized resource
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import date, datetime, timezone
from typing import Any, Dict, List


class BaseCollector(ABC):

    key: str | None = None
    resource_type: str | None = None

    def __init__(
        self,
        scan,
        region: str | None = None,
        profile: Dict[str, Any] | None = None,
    ):
        self.scan = scan
        self.region = region or scan.region
        self.profile = profile or {}
    def collect(self) -> List[Dict[str, Any]]:
        resources: List[Dict[str, Any]] = []

        discovered = self.discover()

        for resource in discovered:

            try:
                collected = self._collect_resource(resource)

                resources.append(collected)

                self._print_summary(collected)

            except Exception as exc:
                resource_id = self._safe_resource_id(resource)

                print(
                    f"[{self.key}] Failed to collect "
                    f"{resource_id}: {exc}"
                )

        return resources

    def _collect_resource(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        resource_id = self.get_resource_id(resource)

        context: Dict[str, Any] = {
            "resource_id": resource_id,
            "resource_type": self.resource_type,
            "region": self.region,
        }

        if self._section_enabled("identity"):
            context["identity"] = self.collect_identity(resource)

        if self._section_enabled("configuration"):
            context["configuration"] = (
                self.collect_configuration(resource)
            )

        if self._section_enabled("relationships"):
            context["relationships"] = (
                self.collect_relationships(resource)
            )

        if self._section_enabled("observations"):
            context["observations"] = (
                self.collect_observations(resource)
            )

        if self._section_enabled("topology"):
            context["topology"] = self.collect_topology(
                resource,
                context,
            )

        evidence = self.build_optimization_evidence(
            resource,
            context,
        )

        if evidence:
            context["optimization_evidence"] = evidence


        context["raw"] = resource

        return context
    def get_analysis_period(self):
        start = (
            getattr(self.scan, "analysis_start", None)
            or getattr(self.scan, "start_date", None)
            or getattr(self.scan, "start_time", None)
        )

        end = (
            getattr(self.scan, "analysis_end", None)
            or getattr(self.scan, "end_date", None)
            or getattr(self.scan, "end_time", None)
        )

        if start is None or end is None:
            raise ValueError(
                "Scan analysis period is not configured. "
                "Expected analysis_start/analysis_end, "
                "start_date/end_date, or start_time/end_time."
            )

        start = self._normalize_datetime(start)
        end = self._normalize_datetime(end)

        if start >= end:
            raise ValueError(
                f"Invalid analysis period: "
                f"start={start}, end={end}"
            )

        return start, end

    def _section_enabled(
        self,
        section_name: str,
        default: bool = False,
    ) -> bool:

        section = self.profile.get(
            section_name,
            {},
        )

        if not isinstance(section, dict):
            return default

        return section.get(
            "enabled",
            default,
        ) is True

    @abstractmethod
    def discover(self) -> list:
        raise NotImplementedError

    def get_resource_id(
        self,
        resource: dict,
    ) -> str:
        raise NotImplementedError
    def collect_identity(
        self,
        resource: dict,
    ) -> dict:
        return {}

    def collect_configuration(
        self,
        resource: dict,
    ) -> dict:
        return {}

    def collect_observations(
        self,
        resource: dict,
    ) -> dict:
        return {}

    def collect_relationships(
        self,
        resource: dict,
    ) -> dict:
        return {}

    def collect_topology(
        self,
        resource: dict,
        collected_resource: dict,
    ) -> dict:
        return {}

    def build_optimization_evidence(
        self,
        resource: dict,
        collected_resource: dict,
    ) -> dict:
        return {}

    def _print_summary(
        self,
        context: Dict[str, Any],
    ) -> None:

        print(
            f"Collected: "
            f"{context.get('resource_type')} - "
            f"{context.get('resource_id')}"
        )

        print(
            f"  Region: {context.get('region')}"
        )

        identity = context.get("identity")

        if identity:
            print(
                f"  Identity: "
                f"{identity.get('name') or context.get('resource_id')}"
            )

        observations = context.get("observations", {})
        cloudwatch = observations.get("cloudwatch", {})

        if cloudwatch:
            metrics = cloudwatch.get("metrics", {})

            if isinstance(metrics, dict):
                metric_list = list(metrics.values())
            else:
                metric_list = metrics or []

            print(
                f"  CloudWatch metrics: "
                f"{len(metric_list)}"
            )

    @staticmethod
    def _safe_resource_id(
        resource: Dict[str, Any],
    ) -> str:

        return str(
            resource.get("id")
            or resource.get("arn")
            or resource.get("name")
            or "unknown"
        )

    @staticmethod
    def _normalize_datetime(
        value,
    ) -> datetime:

        if isinstance(value, datetime):

            if value.tzinfo is None:
                return value.replace(
                    tzinfo=timezone.utc
                )

            return value.astimezone(
                timezone.utc
            )

        if isinstance(value, date):

            return datetime(
                value.year,
                value.month,
                value.day,
                tzinfo=timezone.utc,
            )

        if isinstance(value, str):

            value = value.strip()

            if value.endswith("Z"):
                value = value[:-1] + "+00:00"

            parsed = datetime.fromisoformat(value)

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(
                timezone.utc
            )

        raise TypeError(
            f"Unsupported datetime value: "
            f"{type(value).__name__}"
        )