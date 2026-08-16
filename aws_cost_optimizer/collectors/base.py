"""
Base collector.

Provides the common lifecycle for all AWS resource collectors:

discovery
    -> identity
    -> configuration
    -> relationships
    -> observations
    -> topology
    -> optimization evidence
    -> data quality

The base collector never makes optimization decisions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import date, datetime, timezone
from typing import Any, Dict, List


class BaseCollector(ABC):

    key: str | None = None
    resource_type: str | None = None

    SECTION_DEFAULTS = {
        "identity": True,
        "configuration": True,
        "relationships": True,
        "observations": False,
        "topology": True,
    }

    def __init__(
        self,
        scan,
        region: str | None = None,
        profile: Dict[str, Any] | None = None,
    ):
        self.scan = scan
        self.region = (
            region
            or scan.region
        )
        self.profile = (
            profile
            if isinstance(profile, dict)
            else {}
        )

    # ==================================================================
    # PUBLIC COLLECTION
    # ==================================================================

    def collect(
        self,
    ) -> List[Dict[str, Any]]:

        resources: List[
            Dict[str, Any]
        ] = []

        discovered = self.discover()

        if not isinstance(discovered, list):
            raise TypeError(
                f"{self.__class__.__name__}.discover() "
                "must return a list."
            )

        for resource in discovered:

            if not isinstance(resource, dict):
                continue

            resource_id = (
                self._safe_resource_id(
                    resource
                )
            )

            try:

                collected = (
                    self._collect_resource(
                        resource
                    )
                )

                resources.append(
                    collected
                )

                self._print_summary(
                    collected
                )

            except Exception as exc:

                print(
                    f"[{self.key}] Failed to collect "
                    f"{resource_id}: {exc}"
                )

                resources.append(
                    {
                        "resource_id":
                            resource_id,

                        "resource_type":
                            self.resource_type,

                        "region":
                            self.region,

                        "collection_status":
                            "failed",

                        "collection_errors": {
                            "resource":
                                str(exc),
                        },

                        "data_quality": {
                            "collection_status":
                                "failed",

                            "resource_collection":
                                "failed",

                            "section_errors": {
                                "resource":
                                    str(exc),
                            },

                            "optimization_evidence_available":
                                False,
                        },

                        "optimization_evidence":
                            {},

                        "raw":
                            resource,
                    }
                )

        return resources

    # ==================================================================
    # RESOURCE LIFECYCLE
    # ==================================================================

    def _collect_resource(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        resource_id = (
            self.get_resource_id(
                resource
            )
        )

        context: Dict[
            str,
            Any,
        ] = {
            "resource_id":
                str(
                    resource_id
                ),

            "resource_type":
                self.resource_type,

            "region":
                self.region,

            "collection_status":
                "complete",

            "collection_errors":
                {},
        }

        # --------------------------------------------------------------
        # Identity
        # --------------------------------------------------------------

        self._safe_collect_section(
            context=context,
            section_name="identity",
            resource=resource,
            collector=self.collect_identity,
        )

        # --------------------------------------------------------------
        # Configuration
        # --------------------------------------------------------------

        self._safe_collect_section(
            context=context,
            section_name="configuration",
            resource=resource,
            collector=self.collect_configuration,
        )

        # --------------------------------------------------------------
        # Relationships
        # --------------------------------------------------------------

        self._safe_collect_section(
            context=context,
            section_name="relationships",
            resource=resource,
            collector=self.collect_relationships,
        )

        # --------------------------------------------------------------
        # Observations
        # --------------------------------------------------------------

        self._safe_collect_section(
            context=context,
            section_name="observations",
            resource=resource,
            collector=self.collect_observations,
        )

        # --------------------------------------------------------------
        # Topology
        # --------------------------------------------------------------

        topology_context = (
            self._safe_collect_topology(
                context=context,
                resource=resource,
            )
        )

        if topology_context is not None:

            context["topology"] = (
                topology_context
            )

        # --------------------------------------------------------------
        # Optimization evidence
        #
        # This is collector-derived evidence. It must be built only
        # after all collector sections are available.
        # --------------------------------------------------------------

        optimization_evidence = {}

        try:

            value = (
                self.build_optimization_evidence(
                    resource,
                    context,
                )
            )

            if isinstance(value, dict):
                optimization_evidence = value

        except Exception as exc:

            self._record_error(
                context,
                "optimization_evidence",
                exc,
            )

        context[
            "optimization_evidence"
        ] = optimization_evidence

        # --------------------------------------------------------------
        # Final status
        # --------------------------------------------------------------

        errors = context.get(
            "collection_errors",
            {},
        )

        context[
            "collection_status"
        ] = (
            "partial"
            if errors
            else "complete"
        )

        # --------------------------------------------------------------
        # Data quality
        # --------------------------------------------------------------

        context[
            "data_quality"
        ] = self._build_data_quality(
            context
        )

        # --------------------------------------------------------------
        # Preserve collector source payload.
        # --------------------------------------------------------------

        context["raw"] = resource

        return context

    # ==================================================================
    # SAFE SECTION COLLECTION
    # ==================================================================

    def _safe_collect_section(
        self,
        *,
        context: Dict[str, Any],
        section_name: str,
        resource: Dict[str, Any],
        collector,
    ) -> None:

        if not self._section_enabled(
            section_name
        ):

            context[
                section_name
            ] = {
                "status":
                    "disabled"
            }

            return

        try:

            value = collector(
                resource
            )

            if value is None:
                value = {}

            if not isinstance(
                value,
                dict,
            ):
                raise TypeError(
                    f"{section_name} collector must return dict, "
                    f"got {type(value).__name__}"
                )

            context[
                section_name
            ] = value

        except Exception as exc:

            self._record_error(
                context,
                section_name,
                exc,
            )

            context[
                section_name
            ] = {
                "status":
                    "error",

                "error":
                    str(exc),
            }

    def _safe_collect_topology(
        self,
        *,
        context: Dict[str, Any],
        resource: Dict[str, Any],
    ) -> Dict[str, Any] | None:

        if not self._section_enabled(
            "topology"
        ):

            return {
                "status":
                    "disabled"
            }

        try:

            value = (
                self.collect_topology(
                    resource,
                    context,
                )
            )

            if value is None:
                return {}

            if not isinstance(
                value,
                dict,
            ):
                raise TypeError(
                    "topology collector must return dict."
                )

            return value

        except Exception as exc:

            self._record_error(
                context,
                "topology",
                exc,
            )

            return {
                "status":
                    "error",

                "error":
                    str(exc),
            }

    @staticmethod
    def _record_error(
        context: Dict[str, Any],
        section: str,
        exc: Exception,
    ) -> None:

        errors = context.setdefault(
            "collection_errors",
            {},
        )

        errors[
            section
        ] = str(exc)

    # ==================================================================
    # DATA QUALITY
    # ==================================================================

    @staticmethod
    def _build_data_quality(
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        from aws_cost_optimizer.analysis.metrics import (
            count_queried_metrics,
            count_observed_metrics,
            count_missing_metrics,
            count_metric_errors,
        )

        errors = context.get(
            "collection_errors",
            {},
        )

        observations = context.get(
            "observations",
            {},
        )

        topology = context.get(
            "topology",
            {},
        )

        optimization_evidence = context.get(
            "optimization_evidence",
            {},
        )

        if not isinstance(
            optimization_evidence,
            dict,
        ):
            optimization_evidence = {}

        cloudwatch = (
            observations.get(
                "cloudwatch",
                {},
            )
            if isinstance(
                observations,
                dict,
            )
            else {}
        )

        if not isinstance(
            cloudwatch,
            dict,
        ):
            cloudwatch = {}

        metrics = (
            cloudwatch.get(
                "metrics",
                {},
            )
            if isinstance(
                cloudwatch,
                dict,
            )
            else {}
        )

        queried = count_queried_metrics(
            metrics
        )

        observed = count_observed_metrics(
            metrics
        )

        no_data = count_missing_metrics(
            metrics
        )

        metric_errors = count_metric_errors(
            metrics
        )

        topology_status = (
            topology.get(
                "status"
            )
            if isinstance(
                topology,
                dict,
            )
            else None
        )

        return {
            "collection_status":
                (
                    "partial"
                    if errors
                    else "complete"
                ),

            "section_errors":
                dict(errors),

            "identity_available":
                bool(
                    context.get(
                        "identity"
                    )
                ),

            "configuration_available":
                bool(
                    context.get(
                        "configuration"
                    )
                ),

            "relationships_available":
                bool(
                    context.get(
                        "relationships"
                    )
                ),

            "topology_available":
                topology_status == "ok",

            "observations_available":
                queried > 0,

            "optimization_evidence_available":
                bool(
                    optimization_evidence
                ),

            "metric_result_count":
                queried,

            "queried_metric_count":
                queried,

            "observed_metric_count":
                observed,

            "no_data_metric_count":
                no_data,

            "metric_error_count":
                metric_errors,

            "metric_observation_ratio":
                (
                    observed / queried
                    if queried > 0
                    else None
                ),
        }

    # ==================================================================
    # ANALYSIS PERIOD
    # ==================================================================

    def get_analysis_period(self):

        start = (
            getattr(
                self.scan,
                "analysis_start",
                None,
            )
            or getattr(
                self.scan,
                "start_date",
                None,
            )
            or getattr(
                self.scan,
                "start_time",
                None,
            )
        )

        end = (
            getattr(
                self.scan,
                "analysis_end",
                None,
            )
            or getattr(
                self.scan,
                "end_date",
                None,
            )
            or getattr(
                self.scan,
                "end_time",
                None,
            )
        )

        if start is None or end is None:

            raise ValueError(
                "Scan analysis period is not configured. "
                "Expected analysis_start/analysis_end, "
                "start_date/end_date, or start_time/end_time."
            )

        start = (
            self._normalize_datetime(
                start
            )
        )

        end = (
            self._normalize_datetime(
                end
            )
        )

        if start >= end:

            raise ValueError(
                "Invalid analysis period: "
                f"start={start}, end={end}"
            )

        return start, end

    # ==================================================================
    # PROFILE
    # ==================================================================

    def _section_enabled(
        self,
        section_name: str,
        default: bool | None = None,
    ) -> bool:

        if default is None:

            default = (
                self.SECTION_DEFAULTS.get(
                    section_name,
                    False,
                )
            )

        section = self.profile.get(
            section_name,
            {},
        )

        if not isinstance(
            section,
            dict,
        ):
            return default

        if "enabled" not in section:
            return default

        return (
            section.get(
                "enabled"
            )
            is True
        )

    # ==================================================================
    # ABSTRACT / DEFAULT INTERFACES
    # ==================================================================

    @abstractmethod
    def discover(
        self,
    ) -> list:
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

    # ==================================================================
    # CONSOLE SUMMARY
    # ==================================================================

    def _print_summary(
        self,
        context: Dict[str, Any],
    ) -> None:

        print(
            "Collected: "
            f"{context.get('resource_type')} - "
            f"{context.get('resource_id')}"
        )

        print(
            f"  Region: "
            f"{context.get('region')}"
        )

        identity = context.get(
            "identity"
        )

        if isinstance(
            identity,
            dict,
        ):
            print(
                "  Identity: "
                + (
                    str(
                        identity.get("name")
                    )
                    if identity.get("name")
                    else "available"
                )
            )

        configuration = context.get(
            "configuration"
        )

        if isinstance(
            configuration,
            dict,
        ):
            print(
                "  Configuration: "
                + (
                    "available"
                    if configuration
                    else "empty"
                )
            )

        topology = context.get(
            "topology"
        )

        if isinstance(
            topology,
            dict,
        ):
            print(
                "  Topology: "
                + (
                    str(
                        topology.get("status")
                    )
                    if topology.get("status")
                    else (
                        "available"
                        if topology
                        else "empty"
                    )
                )
            )

        relationships = context.get(
            "relationships"
        )

        if isinstance(
            relationships,
            dict,
        ):
            print(
                "  Relationships: "
                + (
                    "available"
                    if relationships
                    else "empty"
                )
            )

        observations = context.get(
            "observations"
        )

        if isinstance(
            observations,
            dict,
        ):
            print(
                "  Observations: "
                + (
                    "available"
                    if observations
                    else "empty"
                )
            )

        # --------------------------------------------------------------
        # FIX:
        # The old implementation printed:
        #
        #     optimization_evidence.get("name")
        #
        # There is normally no "name" field in optimization evidence.
        # --------------------------------------------------------------

        optimization_evidence = context.get(
            "optimization_evidence"
        )

        if isinstance(
            optimization_evidence,
            dict,
        ):
            print(
                "  Optimization Evidence: "
                + (
                    "available"
                    if optimization_evidence
                    else "none"
                )
            )

        errors = context.get(
            "collection_errors",
            {},
        )

        if errors:

            print(
                "  Collection errors: "
                + str(errors)
            )

        observations = context.get(
            "observations",
            {},
        )

        if not isinstance(
            observations,
            dict,
        ):
            observations = {}

        cloudwatch = observations.get(
            "cloudwatch",
            {},
        )

        if isinstance(
            cloudwatch,
            dict,
        ) and cloudwatch:

            metrics = cloudwatch.get(
                "metrics",
                {},
            )

            if isinstance(
                metrics,
                dict,
            ):
                metric_list = list(
                    metrics.values()
                )
            else:
                metric_list = list(
                    metrics or []
                )

            observed = sum(
                1
                for metric in metric_list
                if (
                    isinstance(
                        metric,
                        dict,
                    )
                    and metric.get(
                        "status"
                    ) == "ok"
                    and metric.get(
                        "has_data"
                    ) is True
                )
            )

            errors_count = sum(
                1
                for metric in metric_list
                if (
                    isinstance(
                        metric,
                        dict,
                    )
                    and metric.get(
                        "status"
                    ) == "error"
                )
            )

            no_data = sum(
                1
                for metric in metric_list
                if (
                    isinstance(
                        metric,
                        dict,
                    )
                    and metric.get(
                        "status"
                    ) in {
                        "no_data",
                        "missing",
                    }
                )
            )

            print(
                "  CloudWatch results: "
                f"{len(metric_list)} "
                f"(observed={observed}, "
                f"no_data={no_data}, "
                f"errors={errors_count})"
            )

        status = context.get(
            "collection_status"
        )

        if status:

            print(
                f"  Collection status: "
                f"{status}"
            )

    # ==================================================================
    # HELPERS
    # ==================================================================

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

        if isinstance(
            value,
            datetime,
        ):

            if value.tzinfo is None:

                return value.replace(
                    tzinfo=timezone.utc
                )

            return value.astimezone(
                timezone.utc
            )

        if isinstance(
            value,
            date,
        ):

            return datetime(
                value.year,
                value.month,
                value.day,
                tzinfo=timezone.utc,
            )

        if isinstance(
            value,
            str,
        ):

            value = value.strip()

            if value.endswith(
                "Z"
            ):

                value = (
                    value[:-1]
                    + "+00:00"
                )

            parsed = datetime.fromisoformat(
                value
            )

            if parsed.tzinfo is None:

                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(
                timezone.utc
            )

        raise TypeError(
            "Unsupported datetime value: "
            f"{type(value).__name__}"
        )