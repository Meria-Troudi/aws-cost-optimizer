"""
Finding evaluation engine.

Pipeline:

resources
    -> analyzers
    -> raw resource findings
    -> persist raw findings
    -> aggregation
    -> reportable findings
    -> recommendation source IDs resolved to persisted findings

Important
---------
A database Finding row represents ONE raw resource-level finding.

Aggregation is a reporting concern only.

Therefore:

    nat-1 + nat-2 + nat-3
        -> 3 persisted Finding rows
        -> 1 aggregated/reportable finding

This preserves resource-level traceability while still allowing
regional/account/service aggregation for the UI and reporting.
"""

from __future__ import annotations

from typing import Any

from . import analyzers as _analyzers  # noqa: F401
from .aggregation import FindingAggregator
from .engine import AnalysisEngine
from .finding import Finding


class FindingEngine:

    def __init__(
        self,
        analyzers=None,
    ) -> None:

        self.analysis_engine = AnalysisEngine(
            analyzers=analyzers
        )

        self.aggregator = (
            FindingAggregator()
        )

    # ==============================================================
    # EVALUATE
    # ==============================================================

    def evaluate(
        self,
        resources,
        *,
        scan_id=None,
        account_id=None,
        enriched_results=None,
        pre_findings=None,
    ):

        _ = enriched_results

        raw_findings = (
            self.analysis_engine.analyze(
                resources,
                scan_id=scan_id,
                account_id=account_id,
            )
        )

        aggregated = (
            self.aggregator.aggregate(
                raw_findings
            )
        )

        result: list[Any] = []

        # ----------------------------------------------------------
        # Data-quality findings generated upstream.
        #
        # These are already dictionaries and are not part of the
        # analyzer raw Finding lifecycle.
        # ----------------------------------------------------------

        for finding in (
            pre_findings or []
        ):

            if not isinstance(
                finding,
                dict,
            ):
                continue

            normalized = dict(
                finding
            )

            normalized.setdefault(
                "category",
                "data_quality",
            )

            normalized.setdefault(
                "status",
                "informational",
            )

            normalized.setdefault(
                "recommendation_eligible",
                False,
            )

            normalized.setdefault(
                "resource_ids",
                [],
            )

            result.append(
                normalized
            )

        # ----------------------------------------------------------
        # Aggregated optimization findings.
        # ----------------------------------------------------------

        result.extend(
            aggregated
        )

        return result

    # ==============================================================
    # EVALUATE + PERSIST
    # ==============================================================

    def evaluate_and_persist(
        self,
        db,
        scan,
        resources,
        enriched_results=None,
        pre_findings=None,
    ):

        _ = enriched_results

        if scan is None:
            raise ValueError(
                "scan is required."
            )

        # ----------------------------------------------------------
        # 1. Analyze resources into RAW resource-level findings.
        # ----------------------------------------------------------

        raw_findings = (
            self.analysis_engine.analyze(
                resources,
                scan_id=scan.id,
                account_id=getattr(
                    scan,
                    "account_id",
                    None,
                ),
            )
        )

        # ----------------------------------------------------------
        # 2. Persist RAW findings.
        #
        # This is the authoritative DB representation.
        #
        # Example:
        #
        #   NAT-1 -> Finding.id = 101
        #   NAT-2 -> Finding.id = 102
        #   NAT-3 -> Finding.id = 103
        # ----------------------------------------------------------

        saved_raw = self._persist_raw_findings(
            db=db,
            scan=scan,
            findings=raw_findings,
        )

        self._attach_database_ids_to_raw_findings(
            raw_findings,
            saved_raw,
        )

        raw_database_id_by_stable_id = {
            finding.finding_id:
                getattr(
                    persisted,
                    "id",
                    None,
                )
            for finding, persisted
            in zip(
                raw_findings,
                saved_raw,
            )
            if (
                finding.finding_id
                and getattr(
                    persisted,
                    "id",
                    None,
                ) is not None
            )
        }

        # ----------------------------------------------------------
        # 3. Aggregate raw findings for reporting.
        #
        # The aggregator still works entirely on raw Finding objects.
        # ----------------------------------------------------------

        aggregated = (
            self.aggregator.aggregate(
                raw_findings
            )
        )

        # ----------------------------------------------------------
        # 4. Attach persisted DB finding IDs to each aggregated
        #    finding so RecommendationEngine can reference the
        #    actual raw rows.
        # ----------------------------------------------------------

        self._attach_source_database_ids(
            aggregated,
            raw_database_id_by_stable_id,
        )

        result: list[Any] = []

        # ----------------------------------------------------------
        # 5. Add upstream data-quality findings.
        #
        # These are not recommendation-eligible and therefore do not
        # need raw analyzer Finding persistence.
        # ----------------------------------------------------------

        for finding in (
            pre_findings or []
        ):

            if not isinstance(
                finding,
                dict,
            ):
                continue

            normalized = dict(
                finding
            )

            normalized.setdefault(
                "category",
                "data_quality",
            )

            normalized.setdefault(
                "status",
                "informational",
            )

            normalized.setdefault(
                "recommendation_eligible",
                False,
            )

            normalized.setdefault(
                "resource_ids",
                [],
            )

            result.append(
                normalized
            )

        # ----------------------------------------------------------
        # 6. Add aggregated optimization findings.
        # ----------------------------------------------------------

        result.extend(
            aggregated
        )

        return result

    # ==============================================================
    # RAW FINDING PERSISTENCE
    # ==============================================================

    @staticmethod
    def _persist_raw_findings(
        db,
        scan,
        findings: list[Finding],
    ):

        if not findings:
            return []

        from backend.database.repositories.finding_repository import (
            save_findings,
        )

        payload = [
            finding.to_dict()
            for finding in findings
            if isinstance(
                finding,
                Finding,
            )
        ]

        if not payload:
            return []

        saved = save_findings(
            db=db,
            scan_run_id=scan.id,
            findings=payload,
        )

        if saved is None:
            return []

        if not isinstance(
            saved,
            list,
        ):
            saved = [saved]

        if len(saved) != len(payload):
            raise RuntimeError(
                "Raw finding persistence count mismatch: "
                f"{len(payload)} generated, "
                f"{len(saved)} persisted."
            )

        return saved

    # ==============================================================
    # DATABASE IDS -> RAW FINDINGS
    # ==============================================================

    @staticmethod
    def _attach_database_ids_to_raw_findings(
         findings: list[Finding],
        saved,
    ) -> None:

        if len(findings) != len(saved):
            raise RuntimeError(
                "Raw finding persistence count mismatch: "
                f"{len(findings)} generated, "
                f"{len(saved)} persisted."
            )

        for finding, database_object in zip(
            findings,
            saved,
        ):

            database_id = getattr(
                database_object,
                "id",
                None,
            )

            if database_id is None:
                raise RuntimeError(
                    "Persisted raw finding has no database ID."
                )

            finding.database_id = int(
                database_id
            )

    # ==============================================================
    # RAW DATABASE IDS -> AGGREGATED FINDINGS
    # ==============================================================

    @staticmethod
    def _attach_source_database_ids(
        aggregated: list[dict[str, Any]],
        raw_database_id_by_stable_id: dict[str, int | None],
    ) -> None:

        for finding in aggregated:

            if not isinstance(
                finding,
                dict,
            ):
                continue

            source_stable_ids = (
                finding.get(
                    "source_finding_stable_ids"
                )
            )

            if not isinstance(
                source_stable_ids,
                list,
            ):
                source_stable_ids = []

            database_ids: list[int] = []
            seen: set[int] = set()

            for stable_id in source_stable_ids:

                database_id = (
                    raw_database_id_by_stable_id.get(
                        stable_id
                    )
                )

                if database_id is None:
                    continue

                database_id = int(
                    database_id
                )

                if database_id in seen:
                    continue

                seen.add(
                    database_id
                )

                database_ids.append(
                    database_id
                )

            finding[
                "source_finding_ids"
            ] = database_ids

    # ==============================================================
    # LEGACY COMPATIBILITY
    # ==============================================================

    @staticmethod
    def _persist(
        db,
        scan,
        findings,
    ):
        """
        Compatibility wrapper.

        New code must persist RAW findings through
        _persist_raw_findings().

        This method remains available so older callers do not fail.
        """

        raw_findings = [
            finding
            for finding in findings
            if isinstance(
                finding,
                Finding,
            )
        ]

        return FindingEngine._persist_raw_findings(
            db=db,
            scan=scan,
            findings=raw_findings,
        )