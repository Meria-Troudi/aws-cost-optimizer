"""
Finding evaluation engine.



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
        result.extend(
            aggregated
        )

        return result
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

      
        aggregated = (
            self.aggregator.aggregate(
                raw_findings
            )
        )



        self._attach_source_database_ids(
            aggregated,
            raw_database_id_by_stable_id,
        )

        # Raw findings are one-resource-plus-one-condition facts, each
        # already carrying its own database_id -- this is what the
        # recommendation engine consumes so it can emit exactly one
        # recommendation per eligible finding. Aggregated findings
        # (built above) stay a separate, reporting-only view: they
        # collapse many resources into one summary row and must never
        # be fed back into recommendation generation.
        raw_finding_dicts = [
            finding.to_dict()
            for finding in raw_findings
        ]

        result: list[Any] = []

      
        normalized_pre_findings: list[
            dict[str, Any]
        ] = []

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

            normalized_pre_findings.append(
                normalized
            )

        if normalized_pre_findings:

            from backend.database.repositories.finding_repository import (
                save_findings,
            )

            save_findings(
                db=db,
                scan_run_id=scan.id,
                findings=normalized_pre_findings,
            )

        result.extend(
            normalized_pre_findings
        )
        result.extend(
            aggregated
        )

        return {
            "raw_findings":
                raw_finding_dicts,

            "aggregated_findings":
                result,
        }
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
    @staticmethod
    def _persist(
        db,
        scan,
        findings,
    ):


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