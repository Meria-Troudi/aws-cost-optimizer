"""
Analysis engine.

Responsibilities
----------------
- execute analyzers
- normalize raw findings
- ensure stable resource identity
- perform deterministic raw deduplication

Important
---------
This engine NEVER decides aggregation scope.

Each Finding produced here remains a raw resource-level fact,
but `aggregation_scope` is left unset.

FindingAggregator is responsible for deciding whether raw findings
are reported per resource, region, account, or service.
"""

from __future__ import annotations

from typing import Any

from . import analyzers as _analyzers  # noqa: F401
from .base import Analyzer
from .context import AnalysisContext
from .finding import Finding
from .registry import get_analyzers


class AnalysisEngine:

    def __init__(
        self,
        analyzers: list[Analyzer] | None = None,
    ) -> None:

        self.analyzers = (
            analyzers
            if analyzers is not None
            else get_analyzers()
        )

    # ==============================================================
    # ANALYZE
    # ==============================================================

    def analyze(
        self,
        resources: list[dict[str, Any]],
        *,
        scan_id: int | str | None = None,
        account_id: str | None = None,
    ) -> list[Finding]:

        findings: list[Finding] = []

        for resource in resources:

            if not isinstance(
                resource,
                dict,
            ):
                continue

            context = self._build_context(
                resource=resource,
                scan_id=scan_id,
                account_id=account_id,
            )

            for analyzer in self.analyzers:

                # --------------------------------------------------
                # SUPPORT
                # --------------------------------------------------

                try:

                    if not analyzer.supports(
                        context
                    ):
                        continue

                except Exception as exc:

                    print(
                        "[ERROR] Analyzer "
                        f"{analyzer.name} support check failed "
                        f"for {context.resource_id}: {exc}"
                    )

                    continue

                # --------------------------------------------------
                # ANALYZE
                # --------------------------------------------------

                try:

                    results = analyzer.analyze(
                        context
                    )

                except Exception as exc:

                    print(
                        "[ERROR] Analyzer "
                        f"{analyzer.name} failed "
                        f"for {context.resource_id}: {exc}"
                    )

                    continue

                if not isinstance(
                    results,
                    list,
                ):

                    print(
                        "[ERROR] Analyzer "
                        f"{analyzer.name} returned "
                        "non-list result"
                    )

                    continue

                # --------------------------------------------------
                # NORMALIZE
                # --------------------------------------------------

                for finding in results:

                    if not isinstance(
                        finding,
                        Finding,
                    ):

                        print(
                            "[ERROR] Analyzer "
                            f"{analyzer.name} returned "
                            "invalid finding object"
                        )

                        continue

                    self._normalize_finding(
                        finding=finding,
                        context=context,
                        account_id=account_id,
                    )

                    findings.append(
                        finding
                    )

        return self._deduplicate_findings(
            findings
        )

    # ==============================================================
    # NORMALIZATION
    # ==============================================================

    @staticmethod
    def _normalize_finding(
        *,
        finding: Finding,
        context: AnalysisContext,
        account_id: str | None,
    ) -> None:

        # ----------------------------------------------------------
        # Resource identity
        # ----------------------------------------------------------

        if not finding.resource_id:

            finding.resource_id = (
                context.resource_id
                or "unknown"
            )

        if not finding.resource_type:

            finding.resource_type = (
                context.resource_type
                or "unknown"
            )

        # ----------------------------------------------------------
        # Account
        # ----------------------------------------------------------

        if not finding.account_id:

            finding.account_id = (
                str(account_id)
                if account_id is not None
                else None
            )

        # ----------------------------------------------------------
        # Region
        # ----------------------------------------------------------

        if context.region:

            finding.metadata.setdefault(
                "region",
                context.region,
            )

        if account_id:

            finding.metadata.setdefault(
                "account_id",
                str(account_id),
            )

        # ----------------------------------------------------------
        # IMPORTANT
        #
        # DO NOT set aggregation_scope here.
        #
        # None means:
        #     "the analyzer did not select report scope"
        #
        # The aggregator decides the report scope.
        # ----------------------------------------------------------

        # ----------------------------------------------------------
        # Finding identity
        #
        # Raw finding identity always includes resource_id.
        # ----------------------------------------------------------

        finding.finding_key = (
            finding.finding_key
            or finding.build_finding_key()
        )

        finding.finding_id = (
            finding.build_stable_id()
        )

    # ==============================================================
    # RAW DEDUPLICATION
    # ==============================================================

    @staticmethod
    def _deduplicate_findings(
        findings: list[Finding],
    ) -> list[Finding]:

        result: list[Finding] = []

        seen: set[
            tuple[
                str,
                str,
                str,
                str,
                str,
            ]
        ] = set()

        for finding in findings:

            key = (
                str(
                    finding.account_id
                    or "unknown"
                ),

                str(
                    finding.finding_key
                    or finding.finding_type
                ),

                str(
                    finding.resource_type
                    or "unknown"
                ),

                str(
                    finding.resource_id
                    or "unknown"
                ),

                str(
                    finding._region()
                    or "unknown"
                ),
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            result.append(
                finding
            )

        return result

    # ==============================================================
    # CONTEXT
    # ==============================================================

    @staticmethod
    def _build_context(
        resource: dict[str, Any],
        scan_id: int | str | None,
        account_id: str | None,
    ) -> AnalysisContext:

        return AnalysisContext(
            resource=resource,

            scan_id=scan_id,

            account_id=account_id,

            observation_period=(
                resource.get(
                    "observation_period"
                )
            ),

            cost_context=(
                resource.get(
                    "cost_context"
                )
            ),
        )