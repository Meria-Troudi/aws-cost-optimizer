"""
Analysis engine.

"""

from __future__ import annotations

from typing import Any

from .analyzers.base import Analyzer
from .analyzers.registry import get_analyzers
from . import analyzers as _analyzers  # noqa: F401
from .context import AnalysisContext
from .finding import Finding


class AnalysisEngine:

    def __init__(
        self,
        analyzers: list[Analyzer] | None = None,
    ) -> None:
        self.analyzers = analyzers if analyzers is not None else get_analyzers()

    def analyze(
        self,
        resources: list[dict[str, Any]],
        *,
        scan_id: int | str | None = None,
        account_id: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for resource in resources:
            context = self._build_context(
                resource=resource,
                scan_id=scan_id,
                account_id=account_id,
            )

            for analyzer in self.analyzers:
                if not analyzer.supports(context):
                    continue

                try:
                    results = analyzer.analyze(context)
                except Exception as exc:
                    # In production, use structured logging
                    print( f"[ERROR] Analyzer {analyzer.name} failed " f"for {context.resource_id}: {exc}"
                    )
                    continue

                findings.extend(results)

        return findings

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
            observation_period=resource.get("observation_period"),
            cost_context=resource.get("cost_context"),
        )
