"""
Base analyzer interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .context import AnalysisContext
from .finding import Finding


class Analyzer(ABC):

    name: str = "unknown"
    version: str = "1.0"

    @abstractmethod
    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:
        raise NotImplementedError

    @abstractmethod
    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:
        raise NotImplementedError

    def classify(
        self,
        context: AnalysisContext,
        findings: list[Finding],
    ) -> tuple[str, str | None]:
        """
        Classify the *outcome* of an analysis, separately from the raw
        finding count.

        Returns a ``(status, reason)`` tuple where ``status`` is one of:

            finding_generated      -> a real optimization finding was produced
            no_optimization_match  -> enough evidence was available but nothing
                                      qualified for an optimization finding
            insufficient_evidence  -> required evidence was missing/unknown, so
                                      a safe optimization decision was impossible

        The default behaviour is intentionally conservative:

            findings exist  -> finding_generated
            no findings     -> no_optimization_match

        Analyzers that genuinely cannot decide when evidence is missing
        (e.g. Transit Gateway with incomplete route topology, WAF with
        incomplete CloudWatch telemetry) override this to return
        ``insufficient_evidence`` instead.  The key rule to preserve:
        *absence of an optimization finding must never automatically mean
        insufficient evidence, nor must missing evidence become zero.*
        """

        if findings:
            return ("finding_generated", None)

        return ("no_optimization_match", None)
