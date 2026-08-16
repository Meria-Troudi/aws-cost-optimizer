"""
AWS Cost Optimizer analysis package.
"""

from __future__ import annotations

__all__ = [
    "AnalysisEngine",
    "AnalysisContext",
    "Analyzer",
    "Finding",
    "FindingAggregator",
]


def __getattr__(name: str):


    if name == "AnalysisEngine":
        from .engine import AnalysisEngine

        return AnalysisEngine

    if name == "AnalysisContext":
        from .context import AnalysisContext

        return AnalysisContext

    if name == "Analyzer":
        from .base import Analyzer

        return Analyzer

    if name == "Finding":
        from .finding import Finding

        return Finding

    if name == "FindingAggregator":
        from .aggregation import FindingAggregator

        return FindingAggregator

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )