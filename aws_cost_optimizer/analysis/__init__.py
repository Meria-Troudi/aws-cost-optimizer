"""
Analysis module.

Provides finding-based optimization detection.
"""

from .engine import AnalysisEngine
from .aggregation import FindingAggregator
from .finding import Finding

__all__ = [
    "AnalysisEngine",
    "FindingAggregator",
    "Finding",
]