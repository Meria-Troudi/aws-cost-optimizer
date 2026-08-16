"""
Recommendation subsystem.

Findings are produced by the analysis subsystem.

Recommendations are composed from those findings.

LLM integration is intentionally separate and can be added later.
"""

from .engine import RecommendationEngine
from .model import Recommendation
from .optimization import OptimizationPipeline
__all__ = [
    "RecommendationEngine",
    "Recommendation","OptimizationPipeline",
]

 