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