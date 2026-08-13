"""
FindingStore has been removed.
"""

from __future__ import annotations

from typing import Any


class FindingStore:

    def __init__(self) -> None:
        raise NotImplementedError(
            "FindingStore has been removed. "
            "Use FindingAggregator for aggregation."
        )