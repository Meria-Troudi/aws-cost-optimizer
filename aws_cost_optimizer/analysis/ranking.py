"""
Shared severity/confidence/priority ordering.

Single source of truth for sort-rank mappings used across the
analysis engine, recommendation engine, and backend repositories --
severity, confidence, and priority all share the same underlying
vocabulary (critical/high/medium/low[/info]), so one mapping covers
all three call sites instead of being redefined per module.
"""

from __future__ import annotations


SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

CONFIDENCE_RANK: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
}
