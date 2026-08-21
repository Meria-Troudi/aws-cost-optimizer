"""
Shared severity/confidence/priority ordering.

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
