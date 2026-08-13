"""
Analyzer registry.
"""

from __future__ import annotations

from .base import Analyzer

_ANALYZERS: list[Analyzer] = []


def register(analyzer_class: type[Analyzer]) -> type[Analyzer]:
    _ANALYZERS.append(analyzer_class)
    return analyzer_class


def get_analyzers() -> list[Analyzer]:
    instances = []
    for analyzer in _ANALYZERS:
        if isinstance(analyzer, type):
            instances.append(analyzer())
        else:
            instances.append(analyzer)
    return instances
