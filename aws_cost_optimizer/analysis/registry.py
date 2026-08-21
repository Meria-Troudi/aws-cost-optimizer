"""
Analyzer registry.

"""

from __future__ import annotations

from .base import Analyzer


_ANALYZERS: list[
    type[Analyzer] | Analyzer
] = []


def register(
    analyzer_class: type[Analyzer],
) -> type[Analyzer]:

    
    if analyzer_class not in _ANALYZERS:

        _ANALYZERS.append(
            analyzer_class
        )

    return analyzer_class


def get_analyzers() -> list[Analyzer]:

    instances: list[Analyzer] = []

    seen_types: set[type] = set()

    for registered in _ANALYZERS:

        if isinstance(
            registered,
            type,
        ):

            analyzer_type = registered

            if analyzer_type in seen_types:
                continue

            seen_types.add(
                analyzer_type
            )

            instances.append(
                analyzer_type()
            )

            continue

        analyzer_type = type(
            registered
        )

        if analyzer_type in seen_types:
            continue

        seen_types.add(
            analyzer_type
        )

        instances.append(
            registered
        )

    return instances