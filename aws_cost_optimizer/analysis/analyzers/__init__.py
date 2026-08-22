"""
Analysis analyzers.

Importing this package registers every analyzer via its @register
decorator. Modules are resolved from the resource catalog by
loader.load_analyzers() rather than from a hand-maintained import
list -- see loader.py for why (the previous list silently disabled the
Aurora analyzer entirely).

Analyzer classes are re-exported at package level, so
`from analysis.analyzers import RDSAnalyzer` keeps working. Those
names are bound dynamically from the registry, which means they follow
the catalog automatically and cannot drift out of sync with it. The
trade-off is that static analysis will not see them; use
analysis.registry.get_analyzers() when you want the live set rather
than a specific class.
"""

from __future__ import annotations

from ..registry import registered_analyzer_classes
from .loader import IMPORT_ERRORS, analyzer_modules, load_analyzers

load_analyzers()

# Bind each registered analyzer class as a package-level name.
_EXPORTED: list[str] = []

for _analyzer_class in registered_analyzer_classes():
    globals()[_analyzer_class.__name__] = _analyzer_class
    _EXPORTED.append(_analyzer_class.__name__)

__all__ = [
    "IMPORT_ERRORS",
    "analyzer_modules",
    "load_analyzers",
    *sorted(_EXPORTED),
]
