"""
Contract tests for analyzer registration.

Analyzers were previously registered by a hand-maintained import list
in analyzers/__init__.py. Nothing checked that list against the
resource catalog, so omitting an entry silently disabled an entire
analyzer -- the Aurora analyzer was ~2,300 implemented lines that never
ran, and the only visible symptom was six recommendation routes with no
emitter.

Registration is now catalog-driven (analyzers/loader.py), mirroring
collection/registry.py::load_collectors(). These tests are the wiring
that makes the failure mode loud: they are the analyzer-side
counterpart to test_collector_contracts.py.
"""

from __future__ import annotations

import inspect

import analysis.analyzers as analyzers
from analysis.registry import get_analyzers, registered_analyzer_classes


def test_no_analyzer_module_failed_to_import():
    """A broken analyzer module must not be silently skipped.

    load_analyzers() records import errors instead of raising, so that
    one bad module cannot take down the whole analysis layer at
    startup. That is only safe if something asserts the map is empty.

    This is what would have caught Aurora's `from ....base` import (one
    level too deep for its directory), which raised ImportError the
    moment it was first imported.
    """

    assert analyzers.IMPORT_ERRORS == {}


def test_every_catalog_analyzer_module_is_registered():
    """Every analyzer module the catalog resolves must register a class.

    Covers the case where a module imports cleanly but its @register
    decorator never runs -- the module is present, the import succeeds,
    and the analyzer is still absent at runtime.
    """

    modules = analyzers.analyzer_modules()

    assert modules, "catalog resolved no analyzer modules at all"

    registered_files = {
        inspect.getfile(analyzer_class)
        for analyzer_class in registered_analyzer_classes()
    }

    unregistered = sorted(
        collector_key
        for collector_key, path in modules.items()
        if str(path) not in registered_files
    )

    assert not unregistered, (
        "catalog entries whose analyzer module exists but registered "
        f"no analyzer: {unregistered}"
    )


def test_registered_analyzers_are_exported_by_name():
    """`from analysis.analyzers import SomeAnalyzer` must keep working.

    The package binds these names dynamically from the registry rather
    than from a static import list. That is what stops the list
    drifting, but it also means nothing would notice if the re-export
    loop broke -- hence this test.
    """

    for analyzer_class in registered_analyzer_classes():
        assert hasattr(analyzers, analyzer_class.__name__)
        assert getattr(analyzers, analyzer_class.__name__) is analyzer_class


def test_analyzer_names_are_unique():
    """Two analyzers sharing a name makes registry lookups ambiguous."""

    names = [analyzer.name for analyzer in get_analyzers()]

    assert len(names) == len(set(names)), f"duplicate analyzer names: {sorted(names)}"
