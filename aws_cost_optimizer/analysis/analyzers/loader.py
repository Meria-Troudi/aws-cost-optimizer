"""
Catalog-driven analyzer loading.

Analyzers used to be registered by a hand-maintained import list in
analyzers/__init__.py. That list is not checked against anything, so
omitting an entry silently disables a whole analyzer: the Aurora
analyzer sat fully implemented and never executed, and the only
symptom was six recommendation routes that nothing emitted.

Collectors do not have this failure mode -- collection/registry.py
::load_collectors() resolves modules from the resource catalog. This
mirrors that approach for analyzers, so adding a catalog entry is the
single action required to wire up both halves of a resource type.

Layout
------
Analyzer modules mirror collectors:

    analyzers/{domain}/{subdomain}/{file}.py
    analyzers/{domain}/{file}.py            (no subdomain)

with two documented deviations, both resolved by trying candidates in
order rather than by special-casing:

  * some modules are named after the resource rather than the
    collector key (rds -> instance.py, eks -> cluster.py), handled by
    _ANALYZER_FILE_OVERRIDES;

  * the QuickSight analyzer is analytics/quicksight.py while its
    collector is collectors/analytics/quicksight/quicksight.py -- the
    analyzer side has no subdomain directory. Both shapes are tried.

A catalog entry with no analyzer module on disk is skipped, not an
error: collectors and analyzers are allowed to land separately.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Dict, Iterator

from aws_cost_optimizer.planner.resource_catalog import ResourceCatalog

# Analyzer module file names that differ from the collector key.
# Mirrors _COLLECTOR_FILE_OVERRIDES in collection/registry.py; kept
# separate because the two trees are permitted to diverge (they
# already do for QuickSight) and cross-importing would couple the
# analysis layer to the collection layer for no benefit.
_ANALYZER_FILE_OVERRIDES: Dict[str, str] = {
    "rds": "instance",
    "aurora_cluster": "aurora",
    "eks": "cluster",
    "elb": "load_balancer",
}

# Import failures, keyed by collector key. Populated by
# load_analyzers() and surfaced by the registry contract test so a
# broken analyzer module is loud rather than silently absent.
IMPORT_ERRORS: Dict[str, str] = {}

_PACKAGE_ROOT = Path(__file__).parent


def _analyzer_file_name(collector_key: str) -> str:
    return _ANALYZER_FILE_OVERRIDES.get(
        collector_key,
        collector_key,
    )


def _candidate_paths(
    domain: str | None,
    subdomain: str | None,
    collector_key: str,
) -> Iterator[Path]:
    """Yield possible analyzer module paths, most specific first."""

    if not domain:
        return

    file_name = _analyzer_file_name(collector_key)

    if subdomain:
        yield _PACKAGE_ROOT / domain / subdomain / f"{file_name}.py"

    # Fallback covers both the no-subdomain catalog entries and the
    # QuickSight case, where the analyzer skips the subdomain level
    # that the collector uses.
    yield _PACKAGE_ROOT / domain / f"{file_name}.py"


def _module_path(item: Dict[str, Any], catalog_key: str) -> Path | None:
    """First existing analyzer module for a catalog entry, if any."""

    collector_key = item.get("collector", {}).get("key", catalog_key)

    for candidate in _candidate_paths(
        item.get("domain"),
        item.get("subdomain"),
        collector_key,
    ):
        if candidate.exists():
            return candidate

    return None


def _enabled_catalog_items() -> Iterator[tuple[str, Dict[str, Any]]]:
    catalog = ResourceCatalog()

    for catalog_key, item in catalog.items.items():
        if item.get("rules", {}).get("enabled") is False:
            continue

        yield catalog_key, item


def analyzer_modules() -> Dict[str, Path]:
    """Map collector key -> analyzer module path, for entries that have one."""

    modules: Dict[str, Path] = {}

    for catalog_key, item in _enabled_catalog_items():
        path = _module_path(item, catalog_key)

        if path is None:
            continue

        collector_key = item.get("collector", {}).get("key", catalog_key)
        modules[collector_key] = path

    return modules


def load_analyzers() -> None:
    """Import every analyzer module the catalog points at.

    Importing runs each module's @register decorator. Import errors are
    recorded rather than raised so one broken analyzer cannot take down
    the whole analysis layer -- the contract test asserts the map is
    empty.
    """

    for collector_key, path in analyzer_modules().items():
        relative = (
            path.relative_to(_PACKAGE_ROOT).with_suffix("").as_posix().replace("/", ".")
        )

        try:
            importlib.import_module(f"{__package__}.{relative}")
        except Exception as exc:  # noqa: BLE001 - recorded, then asserted on
            IMPORT_ERRORS[collector_key] = f"{type(exc).__name__}: {exc}"
