"""
Collector registry
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Dict

from aws_cost_optimizer.planner.resource_catalog import ResourceCatalog

COLLECTORS: dict[str, type] = {}
IMPORT_ERRORS: dict[str, str] = {}
_COLLECTOR_FILE_OVERRIDES: Dict[str, str] = {
    "rds": "instance",
    "aurora_cluster": "aurora",
    "eks": "cluster",
    "elb": "load_balancer",
}


def register(cls):
    key = getattr(cls, "key", None)

    if not key:
        raise ValueError(f"Collector {cls.__name__!r} cannot register without a 'key'.")

    existing = COLLECTORS.get(key)

    if existing is not None and existing is not cls:
        # A silent overwrite would hide one of the two implementations
        # for the entire scan. Fail loudly instead.
        raise ValueError(
            f"Duplicate collector registration for key {key!r}: "
            f"{existing.__name__!r} is already registered; "
            f"{cls.__name__!r} attempted to replace it."
        )

    COLLECTORS[key] = cls
    return cls


def _collector_file_name(collector_key: str) -> str:
    return _COLLECTOR_FILE_OVERRIDES.get(
        collector_key,
        collector_key,
    )


def _collector_module_path(
    domain: str,
    subdomain: str | None,
    collector_key: str,
) -> Path:
    file_name = _collector_file_name(collector_key)
    parts = ["collectors", domain]

    if subdomain:
        parts.append(subdomain)

    parts.append(f"{file_name}.py")

    return Path(__file__).parent / Path(*parts)


def load_collectors() -> None:
    catalog = ResourceCatalog()

    for catalog_key, item in catalog.items.items():
        rules_config = item.get("rules", {})
        if rules_config.get("enabled") is False:
            continue

        collector_config = item.get("collector", {})
        collector_key = collector_config.get("key", catalog_key)

        module_path = _collector_module_path(
            domain=item.get("domain"),
            subdomain=item.get("subdomain"),
            collector_key=collector_key,
        )
        if not module_path.exists():
            continue

        try:
            relative = (
                Path(module_path)
                .relative_to(Path(__file__).parent)
                .with_suffix("")
                .as_posix()
                .replace("/", ".")
            )
            importlib.import_module(f"collection.{relative}")
        except Exception as exc:
            # Import failures (ImportError, SyntaxError, AttributeError,
            # ...) become registry diagnostics via missing_collectors()/
            # validate_collector_registry() -- a broken collector module
            # must never silently disappear from validation, but it also
            # must not abort loading of every other collector.
            IMPORT_ERRORS[collector_key] = f"{type(exc).__name__}: {exc}"


def get_collector(name: str):
    return COLLECTORS.get(name)


def catalog_collector_keys() -> list[str]:
    catalog = ResourceCatalog()
    keys: list[str] = []

    for catalog_key, item in catalog.items.items():
        if item.get("rules", {}).get("enabled") is False:
            continue

        collector_config = item.get("collector", {})
        collector_key = collector_config.get("key", catalog_key)

        module_path = _collector_module_path(
            domain=item.get("domain"),
            subdomain=item.get("subdomain"),
            collector_key=collector_key,
        )

        if not module_path.exists():
            continue

        keys.append(collector_key)

    return sorted(set(keys))


def missing_collectors() -> list[str]:
    required = set(catalog_collector_keys())
    registered = set(COLLECTORS.keys())
    return sorted(required - registered)


def validate_collector_registry(*, strict: bool = False) -> list[str]:
    missing = missing_collectors()

    if missing or IMPORT_ERRORS:
        print("\nCOLLECTOR REGISTRY VALIDATION")
        print("-" * 40)

        for collector_name in catalog_collector_keys():
            if collector_name in COLLECTORS:
                print(f"  ok  {collector_name}")
            else:
                detail = IMPORT_ERRORS.get(
                    collector_name,
                    "module imported but @register did not run",
                )
                print(f"  MISSING  {collector_name}: {detail}")

        if strict and missing:
            raise RuntimeError(
                "Collector registry validation failed. "
                f"Missing collectors: {', '.join(missing)}"
            )

    return missing


# Removed: _catalog_collector_entry() declared a Dict return type but
# returned a tuple, and had no callers.
