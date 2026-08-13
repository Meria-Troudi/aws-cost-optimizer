"""
Collector registry
"""
from __future__ import annotations

import importlib
from pathlib import Path

from aws_cost_optimizer.planner.resource_catalog import ResourceCatalog

COLLECTORS: dict[str, type] = {}
IMPORT_ERRORS: dict[str, str] = {}


def register(cls):
    COLLECTORS[cls.key] = cls
    return cls


def _collector_module_path(collector_name: str) -> Path:
    return (
        Path(__file__).parent
        / "services"
        / f"{collector_name}.py"
    )


def load_collectors() -> None:
    catalog = ResourceCatalog()

    for key, item in catalog.items.items():
        rules_config = item.get("rules", {})
        if rules_config.get("enabled") is False:
            continue

        collector_config = item.get("collector", {})
        collector_name = collector_config.get("key", key)

        module_path = _collector_module_path(collector_name)
        if not module_path.exists():
            continue

        try:
            importlib.import_module(
                f"collectors.services.{collector_name}"
            )
        except ImportError as exc:
            IMPORT_ERRORS[collector_name] = str(exc)


def get_collector(name: str):
    return COLLECTORS.get(name)


def registered_collector_keys() -> list[str]:
    return sorted(COLLECTORS.keys())


def catalog_collector_keys() -> list[str]:
    catalog = ResourceCatalog()
    keys: list[str] = []

    for key, item in catalog.items.items():
        if item.get("rules", {}).get("enabled") is False:
            continue

        collector_config = item.get("collector", {})
        collector_name = collector_config.get("key", key)

        if not _collector_module_path(collector_name).exists():
            continue

        keys.append(collector_name)

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
