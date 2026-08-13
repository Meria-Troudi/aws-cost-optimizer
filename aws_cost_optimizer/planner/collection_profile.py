"""
Collection profile loader.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class CollectionProfile:

    REQUIRED_SECTIONS = {
        "identity",
        "configuration",
        "relationships",
        "observations",
        "topology",
    }

    ALIASES = {
        "elastic_ip": "public_ipv4",
    }

    def __init__(self) -> None:

        path = Path(__file__).parent / "collection_profiles.yaml"

        if not path.exists():
            raise FileNotFoundError(
                f"Collection profile not found: {path}"
            )

        with open(path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            raise ValueError(
                "collection_profiles.yaml must contain a mapping"
            )

        self.profiles: dict[str, dict[str, Any]] = data

        self._validate()

    def _validate(self) -> None:
        for resource_type, profile in self.profiles.items():
            if not isinstance(profile, dict):
                raise ValueError(
                    f"Invalid profile for '{resource_type}'"
                )

            for section in self.REQUIRED_SECTIONS:

                if section not in profile:
                    continue

                value = profile[section]

                if not isinstance(value, dict):
                    raise ValueError(
                        f"{resource_type}.{section} "
                        f"must be a mapping"
                    )

                if "enabled" in value and not isinstance(
                    value["enabled"],
                    bool,
                ):
                    raise ValueError(
                        f"{resource_type}.{section}.enabled "
                        f"must be boolean"
                    )

    def get(self, resource_type: str) -> dict[str, Any]:

        resource_type = self.ALIASES.get(
            resource_type,
            resource_type,
        )

        return self.profiles.get(
            resource_type,
            {},
        )

    def describe(self, resource_type: str) -> dict[str, Any]:


        profile = self.get(resource_type)

        if not profile:
            return {}

        return {
            section: bool(
                isinstance(config, dict)
                and config.get("enabled", False)
            )
            for section, config in profile.items()
            if isinstance(config, dict)
        }

    def all(self) -> dict[str, dict[str, Any]]:
        return self.profiles