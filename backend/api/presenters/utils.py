"""
Common presenter utilities.

Presenter functions receive values that may come from:
- SQLAlchemy Text columns containing JSON strings
- already-decoded dict/list values
- None
"""

from __future__ import annotations

import json
from typing import Any


def parse_json_field(
    value: Any,
    default: Any = None,
) -> Any:


    if value is None:
        return default

    if isinstance(value, (dict, list, tuple, int, float, bool)):
        return value

    if not isinstance(value, str):
        return default

    value = value.strip()

    if not value:
        return default

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default


def parse_json_object(
    value: Any,
) -> dict[str, Any]:
    """
    Return a JSON field as an object.
    """
    parsed = parse_json_field(value, default={})

    if isinstance(parsed, dict):
        return parsed

    return {}


def parse_json_list(
    value: Any,
) -> list[Any]:

    parsed = parse_json_field(value, default=[])

    if isinstance(parsed, list):
        return parsed

    return []