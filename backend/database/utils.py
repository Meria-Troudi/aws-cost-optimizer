"""
Database JSON serialization utilities.
"""

from __future__ import annotations

import json
from typing import Any


def json_dumps(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, default=str)


def json_loads(value: str | None) -> Any:
    if value is None:
        return None
    return json.loads(value)