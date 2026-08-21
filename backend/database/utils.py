"""
Database serialization and query utilities.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func


def json_dumps(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, default=str)


def json_loads(value: str | None) -> Any:
    if value is None:
        return None
    return json.loads(value)


def month_expression(start_date_column):
    """SQLite-safe YYYY-MM grouping for date columns."""
    return func.strftime("%Y-%m", start_date_column)