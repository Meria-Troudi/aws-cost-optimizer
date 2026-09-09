from __future__ import annotations

import os
from collections.abc import Generator

from fastapi import Header, HTTPException, status

from backend.database.connection import SessionLocal


def get_db() -> Generator:
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def require_api_key(
    x_api_key: str | None = Header(default=None),
) -> None:
    """
    Gate every non-health route behind the ``API_KEY`` env var.

    Auth is opt-in: with no ``API_KEY`` set (the default for local/dev
    use, matching the README's zero-config quick start), every request
    is allowed. Setting ``API_KEY`` turns this into a hard requirement
    -- every request must send a matching ``X-API-Key`` header, or it
    is rejected with 401. This is intentionally simple (a single shared
    key, not per-user accounts) -- enough to keep a deployed instance
    from being fully open to the internet, not a full auth system.
    """

    expected = os.getenv("API_KEY")

    if not expected:
        return

    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key.",
        )
