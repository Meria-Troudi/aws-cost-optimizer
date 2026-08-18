from __future__ import annotations

from collections.abc import Generator

from backend.database.connection import SessionLocal


def get_db() -> Generator:
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()