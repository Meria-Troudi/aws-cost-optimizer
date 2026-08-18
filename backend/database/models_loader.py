"""
Initialize the application database.
"""

from backend.database.base import Base
from backend.database.connection import engine

# IMPORTANT:
# Register every ORM model before create_all().
from backend.database.models import (
    scan_run,
    cost_record,
    resource,
    snapshot,
    metric,
    finding,
    recommendation,
    collection_plan,
)


def init_db() -> None:
    Base.metadata.create_all(
        bind=engine,
    )

    # Lightweight idempotent migrations for SQLite.
    # Kept here so existing databases gain new columns
    # without requiring a destructive rebuild.
    try:
        with engine.connect() as conn:
            columns = [
                row[1]
                for row in conn.exec_driver_sql(
                    "PRAGMA table_info(scan_runs)"
                )
            ]

            if (
                "progress_percent"
                not in columns
            ):
                conn.exec_driver_sql(
                    "ALTER TABLE scan_runs "
                    "ADD COLUMN progress_percent "
                    "FLOAT NOT NULL DEFAULT 0.0"
                )

            conn.commit()
    except Exception:
        # Migration is best-effort; the model already
        # carries a server-side default for new rows.
        pass


if __name__ == "__main__":
    init_db()