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


def _column_default_sql(column) -> str:
    """
    Build the DEFAULT clause for an added column.

    SQLite cannot add a NOT NULL column without a default, so a
    non-nullable column with no declared default gets a type-appropriate
    zero value rather than being silently added as nullable.
    """

    server_default = getattr(
        column,
        "server_default",
        None,
    )

    if server_default is not None:

        arg = getattr(
            server_default,
            "arg",
            None,
        )

        if arg is not None:
            return f" DEFAULT {arg}"

    default = getattr(column, "default", None)

    if default is not None and getattr(
        default,
        "is_scalar",
        False,
    ):
        value = default.arg

        if isinstance(value, str):
            escaped = value.replace("'", "''")
            return f" DEFAULT '{escaped}'"

        if isinstance(value, bool):
            return f" DEFAULT {1 if value else 0}"

        if isinstance(value, (int, float)):
            return f" DEFAULT {value}"

    if not column.nullable:

        affinity = str(column.type).upper()

        if any(
            token in affinity
            for token in ("CHAR", "TEXT", "CLOB")
        ):
            return " DEFAULT ''"

        return " DEFAULT 0"

    return ""


def _sync_sqlite_columns() -> list[str]:
    """
    Add columns present on the ORM models but missing from an existing
    SQLite table.

    create_all() creates missing *tables* but never alters existing
    ones, so a database created before a column was added keeps failing
    with "no such column" on every read. Previously this was a short
    hand-maintained list of ALTER statements, which drifted: roughly
    nineteen columns across findings/recommendations were added to the
    models with no matching migration.

    Deriving the diff from the model metadata instead means any future
    column is picked up automatically.

    Returns the list of applied "table.column" migrations.
    """

    applied: list[str] = []

    with engine.connect() as conn:

        for table_name, table in Base.metadata.tables.items():

            existing = {
                row[1]
                for row in conn.exec_driver_sql(
                    f"PRAGMA table_info({table_name})"
                )
            }

            # Table absent entirely -> create_all() just made it.
            if not existing:
                continue

            for column in table.columns:

                if column.name in existing:
                    continue

                column_type = column.type.compile(
                    dialect=engine.dialect
                )

                nullability = (
                    ""
                    if column.nullable
                    else " NOT NULL"
                )

                statement = (
                    f"ALTER TABLE {table_name} "
                    f"ADD COLUMN {column.name} "
                    f"{column_type}"
                    f"{nullability}"
                    f"{_column_default_sql(column)}"
                )

                conn.exec_driver_sql(statement)

                applied.append(
                    f"{table_name}.{column.name}"
                )

        conn.commit()

    return applied


def init_db() -> None:
    Base.metadata.create_all(
        bind=engine,
    )

    try:
        applied = _sync_sqlite_columns()

    except Exception as exc:
        # Never silent: an unmigrated database fails later with an
        # opaque "no such column", far from the real cause.
        print(
            "[init_db] WARNING: schema migration failed -- the "
            "database may be missing columns the models expect. "
            f"{type(exc).__name__}: {exc}"
        )
        return

    if applied:
        print(
            f"[init_db] Added {len(applied)} missing column(s): "
            + ", ".join(applied)
        )


if __name__ == "__main__":
    init_db()