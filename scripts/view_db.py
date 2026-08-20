"""
Database inspection utility.

Usage:
    py scripts/view_db.py                 # list all tables
    py scripts/view_db.py scan_runs       # view a specific table
    py scripts/view_db.py scan_runs --limit 5
    py scripts/view_db.py --all           # dump all tables
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "aws_optimizer.db"


def list_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [r[1] for r in rows]


def print_table(
    conn: sqlite3.Connection,
    table: str,
    limit: int = 20,
    where: str | None = None,
):
    cols = table_columns(conn, table)
    if not cols:
        print(f"Table '{table}' not found.")
        return

    sql = f"SELECT * FROM {table}"
    if where:
        sql += f" WHERE {where}"
    sql += f" LIMIT {limit}"

    rows = conn.execute(sql).fetchall()

    print(f"\n{'=' * 80}")
    print(f"TABLE: {table}  ({len(rows)} rows shown)")
    print(f"{'=' * 80}")

    if not rows:
        print("  (empty)")
        return

    # Print column headers
    print(" | ".join(cols))
    print("-" * 80)

    for row in rows:
        values = []
        for v in row:
            s = str(v)
            if len(s) > 60:
                s = s[:57] + "..."
            values.append(s)
        print(" | ".join(values))


def main():
    args = sys.argv[1:]
    table = None
    limit = 20
    where = None
    dump_all = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--limit":
            i += 1
            limit = int(args[i])
        elif arg == "--where":
            i += 1
            where = args[i]
        elif arg == "--all":
            dump_all = True
        elif arg.startswith("--"):
            print(f"Unknown option: {arg}")
            sys.exit(1)
        else:
            table = arg
        i += 1

    if not DB_PATH.exists():
        print(f"Database not found: {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    tables = list_tables(conn)
    print(f"Database: {DB_PATH}")
    print(f"Tables ({len(tables)}): {', '.join(tables)}")

    if dump_all:
        for t in tables:
            print_table(conn, t, limit=limit, where=where)
    elif table:
        print_table(conn, table, limit=limit, where=where)
    else:
        # Show row counts for all tables
        print("\nRow counts:")
        for t in tables:
            count = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"  {t}: {count}")

    conn.close()


if __name__ == "__main__":
    main()