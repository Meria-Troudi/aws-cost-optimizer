"""Check cost records for a specific scan and compare with summary."""

import sqlite3
import sys

DB_PATH = "aws_optimizer.db"


def main():
    scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else 14

    conn = sqlite3.connect(DB_PATH)

    # Scan info
    scan = conn.execute(
        "SELECT id, start_date, end_date, region FROM scan_runs WHERE id=?",
        (scan_id,),
    ).fetchone()
    if not scan:
        print(f"Scan {scan_id} not found.")
        return

    print(f"Scan {scan_id}: {scan[1]} -> {scan[2]} region={scan[3]!r}")

    # Total cost
    total = conn.execute(
        "SELECT SUM(amount) FROM cost_records WHERE scan_run_id=?",
        (scan_id,),
    ).fetchone()[0]
    print(f"Total cost: ${total:.2f}")

    # By month
    print("\nBy month:")
    rows = conn.execute(
        """
        SELECT substr(start_date, 1, 7) as month, SUM(amount) as total
        FROM cost_records WHERE scan_run_id=?
        GROUP BY month ORDER BY month
        """,
        (scan_id,),
    ).fetchall()
    for r in rows:
        print(f"  {r[0]}: ${r[1]:.2f}")

    # Regions
    regions = conn.execute(
        "SELECT DISTINCT region FROM cost_records WHERE scan_run_id=?",
        (scan_id,),
    ).fetchall()
    print(f"\nRegions: {[r[0] for r in regions]}")

    # Services
    services = conn.execute(
        "SELECT DISTINCT service FROM cost_records WHERE scan_run_id=?",
        (scan_id,),
    ).fetchall()
    print(f"Services ({len(services)}):")
    for s in services:
        svc_total = conn.execute(
            "SELECT SUM(amount) FROM cost_records WHERE scan_run_id=? AND service=?",
            (scan_id, s[0]),
        ).fetchone()[0]
        print(f"  {s[0]}: ${svc_total:.2f}")

    conn.close()


if __name__ == "__main__":
    main()