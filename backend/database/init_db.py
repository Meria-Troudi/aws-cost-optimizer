"""
Initialize the database - creates all tables.

"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database.base import Base
from sqlalchemy import inspect, text

from backend.database.connection import engine
from backend.database.models import (
    ScanRun,
    CostRecord,
    CollectionPlan,
    Resource,
    ResourceSnapshot,
    Metric,
    Finding,
    Recommendation,
)


def _upgrade_resources_table():
    inspector = inspect(engine)
    if "resources" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("resources")}
    if "account_id" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE resources ADD COLUMN account_id VARCHAR"))
            connection.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_resources_account_id "
                "ON resources (account_id)"
            ))
        print("Upgraded resources table: added account_id")


def _upgrade_findings_table():
    inspector = inspect(engine)
    if "findings" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("findings")}
    if "resource_type" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE findings ADD COLUMN resource_type VARCHAR"))
            connection.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_findings_resource_type "
                "ON findings (resource_type)"
            ))
        print("Upgraded findings table: added resource_type")


def init_database():
    _ = ScanRun
    _ = CostRecord
    _ = CollectionPlan
    _ = Resource
    _ = ResourceSnapshot
    _ = Metric
    _ = Finding
    _ = Recommendation

    # Create all tables
    Base.metadata.create_all(bind=engine)
    _upgrade_resources_table()
    _upgrade_findings_table()

    print("Database initialized successfully")
    print("\nTables created:")
    for table in Base.metadata.sorted_tables:
        print(f"  - {table.name}")


if __name__ == "__main__":
    init_database()
