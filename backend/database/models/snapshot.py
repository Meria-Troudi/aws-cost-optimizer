"""
Resource snapshot model - tracks resource state over time.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship
from datetime import datetime

from backend.database.base import Base


class ResourceSnapshot(Base):

    __tablename__ = "resource_snapshots"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    resource_id = Column(
        Integer,
        ForeignKey("resources.id"),
        nullable=False
    )

    scan_run_id = Column(
        Integer,
        ForeignKey("scan_runs.id"),
        nullable=False
    )

    source_api = Column(
        String,
        nullable=False
    )

    configuration = Column(
        JSON,
        nullable=False
    )

    raw_response = Column(
        JSON,
        nullable=False
    )

    collected_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # Relationships
    resource = relationship(
        "Resource",
        back_populates="snapshots"
    )

    scan_run = relationship(
        "ScanRun",
        back_populates="resource_snapshots"
    )

    __table_args__ = (
        Index(
            "idx_snapshot_resource_scan",
            "resource_id",
            "scan_run_id"
        ),
        Index(
            "idx_snapshot_scan_run",
            "scan_run_id"
        ),
    )