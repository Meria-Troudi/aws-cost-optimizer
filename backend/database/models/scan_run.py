"""
ScanRun model - represents one analysis execution.
Everything created during analysis is linked to a scan.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Date,
    JSON,
    Float,
    DateTime,
)
from sqlalchemy.orm import relationship
from datetime import datetime

from backend.database.base import Base


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    account_id = Column(
        String,
        index=True
    )

    start_date = Column(
        Date,
        nullable=False
    )

    end_date = Column(
        Date,
        nullable=False
    )

    region = Column(
        String,
        nullable=True
    )

    cost_threshold = Column(
        Float,
        default=100.0
    )

    tag_filter = Column(
        JSON,
        nullable=True
    )

    status = Column(
        String,
        default="running",
        index=True
    )

    collector_version = Column(
        String,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    finished_at = Column(
        DateTime,
        nullable=True
    )

    # Relationships - pipeline stages
    collection_plans = relationship(
        "CollectionPlan",
        back_populates="scan_run",
        cascade="all, delete-orphan"
    )

    resource_snapshots = relationship(
        "ResourceSnapshot",
        back_populates="scan_run"
    )

    metrics = relationship(
        "Metric",
        back_populates="scan_run"
    )

    findings = relationship(
        "Finding",
        back_populates="scan_run",
        cascade="all, delete-orphan"
    )
