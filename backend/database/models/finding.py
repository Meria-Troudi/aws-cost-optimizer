"""
Finding model - analysis result. This is NOT the recommendation.
It is the detected problem.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    JSON,
    ForeignKey,
    DateTime,
    Index,
)
from sqlalchemy.orm import relationship
from datetime import datetime

from backend.database.base import Base


class Finding(Base):

    __tablename__ = "findings"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    scan_run_id = Column(
        Integer,
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True
    )

    resource_id = Column(
        Integer,
        ForeignKey("resources.id"),
        nullable=True
    )

    resource_type = Column(
        String,
        nullable=True,
        index=True,
    )

    service = Column(
        String,
        nullable=True,
        index=True
    )

    finding_type = Column(
        String,
        nullable=False,
        index=True
    )

    title = Column(
        String,
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    severity = Column(
        String,
        nullable=False
    )

    evidence = Column(
        JSON,
        nullable=False
    )

    status = Column(
        String,
        default="open"  # open, reviewed, ignored
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    # Relationships
    scan_run = relationship("ScanRun", back_populates="findings")
    resource = relationship("Resource", back_populates="findings")
    recommendations = relationship(
        "Recommendation",
        back_populates="finding",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_finding_scan_run", "scan_run_id"),
        Index("idx_finding_service", "service"),
    )
