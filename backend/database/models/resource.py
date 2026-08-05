"""
Resource model - stores discovered AWS resources.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    Index,
    ForeignKey,
)
from sqlalchemy.orm import relationship

from backend.database.base import Base


class Resource(Base):
    __tablename__ = "resources"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    scan_run_id = Column(
        Integer,
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    # AWS resource IDs are only unique within an account.  Keep the account on
    # the resource itself so repository lookups can safely deduplicate scans
    # from multiple AWS accounts.
    account_id = Column(
        String,
        nullable=True,
        index=True,
    )

    aws_resource_id = Column(
        String,
        nullable=False,
        index=True
    )

    service = Column(
        String,
        nullable=False,
        index=True
    )

    resource_type = Column(
        String,
        nullable=False,
        index=True
    )

    region = Column(
        String,
        nullable=False,
        index=True
    )

    availability_zone = Column(
        String,
        nullable=True
    )

    name = Column(
        String,
        nullable=True
    )

    state = Column(
        String,
        nullable=True
    )

    tags = Column(
        JSON,
        nullable=True
    )

    attributes = Column(
        JSON,
        nullable=True
    )

    created_at = Column(
        DateTime,
        nullable=True
    )

    # Relationships
    snapshots = relationship(
        "ResourceSnapshot",
        back_populates="resource",
        cascade="all, delete-orphan"
    )

    metrics = relationship(
        "Metric",
        back_populates="resource",
        cascade="all, delete-orphan"
    )

    findings = relationship(
        "Finding",
        back_populates="resource"
    )
