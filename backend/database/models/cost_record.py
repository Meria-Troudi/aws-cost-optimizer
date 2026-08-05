"""
CostRecord model - detailed Cost Explorer data storage.
This is the main fact table for all cost analysis.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Date,
    DateTime,
    ForeignKey,
)

from backend.database.base import Base
from datetime import datetime


class CostRecord(Base):
    __tablename__ = "cost_records"

    id = Column(
        Integer,
        primary_key=True
    )

    scan_run_id = Column(
        Integer,
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    # Time period
    start_date = Column(
        Date,
        nullable=False
    )

    end_date = Column(
        Date,
        nullable=False
    )

    # Cost Explorer dimensions
    service = Column(
        String,
        nullable=False,
        index=True
    )

    usage_type = Column(
        String,
        nullable=False,
        index=True
    )

    operation = Column(
        String,
        nullable=True
    )

    region = Column(
        String,
        nullable=True,
        index=True
    )

    availability_zone = Column(
        String,
        nullable=True
    )

    linked_account = Column(
        String,
        nullable=True
    )

    # Cost metrics
    amount = Column(
        Float,
        nullable=False
    )

    usage_quantity = Column(
        Float,
        nullable=True
    )

    unit = Column(
        String,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )
