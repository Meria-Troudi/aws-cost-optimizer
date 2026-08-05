"""
CollectionPlan model - the planner decides what investigation is needed.
This is the intelligence layer before AWS API calls.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    ForeignKey,
    DateTime,
    Index,
)
from sqlalchemy.orm import relationship
from datetime import datetime

from backend.database.base import Base


class CollectionPlan(Base):
    __tablename__ = "collection_plans"

    id = Column(Integer, primary_key=True, autoincrement=True)

    scan_run_id = Column(
        Integer,
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    service = Column(String, nullable=False, index=True)
    region = Column(String, nullable=True, index=True)
    usage_type = Column(String, nullable=False, index=True)

    resource_type = Column(String, nullable=True)
    collector_name = Column(String, nullable=True)

    priority = Column(String, nullable=True)  # high, medium, low
    cost_context = Column(Float, nullable=True)
    status = Column(String, default="planned")  # planned, running, completed

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    # Relationships
    scan_run = relationship("ScanRun", back_populates="collection_plans")

    __table_args__ = (
        Index(
            "idx_collection_plan_scan_service_region_usage",
            "scan_run_id",
            "service",
            "region",
            "usage_type",
            unique=True,
        ),
    )