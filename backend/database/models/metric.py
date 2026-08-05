from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship

from backend.database.base import Base


class Metric(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True)

    resource_id = Column(
        Integer,
        ForeignKey("resources.id"),
        nullable=False,
        index=True,
    )

    scan_run_id = Column(
        Integer,
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    namespace = Column(String)
    metric_name = Column(String)

    statistic = Column(String)
    period = Column(Integer)

    value = Column(Float)

    unit = Column(String)

    metric_start = Column(DateTime)
    metric_end = Column(DateTime)

    collected_at = Column(DateTime)

    dimensions = Column(JSON, nullable=True)
    raw_datapoints = Column(JSON, nullable=True)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="metrics")
    resource = relationship("Resource", back_populates="metrics")

    __table_args__ = (
        Index(
            "idx_metric_resource_scan",
            "resource_id",
            "scan_run_id",
        ),
        Index(
            "idx_metric_scan_run",
            "scan_run_id",
        ),
    )
