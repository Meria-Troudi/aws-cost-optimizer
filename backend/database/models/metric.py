"""
Metric model.

One metric observation is uniquely identified by:

resource + scan + namespace + metric + statistic
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class Metric(Base):
    __tablename__ = "metrics"

    __table_args__ = (
        UniqueConstraint(
            "resource_id",
            "scan_run_id",
            "namespace",
            "metric_name",
            "statistic",
            name="uq_metric_identity",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    resource_id: Mapped[int] = mapped_column(
        ForeignKey(
            "resources.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey(
            "scan_runs.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    namespace: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    metric_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    statistic: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    period: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    value: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    unit: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    metric_start: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    metric_end: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    dimensions: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    resource = relationship(
        "Resource",
        back_populates="metrics",
    )