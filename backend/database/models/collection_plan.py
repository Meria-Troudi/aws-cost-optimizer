from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class CollectionPlan(Base):
    __tablename__ = "collection_plans"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    service: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    region: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    usage_type: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    collector_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    cost_context: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        default="planned",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    scan_run = relationship(
        "ScanRun",
        back_populates="collection_plans",
    )