from datetime import date, datetime

from sqlalchemy import Date, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class CostRecord(Base):
    __tablename__ = "cost_records"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    start_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    end_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    service: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        index=True,
    )

    usage_type: Mapped[str | None] = mapped_column(
        String(250),
        nullable=True,
        index=True,
    )

    operation: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )

    region: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )

    amount: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    usage_quantity: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    unit: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    scan_run = relationship(
        "ScanRun",
        back_populates="cost_records",
    )