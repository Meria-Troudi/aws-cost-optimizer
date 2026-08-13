from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class ResourceSnapshot(Base):
    __tablename__ = "resource_snapshots"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    resource_id: Mapped[int] = mapped_column(
        ForeignKey("resources.id"),
        nullable=False,
        index=True,
    )

    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    state: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    configuration: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    topology: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    resource = relationship(
        "Resource",
        back_populates="snapshots",
    )