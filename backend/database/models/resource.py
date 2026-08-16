from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class Resource(Base):
    __tablename__ = "resources"

    __table_args__ = (
        UniqueConstraint(
            "account_id",
            "region",
            "aws_resource_id",
            name="uq_resource_identity",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    # Stable identity - NOT tied to a specific scan run.
    account_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    aws_resource_id: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        index=True,
    )

    service: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    region: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )

    name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    tags: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    snapshots = relationship(
        "ResourceSnapshot",
        back_populates="resource",
        cascade="all, delete-orphan",
    )

    metrics = relationship(
        "Metric",
        back_populates="resource",
        cascade="all, delete-orphan",
    )