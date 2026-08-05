from sqlalchemy import Column, Integer, String, Float, JSON
from backend.database.base import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True)

    scan_run_id = Column(Integer, nullable=False)

    finding_id = Column(Integer)

    evidence_type = Column(String)

    resource_id = Column(String)

    value = Column(Float)

    details = Column(JSON)