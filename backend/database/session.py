"""
Database session helper
"""
from sqlalchemy.orm import Session
from .connection import SessionLocal
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
