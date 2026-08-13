"""
Top-level module.

Re-exports the FastAPI application.
"""

from backend.api.main import app

__all__ = ["app"]