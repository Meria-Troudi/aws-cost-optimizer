"""
Top-level module.

Re-exports the FastAPI application.
"""

from backend.bootstrap import ensure_project_paths
ensure_project_paths()

import backend.database.models  # noqa
from backend.api.main import app

__all__ = ["app"]
