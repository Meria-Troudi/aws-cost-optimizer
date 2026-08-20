"""
Test bootstrap.

The engine uses bare top-level imports (`from collectors.registry ...`),
so both the repo root and aws_cost_optimizer/ must be on sys.path --
the same thing backend/bootstrap.py::ensure_project_paths() does for the
application.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

for path in (ROOT, ROOT / "aws_cost_optimizer"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
