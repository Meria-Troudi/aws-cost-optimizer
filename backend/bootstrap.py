"""
Ensure legacy aws_cost_optimizer imports resolve when running via the API.

The optimizer package uses top-level imports like `from collectors.registry import …`
which require `fin/aws_cost_optimizer` on sys.path (same as aws_cost_optimizer/main.py).
"""

from __future__ import annotations

import os
import sys

_PATHS_CONFIGURED = False


def ensure_project_paths() -> None:
    global _PATHS_CONFIGURED
    if _PATHS_CONFIGURED:
        return

    # backend/bootstrap.py → backend → fin
    project_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
    optimizer_root = os.path.join(project_root, "aws_cost_optimizer")

    for path in (project_root, optimizer_root):
        if path not in sys.path:
            sys.path.insert(0, path)

    _PATHS_CONFIGURED = True
