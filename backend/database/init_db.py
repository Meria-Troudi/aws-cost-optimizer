import os
import sys


def init_db():
    from .connection import engine
    from .base import Base
    # Import all models to register them with SQLAlchemy
    from .models import (
        scan_run,
        cost_record,
        resource,
        snapshot,
        metric,
        finding,
        recommendation,
        collection_plan,
    )
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    # Allow running as a script by adding project root to path
    _project_root = os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__)
            )
        )
    )
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)

    from backend.database.init_db import init_db

    init_db()
    print("Database initialized.")
