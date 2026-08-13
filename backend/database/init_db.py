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
    init_db()
    print("Database initialized.")