from __future__ import annotations

from backend.bootstrap import ensure_project_paths
ensure_project_paths()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database import models_loader
from backend.database.models_loader import init_db

init_db()

from backend.api.routes.account import router as account_router
from backend.api.routes.dashboard import router as dashboard_router
from backend.api.routes.scans import router as scans_router
from backend.api.routes.scan_results import (
    router as scan_results_router,
)
from backend.api.routes.cost import router as cost_router
from backend.api.routes.recommendations import (
    router as recommendations_router,
)


app = FastAPI(
    title="AWS Cost Optimizer API",
    version="1.0.0",
    description=(
        "AWS FinOps cost optimization platform API."
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def close_out_interrupted_scans() -> None:
    """
    Scans run in daemon threads, so a restart or crash leaves their
    rows stuck in 'pending'/'running' forever and the UI polls them
    until it gives up. Close them out on startup.
    """

    from backend.database.connection import SessionLocal
    from backend.database.scan_recovery import recover_stuck_scans

    db = SessionLocal()

    try:
        recover_stuck_scans(db)
    except Exception as exc:
        db.rollback()
        print(
            "[startup] Could not recover interrupted scans: "
            f"{type(exc).__name__}: {exc}"
        )
    finally:
        db.close()


app.include_router(account_router)
app.include_router(dashboard_router)
app.include_router(scans_router)
app.include_router(scan_results_router)
app.include_router(cost_router)
app.include_router(recommendations_router)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "aws-cost-optimizer-api",
    }
