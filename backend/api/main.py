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


app.include_router(account_router)
app.include_router(dashboard_router)
app.include_router(scans_router)
app.include_router(scan_results_router)
app.include_router(cost_router)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "aws-cost-optimizer-api",
    }
