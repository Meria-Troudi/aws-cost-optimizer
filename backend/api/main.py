"""
FastAPI application entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes.account_cost import router as account_cost_router
from backend.api.routes.dashboard import router as dashboard_router
from backend.api.routes.scans import router as scan_router
from backend.database.connection import SessionLocal
from backend.database.scan_recovery import recover_stuck_scans

from backend.database.models import (  # noqa: F401
    scan_run,
    cost_record,
    resource,
    snapshot,
    metric,
    finding,
    recommendation,
    collection_plan,
)


app = FastAPI(
    title="AWS Cost Optimizer API",
    version="1.0.0",
)


# Local dev: allow any localhost port (Vite proxy avoids CORS; this covers direct API calls too)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.get("/")
def root():
    return {
        "name": "AWS Cost Optimizer API",
        "status": "running",
    }


@app.get("/api/health")
def health():
    return {
        "status": "ok",
    }


app.include_router(scan_router)
app.include_router(dashboard_router)
app.include_router(account_cost_router)


@app.on_event("startup")
def on_startup():
    db = SessionLocal()
    try:
        recovered = recover_stuck_scans(db)
        if recovered:
            print(f"Recovered {recovered} stuck scan(s)")
    finally:
        db.close()
