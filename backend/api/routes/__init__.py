"""Central router registration."""

from fastapi import APIRouter

from .account import router as account_router
from .dashboard import router as dashboard_router
from .scans import router as scans_router
from .cost import router as cost_router

router = APIRouter()
router.include_router(account_router)
router.include_router(dashboard_router)
router.include_router(scans_router)
router.include_router(cost_router)
