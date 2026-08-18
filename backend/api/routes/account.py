"""
Account API routes.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from backend.api.services.account_service import (
    discover_current_account,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/account",
    tags=["Account"],
)


@router.get("")
def get_account():
    """
    Return the currently authenticated AWS account.
    """

    try:
        return discover_current_account()

    except Exception as exc:
        logger.exception(
            "AWS account discovery failed."
        )

        raise HTTPException(
            status_code=503,
            detail="Unable to discover AWS account.",
        ) from exc


@router.get("/health")
def account_health():
    """
    Verify that AWS credentials and STS are available.
    """

    try:
        account = (
            discover_current_account()
        )

        return {
            "status": "ok",
            "account_id": account[
                "account_id"
            ],
            "source": "sts",
        }

    except Exception as exc:
        logger.exception(
            "AWS account health check failed."
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "AWS credentials unavailable."
            ),
        ) from exc