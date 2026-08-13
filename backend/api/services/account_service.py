"""AWS account discovery via STS."""

from __future__ import annotations

from datetime import datetime, timezone

from aws_cost_optimizer.config.client import get_client
from aws_cost_optimizer.config.settings import CE_REGION


def discover_current_account() -> dict:
    sts = get_client("sts", CE_REGION)
    identity = sts.get_caller_identity()
    account_id = identity.get("Account")
    if not account_id:
        raise RuntimeError("Unable to determine AWS account from STS")

    return {
        "account_id": account_id,
        "arn": identity.get("Arn"),
        "user_id": identity.get("UserId"),
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "source": "sts_get_caller_identity",
        "region": CE_REGION,
    }
