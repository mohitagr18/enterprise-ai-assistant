"""
Layer 11 — Human Gate: Human-in-the-loop validation for high-stakes actions.

Defends against:
  - Irreversible actions executing without human oversight.
  - Exploit vectors performing automatic data deletion or privilege modification.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

import redis.asyncio as aioredis
import structlog

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult

logger = structlog.get_logger(__name__)


def _get_token_key(token: str) -> str:
    """Generate the Redis key for a human gate approval token."""
    return f"human_gate:token:{token}"


async def check_human_gate(
    action_category: str | None,
    user_id: str,
    redis_conn: aioredis.Redis,
    settings: Settings,
) -> LayerResult:
    """
    Check if the requested action category requires human-in-the-loop approval.
    If it does, intercepts execution by returning passed=False and status=PENDING_APPROVAL
    along with a unique approval token stored in Redis.

    Input:
      - action_category: The type of action (e.g. "data_deletion", "policy_change")
      - user_id: ID of the user requesting the action
      - redis_conn: Redis connection pool client
      - settings: Application Settings

    Output:
      - LayerResult: passed=True if no approval needed.
        passed=False with status PENDING_APPROVAL and unique token if action is gated.
    """
    layer_name = "human_gate"

    if not action_category:
        return LayerResult(layer_name=layer_name, passed=True)

    # Resolve human gate actions. Accept list or comma-separated string.
    gated_actions = settings.HUMAN_GATE_ACTIONS
    if isinstance(gated_actions, str):
        gated_actions = [a.strip() for a in gated_actions.split(",") if a.strip()]

    # If action is not gated, let it pass
    if action_category not in gated_actions:
        return LayerResult(layer_name=layer_name, passed=True)

    try:
        # Generate a cryptographically secure token
        token = secrets.token_hex(32)
        key = _get_token_key(token)

        payload = {
            "user_id": user_id,
            "action_category": action_category,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Store token in Redis with configured TTL
        ttl = settings.HUMAN_GATE_TOKEN_TTL_SECONDS
        await redis_conn.setex(key, ttl, json.dumps(payload))

        logger.warning(
            "human_gate_intercepted_action",
            user_id=user_id,
            action_category=action_category,
            token_generated=True,
            ttl_seconds=ttl,
        )

        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"Action '{action_category}' requires explicit human approval.",
            details={
                "status": "PENDING_APPROVAL",
                "approval_token": token,
                "action_category": action_category,
                "expires_in_seconds": ttl,
            },
        )

    except Exception as e:
        logger.error(
            "human_gate_failed_closed",
            user_id=user_id,
            action_category=action_category,
            error=str(e),
        )
        # Fail closed on DB/Redis outages for security-critical gate
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"Verification failed closed due to database error: {str(e)}",
        )


async def verify_and_approve_token(
    token: str,
    redis_conn: aioredis.Redis,
) -> bool:
    """
    Verify the token in Redis. If it exists and is pending, approve and delete/consume it,
    returning True. If it is expired, missing, or already processed, returns False.
    """
    key = _get_token_key(token)
    try:
        val = await redis_conn.get(key)
        if not val:
            logger.warning("human_gate_approval_token_expired_or_invalid", token=token[:8])
            return False

        payload = json.loads(val)
        if payload.get("status") == "pending":
            # Consume token upon successful validation
            await redis_conn.delete(key)
            logger.info(
                "human_gate_action_approved",
                action_category=payload.get("action_category"),
                user_id=payload.get("user_id"),
            )
            return True

        return False
    except Exception as e:
        logger.error(
            "human_gate_token_verification_failed",
            token=token[:8],
            error=str(e),
        )
        return False
