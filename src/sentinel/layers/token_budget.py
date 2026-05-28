"""
Layer 5 — Token Budget: Budget tracking and cost abuse prevention.

Defends against:
  - Denial of Wallet (DoW) attacks via cost-heavy model requests.
  - Cost runway by limiting daily token expenditures by user role.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult


def _get_budget_key(user_id: str) -> str:
    """Generate the Redis key for a user's daily token budget."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"token_budget:{user_id}:{today}"


def _get_next_reset_time() -> datetime:
    """Calculate the next midnight UTC reset time."""
    now = datetime.now(timezone.utc)
    return (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)


async def check_token_budget(
    user_id: str,
    estimated_tokens: int,
    user_role: str,
    redis_conn: aioredis.Redis,
    settings: Settings,
) -> LayerResult:
    """
    Check if the user has sufficient remaining daily token budget for the request.
    Does not increment usage; increments occur post-LLM invocation.
    """
    layer_name = "token_budget"
    key = _get_budget_key(user_id)
    budget_limit = settings.token_budget_for_role(user_role)

    try:
        # Retrieve current daily usage
        val = await redis_conn.get(key)
        current_used = int(val) if val is not None else 0
    except Exception as e:
        # Fail closed on infrastructure errors for budget enforcement
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"Failed to check token budget from database: {str(e)}.",
        )

    # Enforce budget boundary
    if current_used + estimated_tokens > budget_limit:
        reset_time = _get_next_reset_time()
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason="Daily token budget exhausted.",
            details={
                "limit": budget_limit,
                "current_used": current_used,
                "estimated_tokens": estimated_tokens,
                "reset_time": reset_time.isoformat(),
            },
        )

    remaining = budget_limit - current_used - estimated_tokens
    return LayerResult(
        layer_name=layer_name,
        passed=True,
        details={
            "limit": budget_limit,
            "current_used": current_used,
            "estimated_tokens": estimated_tokens,
            "remaining": remaining,
        },
    )


async def increment_token_usage(
    user_id: str,
    actual_tokens: int,
    redis_conn: aioredis.Redis,
) -> int:
    """
    Increment the user's daily token budget.
    Automatically sets key TTL to 2 days to ensure cleanup.
    """
    key = _get_budget_key(user_id)
    # Increment atomically
    new_total = await redis_conn.incrby(key, actual_tokens)
    # Set expiration for 48 hours to prevent database bloat
    await redis_conn.expire(key, 172800)
    return new_total
