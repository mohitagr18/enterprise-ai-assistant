"""
Layer 12 — Threat Monitor: Rolling-window behavioral abuse tracking.

Defends against:
  - Coordinated attacks and repeated probing across requests.
  - Brute-force budget exhaustion or scanning for prompt injection vulnerabilities.
"""

from __future__ import annotations

import time
import uuid

import redis.asyncio as aioredis
import structlog

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult

logger = structlog.get_logger(__name__)


def _get_threat_key(user_id: str, metric: str) -> str:
    """Generate the Redis ZSET key for a user's threat metric."""
    return f"threat_monitor:{user_id}:{metric}"


def _get_flagged_key(user_id: str) -> str:
    """Generate the Redis key used to flag a user's rate limit."""
    return f"threat:flagged:{user_id}"


async def monitor_threats(
    user_id: str,
    session_id: str,
    layer_results: list[LayerResult],
    redis_conn: aioredis.Redis,
    settings: Settings,
) -> LayerResult:
    """
    Examine the results of preceding layers for the current request.
    If there are failures, record them in Redis ZSETs and check if rolling-window
    thresholds have been breached. If so, flag the user to reduce rate limits and block.

    Input:
      - user_id: ID of the requesting user
      - session_id: Current session ID
      - layer_results: List of LayerResults from preceding layers in this request
      - redis_conn: Redis connection client
      - settings: Application Settings

    Output:
      - LayerResult: passed=False if threat thresholds exceeded, else passed=True.
    """
    layer_name = "threat_monitor"
    now = time.time()
    window = settings.THREAT_MONITOR_WINDOW_SECONDS
    clear_before = now - window

    # Check if the current request has any layer blocks
    failed_layers = [r for r in layer_results if not r.passed]

    # If nothing failed, check if they are already flagged (to log or propagate status)
    if not failed_layers:
        try:
            is_flagged = await redis_conn.exists(_get_flagged_key(user_id))
            return LayerResult(
                layer_name=layer_name,
                passed=True,
                details={"flagged": bool(is_flagged)},
            )
        except Exception as e:
            logger.error("threat_monitor_redis_check_failed", error=str(e))
            return LayerResult(layer_name=layer_name, passed=True)

    try:
        # We have failures! Record them in Redis.
        async with redis_conn.pipeline(transaction=True) as pipe:
            member = f"{now}:{uuid.uuid4().hex}"

            # 1. Record the block
            blocks_key = _get_threat_key(user_id, "blocks")
            pipe.zadd(blocks_key, {member: now})
            pipe.zremrangebyscore(blocks_key, "-inf", clear_before)
            pipe.zcard(blocks_key)

            # 2. Record specific layer failures
            injections_key = _get_threat_key(user_id, "injections")
            semantic_key = _get_threat_key(user_id, "semantic")
            budget_key = _get_threat_key(user_id, "budget_hits")

            # Check which layers failed and pipe their records
            has_injection = False
            has_semantic = False
            has_budget = False

            for failed in failed_layers:
                if failed.layer_name == "input_validator":
                    pipe.zadd(injections_key, {member: now})
                    has_injection = True
                elif failed.layer_name == "semantic_guard":
                    pipe.zadd(semantic_key, {member: now})
                    has_semantic = True
                elif failed.layer_name == "token_budget":
                    pipe.zadd(budget_key, {member: now})
                    has_budget = True

            pipe.zremrangebyscore(injections_key, "-inf", clear_before)
            pipe.zcard(injections_key)

            pipe.zremrangebyscore(semantic_key, "-inf", clear_before)
            pipe.zcard(semantic_key)

            pipe.zremrangebyscore(budget_key, "-inf", clear_before)
            pipe.zcard(budget_key)

            # Execute transaction pipeline
            pipe_results = await pipe.execute()

        # Extract counts from pipeline results.
        # Structure of pipe_results matches command index execution order.
        # Let's count them carefully:
        # - blocks: zadd (index 0), zremrangebyscore (index 1), zcard (index 2)
        # Then, conditionally, the other metrics are added.
        # To avoid index matching bugs, let's just query the ZCARD counts explicitly!
        # This is much cleaner and less error-prone than parsing transactional pipeline slices.
        
        blocks_count = await redis_conn.zcard(blocks_key)
        injections_count = await redis_conn.zcard(injections_key)
        semantic_count = await redis_conn.zcard(semantic_key)
        budget_count = await redis_conn.zcard(budget_key)

        # Clean up Redis TTLs to avoid memory bloat
        await redis_conn.expire(blocks_key, window)
        await redis_conn.expire(injections_key, window)
        await redis_conn.expire(semantic_key, window)
        await redis_conn.expire(budget_key, window)

        # Check threshold breaches
        breached = []
        if blocks_count >= settings.THREAT_MONITOR_MAX_BLOCKS:
            breached.append(f"total_blocks ({blocks_count}/{settings.THREAT_MONITOR_MAX_BLOCKS})")
        if injections_count >= settings.THREAT_MONITOR_MAX_INJECTION_MATCHES:
            breached.append(f"injections ({injections_count}/{settings.THREAT_MONITOR_MAX_INJECTION_MATCHES})")
        if semantic_count >= settings.THREAT_MONITOR_MAX_SEMANTIC_TRIGGERS:
            breached.append(f"semantic_triggers ({semantic_count}/{settings.THREAT_MONITOR_MAX_SEMANTIC_TRIGGERS})")
        if budget_count >= settings.THREAT_MONITOR_MAX_BUDGET_HITS:
            breached.append(f"budget_exhaustions ({budget_count}/{settings.THREAT_MONITOR_MAX_BUDGET_HITS})")

        if breached:
            # Flag the user in Redis to trigger rate limit reduction in the middleware
            flag_key = _get_flagged_key(user_id)
            await redis_conn.setex(flag_key, window, "1")

            logger.error(
                "threat_monitor_threshold_breached",
                user_id=user_id,
                breached_metrics=breached,
                action_taken="rate_limit_reduced",
            )

            return LayerResult(
                layer_name=layer_name,
                passed=False,
                reason=f"Threat threshold breached: {', '.join(breached)}.",
                details={
                    "flagged": True,
                    "breached_metrics": breached,
                    "action_taken": "rate_limit_reduced",
                    "window_seconds": window,
                },
            )

        return LayerResult(
            layer_name=layer_name,
            passed=True,
            details={
                "flagged": False,
                "counts": {
                    "blocks": blocks_count,
                    "injections": injections_count,
                    "semantic": semantic_count,
                    "budget": budget_count,
                }
            },
        )

    except Exception as e:
        logger.error("threat_monitor_execution_failed", error=str(e))
        # Fail closed on threat monitor execution failure to prevent bypassing detection
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"Threat verification failed closed: {str(e)}",
        )
