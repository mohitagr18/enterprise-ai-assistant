"""
Redis-backed sliding window rate limiter middleware.

Chapter 3 — Rate Limiting: Denial of Service and Brute Force Prevention.
"""

from __future__ import annotations

import json
import time
import uuid

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

import sentinel.dependencies
from sentinel.dependencies import get_settings

logger = structlog.get_logger(__name__)

# Lua script to atomicity calculate sliding window rate limit.
# Using ZSET where both score and value are the epoch time.
LUA_SLIDING_WINDOW = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local clear_before = now - window

-- Remove expired records
redis.call('zremrangebyscore', key, '-inf', clear_before)

-- Count current window requests
local current_requests = redis.call('zcard', key)

if current_requests < limit then
    -- Add request (using timestamp as score and member)
    redis.call('zadd', key, now, member)
    redis.call('expire', key, window)
    return 1 -- Allowed
else
    return 0 -- Blocked
end
"""


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    FastAPI HTTP middleware enforcing sliding window rate limiting.
    Differentiates authenticated users (by username) from unauthenticated users (by IP).
    Supports dynamic rate reduction if a user is flagged by the Threat Monitor.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        path = request.url.path

        # Health endpoint should be excluded from rate limiting
        if path == "/health":
            return await call_next(request)

        settings = getattr(request.app.state, "settings", None) or get_settings()

        # 1. Resolve rate limit key and identity
        if hasattr(request.state, "user"):
            user_id = request.state.user["username"]
            key = f"rate_limit:user:{user_id}"
            is_authenticated = True
        else:
            client_ip = request.client.host if request.client else "unknown"
            key = f"rate_limit:ip:{client_ip}"
            is_authenticated = False

        # 2. Get active Redis connection (falls back to fakeredis automatically)
        redis_conn = sentinel.dependencies._redis_client
        if redis_conn is None:
            # Fail open or log error? Standard practice is logging error and letting request pass.
            logger.error("redis_not_initialized", key=key)
            return await call_next(request)

        # 3. Check if user is flagged by Layer 12 (Threat Monitor) to reduce rate limit
        limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE
        if is_authenticated:
            user_id = request.state.user["username"]
            flagged_key = f"threat:flagged:{user_id}"
            try:
                is_flagged = await redis_conn.exists(flagged_key)
                if is_flagged:
                    limit = settings.THREAT_MONITOR_REDUCED_RATE_LIMIT
                    logger.warning(
                        "rate_limit_reduced_by_threat_monitor",
                        user_id=user_id,
                        new_limit=limit,
                    )
            except Exception as e:
                logger.error("threat_flag_redis_check_failed", error=str(e))

        # 4. Enforce rate limit via Lua script
        now = time.time()
        window = settings.RATE_LIMIT_WINDOW_SECONDS
        member = f"{now}:{uuid.uuid4().hex}"

        try:
            allowed = await redis_conn.eval(LUA_SLIDING_WINDOW, 1, key, now, window, limit, member)
            if not allowed:
                logger.warning(
                    "rate_limit_exceeded",
                    key=key,
                    limit=limit,
                    window_seconds=window,
                )
                return Response(
                    content=json.dumps({
                        "detail": "Rate limit exceeded. Please try again later.",
                        "error_code": "RATE_LIMIT_EXCEEDED",
                    }),
                    status_code=429,
                    media_type="application/json",
                )
        except Exception as e:
            logger.error("rate_limiter_execution_failed", error=str(e))
            # Fail open to ensure availability, but log severe warning
            pass

        return await call_next(request)
