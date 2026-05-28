"""
FastAPI Router for Admin Operations.

Chapter 11 — Human Gate & Admin Operations: Admin Router.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
import redis.asyncio as aioredis

from sentinel.auth.middleware import get_current_user
from sentinel.auth.routes import MOCK_USER_DB
from sentinel.config import Settings
from sentinel.dependencies import get_redis, get_settings
from sentinel.layers.human_gate import verify_and_approve_token
from sentinel.models.responses import ApprovalResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])


class ApprovalRequest(BaseModel):
    """Schema for approving or rejecting a pending action."""
    decision: Literal["approve", "reject"] = Field(..., description="Decision: 'approve' or 'reject'.")
    reason: str | None = Field(None, description="Optional administrative explanation.")


class UsageResponse(BaseModel):
    """Schema for token usage statistics."""
    user_id: str = Field(..., description="The user identifier.")
    date: str = Field(..., description="UTC date string (YYYY-MM-DD).")
    tokens_used: int = Field(..., description="Tokens consumed today.")
    tokens_remaining: int = Field(..., description="Tokens remaining in budget.")
    limit: int = Field(..., description="Max token budget limit.")
    requests: int = Field(..., description="Total requests processed today.")


class AuditLogsResponse(BaseModel):
    """Schema for paginated audit log events."""
    events: list[dict[str, Any]] = Field(..., description="List of audit event objects.")
    total: int = Field(..., description="Total filtered event count.")


def _get_role_for_user(user_id: str) -> str:
    """Helper to retrieve mock user role."""
    user = MOCK_USER_DB.get(user_id)
    if user:
        return user["role"]
    return "standard"


def _count_requests_in_audit_log(user_id: str, date_str: str, log_file_path: str) -> int:
    """
    Scan the audit log file and count the number of requests matching user_id today.
    """
    if not os.path.exists(log_file_path):
        return 0

    count = 0
    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    event_time = event.get("timestamp", "")
                    event_user = event.get("user_id", "")
                    # Check if matching user and day
                    if event_user == user_id and event_time.startswith(date_str):
                        count += 1
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error("error_reading_audit_log_for_usage", error=str(e))
    
    return count


@router.post(
    "/approve/{token}",
    response_model=ApprovalResponse,
    responses={
        200: {"model": ApprovalResponse, "description": "Token approved or rejected successfully."},
        400: {"description": "Token verification failed (expired or already consumed)."},
        403: {"description": "Requires admin privileges."},
        404: {"description": "Token not found or expired."},
    },
)
async def approve_gated_action(
    token: str,
    body: ApprovalRequest,
    current_user: dict = Depends(get_current_user),
    redis: aioredis.Redis = Depends(get_redis),
) -> ApprovalResponse:
    """
    Approve or reject a pending gated action.
    Requires admin privileges.
    """
    # 1. Enforce Admin only
    if current_user["role"] != "admin":
        logger.warning(
            "unauthorized_approval_attempt",
            user_id=current_user["username"],
            role=current_user["role"],
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Admin privileges required to approve gated actions.",
        )

    # 2. Look up token in Redis
    key = f"human_gate:token:{token}"
    token_val = await redis.get(key)
    if not token_val:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval token not found or expired.",
        )

    payload = json.loads(token_val)
    action_category = payload.get("action_category", "unknown")

    if body.decision == "approve":
        # Consume the token via approval layer logic
        success = await verify_and_approve_token(token, redis)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token verification failed (already consumed or expired).",
            )
        status_str = "approved"
    else:
        # Rejected: delete token key from Redis
        await redis.delete(key)
        status_str = "rejected"
        logger.info(
            "human_gate_action_rejected",
            action_category=action_category,
            user_id=payload.get("user_id"),
            rejected_by=current_user["username"],
            reason=body.reason,
        )

    return ApprovalResponse(
        status=status_str,
        token=token,
        action=action_category,
    )


@router.get(
    "/approvals",
    response_model=list[dict[str, Any]],
    responses={
        200: {"description": "List of pending gated action approvals."},
        403: {"description": "Requires admin privileges."},
    },
)
async def get_pending_approvals(
    current_user: dict = Depends(get_current_user),
    redis: aioredis.Redis = Depends(get_redis),
) -> list[dict[str, Any]]:
    """
    Retrieve all pending gated approvals from Redis.
    Requires admin privileges.
    """
    # Enforce Admin only
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Admin privileges required to view pending approvals.",
        )

    pending_tokens = []
    # Scan for keys in Redis matching the approval token key structure
    keys = await redis.keys("human_gate:token:*")
    for key in keys:
        val = await redis.get(key)
        if val:
            try:
                payload = json.loads(val)
                # Decode key name to extract token hex
                token_id = key.split(":")[-1]
                payload["token"] = token_id
                payload["ttl"] = await redis.ttl(key)
                pending_tokens.append(payload)
            except Exception:
                continue

    return pending_tokens


@router.get(
    "/usage",
    response_model=list[UsageResponse],
    responses={
        200: {"model": list[UsageResponse], "description": "Token usage and budget statistics."},
        403: {"description": "Requires admin privileges."},
    },
)
async def get_usage_stats(
    user_id: str | None = Query(None, description="Filter usage for a specific user ID."),
    current_user: dict = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
    redis: aioredis.Redis = Depends(get_redis),
) -> list[UsageResponse]:
    """
    Retrieve today's token budgets and request counts.
    If user_id is provided, returns statistics for that user.
    If user_id is empty, returns stats for all active mock users.
    Requires admin privileges.
    """
    # Enforce Admin only
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Admin privileges required to view usage statistics.",
        )

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    users_to_query = [user_id] if user_id else list(MOCK_USER_DB.keys())

    stats = []
    for uid in users_to_query:
        role = _get_role_for_user(uid)
        budget_limit = settings.token_budget_for_role(role)
        
        # Query Redis token usage key
        key = f"token_budget:{uid}:{today}"
        used_val = await redis.get(key)
        tokens_used = int(used_val) if used_val is not None else 0
        tokens_remaining = max(0, budget_limit - tokens_used)

        # Query request count from audit logs
        requests_count = _count_requests_in_audit_log(uid, today, settings.AUDIT_LOG_FILE)

        stats.append(
            UsageResponse(
                user_id=uid,
                date=today,
                tokens_used=tokens_used,
                tokens_remaining=tokens_remaining,
                limit=budget_limit,
                requests=requests_count,
            )
        )

    return stats


@router.get(
    "/audit",
    response_model=AuditLogsResponse,
    responses={
        200: {"model": AuditLogsResponse, "description": "Filtered structured JSON audit events."},
        403: {"description": "Requires admin privileges."},
    },
)
async def get_audit_logs(
    start: str | None = Query(None, description="Start date/time ISO8601 UTC."),
    end: str | None = Query(None, description="End date/time ISO8601 UTC."),
    user_id: str | None = Query(None, description="Filter events by user ID."),
    limit: int = Query(100, ge=1, le=1000, description="Max audit entries to return."),
    current_user: dict = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> AuditLogsResponse:
    """
    Retrieve audit logs filtered by timerange and/or user.
    Returns the most recent events first.
    Requires admin privileges.
    """
    # Enforce Admin only
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Admin privileges required to view audit logs.",
        )

    log_file_path = settings.AUDIT_LOG_FILE
    if not os.path.exists(log_file_path):
        return AuditLogsResponse(events=[], total=0)

    events = []
    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    event_user = event.get("user_id", "")
                    event_time_str = event.get("timestamp", "")

                    # Filter by User ID
                    if user_id and event_user != user_id:
                        continue

                    # Filter by Start/End ISO timestamps
                    if event_time_str:
                        # Normalize strings to datetime for comparison
                        # Strip trailing Z/offset if present for cleaner parsing
                        time_stripped = event_time_str.split("+")[0].rstrip("Z")
                        try:
                            event_dt = datetime.fromisoformat(time_stripped)
                            if start:
                                start_stripped = start.split("+")[0].rstrip("Z")
                                start_dt = datetime.fromisoformat(start_stripped)
                                if event_dt < start_dt:
                                    continue
                            if end:
                                end_stripped = end.split("+")[0].rstrip("Z")
                                end_dt = datetime.fromisoformat(end_stripped)
                                if event_dt > end_dt:
                                    continue
                        except ValueError:
                            pass  # Ignore invalid format parse issues in filters

                    events.append(event)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error("error_reading_audit_logs", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read audit logs: {str(e)}",
        )

    # Sort events by timestamp descending (newest first)
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    total = len(events)
    # Paginate results
    paginated_events = events[:limit]

    return AuditLogsResponse(events=paginated_events, total=total)
