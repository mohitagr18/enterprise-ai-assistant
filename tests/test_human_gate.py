"""
Tests for Layer 11 — Human Gate.

Chapter 12 — Human Gate: Verification.
"""

from __future__ import annotations

import pytest
import redis.asyncio as aioredis

from sentinel.config import Settings
from sentinel.layers.human_gate import check_human_gate, verify_and_approve_token


@pytest.mark.asyncio
async def test_human_gate_happy_path(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Happy path: A request with no high-stakes action category passes through
    without creating a gate.
    """
    # 1. Action is None
    result_none = await check_human_gate(
        action_category=None,
        user_id="user_123",
        redis_conn=mock_redis,
        settings=test_settings,
    )
    assert result_none.passed is True

    # 2. Action is not gated (e.g. 'read_public_data')
    result_not_gated = await check_human_gate(
        action_category="read_public_data",
        user_id="user_123",
        redis_conn=mock_redis,
        settings=test_settings,
    )
    assert result_not_gated.passed is True


@pytest.mark.asyncio
async def test_human_gate_intercept_action(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Attack scenario: A request triggering a gated action (e.g., data_deletion)
    is intercepted, returning passed=False, status=PENDING_APPROVAL, and a unique token.
    """
    result = await check_human_gate(
        action_category="data_deletion",
        user_id="user_123",
        redis_conn=mock_redis,
        settings=test_settings,
    )

    assert result.passed is False
    assert "requires explicit human approval" in result.reason
    assert result.details["status"] == "PENDING_APPROVAL"
    assert result.details["action_category"] == "data_deletion"
    assert "approval_token" in result.details
    assert len(result.details["approval_token"]) == 64  # token_hex(32) is 64 chars


@pytest.mark.asyncio
async def test_human_gate_token_lifecycle_and_expiration(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Edge case:
    1. A generated token can be successfully verified and approved.
    2. Once approved, the token is consumed and cannot be reused.
    3. An invalid or expired (non-existent) token is rejected.
    """
    # Generate token
    result = await check_human_gate(
        action_category="policy_change",
        user_id="admin_user",
        redis_conn=mock_redis,
        settings=test_settings,
    )
    assert result.passed is False
    token = result.details["approval_token"]

    # 1. Verify and approve token
    approved = await verify_and_approve_token(token, mock_redis)
    assert approved is True

    # 2. Try to reuse the token -> should be consumed/deleted, thus returns False
    re_approved = await verify_and_approve_token(token, mock_redis)
    assert re_approved is False

    # 3. Try to verify an expired or non-existent token
    expired_token = "some_random_non_existent_token"
    approved_expired = await verify_and_approve_token(expired_token, mock_redis)
    assert approved_expired is False
