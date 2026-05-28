"""
Tests for Layer 5 — Token Budget.

Chapter 6 — Token Budget: Verification.
"""

from __future__ import annotations

import pytest
import redis.asyncio as aioredis

from sentinel.config import Settings
from sentinel.layers.token_budget import (
    _get_budget_key,
    check_token_budget,
    increment_token_usage,
)


@pytest.mark.asyncio
async def test_token_budget_happy_path(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Happy path: A user with remaining budget passes, and the response
    includes accurate remaining balance.
    """
    user_id = "standard_user_123"
    role = "standard"  # 100,000 budget
    limit = test_settings.token_budget_for_role(role)

    # 1. First check (0 tokens used)
    result = await check_token_budget(user_id, 1000, role, mock_redis, test_settings)
    assert result.passed is True
    assert result.details["current_used"] == 0
    assert result.details["remaining"] == limit - 1000

    # 2. Increment usage by 1000
    new_total = await increment_token_usage(user_id, 1000, mock_redis)
    assert new_total == 1000

    # 3. Second check (1000 tokens used)
    result = await check_token_budget(user_id, 2000, role, mock_redis, test_settings)
    assert result.passed is True
    assert result.details["current_used"] == 1000
    assert result.details["remaining"] == limit - 3000


@pytest.mark.asyncio
async def test_token_budget_exhausted(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Attack scenario: A user who has exhausted their daily budget is blocked,
    and the response includes the UTC reset time.
    """
    user_id = "standard_user_abuse"
    role = "standard"
    limit = test_settings.token_budget_for_role(role)

    # Populate Redis key to be close to the limit
    key = _get_budget_key(user_id)
    await mock_redis.set(key, limit - 100)

    # Check with 200 tokens (needs 100, so it exceeds by 100)
    result = await check_token_budget(user_id, 200, role, mock_redis, test_settings)
    assert result.passed is False
    assert result.reason == "Daily token budget exhausted."
    assert "reset_time" in result.details
    assert result.details["current_used"] == limit - 100
    assert result.details["limit"] == limit


@pytest.mark.asyncio
async def test_token_budget_exact_boundary(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Edge case: A request that would exactly exhaust the remaining budget
    (remaining = estimated) is allowed but leaves 0 remaining.
    """
    user_id = "standard_user_edge"
    role = "standard"
    limit = test_settings.token_budget_for_role(role)

    # Populate Redis key to leave exactly 500 tokens
    key = _get_budget_key(user_id)
    await mock_redis.set(key, limit - 500)

    # Check with estimated exactly 500
    result = await check_token_budget(user_id, 500, role, mock_redis, test_settings)
    assert result.passed is True
    assert result.details["remaining"] == 0
    assert result.details["current_used"] == limit - 500
