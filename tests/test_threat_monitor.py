"""
Tests for Layer 12 — Threat Monitor.

Chapter 13 — Threat Monitor: Verification.
"""

from __future__ import annotations

import pytest
import redis.asyncio as aioredis

from sentinel.config import Settings
from sentinel.layers.threat_monitor import monitor_threats
from sentinel.models.layer_result import LayerResult


@pytest.mark.asyncio
async def test_threat_monitor_happy_path(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Happy path: A user under all thresholds passes threat monitoring.
    """
    layer_results = [
        LayerResult(layer_name="input_validator", passed=True),
        LayerResult(layer_name="semantic_guard", passed=True),
    ]

    result = await monitor_threats(
        user_id="user_123",
        session_id="session_abc",
        layer_results=layer_results,
        redis_conn=mock_redis,
        settings=test_settings,
    )

    assert result.passed is True
    assert result.details["flagged"] is False


@pytest.mark.asyncio
async def test_threat_monitor_attack_scenario(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Attack scenario: A user triggering multiple pattern blocks within the window
    is flagged, setting the threat:flagged key in Redis.
    """
    user_id = "attacker_456"
    test_settings.THREAT_MONITOR_MAX_INJECTION_MATCHES = 3

    # First injection match block
    res1 = await monitor_threats(
        user_id=user_id,
        session_id="sess_1",
        layer_results=[LayerResult(layer_name="input_validator", passed=False, reason="Null byte")],
        redis_conn=mock_redis,
        settings=test_settings,
    )
    assert res1.passed is True  # Count is 1 < 3

    # Second injection match block
    res2 = await monitor_threats(
        user_id=user_id,
        session_id="sess_2",
        layer_results=[LayerResult(layer_name="input_validator", passed=False, reason="Regex")],
        redis_conn=mock_redis,
        settings=test_settings,
    )
    assert res2.passed is True  # Count is 2 < 3

    # Third injection match block - threshold is now hit (3 >= 3)
    res3 = await monitor_threats(
        user_id=user_id,
        session_id="sess_3",
        layer_results=[LayerResult(layer_name="input_validator", passed=False, reason="Regex")],
        redis_conn=mock_redis,
        settings=test_settings,
    )
    assert res3.passed is False
    assert res3.details["flagged"] is True
    assert "injections" in res3.reason

    # Verify that the threat flag was set in Redis
    flagged = await mock_redis.exists(f"threat:flagged:{user_id}")
    assert flagged == 1


@pytest.mark.asyncio
async def test_threat_monitor_user_isolation(
    mock_redis: aioredis.Redis,
    test_settings: Settings,
) -> None:
    """
    Edge case: Multiple users probing simultaneously do not affect each other's
    threat scores (proper user isolation in Redis).
    """
    user_a = "attacker_a"
    user_b = "benign_b"
    test_settings.THREAT_MONITOR_MAX_INJECTION_MATCHES = 3

    # 1. Attacker A generates 2 injection blocks
    for i in range(2):
        await monitor_threats(
            user_id=user_a,
            session_id=f"sess_a_{i}",
            layer_results=[LayerResult(layer_name="input_validator", passed=False, reason="Blocked")],
            redis_conn=mock_redis,
            settings=test_settings,
        )

    # 2. Benign B generates a single injection block
    res_b = await monitor_threats(
        user_id=user_b,
        session_id="sess_b",
        layer_results=[LayerResult(layer_name="input_validator", passed=False, reason="Blocked")],
        redis_conn=mock_redis,
        settings=test_settings,
    )
    # Benign B has only 1 block, so should pass
    assert res_b.passed is True

    # Check that B is not flagged in Redis
    flagged_b = await mock_redis.exists(f"threat:flagged:{user_b}")
    assert flagged_b == 0

    # Attacker A makes the 3rd failing request -> gets flagged
    res_a = await monitor_threats(
        user_id=user_a,
        session_id="sess_a_2",
        layer_results=[LayerResult(layer_name="input_validator", passed=False, reason="Blocked")],
        redis_conn=mock_redis,
        settings=test_settings,
    )
    assert res_a.passed is False
    assert res_a.details["flagged"] is True

    # Check that A is flagged in Redis, but B is still NOT flagged
    flagged_a = await mock_redis.exists(f"threat:flagged:{user_a}")
    assert flagged_a == 1
    flagged_b_after = await mock_redis.exists(f"threat:flagged:{user_b}")
    assert flagged_b_after == 0
