"""
Tests for Rate Limiting Middleware.

Chapter 3 — Rate Limiting: Verification.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from sentinel.dependencies import get_settings


@pytest.mark.asyncio
async def test_rate_limiter_happy_path(async_client: AsyncClient) -> None:
    """
    Test that requests within the rate limit pass through normally.
    """
    # 1. Login to get Bearer token
    login_resp = await async_client.post(
        "/auth/login",
        json={"username": "standarduser", "password": "userpass123"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # 2. Send rapid requests within limit (default limit is 30/min, so 3 is well within)
    for _ in range(3):
        response = await async_client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_rate_limiter_burst_attack(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """
    Attack Scenario: Verify that requests exceeding the limit are blocked with 429.
    """
    original_limit = test_settings.RATE_LIMIT_REQUESTS_PER_MINUTE
    # Set a small limit for testing speed
    test_settings.RATE_LIMIT_REQUESTS_PER_MINUTE = 5

    try:
        # 1. Login
        login_resp = await async_client.post(
            "/auth/login",
            json={"username": "standarduser", "password": "userpass123"},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]

        # 2. Exhaust the limit (send 5 allowed requests)
        for _ in range(5):
            response = await async_client.post(
                "/auth/logout",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200

        # 3. The 6th request must be blocked with HTTP 429
        blocked_response = await async_client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert blocked_response.status_code == 429
        assert blocked_response.json()["error_code"] == "RATE_LIMIT_EXCEEDED"
    finally:
        # Restore settings
        test_settings.RATE_LIMIT_REQUESTS_PER_MINUTE = original_limit


@pytest.mark.asyncio
async def test_rate_limiter_multi_user_isolation(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """
    Edge Case: Verify that rate limits for different users are completely isolated.
    """
    original_limit = test_settings.RATE_LIMIT_REQUESTS_PER_MINUTE
    test_settings.RATE_LIMIT_REQUESTS_PER_MINUTE = 3

    try:
        # 1. User 1 Login
        login_resp1 = await async_client.post(
            "/auth/login",
            json={"username": "standarduser", "password": "userpass123"},
        )
        token1 = login_resp1.json()["access_token"]

        # 2. User 2 Login
        login_resp2 = await async_client.post(
            "/auth/login",
            json={"username": "admin", "password": "adminpass123"},
        )
        token2 = login_resp2.json()["access_token"]

        # 3. Exhaust User 1 limit
        for _ in range(3):
            response = await async_client.post(
                "/auth/logout",
                headers={"Authorization": f"Bearer {token1}"},
            )
            assert response.status_code == 200

        # User 1 is now blocked
        response1 = await async_client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token1}"},
        )
        assert response1.status_code == 429

        # 4. User 2 should still be allowed to execute request
        response2 = await async_client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token2}"},
        )
        assert response2.status_code == 200
    finally:
        test_settings.RATE_LIMIT_REQUESTS_PER_MINUTE = original_limit
