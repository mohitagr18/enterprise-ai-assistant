"""
Tests for Authentication and JWT flow.

Chapter 11 — Agent Identity & Authentication: Verification.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from httpx import AsyncClient
from jose import jwt

from sentinel.config import Settings


@pytest.mark.asyncio
async def test_auth_happy_path(async_client: AsyncClient) -> None:
    """
    Test login with valid credentials, using the returned access token
    to call a protected route, and checking token contents.
    """
    # 1. Login request
    response = await async_client.post(
        "/auth/login",
        json={"username": "standarduser", "password": "userpass123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

    # 2. Use access token to logout (a protected endpoint)
    access_token = data["access_token"]
    logout_response = await async_client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_response.status_code == 200
    assert logout_response.json() == {"message": "Logged out successfully"}


@pytest.mark.asyncio
async def test_auth_invalid_credentials(async_client: AsyncClient) -> None:
    """Test login fails with incorrect password."""
    response = await async_client.post(
        "/auth/login",
        json={"username": "standarduser", "password": "wrongpassword"},
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auth_none_alg_attack(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """
    Attack Scenario: Verify that a JWT using the 'none' algorithm is explicitly rejected.
    """
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub": "standarduser",
        "role": "standard",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "type": "access",
    }

    # Manually base64-encode header and payload to build token without signature
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    none_token = f"{header_b64}.{payload_b64}."

    response = await async_client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {none_token}"},
    )
    assert response.status_code == 401
    assert "none" in response.json()["detail"] or "Authentication failed" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auth_expired_token(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """
    Edge Case: Verify that an expired access token is rejected.
    """
    payload = {
        "sub": "standarduser",
        "role": "standard",
        "exp": int(time.time()) - 100,  # expired in past
        "iat": int(time.time()) - 200,
        "type": "access",
    }
    expired_token = jwt.encode(
        payload,
        test_settings.JWT_SECRET_KEY,
        algorithm=test_settings.JWT_ALGORITHM,
    )

    response = await async_client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert "Authentication failed" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auth_refresh_token(async_client: AsyncClient) -> None:
    """
    Test that a valid refresh token yields a new access token.
    """
    # 1. Login to get refresh token
    login_resp = await async_client.post(
        "/auth/login",
        json={"username": "standarduser", "password": "userpass123"},
    )
    assert login_resp.status_code == 200
    refresh_token = login_resp.json()["refresh_token"]

    # 2. Call refresh endpoint (requires Bearer refresh token in header + body)
    refresh_resp = await async_client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert refresh_resp.status_code == 200
    data = refresh_resp.json()
    assert "access_token" in data
    assert data["expires_in"] > 0
