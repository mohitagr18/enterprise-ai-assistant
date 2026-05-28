"""
Shared pytest fixtures for Sentinel AI tests.
"""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator

import fakeredis.aioredis as fakeredis_aio
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from sentinel.config import Settings
from sentinel.dependencies import get_redis, get_settings


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Session-scoped test settings."""
    return Settings(
        OPENAI_API_KEY="test-openai-api-key",
        JWT_SECRET_KEY="test-jwt-secret-key-that-is-very-long-and-secure-for-testing",
        REDIS_URL=None,
        CHROMADB_PERSIST_DIR="./data/test_chromadb",
        AUDIT_LOG_FILE="./logs/test_audit.jsonl",
        APP_DEBUG=True,
        TOKEN_BUDGET_STANDARD=100000,
        TOKEN_BUDGET_POWER_USER=500000,
        TOKEN_BUDGET_ADMIN=1000000,
    )


@pytest_asyncio.fixture
async def mock_redis() -> AsyncGenerator[fakeredis_aio.FakeRedis, None]:
    """Function-scoped fake Redis client for isolation."""
    import sentinel.dependencies
    from fakeredis import FakeServer
    server = FakeServer()
    client = fakeredis_aio.FakeRedis(server=server, decode_responses=True)
    old_client = sentinel.dependencies._redis_client
    sentinel.dependencies._redis_client = client
    try:
        yield client
    finally:
        sentinel.dependencies._redis_client = old_client
        await client.aclose()


@pytest_asyncio.fixture
async def async_client(
    test_settings: Settings,
    mock_redis: fakeredis_aio.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """
    Async HTTP client for API testing.
    Overlays dependency overrides for test settings and fake Redis.
    """
    # Import app here to avoid premature import errors if main.py is still scaffolding
    from sentinel.main import app

    # Store test settings on app.state so middlewares can access them
    old_settings = getattr(app.state, "settings", None)
    app.state.settings = test_settings

    # Apply dependency overrides
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_redis] = lambda: mock_redis

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    # Clear overrides and restore settings after test
    app.dependency_overrides.clear()
    app.state.settings = old_settings
