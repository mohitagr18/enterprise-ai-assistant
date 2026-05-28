"""
FastAPI dependency providers for Sentinel AI.

Chapter 1 — Architecture: Dependency Injection as a Security Boundary

This module centralises all shared resource creation. FastAPI's dependency
injection system ensures that:
  - Redis and ChromaDB connections are created once at startup and shared.
  - A fakeredis instance is transparently substituted when REDIS_URL is unset,
    allowing the full project to run with zero external services.
  - The Settings singleton is injected into every route and layer that needs it,
    ensuring there is exactly one source of configuration truth.

No other module should import redis, chromadb, or Settings directly.
Always request them via FastAPI Depends().
"""

from __future__ import annotations

import structlog
from functools import lru_cache
from typing import AsyncGenerator

import redis.asyncio as aioredis
from fastapi import Depends

from sentinel.config import Settings

logger = structlog.get_logger(__name__)

# ------------------------------------------------------------------ #
# Settings — singleton via lru_cache
# ------------------------------------------------------------------ #


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the application Settings singleton.

    lru_cache ensures the .env file is parsed exactly once at startup.
    Override in tests with app.dependency_overrides[get_settings] = lambda: mock_settings.
    """
    return Settings()


# ------------------------------------------------------------------ #
# Redis — real or fakeredis fallback
# ------------------------------------------------------------------ #

# Module-level connection pool (created once per process).
_redis_client: aioredis.Redis | None = None


async def init_redis(settings: Settings) -> None:
    """
    Initialise the Redis connection pool at application startup.

    Called from the FastAPI lifespan context manager in main.py.
    If REDIS_URL is not set, falls back to fakeredis and logs a warning.
    """
    global _redis_client

    if _redis_client is not None:
        logger.info("redis_already_initialized")
        return

    if settings.REDIS_URL:
        _redis_client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        # Verify connection is alive at startup.
        await _redis_client.ping()
        logger.info("redis_connected", url=settings.REDIS_URL)
    else:
        # Lazy import so fakeredis is only required if REDIS_URL is absent.
        import fakeredis.aioredis as fakeredis_aio  # type: ignore[import]

        _redis_client = fakeredis_aio.FakeRedis(decode_responses=True)
        logger.warning(
            "redis_fallback",
            message=(
                "REDIS_URL not set. Using in-process fakeredis. "
                "Token budgets and rate limits will reset on restart. "
                "Set REDIS_URL in .env for persistent state."
            ),
        )


async def close_redis() -> None:
    """Close the Redis connection pool at application shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
        logger.info("redis_closed")


async def get_redis() -> AsyncGenerator[aioredis.Redis, None]:
    """
    FastAPI dependency that yields the shared Redis client.

    Usage in routes:
        async def my_route(redis: aioredis.Redis = Depends(get_redis)):
    """
    if _redis_client is None:
        raise RuntimeError(
            "Redis client not initialised. "
            "Ensure init_redis() is called in the application lifespan."
        )
    yield _redis_client


# ------------------------------------------------------------------ #
# ChromaDB — embedded, no server required
# ------------------------------------------------------------------ #

_chroma_client = None
_chroma_collection = None


def init_chromadb(settings: Settings) -> None:
    """
    Initialise the ChromaDB embedded client and ensure the collection exists.

    Called synchronously from the FastAPI lifespan context manager.
    ChromaDB is embedded (no server), so this just opens the local database file.
    """
    global _chroma_client, _chroma_collection

    import chromadb  # type: ignore[import]

    _chroma_client = chromadb.PersistentClient(path=settings.CHROMADB_PERSIST_DIR)
    _chroma_collection = _chroma_client.get_or_create_collection(
        name=settings.CHROMADB_COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    logger.info(
        "chromadb_ready",
        path=settings.CHROMADB_PERSIST_DIR,
        collection=settings.CHROMADB_COLLECTION_NAME,
    )


def get_chroma_collection():
    """
    FastAPI dependency that returns the shared ChromaDB collection.

    Usage in routes:
        async def my_route(collection = Depends(get_chroma_collection)):
    """
    if _chroma_collection is None:
        raise RuntimeError(
            "ChromaDB not initialised. "
            "Ensure init_chromadb() is called in the application lifespan."
        )
    return _chroma_collection
