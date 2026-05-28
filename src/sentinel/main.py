"""
FastAPI application entrypoint for Sentinel AI.

Chapter 1 — Architecture: Secure App Bootstrap.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel.auth.middleware import JWTAuthenticationMiddleware
from sentinel.auth.routes import router as auth_router
from sentinel.config import Settings
from sentinel.dependencies import close_redis, get_settings, init_chromadb, init_redis
from sentinel.logging_setup import setup_logging
from sentinel.middleware.rate_limiter import RateLimitingMiddleware
from sentinel.middleware.security_headers import SecurityHeadersMiddleware

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI lifespan context manager for startup and shutdown hooks.
    """
    settings = get_settings()

    # 1. Setup structured logging
    setup_logging(settings)
    logger.info("sentinel_starting", version="1.0.0")

    # 2. Initialize database connections
    await init_redis(settings)
    init_chromadb(settings)

    yield

    # 3. Graceful shutdown
    logger.info("sentinel_shutting_down")
    await close_redis()


app = FastAPI(
    title="Sentinel AI — Enterprise AI Assistant",
    description="A production-grade, secure by design internal corporate copilot.",
    version="1.0.0",
    lifespan=lifespan,
)

settings = get_settings()
app.state.settings = settings

# Middleware Stack (added in reverse order of execution)

# 1. Outermost: CORS validation (restricting domains and methods)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# 2. Security Headers (appends hardening headers like CSP, X-Frame-Options)
app.add_middleware(SecurityHeadersMiddleware)

# 3. Rate Limiter (sliding window protection against API abuse)
app.add_middleware(RateLimitingMiddleware)

# 4. JWT Authentication (stateless token extraction and validation)
app.add_middleware(JWTAuthenticationMiddleware)

# Register routes
app.include_router(auth_router)
