"""
FastAPI HTTP Middleware for JWT Authentication.

Chapter 11 — Agent Identity & Authentication: Middleware enforcement.
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel.auth.jwt_handler import verify_token
from sentinel.dependencies import get_settings

logger = structlog.get_logger(__name__)

# Endpoints that are accessible without a valid Bearer JWT.
PUBLIC_PATHS = {
    "/health",
    "/auth/login",
    "/docs",
    "/redoc",
    "/openapi.json",
}


class JWTAuthenticationMiddleware(BaseHTTPMiddleware):
    """
    HTTP middleware validating Bearer JWT access tokens on incoming requests.
    Excludes public paths and OPTIONS preflight requests.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        path = request.url.path

        # 1. Skip auth checks for public routes
        if path in PUBLIC_PATHS or path.startswith(("/docs", "/redoc", "/openapi")):
            return await call_next(request)

        # 2. Skip auth for CORS preflight
        if request.method == "OPTIONS":
            return await call_next(request)

        # 3. Extract authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response(
                content=json.dumps({
                    "detail": "Missing or malformed authorization credentials.",
                    "error_code": "UNAUTHORIZED",
                }),
                status_code=401,
                media_type="application/json",
            )

        token = auth_header.split(" ", 1)[1]
        settings = getattr(request.app.state, "settings", None) or get_settings()

        try:
            # /auth/refresh requires a refresh token; all other secured routes require access tokens
            expected_type = "refresh" if path == "/auth/refresh" else "access"
            payload = verify_token(token, settings, expected_type=expected_type)

            # Store verified user info in request state
            request.state.user = {
                "username": payload["sub"],
                "role": payload["role"],
            }
        except Exception as e:
            logger.warning(
                "auth_failed",
                path=path,
                error=str(e),
            )
            return Response(
                content=json.dumps({
                    "detail": f"Authentication failed: {str(e)}",
                    "error_code": "UNAUTHORIZED",
                }),
                status_code=401,
                media_type="application/json",
            )

        return await call_next(request)


def get_current_user(request: Request) -> dict[str, Any]:
    """
    FastAPI dependency to retrieve the authenticated user profile from request state.
    """
    if not hasattr(request.state, "user"):
        # This fallback is a fail-close mechanism
        from fastapi import HTTPException
        raise HTTPException(
            status_code=401,
            detail="User not authenticated.",
        )
    return request.state.user
