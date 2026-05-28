"""
Security Headers Middleware.

Chapter 3 — Security Headers: Defending against XSS, Clickjacking, and MIME sniffing.
"""

from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel.dependencies import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    HTTP middleware appending security hardening headers to all outgoing API responses.
    Defends against:
      - Clickjacking (X-Frame-Options, frame-ancestors)
      - MIME-sniffing exploits (X-Content-Type-Options)
      - Cross-Site Scripting (Content-Security-Policy, X-XSS-Protection)
      - Unwanted browser feature access (Permissions-Policy)
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)

        # 1. Content Security Policy (CSP) — strict defaults
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )

        # 2. Prevent clickjacking (fallback for older browsers not supporting CSP frame-ancestors)
        response.headers["X-Frame-Options"] = "DENY"

        # 3. Disable MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 4. Enforce XSS protection in legacy browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # 5. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 6. Disable access to sensitive browser features
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        # 7. Strict-Transport-Security (HSTS) in production
        settings = get_settings()
        if not settings.APP_DEBUG:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response
