"""
JWT creation, verification, and decoding with algorithm enforcement.

Chapter 11 — Agent Identity & Authentication: Stateless session management.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt, JWTError

from sentinel.config import Settings


def create_access_token(username: str, role: str, settings: Settings) -> str:
    """
    Create a signed JWT access token.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(seconds=settings.JWT_ACCESS_TOKEN_EXPIRE_SECONDS)
    payload = {
        "sub": username,
        "role": role,
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "type": "access",
    }
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(username: str, role: str, settings: Settings) -> str:
    """
    Create a signed JWT refresh token.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(seconds=settings.JWT_REFRESH_TOKEN_EXPIRE_SECONDS)
    payload = {
        "sub": username,
        "role": role,
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "type": "refresh",
    }
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def verify_token(
    token: str,
    settings: Settings,
    expected_type: str = "access",
) -> dict[str, Any]:
    """
    Decode and verify a JWT token.

    Defends against:
      - Algorithm 'none' attack via explicit header check.
      - Algorithm substitution attack by hardcoding the expected algorithm list.
      - Expired tokens via verification validation.
    """
    try:
        # Pre-flight header check for defense-in-depth against 'none' algorithm bypass
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if not alg or alg.upper() == "NONE":
            raise JWTError("Algorithm 'none' is explicitly forbidden.")
        if alg != settings.JWT_ALGORITHM:
            raise JWTError(f"Unexpected algorithm '{alg}', expected '{settings.JWT_ALGORITHM}'.")

        # Perform full decoding and verification
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require_exp": True, "verify_exp": True},
        )

        # Validate token type
        token_type = payload.get("type")
        if token_type != expected_type:
            raise JWTError(f"Invalid token type: expected {expected_type}, got {token_type}.")

        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {str(e)}") from e
