"""
FastAPI Routes for Authentication.

Chapter 11 — Agent Identity & Authentication: Endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from sentinel.auth.jwt_handler import create_access_token, create_refresh_token, verify_token
from sentinel.auth.password import hash_password, verify_password
from sentinel.config import Settings
from sentinel.dependencies import get_settings
from sentinel.models.auth import UserCredentials

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Pre-populate static user data with hashed credentials for testing/demonstration.
# In production, these are stored and queried in a secure relational database.
MOCK_USER_DB = {
    "admin": {
        "password_hash": hash_password("adminpass123"),
        "role": "admin",
    },
    "poweruser": {
        "password_hash": hash_password("powerpass123"),
        "role": "power_user",
    },
    "standarduser": {
        "password_hash": hash_password("userpass123"),
        "role": "standard",
    },
}


class TokenResponse(BaseModel):
    """Schema for successful authentication response containing tokens."""
    access_token: str = Field(..., description="JWT access token.")
    refresh_token: str = Field(..., description="JWT refresh token.")
    token_type: str = Field("bearer", description="Token scheme.")
    expires_in: int = Field(..., description="Access token lifetime in seconds.")


class RefreshRequest(BaseModel):
    """Schema for refresh token request."""
    refresh_token: str = Field(..., description="Valid JWT refresh token.")


class RefreshResponse(BaseModel):
    """Schema for access token renewal response."""
    access_token: str = Field(..., description="New JWT access token.")
    expires_in: int = Field(..., description="New access token lifetime in seconds.")


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: UserCredentials,
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    """
    Authenticate user credentials and issue access and refresh tokens.
    """
    user = MOCK_USER_DB.get(credentials.username)
    if not user or not verify_password(user["password_hash"], credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    access_token = create_access_token(credentials.username, user["role"], settings)
    refresh_token = create_refresh_token(credentials.username, user["role"], settings)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_SECONDS,
    )


@router.post("/refresh", response_model=RefreshResponse)
async def refresh(
    body: RefreshRequest,
    settings: Settings = Depends(get_settings),
) -> RefreshResponse:
    """
    Validate refresh token and issue a new access token.
    """
    try:
        payload = verify_token(body.refresh_token, settings, expected_type="refresh")
        username = payload["sub"]
        role = payload["role"]

        access_token = create_access_token(username, role, settings)
        return RefreshResponse(
            access_token=access_token,
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_SECONDS,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired refresh token: {str(e)}",
        )


@router.post("/logout")
async def logout() -> dict[str, str]:
    """
    Logout the active user session.
    """
    # In a stateless JWT environment, clients discard their tokens.
    # TODO(security): Implement blacklisting of active tokens in Redis on logout.
    return {"message": "Logged out successfully"}
