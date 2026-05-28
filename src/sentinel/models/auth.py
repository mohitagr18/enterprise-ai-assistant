"""
Pydantic authentication schemas for Sentinel AI.

Chapter 11 — Agent Identity & Authentication context.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class UserCredentials(BaseModel):
    """Schema for authentication login request."""
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="The username of the user.",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="The password of the user.",
    )


class TokenPayload(BaseModel):
    """Schema for JWT token payload parsing and verification."""
    sub: str = Field(..., description="Subject of the token (typically user ID).")
    role: str = Field(..., description="The user's role (standard, power_user, admin).")
    exp: int = Field(..., description="Expiration epoch timestamp.")


class UserProfile(BaseModel):
    """Schema representing user profile details."""
    username: str = Field(..., description="The unique username.")
    role: str = Field(..., description="The assigned security role.")
    is_active: bool = Field(True, description="Account activation status.")
