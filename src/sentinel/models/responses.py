"""
Pydantic response schemas for Sentinel AI.

Chapter 9 — Output Validator: Schema enforcement and error surface hardening.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class TokenUsage(BaseModel):
    """Schema for tracking token consumption."""
    input: int = Field(0, description="Number of input tokens processed.")
    output: int = Field(0, description="Number of output tokens generated.")


class ChatResponse(BaseModel):
    """Schema for successful chat response."""
    response: str = Field(..., description="The assistant's response text.")
    session_id: str = Field(..., description="Session identifier.")
    tokens_used: TokenUsage = Field(
        default_factory=TokenUsage,
        description="Tokens consumed by the request.",
    )
    layers_fired: list[str] = Field(
        default_factory=list,
        description="The list of security layers that evaluated this request.",
    )
    processing_time_ms: int = Field(
        ...,
        description="Processing time in milliseconds.",
    )


class ErrorResponse(BaseModel):
    """Schema for structured error responses when a layer blocks or API fails."""
    detail: str = Field(..., description="A safe, user-friendly error message.")
    error_code: str = Field(..., description="Specific security or API error code.")
    session_id: str | None = Field(None, description="Active session ID if available.")
    details: dict[str, Any] | None = Field(
        None,
        description="Additional non-sensitive details about the block (e.g. human gate details).",
    )


class ApprovalResponse(BaseModel):
    """Schema for action approval decision response."""
    status: str = Field(..., description="Approval status: approved or rejected.")
    token: str = Field(..., description="The approval token identifier.")
    action: str = Field(..., description="The action category that required approval.")
