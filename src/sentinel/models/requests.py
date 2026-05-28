"""
Pydantic request schemas for Sentinel AI.

Chapter 2 — Input Validator: API Request Validation.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    """Schema for incoming chat messages."""
    message: str = Field(
        ...,
        min_length=1,
        description="The raw user message to process.",
    )
    session_id: str | None = Field(
        None,
        description="Optional session/conversation identifier for threat monitoring.",
    )
    include_context: bool = Field(
        True,
        description="Whether to retrieve and include document context (RAG).",
    )


class DocumentUploadRequest(BaseModel):
    """Schema for document upload metadata."""
    classification_level: str = Field(
        "public",
        description="Security classification: public, internal, confidential, or restricted.",
    )
    source: str = Field(
        ...,
        min_length=1,
        description="Source metadata (e.g. hr_policies, internal_docs).",
    )
