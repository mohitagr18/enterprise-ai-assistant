"""
Tests for Layer 10 — Agent Identity.

Chapter 11 — Agent Identity: Verification.
"""

from __future__ import annotations

import pytest

from sentinel.config import Settings
from sentinel.layers.agent_identity import enforce_agent_identity


@pytest.mark.asyncio
async def test_agent_identity_happy_path(test_settings: Settings) -> None:
    """
    Happy path: A standard user requesting access to an allowed source with an
    allowed action passes.
    """
    # standard (rank 0) <= power_user (rank 1, default max ceiling)
    result = await enforce_agent_identity(
        user_role="standard",
        requested_sources=["internal_docs", "company_wiki"],
        requested_actions=["answer_question"],
        settings=test_settings,
    )
    assert result.passed is True


@pytest.mark.asyncio
async def test_agent_identity_admin_exceeds_scope(test_settings: Settings) -> None:
    """
    Attack scenario: An admin user attempting to access an unauthorized source
    is blocked. Even admin cannot exceed agent scope.
    """
    # First, let's configure settings so admin (rank 2) is allowed by ceiling
    test_settings.AGENT_MAX_PRIVILEGE = "admin"

    # Requesting source 'financial_ledger' which is not in AGENT_ALLOWED_SOURCES
    result = await enforce_agent_identity(
        user_role="admin",
        requested_sources=["internal_docs", "financial_ledger"],
        requested_actions=["answer_question"],
        settings=test_settings,
    )
    assert result.passed is False
    assert "unauthorized knowledge source requested" in result.reason.lower()


@pytest.mark.asyncio
async def test_agent_identity_ceiling_exceeded(test_settings: Settings) -> None:
    """
    Edge case: A user with role "power_user" when AGENT_MAX_PRIVILEGE is "standard"
    is blocked because their role exceeds the agent's ceiling.
    """
    test_settings.AGENT_MAX_PRIVILEGE = "standard"

    # power_user (rank 1) > standard (rank 0) -> blocked
    result = await enforce_agent_identity(
        user_role="power_user",
        requested_sources=["internal_docs"],
        requested_actions=["answer_question"],
        settings=test_settings,
    )
    assert result.passed is False
    assert "exceeds the maximum authorized privilege level" in result.reason.lower()
