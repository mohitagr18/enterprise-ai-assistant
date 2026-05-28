"""
Tests for Layer 6 — Content Moderator.

Chapter 7 — Content Moderator: Verification.
"""

from __future__ import annotations

from typing import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.config import Settings
from sentinel.layers.content_moderator import moderate_content


@pytest.fixture(autouse=True)
def reset_openai_client() -> Generator[None, None]:
    """Ensure the shared client instance is reset before and after each test."""
    import sentinel.layers.content_moderator

    sentinel.layers.content_moderator._openai_client = None
    yield
    sentinel.layers.content_moderator._openai_client = None


@pytest.mark.asyncio
async def test_content_moderator_happy_path(test_settings: Settings) -> None:
    """
    Happy path: A normal business question passes moderation in both directions.
    """
    # Create mock result structure matching OpenAI API
    mock_result = MagicMock()
    mock_result.flagged = False
    mock_response = MagicMock()
    mock_response.results = [mock_result]

    mock_create = AsyncMock(return_value=mock_response)

    with patch("openai.resources.AsyncModerations.create", mock_create):
        result = await moderate_content(
            text="How do I calculate standard deviation in python?",
            direction="input",
            user_id="user_123",
            settings=test_settings,
        )
        assert result.passed is True
        assert result.details["flagged"] is False
        mock_create.assert_called_once_with(
            model=test_settings.MODERATION_MODEL,
            input="How do I calculate standard deviation in python?",
        )


@pytest.mark.asyncio
async def test_content_moderator_hate_speech_flagged(test_settings: Settings) -> None:
    """
    Attack scenario: Verify that violent/hateful input is flagged and blocked.
    """
    # Create a mock result that is flagged for hate speech
    mock_result = MagicMock()
    mock_result.flagged = True
    
    mock_result.categories = {"hate": True, "violence": False}
    mock_result.category_scores = {"hate": 0.99, "violence": 0.01}

    mock_response = MagicMock()
    mock_response.results = [mock_result]
    mock_create = AsyncMock(return_value=mock_response)

    with patch("openai.resources.AsyncModerations.create", mock_create):
        result = await moderate_content(
            text="Insert hateful speech here...",
            direction="input",
            user_id="attacker_456",
            settings=test_settings,
        )
        assert result.passed is False
        assert "Content blocked by safety policy" in result.reason
        assert result.details["direction"] == "input"
        assert "hate" in result.details["flagged_categories"]
        assert result.details["category_scores"]["hate"] == 0.99


@pytest.mark.asyncio
async def test_content_moderator_fail_closed(test_settings: Settings) -> None:
    """
    Edge case: Verify that when the API is unreachable, the filter fails closed.
    """
    mock_create = AsyncMock(side_effect=RuntimeError("API Connection Timeout."))

    with patch("openai.resources.AsyncModerations.create", mock_create):
        result = await moderate_content(
            text="Hello world",
            direction="input",
            user_id="user_789",
            settings=test_settings,
        )
        assert result.passed is False
        assert "Safety verification failed closed" in result.reason
        assert result.details["error"] == "API Connection Timeout."
