"""
Tests for Layer 4 — Input Restructurer.

Chapter 5 — Input Restructurer: Verification.
"""

from __future__ import annotations

import pytest

from sentinel.config import Settings
from sentinel.layers.input_restructurer import restructure_input


@pytest.mark.asyncio
async def test_input_restructurer_happy_path(test_settings: Settings) -> None:
    """
    Happy path: Verify that inputs within the token limit are untouched.
    """
    text = "What is the capital of France?"
    result = await restructure_input(text, test_settings)

    assert result.passed is True
    assert result.details["truncated"] is False
    assert result.details["restructured_text"] == text
    assert result.details["original_token_count"] == result.details["final_token_count"]


@pytest.mark.asyncio
async def test_input_restructurer_token_bomb(test_settings: Settings) -> None:
    """
    Attack scenario: Verify that inputs exceeding the token limit are truncated
    and annotated with a system notice.
    """
    original_max = test_settings.INPUT_MAX_TOKENS
    test_settings.INPUT_MAX_TOKENS = 5  # Set small limit for easy testing

    try:
        text = "This is a sentence containing more than five tokens."
        result = await restructure_input(text, test_settings)

        assert result.passed is True
        assert result.details["truncated"] is True
        assert "System Notice: The preceding user message was truncated" in result.details["restructured_text"]
        assert result.details["original_token_count"] > 5
    finally:
        test_settings.INPUT_MAX_TOKENS = original_max


@pytest.mark.asyncio
async def test_input_restructurer_boundary_value(test_settings: Settings) -> None:
    """
    Edge case: Verify that an input with exactly the maximum allowed tokens
    passes through without truncation.
    """
    original_max = test_settings.INPUT_MAX_TOKENS
    test_settings.INPUT_MAX_TOKENS = 5

    try:
        # "one two three four five" yields exactly 5 tokens under o200k_base
        text = "one two three four five"
        result = await restructure_input(text, test_settings)

        assert result.passed is True
        assert result.details["truncated"] is False
        assert result.details["original_token_count"] == 5
        assert result.details["restructured_text"] == text
    finally:
        test_settings.INPUT_MAX_TOKENS = original_max
