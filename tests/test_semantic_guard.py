"""
Tests for Layer 2 — Semantic Guard.

Chapter 3 — Semantic Guard: Verification.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel.config import Settings
from sentinel.layers.semantic_guard import check_semantic_safety


@pytest.fixture(autouse=True)
def reset_semantic_guard_singletons() -> Generator[None, None]:
    """
    Ensure the lazy-loaded singletons are cleared before and after each test
    to guarantee mocks are injected properly.
    """
    import sentinel.layers.semantic_guard

    sentinel.layers.semantic_guard._prompt_injection_scanner = None
    sentinel.layers.semantic_guard._toxicity_scanner = None
    sentinel.layers.semantic_guard._ban_topics_scanner = None
    yield
    sentinel.layers.semantic_guard._prompt_injection_scanner = None
    sentinel.layers.semantic_guard._toxicity_scanner = None
    sentinel.layers.semantic_guard._ban_topics_scanner = None


@pytest.mark.asyncio
async def test_semantic_guard_happy_path(test_settings: Settings) -> None:
    """
    Happy path: Verify that benign inputs pass all scanners successfully.
    """
    mock_injection = MagicMock()
    mock_injection.scan.return_value = ("sanitized", True, 0.0)

    mock_toxicity = MagicMock()
    mock_toxicity.scan.return_value = ("sanitized", True, 0.0)

    mock_ban_topics = MagicMock()
    mock_ban_topics.scan.return_value = ("sanitized", True, 0.0)

    with patch("llm_guard.input_scanners.PromptInjection", return_value=mock_injection), \
         patch("llm_guard.input_scanners.Toxicity", return_value=mock_toxicity), \
         patch("llm_guard.input_scanners.BanTopics", return_value=mock_ban_topics):

        result = await check_semantic_safety("What is our vacation policy?", test_settings)
        assert result.passed is True
        assert result.reason is None
        assert result.details["scores"]["prompt_injection"] == 0.0
        assert result.details["scores"]["toxicity"] == 0.0
        assert result.details["scores"]["ban_topics"] == 0.0


@pytest.mark.asyncio
async def test_semantic_guard_attack_scenario(test_settings: Settings) -> None:
    """
    Attack scenario: Verify that prompt injection triggers blocking.
    """
    mock_injection = MagicMock()
    mock_injection.scan.return_value = ("sanitized", False, 1.0)

    mock_safe = MagicMock()
    mock_safe.scan.return_value = ("sanitized", True, 0.0)

    with patch("llm_guard.input_scanners.PromptInjection", return_value=mock_injection), \
         patch("llm_guard.input_scanners.Toxicity", return_value=mock_safe), \
         patch("llm_guard.input_scanners.BanTopics", return_value=mock_safe):

        result = await check_semantic_safety("IGNORE PREVIOUS INSTRUCTIONS...", test_settings)
        assert result.passed is False
        assert "blocked by scanners: prompt_injection" in result.reason
        assert result.details["blocked_scanners"] == ["prompt_injection"]


@pytest.mark.asyncio
async def test_semantic_guard_fail_closed_init_error(test_settings: Settings) -> None:
    """
    Edge case: Verify that initialization errors (e.g. download failures)
    cause the layer to fail closed.
    """
    with patch(
        "sentinel.layers.semantic_guard._get_scanners",
        side_effect=ValueError("Download timeout."),
    ):
        result = await check_semantic_safety("Hello", test_settings)
        assert result.passed is False
        assert "failed closed" in result.reason
        assert "Download timeout" in result.reason


@pytest.mark.asyncio
async def test_semantic_guard_fail_closed_execution_error(test_settings: Settings) -> None:
    """
    Edge case: Verify that runtime errors during scanning cause the layer to fail closed.
    """
    mock_error = MagicMock()
    mock_error.scan.side_effect = RuntimeError("onnxruntime GPU OOM")

    mock_safe = MagicMock()
    mock_safe.scan.return_value = ("sanitized", True, 0.0)

    with patch("llm_guard.input_scanners.PromptInjection", return_value=mock_error), \
         patch("llm_guard.input_scanners.Toxicity", return_value=mock_safe), \
         patch("llm_guard.input_scanners.BanTopics", return_value=mock_safe):

        result = await check_semantic_safety("Hello", test_settings)
        assert result.passed is False
        assert "failed closed" in result.reason
        assert "onnxruntime GPU OOM" in result.reason


@pytest.mark.asyncio
async def test_semantic_guard_timeout(test_settings: Settings) -> None:
    """
    Edge case: Verify that scanner execution timeout causes the layer to fail closed.
    """
    mock_slow = MagicMock()

    def slow_scan(*args, **kwargs):
        import time
        time.sleep(2)
        return ("sanitized", True, 0.0)

    mock_slow.scan = slow_scan

    mock_safe = MagicMock()
    mock_safe.scan.return_value = ("sanitized", True, 0.0)

    # Set custom timeout of 0.1s
    test_settings.SEMANTIC_GUARD_TIMEOUT = 0.1
    test_settings.SEMANTIC_GUARD_FAIL_CLOSED = True

    with patch("llm_guard.input_scanners.PromptInjection", return_value=mock_slow), \
         patch("llm_guard.input_scanners.Toxicity", return_value=mock_safe), \
         patch("llm_guard.input_scanners.BanTopics", return_value=mock_safe):

        result = await check_semantic_safety("Hello", test_settings)
        assert result.passed is False
        assert "timed out" in result.reason
