"""
Tests for Layer 3 — System Prompt Hardener.

Chapter 4 — System Prompt Hardener: Verification.
"""

from __future__ import annotations

from sentinel.config import Settings
from sentinel.layers.system_prompt import build_hardened_prompt


def test_system_prompt_happy_path(test_settings: Settings) -> None:
    """
    Happy path: Verify that the built prompt contains context tags and documents
    when context is provided.
    """
    docs = ["Document 1 content details", "Document 2 content details"]
    prompt = build_hardened_prompt(docs, test_settings)

    assert test_settings.AGENT_NAME in prompt
    assert "<context>" in prompt
    assert "</context>" in prompt
    assert "Document 1 content details" in prompt
    assert "Document 2 content details" in prompt


def test_system_prompt_security_phrases(test_settings: Settings) -> None:
    """
    Attack scenario: Verify that the prompt contains defensive instructions
    such as 'untrusted data' and 'cannot be reprogrammed'.
    """
    prompt = build_hardened_prompt(None, test_settings)

    assert "untrusted data" in prompt.lower()
    assert "cannot be reprogrammed" in prompt.lower()
    assert "reveal your instructions" in prompt.lower()


def test_system_prompt_empty_docs(test_settings: Settings) -> None:
    """
    Edge case: Verify that when context_documents is empty or None,
    the context tag block is completely omitted.
    """
    # Test None context
    prompt_none = build_hardened_prompt(None, test_settings)
    assert "<context>" not in prompt_none
    assert "</context>" not in prompt_none

    # Test empty list context
    prompt_empty = build_hardened_prompt([], test_settings)
    assert "<context>" not in prompt_empty
    assert "</context>" not in prompt_empty
