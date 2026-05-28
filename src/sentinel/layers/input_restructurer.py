"""
Layer 4 — Input Restructurer: Token budget enforcement and input normalization.

Defends against:
  - Token-bombing attacks designed to exhaust context windows.
  - Excessive costs caused by maliciously large user prompts.
"""

from __future__ import annotations

import tiktoken

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult


async def restructure_input(text: str, settings: Settings) -> LayerResult:
    """
    Count tokens in user input using tiktoken and truncate if it exceeds the limit.
    Always passes (passed=True) but modifies/restructures the text as needed.
    """
    layer_name = "input_restructurer"

    try:
        # Get the appropriate tiktoken encoding for the configured model
        encoding = tiktoken.get_encoding(settings.TIKTOKEN_ENCODING)
    except Exception:
        # Fall back to default o200k_base (GPT-4o) if encoding load fails
        encoding = tiktoken.get_encoding("o200k_base")

    # Encode raw text to tokens
    tokens = encoding.encode(text)
    original_count = len(tokens)

    if original_count > settings.INPUT_MAX_TOKENS:
        # Truncate to the maximum allowed tokens
        truncated_tokens = tokens[:settings.INPUT_MAX_TOKENS]
        truncated_text = encoding.decode(truncated_tokens)

        # Append a clear system notice about truncation to prevent confusing the model
        restructured_text = (
            truncated_text
            + "\n\n[System Notice: The preceding user message was truncated to fit security token budget constraints.]"
        )
        final_count = len(encoding.encode(restructured_text))
    else:
        restructured_text = text
        final_count = original_count

    return LayerResult(
        layer_name=layer_name,
        passed=True,
        details={
            "restructured_text": restructured_text,
            "original_token_count": original_count,
            "final_token_count": final_count,
            "truncated": original_count > settings.INPUT_MAX_TOKENS,
        },
    )
