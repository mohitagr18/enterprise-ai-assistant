"""
Layer 1 — Input Validator: Basic request sanitation and policy checks.

Defends against:
  - Null byte injections (\x00)
  - Oversized or empty payloads (DoS)
  - Simple, regex-based prompt injection signatures
"""

from __future__ import annotations

import re

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult


async def validate_input(raw_input: str, settings: Settings) -> LayerResult:
    """
    Validate the raw user input against basic policy rules:
    - Block null bytes if configured.
    - Check min and max length bounds.
    - Match against a list of blocked regex signatures.
    """
    layer_name = "input_validator"

    # 1. Null byte detection (common payload escape vector)
    if settings.INPUT_BLOCK_NULL_BYTES and "\x00" in raw_input:
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason="Null byte detected.",
        )

    # 2. Minimum length check (prevent empty prompts)
    stripped = raw_input.strip()
    if len(stripped) < settings.INPUT_MIN_LENGTH:
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"Input is too short (minimum {settings.INPUT_MIN_LENGTH} characters).",
        )

    # 3. Maximum length check (prevent context exhaustion / DoS)
    if len(raw_input) > settings.INPUT_MAX_LENGTH:
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"Input exceeds maximum length of {settings.INPUT_MAX_LENGTH} characters.",
        )

    # 4. Pattern matching (block known prompt injection signatures)
    for pattern in settings.INPUT_INJECTION_PATTERNS:
        try:
            # Match case-insensitively anywhere in the input
            regex = re.compile(pattern, re.IGNORECASE)
            if regex.search(raw_input):
                return LayerResult(
                    layer_name=layer_name,
                    passed=False,
                    reason=(
                        f"Request rejected: Injection pattern match detected ('{pattern}'). "
                        "This input contains patterns associated with prompt manipulation or system overrides."
                    ),
                )
        except re.error:
            # Fall back to substring match if pattern is not valid regex syntax
            if pattern.lower() in raw_input.lower():
                return LayerResult(
                    layer_name=layer_name,
                    passed=False,
                    reason=(
                        f"Request rejected: Injection pattern match detected ('{pattern}'). "
                        "This input contains patterns associated with prompt manipulation or system overrides."
                    ),
                )

    return LayerResult(
        layer_name=layer_name,
        passed=True,
    )
