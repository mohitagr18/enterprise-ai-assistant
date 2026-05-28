"""
Tests for Layer 8 — Output Validator.

Chapter 9 — Output Validator: Verification.
"""

from __future__ import annotations

import pytest

from sentinel.config import Settings
from sentinel.layers.output_validator import FALLBACK_RESPONSE, validate_output


@pytest.mark.asyncio
async def test_output_validator_happy_path(test_settings: Settings) -> None:
    """
    Happy path: Verify that well-formed LLM JSON output is parsed and validated
    successfully against the response schema.
    """
    raw_output = '{"response": "The Q4 targets have been successfully retrieved and validated."}'
    result = await validate_output(raw_output, test_settings)

    assert result.passed is True
    assert result.details["response"] == "The Q4 targets have been successfully retrieved and validated."


@pytest.mark.asyncio
async def test_output_validator_traceback_attack(test_settings: Settings) -> None:
    """
    Attack scenario: Verify that LLM output containing raw Python tracebacks or
    exceptions is caught and the safe fallback response is returned instead.
    """
    # 1. Raw python traceback
    traceback_output = (
        '{"response": "Here is your data: Traceback (most recent call last):\n'
        '  File \\"main.py\\", line 12, in <module>\n'
        '    result = 1 / 0\n'
        'ZeroDivisionError: division by zero"}'
    )
    result_tb = await validate_output(traceback_output, test_settings)
    assert result_tb.passed is False
    assert result_tb.details["error_type"] == "error_leakage_detected"
    assert result_tb.details["fallback_response"] == FALLBACK_RESPONSE

    # 2. Database Error / API exception leak
    api_error_output = (
        '{"response": "Error: openai.BadRequestError: The requested model is not available."}'
    )
    result_api = await validate_output(api_error_output, test_settings)
    assert result_api.passed is False
    assert result_api.details["error_type"] == "error_leakage_detected"
    assert result_api.details["fallback_response"] == FALLBACK_RESPONSE


@pytest.mark.asyncio
async def test_output_validator_retry_on_trailing_comma(test_settings: Settings) -> None:
    """
    Edge case: LLM returns almost-valid JSON (e.g. trailing comma).
    The first parse fails, and a retry (simulated here) with corrected JSON succeeds.
    """
    # 1. First parse fails (almost-valid JSON with trailing comma)
    almost_valid_json = '{"response": "Corrected information",}'
    result_1 = await validate_output(almost_valid_json, test_settings)
    assert result_1.passed is False
    assert result_1.details["error_type"] == "json_parse_error"
    assert result_1.details["fallback_response"] == FALLBACK_RESPONSE

    # 2. Retry succeeds after receiving format reminder (simulated via corrected output)
    corrected_json = '{"response": "Corrected information"}'
    result_2 = await validate_output(corrected_json, test_settings)
    assert result_2.passed is True
    assert result_2.details["response"] == "Corrected information"
