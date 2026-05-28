"""
Layer 8 — Output Validator: Schema enforcement and error surface hardening.

Defends against:
  - Malformed LLM responses that violate the expected JSON schema.
  - Leakage of raw system errors, tracebacks, or API exceptions to the user.
"""

from __future__ import annotations

import json
import re
from typing import Any

import structlog
from pydantic import BaseModel, Field, ValidationError

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult

logger = structlog.get_logger(__name__)

# Safe fallback message returned when output validation fails
FALLBACK_RESPONSE = (
    "I apologize, but I encountered an internal error while processing the response. "
    "Please try your request again."
)

# Common indicators of tracebacks, exceptions, or raw backend errors
ERROR_PATTERNS = [
    "traceback (most recent call last):",
    "zerodivisionerror:",
    "valueerror:",
    "typeerror:",
    "keyerror:",
    "syntaxerror:",
    "nameerror:",
    "attributeerror:",
    "indexerror:",
    "modulenotfounderror:",
    "openai.error.",
    "badrequesterror",
    "database error:",
    "internal server error",
    "unhandled exception",
]


class LLMResponseSchema(BaseModel):
    """
    The structured JSON schema expected from the LLM.
    The orchestrator or LLM client prompts the model to output JSON matching this structure.
    """
    response: str = Field(..., description="The assistant's text response to the user.")


async def validate_output(raw_output: str, settings: Settings) -> LayerResult:
    """
    Validate the raw LLM output against the expected JSON schema and check for
    exposed backend error surfaces (tracebacks, API logs).

    Input:
      - raw_output: The raw text string returned by the LLM
      - settings: The application Settings instance

    Output:
      - LayerResult with passed=True and parsed JSON dict in details.
        If validation fails, returns passed=False with the safe fallback response.
    """
    layer_name = "output_validator"

    # 1. Error Surface Hardening: Scan for tracebacks, internal server errors, or SDK exceptions
    normalized_output = raw_output.lower()
    for pattern in ERROR_PATTERNS:
        if pattern in normalized_output:
            logger.error(
                "output_validation_error_surface_detected",
                pattern_matched=pattern,
            )
            return LayerResult(
                layer_name=layer_name,
                passed=False,
                reason="Raw error surface detected in output.",
                details={
                    "fallback_response": FALLBACK_RESPONSE,
                    "error_type": "error_leakage_detected",
                },
            )

    # 2. Schema Enforcement: Parse and validate JSON
    try:
        parsed_data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        logger.warning(
            "output_validation_json_parse_failed",
            error=str(e),
            raw_output_snippet=raw_output[:100],
        )
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"Failed to parse LLM output as JSON: {str(e)}",
            details={
                "fallback_response": FALLBACK_RESPONSE,
                "error_type": "json_parse_error",
            },
        )

    try:
        # Validate using Pydantic model
        validated = LLMResponseSchema.model_validate(parsed_data)
        logger.info("output_validation_success")
        return LayerResult(
            layer_name=layer_name,
            passed=True,
            details=validated.model_dump(),
        )
    except ValidationError as e:
        logger.warning(
            "output_validation_schema_violation",
            error=str(e),
        )
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"LLM output violated response schema: {str(e)}",
            details={
                "fallback_response": FALLBACK_RESPONSE,
                "error_type": "schema_validation_error",
            },
        )
