"""
Phase 1 — Baseline Comparison: Naive Endpoint Simulator

This module defines a minimally-protected endpoint that represents what an
enterprise AI assistant would look like WITHOUT Sentinel AI's 12 security layers:
  - Accepts any input (no validation, no injection checks)
  - No semantic scanning
  - No token budget enforcement
  - No content moderation
  - No context isolation or role-based document filtering
  - No output validation
  - No human gate
  - No threat monitor / behavioral lockout
  - No audit logging

The naive baseline DOES retain:
  - Authentication (JWT) — because without auth you cannot meaningfully
    compare behavior; removing it would test a different system entirely
  - A simulated LLM call (mocked) — same mock used in the protected pipeline

This design makes the comparison fair: same input, same (mocked) LLM,
only the security middleware differs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class NaiveResult:
    """Result from the naive baseline endpoint."""
    payload: str
    outcome: str          # PASSED | ERROR
    response: str         # simulated LLM response or error message
    notes: str = ""


async def naive_endpoint(payload: str) -> NaiveResult:
    """
    Simulate a naive enterprise LLM endpoint with no meaningful security enforcement.

    This is deliberately minimal:
      - No input validation of any kind
      - No size/length limits
      - No injection pattern detection
      - No content moderation
      - No budget checks
      - No human gate
      - No threat monitoring
      - No audit logging

    The LLM call is mocked to return a generic response — the same response
    for all inputs (since we are comparing security behavior, not LLM quality).
    """
    # Minimal preprocessing: strip only (no null byte check, no length limit)
    text = payload.strip()

    # Empty input — even naive endpoints usually crash on empty
    if len(text) == 0:
        return NaiveResult(
            payload=payload,
            outcome="ERROR",
            response="Empty input received.",
            notes="Even naive endpoints reject completely empty input.",
        )

    # Simulate LLM call (no security processing before or after)
    # In a real naive endpoint, this would be: openai.ChatCompletion.create(...)
    simulated_response = (
        f"I received your message: '{text[:80]}{'...' if len(text) > 80 else ''}'. "
        "Here is my response as a helpful enterprise assistant."
    )

    return NaiveResult(
        payload=payload,
        outcome="PASSED",
        response=simulated_response,
        notes="No security layer evaluated this input.",
    )
