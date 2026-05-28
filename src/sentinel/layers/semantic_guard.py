"""
Layer 2 — Semantic Guard: Machine Learning prompt safety checks.

Defends against:
  - Complex, semantic prompt injections
  - High toxicity or abusive prompts
  - Queries referencing banned organizational topics
"""

from __future__ import annotations

import structlog
from fastapi.concurrency import run_in_threadpool

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult

logger = structlog.get_logger(__name__)

# Module-level singletons for lazy-loading model instances
_prompt_injection_scanner = None
_toxicity_scanner = None
_ban_topics_scanner = None


def _get_scanners(settings: Settings) -> dict[str, Any]:
    """
    Lazy load and initialize llm-guard scanners once.
    This prevents loading models on module import.
    """
    global _prompt_injection_scanner, _toxicity_scanner, _ban_topics_scanner

    # Lazy import to allow failing closed if llm-guard package or model files are unavailable
    from llm_guard.input_scanners import BanTopics, PromptInjection, Toxicity

    if _prompt_injection_scanner is None:
        _prompt_injection_scanner = PromptInjection()
    if _toxicity_scanner is None:
        _toxicity_scanner = Toxicity()
    if _ban_topics_scanner is None:
        _ban_topics_scanner = BanTopics(
            topics=settings.SEMANTIC_GUARD_BANNED_TOPICS,
            threshold=settings.SEMANTIC_GUARD_THRESHOLD,
        )

    return {
        "prompt_injection": _prompt_injection_scanner,
        "toxicity": _toxicity_scanner,
        "ban_topics": _ban_topics_scanner,
    }


async def check_semantic_safety(text: str, settings: Settings) -> LayerResult:
    """
    Validate the input text using ML-based scanners (llm-guard).
    Runs scanners inside a thread pool to avoid blocking the ASGI event loop.
    Fails closed on any scanner exception or timeout.
    """
    layer_name = "semantic_guard"
    timeout = getattr(settings, "SEMANTIC_GUARD_TIMEOUT", 10.0)

    async def _run_scans() -> LayerResult:
        try:
            # Execute scanner initialization inside thread pool to prevent blocking the ASGI event loop
            scanners = await run_in_threadpool(_get_scanners, settings)
        except Exception as e:
            logger.error("semantic_guard_initialization_failed", error=str(e))
            if settings.SEMANTIC_GUARD_FAIL_CLOSED:
                return LayerResult(
                    layer_name=layer_name,
                    passed=False,
                    reason=f"Semantic safety check failed closed on initialization: {str(e)}.",
                )
            return LayerResult(layer_name=layer_name, passed=True)

        details = {}
        blocked_scanners = []

        for name, scanner in scanners.items():
            try:
                # Execute the CPU-heavy scan synchronously inside a thread pool
                _, is_valid, risk_score = await run_in_threadpool(scanner.scan, text)
                details[name] = risk_score

                # Block if scanner flags it, or risk score exceeds the threshold
                if not is_valid or risk_score > settings.SEMANTIC_GUARD_THRESHOLD:
                    blocked_scanners.append(name)
            except Exception as e:
                logger.error("semantic_scanner_execution_failed", scanner=name, error=str(e))
                if settings.SEMANTIC_GUARD_FAIL_CLOSED:
                    return LayerResult(
                        layer_name=layer_name,
                        passed=False,
                        reason=f"Semantic safety check failed closed on scanner '{name}': {str(e)}.",
                    )

        if blocked_scanners:
            return LayerResult(
                layer_name=layer_name,
                passed=False,
                reason=(
                    f"Request rejected: Semantic security check blocked by scanners: {', '.join(blocked_scanners)}. "
                    "This input references restricted policy topics (e.g., weapons manufacturing, illegal drugs) "
                    "or prompt injection patterns."
                ),
                details={"scores": details, "blocked_scanners": blocked_scanners},
            )

        return LayerResult(
            layer_name=layer_name,
            passed=True,
            details={"scores": details},
        )

    try:
        import asyncio
        return await asyncio.wait_for(_run_scans(), timeout=timeout)
    except asyncio.TimeoutError as te:
        logger.error("semantic_guard_timeout", timeout=timeout, error=str(te))
        if settings.SEMANTIC_GUARD_FAIL_CLOSED:
            return LayerResult(
                layer_name=layer_name,
                passed=False,
                reason=(
                    "Request rejected: Semantic safety check failed closed. "
                    f"Scanner execution timed out after {timeout}s under our fail-closed security policy."
                ),
            )
        return LayerResult(layer_name=layer_name, passed=True)
    except Exception as e:
        logger.error("semantic_guard_unexpected_error", error=str(e))
        if settings.SEMANTIC_GUARD_FAIL_CLOSED:
            return LayerResult(
                layer_name=layer_name,
                passed=False,
                reason=f"Semantic safety check failed closed on unexpected error: {str(e)}.",
            )
        return LayerResult(layer_name=layer_name, passed=True)
