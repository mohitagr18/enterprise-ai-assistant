"""
Layer 6 — Content Moderator: OpenAI Moderation API compliance filter.

Defends against:
  - Toxic, hateful, self-harm, or violent user prompts reaching the model (input).
  - Model jailbreaks generating unsafe or non-compliant output (output).
"""

from __future__ import annotations

from datetime import datetime, timezone

import structlog
from openai import AsyncOpenAI

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult

logger = structlog.get_logger(__name__)

# Single client instance reused across requests to benefit from connection pooling
_openai_client: AsyncOpenAI | None = None


def _get_client(settings: Settings) -> AsyncOpenAI:
    """Initialize and retrieve the shared AsyncOpenAI client."""
    global _openai_client
    if _openai_client is None:
        # Require API key in production, but allow mock during tests
        api_key = settings.OPENAI_API_KEY or "mock-key"
        _openai_client = AsyncOpenAI(
            api_key=api_key,
            timeout=settings.OPENAI_TIMEOUT_SECONDS,
        )
    return _openai_client


async def moderate_content(
    text: str,
    direction: str,
    user_id: str,
    settings: Settings,
) -> LayerResult:
    """
    Evaluate content safety via the OpenAI Moderation API.
    Fails closed if the OpenAI service is unreachable or errors.
    """
    layer_name = "content_moderator"

    # Quick skip if disabled in settings
    if not settings.CONTENT_MODERATION_ENABLED:
        return LayerResult(
            layer_name=layer_name,
            passed=True,
            details={"skipped": True, "direction": direction},
        )

    try:
        client = _get_client(settings)
        # Invoke Moderation API
        response = await client.moderations.create(
            model=settings.MODERATION_MODEL,
            input=text,
        )
        result = response.results[0]

        if result.flagged:
            # Collect flagged categories and their matching scores
            categories_dict = dict(result.categories)
            scores_dict = dict(result.category_scores)
            flagged_categories = [cat for cat, flagged in categories_dict.items() if flagged]
            scores = {
                cat: scores_dict.get(cat, 0.0)
                for cat in flagged_categories
            }

            logger.warning(
                "content_blocked_by_moderation",
                user_id=user_id,
                direction=direction,
                flagged_categories=flagged_categories,
            )

            return LayerResult(
                layer_name=layer_name,
                passed=False,
                reason=f"Content blocked by safety policy ({direction}).",
                details={
                    "direction": direction,
                    "flagged_categories": flagged_categories,
                    "category_scores": scores,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )

    except Exception as e:
        logger.error(
            "moderation_api_call_failed",
            user_id=user_id,
            direction=direction,
            error=str(e),
        )
        # Fail closed for maximum safety
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=f"Safety verification failed closed due to network/service outage ({direction}).",
            details={
                "direction": direction,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    return LayerResult(
        layer_name=layer_name,
        passed=True,
        details={
            "direction": direction,
            "flagged": False,
        },
    )
