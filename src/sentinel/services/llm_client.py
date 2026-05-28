"""
LLM Client: Async OpenAI client wrapper with retry and timeout.

Chapter 8 — Knowledge Base: LLM Client integration.
"""

from __future__ import annotations

import asyncio
from typing import Any

from openai import AsyncOpenAI
import structlog

from sentinel.config import Settings

logger = structlog.get_logger(__name__)


class LLMClient:
    """
    Wrapper around the official AsyncOpenAI SDK.
    Centralises error handling, timeouts, and exponential backoff retry logic.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        api_key = settings.OPENAI_API_KEY or "mock-key"
        self.client = AsyncOpenAI(
            api_key=api_key,
            timeout=settings.OPENAI_TIMEOUT_SECONDS,
        )

    async def create_chat_completion(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        temperature: float = 0.0,
    ) -> str:
        """
        Request a chat completion with retry logic.
        """
        model = self.settings.OPENAI_CHAT_MODEL
        max_tokens = max_tokens or self.settings.OPENAI_MAX_RESPONSE_TOKENS
        retries = 3
        backoff = 0.5  # short backoff for responsive API calls

        for attempt in range(1, retries + 1):
            try:
                response = await self.client.chat.completions.create(
                    model=model,
                    messages=messages,  # type: ignore[arg-type]
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                content = response.choices[0].message.content
                return content or ""
            except Exception as e:
                logger.warning(
                    "llm_chat_completion_attempt_failed",
                    attempt=attempt,
                    retries=retries,
                    error=str(e),
                )
                if attempt == retries:
                    logger.error("llm_chat_completion_failed_exhausted", error=str(e))
                    raise RuntimeError(f"LLM chat completion failed after {retries} attempts: {str(e)}") from e
                await asyncio.sleep(backoff)
                backoff *= 2.0

        return ""

    async def get_embedding(self, text: str) -> list[float]:
        """
        Generate a text embedding vector with retry logic.
        """
        model = self.settings.OPENAI_EMBEDDING_MODEL
        retries = 3
        backoff = 0.5

        for attempt in range(1, retries + 1):
            try:
                response = await self.client.embeddings.create(
                    model=model,
                    input=text,
                )
                return response.data[0].embedding
            except Exception as e:
                logger.warning(
                    "llm_embedding_attempt_failed",
                    attempt=attempt,
                    retries=retries,
                    error=str(e),
                )
                if attempt == retries:
                    logger.error("llm_embedding_failed_exhausted", error=str(e))
                    raise RuntimeError(f"LLM embedding failed after {retries} attempts: {str(e)}") from e
                await asyncio.sleep(backoff)
                backoff *= 2.0

        return []
