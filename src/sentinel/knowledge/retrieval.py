"""
Retrieval: High-level semantic search retrieval function for context building.

Chapter 8 — Knowledge Base: Document retrieval.
"""

from __future__ import annotations

from typing import Any

import structlog

from sentinel.knowledge.store import query_similar_documents
from sentinel.services.llm_client import LLMClient

logger = structlog.get_logger(__name__)


async def retrieve_context(
    query: str,
    collection: Any,
    llm_client: LLMClient,
    limit: int = 5,
) -> list[dict]:
    """
    Given a user query, generate its vector embedding using LLMClient
    and query the vector store to retrieve similar documents.
    """
    logger.info("retrieving_context_for_query", query_length=len(query), limit=limit)

    # 1. Generate search vector embedding using LLM Client
    embedding = await llm_client.get_embedding(query)

    # 2. Search against ChromaDB
    documents = await query_similar_documents(
        collection=collection,
        query_embedding=embedding,
        limit=limit,
    )

    logger.info("context_retrieval_finished", count=len(documents))
    return documents
