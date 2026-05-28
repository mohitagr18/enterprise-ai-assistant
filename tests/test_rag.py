"""
Tests for Phase 7 — Knowledge Base (RAG Layer).

Chapter 8 — Knowledge Base: Verification.
"""

from __future__ import annotations

import sys
import uuid
from unittest.mock import MagicMock

# Mock out magic module to prevent libmagic import errors on systems without the C library
mock_magic = MagicMock()
sys.modules["magic"] = mock_magic

import pytest
from unittest.mock import AsyncMock, patch

import chromadb
from sentinel.config import Settings
from sentinel.services.llm_client import LLMClient
from sentinel.knowledge.store import KnowledgeStore
from sentinel.knowledge.retrieval import retrieve_context
from sentinel.knowledge.ingestion import ingest_document


@pytest.fixture
def mock_chroma_collection():
    """Create a temporary in-memory ChromaDB collection for testing."""
    client = chromadb.EphemeralClient()
    collection_name = f"test_collection_{uuid.uuid4().hex}"
    collection = client.get_or_create_collection(collection_name, metadata={"hnsw:space": "cosine"})
    return collection


@pytest.mark.asyncio
async def test_llm_client_chat_and_embeddings(test_settings: Settings) -> None:
    """
    Test LLMClient happy path and retry logic.
    """
    llm_client = LLMClient(test_settings)

    # 1. Test chat completion happy path
    mock_completion_response = MagicMock()
    mock_completion_choice = MagicMock()
    mock_completion_choice.message.content = "Chat response content"
    mock_completion_response.choices = [mock_completion_choice]
    
    mock_chat_create = AsyncMock(return_value=mock_completion_response)

    # 2. Test embedding happy path
    mock_embedding_response = MagicMock()
    mock_embedding_data = MagicMock()
    mock_embedding_data.embedding = [0.1, 0.2, 0.3]
    mock_embedding_response.data = [mock_embedding_data]

    mock_embedding_create = AsyncMock(return_value=mock_embedding_response)

    with patch("openai.resources.chat.completions.AsyncCompletions.create", mock_chat_create), \
         patch("openai.resources.embeddings.AsyncEmbeddings.create", mock_embedding_create):
         
        # Assert chat completion works
        chat_res = await llm_client.create_chat_completion([{"role": "user", "content": "Hello"}])
        assert chat_res == "Chat response content"

        # Assert embedding generation works
        embed_res = await llm_client.get_embedding("Hello")
        assert embed_res == [0.1, 0.2, 0.3]


@pytest.mark.asyncio
async def test_llm_client_retry_exhausted(test_settings: Settings) -> None:
    """
    Test LLMClient error handling: raises error after 3 failures.
    """
    llm_client = LLMClient(test_settings)
    mock_chat_create = AsyncMock(side_effect=RuntimeError("Connection lost"))

    with patch("openai.resources.chat.completions.AsyncCompletions.create", mock_chat_create), \
         patch("asyncio.sleep", AsyncMock()):  # Speed up retries
         
        with pytest.raises(RuntimeError) as exc_info:
            await llm_client.create_chat_completion([{"role": "user", "content": "Hello"}])
        assert "failed after 3 attempts" in str(exc_info.value)
        assert mock_chat_create.call_count == 3


@pytest.mark.asyncio
async def test_knowledge_store_crud(mock_chroma_collection) -> None:
    """
    Test KnowledgeStore add, list, query, and delete operations.
    """
    collection = mock_chroma_collection

    # 1. Add document
    await KnowledgeStore.add_document(
        collection=collection,
        doc_id="doc_a",
        content="This is document A content about Python development.",
        source="company_wiki",
        classification_level="internal",
        embedding=[1.0, 0.0, 0.0],
    )

    # 2. List documents
    docs, total = await KnowledgeStore.list_documents(collection, offset=0, limit=10)
    assert total == 1
    assert len(docs) == 1
    assert docs[0]["id"] == "doc_a"
    assert docs[0]["content"] == "This is document A content about Python development."
    assert docs[0]["source"] == "company_wiki"
    assert docs[0]["classification_level"] == "internal"

    # 3. Query document
    results = await KnowledgeStore.query_similar_documents(
        collection=collection,
        query_embedding=[0.9, 0.1, 0.0],
        limit=5,
    )
    assert len(results) == 1
    assert results[0]["id"] == "doc_a"

    # 4. Delete document
    await KnowledgeStore.delete_document(collection, "doc_a")
    docs_after, total_after = await KnowledgeStore.list_documents(collection, offset=0, limit=10)
    assert total_after == 0
    assert len(docs_after) == 0


@pytest.mark.asyncio
async def test_retrieval_semantic_search(mock_chroma_collection, test_settings: Settings) -> None:
    """
    Test retrieval context flow mapping query to embeddings and fetching matches.
    """
    collection = mock_chroma_collection

    # Populates two documents
    await KnowledgeStore.add_document(collection, "doc_1", "HR manual info", "hr", "public", [0.1, 0.9])
    await KnowledgeStore.add_document(collection, "doc_2", "IT policy info", "it", "public", [0.9, 0.1])

    # Mock LLMClient to return query vector matching doc_2
    llm_client = LLMClient(test_settings)
    mock_get_embedding = AsyncMock(return_value=[0.85, 0.15])

    with patch.object(llm_client, "get_embedding", mock_get_embedding):
        docs = await retrieve_context(
            query="Tell me about IT support",
            collection=collection,
            llm_client=llm_client,
            limit=1,
        )
        assert len(docs) == 1
        assert docs[0]["id"] == "doc_2"
        assert docs[0]["content"] == "IT policy info"


@pytest.mark.asyncio
async def test_ingestion_guards(mock_chroma_collection, test_settings: Settings) -> None:
    """
    Verify upload security:
    1. Happy path: Valid file content passes.
    2. MIME spoofing: Binary file disguised as txt is blocked.
    3. Moderation block: Toxic file is blocked.
    """
    collection = mock_chroma_collection
    llm_client = LLMClient(test_settings)

    # Mock embeddings & moderation passes
    mock_get_embedding = AsyncMock(return_value=[0.1, 0.2])
    
    mock_mod_response = MagicMock()
    mock_mod_response.results = [MagicMock(flagged=False)]
    mock_mod_create = AsyncMock(return_value=mock_mod_response)

    # 1. Happy path
    with patch.object(llm_client, "get_embedding", mock_get_embedding), \
         patch("openai.resources.AsyncModerations.create", mock_mod_create), \
         patch("magic.from_buffer", return_value="text/plain"):
         
        res = await ingest_document(
            file_bytes=b"This is safe document content.",
            filename="document.txt",
            classification_level="public",
            source="wiki",
            user_id="user_1",
            collection=collection,
            llm_client=llm_client,
            settings=test_settings,
        )
        assert res["status"] == "indexed"
        assert res["chunks"] == 1

    # 2. MIME spoofing attack (disguised binary executable payload)
    with patch.object(llm_client, "get_embedding", mock_get_embedding), \
         patch("openai.resources.AsyncModerations.create", mock_mod_create), \
         patch("magic.from_buffer", return_value="application/x-executable"):
         
        with pytest.raises(ValueError) as exc_info:
            await ingest_document(
                file_bytes=b"\x7fELF_binary_payload",
                filename="fake_doc.txt",  # looks like a text file extension, but bytes represent an ELF binary
                classification_level="public",
                source="wiki",
                user_id="user_1",
                collection=collection,
                llm_client=llm_client,
                settings=test_settings,
            )
        assert "Unsupported file type" in str(exc_info.value)

    # 3. Content moderation block (poisoned/toxic content in file)
    mock_mod_toxic_response = MagicMock()
    mock_mod_toxic_response.results = [MagicMock(flagged=True, categories={"hate": True}, category_scores={"hate": 0.98})]
    mock_mod_toxic_create = AsyncMock(return_value=mock_mod_toxic_response)

    with patch.object(llm_client, "get_embedding", mock_get_embedding), \
         patch("openai.resources.AsyncModerations.create", mock_mod_toxic_create), \
         patch("magic.from_buffer", return_value="text/plain"):
         
        with pytest.raises(ValueError) as exc_info:
            await ingest_document(
                file_bytes=b"Hateful toxic payload content here...",
                filename="document.txt",
                classification_level="public",
                source="wiki",
                user_id="user_1",
                collection=collection,
                llm_client=llm_client,
                settings=test_settings,
            )
        assert "moderation" in str(exc_info.value).lower()
