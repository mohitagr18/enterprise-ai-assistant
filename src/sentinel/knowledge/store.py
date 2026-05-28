"""
Knowledge Store: ChromaDB collection management and raw database operations.

Chapter 8 — Knowledge Base: Vector database storage.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class KnowledgeStore:
    """
    ChromaDB collection management and wrapper.
    Encapsulates raw vector database interactions behind clean static methods.
    """

    @staticmethod
    async def add_document(
        collection: Any,
        doc_id: str,
        content: str,
        source: str,
        classification_level: str,
        embedding: list[float],
    ) -> None:
        """
        Upsert a document along with its vector embedding and security metadata.
        """
        try:
            collection.add(
                ids=[doc_id],
                embeddings=[embedding],
                metadatas=[
                    {
                        "source": source,
                        "classification_level": classification_level,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                documents=[content],
            )
            logger.info(
                "document_added_to_vector_db",
                doc_id=doc_id,
                source=source,
                classification_level=classification_level,
            )
        except Exception as e:
            logger.error("failed_to_add_document_to_vector_db", doc_id=doc_id, error=str(e))
            raise RuntimeError(f"Database error writing document: {str(e)}") from e

    @staticmethod
    async def delete_document(collection: Any, doc_id: str) -> None:
        """
        Remove a document from the vector store by its ID.
        """
        try:
            collection.delete(ids=[doc_id])
            logger.info("document_deleted_from_vector_db", doc_id=doc_id)
        except Exception as e:
            logger.error("failed_to_delete_document_from_vector_db", doc_id=doc_id, error=str(e))
            raise RuntimeError(f"Database error deleting document: {str(e)}") from e

    @staticmethod
    async def query_similar_documents(
        collection: Any,
        query_embedding: list[float],
        limit: int = 5,
    ) -> list[dict]:
        """
        Perform a cosine similarity search against the vector store using the query embedding.
        Converts ChromaDB outputs to our standard document dictionary format.
        """
        try:
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=limit,
            )

            retrieved_docs = []
            if results and results.get("ids") and len(results["ids"]) > 0:
                ids = results["ids"][0]
                documents = results.get("documents", [[]])[0] or []
                metadatas = results.get("metadatas", [[]])[0] or []

                now_str = datetime.now(timezone.utc).isoformat()

                for i in range(len(ids)):
                    meta = metadatas[i] if i < len(metadatas) else {}
                    doc_content = documents[i] if i < len(documents) else ""
                    retrieved_docs.append(
                        {
                            "id": ids[i],
                            "content": doc_content,
                            "source": meta.get("source", "unknown"),
                            "classification_level": meta.get("classification_level", "public"),
                            "retrieval_timestamp": now_str,
                        }
                    )

            logger.info("vector_db_query_completed", results_count=len(retrieved_docs))
            return retrieved_docs
        except Exception as e:
            logger.error("vector_db_query_failed", error=str(e))
            raise RuntimeError(f"Database query error: {str(e)}") from e

    @staticmethod
    async def list_documents(
        collection: Any,
        offset: int = 0,
        limit: int = 20,
    ) -> tuple[list[dict], int]:
        """
        List stored documents with offset/limit pagination. Returns a tuple of
        (document list, total count).
        """
        try:
            results = collection.get(
                offset=offset,
                limit=limit,
                include=["metadatas", "documents"],
            )
            total = collection.count()

            ids = results.get("ids", [])
            documents = results.get("documents") or []
            metadatas = results.get("metadatas") or []

            docs = []
            for i in range(len(ids)):
                meta = metadatas[i] if i < len(metadatas) else {}
                doc_content = documents[i] if i < len(documents) else ""
                docs.append(
                    {
                        "id": ids[i],
                        "content": doc_content,
                        "source": meta.get("source", "unknown"),
                        "classification_level": meta.get("classification_level", "public"),
                        "created_at": meta.get("created_at"),
                    }
                )

            return docs, total
        except Exception as e:
            logger.error("failed_to_list_documents", error=str(e))
            raise RuntimeError(f"Database listing error: {str(e)}") from e


# Keep module-level aliases for direct imports and backwards-compatibility
add_document = KnowledgeStore.add_document
delete_document = KnowledgeStore.delete_document
query_similar_documents = KnowledgeStore.query_similar_documents
list_documents = KnowledgeStore.list_documents
