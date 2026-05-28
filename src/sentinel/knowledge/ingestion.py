"""
Document Ingestion: Secure ingestion pipeline with magic bytes check and moderation.

Chapter 8 — Knowledge Base: Document upload security validation.
"""

from __future__ import annotations

import hashlib
import mimetypes
from typing import Any
import uuid

import structlog

from sentinel.config import Settings
from sentinel.knowledge.store import add_document
from sentinel.layers.content_moderator import moderate_content
from sentinel.services.llm_client import LLMClient

logger = structlog.get_logger(__name__)

# Permitted file types for the enterprise knowledge base
ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/markdown",
    "application/json",
    "text/csv",
}


async def ingest_document(
    file_bytes: bytes,
    filename: str,
    classification_level: str,
    source: str,
    user_id: str,
    collection: Any,
    llm_client: LLMClient,
    settings: Settings,
) -> dict:
    """
    Process an uploaded document through safety boundaries:
    1. Read magic bytes to determine the actual MIME type (detect file spoofing).
    2. Check if the MIME type is in the ALLOWED_MIME_TYPES.
    3. Ensure content is valid UTF-8.
    4. Run content moderation check via Layer 6 content moderator.
    5. Generate vector embedding and store in ChromaDB.

    Raises ValueError if validation fails.
    """
    logger.info("starting_document_ingestion", filename=filename, size_bytes=len(file_bytes))

    # 1. Magic bytes detection to prevent file extension spoofing
    mime_type = None
    try:
        import magic  # type: ignore[import]
        # Inspect magic bytes from buffer
        mime_type = magic.from_buffer(file_bytes, mime=True)
        logger.info("magic_bytes_detected_mime", filename=filename, mime_type=mime_type)
    except Exception as e:
        logger.warning("magic_bytes_detection_failed_using_mimetypes_fallback", error=str(e))
        # Fall back to extension guess if libmagic is unavailable/fails
        mime, _ = mimetypes.guess_type(filename)
        mime_type = mime or "application/octet-stream"

    # 2. Enforce allowed MIME types list
    if mime_type not in ALLOWED_MIME_TYPES:
        logger.warning("ingestion_blocked_unsupported_mime", filename=filename, mime_type=mime_type)
        raise ValueError(
            f"Unsupported file type '{mime_type}'. Only plain text, Markdown, "
            "and JSON files are permitted for ingestion."
        )

    # 3. Ensure valid UTF-8 text decoding
    try:
        content = file_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        logger.warning("ingestion_blocked_unicode_decode_error", filename=filename)
        raise ValueError("File content is not valid UTF-8 encoded text.") from e

    # 4. Content moderation check (pre-DB check)
    mod_result = await moderate_content(
        text=content,
        direction="input",
        user_id=user_id,
        settings=settings,
    )
    if not mod_result.passed:
        logger.warning(
            "ingestion_blocked_moderation_failed",
            filename=filename,
            reason=mod_result.reason,
        )
        raise ValueError(f"Document content rejected by safety moderation: {mod_result.reason}")

    # 5. Generate unique document ID (SHA-256 of content to prevent duplicate indexing)
    doc_id = hashlib.sha256(content.encode("utf-8")).hexdigest()

    # 6. Generate embedding vector
    embedding = await llm_client.get_embedding(content)

    # 7. Add to ChromaDB store
    await add_document(
        collection=collection,
        doc_id=doc_id,
        content=content,
        source=source,
        classification_level=classification_level,
        embedding=embedding,
    )

    logger.info("document_ingestion_success", filename=filename, doc_id=doc_id)

    return {
        "document_id": doc_id,
        "filename": filename,
        "status": "indexed",
        "mime_type": mime_type,
        "chunks": 1,
    }
