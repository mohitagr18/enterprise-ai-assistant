"""
FastAPI Router for Document Knowledge Base (RAG) Operations.

Chapter 8 — Knowledge Base & API Integration: Documents Router.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field

from sentinel.auth.middleware import get_current_user
from sentinel.config import Settings
from sentinel.dependencies import get_chroma_collection, get_settings
from sentinel.knowledge.ingestion import ingest_document
from sentinel.knowledge.store import delete_document, list_documents
from sentinel.services.llm_client import LLMClient

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/documents", tags=["Documents"])


class DocumentMetaData(BaseModel):
    """Schema for document representation in list responses."""
    id: str = Field(..., description="Document content hash.")
    source: str = Field(..., description="Source system/department identifier.")
    classification_level: str = Field(..., description="Document clearance classification.")
    created_at: str | None = Field(None, description="Ingestion UTC timestamp.")


class DocumentListResponse(BaseModel):
    """Schema for paginated document list responses."""
    documents: list[DocumentMetaData] = Field(..., description="List of documents.")
    total: int = Field(..., description="Total documents in the collection.")


class DocumentUploadResponse(BaseModel):
    """Schema for successful document ingestion response."""
    document_id: str = Field(..., description="Document content hash.")
    filename: str = Field(..., description="Filename uploaded.")
    status: str = Field(..., description="Status of ingestion (e.g. indexed).")
    chunks: int = Field(..., description="Number of vector chunks generated.")


@router.post(
    "",
    response_model=DocumentUploadResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"model": DocumentUploadResponse, "description": "Document successfully indexed."},
        400: {"description": "Validation failure (unsupported MIME, bad UTF-8, toxic content)."},
        403: {"description": "Insufficient clearance role."},
    },
)
async def upload_document(
    file: UploadFile = File(...),
    classification_level: str = Form("public"),
    source: str = Form(...),
    current_user: dict = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
    chroma_collection = Depends(get_chroma_collection),
) -> DocumentUploadResponse:
    """
    Ingest a new document into the internal knowledge base.
    Restricted to admin and power_user roles.
    Checks file magic bytes (prevent spoofing) and runs moderation checks.
    """
    # 1. Enforce Role clearance for document creation
    role = current_user["role"]
    if role not in ("admin", "power_user"):
        logger.warning(
            "document_upload_forbidden",
            user_id=current_user["username"],
            role=role,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Insufficient privileges to upload documents.",
        )

    # Validate classification level
    allowed_levels = settings.CLASSIFICATION_LEVELS
    if isinstance(allowed_levels, str):
        allowed_levels = [l.strip() for l in allowed_levels.split(",") if l.strip()]

    if classification_level not in allowed_levels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid classification_level. Must be one of: {allowed_levels}",
        )

    # 2. Read bytes and parse
    try:
        content_bytes = await file.read()
        llm_client = LLMClient(settings)

        result = await ingest_document(
            file_bytes=content_bytes,
            filename=file.filename or "unknown",
            classification_level=classification_level,
            source=source,
            user_id=current_user["username"],
            collection=chroma_collection,
            llm_client=llm_client,
            settings=settings,
        )

        return DocumentUploadResponse(
            document_id=result["document_id"],
            filename=result["filename"],
            status=result["status"],
            chunks=result["chunks"],
        )
    except ValueError as val_err:
        # Expected validation exceptions (magic bytes mismatch, toxic content, etc.)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        logger.error("document_upload_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal database error indexing document: {str(exc)}",
        )


@router.get(
    "",
    response_model=DocumentListResponse,
    responses={
        200: {"model": DocumentListResponse, "description": "Paginated document list."},
        401: {"description": "Unauthorized session."},
    },
)
async def get_documents(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    chroma_collection = Depends(get_chroma_collection),
) -> DocumentListResponse:
    """
    List all documents in the knowledge base with pagination.
    Accessible by all authenticated users.
    """
    try:
        offset = (page - 1) * limit
        docs, total = await list_documents(chroma_collection, offset=offset, limit=limit)
        
        # Format response
        formatted_docs = []
        for d in docs:
            formatted_docs.append(
                DocumentMetaData(
                    id=d["id"],
                    source=d["source"],
                    classification_level=d["classification_level"],
                    created_at=d.get("created_at"),
                )
            )

        return DocumentListResponse(documents=formatted_docs, total=total)
    except Exception as exc:
        logger.error("list_documents_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query knowledge base documents: {str(exc)}",
        )


@router.delete(
    "/{id}",
    responses={
        200: {"description": "Document deleted successfully."},
        403: {"description": "Forbidden: Requires admin privileges."},
        500: {"description": "Internal database deletion failure."},
    },
)
async def remove_document(
    id: str,
    current_user: dict = Depends(get_current_user),
    chroma_collection = Depends(get_chroma_collection),
) -> dict[str, str]:
    """
    Remove a document from the vector store by its ID.
    Restricted to admin role only.
    """
    # Enforce role clearance
    role = current_user["role"]
    if role != "admin":
        logger.warning(
            "document_deletion_forbidden",
            user_id=current_user["username"],
            role=role,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Admin privileges required to delete documents.",
        )

    try:
        await delete_document(chroma_collection, id)
        return {
            "message": "Document deleted successfully",
            "document_id": id,
        }
    except Exception as exc:
        logger.error("document_deletion_failed", doc_id=id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete document from database: {str(exc)}",
        )
