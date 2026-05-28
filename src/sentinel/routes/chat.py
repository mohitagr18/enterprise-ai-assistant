"""
FastAPI Router for Chat Operations.

Chapter 8 — Pipeline Orchestrator & API Integration: Chat Router.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
import redis.asyncio as aioredis

from sentinel.auth.middleware import get_current_user
from sentinel.config import Settings
from sentinel.dependencies import get_chroma_collection, get_redis, get_settings
from sentinel.models.requests import ChatRequest
from sentinel.models.responses import ChatResponse, ErrorResponse
from sentinel.services.llm_client import LLMClient
from sentinel.services.pipeline import SecurityPipeline

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Chat"])


@router.post(
    "/chat",
    response_model=ChatResponse,
    responses={
        200: {"model": ChatResponse, "description": "Successful chat completion."},
        202: {"model": ErrorResponse, "description": "High-stakes action pending human approval."},
        400: {"model": ErrorResponse, "description": "Request blocked by safety layers (input validation, budget, etc.)."},
        403: {"model": ErrorResponse, "description": "Blocked by Agent Identity or Threat Monitor lockout."},
        500: {"model": ErrorResponse, "description": "Unhandled system error."},
    },
)
async def chat(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
    redis: aioredis.Redis = Depends(get_redis),
    chroma_collection = Depends(get_chroma_collection),
) -> ChatResponse | JSONResponse:
    """
    Submit a message to the assistant.
    The message will pass through all 12 security layers of Sentinel.
    """
    user_id = current_user["username"]
    user_role = current_user["role"]

    logger.info("incoming_chat_request", user_id=user_id, role=user_role)

    # Instantiate LLMClient (re-uses AsyncOpenAI client)
    llm_client = LLMClient(settings)

    # Instantiate the Security Pipeline
    pipeline = SecurityPipeline(
        settings=settings,
        redis_conn=redis,
        chroma_collection=chroma_collection,
        llm_client=llm_client,
    )

    # Run the 12-layer pipeline
    response = await pipeline.run_pipeline(
        request=request,
        user_id=user_id,
        user_role=user_role,
    )

    if isinstance(response, ChatResponse):
        return response

    # If it is an ErrorResponse, map the error code to appropriate HTTP status codes
    error_code = response.error_code
    status_code = status.HTTP_400_BAD_REQUEST

    if error_code == "PENDING_HUMAN_APPROVAL":
        status_code = status.HTTP_202_ACCEPTED
    elif error_code in ("AGENT_IDENTITY_VIOLATION", "THREAT_MONITOR_BLOCKED"):
        status_code = status.HTTP_403_FORBIDDEN
    elif error_code == "INTERNAL_SERVER_ERROR":
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    logger.warning(
        "chat_request_blocked",
        user_id=user_id,
        error_code=error_code,
        status_code=status_code,
        reason=response.detail,
    )

    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(),
    )
