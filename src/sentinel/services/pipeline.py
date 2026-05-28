"""
Pipeline Orchestrator: Central coordination of all 12 security layers.

Chapter 8 — Pipeline Orchestrator: Implementation.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
import redis.asyncio as aioredis

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult
from sentinel.models.requests import ChatRequest
from sentinel.models.responses import ChatResponse, ErrorResponse, TokenUsage
from sentinel.services.llm_client import LLMClient
from sentinel.layers import (
    validate_input,
    check_semantic_safety,
    build_hardened_prompt,
    restructure_input,
    check_token_budget,
    increment_token_usage,
    moderate_content,
    isolate_context,
    validate_output,
    log_audit_event,
    AuditEvent,
    enforce_agent_identity,
    check_human_gate,
    monitor_threats,
)

logger = structlog.get_logger(__name__)


class SecurityPipeline:
    """
    Central orchestration service coordinating the request lifecycle through
    all security layers. Fail-closed on security violations and infrastructure errors.
    """

    def __init__(
        self,
        settings: Settings,
        redis_conn: aioredis.Redis,
        chroma_collection: Any,
        llm_client: LLMClient,
    ):
        self.settings = settings
        self.redis = redis_conn
        self.chroma_collection = chroma_collection
        self.llm_client = llm_client

    def _detect_action_category(self, text: str) -> str | None:
        """
        Scan response text to detect if any gated actions are requested.
        Maps keywords to standard gated actions for Layer 11 Human Gate validation.
        """
        normalized = text.lower()
        if "delete" in normalized or "deletion" in normalized:
            return "data_deletion"
        if "change policy" in normalized or "update policy" in normalized:
            return "policy_change"
        if "approve transfer" in normalized or "payment" in normalized or "wire money" in normalized:
            return "financial_approval"
        if "grant access" in normalized or "grant privilege" in normalized:
            return "access_grant"
        if "configure system" in normalized or "modify config" in normalized:
            return "system_configuration"
        return None

    async def run_pipeline(
        self,
        request: ChatRequest,
        user_id: str,
        user_role: str,
    ) -> ChatResponse | ErrorResponse:
        """
        Execute the full 12-layer security pipeline for a user message.
        """
        start_time = time.perf_counter()
        session_id = request.session_id or f"session_{uuid.uuid4().hex}"
        
        layers_fired: list[str] = []
        layers_blocked: dict[str, str] = {}
        token_counts = {"input": 0, "output": 0}
        
        current_layer_results: list[LayerResult] = []
        processing_time_ms = 0

        try:
            # --------------------------------------------------------------
            # Layer 1 — Input Validator
            # --------------------------------------------------------------
            val_res = await validate_input(request.message, self.settings)
            layers_fired.append(val_res.layer_name)
            current_layer_results.append(val_res)
            if not val_res.passed:
                layers_blocked[val_res.layer_name] = val_res.reason
                await monitor_threats(
                    user_id=user_id,
                    session_id=session_id,
                    layer_results=current_layer_results,
                    redis_conn=self.redis,
                    settings=self.settings,
                )
                return ErrorResponse(
                    detail=val_res.reason,
                    error_code="INPUT_VALIDATION_FAILED",
                    session_id=session_id,
                )

            # --------------------------------------------------------------
            # Layer 2 — Semantic Guard
            # --------------------------------------------------------------
            sem_res = await check_semantic_safety(request.message, self.settings)
            layers_fired.append(sem_res.layer_name)
            current_layer_results.append(sem_res)
            if not sem_res.passed:
                layers_blocked[sem_res.layer_name] = sem_res.reason
                await monitor_threats(
                    user_id=user_id,
                    session_id=session_id,
                    layer_results=current_layer_results,
                    redis_conn=self.redis,
                    settings=self.settings,
                )
                return ErrorResponse(
                    detail=sem_res.reason,
                    error_code="SEMANTIC_GUARD_BLOCKED",
                    session_id=session_id,
                )

            # --------------------------------------------------------------
            # Layer 4 — Input Restructurer (Enforces token limit, always passes)
            # --------------------------------------------------------------
            rest_res = await restructure_input(request.message, self.settings)
            layers_fired.append(rest_res.layer_name)
            current_layer_results.append(rest_res)
            
            restructured_text = rest_res.details["restructured_text"]
            estimated_input_tokens = rest_res.details["final_token_count"]
            token_counts["input"] = estimated_input_tokens

            # --------------------------------------------------------------
            # Layer 5 — Token Budget
            # --------------------------------------------------------------
            bud_res = await check_token_budget(
                user_id=user_id,
                estimated_tokens=estimated_input_tokens,
                user_role=user_role,
                redis_conn=self.redis,
                settings=self.settings,
            )
            layers_fired.append(bud_res.layer_name)
            current_layer_results.append(bud_res)
            if not bud_res.passed:
                layers_blocked[bud_res.layer_name] = bud_res.reason
                await monitor_threats(
                    user_id=user_id,
                    session_id=session_id,
                    layer_results=current_layer_results,
                    redis_conn=self.redis,
                    settings=self.settings,
                )
                return ErrorResponse(
                    detail=bud_res.reason,
                    error_code="TOKEN_BUDGET_EXHAUSTED",
                    session_id=session_id,
                )

            # --------------------------------------------------------------
            # Layer 10 — Agent Identity (Scope check before LLM invocation)
            # --------------------------------------------------------------
            requested_sources = ["internal_docs"] if request.include_context else []
            requested_actions = ["answer_question"]
            
            ident_res = await enforce_agent_identity(
                user_role=user_role,
                requested_sources=requested_sources,
                requested_actions=requested_actions,
                settings=self.settings,
            )
            layers_fired.append(ident_res.layer_name)
            current_layer_results.append(ident_res)
            if not ident_res.passed:
                layers_blocked[ident_res.layer_name] = ident_res.reason
                await monitor_threats(
                    user_id=user_id,
                    session_id=session_id,
                    layer_results=current_layer_results,
                    redis_conn=self.redis,
                    settings=self.settings,
                )
                return ErrorResponse(
                    detail=ident_res.reason,
                    error_code="AGENT_IDENTITY_VIOLATION",
                    session_id=session_id,
                )

            # --------------------------------------------------------------
            # Layer 6 — Content Moderator (INPUT direction)
            # --------------------------------------------------------------
            mod_in_res = await moderate_content(
                text=restructured_text,
                direction="input",
                user_id=user_id,
                settings=self.settings,
            )
            layers_fired.append(mod_in_res.layer_name)
            current_layer_results.append(mod_in_res)
            if not mod_in_res.passed:
                layers_blocked[mod_in_res.layer_name] = mod_in_res.reason
                await monitor_threats(
                    user_id=user_id,
                    session_id=session_id,
                    layer_results=current_layer_results,
                    redis_conn=self.redis,
                    settings=self.settings,
                )
                return ErrorResponse(
                    detail=mod_in_res.reason,
                    error_code="CONTENT_MODERATION_BLOCKED",
                    session_id=session_id,
                )

            # --------------------------------------------------------------
            # Layer 12 — Threat Monitor
            # --------------------------------------------------------------
            threat_res = await monitor_threats(
                user_id=user_id,
                session_id=session_id,
                layer_results=current_layer_results,
                redis_conn=self.redis,
                settings=self.settings,
            )
            layers_fired.append(threat_res.layer_name)
            if not threat_res.passed:
                layers_blocked[threat_res.layer_name] = threat_res.reason
                return ErrorResponse(
                    detail=threat_res.reason,
                    error_code="THREAT_MONITOR_BLOCKED",
                    session_id=session_id,
                )

            # --------------------------------------------------------------
            # Retrieval & Layer 7 — Context Isolator
            # --------------------------------------------------------------
            wrapped_docs: list[str] = []
            if request.include_context and self.chroma_collection is not None:
                from sentinel.knowledge.retrieval import retrieve_context
                
                # Fetch similar documents
                retrieved_docs = await retrieve_context(
                    query=restructured_text,
                    collection=self.chroma_collection,
                    llm_client=self.llm_client,
                    limit=5,
                )
                
                # Filter and wrap them
                context_res = await isolate_context(
                    documents=retrieved_docs,
                    user_role=user_role,
                    settings=self.settings,
                )
                layers_fired.append(context_res.layer_name)
                current_layer_results.append(context_res)
                if not context_res.passed:
                    layers_blocked[context_res.layer_name] = context_res.reason
                    return ErrorResponse(
                        detail=context_res.reason,
                        error_code="CONTEXT_ISOLATION_FAILED",
                        session_id=session_id,
                    )
                wrapped_docs = context_res.details.get("wrapped_documents", [])

            # --------------------------------------------------------------
            # Layer 3 — System Prompt Hardener
            # --------------------------------------------------------------
            system_prompt = build_hardened_prompt(
                context_documents=wrapped_docs,
                settings=self.settings,
            )
            layers_fired.append("system_prompt_hardener")

            # --------------------------------------------------------------
            # ★ LLM INVOCATION
            # --------------------------------------------------------------
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": restructured_text},
            ]
            raw_output = await self.llm_client.create_chat_completion(messages)

            # --------------------------------------------------------------
            # Layer 8 — Output Validator (with retry logic)
            # --------------------------------------------------------------
            out_val_res = await validate_output(raw_output, self.settings)
            layers_fired.append(out_val_res.layer_name)
            current_layer_results.append(out_val_res)
            
            if not out_val_res.passed:
                error_type = out_val_res.details.get("error_type")
                # Retry once if it is a formatting/schema issue (not traceback/error leakage)
                if error_type in ("json_parse_error", "schema_validation_error"):
                    logger.warning("llm_output_invalid_attempting_retry", error=out_val_res.reason)
                    retry_messages = messages + [
                        {"role": "assistant", "content": raw_output},
                        {
                            "role": "user",
                            "content": (
                                "Format reminder: Your output must be a valid JSON object "
                                "matching the schema: {\"response\": \"your text response here\"}."
                            ),
                        },
                    ]
                    # Invoke LLM again
                    raw_output_retry = await self.llm_client.create_chat_completion(retry_messages)
                    # Re-validate
                    out_val_res = await validate_output(raw_output_retry, self.settings)
                    layers_fired.append(f"{out_val_res.layer_name}_retry")
                    current_layer_results.append(out_val_res)

            # If validation still failed (or blocked by traceback detection)
            if not out_val_res.passed:
                layers_blocked[out_val_res.layer_name] = out_val_res.reason
                return ErrorResponse(
                    detail=out_val_res.details.get("fallback_response", "Internal validation error."),
                    error_code="OUTPUT_VALIDATION_FAILED",
                    session_id=session_id,
                )

            # Extract validated content text
            response_text = out_val_res.details["response"]

            # --------------------------------------------------------------
            # Layer 6 — Content Moderator (OUTPUT direction)
            # --------------------------------------------------------------
            mod_out_res = await moderate_content(
                text=response_text,
                direction="output",
                user_id=user_id,
                settings=self.settings,
            )
            layers_fired.append(f"{mod_out_res.layer_name}_output")
            current_layer_results.append(mod_out_res)
            if not mod_out_res.passed:
                layers_blocked[f"{mod_out_res.layer_name}_output"] = mod_out_res.reason
                return ErrorResponse(
                    detail=mod_out_res.reason,
                    error_code="CONTENT_MODERATION_BLOCKED",
                    session_id=session_id,
                )

            # --------------------------------------------------------------
            # Layer 11 — Human Gate (intercept high-stakes actions)
            # --------------------------------------------------------------
            # Detect gated action from either the user's input or the LLM's response
            action_category = self._detect_action_category(request.message) or self._detect_action_category(response_text)
            gate_res = await check_human_gate(
                action_category=action_category,
                user_id=user_id,
                redis_conn=self.redis,
                settings=self.settings,
            )
            layers_fired.append(gate_res.layer_name)
            current_layer_results.append(gate_res)
            if not gate_res.passed:
                layers_blocked[gate_res.layer_name] = gate_res.reason
                return ErrorResponse(
                    detail=gate_res.reason,
                    error_code="PENDING_HUMAN_APPROVAL",
                    session_id=session_id,
                    details=gate_res.details,
                )

            # --------------------------------------------------------------
            # Budget Post-Incr: Count output tokens and record daily usage
            # --------------------------------------------------------------
            try:
                import tiktoken
                encoding = tiktoken.get_encoding(self.settings.TIKTOKEN_ENCODING)
            except Exception:
                encoding = tiktoken.get_encoding("o200k_base")
            
            output_tokens = len(encoding.encode(response_text))
            token_counts["output"] = output_tokens

            # Increment usage in Redis
            total_tokens = token_counts["input"] + token_counts["output"]
            await increment_token_usage(
                user_id=user_id,
                actual_tokens=total_tokens,
                redis_conn=self.redis,
            )

            processing_time_ms = int((time.perf_counter() - start_time) * 1000)

            # Gather all executed layer details
            results_dict = {}
            for res in current_layer_results:
                key = res.layer_name
                if key == "content_moderator" and res.details.get("direction") == "output":
                    key = "content_moderator_output"
                results_dict[key] = {
                    "passed": res.passed,
                    "reason": res.reason,
                    "details": res.details,
                }

            return ChatResponse(
                response=response_text,
                session_id=session_id,
                tokens_used=TokenUsage(
                    input=token_counts["input"],
                    output=token_counts["output"],
                ),
                layers_fired=layers_fired,
                layer_results=results_dict,
                processing_time_ms=processing_time_ms,
            )

        except Exception as e:
            logger.error("pipeline_unhandled_failure", error=str(e))
            processing_time_ms = int((time.perf_counter() - start_time) * 1000)
            return ErrorResponse(
                detail="An unhandled system error occurred. Please try again.",
                error_code="INTERNAL_SERVER_ERROR",
                session_id=session_id,
            )

        finally:
            # --------------------------------------------------------------
            # Layer 9 — Audit Logger (Fires unconditionally on every request)
            # --------------------------------------------------------------
            try:
                input_hash = hashlib.sha256(request.message.encode("utf-8")).hexdigest()
                event = AuditEvent(
                    user_id=user_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    request_hash=input_hash,
                    layers_fired=layers_fired,
                    layers_blocked=layers_blocked,
                    token_counts=token_counts,
                    response_time_ms=processing_time_ms,
                    session_id=session_id,
                )
                await log_audit_event(event, self.settings)
            except Exception as audit_err:
                logger.error("audit_log_generation_failed", error=str(audit_err))
