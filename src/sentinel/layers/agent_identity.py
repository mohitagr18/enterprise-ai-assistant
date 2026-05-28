"""
Layer 10 — Agent Identity: Enforcement of privilege ceiling and interaction scope.

Defends against:
  - Privilege escalation attacks (forcing agent to act beyond ceiling).
  - Scope creep (accessing resources or actions outside agent's config).
"""

from __future__ import annotations

import structlog

from sentinel.config import Settings
from sentinel.models.layer_result import LayerResult

logger = structlog.get_logger(__name__)


async def enforce_agent_identity(
    user_role: str,
    requested_sources: list[str],
    requested_actions: list[str],
    settings: Settings,
) -> LayerResult:
    """
    Validate that:
    1. The user's role does not exceed the agent's maximum privilege rank (privilege ceiling).
    2. All requested data sources are within the agent's allowed sources list.
    3. All requested actions are within the agent's allowed actions list.

    Input:
      - user_role: The role of the requesting user (e.g. "standard", "admin")
      - requested_sources: List of knowledge/data sources requested
      - requested_actions: List of actions requested
      - settings: The application Settings instance

    Output:
      - LayerResult with passed=True if all checks succeed.
        Fails closed with passed=False and reason if any boundary is breached.
    """
    layer_name = "agent_identity"

    # Helper function to parse lists (handles strings from .env / lists from defaults.toml)
    def parse_list(val: str | list[str]) -> list[str]:
        if isinstance(val, str):
            return [x.strip() for x in val.split(",") if x.strip()]
        return val

    allowed_sources = parse_list(settings.AGENT_ALLOWED_SOURCES)
    allowed_actions = parse_list(settings.AGENT_ALLOWED_ACTIONS)

    # 1. Enforce privilege ceiling: user rank must not exceed agent ceiling rank
    user_rank = settings.privilege_rank(user_role)
    ceiling_rank = settings.privilege_rank(settings.AGENT_MAX_PRIVILEGE)

    if user_rank > ceiling_rank:
        logger.warning(
            "agent_identity_privilege_ceiling_exceeded",
            user_role=user_role,
            user_rank=user_rank,
            agent_max_privilege=settings.AGENT_MAX_PRIVILEGE,
            ceiling_rank=ceiling_rank,
        )
        return LayerResult(
            layer_name=layer_name,
            passed=False,
            reason=(
                f"Request blocked: user role '{user_role}' exceeds the maximum "
                f"authorized privilege level of this agent ('{settings.AGENT_MAX_PRIVILEGE}')."
            ),
        )

    # 2. Enforce allowed sources scope
    for source in requested_sources:
        if source not in allowed_sources:
            logger.warning(
                "agent_identity_unauthorized_source_requested",
                requested_source=source,
                allowed_sources=allowed_sources,
                user_role=user_role,
            )
            return LayerResult(
                layer_name=layer_name,
                passed=False,
                reason=f"Request blocked: unauthorized knowledge source requested ('{source}').",
            )

    # 3. Enforce allowed actions scope
    for action in requested_actions:
        if action not in allowed_actions:
            logger.warning(
                "agent_identity_unauthorized_action_requested",
                requested_action=action,
                allowed_actions=allowed_actions,
                user_role=user_role,
            )
            return LayerResult(
                layer_name=layer_name,
                passed=False,
                reason=f"Request blocked: unauthorized action requested ('{action}').",
            )

    logger.info(
        "agent_identity_check_passed",
        user_role=user_role,
        requested_sources=requested_sources,
        requested_actions=requested_actions,
    )
    return LayerResult(
        layer_name=layer_name,
        passed=True,
    )
