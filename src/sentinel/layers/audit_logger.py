"""
Layer 9 — Audit Logger: Compliance and Observability Foundation.

Writes structured JSON audit events to the console and an append-only log file.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

import structlog

from sentinel.config import Settings

logger = structlog.get_logger(__name__)


@dataclass
class AuditEvent:
    """
    Representation of a security audit event for compliance tracking.
    Contains metadata of the request evaluation without storing raw user prompts.
    """
    user_id: str
    timestamp: str
    request_hash: str
    layers_fired: list[str]
    layers_blocked: dict[str, str]  # layer_name -> block_reason
    token_counts: dict[str, int]    # e.g., {"input": 100, "output": 50}
    response_time_ms: int
    session_id: str | None = None


async def log_audit_event(event: AuditEvent, settings: Settings) -> None:
    """
    Log an audit event to structured logging (console) and an append-only file.

    Falls back to console-only logging if the target file is unwritable.
    """
    event_dict = asdict(event)
    event_json = json.dumps(event_dict)

    # 1. Log to console
    logger.info("audit_event", **event_dict)

    # 2. Append to log file
    log_file_path = Path(settings.AUDIT_LOG_FILE)
    try:
        # Create directories if they do not exist
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Append JSON log line
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(event_json + "\n")
    except OSError as e:
        # Fall back to console-only and log warning
        logger.warning(
            "audit_file_unwritable",
            message="Audit log file path is unwritable, fell back to console-only logging.",
            path=settings.AUDIT_LOG_FILE,
            error=str(e),
        )
