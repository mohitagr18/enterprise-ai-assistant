"""
Logging setup for Sentinel AI using structlog.

Chapter 1 — Architecture: Structured Logging as an Operational Security Requirement.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from sentinel.config import Settings


def setup_logging(settings: Settings | None = None) -> None:
    """
    Configure structlog for structured JSON logging.

    If settings is not provided, defaults are loaded from dependencies.
    """
    if settings is None:
        from sentinel.dependencies import get_settings
        settings = get_settings()

    log_level_str = settings.LOG_LEVEL.upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Core processors for all loggers
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    # For production, we want structured JSON. In debug, we can use JSON too or console.
    # PLAN.md specifies: "Structured JSON logging configured once, used everywhere."
    # So we always use JSONRenderer.
    processors = shared_processors + [
        structlog.processors.JSONRenderer()
    ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        cache_logger_on_first_use=True,
    )
