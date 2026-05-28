"""
LayerResult dataclass definition.

Chapter 1 — Architecture: Standardized security layer communication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LayerResult:
    """
    Standardized return type for all 12 security layers.

    Allows the pipeline orchestrator to treat all security checks uniformly.
    """
    layer_name: str
    passed: bool
    reason: str | None = None
    status: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
