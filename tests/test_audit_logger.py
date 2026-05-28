"""
Tests for Layer 9 — Audit Logger.

Chapter 10 — Audit Logger: Verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.config import Settings
from sentinel.layers.audit_logger import AuditEvent, log_audit_event


@pytest.mark.asyncio
async def test_audit_logger_happy_path(
    test_settings: Settings,
    tmp_path: Path,
) -> None:
    """
    Happy path: A complete AuditEvent is serialized to JSON and written to the
    configured log file.
    """
    log_file = tmp_path / "test_audit.jsonl"
    test_settings.AUDIT_LOG_FILE = str(log_file)

    event = AuditEvent(
        user_id="user_123",
        timestamp="2026-05-27T12:00:00Z",
        request_hash="a1b2c3d4e5f6g7h8",
        layers_fired=["input_validator", "semantic_guard"],
        layers_blocked={},
        token_counts={"input": 50, "output": 30},
        response_time_ms=120,
        session_id="session_abc",
    )

    await log_audit_event(event, test_settings)

    # Verify file was written
    assert log_file.exists()

    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    assert len(lines) == 1
    logged_event = json.loads(lines[0])

    assert logged_event["user_id"] == "user_123"
    assert logged_event["request_hash"] == "a1b2c3d4e5f6g7h8"
    assert logged_event["layers_fired"] == ["input_validator", "semantic_guard"]
    assert logged_event["layers_blocked"] == {}
    assert logged_event["token_counts"] == {"input": 50, "output": 30}
    assert logged_event["response_time_ms"] == 120
    assert logged_event["session_id"] == "session_abc"


@pytest.mark.asyncio
async def test_audit_logger_no_raw_input(
    test_settings: Settings,
    tmp_path: Path,
) -> None:
    """
    Attack scenario: Verify that the audit log does NOT contain the raw input prompt
    itself, but does contain the request hash for tracking.
    """
    log_file = tmp_path / "test_audit_safety.jsonl"
    test_settings.AUDIT_LOG_FILE = str(log_file)

    secret_input = "My super secret raw user prompt containing password123"
    import hashlib
    h = hashlib.sha256(secret_input.encode("utf-8")).hexdigest()

    event = AuditEvent(
        user_id="user_123",
        timestamp="2026-05-27T12:00:00Z",
        request_hash=h,
        layers_fired=["input_validator"],
        layers_blocked={"input_validator": "Null byte"},
        token_counts={"input": 12, "output": 0},
        response_time_ms=5,
        session_id="session_xyz",
    )

    await log_audit_event(event, test_settings)

    with open(log_file, "r", encoding="utf-8") as f:
        log_content = f.read()

    # The SHA-256 hash must be present, but the raw prompt must not
    assert h in log_content
    assert secret_input not in log_content
    assert "password123" not in log_content


@pytest.mark.asyncio
async def test_audit_logger_unwritable_path_fallback(
    test_settings: Settings,
) -> None:
    """
    Edge case: When the log file path is unwritable, the logger falls back to
    console-only output and logs a warning rather than crashing.
    """
    # Use an invalid path that cannot be written to
    test_settings.AUDIT_LOG_FILE = "/sys/unwritable_dir/audit.jsonl"

    event = AuditEvent(
        user_id="user_123",
        timestamp="2026-05-27T12:00:00Z",
        request_hash="hash_val",
        layers_fired=["input_validator"],
        layers_blocked={},
        token_counts={"input": 5, "output": 5},
        response_time_ms=10,
        session_id="session_123",
    )

    with patch("sentinel.layers.audit_logger.logger.warning") as mock_warn:
        # Should not raise OSError, but fall back gracefully
        await log_audit_event(event, test_settings)
        mock_warn.assert_called_once()
        args, kwargs = mock_warn.call_args
        assert kwargs["path"] == "/sys/unwritable_dir/audit.jsonl"
        assert "unwritable" in args[0]
