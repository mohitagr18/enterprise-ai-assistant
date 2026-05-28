"""
Configuration module for Sentinel AI.

Chapter 1 — Architecture: The Layered Configuration Contract

Configuration is resolved in the following priority order (highest wins):

  1. Real environment variables  — for CI/CD pipelines and containers
  2. .env file                   — deployment secrets (never committed)
  3. config/defaults.toml        — organizational policy (committed, code-reviewed)
  4. Field defaults in this file — last-resort fallbacks

This three-tier design enforces a key principle from Chapter 1:
  * Secrets belong in the environment.
  * Policy belongs in version control.
  * Code should not contain either.

A junior engineer should be able to open config/defaults.toml to understand
every security decision this system makes, without reading any Python.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Literal

import structlog
from pydantic import Field, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

logger = structlog.get_logger(__name__)

# Path to the committed policy file, relative to the project root.
_DEFAULTS_TOML = Path(__file__).resolve().parents[2] / "config" / "defaults.toml"


class Settings(BaseSettings):
    """
    Application settings resolved from three sources (see module docstring).

    Override in tests with:
        app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None, OPENAI_API_KEY="test-key"
        )
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        toml_file=str(_DEFAULTS_TOML),
        case_sensitive=False,
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """
        Define the priority order for config resolution.

        Programmatic overrides (init) beat environment variables, which beat
        the .env file, which beats the committed defaults.toml.
        """
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            TomlConfigSettingsSource(settings_cls),
        )

    # ------------------------------------------------------------------ #
    # Secrets — must come from .env or environment variables, never TOML
    # ------------------------------------------------------------------ #

    OPENAI_API_KEY: str = Field(
        default="",
        description="OpenAI API key. Must be set in .env — never in defaults.toml.",
    )
    JWT_SECRET_KEY: str = Field(
        default="",
        description=(
            "JWT signing secret. If empty, an ephemeral key is generated at startup "
            "with a loud warning. Suitable for local dev only."
        ),
    )

    # ------------------------------------------------------------------ #
    # Deployment — environment-specific, typically from .env
    # ------------------------------------------------------------------ #

    REDIS_URL: str | None = Field(
        default=None,
        description=(
            "Redis connection URL. If unset, falls back to an in-process fakeredis "
            "instance. Token budgets and rate limits will NOT persist across restarts."
        ),
    )
    CHROMADB_PERSIST_DIR: str = Field(default="./data/chromadb")
    AUDIT_LOG_FILE: str = Field(default="./logs/audit.jsonl")
    APP_HOST: str = Field(default="127.0.0.1")
    APP_PORT: int = Field(default=8000, ge=1, le=65535)
    APP_DEBUG: bool = Field(default=False)
    CORS_ALLOWED_ORIGINS: list[str] = Field(default=["http://localhost:3000"])
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    CONTENT_MODERATION_ENABLED: bool = Field(default=True)

    # ------------------------------------------------------------------ #
    # Policy — defaults loaded from config/defaults.toml
    # Fields below mirror every key in that file.
    # ------------------------------------------------------------------ #

    # OpenAI
    OPENAI_CHAT_MODEL: str = Field(default="gpt-4o-mini")
    OPENAI_EMBEDDING_MODEL: str = Field(default="text-embedding-3-small")
    OPENAI_MAX_RESPONSE_TOKENS: int = Field(default=2048, ge=256, le=16384)
    OPENAI_TIMEOUT_SECONDS: int = Field(default=30, ge=5, le=120)

    # ChromaDB
    CHROMADB_COLLECTION_NAME: str = Field(default="sentinel_knowledge")

    # JWT (algorithm is hardcoded — it never changes)
    JWT_ALGORITHM: Literal["HS256"] = Field(
        default="HS256",
        description="Only HS256 is permitted. The 'none' algorithm is explicitly rejected.",
    )
    JWT_ACCESS_TOKEN_EXPIRE_SECONDS: int = Field(default=3600, ge=60)
    JWT_REFRESH_TOKEN_EXPIRE_SECONDS: int = Field(default=604800, ge=300)

    # Layer 1 — Input Validator
    INPUT_MAX_LENGTH: int = Field(default=10000, ge=1)
    INPUT_MIN_LENGTH: int = Field(default=1, ge=1)
    INPUT_BLOCK_NULL_BYTES: bool = Field(default=True)
    INPUT_INJECTION_PATTERNS: list[str] = Field(
        default=[
            "ignore previous instructions",
            "ignore all prior",
            "disregard above",
            "you are now",
            "act as if",
            "pretend you are",
            "system prompt",
            "reveal your instructions",
            "override safety",
        ]
    )

    # Layer 2 — Semantic Guard
    SEMANTIC_GUARD_THRESHOLD: float = Field(default=0.5, ge=0.0, le=1.0)
    SEMANTIC_GUARD_FAIL_CLOSED: bool = Field(default=True)
    SEMANTIC_GUARD_BANNED_TOPICS: list[str] = Field(
        default=["weapons manufacturing", "illegal drugs synthesis",
                 "exploit development", "malware creation"]
    )

    # Layer 4 — Input Restructurer
    INPUT_MAX_TOKENS: int = Field(default=4096, ge=256)
    TIKTOKEN_ENCODING: str = Field(default="o200k_base")

    # Layer 5 — Token Budget
    TOKEN_BUDGET_STANDARD: int = Field(default=100_000, ge=1000)
    TOKEN_BUDGET_POWER_USER: int = Field(default=500_000, ge=1000)
    TOKEN_BUDGET_ADMIN: int = Field(default=1_000_000, ge=1000)

    # Layer 6 — Content Moderator
    MODERATION_MODEL: str = Field(default="omni-moderation-latest")

    # Layer 7 — Context Isolator
    CLASSIFICATION_LEVELS: list[str] = Field(
        default=["public", "internal", "confidential", "restricted"]
    )
    RESTRICTED_ACCESS_ROLES: list[str] = Field(default=["admin", "security_officer"])

    # Layer 10 — Agent Identity
    AGENT_NAME: str = Field(default="Sentinel AI")
    AGENT_ID: str = Field(default="sentinel-dev-001")
    AGENT_ALLOWED_SOURCES: list[str] = Field(
        default=["internal_docs", "company_wiki", "hr_policies"]
    )
    AGENT_ALLOWED_ACTIONS: list[str] = Field(
        default=["answer_question", "summarize_document", "search_knowledge_base"]
    )
    AGENT_MAX_PRIVILEGE: Literal["standard", "power_user", "admin"] = Field(
        default="power_user"
    )

    # Layer 11 — Human Gate
    HUMAN_GATE_ACTIONS: list[str] = Field(
        default=["data_deletion", "policy_change", "financial_approval",
                 "access_grant", "system_configuration"]
    )
    HUMAN_GATE_TOKEN_TTL_SECONDS: int = Field(default=3600, ge=60)

    # Layer 12 — Threat Monitor
    THREAT_MONITOR_WINDOW_SECONDS: int = Field(default=300, ge=30)
    THREAT_MONITOR_MAX_BLOCKS: int = Field(default=5, ge=1)
    THREAT_MONITOR_MAX_INJECTION_MATCHES: int = Field(default=3, ge=1)
    THREAT_MONITOR_MAX_SEMANTIC_TRIGGERS: int = Field(default=3, ge=1)
    THREAT_MONITOR_MAX_BUDGET_HITS: int = Field(default=10, ge=1)
    THREAT_MONITOR_REDUCED_RATE_LIMIT: int = Field(default=5, ge=1)

    # Rate Limiting
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(default=30, ge=1)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, ge=10)

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #

    @field_validator(
        "CORS_ALLOWED_ORIGINS",
        "AGENT_ALLOWED_SOURCES",
        "AGENT_ALLOWED_ACTIONS",
        "HUMAN_GATE_ACTIONS",
        "CLASSIFICATION_LEVELS",
        "RESTRICTED_ACCESS_ROLES",
        "INPUT_INJECTION_PATTERNS",
        "SEMANTIC_GUARD_BANNED_TOPICS",
        mode="before",
    )
    @classmethod
    def split_comma_list(cls, v: str | list) -> list[str]:
        """
        Accept comma-separated strings from environment variables OR
        native TOML arrays. Both formats work transparently.

        .env format:  CORS_ALLOWED_ORIGINS=http://a.com,http://b.com
        TOML format:  cors_allowed_origins = ["http://a.com", "http://b.com"]
        """
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @model_validator(mode="after")
    def generate_ephemeral_jwt_secret_if_missing(self) -> "Settings":
        """
        If JWT_SECRET_KEY is not set, generate a random ephemeral key and warn.

        This pattern — generate + warn rather than crash — lets readers run the
        project with zero configuration while making production misconfiguration
        audibly visible.
        """
        if not self.JWT_SECRET_KEY:
            self.JWT_SECRET_KEY = secrets.token_hex(32)
            logger.warning(
                "jwt_secret_ephemeral",
                message=(
                    "JWT_SECRET_KEY not set. Generated an ephemeral key. "
                    "Sessions will be invalidated on restart. "
                    "Set JWT_SECRET_KEY in .env for persistent sessions."
                ),
            )
        return self

    # ------------------------------------------------------------------ #
    # Convenience helpers (used by pipeline layers)
    # ------------------------------------------------------------------ #

    def token_budget_for_role(self, role: str) -> int:
        """Return the daily token budget for a given user role."""
        budgets: dict[str, int] = {
            "standard": self.TOKEN_BUDGET_STANDARD,
            "power_user": self.TOKEN_BUDGET_POWER_USER,
            "admin": self.TOKEN_BUDGET_ADMIN,
        }
        return budgets.get(role, self.TOKEN_BUDGET_STANDARD)

    def privilege_rank(self, role: str) -> int:
        """
        Return a numeric rank for a privilege level.
        Higher rank = more privileged. Used by Layer 10 for ceiling comparison.
        """
        ranks: dict[str, int] = {"standard": 0, "power_user": 1, "admin": 2}
        return ranks.get(role, 0)
