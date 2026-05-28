# CHECKLIST.md — Agent-Resilient Build Checklist

> **PURPOSE:** This file is the single source of truth for build progress. It is designed
> so that ANY agent (or human) can pick up work mid-stream, understand exactly what has been
> completed, what failed, and what to do next — even if the previous agent ran out of tokens,
> crashed, or was a completely different model.

> **RULES FOR AGENTS:**
> 1. **Read this file FIRST** before doing any work. Find the first unchecked `[ ]` item.
> 2. **Mark items `[/]`** when you START working on them.
> 3. **Mark items `[x]`** when COMPLETE and VERIFIED.
> 4. **Mark items `[!]`** if something FAILED — add a note explaining what went wrong.
> 5. **Update the HANDOFF LOG** at the bottom every time you start or stop working.
> 6. **Never skip a phase.** Phases must be completed in order.
> 7. **Each phase has a VERIFY gate.** Do not proceed to the next phase until verification passes.
> 8. **Reference files:** `PLAN.md` has the full architecture. This file has the execution order.

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| `[ ]`  | Not started |
| `[/]`  | In progress — an agent is currently working on this |
| `[x]`  | Complete and verified |
| `[!]`  | Failed — see note for details |

---

## Phase 0 — Planning (GATE: User approval of PLAN.md)

- [x] Create `PLAN.md` with all 10 sections
- [x] User reviewed and approved plan (Docker removed per user feedback)

---

## Phase 1 — Project Scaffolding

> **Goal:** A runnable project skeleton. After this phase, `uv sync` succeeds and
> `uv run python -c "from sentinel.config import Settings; print('OK')"` works.

- [x] 1.1 Run `uv init` in project root
- [x] 1.2 Create full directory structure (all folders and `__init__.py` files from PLAN.md Section 2)
- [x] 1.3 Create `pyproject.toml` with all dependencies from PLAN.md Section 6
- [x] 1.4a Create `.env.example` — secrets + deployment vars only (~12 lines)
- [x] 1.4b Create `config/defaults.toml` — committed policy file (injection patterns, thresholds, agent scope, budgets)
- [x] 1.5 Create `.gitignore` (Python, IDE, .env, logs/, data/, __pycache__, .venv)
- [x] 1.6 Run `uv sync` — must exit 0
- [x] 1.7 Create `src/sentinel/config.py` — Pydantic Settings v2 loading all `.env` variables
- [x] 1.8 Create `src/sentinel/dependencies.py` — Redis (with fakeredis fallback), ChromaDB, Settings providers
- [x] 1.9 Create `logs/.gitkeep` and `data/.gitkeep`

### VERIFY Phase 1:
```bash
uv sync
uv run python -c "from sentinel.config import Settings; s = Settings(_env_file='.env.example'); print(f'Config OK: {s.AGENT_NAME}')"
```
- [x] 1.V Verification command passes

---

## Phase 2 — Shared Foundations

> **Goal:** The building blocks every other layer depends on: LayerResult, logging, schemas.
> After this phase, all models import cleanly and logging outputs structured JSON.

- [x] 2.1 Create `src/sentinel/models/layer_result.py` — LayerResult dataclass
- [x] 2.2 Create `src/sentinel/logging_setup.py` — structlog JSON configuration
- [x] 2.3 Create `src/sentinel/models/requests.py` — ChatRequest, DocumentUploadRequest
- [x] 2.4 Create `src/sentinel/models/responses.py` — ChatResponse, ErrorResponse, ApprovalResponse
- [x] 2.5 Create `src/sentinel/models/auth.py` — TokenPayload, UserCredentials, UserProfile
- [x] 2.6 Create `src/sentinel/layers/audit_logger.py` — Layer 9: structured JSON audit trail
- [x] 2.7 Create `tests/conftest.py` — shared fixtures (async client, mock Redis, mock settings)

### VERIFY Phase 2:
```bash
uv run python -c "from sentinel.models.layer_result import LayerResult; print(LayerResult(layer_name='test', passed=True, reason='ok'))"
uv run python -c "from sentinel.logging_setup import setup_logging; setup_logging(); print('Logging OK')"
```
- [x] 2.V Verification commands pass

---

## Phase 3 — Authentication & Rate Limiting

> **Goal:** JWT auth and rate limiting middleware working. After this phase,
> `/auth/login` returns a token and rate limiting rejects excess requests.

- [x] 3.1 Create `src/sentinel/auth/password.py` — Argon2 hashing
- [x] 3.2 Create `src/sentinel/auth/jwt_handler.py` — JWT create/verify/refresh, reject "none" alg
- [x] 3.3 Create `src/sentinel/auth/middleware.py` — FastAPI auth middleware
- [x] 3.4 Create `src/sentinel/auth/routes.py` — /auth/login, /auth/refresh, /auth/logout
- [x] 3.5 Create `src/sentinel/middleware/rate_limiter.py` — Redis-backed sliding window
- [x] 3.6 Create `src/sentinel/middleware/security_headers.py` — CSP, X-Frame-Options, etc.
- [x] 3.7 Create `src/sentinel/main.py` — FastAPI app factory with lifespan, middleware registration
- [x] 3.8 Create `tests/test_auth.py` — happy path, "none" alg attack, expired token edge case
- [x] 3.9 Create `tests/test_rate_limiter.py` — happy path, burst attack, multi-user isolation

### VERIFY Phase 3:
```bash
uv run pytest tests/test_auth.py tests/test_rate_limiter.py -v
```
- [x] 3.V All tests pass

---

## Phase 4 — Security Layers 1–4 (Pre-LLM, No External Services)

> **Goal:** The first four defensive layers that require no external API calls.
> These are fast, cheap checks that run before any expensive processing.

- [x] 4.1 Create `src/sentinel/layers/input_validator.py` — Layer 1
- [x] 4.2 Create `tests/test_input_validator.py` — happy path, injection pattern, boundary length
- [x] 4.3 Create `src/sentinel/layers/semantic_guard.py` — Layer 2 (llm-guard, fail-closed)
- [x] 4.4 Create `tests/test_semantic_guard.py` — happy path, disguised injection, exception fail-closed
- [x] 4.5 Create `src/sentinel/layers/system_prompt.py` — Layer 3
- [x] 4.6 Create `tests/test_system_prompt.py` — happy path, security phrases present, empty docs
- [x] 4.7 Create `src/sentinel/layers/input_restructurer.py` — Layer 4 (tiktoken)
- [x] 4.8 Create `tests/test_input_restructurer.py` — happy path, token bomb, boundary value

### VERIFY Phase 4:
```bash
uv run pytest tests/test_input_validator.py tests/test_semantic_guard.py tests/test_system_prompt.py tests/test_input_restructurer.py -v
```
- [x] 4.V All tests pass

---

## Phase 5 — Security Layers 5–8 (External Services, Pre/Post LLM)

> **Goal:** Layers that interact with Redis and OpenAI Moderation API, plus the
> context isolation and output validation layers.

- [x] 5.1 Create `src/sentinel/layers/token_budget.py` — Layer 5 (Redis-backed)
- [x] 5.2 Create `tests/test_token_budget.py` — happy path, exhausted budget, exact boundary
- [x] 5.3 Create `src/sentinel/layers/content_moderator.py` — Layer 6 (OpenAI Moderation)
- [x] 5.4 Create `tests/test_content_moderator.py` — happy path, hate speech flagged, API timeout fail-closed
- [x] 5.5 Create `src/sentinel/layers/context_isolator.py` — Layer 7
- [x] 5.6 Create `tests/test_context_isolator.py` — happy path, poisoned doc wrapped, restricted filtered
- [x] 5.7 Create `src/sentinel/layers/output_validator.py` — Layer 8
- [x] 5.8 Create `tests/test_output_validator.py` — happy path, traceback caught, retry on bad JSON

### VERIFY Phase 5:
```bash
uv run pytest tests/test_token_budget.py tests/test_content_moderator.py tests/test_context_isolator.py tests/test_output_validator.py -v
```
- [x] 5.V All tests pass

---

## Phase 6 — Security Layers 10–12 (Identity, Gates, Monitoring)

> **Goal:** The advanced enterprise layers: agent-level access control,
> human-in-the-loop approval, and behavioral threat detection.

- [x] 6.1 Create `src/sentinel/layers/agent_identity.py` — Layer 10
- [x] 6.2 Create `tests/test_agent_identity.py` — happy path, admin exceeds scope, role exceeds ceiling
- [x] 6.3 Create `src/sentinel/layers/human_gate.py` — Layer 11 (Redis-backed approval tokens)
- [x] 6.4 Create `tests/test_human_gate.py` — happy path, data_deletion intercepted, expired token
- [x] 6.5 Create `src/sentinel/layers/threat_monitor.py` — Layer 12 (Redis-backed rolling window)
- [x] 6.6 Create `tests/test_threat_monitor.py` — happy path, threshold breach flagged, user isolation
- [x] 6.7 Create `tests/test_audit_logger.py` — happy path, SHA-256 hash present, unwritable path fallback

### VERIFY Phase 6:
```bash
uv run pytest tests/test_agent_identity.py tests/test_human_gate.py tests/test_threat_monitor.py tests/test_audit_logger.py -v
```
- [x] 6.V All tests pass

---

## Phase 7 — Knowledge Base (RAG Layer)

> **Goal:** Document ingestion with security checks and retrieval that feeds Layer 7.

- [x] 7.1 Create `src/sentinel/knowledge/store.py` — ChromaDB collection management
- [x] 7.2 Create `src/sentinel/knowledge/ingestion.py` — MIME validation, magic bytes, content mod
- [x] 7.3 Create `src/sentinel/knowledge/retrieval.py` — semantic search feeding context isolator
- [x] 7.4 Create `src/sentinel/services/llm_client.py` — async OpenAI wrapper with retry/timeout

### VERIFY Phase 7:
```bash
uv run python -c "from sentinel.knowledge.store import KnowledgeStore; print('Store OK')"
uv run python -c "from sentinel.services.llm_client import LLMClient; print('Client OK')"
```
- [x] 7.V Verification commands pass

---

## Phase 8 — Pipeline Orchestrator

> **Goal:** The central service that wires all 12 layers in the correct sequence.
> This is the most critical file in the codebase.

- [x] 8.1 Create `src/sentinel/services/pipeline.py` — orchestrator per PLAN.md Section 4
- [x] 8.2 Create `src/sentinel/layers/__init__.py` — export all layer functions

### VERIFY Phase 8:
```bash
uv run python -c "from sentinel.services.pipeline import SecurityPipeline; print('Pipeline OK')"
```
- [x] 8.V Verification command passes

---

## Phase 9 — API Routes & Streamlit UI

> **Goal:** All HTTP endpoints wired up and Streamlit UI client completed.

- [x] 9.1 Create `src/sentinel/routes/chat.py` — POST /chat
- [x] 9.2 Create `src/sentinel/routes/documents.py` — POST/GET/DELETE /documents
- [x] 9.3 Create `src/sentinel/routes/admin.py` — POST /admin/approve, GET /admin/usage, GET /admin/audit
- [x] 9.4 Update `src/sentinel/main.py` — register all route modules
- [x] 9.5 Add GET /health endpoint (no auth required)
- [x] 9.6 Create Streamlit companion UI (`streamlit_app.py`)

### VERIFY Phase 9:
```bash
# Verify API routes and security layers via HTTP tests
uv run pytest tests/test_api.py -v
```
- [x] 9.V All API tests pass, endpoints return correct status codes.

---

## Phase 10 — Integration Tests

> **Goal:** End-to-end tests covering the full pipeline including multi-layer attack scenarios.

- [x] 10.1 Create `tests/test_pipeline_integration.py`:
  - [x] 10.1a Happy path — full chat request through all 12 layers
  - [x] 10.1b Multi-layer attack — injection passes Layer 1, caught by Layer 2
  - [x] 10.1c Cascading attack — 6 injections in 5 min triggers Layer 12

### VERIFY Phase 10:
```bash
uv run pytest tests/ -v --tb=short
```
- [x] 10.V ALL tests pass (unit + integration)

---

## Phase 11 — README

> **Goal:** Complete documentation so a book reader can clone, run, and understand.

- [ ] 11.1 Write `README.md`:
  - [ ] 11.1a Project overview and prerequisites
  - [ ] 11.1b Setup instructions (uv commands only, no Docker)
  - [ ] 11.1c How to run locally (with and without Redis)
  - [ ] 11.1d How to run tests
  - [ ] 11.1e Description of all 12 security layers
  - [ ] 11.1f API endpoint reference
  - [ ] 11.1g "Attack Scenarios" section with example curl commands

### VERIFY Phase 11:
- [ ] 11.V README reviewed, all commands tested

---

## FINAL VERIFICATION

```bash
# Full test suite
uv run pytest tests/ -v --tb=short

# App starts without errors
uv run uvicorn sentinel.main:app --host 127.0.0.1 --port 8000

# Verify no hardcoded secrets
grep -r "sk-" src/ --include="*.py" | grep -v "example" | grep -v ".env"
```
- [ ] F.1 All tests pass
- [ ] F.2 App starts cleanly
- [ ] F.3 No hardcoded secrets in source code

---

## HANDOFF LOG

> **INSTRUCTIONS:** Every time an agent starts or stops working on this project,
> add a timestamped entry below. This is how the next agent knows what happened.
>
> Format: `| YYYY-MM-DD HH:MM | agent_model | started/stopped/completed | Phase X.Y | notes |`

| Timestamp | Agent | Action | Item | Notes |
|-----------|-------|--------|------|-------|
| 2026-05-27 19:45 | claude-opus-4-6 | completed | Phase 0 | PLAN.md created with all 10 sections, user approved. Docker removed per user feedback. |
| 2026-05-27 20:09 | claude-sonnet-4-6 | completed | Phase 1 | uv sync OK. config.py, dependencies.py created. Fakeredis fallback verified. All items [x]. |
| 2026-05-27 20:39 | gemini-3.5-flash | completed | Phase 2 | Created LayerResult, structlog setup, requests/responses/auth models, audit_logger, conftest.py. Verified imports. |
| 2026-05-27 20:41 | gemini-3.5-flash | completed | Phase 3 | Argon2id hashing, JWT handler, auth routes, sliding-window rate limiter, and security headers implemented. Fixed pytest-asyncio event-loop sharing and ZSET concurrency collisions. |
| 2026-05-27 21:09 | gemini-3.5-flash | completed | Phase 4 | Completed Layers 1-4: Input Validator, Semantic Guard, System Prompt Hardener, and Input Restructurer. Configured list validation in config.py using Union types (str | list[str]) to prevent Pydantic JSON parsing errors from environment variables. |
| 2026-05-27 22:30 | antigravity | started | Phase 5 | Resumed Phase 5: verified layers 5 & 6, starting implementation of Layer 7 (Context Isolator) and Layer 8 (Output Validator). |
| 2026-05-27 22:45 | antigravity | completed | Phase 6 | Completed Phase 5 & Phase 6. Implemented Layer 7 (Context Isolator), Layer 8 (Output Validator), Layer 10 (Agent Identity), Layer 11 (Human Gate), Layer 12 (Threat Monitor), and wrote tests for all of them + Layer 9 (Audit Logger). Verified all 24 new/existing unit tests pass. |
| 2026-05-27 23:05 | antigravity | completed | Phase 8 & 10 | Completed Phase 7, Phase 8, and Phase 10. Implemented RAG storage (store.py), retrieval (retrieval.py), ingestion with magic bytes & moderation guards (ingestion.py), and OpenAI wrapper with retry (llm_client.py). Wrote layers/__init__.py and wired all 12 layers in services/pipeline.py. Verified integration tests & all 55 tests pass. |
| 2026-05-28 09:37 | antigravity | completed | Phase 9 | Implemented all secure API routes: Chat, Documents, Admin, and Health. Built a high-fidelity Streamlit UI Dashboard companion app (Option 2). Wrote complete endpoint test suite (test_api.py). All 60 tests pass. |


---

## RECOVERY INSTRUCTIONS

> **If you are a new agent picking up this project:**
>
> 1. Read this file top to bottom.
> 2. Find the first `[ ]` or `[/]` item — that's where work stopped.
> 3. If an item is `[/]` (in progress), check if the file it references exists and is complete.
>    - If the file exists and looks complete → mark it `[x]` and move on.
>    - If the file is partial or broken → finish it, then mark `[x]`.
>    - If the file doesn't exist → the previous agent was interrupted before creating it. Start fresh on that item.
> 4. If an item is `[!]` (failed), read the note, fix the issue, then mark `[x]`.
> 5. Run the VERIFY gate for the current phase before moving to the next.
> 6. Add yourself to the HANDOFF LOG.
> 7. Reference `PLAN.md` for all architectural details, function signatures, and design decisions.
>
> **Key files to understand the project:**
> - `PLAN.md` — Full architecture, 12 layer specs, API endpoints, tech stack
> - `CHECKLIST.md` — This file. Execution order and progress tracking.
> - `src/sentinel/config.py` — All configurable values (created in Phase 1)
> - `src/sentinel/services/pipeline.py` — Pipeline orchestrator (created in Phase 8)
> - `tests/conftest.py` — Shared test fixtures (created in Phase 2)
