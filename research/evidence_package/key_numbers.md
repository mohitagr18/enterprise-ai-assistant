# Sentinel AI — Key Numbers Cheat Sheet

Quick-reference for paper writing, slides, and reviewer responses.
All numbers sourced from empirical evaluation runs in `research/`.

---

## The Headline Numbers

| Claim | Number | Source |
|-------|--------|--------|
| Attack pass-through rate (naive baseline) | **100%** | Phase 1 comparison |
| Attack pass-through rate (protected pipeline) | **6%** | Phase 1 comparison |
| Reduction in attack pass-through | **−94%** | Phase 1 comparison |
| False positive rate on benign queries | **0%** | Phase 1 + Phase 3 |
| Design-match rate (adversarial evaluation) | **97.4%** (38/39) | Phase 3 |
| Threat categories covered (OWASP LLM Top 10) | **6 / 10** | Phase 2 |
| Fail-closed layers | **10 / 12** | Phase 2 |

---

## Architecture Numbers

- **12** security layers total
- **10** layers fail closed on infrastructure errors
- **3** independent controls for prompt injection (L1 regex, L2 ML, L3 hardened prompt)
- **9** injection regex patterns, all verified active in adversarial evaluation
- **3** ML scanners in Layer 2 (PromptInjection, Toxicity, BanTopics)
- **4** banned topic categories
- **5** human-gate action categories requiring admin approval
- **4** document classification levels (public → restricted)

## Limits and Thresholds

- **10,000 chars** — max input length (Layer 1)
- **4,096 tokens** — max input token count (Layer 4, tiktoken)
- **100K / 500K / 1M tokens/day** — budget by role (standard / power_user / admin)
- **30 req/min** — normal rate limit
- **5 req/min** — post-lockout punitive rate limit
- **5 blocks in 300 seconds** — threat monitor lockout threshold
- **1 hour TTL** — human gate approval token expiry

## Evaluation Scale

- **39** total adversarial test cases
- **8** attack families
- **4** benign control cases
- **35** attack-only cases for baseline comparison
- **1** design mismatch (CF-02 — blocked *stricter* than predicted, not a bypass)

## Compliance Design

- `audit.jsonl` — append-only, SHA-256 hashed input (not raw text)
- `config/defaults.toml` — all policy in version control, PR-reviewed
- JWT: HS256 only, alg:none explicitly rejected
- Passwords: Argon2id + unique salt per user

---

## Reproducibility

```bash
# Run all evaluations from project root:
uv run python research/adversarial_evaluation/run_evaluation.py
uv run python research/baseline_comparison/run_comparison.py

# Run existing unit test suite:
uv run pytest tests/ -v

# No API key, no server, no external dependencies required.
```
