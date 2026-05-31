# Sentinel AI — Research Artifacts & Evaluation Directory

Welcome to the Sentinel AI research folder. This directory contains the complete collection of formal threat models, baseline comparisons, adversarial evaluations, and reproducibility guides developed for this paper.

---

## 🗺️ Research Artifact Index

Use this directory to navigate directly to the primary research materials and verification documentation:

### 1. Conceptual Framing & Threats
*   **[Formal Threat Model](threat_model/threat_model.md)**
    *   *Why it matters:* Catalogs 16 standard enterprise threats, details the fail-closed status of each layer, and aligns Sentinel AI with the OWASP LLM Top 10 framework.
*   **[Related Work & Literature Positioning](threat_model/related_work.md)**
    *   *Why it matters:* Positions Sentinel AI within the context of existing literature on prompt injection filters, single-control gateways, and human-in-the-loop approvals.
*   **[Production Hardening Blueprints](threat_model/production_hardening_blueprints.md)**
    *   *Why it matters:* Bridges the gap between the test codebase and production deployments, mapping out designs for model provenance, input normalizers, and secure SIEM logging.

### 2. Empirical Performance Metrics
*   **[Baseline Comparison Table](baseline_comparison/baseline_comparison_table.md)**
    *   *Why it matters:* Shows results comparing a standard unprotected assistant (naive baseline) and the protected Sentinel AI pipeline across 35 distinct attacks.
*   **[Adversarial Results Table](adversarial_evaluation/adversarial_results_table.md)**
    *   *Why it matters:* Reports case-by-case outcomes for all 39 payloads in our attack corpus, identifying exactly which layer intercepted each threat.
*   **[Evaluation Summary & Limitations](adversarial_evaluation/evaluation_summary.md)**
    *   *Why it matters:* Discusses matches against designed expectations, identifies discrepancies (such as character-limit overlaps), and outlines honest evaluation limitations.

### 3. Reviewer Verification Packages
*   **[Adversarial Attack Corpus](adversarial_evaluation/attack_corpus.py)**
    *   *Why it matters:* The reusable, structured test suite containing 39 payloads across 8 attack families.
*   **[Reviewer Reproducibility Guide](reproducibility.md)**
    *   *Why it matters:* A single, step-by-step document explaining how to install packages and run scripts to reproduce every table in the paper.
*   **[Key Numbers Cheat Sheet](evidence_package/evidence_package.md#key-numbers-cheat-sheet)**
    *   *Why it matters:* Provides a quick-reference list of all headline percentages, daily limits, rate thresholds, and model parameters for paper writing.
*   **[Reviewer-Facing Summary Tables](evidence_package/evidence_package.md#table-1-baseline-vs-protected-pipeline-summary)**
    *   *Why it matters:* Consolidates the two most important evaluation tables in a single location for instant reviewer verification.

---

## 🧪 Quick Reproduction Commands
From the project root directory, run these commands to regenerate the empirical findings:

```bash
# Run baseline-vs-protected comparison (Phase 1)
uv run python research/baseline_comparison/run_comparison.py

# Run complete 39-case adversarial evaluation (Phase 3)
uv run python research/adversarial_evaluation/run_evaluation.py
```
Outputs are written directly to `baseline_results.json` and `evaluation_results.json`.
