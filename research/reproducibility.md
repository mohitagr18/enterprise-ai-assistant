# Sentinel AI — Evaluation Reproducibility Guide

This guide describes how to reproduce the baseline comparison (Phase 1) and the adversarial evaluation (Phase 3) empirical results presented in this paper.

---

## 1. System Requirements & Setup
All evaluation runs are designed to be **offline-first, zero-cost, and independent of external APIs**. 

### Prerequisites
*   **Python:** Version 3.12 or newer.
*   **Package Manager:** `uv` (recommended for fast dependency resolution).

### Step-by-Step Installation
1.  Clone the repository and navigate to the project directory:
    ```bash
    git clone https://github.com/mohitagr18/enterprise-ai-assistant.git
    cd enterprise-ai-assistant
    ```
2.  Install dependencies and synchronize the environment:
    ```bash
    uv sync --all-extras
    ```
3.  Set up the local environment variables. (No actual keys are needed to run the offline evaluation runner):
    ```bash
    cp .env.example .env
    ```

---

## 2. Reproducing Phase 1: Baseline Comparison
This step runs the attack corpus against both the naive baseline assistant (no security layers) and the Sentinel AI pipeline, saving the performance differences.

### Execution Command
```bash
uv run python research/baseline_comparison/run_comparison.py
```

### Process Mechanics
*   **Inputs:** Loads 35 structured attack payloads from `research/adversarial_evaluation/attack_corpus.py`.
*   **Execution:** Fires all attacks at [naive_baseline.py](baseline_comparison/naive_baseline.py) (which simulates a direct LLM call) and at the Sentinel AI security layers.
*   **Generated Outputs:**
    *   [baseline_results.json](baseline_comparison/baseline_results.json): Raw execution results capturing layer performance for both configurations.
    *   [baseline_comparison_table.md](baseline_comparison/baseline_comparison_table.md): A detailed, markdown-formatted comparison table comparing every attack outcome.

---

## 3. Reproducing Phase 3: Adversarial Evaluation
This step executes the complete 39-case attack corpus against the active Sentinel AI security layer functions to measure their security effectiveness and compliance with design boundaries.

### Execution Command
```bash
uv run python research/adversarial_evaluation/run_evaluation.py
```

### Process Mechanics
*   **Inputs:** Loads 39 attack cases (35 attacks + 4 benign controls) defined in `attack_corpus.py`.
*   **Execution:** Runs the layer functions directly using an in-process Redis database emulator (`fakeredis`) to verify token budget ceilings, lockout gates, and administrative approval mechanisms.
*   **Generated Outputs:**
    *   [evaluation_results.json](adversarial_evaluation/evaluation_results.json): Raw JSON validation metadata.
    *   [adversarial_results_table.md](adversarial_evaluation/adversarial_results_table.md): Full case-by-case report mapping each Attack ID to its outcome and the specific blocking layer.
    *   [evaluation_summary.md](adversarial_evaluation/evaluation_summary.md): Text summary including findings, discrepancies, and details about the Layer 2 (Semantic Guard) simulation.

---

## 4. Verification Check
To verify the reproducibility package runs correctly, confirm that the console output shows a 100% design-match rate for all attack families (with `CF-02` correctly reported as blocked earlier at Layer 1 due to character limits):

```
=================================================================
  Sentinel AI — Adversarial Evaluation Runner
  Phase 3: Empirical Red-Team Study
=================================================================
...
  [Family 8] Benign Control Cases (n=4, should all pass) ...
  BC-01: PASSED via none — ✓ MATCH
  BC-02: PASSED via none — ✓ MATCH
  BC-03: PASSED via none — ✓ MATCH
  BC-04: PASSED via none — ✓ MATCH

  Raw results written to: .../research/adversarial_evaluation/evaluation_results.json
  Results table written to: .../research/adversarial_evaluation/adversarial_results_table.md
```
