# Related Work & Literature Positioning

This document maps Sentinel AI to the existing academic and industry literature in LLM security, defense-in-depth gateways, human-in-the-loop (HITL) authorization, and compliance auditing.

---

## 1. Prompt Injection Defense (Regex vs. Machine Learning)
*   **Prior Work:** Early prompt injection defenses relied either on simple heuristic pattern matching (regex) or local classifier models (e.g., DeBERTa/RoBERTa classifiers like those in LLM-Guard). 
    *   *Limitations:* Heuristic approaches are highly susceptible to simple semantic variations (leetspeak, homoglyphs). Conversely, classifier models introduce significant CPU/GPU latency, overhead, and failures (e.g., model errors or download timeouts).
*   **Sentinel AI's Contribution:** Sentinel AI implements a **layered security architecture** that sequences these controls. Fast, low-overhead heuristic matches (Layer 1) run first to immediately short-circuit obvious attacks. Heavy, CPU-bound machine learning scans (Layer 2) are only executed on inputs that pass Layer 1. This prevents unnecessary compute costs and latency on obviously malicious payloads.

---

## 2. Security Gateways Focused on Single Controls
*   **Prior Work:** Frameworks like NeMo Guardrails or standalone libraries focus primarily on prompt validation or output filtering.
    *   *Limitations:* In a single-control system, if the validation model or service fails (due to a timeout or network outage), the system must choose to either fail open (compromising security) or fail closed (compromising availability). Furthermore, single-layer systems lack redundancy; if an attacker evades the main filter, they gain full system access.
*   **Sentinel AI's Contribution:** Sentinel AI introduces a **fail-closed pipeline** containing 12 sequential, independent layers. It enforces true defense-in-depth through multi-layer redundancy. For example, prompt injection is mitigated by three independent boundaries: Layer 1 (Regex), Layer 2 (ML Semantic Scanners), and Layer 3 (System Prompt Hardening). If any layer fails due to an infrastructure error (e.g., Redis or OpenAI API unreachable), the pipeline defaults to a secure fail-closed state.

---

## 3. Human-in-the-Loop & Approval-Gated AI Systems
*   **Prior Work:** Human-in-the-loop (HITL) research focuses on reviewing AI outputs before displaying them to users, or verifying tool execution.
    *   *Limitations:* Prior architectures typically intercept requests only at the input phase, or run as external processes that can be bypassed if the LLM convinces the application to call a tool directly. They also lack stateful approval persistence and cryptographic tracking.
*   **Sentinel AI's Contribution:** Sentinel AI implements a stateful **Human Gate** (Layer 11) that checks action keywords in *both* the user's input and the model's generated output. If a gated action is detected, the request is paused. The system generates a cryptographically secure approval token stored in Redis with a 1-hour Time-To-Live (TTL). The action cannot proceed until an administrator explicitly consumes the token via a separate, authenticated `/admin/approve` call.

---

## 4. Enterprise & Policy-Enforced RAG Architectures
*   **Prior Work:** Enterprise assistants secure Retrieval-Augmented Generation (RAG) by applying Role-Based Access Control (RBAC) at the database query level or by relying on the LLM to ignore restricted information.
    *   *Limitations:* Simply querying the database with role filters is insufficient if documents contain indirect injections. Relying on the LLM to enforce access control is highly vulnerable to jailbreaks.
*   **Sentinel AI's Contribution:** Sentinel AI secures the RAG boundary using **Context Isolation** (Layer 7) and **Agent Identity Enforcer** (Layer 10). Layer 7 filters out restricted documents at the memory layer *before* they are loaded into context, then wraps allowed documents in XML tags with clear instructions to treat contents as passive data. Layer 10 enforces an agent privilege ceiling (preventing standard users from elevating an agent to admin status, even if they spoof inputs).

---

## 5. Auditability and Compliance-Focused AI
*   **Prior Work:** Compliance frameworks require logging user queries and LLM outputs for audit trails.
    *   *Limitations:* Logging raw inputs risks violating privacy regulations (e.g., GDPR, HIPAA) by storing personally identifiable information (PII) or secrets. Additionally, if the logging function is part of the standard execution path, an unhandled exception in the model call can prevent the log from being written.
*   **Sentinel AI's Contribution:** Sentinel AI's **Audit Logger** (Layer 9) runs unconditionally in a `finally` block, ensuring a log is written even if the server crashes or fails closed. To ensure GDPR compliance, it logs the SHA-256 hash of the input rather than raw text, protecting privacy while maintaining tamper-evidence and permitting duplication analysis.

---

## Literature Positioning Matrix

| Defense Dimension | Prior Work (Single Controls / Standalone SDKs) | Sentinel AI (12-Layer Fail-Closed Pipeline) |
|---|---|---|
| **Pipeline Composition** | Often stateless, single-filter (e.g. just input scanning). | 12 sequential, stateful layers composing input, context, output, and rate controls. |
| **Fail Disposition** | Defaults to fail-open to preserve uptime, or crashes. | 10 of 12 layers explicitly fail closed on infrastructure exceptions. |
| **RAG Boundary** | Relies on vector DB metadata filtering only. | Layer 7 escapes XML delimiters, filters classification levels, and wraps context. |
| **High-Stakes Verification** | Text-based prompt warnings or direct execution. | Stateful human approval gate backed by TTL-limited Redis tokens. |
| **Forensic Traceability** | Raw text logs (risks GDPR violation) or bypassable logging. | Unconditional `finally` block audit logging of SHA-256 text hashes. |
