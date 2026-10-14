# Security & Threat Framework Alignment

This document outlines the technical security model for the **AI Compliance Layer**, mapping automated CI gates and architectural requirements to the **OWASP Top 10 for LLM Applications** and the **EU Artificial Intelligence Act (Regulation EU 2024/1689)**.

---

## 1. OWASP Top 10 for LLM Applications Matrix

The compliance harness distinguishes between **mechanically enforced CI gates** (deterministic blockers) and **architectural guidelines** (best practices owned by service teams or platform policies):

| OWASP Vulnerability | Technical Threat Description | Compliance Layer Implementation | Enforcement Status |
| :--- | :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Adversarial user input attempts to override system instructions or hijack control flow. | Multi-vector adversarial probing with computed-token verification (`checker/safety_evaluator.py`). | **Enforced (P0 Gate)** |
| **LLM02: Sensitive Information Disclosure** | Exposure of proprietary prompts, canaries, or backend data in LLM outputs. | Output canary assertion and generic system-prompt leakage heuristics (`checker/safety_evaluator.py`). | **Enforced (P0 / P1 Advisory)** |
| **LLM03: Supply Chain Vulnerabilities** | Compromised third-party packages or unpinned dependencies. | Static scanning of repository configuration; pinned dependency guidance. | **Architectural (Advisory)** |
| **LLM06: Excessive Agency** | Autonomous actions executing state-changing operations without oversight. | Manifest validation requiring `human_oversight: true` for stateful services; code AST analysis for undeclared DB/OS calls. | **Enforced via Manifest (P0 Gate)** |
| **LLM07: System Prompt Leakage** | Extraction of internal system instructions or developer secrets. | Probe checks for leaked system prompt fragments or declared canary tokens. | **Enforced (P0 Gate)** |
| **LLM10: Unbounded Consumption** | Resource exhaustion / DoS via massive context payloads. | Schema payload length limits (`max_length`) and request latency monitoring. | **Enforced in Reference App (P1)** |
| **CWE-798: Hardcoded Credentials** | AI provider API keys accidentally committed to source repositories. | Pattern-based static secret scanning across 10+ AI providers with `.gitignore` and `.complianceignore` verification. | **Enforced (P0 Gate)** |

---

## 2. EU Artificial Intelligence Act Alignment (Regulation EU 2024/1689)

The compliance harness enforces governance tiering at deployment time through declarative `service.yaml` manifests:

| Risk Classification | Scope under EU AI Act | Platform & Checker Action | Enforcement Status |
| :--- | :--- | :--- | :--- |
| **`prohibited_risk`** | Article 5: Biometric categorization, cognitive manipulation, social scoring. | Immediate CI rejection. | **Enforced (P0 Blocker)** |
| **`high_risk`** | Articles 6, 9–15: Critical infrastructure, recruitment, credit evaluation. | Mandatory human oversight declaration (`human_oversight: true`) and platform graduation review before deployment. | **Enforced via Manifest Gate** |
| **`specific_transparency_risk`** | Article 50: Direct AI-to-human interaction. | Verification that transparency notices are declared. | **Enforced via Manifest Gate** |
| **`minimal_risk`** | Standard internal productivity tools (e.g., SQL explainer, code review helper). | Standard automated paved-road checks (secrets, auth, observability, safety). | **Enforced (Standard Gate)** |

### Technical Article Mappings
- **Article 12 (Record-Keeping & Logging):** While statutory obligations specifically target high-risk applications, our platform establishes structured logging with `X-Request-ID` correlation across all internal apps as a foundational operational baseline.
- **Article 14 (Human Oversight):** Enforced in manifest validation; applications classified as `high_risk` cannot merge or graduate without designated human overseers declared in `service.yaml`.
- **Article 15 (Cybersecurity & Robustness):** Enforced via automated negative authentication testing across exposed operations and dynamic prompt-injection resistance probing.
