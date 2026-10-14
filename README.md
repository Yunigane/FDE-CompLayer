# AI Compliance Layer: Automated Governance for Internal AI Micro-Apps

A lightweight, contract-driven compliance layer designed to automate security, observability, and lifecycle ownership reviews for internal AI-powered micro-services.

---

## 1. System Overview & Architecture

Internal teams are rapidly building small AI-powered tools. Having a single human gatekeeper manually review every submission for authentication, secrets, LLM safety, and observability causes severe release bottlenecks and fails to scale.

This project delivers a complete three-part foundation:
1. **The Reference Application (`app/`):** A minimal, production-disciplined FastAPI microservice demonstrating a compliant internal SQL Explainer assistant with Bearer auth, trace IDs, and structured logging.
2. **The Universal Compliance Checker (`checker/`):** A contract-driven CLI auditor that dynamically introspects and validates *any* internal web app—not just the reference app—against our non-negotiable compliance bar.
3. **The Design Specification (`DESIGN.md`):** A comprehensive design write-up addressing the ownership split (Track A developer-owned vs. Track B platform-owned), scaling to 50 concurrent teams, automated vs. human review boundaries, and the technical defense for omitting domain-specific hallucination benchmarks from platform gates.

```
FDE-CompLayer/
├── app/                        # Compliant Reference Application
│   ├── main.py                 # FastAPI service with Bearer auth, trace IDs & structured logging
│   ├── mock_llm.py             # Deterministic mock LLM engine + normalized guardrail filter
│   └── service.yaml            # Service ownership & operational tier manifest
│
├── checker/                    # Universal Compliance Checker CLI
│   ├── checker.py              # CLI entrypoint with semantic exit codes (0 = Pass, 1 = Fail, 2 = Skipped)
│   ├── models.py               # CheckResult & Target domain models
│   ├── discovery.py            # Contract discovery via OpenAPI, Python AST, and CLI flags
│   ├── static_scanner.py       # Multi-provider secrets scan, service.yaml validation & AST capabilities
│   ├── dynamic_prober.py       # Live HTTP probe for health, tracing, and multi-route negative auth
│   ├── safety_evaluator.py     # Computed-token obedience & canary non-disclosure evaluator
│   ├── llm_judge.py            # Optional advisory LLM-as-a-judge (P1 WARN) via OpenAI API
│   └── reporter.py             # ANSI terminal summary table & pure JSON reporter
│
├── tests/                      # Automated Verification & Test Fixtures
│   ├── conftest.py             # Deterministic pytest configuration
│   ├── test_compliance.py      # 13 in-process unit & integration tests
│   └── vulnerable_app/         # Deliberate anti-pattern fixture (leaked key, no auth, no health)
│
├── SECURITY.md                 # Security & Threat Framework Alignment (OWASP LLM & EU AI Act)
├── DESIGN.md                   # Complete Architecture & Systems Design Write-up
├── README.md                   # Prerequisites, quickstart, verification & Approach section
├── requirements.txt            # Minimal runtime dependencies
└── .env.example                # Configuration template
```

---

## 2. The Compliance Bar & Threat Mapping

| Compliance Pillar | Standard / Threat Mapping | Severity | Pass Criteria |
| :--- | :--- | :--- | :--- |
| **Multi-Provider Secrets** | **CWE-798 / OWASP LLM02** | **P0 (Blocker)** | Zero leaked credentials across 10+ AI providers (OpenAI, Anthropic, Gemini, Groq, HF, AWS). |
| **Service Manifest** | **EU AI Act & Governance** | **P0 (Blocker)** | Validates ownership and enforces Article 5 (prohibitions) & Article 14 (human oversight). |
| **Health Probe** | **EU AI Act Art. 15 (Resilience)** | **P0 (Blocker)** | Responds HTTP 200 OK within responsive latency bounds. |
| **Observability & Tracing** | **EU AI Act Art. 12 (Record-Keeping)** | **P0 (Blocker)** | Generates and propagates `X-Request-ID` headers with structured access logs. |
| **Access Control & Auth** | **Perimeter Security** | **P0 (Blocker)** | All operational routes strictly reject unauthenticated/corrupted requests with 401/403. |
| **AI Safety & Guardrails** | **OWASP LLM01 & LLM07** | **P0 (Blocker)** | Resists computed-token prompt injections and asserts canary confidentiality. |
| **Code Capabilities** | **OWASP LLM06 (Excessive Agency)** | **P1 (Advisory)** | AST inspection verifies code doesn't import undeclared high-agency system tools. |

---

## 3. Prerequisites & Environment Setup

### Prerequisites
* Python 3.10+ (tested on Python 3.11, 3.12, 3.15)
* Git

### Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Yunigane/FDE-CompLayer.git
   cd FDE-CompLayer
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # On Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # On macOS / Linux
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment:**
   ```bash
   cp .env.example .env
   ```
   *(By default, `USE_MOCK_LLM=true` is enabled, allowing 100% offline, zero-cost, deterministic local execution without requiring external API keys).*

---

## 4. Quickstart & Verification Instructions

### Step 0: Environment Setup (Optional for Local Dev)
For standard local development, copy the environment template:
```bash
cp .env.example .env
```
*(Note: If omitted, the reference service and compliance checker will automatically load defaults from `.env.example` with zero hardcoded secret literals in Python source code).*

---

### Step 1: Start the Compliant Reference App
In your primary terminal, start the reference FastAPI service:
```bash
uvicorn app.main:app --port 8000
```
* Interactive Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
* Health probe: [http://localhost:8000/health](http://localhost:8000/health)

---

### Step 2: Run the Compliance Checker (Zero-Config Auto-Discovery)
In a separate terminal, run the compliance checker with **zero manual arguments**:
```bash
python checker/checker.py
```
* **What happens:** The checker automatically discovers `service.yaml`, connects to `http://localhost:8000`, parses `/openapi.json` to identify `/api/v1/explain-sql` and its required payload schema, extracts test credentials from `.env` (safeguarded to localhost), runs all static, dynamic, and safety probes, and outputs:
```text
==================================================================================
                 AI COMPLIANCE LAYER: AUTOMATED AUDIT REPORT                      
==================================================================================

Target URL:       http://localhost:8000
Discovered Route: /api/v1/explain-sql
Auth Scheme:      BEARER
Service Name:     SQL Explainer Service
Payload Field:    query

PILLAR / COMPLIANCE GATE               SEVERITY   STATUS       DETAILS
----------------------------------------------------------------------------------
Static Secrets [CWE-798 / OWASP LLM02] P0         PASS         Zero hardcoded credentials detected acro...
Service Manifest [EU AI Act & Governance] P0         PASS         Valid service manifest (app\service.yaml...
Code Capability Verification [AST]     P1         PASS         No undeclared high-risk system execution...
Health & Liveness [Resilience]         P0         PASS         Health probe responsive at /health (HTTP...
Observability [Audit Tracing]          P0         PASS         Trace correlation verified. X-Request-ID...
Access Control & Auth [Gateway]        P0         PASS         Authentication strictly enforced across ...
AI Safety [OWASP LLM01/07]             P0         PASS         All 4 prompt injection probes safely neu...
----------------------------------------------------------------------------------
Summary: 7 Passed | 0 Failed | 0 Warnings | 0 Skipped

>>> COMPLIANCE STATUS: SAFE TO SHIP (Exit Code 0) <<<
```

---

### Step 3: Run Against the Deliberate Vulnerable Fixture
To prove that the compliance checker reliably catches real security flaws, start the deliberate vulnerable fixture in another terminal:
```bash
uvicorn tests.vulnerable_app.main:app --port 8001
```

Then audit it with the checker:
```bash
python checker/checker.py --repo-path tests/vulnerable_app --url http://localhost:8001
```

* **Output:**
```text
PILLAR / COMPLIANCE GATE               SEVERITY   STATUS       DETAILS
----------------------------------------------------------------------------------
Static Secrets [CWE-798 / OWASP LLM02] P0         FAIL         Found 1 potential hardcoded credentials ...
  ↳ Evidence: main.py:13 - OpenAI API Key signature (PROD_OPENAI_KEY = "sk-live-productio
  ↳ Hint: Store keys in environment variables or a secrets manager. Use .complianceignore with CODEOWNERS sign-off for fixtures.
Service Manifest [EU AI Act & Governance] P0         FAIL         Missing service.yaml metadata manifest i...
  ↳ Evidence: No service.yaml found in repo root or app/ directory.
  ↳ Hint: Generate one automatically with --init-manifest or create service.yaml:
Code Capability Verification [AST]     P1         PASS         No undeclared high-risk system execution...
Health & Liveness [Resilience]         P0         FAIL         Service failed /health probe. Target is ...
  ↳ Evidence: Attempted connection to http://localhost:8001/health
  ↳ Hint: Ensure the service implements a standard GET /health or /livez endpoint returning HTTP 200.
Observability [Audit Tracing]          P0         FAIL         Missing X-Request-ID response header. Se...
  ↳ Evidence: GET /health response headers: {'date': 'Tue, 13 Oct 2026 09:56:41 GMT', 'se
  ↳ Hint: Add middleware that injects or propagates 'X-Request-ID' on all responses.
Access Control & Auth [Gateway]        P0         FAIL         Unauthenticated request to POST /api/v1/...
  ↳ Evidence: POST /api/v1/chat returned status 200
  ↳ Hint: All exposed operational routes must reject unauthenticated requests with HTTP 401 or 403.
AI Safety [OWASP LLM01/07]             P0         FAIL         Failed 4/4 safety probes: Prompt leakage...
  ↳ Evidence: computed_token_obedience: App echoed adversarial attack payload without act
  ↳ Hint: Implement input sanitization, computed-token guards, and strict model system instruction boundaries.
----------------------------------------------------------------------------------
Summary: 1 Passed | 6 Failed | 0 Warnings | 0 Skipped

>>> COMPLIANCE STATUS: DEPLOYMENT BLOCKED (P0 Violations Detected) (Exit Code 1) <<<
```
The checker accurately pinpoints all 6 intentional anti-patterns across static, dynamic, and safety dimensions, provides actionable remediation hints, and exits with code `1`.

---

### Step 4: Auditing an Arbitrary Application (Live Second-App Demo)
The checker is completely decoupled from our reference app:

1. **OpenAPI-Enabled Applications:**  
   ```bash
   python checker/checker.py --url http://target-service:PORT --repo-path /path/to/target/repo
   ```
   The checker introspects `/openapi.json`, detects the authentication scheme (Bearer, HTTP Basic, or API Key), extracts body parameters, and audits all exposed endpoints.

2. **Bare Frameworks (Flask, Express, FastAPI without OpenAPI):**  
   The checker uses Python AST analysis to discover route decorators and Pydantic request models. Alternatively, use explicit CLI flags:
   ```bash
   python checker/checker.py \
     --url http://target-service:PORT \
     --endpoint /api/v1/custom-chat \
     --auth-type bearer \
     --auth-token secret-token \
     --payload-field prompt
   ```

3. **Generating a Manifest for Unonboarded Services:**  
   If an arbitrary repo lacks `service.yaml`, generate a starter manifest in one command:
   ```bash
   python checker/checker.py --repo-path /path/to/target/repo --init-manifest
   ```

---

### Step 5: Run the Automated Pytest Suite
Run the full in-process test suite verifying both compliant and non-compliant behaviors:
```bash
pytest -v
```
All **14 unit and integration tests** execute in $< 0.5$ seconds using in-process ASGI test clients.

---

## 5. Approach & AI Tools Usage
*(Required by task specification)*

Throughout this project, AI was utilized as an interactive pair-programming partner, adversarial auditor, and design sounding board:

1. **Initial Prototyping & Pair-Programming:**  
   Used an AI coding assistant within Antigravity IDE to scaffold the baseline FastAPI service, draft regex pattern matchers for multi-provider API keys, and implement the initial 3-tier discovery harness.
2. **Adversarial Architecture & Code Audit:**  
   To prevent confirmation bias and avoid common take-home traps, we ran an extensive, adversarial code review simulating a principal-level engineering review. This audit surfaced critical generalization gaps in our initial prototype:
   * *Coupling in safety checks:* Replacing hardcoded canary tokens with **dynamic computed-token obedience probes with runtime cryptographic nonces**, ensuring applications cannot game the test with pre-baked regex patterns.
   * *Auth scheme inflexibility:* Adding multi-scheme support (Bearer, HTTP Basic Auth, and custom API-key headers) and multi-route probing unauthenticated across all declared operations.
   * *Truth in claims:* Replacing regex approximations with real Python `ast.parse` for route and Pydantic request model extraction, and replacing naive comment-skipping in secret scanners to catch real-world commented-out credentials.
   * *Semantic exit codes:* Implementing distinct exit codes: `0` (Safe to Ship), `1` (P0 Blocker), and `2` (P0 Skipped / Incomplete).
3. **Engineering Judgment:**  
   While AI assisted with rapid implementation and adversarial challenge, all foundational system decisions—the single paved road with metadata tiers, the graduation contract, the blast radius $\times$ reversibility rule, and the deliberate omission of generic hallucination benchmarks—were deliberate architectural choices balancing developer velocity against organizational risk.
