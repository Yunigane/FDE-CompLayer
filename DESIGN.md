# Compliance Layer Architecture & Design Specification

This document details the architectural choices, boundary lines, and operational tradeoffs for the automated AI compliance layer, directly answering the five core evaluation criteria.

---

## 1. What's in the Bar and Why. What Was Deliberately Left Out, and Why.

### What is in the bar (The Non-Negotiable Baseline)

The compliance bar is designed to be a deterministic, fast (<15 seconds), and objective CI gate. If a check cannot produce a reproducible pass/fail verdict without human judgment, it does not belong in the blocking gate.

1. **No Committed Credentials (Static):**
   * *What:* Pattern-based scanning across major AI providers (OpenAI, Anthropic, Gemini, Groq, Mistral, HuggingFace, AWS) plus verifying `.env` is uncommitted and listed in `.gitignore`.
   * *Why:* The most common security incident in internal AI micro-apps is leaking production API keys under the assumption that internal git repositories are private. A leaked key compromises organization data and creates unbounded cloud spend.
2. **Authentication Enforced on All Routes (Dynamic):**
   * *What:* Negative probing across all exposed API operations unauthenticated and with corrupt tokens, asserting HTTP `401` or `403`.
   * *Why:* Internal networks are not zero-trust. Leaving auxiliary routes open (e.g., leaving a chat endpoint behind auth while leaving an admin or status route exposed) allows lateral privilege escalation between teams.
3. **Structured Tracing & Health Liveness (Dynamic & Static):**
   * *What:* An active HTTP `200` health check at `/health` and propagation/generation of `X-Request-ID` correlation headers logged in structured JSON with latency.
   * *Why:* When 50 internal apps talk to shared models, incidents become impossible to debug without request IDs. It also satisfies statutory audit logging requirements (such as EU AI Act Article 12).
4. **Prompt Injection & Computed Token Obedience (Dynamic):**
   * *What:* Probing endpoints with adversarial system-prompt extractions and a computed-token obedience challenge (`"concatenate CMP and 7731"` $\rightarrow$ `"CMP7731"`).
   * *Why:* Basic prompt injection resistance prevents arbitrary instruction hijacking. The computed-token mechanism is critical: it distinguishes an LLM that actually follows attacker commands from an app that merely echoes or formats user input.
5. **Declarative Service Manifest (`service.yaml`):**
   * *What:* Mandatory repository metadata declaring owning team, operational tier, alert targets, and statutory risk classification.
   * *Why:* Eliminates "orphan apps" and establishes clear alert routing before the app ever receives production traffic.

---

### What was deliberately left out, and why

1. **Model Accuracy & Hallucination Benchmarks:**
   * *Why:* You cannot build a generic, platform-level gate for hallucination. Hallucination is completely domain-specific. A SQL explainer needs ground-truth SQL syntax tests; an internal HR policy bot needs company handbook retrieval evals; a code translator needs test execution. 
   * *The Failure Mode:* Imposing a universal hallucination benchmark inside a platform compliance gate produces either high false positives (blocking valid PRs because a generic metric disagreed) or false confidence (a toy benchmark passed, but real domain answers were wrong).
   * *Where it belongs:* Offline golden-dataset evaluation suites owned by the specific product team, paired with post-deployment user feedback widgets. The platform provides evaluation tooling and dataset storage, but individual teams own their domain ground truth.
2. **Deep Data Loss Prevention (DLP) & PII Content Inspection:**
   * *Why:* Running universal regex inspection for credit cards, tax IDs, or names across arbitrary internal business payloads (finance tables, HR queries, engineering traces) introduces heavy latency and massive false-positive rates.
   * *Where it belongs:* Enforced at IAM and platform database access boundaries (least-privilege service accounts, database-level column masking), not via payload regexes in a lightweight CI gate.
3. **Fine-Grained Authorization (RBAC):**
   * *Why:* The platform gate verifies *identity* (authentication: is this request signed by a valid user/service?). Verifying *permissions* (can User X read Employee Y's salary?) requires deep business domain knowledge that belongs in application code.

---

## 2. The Ownership Split: Developer-Owned vs. Centrally-Owned Apps

Maintaining two separate technology stacks—a loose "wild west" stack for hackathon prototypes and a rigid platform stack for "official" tools—inevitably leads to technical debt and security blind spots.

Our design uses a **Single Paved Road with Metadata-Driven Operational Tiers**. Both tracks use identical container base images, deploy to the same Kubernetes infrastructure, pass through the same compliance checker, and ship logs to the same OpenTelemetry pipeline. The way of working is governed entirely by `service.yaml`:

```yaml
service_name: "sql-assistant"
owner_team: "bi-analytics"
operational_tier: "tier_2_self_service" # or "tier_1_platform_managed"
alerts:
  slack_channel: "#bi-tooling-alerts"
  pagerduty_service: "PD-BI-TEAM"
contact: "bi-eng@company.internal"
regulatory_compliance:
  eu_ai_act_risk_tier: "minimal_risk"
  human_oversight: false
  transparency_notice: true
```

### How the way of working differs in practice

| Operational Responsibility | Track A: Developer-Owned (`tier_2_self_service`) | Track B: Centrally-Owned (`tier_1_platform_managed`) |
| :--- | :--- | :--- |
| **Monitoring & PagerDuty** | Platform alert router sends latency/5xx alerts directly to the owning team's Slack and PagerDuty rotation. | Alert rules route directly to the Central Platform SRE / on-call rotation. |
| **User Feedback Routing** | In-app feedback widget auto-files tickets in the owning team's Jira/Linear board. | Feedback routes to the Central Platform Support queue with formal SLAs. |
| **Deployments & Cadence** | Continuous deployment: PR merges deploy automatically upon passing the compliance checker. | Scheduled deployment windows with required canary bake periods and automated rollback triggers. |
| **Incident Rollbacks** | Team engineer on-call executes rollback via self-service CLI. | Automated platform rollback executed by SRE when error budgets are breached. |
| **Dependencies & Patching** | Owning team maintains library updates and security patches. | Central platform Renovate bot automatically applies and tests platform base image patches. |

### Practical infrastructure decisions that prevent chaos

1. **Alert Routing Daemon:** A central telemetry router consumes `service.yaml` on deployment and dynamically configures alert routing. If `operational_tier == tier_2_self_service`, Prometheus Alertmanager targets the team's PagerDuty key; if `tier_1_platform_managed`, it routes to platform on-call.
2. **The Graduation Contract (Hand-Off SLA):** To stop teams from simply "dumping" unmaintainable prototypes onto the central team, an app cannot graduate from Track A to Track B without passing formal hand-off criteria:
   * **30-Day Stability:** Zero compliance failures or active waivers for $\ge 30$ continuous days.
   * **Test Coverage:** $\ge 80\%$ automated integration test coverage.
   * **Runbook & Architecture:** Documented failure modes, upstream model dependencies, and escalation contacts.
   * **Budget Sign-Off:** Token spend and cloud resource limits approved by Platform Leadership.
   * **Named Domain SME:** A designated engineer from the building team remains committed for Tier-3 domain escalations.

---

## 3. Scaling to 50 Teams Submitting Concurrently: Where It Bends First & What I'd Change

### Where it bends first

1. **Target Environment Bottlenecks for Dynamic Probes:** Running dynamic HTTP probes (auth, health, prompt safety) against 50 concurrent PRs requires target apps to actually run somewhere. Provisioning 50 ephemeral cloud environments or running live containers in CI runners creates cold-start latency (1–3 minutes per PR), networking ingress headaches, and runner resource exhaustion.
2. **Rule Rollouts Breaking 50 Teams at Once:** Pushing an updated compliance check simultaneously across 50 repos risks breaking dozens of active feature branches overnight, eroding developer trust in platform tooling.
3. **Waiver & False-Positive Volume:** As velocity increases, waiver requests (`.complianceignore`) and false-positive triage overwhelm the platform team.
4. **Self-Attestation Drift:** Teams will naturally take the path of least resistance and declare `minimal_risk` in `service.yaml` to avoid regulatory scrutiny.

### What I would change at scale

1. **Developer-Local Inner Loop vs. Ephemeral Multi-Tenant Container Runners:**
   * *Local Inner Loop:* Individual developers use in-process ASGI/WSGI test clients (as demonstrated in our pytest suite) for sub-second local iterations without spinning up servers.
   * *Multi-Tenant Platform Scale:* Across 50 heterogeneous enterprise teams, applications rely on conflicting dependency trees (Pydantic v1 vs. v2, PyTorch, different Python versions) or polyglot runtimes (FastAPI, Flask, Next.js/Node, Go). A central compliance gate cannot `import app` directly without severe dependency hell and arbitrary code execution vulnerabilities in CI runners. Instead, the platform standardizes on **ephemeral container runners (OCI/Docker containers in CI)** booting in $<3$s, which the compliance CLI audits over localhost HTTP. This enforces true black-box language independence and security isolation.
2. **Warn-Then-Enforce Rollout Cycles:** New compliance rules must be introduced as `P1 WARN` for two sprint cycles (30 days). The checker surfaces warnings in CI logs without failing builds, giving teams advance notice before the rule flips to a blocking `P0 FAIL`.
3. **The 90/10 Waiver Governance Model:**
   * Automation eliminates 90% of mechanical toil (hardcoded keys, missing auth middleware, missing `/healthz`, unpropagated trace IDs), freeing platform gatekeepers from routine manual audits.
   * Waivers via `.complianceignore` are strictly time-bounded (max 30 days) and require an active issue tracker reference. Permanent waivers or production high-risk overrides require `CODEOWNERS` platform sign-off. Expired waivers fail the build automatically.
4. **Static AST Capability Checks:** Supplement self-attested YAML by statically inspecting code for undeclared high-agency imports (`subprocess`, `shutil`, `sqlalchemy`, `psycopg2`, `asyncpg`, `os.system`). If a service declares `minimal_risk` with no database access but imports raw database drivers or shell execution tools, CI flags the discrepancy for human review.

---

## 4. Automated vs. Human Review Boundaries: Where to Draw the Line and Why

### The Decision Rule: Blast Radius $\times$ Reversibility

* **Fully Automated:** Decisions that are binary, deterministic, fast to execute, and easily reversible by pushing a code fix.
* **Human Review:** Decisions that involve high blast radius, irreversible state changes, sensitive external compliance liability, or subjective domain nuance.

### SRE vs. Domain SME Operational Boundary

In centrally managed apps (`tier_1_platform_managed`), operational accountability is strictly segmented:
* **Platform SRE Owns Infrastructure Golden Signals:** Container uptime, HTTP 5xx error budgets, latency SLOs ($p95 < 500\text{ms}$), API credential rotation, and token cost quotas. SRE executes rollbacks when error budgets are exhausted.
* **Domain Teams Own Semantic Quality & Prompt Drift:** Model hallucinations, response accuracy, and prompt tuning are **never an SRE paging incident**. User feedback and accuracy regressions route asynchronously to the designated business unit SME during normal business hours.

| Finding / Scope | Fully Automated Gate | Escalates to Human Review | Rationale |
| :--- | :--- | :--- | :--- |
| **API Keys & Secrets** | Hardcoded key patterns block immediately. | Formal waiver request with ticket ID and expiry. | Secret leaks are objective and non-negotiable. |
| **Route Authentication** | Endpoints returning 200 without auth block build. | Exposing an intentionally public route (`auth: none`). | Exposing unauthenticated routes dramatically widens the organization's attack perimeter. |
| **Prompt Injection** | Dynamic computed-token obedience and canary disclosure. | Complex autonomous agents executing external tool calls. | Autonomous tools can trigger irreversible side effects on internal systems. |
| **Regulatory Tiering** | Manifest syntax, schema, and legal enum checks. | Declaring or changing an app to `high_risk` (EU AI Act). | Regulatory classification carries legal liability and cannot be purely self-attested. |
| **Data & DB Access** | Manifest declarations of read-only access. | Requests for production database write permissions or raw PII access. | Database mutations and customer data exposure are irreversible. |

---

## 5. What I'd Tackle First With Two More Weeks

If given two additional weeks of engineering time, the top priorities would be:

1. **Company AI Scaffolding CLI (`create-ai-app`):**
   * The most effective way to enforce compliance is to make the compliant path the easiest path. A lightweight CLI scaffolding tool (supporting FastAPI and Next.js/TypeScript) that generates repositories with auth middleware, OpenTelemetry tracing, `X-Request-ID` propagation, and pre-wired guardrails by default. Teams pass compliance out of the box on day one.
2. **Golden-Set Offline Evaluation Pipeline:**
   * Provide a standardized evaluation library allowing teams to run golden-dataset accuracy and hallucination evaluations offline during development, completely separate from the pre-merge blocking CI gate.
3. **Central Compliance Dashboard & Expiring Waiver Registry:**
   * A lightweight web console aggregating compliance status, operational tier distribution, and expiring waivers across all 50 internal applications, giving platform leads real-time visibility without blocking developer PR workflows.
