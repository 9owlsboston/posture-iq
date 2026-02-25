# PostureIQ — ME5 Security Posture Assessment Agent

> **Project:** PostureIQ — an intelligent agent that assesses ME5 security posture and accelerates the Project 479 "Get to Green" motion
> **Target:** GitHub Copilot SDK Enterprise Challenge — Submission by **Mar 7, 10 PM PST**
> **Stack:** Copilot SDK (Python) + Microsoft Graph Security API + M365 Defender + Purview + Entra ID P2 + Azure OpenAI
> **Deployment:** Azure Container Apps
> **Scoring ceiling:** ~128 pts (98 base + 30 bonus)
> **Repo:** `posture-iq`

---

## Phase 0 — Project Setup & Scaffolding (Day 1)

### 0.1 Repository & Dev Environment

- [ ] Create GitHub repo `posture-iq`
- [ ] Initialize Python project structure:
  ```
  posture-iq/
  ├── src/
  │   ├── agent/              # Agent host app
  │   │   ├── __init__.py
  │   │   ├── main.py         # Entry point — Copilot SDK session setup
  │   │   ├── system_prompt.py # Agent persona & instructions
  │   │   └── config.py       # Environment config loader
  │   ├── tools/              # Tool implementations (Graph API calls)
  │   │   ├── __init__.py
  │   │   ├── secure_score.py
  │   │   ├── defender_coverage.py
  │   │   ├── purview_policies.py
  │   │   ├── entra_config.py
  │   │   ├── remediation_plan.py
  │   │   └── adoption_scorecard.py
  │   ├── middleware/          # Cross-cutting concerns
  │   │   ├── __init__.py
  │   │   ├── content_safety.py   # Azure AI Content Safety wrapper
  │   │   ├── pii_redaction.py    # PII/tenant data redaction
  │   │   ├── audit_logger.py     # Immutable audit trail
  │   │   └── tracing.py          # App Insights distributed tracing
  │   └── api/                # HTTP API layer (health probes + optional REST)
  │       ├── __init__.py
  │       └── app.py
  ├── infra/                  # Bicep IaC templates
  │   ├── main.bicep
  │   ├── modules/
  │   │   ├── container-app.bicep
  │   │   ├── openai.bicep
  │   │   ├── app-insights.bicep
  │   │   ├── content-safety.bicep
  │   │   └── keyvault.bicep
  │   └── parameters/
  │       ├── dev.bicepparam
  │       └── prod.bicepparam
  ├── .github/
  │   └── workflows/
  │       └── ci-cd.yml       # GitHub Actions pipeline
  ├── tests/
  │   ├── unit/
  │   └── integration/
  ├── docs/
  │   ├── sdk-feedback.md     # Running log of SDK pain points (10 bonus pts)
  │   ├── setup-guide.md      # Graph API permission setup script
  │   └── architecture.md     # Architecture diagram for deck
  ├── Dockerfile
  ├── pyproject.toml
  ├── requirements.txt
  └── README.md
  ```
- [ ] Set up Python virtual environment with dependencies:
  - `copilot-sdk` (GitHub Copilot SDK)
  - `azure-identity` (Entra ID auth)
  - `msgraph-sdk` (Microsoft Graph API)
  - `openai` / `azure-ai-openai` (Azure OpenAI)
  - `azure-ai-contentsafety` (RAI content filtering)
  - `azure-monitor-opentelemetry` (App Insights distributed tracing)
  - `fastapi` + `uvicorn` (health probes API)
  - `pytest`, `pytest-asyncio` (testing)
- [ ] Configure `.env.example` with required environment variables
- [ ] **Start `docs/sdk-feedback.md`** — log every friction point from day 1

### 0.2 Azure Resource Provisioning (Manual or Bicep)

- [ ] Create Azure Resource Group: `rg-postureiq-dev`
- [ ] Provision Azure OpenAI (GPT-4o deployment) — for reasoning & summarization
- [ ] Provision Azure AI Content Safety — for RAI filtering
- [ ] Provision Azure Application Insights — for observability
- [ ] Provision Azure Key Vault — for Graph API secrets & credentials
- [ ] Register an Entra ID App Registration — for delegated Graph API access
  - Required Graph API scopes (minimal, least-privilege):
    - `SecurityEvents.Read.All` (Secure Score)
    - `SecurityActions.Read.All` (Defender status)
    - `InformationProtection.Read.All` (Purview policies) 
    - `Policy.Read.All` (Conditional Access / Entra config)
    - `Reports.Read.All` (Usage & adoption telemetry)
  - Document admin consent requirements in `docs/setup-guide.md`
- [ ] Create a setup script (`scripts/setup-permissions.sh`) for Graph API permission grants

---

## Phase 1 — Core Agent Implementation (Days 2–4)

### 1.1 Agent Host Setup (Copilot SDK)

- [ ] Implement `src/agent/main.py` — Copilot SDK client initialization:
  - Import SDK, create `CopilotClient`
  - Register all 6 tools (see 1.2)
  - Set system prompt (see 1.3)
  - Create session and handle multi-turn conversation loop
- [ ] Implement session lifecycle management (create, maintain, close)
- [ ] Wire up streaming responses for real-time UX

### 1.2 Tool Implementations (6 tools — the agent's "hands")

Each tool wraps Microsoft Graph Security API calls and returns structured data for the runtime to reason over.

#### Tool 1: `query_secure_score`
- [ ] Call Graph API: `GET /security/secureScores`
- [ ] Parse and return:
  - Current secure score (numerical)
  - Score breakdown by category (Identity, Data, Device, Apps, Infrastructure)
  - Trend data (last 30 days)
  - Comparison to avg tenant in same industry
- [ ] Add App Insights trace span for this tool call

#### Tool 2: `assess_defender_coverage`
- [ ] Query M365 Defender deployment status:
  - Defender for Endpoint: onboarded device count vs total
  - Defender for Office 365: enabled policies (Safe Links, Safe Attachments)
  - Defender for Identity: sensor coverage
  - Defender for Cloud Apps: connected apps count
- [ ] Return coverage percentage per workload + gap list
- [ ] Add App Insights trace span

#### Tool 3: `check_purview_policies`
- [ ] Query Information Protection & Compliance policies:
  - DLP policies: count, status (active/test/disabled), scope
  - Sensitivity labels: published labels, auto-labeling rules
  - Retention policies: coverage across Exchange, SharePoint, OneDrive, Teams
  - Insider Risk Management: policy status
- [ ] Return adoption status with specific gaps identified
- [ ] Add App Insights trace span

#### Tool 4: `get_entra_config`
- [ ] Query Entra ID P2 security configuration:
  - Conditional Access policies: count, named locations, MFA enforcement
  - PIM (Privileged Identity Management): active assignments vs eligible
  - Identity Protection: risk policies (sign-in risk, user risk) — enabled or not
  - Access Reviews: configured or not
  - SSO app registrations count
- [ ] Return config assessment with risk flags
- [ ] Add App Insights trace span

#### Tool 5: `generate_remediation_plan`
- [ ] Takes output from tools 1–4 as input context
- [ ] Uses Azure OpenAI (GPT-4o) to generate:
  - Prioritized remediation steps (P0/P1/P2)
  - For each step: description, impact on secure score, effort estimate, PowerShell/CLI config scripts
  - Estimated time-to-green if all steps completed
- [ ] Route LLM output through **Azure AI Content Safety** before returning
- [ ] Add confidence scores to each recommendation
- [ ] Redact tenant-specific PII (tenant IDs, user emails) before sending to model
- [ ] Add App Insights trace span

#### Tool 6: `create_adoption_scorecard`
- [ ] Aggregates data from all tools into a structured scorecard:
  - Overall ME5 adoption percentage
  - Per-workload status (green/yellow/red): Defender XDR, Purview, Entra ID P2
  - Top 5 gaps with remediation priority
  - Estimated days to green
  - Historical trend (if available)
- [ ] Output format: structured JSON (for programmatic consumption) + markdown (for human reading)
- [ ] Add App Insights trace span

### 1.3 System Prompt Engineering

- [ ] Write system prompt in `src/agent/system_prompt.py`:
  - Persona: "You are an ME5 Security Posture Assessment specialist..."
  - Context: Project 479 "Get to Green" campaign objectives
  - Behavioral instructions:
    - Always start with `query_secure_score` to establish baseline
    - Assess all workloads before generating remediation
    - Prioritize by impact on secure score
    - Be specific — include PowerShell scripts, not just descriptions
    - Never expose raw tenant IDs or user data in responses
  - Guardrails:
    - Do not make changes to customer tenants — assessment only
    - Flag when admin consent is needed for deeper assessment
    - Include disclaimers on AI-generated recommendations

### 1.4 Unit Tests

- [ ] Test each tool with mocked Graph API responses
- [ ] Test system prompt produces expected agent behavior patterns
- [ ] Test PII redaction catches tenant IDs, emails, UPNs
- [ ] Test content safety integration rejects harmful outputs

---

## Phase 2 — Cross-Cutting: Operational Readiness (Days 3–5)

> **Target: 15 pts → capture all 15** (currently at 5 = −10 pts gap)

### 2.1 CI/CD Pipeline (GitHub Actions)

- [ ] Create `.github/workflows/ci-cd.yml`:
  ```yaml
  # Trigger on push to main
  # Stages: lint → test → build → deploy
  ```
  - **Lint**: `ruff` + `mypy` type checking
  - **Test**: `pytest` with coverage report, fail if < 80%
  - **Build**: Docker image build, push to Azure Container Registry
  - **Deploy**: Bicep deployment to Azure Container Apps
- [ ] Add branch protection rules on `main` (require passing CI)
- [ ] Add a `dev` environment for PR deployments (optional but impressive)

### 2.2 Infrastructure as Code (Bicep)

- [ ] `infra/main.bicep` — orchestrator that calls modules:
  - Azure Container Apps Environment + Container App
  - Azure OpenAI account + GPT-4o deployment
  - Azure Application Insights + Log Analytics workspace
  - Azure AI Content Safety instance
  - Azure Key Vault (for Graph API credentials)
  - Managed Identity assignments
- [ ] `infra/modules/container-app.bicep`:
  - Scales 0–5 replicas (emphasize scale-to-zero for cost)
  - Health probe configuration (`/health`, `/ready`)
  - Managed Identity enabled
  - Environment variables from Key Vault references
- [ ] `infra/parameters/dev.bicepparam` and `prod.bicepparam`
- [ ] Validate Bicep linting passes in CI

### 2.3 Observability (Azure Application Insights)

- [ ] Integrate `azure-monitor-opentelemetry` SDK in `src/middleware/tracing.py`:
  - Every tool call = a distributed trace **span** with:
    - Tool name
    - Duration
    - Input parameters (redacted)
    - Output summary (token count, status)
    - Graph API call latency
  - Every LLM call = a span with:
    - Model name
    - Token usage (prompt + completion)
    - Content Safety filter result
  - Every session = a trace with correlation across all tool calls
- [ ] Structured JSON logging (`structlog` or `python-json-logger`):
  - Log format: `{"timestamp", "level", "tool", "session_id", "duration_ms", "status"}`
  - No PII in logs (redaction middleware applied)
- [ ] Custom App Insights metrics:
  - `postureiq.secure_score.current` — gauge
  - `postureiq.assessment.duration_seconds` — histogram
  - `postureiq.remediation.steps_generated` — counter
  - `postureiq.content_safety.blocked_count` — counter
- [ ] Create an App Insights dashboard (can be shown in demo)

### 2.4 Health Probes

- [ ] Implement in `src/api/app.py` (FastAPI):
  - `GET /health` — returns 200 if the process is alive
  - `GET /ready` — returns 200 only if:
    - Copilot SDK session can be created
    - Graph API auth token is valid
    - Azure OpenAI endpoint responds
    - Key Vault is accessible
  - `GET /version` — returns build info (git SHA, build time)

### 2.5 Deployment Target: Azure Container Apps

- [ ] Write `Dockerfile`:
  - Python slim base image
  - Install GitHub CLI (required for Copilot SDK runtime)
  - Copy app code, install dependencies
  - Expose health probe port
  - Set entrypoint to `uvicorn src.api.app:app`
- [ ] Configure Container Apps:
  - Ingress: internal (or external for demo)
  - Scale: min 0, max 5 replicas
  - Health probes defined in Bicep
  - Managed Identity for Key Vault + Azure OpenAI access

---

## Phase 3 — Cross-Cutting: Security, Governance & RAI (Days 4–5)

> **Target: 15 pts → capture 14–15** (currently at 14 = −1 pt gap)

### 3.1 Authentication & Authorization

- [ ] **User auth**: Entra ID with OAuth2 authorization code flow
  - Users authenticate to the agent via Entra ID
  - The agent uses **delegated permissions** (acts on behalf of the user)
  - Ensures the agent only sees data the user is authorized to see
- [ ] **Service auth**: Managed Identity for service-to-service
  - Container App → Azure OpenAI (Managed Identity, no API keys)
  - Container App → Key Vault (Managed Identity)
  - Container App → App Insights (Managed Identity)
- [ ] **Graph API auth**: 
  - Use `azure-identity` `InteractiveBrowserCredential` (for dev) / `ClientSecretCredential` (for service)  
  - Store client secret in Key Vault, access via Managed Identity
  - Document least-privilege scopes in `docs/setup-guide.md`
  - Provide `scripts/setup-permissions.sh` for admin consent

### 3.2 Responsible AI (RAI)

- [ ] **Azure AI Content Safety integration** (`src/middleware/content_safety.py`):
  - Filter all LLM inputs (prevent prompt injection in user queries)
  - Filter all LLM outputs (ensure remediation plans don't contain harmful content)
  - Log filter results to App Insights
  - Block responses that fail safety checks; return safe fallback
- [ ] **PII Redaction** (`src/middleware/pii_redaction.py`):
  - Before sending any data to Azure OpenAI:
    - Redact tenant GUIDs → `[TENANT_ID]`
    - Redact user emails/UPNs → `[USER_EMAIL]`
    - Redact IP addresses → `[IP_ADDRESS]`
    - Redact user display names → `[USER_NAME]`
  - After receiving model output, re-hydrate if needed for customer-facing display
- [ ] **Confidence scores**:
  - Every remediation recommendation includes a confidence score (high/medium/low)
  - Based on: how much data was available, how standard the remediation is
- [ ] **Disclaimer watermarks**:
  - All AI-generated scorecards include: "Generated by AI — review with your security team before implementing"
- [ ] **Prompt injection guardrails**:
  - System prompt includes explicit instructions to ignore override attempts
  - Input validation on user queries (length, character set)

### 3.3 Audit Trail

- [ ] **Immutable audit log** (`src/middleware/audit_logger.py`):
  - Every agent action logged with:
    - Timestamp (UTC)
    - Session ID
    - User identity (from Entra ID token)
    - Tool called
    - Input summary (redacted)
    - Output summary (redacted)
    - Reasoning chain (why the agent chose this tool)
  - Stored in App Insights `customEvents` table (queryable via KQL)
  - Retention policy: 90 days (configurable)
- [ ] RBAC on audit log access (only security admins can query)

---

## Phase 4 — Bonus: Foundry IQ / Fabric Integration (Days 5–6)

> **Target: 15 bonus pts → capture 12** (currently at 12 est.)

### 4.1 Foundry IQ Integration (Agent Context)

- [ ] Pull **Project 479 playbooks** from Foundry IQ as agent context:
  - ME5 Get to Green standard playbook
  - Offer catalog (which Project 479 offers to recommend based on gaps)
  - Customer onboarding checklists
- [ ] Inject playbook summaries into the system prompt or as tool context
- [ ] Tool: `get_project479_playbook` — retrieves relevant playbook section based on identified gaps

### 4.2 Fabric Integration (Telemetry Push)

- [ ] Push security posture snapshots to a **Fabric lakehouse**:
  - After each assessment, write a row to the lakehouse:
    - Tenant ID (hashed), assessment timestamp, secure score, per-workload scores, gap count, estimated days to green
  - Enables longitudinal dashboards showing posture improvement over time
- [ ] Create a simple Power BI dashboard template showing:
  - Secure score trend across assessed tenants
  - Most common gaps (aggregated, anonymized)
  - Average time-to-green

---

## Phase 5 — Demo, Deck & Submission (Days 6–7)

### 5.1 Demo Video (3 min max)

- [ ] Script the demo flow:
  1. **Hook** (15s): "ME5 account teams spend weeks assessing security posture. This agent does it in minutes."
  2. **Auth** (15s): Show Entra ID login, delegated permissions
  3. **Assessment run** (60s): User asks "Assess this tenant's ME5 security posture"
     - Agent calls `query_secure_score` → shows score
     - Agent calls `assess_defender_coverage` → shows gaps
     - Agent calls `check_purview_policies` → shows missing DLP
     - Agent calls `get_entra_config` → shows weak Conditional Access
  4. **Remediation** (45s): Agent generates prioritized plan with PowerShell scripts
  5. **Scorecard** (20s): Agent creates adoption scorecard (green/yellow/red per workload)
  6. **Ops & security** (15s): Quick flash of App Insights traces, Content Safety filtering, audit log
  7. **Close** (10s): "This agent accelerates the Project 479 Get-to-Green motion for thousands of ME5 accounts."
- [ ] Record with screen capture + voiceover
- [ ] Keep under 3 minutes

### 5.2 Presentation Deck (1–2 slides)

- [ ] **Slide 1**: Architecture diagram showing:
  - Copilot SDK → Agent Runtime → 6 Tools → Graph Security API
  - Azure services: OpenAI, Content Safety, Container Apps, App Insights, Key Vault, Entra ID
  - Foundry IQ / Fabric integration arrows
- [ ] **Slide 2**: Impact & scoring alignment:
  - "Accelerates Project 479 — a live campaign with thousands of ME5 accounts"
  - Key metrics: time-to-assessment reduced from weeks to minutes
  - Enterprise value: reusable across all ME5 customers
  - Security: inherent — security IS the product

### 5.3 Submission Package

- [ ] Clean up repo README with:
  - Project description
  - Architecture diagram
  - Setup instructions (prerequisites, environment variables, Graph API permissions)
  - Demo video link
  - SDK feedback summary
- [ ] Ensure all code passes CI (lint + test)
- [ ] Final review: check all scoring criteria are addressed

### 5.4 SDK Feedback Document (10 bonus pts)

- [ ] Compile `docs/sdk-feedback.md` throughout development:
  - Pain points encountered
  - API gaps or missing features
  - Documentation quality feedback
  - Suggestions for improvement
  - What worked well
- [ ] Format as actionable product feedback

### 5.5 Customer Validation (10 bonus pts)

- [ ] Identify a Project 479 account team contact
- [ ] Demo the agent to them
- [ ] Collect written endorsement/feedback
- [ ] Include in submission

---

## Task Dependency Map

```
Phase 0 (Setup)
  ├── 0.1 Repo & Dev Env
  └── 0.2 Azure Provisioning
        │
        ▼
Phase 1 (Core Agent) ◄── depends on Phase 0
  ├── 1.1 Agent Host (SDK)
  ├── 1.2 Tools 1–6 (parallel)
  ├── 1.3 System Prompt
  └── 1.4 Unit Tests
        │
        ▼
Phase 2 (Ops) ◄── can start in parallel with Phase 1
  ├── 2.1 CI/CD
  ├── 2.2 Bicep IaC
  ├── 2.3 Observability
  ├── 2.4 Health Probes
  └── 2.5 Container Apps Deploy
        │
        ▼
Phase 3 (Security/RAI) ◄── depends on Phase 1 (tools exist)
  ├── 3.1 Auth (Entra ID + MI)
  ├── 3.2 RAI (Content Safety, PII, guardrails)
  └── 3.3 Audit Trail
        │
        ▼
Phase 4 (Bonus) ◄── depends on core working
  ├── 4.1 Foundry IQ
  └── 4.2 Fabric
        │
        ▼
Phase 5 (Submission) ◄── depends on everything
  ├── 5.1 Demo Video
  ├── 5.2 Deck
  ├── 5.3 Submission Package
  ├── 5.4 SDK Feedback
  └── 5.5 Customer Validation
```

---

## Scoring Projection (with all mitigations applied)

| Criteria | Max | Current | With Plan | Delta | How |
| --- | --- | --- | --- | --- | --- |
| Enterprise value & reusability | 35 | 33 | 33 | — | Already strong — Project 479 anchoring |
| Azure / Microsoft integration | 25 | 22 | 24 | +2 | Add Content Safety, Key Vault, Container Apps, App Insights |
| Operational readiness | 15 | **5** | **14** | **+9** | CI/CD + Bicep + App Insights + health probes + Container Apps |
| Security, governance & RAI | 15 | 14 | 15 | +1 | Content Safety, PII redaction, confidence scores, audit trail |
| Storytelling & amplification | 15 | 14 | 14 | — | Strong narrative already; demo will cement this |
| **Base total** | **100** | **88** | **~100** | **+12** | |
| Bonus: Foundry/Fabric/Work IQ | 15 | 12 | 12 | — | Playbook pull + telemetry push |
| Bonus: Customer validation | 10 | 8 | 8 | — | Demo to Project 479 account team |
| Bonus: SDK feedback | 10 | 0 | 8 | +8 | Running feedback log throughout dev |
| **Total ceiling** | **135** | **108** | **~128** | **+20** | |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Graph Security API requires tenant-level admin consent — may not get access to a test tenant in time | Medium | High | Use Microsoft's demo tenants (CDX tenant) for development. Mock Graph responses for demo if needed |
| Copilot SDK is in preview — APIs may break or behave unexpectedly | Medium | Medium | Start SDK integration early. Log all issues in feedback doc (turns risk into bonus points) |
| Azure OpenAI quota limits during development | Low | Medium | Use S0 tier. Have fallback to direct OpenAI API if Azure quota is exhausted |
| Foundry IQ / Fabric access may require internal approvals | Medium | Low | These are bonus points — prioritize base score first. Can fake the integration for demo with mock data |
| Timeline is tight (Feb 9 – Mar 7) | High | High | Strict phase gates. Cut Foundry/Fabric (Phase 4) if behind. Core agent + ops layer is the priority |

---

## Daily Schedule (Suggested)

| Day | Focus | Deliverable |
| --- | --- | --- |
| Day 1 | Phase 0: Setup | Repo, project structure, Azure resources provisioned, dev env working |
| Day 2 | Phase 1: Tools 1–3 | `query_secure_score`, `assess_defender_coverage`, `check_purview_policies` implemented with mocks |
| Day 3 | Phase 1: Tools 4–6 + Agent Host | `get_entra_config`, `generate_remediation_plan`, `create_adoption_scorecard` + Copilot SDK wired up |
| Day 4 | Phase 2: Ops Layer | CI/CD pipeline, Bicep templates, App Insights tracing, health probes, Dockerfile |
| Day 5 | Phase 3: Security/RAI | Entra ID auth, Content Safety, PII redaction, audit trail, unit tests passing |
| Day 6 | Phase 4: Bonus + Polish | Foundry IQ / Fabric integration (if time). End-to-end testing. Fix bugs |
| Day 7 | Phase 5: Submission | Record demo video, build deck, write README, compile SDK feedback, submit |

> **Critical path:** Phase 0 → Phase 1 (tools + SDK) → Phase 2 (ops) → Phase 5 (submit). Phases 3 and 4 are parallel/optional but high-value.
