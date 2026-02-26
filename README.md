# PostureIQ

**ME5(M365 E5) Security Posture Assessment Agent** — Built with the GitHub Copilot SDK

PostureIQ is a conversational AI agent that assesses an organization's Microsoft 365 E5 security posture, identifies deployment gaps, and generates prioritized remediation plans to accelerate the "Get to Green" (Project 479) motion.

---

## Capabilities

| Tool | Description |
|------|-------------|
| `query_secure_score` | Pull Microsoft Secure Score with category breakdown and trends |
| `assess_defender_coverage` | Evaluate Defender for Endpoint, Office 365, Identity, Cloud Apps |
| `check_purview_policies` | Audit DLP, sensitivity labels, retention, insider risk policies |
| `get_entra_config` | Assess Conditional Access, PIM, Identity Protection, access reviews |
| `generate_remediation_plan` | AI-generated prioritized remediation with PowerShell scripts |
| `create_adoption_scorecard` | Executive summary scorecard with RAG status per workload |
| `get_project479_playbook` | Foundry IQ playbook retrieval for gap-to-remediation mapping |

## Architecture

```
User ↔ Copilot SDK ↔ Agent Runtime ↔ PostureIQ Tools ↔ Microsoft Graph API
                                                      ↔ Azure OpenAI (GPT-4o)
```

See [docs/architecture.md](docs/architecture.md) for the full architecture diagram.

## Quick Start

### Prerequisites

- Python 3.11+
- Azure subscription with OpenAI, Content Safety, App Insights
- Microsoft 365 E5 tenant (or CDX demo tenant)

### Setup

```bash
# Clone and install
git clone https://github.com/velen-msft/posture-iq.git
cd posture-iq
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env — at minimum set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

# Set up Graph API permissions (requires Azure CLI)
chmod +x scripts/setup-permissions.sh
./scripts/setup-permissions.sh
```

### Run Locally

PostureIQ has **two entry points** — choose the one that fits your workflow:

| Command | Interface | Requires |
|---------|-----------|----------|
| `python -m uvicorn src.api.app:app` | Web Chat UI at `http://localhost:8000` | `.env` with Azure/Graph creds |
| `python -m src.agent.main` | CLI via Copilot SDK session loop | `gh` CLI + Copilot CLI running |

#### Option A — Web Chat UI (recommended for demos & local testing)

Starts a FastAPI server with a dark-themed chat page. Tools are dispatched via
keyword intent classification — no Copilot CLI needed.

```bash
source .venv/bin/activate
set -a && source .env && set +a
python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

#### Option B — Copilot SDK Agent Session

Starts an interactive CLI session powered by the Copilot Runtime. The SDK
registers all 8 tools and the runtime (via `gh copilot`) does the LLM planning.

```bash
source .venv/bin/activate
set -a && source .env && set +a
python -m src.agent.main
# Requires: gh CLI installed + Copilot CLI extension
```

### Run Tests

No Azure credentials required — all external calls are mocked:

```bash
source .venv/bin/activate
pytest
```

### Deploy to Azure

```bash
# 1. Set up OIDC Workload Identity Federation (one-time)
chmod +x scripts/setup-oidc.sh
./scripts/setup-oidc.sh

# 2. Provision infrastructure (creates ACR, Container App, OpenAI, etc.)
az group create --name rg-postureiq-dev --location eastus2
az deployment group create \
  --resource-group rg-postureiq-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters/dev.bicepparam

# 3. Push to main — CI/CD automatically builds, pushes to ACR, and deploys
git push origin main
```

**CI/CD Pipeline (fully automated on push to main):**
```
lint → test (80% coverage) → bicep-validate → build & push to ACR → deploy to Container Apps
```

**Authentication:** OIDC Workload Identity Federation — zero stored secrets.  
Only 3 non-sensitive GitHub secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.

## Development

```bash
# Lint
ruff check src/ tests/

# Type check
mypy src/

# Test
pytest --cov=src

# Format
ruff format src/ tests/

# Pre-flight check (run before commit/push)
./scripts/preflight.sh          # Full check (tests, lint, Bicep, YAML, Docker)
./scripts/preflight.sh --quick  # Skip Docker build
```

## Project Structure

```
posture-iq/
├── src/
│   ├── agent/          # Agent host, config, system prompt
│   ├── tools/          # 8 assessment tools (Graph API + Foundry IQ wrappers)
│   ├── middleware/      # Tracing, content safety, PII redaction, audit, auth
│   └── api/            # FastAPI health probes and HTTP endpoints
├── infra/              # Bicep IaC templates (ACR, Container Apps, OpenAI, etc.)
├── tests/              # Unit (1093) and integration (41) tests
├── docs/               # Architecture, setup guide, SDK feedback
├── scripts/            # Setup (permissions, OIDC, provisioning), cleanup, pre-flight
├── Dockerfile          # Multi-stage container build
└── .github/workflows/  # CI/CD pipeline (OIDC auth, ACR push, Bicep deploy)
```

## Security & RAI

- **Read-only** Graph API permissions — no write access
- **PII redaction** on all data before LLM and logging
- **Azure AI Content Safety** — hate, self-harm, sexual, violence filtering
- **Prompt injection detection** — heuristic + Azure Prompt Shield
- **Audit logging** — all tool calls and interactions logged
- **Managed Identity** — no secrets in code or environment variables (production)

## Scoring Alignment

| Category | Points | PostureIQ Coverage |
|----------|--------|-------------------|
| Enterprise Value | 35 | Project 479 acceleration, Secure Score improvement |
| Azure Integration | 25 | OpenAI + Content Safety + App Insights + Key Vault + Container Apps |
| Operational Readiness | 15 | CI/CD (OIDC), health probes, IaC, ACR, auto-scaling |
| Security & RAI | 15 | Content Safety, PII redaction, audit logs, prompt injection |
| Storytelling | 15 | 3-min demo: score → gaps → plan → scorecard |
| Bonus: Foundry IQ | 15 | Azure AI Foundry integration |
| Bonus: SDK Feedback | 10 | sdk-feedback.md log |

## License

Internal Microsoft use only — GitHub Copilot SDK Enterprise Challenge submission.
