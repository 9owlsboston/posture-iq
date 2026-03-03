# SecPostureIQ

> **Note:** This project was previously known as **PostureIQ**. It has been renamed
> to **SecPostureIQ** to better reflect the security-focused mission of the product,
> per a branding decision by the internal product team.

**ME5(M365 E5) Security Posture Assessment Agent** — Built with the GitHub Copilot SDK

SecPostureIQ is a conversational AI agent that assesses an organization's Microsoft 365 E5 security posture, identifies deployment gaps, and generates prioritized remediation plans to accelerate the "Get to Green" (Get to Green) motion.

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
| `push_fabric_telemetry` | Push posture snapshots to Fabric lakehouse for trend analysis & Power BI |
| `get_green_playbook` | Foundry IQ playbook retrieval for gap-to-remediation mapping |

## Architecture

```
User ↔ Copilot SDK ↔ Agent Runtime ↔ SecPostureIQ Tools ↔ Microsoft Graph API
                                                      ↔ Azure OpenAI (GPT-4o)
```

See [docs/architecture.md](docs/architecture.md) for the full architecture diagram.

## Quick Start

### Prerequisites

- Python 3.11+
- **For local dev with mock data:** Nothing else — works out of the box
- **For real tenant assessment:** Entra ID app registration + M365 E5 tenant (or [M365 E5 developer trial](https://developer.microsoft.com/en-us/microsoft-365/dev-program))
- **For cloud deployment:** Azure subscription with OpenAI, Content Safety, App Insights
- Microsoft 365 E5 tenant (or [M365 E5 developer trial](https://developer.microsoft.com/en-us/microsoft-365/dev-program); CDX demo tenants are available to Microsoft employees/partners only) — *optional for local dev, see below*

### Try It Locally (No Azure Required)

The app works **out of the box with zero Azure credentials**. When Graph API
credentials are missing, tools return realistic mock data (`"data_source": "mock"`).
Content Safety falls back to local heuristics. No OpenAI endpoint is needed — the
Web Chat UI uses keyword-based intent classification to route to tools directly.

```bash
# Clone and install
git clone https://github.com/9owlsboston/posture-iq.git
cd posture-iq
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run — no .env needed for mock mode
python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

Try: *"What is our Secure Score?"* → returns mock score of 47.3/100 with category breakdowns.

### Connect to a Real M365 Tenant (Optional)

To assess a **real** Microsoft 365 E5 tenant instead of mock data:

```bash
# 1. Configure credentials
cp .env.example .env
# Edit .env — set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

# 2. Set up Graph API permissions (creates Entra ID App Registration)
chmod +x scripts/setup-permissions.sh
./scripts/setup-permissions.sh

# 3. Run with real credentials
source .venv/bin/activate
set -a && source .env && set +a
python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

| Dependency | Without credentials | With credentials |
|------------|-------------------|-----------------|
| **Graph API** | Mock data (realistic scores, policies, configs) | Real tenant data via Microsoft Graph |
| **Azure OpenAI** | Keyword intent classification (no LLM) | GPT-4o reasoning (requires endpoint in `.env`) |
| **Content Safety** | Local heuristic filtering | Azure AI Content Safety service |
| **App Insights** | Logs to stdout via structlog | Full observability in Azure portal |

#### Copilot SDK Agent Session (Alternative)

For the LLM-powered CLI experience with the Copilot Runtime:

```bash
source .venv/bin/activate
set -a && source .env && set +a
python -m src.agent.main
# Requires: gh CLI installed + Copilot CLI extension
```

### Run Tests

All external calls are mocked — no Azure credentials required:

```bash
source .venv/bin/activate
pytest
```

### Deploy to a Customer's Azure Tenant

Three fully end-to-end options:

| Option | Command | Best For |
|--------|---------|----------|
| **Clone & Deploy** | `git clone ... && ./scripts/deploy-customer.sh` | CSA-led deployments, most customers |
| **Azure Developer CLI** | `git clone ... && azd up` | Azure-savvy developers (single command) |
| **One-Click Portal** | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2F9owlsboston%2Fposture-iq%2Fmain%2Finfra%2Fazuredeploy.json) then `./scripts/post-deploy-button.sh` | Portal-guided, no CLI required |

All three options provision infrastructure **and** set up Entra ID App Registration
with Graph API permissions automatically. See [Customer Deployment Guide](docs/ghcp_challenge_submission/secpostureiq-customer-deployment-guide.md) for full details.

> **"One-Click Portal" flow:**
> The button provisions infrastructure via the Azure Portal. After it finishes,
> run the post-deploy script to build the image, register Graph API, and go live:
>
> ```bash
> git clone https://github.com/9owlsboston/posture-iq.git && cd posture-iq
> chmod +x scripts/post-deploy-button.sh
> ./scripts/post-deploy-button.sh --resource-group <your-rg-name>
> ```

### CI/CD Pipeline (Internal Development)

```bash
# 1. Set up OIDC Workload Identity Federation (one-time)
chmod +x scripts/setup-oidc.sh
./scripts/setup-oidc.sh

# 2. Provision infrastructure (creates ACR, Container App, OpenAI, etc.)
az group create --name rg-secpostureiq-dev --location eastus2
az deployment group create \
  --resource-group rg-secpostureiq-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters/dev.bicepparam

# 3. Push to main — CI/CD automatically builds, pushes to ACR, and deploys
git push origin main
```

**Automated on push to main:**
```
lint → test (80% coverage) → bicep-validate → build & push to ACR → deploy to Container Apps
```

**Authentication:** OIDC Workload Identity Federation — zero stored secrets.  
Only 3 non-sensitive GitHub secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.

## Development Tooling

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

## Test Tools

Two scripts are included for validating a deployment (local or cloud) under realistic traffic.

### Load Test (`scripts/load_test.py`)

Fires ~50 requests over ~60 seconds with randomised delays, exercises all 8 tools via `/chat`, and prints latency percentiles (p50/p95) plus a per-request detail table.

```bash
# Against local dev server (default http://localhost:8000)
python scripts/load_test.py

# Against a cloud deployment
SECPOSTUREIQ_URL=https://my-app.azurecontainerapps.io python scripts/load_test.py
```

### Traffic Simulator (`scripts/simulate_traffic.py`)

Configurable sustained traffic generator — ideal for populating App Insights dashboards or soak-testing a deployment.

```bash
# Quick smoke — single burst of 10 requests
python scripts/simulate_traffic.py

# 30-minute sustained load, burst every 5 min, 20 requests/burst
python scripts/simulate_traffic.py --duration 30 --interval 5 --burst-size 20

# Heavy 1-hour run with health probes
python scripts/simulate_traffic.py --duration 60 --interval 2 --burst-size 50 --concurrency 10 --probes

# Target a cloud deployment
python scripts/simulate_traffic.py --url https://my-app.azurecontainerapps.io

# Exercise only specific tools
python scripts/simulate_traffic.py --tools secure_score,defender,entra
```

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | `http://localhost:8000` | Target SecPostureIQ endpoint |
| `--duration` | `0` (single burst) | Total run time in minutes |
| `--interval` | `5` | Minutes between bursts |
| `--burst-size` | `10` | Chat requests per burst |
| `--concurrency` | `5` | Max simultaneous requests |
| `--tools` | all | Comma-separated: `secure_score`, `defender`, `purview`, `entra`, `remediation`, `scorecard`, `playbook`, `full` |
| `--probes` | off | Include `/health`, `/ready`, `/version` probes |
| `-v` | off | Print each request as it completes |

Both scripts work against mock data (no Azure credentials needed) and produce summary tables showing success rate, latency distribution, and which tools were exercised.

## Project Structure

```
posture-iq/
├── src/
│   ├── agent/          # Agent host, config, system prompt
│   ├── tools/          # 8 assessment tools (Graph API, Fabric, Foundry IQ)
│   ├── middleware/      # Tracing, content safety, PII redaction, audit, auth
│   └── api/            # FastAPI health probes and HTTP endpoints
├── infra/              # Bicep IaC templates (ACR, Container Apps, OpenAI, etc.)
├── tests/              # Unit (1151) and integration (41) tests — 1192 total
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

| Category | Points | SecPostureIQ Coverage |
|----------|--------|-------------------|
| Enterprise Value | 35 | Get to Green acceleration, Secure Score improvement |
| Azure Integration | 25 | OpenAI + Content Safety + App Insights + Key Vault + Container Apps |
| Operational Readiness | 15 | CI/CD (OIDC), health probes, IaC, ACR, auto-scaling |
| Security & RAI | 15 | Content Safety, PII redaction, audit logs, prompt injection |
| Storytelling | 15 | 3-min demo: score → gaps → plan → scorecard |
| Bonus: Foundry IQ | 15 | Azure AI Foundry integration |
| Bonus: SDK Feedback | 10 | sdk-feedback.md log |

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.

**SecPostureIQ™** is a trademark of 9 Owls Boston. The license does not grant permission
to use the SecPostureIQ name or branding. See [TRADEMARKS.md](TRADEMARKS.md) for details.

---

## GitHub Copilot SDK Challenge — Demo Submission

| Asset | Description |
|-------|-------------|
| [SecPostureIQ.mp4](SecPostureIQ.mp4) | 3-minute demo video — live assessment, remediation plan, adoption scorecard |
| [SecPostureIQ.pptx](SecPostureIQ.pptx) | Slide deck — architecture, enterprise value, scoring alignment |
| [sdk-feedback.md.pdf](sdk-feedback.md.pdf) | SDK feedback log — issues, suggestions, workarounds discovered during development |
