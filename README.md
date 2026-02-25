# PostureIQ

**ME5 Security Posture Assessment Agent** — Built with the GitHub Copilot SDK

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

## Architecture

```
User ↔ Copilot SDK ↔ Agent Runtime ↔ PostureIQ Tools ↔ Microsoft Graph API
                                                      ↔ Azure OpenAI (GPT-4o)
```

See [docs/architecture.md](docs/architecture.md) for the full architecture diagram.

## Quick Start

### Prerequisites

- Python 3.11+
- GitHub CLI (`gh`) — required for Copilot Agent Runtime
- Azure subscription with OpenAI, Content Safety, App Insights
- Microsoft 365 E5 tenant (or CDX demo tenant)

### Setup

```bash
# Clone and install
git clone https://github.com/velen-msft/posture-iq.git
cd posture-iq
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env with your Azure and Graph API credentials

# Set up Graph API permissions (requires Azure CLI)
chmod +x scripts/setup-permissions.sh
./scripts/setup-permissions.sh

# Run locally (dev mode)
python -m src.agent.main
```

### Deploy to Azure

```bash
# Deploy infrastructure
az deployment group create \
  --resource-group rg-postureiq-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters/dev.bicepparam
```

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
```

## Project Structure

```
posture-iq/
├── src/
│   ├── agent/          # Agent host, config, system prompt
│   ├── tools/          # 6 assessment tools (Graph API wrappers)
│   ├── middleware/      # Tracing, content safety, PII redaction, audit
│   └── api/            # FastAPI health probes and HTTP endpoints
├── infra/              # Bicep IaC templates
├── tests/              # Unit and integration tests
├── docs/               # Architecture, setup guide, SDK feedback
├── scripts/            # Setup and utility scripts
├── Dockerfile          # Multi-stage container build
└── .github/workflows/  # CI/CD pipeline
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
| Operational Readiness | 15 | CI/CD, health probes, IaC, auto-scaling |
| Security & RAI | 15 | Content Safety, PII redaction, audit logs, prompt injection |
| Storytelling | 15 | 3-min demo: score → gaps → plan → scorecard |
| Bonus: Foundry IQ | 15 | Azure AI Foundry integration |
| Bonus: SDK Feedback | 10 | sdk-feedback.md log |

## License

Internal Microsoft use only — GitHub Copilot SDK Enterprise Challenge submission.
