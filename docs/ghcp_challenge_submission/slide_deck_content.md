# PostureIQ — Slide Deck Content (1–2 Slides)

> Copy this content into PowerPoint / Google Slides.  
> Use a dark theme (navy/slate background, white text) to match the PostureIQ UI.  
> Font: Segoe UI or similar clean sans-serif.

---

## SLIDE 1 — Architecture & Integration

### Title
**PostureIQ** — ME5 Security Posture Assessment Agent

### Subtitle
Built with the GitHub Copilot SDK | Project 479 "Get to Green"

### Architecture Diagram (center of slide)

```
┌──────────────────────────────────────────────────────────────────────┐
│                         PostureIQ Agent                              │
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────────────────┐  │
│  │  Copilot SDK  │───▶│ Agent Runtime │───▶│    8 Assessment Tools  │  │
│  │  (Python)     │    │ (Plans &     │    │                        │  │
│  │              │◀───│  Orchestrates)│◀───│  Secure Score          │  │
│  └──────────────┘    └──────────────┘    │  Defender Coverage     │  │
│                                           │  Purview Policies      │  │
│  ┌──────────────────────────────────┐    │  Entra Config          │  │
│  │     Middleware Layer              │    │  Remediation Plan 🤖   │  │
│  │  Content Safety │ PII Redaction   │    │  Adoption Scorecard    │  │
│  │  Audit Logger   │ Tracing         │    │  Foundry IQ Playbook   │  │
│  └──────────────────────────────────┘    └──────────┬─────────────┘  │
└─────────────────────────────────────────────────────┼────────────────┘
                                                      │
                    ┌─────────────────────────────────┼──────────────┐
                    │              Azure Services      │              │
                    │                                  ▼              │
                    │  ┌─────────────┐  ┌──────────────────────────┐ │
                    │  │ Azure OpenAI │  │ Microsoft Graph Security │ │
                    │  │ (GPT-4o)     │  │ API (Secure Score,       │ │
                    │  └─────────────┘  │ Defender, Purview, Entra) │ │
                    │                    └──────────────────────────┘ │
                    │  ┌─────────────┐  ┌─────────────┐             │
                    │  │ Content     │  │ App Insights │             │
                    │  │ Safety      │  │ (Tracing)    │             │
                    │  └─────────────┘  └─────────────┘             │
                    │  ┌─────────────┐  ┌─────────────┐             │
                    │  │ Key Vault   │  │ Container   │             │
                    │  │ (Secrets)   │  │ Apps (Host)  │             │
                    │  └─────────────┘  └─────────────┘             │
                    │  ┌─────────────┐  ┌─────────────┐             │
                    │  │ ACR (Images)│  │ Entra ID    │             │
                    │  │             │  │ (Auth/RBAC)  │             │
                    │  └─────────────┘  └─────────────┘             │
                    └────────────────────────────────────────────────┘
```

### Key Integration Points (bottom of slide, 3 columns)

| Copilot SDK | Azure Services (7) | Microsoft 365 |
|---|---|---|
| Agent host & tool registration | OpenAI, Content Safety, App Insights | Graph Security API |
| Session management & streaming | Key Vault, Container Apps, ACR | Secure Score, Defender |
| Multi-turn conversation | Entra ID (OIDC + Managed Identity) | Purview, Entra ID P2 |

---

## SLIDE 2 — Enterprise Value & Readiness

### Title
**From Weeks to Minutes** — Enterprise-Grade Security Assessment

### Left Column — Business Impact

**The Problem**
- ME5 account teams manually assess security posture
- Each assessment takes **2–4 weeks**
- Thousands of accounts in the Project 479 pipeline
- Manual process doesn't scale

**PostureIQ Impact**
- Assessment time: **weeks → minutes**
- Reusable across **every ME5 customer**
- Accelerates Project 479 "Get to Green" campaign
- AI-generated remediation with PowerShell scripts

### Center Column — Enterprise Readiness

| Capability | Detail |
|---|---|
| **Tests** | 1,165 (unit + integration) |
| **CI/CD** | GitHub Actions + OIDC (zero secrets) |
| **IaC** | Bicep (6 modules, dev/prod params) |
| **Observability** | App Insights distributed tracing + custom metrics |
| **Health Probes** | /health, /ready, /version |
| **Scaling** | 0–5 replicas, scale-to-zero |

### Right Column — Security & RAI

| Guardrail | Implementation |
|---|---|
| **Content Safety** | Azure AI Content Safety (4 categories) |
| **PII Redaction** | Tenant IDs, emails, IPs, UPNs stripped |
| **Prompt Injection** | 20 detection patterns + Azure Prompt Shield |
| **Audit Trail** | Immutable log, 90-day retention, RBAC |
| **Auth** | Entra ID OAuth2 + Managed Identity |
| **Read-Only** | No write permissions to customer tenant |

### Bottom Banner

> **Bonus:** Foundry IQ integration (playbook retrieval) · Fabric Lakehouse (telemetry push) · SDK Feedback Log

---

## Design Notes

### Color Palette (matches PostureIQ UI)
- Background: `#0f172a` (dark navy)
- Surface: `#1e293b` (slate)
- Primary accent: `#3b82f6` (blue)
- Green: `#22c55e` / Yellow: `#eab308` / Red: `#ef4444`
- Text: `#e2e8f0` (light gray)

### Fonts
- Headers: Segoe UI Semibold, 28–36pt
- Body: Segoe UI Regular, 16–20pt
- Code: Cascadia Code, 14pt

### Logo
- Use the PostureIQ gradient icon (blue → purple gradient, 🛡️ shield on rounded square)
- Place in top-left corner of both slides

### Tips
- **Don't overload slides** — judges will also see the video and repo. Slides are a quick reference.
- Use the architecture diagram as the visual anchor on Slide 1.
- Use the three-column layout on Slide 2 to show breadth without clutter.
- Include the GitHub repo URL in the footer of both slides.
