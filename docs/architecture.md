# PostureIQ — Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PostureIQ Agent                              │
│                                                                     │
│  ┌──────────────┐    ┌────────────────┐    ┌─────────────────────┐ │
│  │ FastAPI       │    │ Copilot SDK    │    │ Agent Runtime       │ │
│  │ (Health/API)  │    │ (thin client)  │    │ (Copilot CLI)       │ │
│  │               │    │                │    │ - Plans tool calls  │ │
│  │ /health       │    │ Registers 6    │    │ - Multi-model route │ │
│  │ /ready        │    │ tools + system │    │ - Context mgmt      │ │
│  │ /assess       │    │ prompt         │    │ - Safety boundaries │ │
│  └──────────────┘    └───────┬────────┘    └──────────┬──────────┘ │
│                              │ JSON-RPC (stdio)       │             │
│                              └────────────────────────┘             │
│                                       │                             │
│  ┌────────────────────────────────────┼────────────────────────┐   │
│  │              Middleware Layer       │                        │   │
│  │  ┌─────────────┐ ┌────────────┐ ┌──┴──────────┐ ┌────────┐│   │
│  │  │Content      │ │PII         │ │Distributed  │ │Audit   ││   │
│  │  │Safety (RAI) │ │Redaction   │ │Tracing      │ │Logger  ││   │
│  │  └─────────────┘ └────────────┘ └─────────────┘ └────────┘│   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                     6 Assessment Tools                      │    │
│  │  ┌────────────┐ ┌──────────────┐ ┌───────────────────────┐ │    │
│  │  │query_      │ │assess_       │ │check_purview_         │ │    │
│  │  │secure_score│ │defender_     │ │policies               │ │    │
│  │  │            │ │coverage      │ │                       │ │    │
│  │  └────────────┘ └──────────────┘ └───────────────────────┘ │    │
│  │  ┌────────────┐ ┌──────────────┐ ┌───────────────────────┐ │    │
│  │  │get_entra_  │ │generate_     │ │create_adoption_       │ │    │
│  │  │config      │ │remediation_  │ │scorecard              │ │    │
│  │  │            │ │plan          │ │                       │ │    │
│  │  └────────────┘ └──────────────┘ └───────────────────────┘ │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────┬───────────────┬──────────────┬──────────────┬────────────┘
          │               │              │              │
          ▼               ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌──────────────┐
│ Microsoft    │ │ Azure OpenAI │ │ Azure AI   │ │ Azure App    │
│ Graph        │ │ (GPT-4o)     │ │ Content    │ │ Insights     │
│ Security API │ │              │ │ Safety     │ │              │
│              │ │ Reasoning &  │ │ RAI filter │ │ Traces &     │
│ Secure Score │ │ remediation  │ │ Prompt     │ │ metrics      │
│ Defender     │ │ plan gen     │ │ injection  │ │              │
│ Purview      │ │              │ │ detection  │ │              │
│ Entra ID     │ │              │ │            │ │              │
└──────────────┘ └──────────────┘ └────────────┘ └──────────────┘
```

## Deployment Architecture

```
┌─────────────────────────────────────────────────────┐
│              Azure Container Apps                    │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │ PostureIQ Container                          │   │
│  │ - Python 3.11 + FastAPI + Copilot SDK       │   │
│  │ - GitHub CLI (agent runtime)                 │   │
│  │ - User-Assigned Managed Identity             │   │
│  │ - Scale: 0–5 replicas                        │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  Health Probes: /health (liveness), /ready (readiness) │
└─────────────────────────────────────────────────────┘
         │              │              │
         ▼              ▼              ▼
  ┌────────────┐ ┌────────────┐ ┌────────────┐
  │ Key Vault  │ │ App        │ │ Content    │
  │ (secrets)  │ │ Insights   │ │ Safety     │
  └────────────┘ └────────────┘ └────────────┘
```

## Auth Flow

```
User → Entra ID (OAuth2) → PostureIQ Agent → Managed Identity → Azure Services
                                            → Delegated Permissions → Graph API
```
