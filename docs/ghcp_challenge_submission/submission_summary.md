# PostureIQ — Challenge Submission Summary

> **Project Name:** PostureIQ  
> **Team:** Solo submission  
> **Repo:** [github.com/9owlsboston/posture-iq](https://github.com/9owlsboston/posture-iq)  

---

## One-Liner

PostureIQ is an AI agent built with the GitHub Copilot SDK that assesses Microsoft 365 E5 security posture in minutes — not weeks — and generates prioritized remediation plans to accelerate the Project 479 "Get to Green" campaign across thousands of enterprise accounts.

---

## Problem

ME5 account teams today spend **2–4 weeks** manually assessing each customer's security posture: pulling Secure Score, auditing Defender deployments, reviewing Purview policies, and checking Entra ID configurations. With thousands of accounts in the Project 479 pipeline, this manual approach doesn't scale.

## Solution

PostureIQ is a conversational AI agent that:

1. **Queries Microsoft Secure Score** — pulls the baseline with category breakdowns and 30-day trends
2. **Assesses Defender Coverage** — evaluates deployment across Endpoint, Office 365, Identity, and Cloud Apps
3. **Audits Purview Policies** — checks DLP, sensitivity labels, retention, and Insider Risk
4. **Reviews Entra ID Config** — Conditional Access, PIM, Identity Protection, Access Reviews
5. **Generates Remediation Plans** — AI-prioritized steps with PowerShell scripts, confidence scores, and time-to-green estimates
6. **Creates Adoption Scorecards** — executive RAG (Red/Amber/Green) summary per workload
7. **Retrieves Project 479 Playbooks** — maps gaps to Foundry IQ remediation offers and onboarding checklists

All through a natural language conversation powered by the GitHub Copilot SDK.

## Architecture

```
User ↔ Copilot SDK ↔ Agent Runtime ↔ PostureIQ (8 Tools) ↔ Microsoft Graph Security API
                                                           ↔ Azure OpenAI (GPT-4o)
                                                           ↔ Azure AI Content Safety
                                                           ↔ Foundry IQ (playbooks)
                                                           ↔ Fabric Lakehouse (telemetry)
```

**Deployment:** Azure Container Apps (auto-scaling 0–5 replicas, scale-to-zero)  
**CI/CD:** GitHub Actions with OIDC Workload Identity Federation (zero stored secrets)  
**IaC:** Bicep templates for full Azure resource provisioning  

## Key Numbers

| Metric | Value |
|--------|-------|
| Tools registered | 8 |
| Unit + integration tests | 1,165 |
| Azure services integrated | 7 (OpenAI, Content Safety, App Insights, Key Vault, Container Apps, ACR, Entra ID) |
| Bicep modules | 6 |
| Time-to-assess reduction | Weeks → Minutes |

## Scoring Alignment

| Criteria | Max Pts | PostureIQ Coverage |
|----------|---------|-------------------|
| Enterprise value & reusability | 35 | Project 479 acceleration — a live campaign with thousands of ME5 accounts. Reusable across every ME5 customer. Security IS the product |
| Azure / Microsoft integration | 25 | Azure OpenAI + Content Safety + App Insights + Key Vault + Container Apps + ACR + Entra ID + Graph Security API |
| Operational readiness | 15 | CI/CD (OIDC), Bicep IaC, health probes (/health, /ready, /version), auto-scaling, App Insights tracing, structured logging |
| Security, governance & RAI | 15 | Content Safety (4-category filtering), PII redaction, prompt injection detection (20 patterns), audit trail, confidence scores, disclaimer watermarks |
| Storytelling & amplification | 15 | 3-min demo: score → gaps → plan → scorecard. Real Project 479 narrative |
| **Bonus:** Foundry IQ | 15 | Playbook retrieval, gap-to-offer mapping, onboarding checklists |
| **Bonus:** SDK Feedback | 10 | Running feedback log (docs/sdk-feedback.md) |

## Links

- **Video:** [See video_script.md for recording guide]
- **Deck:** [See slide_deck_content.md for slide content]
- **SDK Feedback:** [docs/sdk-feedback.md](../../docs/sdk-feedback.md)
- **Architecture:** [docs/architecture.md](../../docs/architecture.md)
