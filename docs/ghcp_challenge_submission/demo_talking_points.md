# PostureIQ — Demo Talking Points & FAQ

> Quick-reference card for the live demo, presentation, or Q&A with judges.

---

## Elevator Pitch (30 seconds)

"PostureIQ is a conversational AI agent built with the GitHub Copilot SDK that assesses Microsoft 365 E5 security posture and generates prioritized remediation plans. It wraps eight assessment tools around the Microsoft Graph Security API, uses Azure OpenAI for reasoning, and deploys to Azure Container Apps with full CI/CD. It turns a 2–4 week manual process into a minutes-long conversation — accelerating the Project 479 Get-to-Green campaign for thousands of enterprise accounts."

---

## Key Talking Points

### 1. Why This Matters (Enterprise Value — 35 pts)

- **Project 479 is real.** It's an active Microsoft campaign to drive ME5 security adoption across thousands of enterprise accounts. Each account needs a posture assessment before remediation can begin.
- **The bottleneck is assessment, not remediation.** Account teams know *what* to fix — they just can't assess fast enough. PostureIQ removes that bottleneck.
- **Reusable across every ME5 customer.** The same agent, same tools, same remediation playbooks work for any M365 E5 tenant.
- **Security IS the product.** Unlike agents that bolt on security, PostureIQ's entire purpose is security assessment — the domain naturally demonstrates security best practices.

### 2. Copilot SDK Usage (Core Requirement)

- **8 tools registered** with the Copilot SDK via `Tool()` objects with JSON schemas
- **Session management** — multi-turn conversations with context carried across turns
- **Streaming responses** via `SessionEvent` handlers for real-time UX
- **Agent runtime** does the LLM planning — we just provide tools and the system prompt
- The SDK is the orchestration backbone, not just a wrapper

### 3. Azure Integration (25 pts)

Seven Azure services, all wired with Managed Identity (no API keys in production):

| Service | Purpose |
|---------|---------|
| Azure OpenAI (GPT-4o) | Reasoning, remediation plan generation |
| Azure AI Content Safety | RAI filtering (hate, self-harm, sexual, violence) + prompt injection detection |
| Azure Application Insights | Distributed tracing, custom metrics, structured logging |
| Azure Key Vault | Secret storage for Graph API credentials |
| Azure Container Apps | Hosting (auto-scale 0–5, scale-to-zero) |
| Azure Container Registry | Docker image store, CI/CD push via OIDC |
| Entra ID | User auth (OAuth2), service auth (Managed Identity), CI/CD auth (OIDC) |

### 4. Operational Readiness (15 pts)

- **CI/CD:** GitHub Actions pipeline — lint → test → bicep-validate → build → push to ACR → deploy to Container Apps
- **OIDC:** Zero stored secrets. GitHub Actions authenticates to Azure via federated identity tokens.
- **IaC:** 6 Bicep modules (Container App, ACR, OpenAI, Content Safety, Key Vault, App Insights) with dev/prod parameter files
- **Health probes:** `/health` (liveness), `/ready` (readiness — checks all 4 dependencies), `/version` (build info)
- **Observability:** Every tool call is a distributed trace span. Custom metrics: secure score gauge, assessment counter, content safety blocked count.
- **Testing:** 1,165 tests (unit + integration), all passing, 80%+ coverage enforced in CI

### 5. Security & RAI (15 pts)

- **Content Safety:** All LLM inputs AND outputs routed through Azure AI Content Safety. Blocks hate, self-harm, sexual, violence content. Falls back to safe response on block.
- **PII Redaction:** Strips tenant GUIDs, email addresses, UPNs, IP addresses, display names before sending to LLM and before logging. Round-trip re-hydration for customer-facing display.
- **Prompt Injection:** 20 heuristic patterns detected + Azure Prompt Shield integration. System prompt includes explicit defense instructions.
- **Audit Trail:** Immutable log of every tool call with timestamp, session ID, user ID, tool name, redacted I/O. RBAC-restricted access. 90-day retention.
- **Auth:** Three-layer auth model — user auth (Entra ID OAuth2), service auth (Managed Identity), CI/CD auth (OIDC federation).
- **Read-only:** The agent NEVER writes to the customer's tenant. All Graph API permissions are read-only.
- **Confidence scores + disclaimers:** Every AI recommendation has a confidence level. Every output includes an AI-generated disclaimer.

### 6. Storytelling (15 pts)

- **Narrative arc:** Problem (manual assessment doesn't scale) → Solution (AI agent does it in minutes) → Impact (accelerates Project 479)
- **Demo flow:** Score → Gaps → Plan → Scorecard (mirrors the real account team workflow)
- **Amplification-ready:** Clear value prop, clean architecture, professional UI — ready for a LinkedIn post or internal showcase

### 7. Bonus: Foundry IQ (up to 15 pts)

- Tool 7 (`get_project479_playbook`) retrieves Project 479 playbooks from Foundry IQ
- Maps identified gaps to specific remediation offers and workshops
- Includes customer onboarding checklists
- Enriches every remediation plan with Foundry IQ context

### 8. Bonus: SDK Feedback (up to 10 pts)

- Running log in `docs/sdk-feedback.md`
- Documents: package naming confusion, API ergonomics, documentation gaps
- Formatted as actionable product feedback for the SDK team

---

## Anticipated Judge Questions & Answers

**Q: How does this differ from just reading Microsoft Secure Score in the portal?**  
A: Secure Score is one data point. PostureIQ correlates across four domains (Secure Score + Defender + Purview + Entra), identifies cross-domain gaps, generates prioritized remediation with PowerShell scripts, and maps everything to Project 479 playbooks. It's the difference between a number and an actionable plan.

**Q: Does this work with real customer tenants?**  
A: Yes — it calls live Microsoft Graph Security API endpoints with delegated permissions. The tenant admin grants read-only consent, and the agent assesses the actual tenant. For the demo, we use mocked responses from a CDX demo tenant to ensure reproducibility.

**Q: Why the Copilot SDK instead of just building a ChatGPT wrapper?**  
A: The Copilot SDK provides the agent runtime — LLM planning, tool orchestration, multi-turn context, streaming. We register tools and a system prompt; the runtime decides when and how to call tools. This is true agentic behavior, not just prompt → response.

**Q: How do you handle PII when sending data to Azure OpenAI?**  
A: All data passes through `pii_redaction.py` before reaching the LLM. Tenant GUIDs, email addresses, UPNs, IP addresses, and display names are replaced with anonymized tokens. After the LLM responds, we re-hydrate the tokens for customer-facing display. PII never reaches the model or the logs.

**Q: What happens if Azure AI Content Safety is unavailable?**  
A: We have a local heuristic fallback in `content_safety.py`. It applies keyword-based filtering for the four harm categories. It's less sophisticated than the Azure service but ensures the agent never emits unfiltered content, even during an outage.

**Q: Can this scale to thousands of tenants?**  
A: Container Apps auto-scales from 0 to 5 replicas based on HTTP request concurrency. Each assessment is stateless — the agent reads from Graph API and generates output. No shared state between assessments. For fleet-wide usage, we'd add a queue-based batch mode and push results to the Fabric lakehouse for aggregated dashboards.

**Q: What's the cost of running this?**  
A: Scale-to-zero means zero cost when idle. Per assessment: ~3–4 Azure OpenAI API calls (GPT-4o), 4 Graph API calls, 2 Content Safety calls. Estimated cost per assessment: < $0.10.

---

## Quick Stats for Slides / Conversation

- **8** tools registered with Copilot SDK
- **7** Azure services integrated
- **1,165** tests passing
- **6** Bicep IaC modules
- **20** prompt injection patterns detected
- **3** auth layers (user, service, CI/CD)
- **0** stored secrets (OIDC + Managed Identity)
- **< $0.10** per assessment
- **Minutes** vs. weeks for posture assessment
