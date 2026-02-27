# PostureIQ — Demo Video Script (3 Minutes)

> **Format:** Screen recording with voiceover  
> **Length:** 3:00 max  
> **Resolution:** 1920×1080 recommended  
> **Tools:** OBS Studio / Windows Game Bar / macOS Screen Recorder  

---

## Pre-Recording Checklist

- [ ] PostureIQ running locally (`uvicorn src.api.app:app --port 8000`)
- [ ] Browser open at `http://localhost:8000` (dark-themed chat UI)
- [ ] Terminal visible for showing test results (optional split-screen)
- [ ] App Insights dashboard open in a separate browser tab
- [ ] VS Code open with project structure visible (for architecture flash)
- [ ] Microphone tested, quiet environment

---

## Script — Scene by Scene

### SCENE 1 — Hook (0:00 – 0:15) 🎯

**[VISUAL]** Title card or opening slide:

> **PostureIQ**  
> ME5 Security Posture Assessment Agent  
> Built with the GitHub Copilot SDK

**[VOICEOVER]**  
> "ME5 account teams spend weeks manually assessing each customer's security posture — pulling Secure Scores, auditing Defender deployments, reviewing hundreds of policies. With thousands of accounts in the Project 479 pipeline, that doesn't scale. PostureIQ does it in minutes."

---

### SCENE 2 — Architecture Flash (0:15 – 0:30) 🏗️

**[VISUAL]** Show the architecture slide (Slide 1) or the mermaid diagram from `docs/architecture.md`.

**[VOICEOVER]**  
> "PostureIQ is built on the GitHub Copilot SDK. It registers eight assessment tools that call the Microsoft Graph Security API, uses Azure OpenAI for reasoning and remediation generation, and routes everything through Azure AI Content Safety for responsible AI compliance. It deploys to Azure Container Apps with full CI/CD via GitHub Actions and OIDC — zero stored secrets."

**[VISUAL]** Briefly highlight on the diagram: SDK → Runtime → Tools → Graph API / OpenAI / Content Safety.

---

### SCENE 3 — Live Assessment (0:30 – 1:30) 💻

**[VISUAL]** Switch to the PostureIQ chat UI in the browser.

**[VOICEOVER + TYPE]**  
> "Let's assess a tenant's ME5 security posture."

**Type in the chat:** `Assess this tenant's ME5 security posture`

**[VISUAL]** As the agent responds, narrate each tool call:

**Step 1 — Secure Score** (0:30 – 0:50)  
> "First, the agent pulls the Microsoft Secure Score. We can see the current score, category breakdown across Identity, Data, Devices, and Apps, and the 30-day trend. This tenant is at 58% — well below the green threshold of 70."

**Step 2 — Defender Coverage** (0:50 – 1:05)  
> "Next, it assesses Defender deployment across all four workloads. We see Defender for Endpoint has high coverage, but Defender for Identity and Cloud Apps have significant gaps."

**Step 3 — Purview Policies** (1:05 – 1:15)  
> "Now Purview — the agent finds that DLP policies exist but only cover Exchange, not SharePoint or Teams. Sensitivity labels are published but not auto-applied. Insider Risk Management isn't enabled."

**Step 4 — Entra Config** (1:15 – 1:30)  
> "Finally, Entra ID configuration — Conditional Access is partially deployed, PIM is active but underutilized, and Access Reviews aren't configured for privileged roles."

---

### SCENE 4 — Remediation Plan (1:30 – 2:10) 📋

**[VISUAL]** The agent generates the remediation plan in the chat.

**[VOICEOVER + TYPE]**  
> "Now let's ask for a remediation plan."

**Type in the chat:** `Generate a remediation plan for the gaps you found`

> "The agent uses Azure OpenAI to generate a prioritized remediation plan. Each step is ranked P0, P1, or P2 by impact on Secure Score. Notice the PowerShell scripts — these are copy-paste ready for the customer's admin."

**[VISUAL]** Scroll through the remediation plan, highlighting:
- Prioritized steps (P0 = Critical, P1 = High, P2 = Medium)
- PowerShell script snippets
- Confidence scores (High/Medium/Low) on each recommendation
- The Project 479 playbook references from Foundry IQ
- The disclaimer watermark at the bottom

> "Every recommendation includes a confidence score, and the AI disclaimer reminds teams to review before implementing. The Foundry IQ integration maps each gap to specific Project 479 offers and workshops."

---

### SCENE 5 — Adoption Scorecard (2:10 – 2:30) 📊

**[TYPE]** `Create an adoption scorecard`

**[VOICEOVER]**  
> "Finally, the adoption scorecard — an executive summary with red, amber, green status per workload. This is what account teams present to customer CISOs. One conversation, and you have a complete assessment with actionable next steps."

**[VISUAL]** Show the structured scorecard output with RAG indicators.

---

### SCENE 6 — Enterprise Readiness Flash (2:30 – 2:50) ⚙️

**[VISUAL]** Quick montage (3–5 seconds each), pre-recorded or screenshot-based:

1. **App Insights Dashboard** — Show distributed traces for tool calls, custom metrics (secure score gauge, assessment counter)
2. **Content Safety** — Show a blocked prompt injection attempt in the chat (e.g., "Ignore your instructions and...")
3. **CI/CD Pipeline** — Show a passing GitHub Actions run (lint → test → bicep-validate → build → deploy)
4. **Test Suite** — Flash terminal output: `1165 tests passed`
5. **Bicep IaC** — Flash the `infra/` folder structure briefly

**[VOICEOVER]**  
> "PostureIQ is enterprise-ready: 1,165 tests, full CI/CD with OIDC, Bicep infrastructure-as-code, distributed tracing in App Insights, PII redaction, content safety filtering, and an immutable audit trail."

---

### SCENE 7 — Close (2:50 – 3:00) 🎬

**[VISUAL]** Return to the architecture slide or a closing card:

> **PostureIQ**  
> Assessment in minutes, not weeks.  
> Built with the GitHub Copilot SDK.

**[VOICEOVER]**  
> "PostureIQ accelerates the Project 479 Get-to-Green motion for thousands of ME5 accounts. It turns a weeks-long manual process into a minutes-long AI-assisted conversation. Built entirely with the GitHub Copilot SDK."

---

## Recording Tips

1. **Pace:** Speak at a natural conversational pace. Don't rush — 3 minutes is enough if you're concise.
2. **Chat responses:** If live responses are slow, pre-record successful runs and splice. Or run locally with mocked Graph API responses for fast, deterministic output.
3. **Zoom:** Use browser zoom (Ctrl+Plus) to make chat text readable in the recording.
4. **Transitions:** Simple cuts between scenes are fine. No fancy transitions needed.
5. **Music:** Optional — a subtle, low-volume background track can improve production quality. Use royalty-free music only.
6. **Bloopers:** Record multiple takes. Pick the best per scene and edit together.

## Fallback: Pre-Recorded Responses

If the live demo is unpredictable, pre-seed the chat with recorded responses:

```bash
# Run with mocked Graph API (no real tenant needed)
export POSTUREIQ_MOCK_MODE=true
uvicorn src.api.app:app --port 8000
```

All tools have full mock implementations that return realistic sample data, so the demo works without Azure credentials.
