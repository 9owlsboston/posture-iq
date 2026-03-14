# Web Agent — Tool Architecture & Extensibility Guide

> **Date**: March 2026  
> **Context**: Questions and findings from web agent implementation and live API verification.

---

## How Does the Web Agent Handle Out-of-Scope Prompts?

The system prompt in `src/agent/system_prompt.py` constrains the LLM's persona to ME5 security posture assessment. When a user asks something outside the 8 registered tools:

1. **Politely redirects** — e.g., *"I'm designed to assess ME5 security posture. I can help you with Secure Score, Defender coverage, Purview policies, or Entra ID configuration."*
2. **Never hallucates a tool call** — the `tools` parameter in the OpenAI API limits function calls to the schemas defined in `src/tools/definitions.py`. The LLM cannot invoke anything that isn't registered there.
3. **Answers general security questions** from its own knowledge — e.g., *"What is Conditional Access?"* gets a text answer without calling any tool.
4. **Enforces guardrails** — read-only (no configuration changes), PII protection, prompt injection defense, and the disclaimer on all remediation plans.

---

## How to Add a New Tool

Adding a tool requires changes in **4 files**, and the tool is automatically available to both the web agent and CLI agent:

### Step 1: Implement the Tool

Create `src/tools/your_tool.py`:

```python
from __future__ import annotations
from typing import Any
from src.middleware.tracing import trace_tool_call

@trace_tool_call("your_tool_name")
async def your_tool_name(graph_token: str = "", **kwargs) -> dict[str, Any]:
    """Your tool description."""
    # Implementation here
    return {"data_source": "graph_api", "result": "..."}
```

### Step 2: Register the Schema

Add an entry to `TOOL_SCHEMAS` in `src/tools/definitions.py`:

```python
{
    "type": "function",
    "function": {
        "name": "your_tool_name",
        "description": "What this tool does — the LLM reads this to decide when to call it.",
        "parameters": {
            "type": "object",
            "properties": {
                "param1": {"type": "string", "description": "..."},
            },
            "required": [],
        },
    },
},
```

### Step 3: Wire the Dispatcher

Add a branch in `_run_tool()` in `src/api/chat.py`:

```python
if name == "your_tool_name":
    from src.tools.your_tool import your_tool_name
    return await your_tool_name(graph_token=graph_token, **args)
```

### Step 4: Update the System Prompt

Add the tool to the "Capabilities" list in `src/agent/system_prompt.py`:

```
9. **your_tool_name** — Description of what it does and when to use it
```

### Optional but Recommended

| Task | File | Purpose |
|---|---|---|
| Add keyword triggers | `src/api/chat.py` → `_TOOL_INTENTS` | Enables keyword-mode fallback |
| Add a formatter | `src/api/chat.py` → `_FORMATTERS` | Pretty-prints results in keyword mode |
| Add unit tests | `tests/unit/test_your_tool.py` | CI coverage |
| Register with CLI agent | `src/agent/main.py` → `TOOLS` list | Copilot SDK CLI support |

No frontend changes are needed — the LLM automatically discovers new tools from `TOOL_SCHEMAS`.

---

## Shared Tool Architecture

Both the web agent and CLI agent share the same tool layer. A tool is implemented **once** and consumed by all entry points:

```
                   ┌─────────────────────┐
                   │  src/tools/*.py      │  ← single implementation
                   │  definitions.py      │  ← single schema
                   └────────┬────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
     Web (LLM mode)    Web (keyword)   CLI Agent
     chat_stream.py     chat.py        main.py
     POST /chat/stream  POST /chat     Copilot SDK
              │             │             │
              └─────────────┼─────────────┘
                            ▼
                       _run_tool()  ← shared dispatcher
```

| Entry Point | How it discovers tools | How it calls tools |
|---|---|---|
| **Web LLM** (`chat_stream.py`) | `TOOL_SCHEMAS` from `definitions.py` → OpenAI function calling | `_run_tool()` from `chat.py` |
| **Web keyword** (`chat.py`) | `_TOOL_INTENTS` keyword list | `_run_tool()` directly |
| **CLI agent** (`main.py`) | `TOOLS` list with Copilot SDK `Tool()` objects | Handler adapters → same tool functions |

The only difference is `main.py` wraps each tool in a Copilot SDK `Tool()` with a handler adapter, while the web paths use `_run_tool()`. Both call the same underlying `async def` function.

---

## Live API Verification Results (March 2026)

All 8 tools were tested against the real Graph API and Azure OpenAI endpoints. Key findings and fixes applied:

### Tool Verification Summary

| Tool | Backend | Verified Result | Issues Found |
|---|---|---|---|
| `query_secure_score` | Graph API `secureScores` | ✅ 141.7/347.0 = 40.8%, 30 trend points, 3 categories | None |
| `assess_defender_coverage` | Graph API `controlProfiles` + `controlScores` | ✅ 3.1% overall, O365 39.9%, Endpoint 0% | **Fixed**: was showing 0% everywhere |
| `check_purview_policies` | Graph API `controlProfiles` + `controlScores` | ✅ 0% overall (genuinely undeployed) | **Fixed**: same root cause as Defender |
| `get_entra_config` | Direct Graph API (CA, PIM, IdP, Access Reviews) | ✅ 46.2%, CA yellow, PIM 403 (expected for app token) | None |
| `generate_remediation_plan` | Azure OpenAI GPT-4o | ✅ 5 steps, P0-P2 priorities, scripts included | None |
| `create_adoption_scorecard` | Aggregates other tool results | ✅ 16.4% overall (from real data) | **Fixed**: was returning mock (45%) |
| `get_green_playbook` | Built-in playbooks (Foundry IQ not configured) | ✅ 2/12 areas matched, offers + checklists | None |
| `push_posture_snapshot` | Fabric Lakehouse (write-only) | ✅ Not tested (no Fabric endpoint configured) | N/A |

### Bug #1: Defender & Purview Showing 0% Coverage

**Root cause**: `_is_gap()` relied on `controlStateUpdates` — a manually-managed field that most tenants **never populate**. Every control appeared as a gap.

**Fix**: Added `fetch_control_scores()` to `src/tools/graph_client.py` as a shared helper. It fetches the latest `SecureScore` snapshot (`GET /security/secureScores?$top=1&$orderby=createdDateTime desc`) and extracts the `control_scores` array — the **actual achieved score** per control, matching the Microsoft Secure Score dashboard.

Both `defender_coverage.py` and `purview_policies.py` now use real scores. The `controlStateUpdates` fallback is preserved for cases where the SecureScore API call fails.

### Bug #2: Adoption Scorecard Always Returning Mock Data

**Root cause**: The scorecard expected short keys (`defender_coverage`, `purview_policies`, `entra_config`) but the LLM session stores results by tool function name (`assess_defender_coverage`, `check_purview_policies`, `get_entra_config`).

**Fix**: `_parse_assessment()` in `adoption_scorecard.py` now normalises function-name keys to canonical short keys so both naming conventions work.

### Bug #3: LLM Hallucinating Base64 Images in Status Fields

**Root cause**: GPT-4o fabricated a base64 PNG for the `"red"` status string and truncated the 30-day trend table with "...".

**Fix**: Added explicit output formatting rules to the system prompt:
- Status indicators must use emoji text (🟢🟡🔴), never base64 images
- Trend tables must show ALL rows, never truncate
- Output must be plain markdown only

### Cross-Check: Control Score Accounting

The Secure Score of 141.7 breaks down across services:

| Service | Achieved Score | Controls with Score > 0 |
|---|---|---|
| MDO (Defender for O365) | 65.0 | 17 controls |
| AzureAD (Entra ID) | 47.7 | 10 controls |
| EXO (Exchange Online) | 11.0 | 3 controls |
| FORMS | 6.0 | 1 control |
| MCAS (Cloud Apps) | 5.0 | 1 control |
| AATP (Defender for Identity) | 5.0 | 1 control |
| **Total** | **141.7** | **33 controls** |

The `AzureAD`, `EXO`, and `FORMS` controls (71.7 points) are assessed by the `entra_config` tool through direct Graph API calls rather than SecureScoreControlProfiles. This is by design — these controls map to Entra ID and Exchange configurations, not Defender workloads.
