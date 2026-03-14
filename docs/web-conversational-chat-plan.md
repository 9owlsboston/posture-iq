# Conversational Chat for the Web App — Chainlit Implementation Plan

> **Status**: Approved — Chainlit  
> **Date**: March 2026  
> **Decision**: Replace the keyword-based `_classify_intent()` web chat with a Chainlit-powered conversational UI backed by Azure OpenAI function calling.

---

## Problem Statement

The web app's `/chat` endpoint cannot:

1. **Handle ambiguous or novel queries** — only keyword-matched messages trigger tools; everything else returns a static help menu.
2. **Have multi-turn conversations** — there's no memory of context between turns beyond raw tool results stored in `session["results"]`.
3. **Compose answers from multiple tool results** — the CLI agent's LLM synthesizes cross-tool insights (e.g., "your Entra gaps are the biggest drag on your Secure Score"); the web app just concatenates formatted sections.
4. **Decide tool ordering dynamically** — the CLI agent can call tool 1, read the result, then decide whether to call tool 5; the web app runs all matched tools in a fixed sequence.

---

## Why Chainlit

[Chainlit](https://chainlit.io) is a Python framework purpose-built for conversational AI applications. It provides:

- **Production chat UI** — markdown rendering, code blocks with syntax highlighting, streaming tokens, message threading.
- **Tool-call visualization** — `cl.Step` renders expandable "Calling query_secure_score..." steps with inputs/outputs, matching the CLI agent's `⚙️` UX.
- **Session management** — `cl.user_session` persists state across turns per user, with automatic cleanup.
- **OAuth integration** — built-in `@cl.oauth_callback` supports Azure AD / Entra ID, mapping directly to our existing auth flow.
- **Streaming-first** — `cl.Message.stream_token()` delivers LLM output character-by-character without building SSE plumbing.
- **FastAPI compatible** — Chainlit can be mounted as a sub-application inside an existing FastAPI app, or run standalone.

### Alternatives Considered

| Framework | Why Not |
|---|---|
| **Direct OpenAI in `chat.py`** (Option A from prior plan) | Requires building the entire chat UI, streaming, session management from scratch. Chainlit provides all of this out of the box. |
| **Copilot SDK in FastAPI** (Option B) | SDK designed for single-user CLI, not multi-user web servers. Session lifecycle, GITHUB_TOKEN auth, and Graph token forwarding are all problematic. |
| **Hybrid LLM + Formatters** (Option C) | Good middle ground but still requires custom frontend work. Chainlit subsumes the UI layer. |
| **Streamlit** | Data-app framework, limited auth customization, doesn't embed well inside existing FastAPI apps. |
| **Gradio** | Fast demos but limited control over layout, auth, and production deployment. |

---

## Architecture

### Current (keyword-based)

```
Browser ──→ GET / ──→ index.html (static SPA)
                         │
                         ▼ POST /chat {message, session_id}
                     chat.py
                         │
                    _classify_intent() ──→ keyword match
                         │
                    _run_tool() × N
                         │
                    _FORMATTERS ──→ markdown
                         │
                     ChatResponse ──→ Browser
```

### Target (Chainlit + Azure OpenAI)

```
Browser ──→ Chainlit UI (served by Chainlit server)
                │
                ▼ WebSocket (Chainlit protocol)
           chainlit_app.py
                │
           @cl.on_message
                │
                ▼
           Azure OpenAI (GPT-4o)
           function-calling with tool definitions
                │
                ▼ tool_calls[]
           _run_tool() ──→ existing tool functions
           (wrapped in cl.Step for UI visualization)
                │
                ▼ tool results
           Azure OpenAI (GPT-4o)
           composes final response
                │
                ▼ cl.Message.stream_token()
           Streaming response ──→ Browser
```

### Coexistence with FastAPI

The existing FastAPI app (`src/api/app.py`) continues to serve:
- `GET /health`, `GET /ready`, `GET /version` — health probes
- `GET /auth/*` — OAuth2 login/callback/me/revoke
- `GET /config` — public app configuration
- `POST /assess` — HTTP-triggered assessment endpoint
- `POST /chat` — **kept as legacy/API mode** for programmatic callers (no UI)

Chainlit runs as a separate ASGI app mounted at `/chat-ui` or served on a separate port. Two mounting strategies:

| Strategy | How | Pros | Cons |
|---|---|---|---|
| **Sub-mount** | `app.mount("/chat-ui", chainlit_asgi_app)` | Single port, single container | Chainlit path prefixing can be tricky |
| **Separate port** | Chainlit on `:8001`, FastAPI on `:8000` | Clean separation | Two ports in the container, needs reverse proxy |
| **Replace root** | Chainlit serves `/`, FastAPI APIs on sub-paths | Cleanest UX | Larger refactor of existing routes |

**Recommended**: Start with **sub-mount** at `/chat-ui`. The existing `index.html` at `/` continues to work as a fallback. Once Chainlit is proven, promote it to root.

---

## Chat Mode Feature Flag

Both the keyword-based and LLM-based chat implementations are preserved and selectable at runtime via the `CHAT_MODE` environment variable:

| Value | Behavior |
|---|---|
| `keyword` *(default)* | Current implementation: `_classify_intent()` keyword matching → `_run_tool()` → `_FORMATTERS` → static Markdown response. No LLM, no streaming. |
| `llm` | Chainlit + Azure OpenAI function calling → streaming responses, multi-turn context, tool visualization. |

### How It Works

- **Config**: `CHAT_MODE` is loaded via `settings.chat_mode` in `src/agent/config.py`. A convenience property `settings.use_llm_chat` returns `True` when the mode is `"llm"`.
- **Web UI routing** (`src/api/app.py`):
  - When `CHAT_MODE=llm`: Mount Chainlit ASGI app at `/chat-ui` (Phase 1–3) or `/` (Phase 6+).
  - When `CHAT_MODE=keyword`: Serve the existing `index.html` SPA at `/` with `POST /chat` endpoint as-is.
- **API endpoint** (`POST /chat`): Always available regardless of mode, for programmatic callers (CI, scripts, external integrations). Uses keyword mode internally.
- **Automatic fallback**: If `CHAT_MODE=llm` but Azure OpenAI is unreachable, the Chainlit handler gracefully degrades to keyword mode with a banner: "⚠️ LLM unavailable — using keyword matching."

### Switching Modes

```bash
# Development: keyword mode (no Azure OpenAI needed)
CHAT_MODE=keyword python -m uvicorn src.api.app:app

# Development: LLM mode (requires Azure OpenAI endpoint)
CHAT_MODE=llm chainlit run src/chainlit_app.py

# Production: set in Azure Container App environment variables
az containerapp update --name secpostureiq \
  --set-env-vars CHAT_MODE=llm
```

### Why Keep Both?

1. **Zero-dependency demo**: Keyword mode runs without Azure OpenAI, useful for offline demos, CI tests, and quick local setups.
2. **Cost control**: Keyword mode costs $0 per query — useful for environments where LLM spend is not approved.
3. **Gradual rollout**: Feature-flag new tenants into LLM mode while the rest stay on keyword mode.
4. **Fallback safety net**: If the LLM endpoint is down or rate-limited, keyword mode keeps the app functional.

---

## Implementation Plan

### Phase 1: Chainlit App Scaffolding

**Goal**: Minimal Chainlit app that echoes messages, with tool-call stubs.

| Task | Detail | Size |
|---|---|---|
| Add `chainlit` to `pyproject.toml` dependencies | `"chainlit>=2.10.0"` | S |
| Create `src/chainlit_app.py` | `@cl.on_chat_start`, `@cl.on_message` handlers | S |
| Create `.chainlit/config.toml` | Theme, project name, telemetry off | S |
| Mount Chainlit ASGI in `app.py` | `app.mount("/chat-ui", chainlit_asgi)` | S |
| Verify local dev works | `chainlit run src/chainlit_app.py` | S |
| **Phase 1 total** | | **~0.5 days** |

### Phase 2: Azure OpenAI Function Calling

**Goal**: LLM-driven tool selection with streaming responses.

| Task | Detail | Size |
|---|---|---|
| Extract shared tool definitions | Move JSON schemas from `main.py` `TOOLS` list to `src/tools/definitions.py` — usable by both CLI and Chainlit | M |
| OpenAI function-calling loop | In `@cl.on_message`: build messages array, call `chat.completions.create(tools=...)`, loop on tool_calls, feed results back | M |
| Reuse `_run_tool()` | Import from `chat.py` — unchanged | S |
| Streaming output | Use `cl.Message.stream_token()` with OpenAI streaming API | S |
| System prompt | Reuse `SYSTEM_PROMPT` from `src/agent/system_prompt.py` | S |
| **Phase 2 total** | | **~1.5 days** |

### Phase 3: Tool-Call Visualization

**Goal**: Users see which tools are running and can expand to see results.

| Task | Detail | Size |
|---|---|---|
| `cl.Step` wrappers | Each `_run_tool()` call wrapped in `async with cl.Step(name=tool_name):` — shows tool name, inputs, formatted output | S |
| Reuse `_FORMATTERS` inside steps | `step.output = _format_defender(result)` — structured markdown inside each expandable step | S |
| Error steps | On tool failure, `step.is_error = True` with error message | S |
| **Phase 3 total** | | **~0.5 days** |

### Phase 4: Authentication & Graph Token

**Goal**: Chainlit OAuth with Entra ID, forwarding the Graph token to tools.

| Task | Detail | Size |
|---|---|---|
| `@cl.oauth_callback` | Configure Entra ID OAuth provider in Chainlit config; exchange auth code for Graph token | M |
| `cl.user_session.set("graph_token", ...)` | Store the delegated Graph token in the user session | S |
| Pass Graph token to `_run_tool()` | `graph_token = cl.user_session.get("graph_token")` before each tool call | S |
| Token refresh | Refresh the Graph token if expired (using MSAL `acquire_token_silent`) | M |
| **Phase 4 total** | | **~1 day** |

#### Auth Extensibility: Social Identity Providers

The authentication layer is designed to be **extensible beyond Entra ID**. Users can login with Google, Facebook, Microsoft personal accounts (Outlook.com), GitHub, etc. via two complementary approaches:

1. **Chainlit Multi-Provider OAuth**: Chainlit natively supports configuring multiple OAuth providers in `.chainlit/config.toml`. Each provider (Google, GitHub, Azure AD, etc.) can be enabled independently. Users see a provider picker at sign-in.

2. **Entra External ID (B2C) Federation** *(recommended for production)*: Azure AD B2C acts as an identity broker — users sign in with their social provider (Google, Facebook, Microsoft personal account) and B2C issues an Entra-compatible token. This is the preferred approach because:
   - The app receives a **single, consistent token format** regardless of provider
   - B2C handles the social provider integration, token mapping, and claim enrichment
   - The existing `validate_token()` pipeline in `auth.py` works unchanged

**Important caveat — Graph API access**: The security tools (Secure Score, Defender, Purview, Entra Config) call Microsoft Graph APIs that require **delegated permissions scoped to an M365 tenant**. A pure social login (Google/Facebook) authenticates the *user*, but does not grant access to any tenant's security data. To bridge this gap, two patterns are available:

| Pattern | How it works | When to use |
|---|---|---|
| **B2C + Linked Entra Account** | Social users are linked to an Entra ID guest account in the target tenant. B2C issues tokens that include Graph-eligible claims. | Multi-tenant SaaS where customers invite consultants via social login |
| **Social login + Separate Graph consent** | Social login handles authentication; a second OAuth flow prompts the user to consent to Graph permissions via their Entra account. | "Login with Google, then connect your M365 tenant" UX |

**Config**: To enable social providers, set `OAUTH_PROVIDERS=entra,google,facebook` (comma-separated) in `.env`. The Chainlit config will read this and enable the corresponding providers. Future implementation in Phase 4 will wire up the `.chainlit/config.toml` provider list dynamically.

### Phase 5: Multi-Turn Context & Session History

**Goal**: Follow-up questions work ("now show me just the Entra gaps").

| Task | Detail | Size |
|---|---|---|
| Store conversation history | `cl.user_session.set("messages", [...])` — append user + assistant messages each turn | S |
| Context window management | Trim history to fit token budget (keep system prompt + last N turns + latest tool results) | M |
| Store tool results per session | `cl.user_session.set("results", {...})` — so remediation/scorecard tools can reference prior assessments | S |
| **Phase 5 total** | | **~0.5 days** |

### Phase 6: Production Hardening

**Goal**: Container deployment, observability, and graceful degradation.

| Task | Detail | Size |
|---|---|---|
| Dockerfile changes | Install Chainlit in the container image | S |
| Tracing integration | Wrap Chainlit calls with existing `trace_agent_invocation` / `trace_tool_call` decorators | M |
| Content safety | Run LLM output through `content_safety` middleware before sending to user | S |
| PII redaction | Apply `pii_redaction` to tool results before storing in session | S |
| Fallback mode | If Azure OpenAI is unavailable, degrade to keyword-based `_classify_intent()` mode with a banner message | S |
| Rate limiting | Per-user message rate limiting to control token cost | S |
| Health check | Add Chainlit readiness to `/ready` probe | S |
| **Phase 6 total** | | **~1 day** |

---

## File Structure (New & Modified)

```
src/
  chainlit_app.py          ← NEW: Chainlit event handlers (@cl.on_message, etc.)
  tools/
    definitions.py         ← NEW: Shared tool JSON schemas (used by CLI + Chainlit)
  api/
    app.py                 ← MODIFIED: Mount Chainlit ASGI at /chat-ui
    chat.py                ← UNCHANGED: Kept as legacy API endpoint
  agent/
    main.py                ← MODIFIED: Import tool schemas from definitions.py
.chainlit/
  config.toml              ← NEW: Chainlit configuration (theme, auth, telemetry)
chainlit.md                ← NEW: Welcome message shown to users on first visit
pyproject.toml             ← MODIFIED: Add chainlit dependency
Dockerfile                 ← MODIFIED: Ensure chainlit is installed
```

---

## Key Code Patterns

### `src/chainlit_app.py` (simplified sketch)

```python
import chainlit as cl
from openai import AsyncAzureOpenAI
from src.agent.config import settings
from src.agent.system_prompt import SYSTEM_PROMPT
from src.api.chat import _run_tool
from src.tools.definitions import TOOL_SCHEMAS


client = AsyncAzureOpenAI(
    azure_endpoint=settings.azure_openai_endpoint,
    api_version=settings.azure_openai_api_version,
    # Uses DefaultAzureCredential or API key from settings
)


@cl.on_chat_start
async def on_start():
    cl.user_session.set("messages", [
        {"role": "system", "content": SYSTEM_PROMPT},
    ])
    cl.user_session.set("results", {})
    await cl.Message(content="🛡️ **SecPostureIQ** ready. Ask me about your tenant's ME5 security posture.").send()


@cl.on_message
async def on_message(message: cl.Message):
    messages = cl.user_session.get("messages")
    messages.append({"role": "user", "content": message.content})
    graph_token = cl.user_session.get("graph_token", "")

    # Function-calling loop
    while True:
        response = await client.chat.completions.create(
            model=settings.azure_openai_deployment,
            messages=messages,
            tools=TOOL_SCHEMAS,
            stream=True,
        )

        # Collect streamed response (handle tool_calls vs content)
        tool_calls, content = await _collect_stream(response)

        if not tool_calls:
            # Final response — stream to user
            msg = cl.Message(content=content)
            await msg.send()
            messages.append({"role": "assistant", "content": content})
            break

        # Execute tool calls with visualization
        messages.append({"role": "assistant", "tool_calls": tool_calls})
        for tc in tool_calls:
            async with cl.Step(name=tc.function.name, type="tool") as step:
                step.input = tc.function.arguments
                result = await _run_tool(tc.function.name, json.loads(tc.function.arguments), graph_token)
                step.output = json.dumps(result, indent=2, default=str)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result, default=str),
                })

    cl.user_session.set("messages", messages)
```

### `src/tools/definitions.py` (shared schemas)

```python
"""Tool JSON schemas shared between CLI agent (main.py) and Chainlit app."""

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "query_secure_score",
            "description": "Retrieve the tenant's Microsoft Secure Score...",
            "parameters": {
                "type": "object",
                "properties": {
                    "tenant_id": {"type": "string", "description": "..."},
                },
                "required": [],
            },
        },
    },
    # ... remaining 7 tools
]
```

---

## Comparison: Before & After

| Aspect | Current (`chat.py` + `index.html`) | Chainlit |
|---|---|---|
| **Intent routing** | Keyword match (`_classify_intent`) | LLM function calling (GPT-4o) |
| **Multi-turn** | None (stateless per turn) | Full (conversation history in session) |
| **Streaming** | None (full response returned) | Token-by-token via WebSocket |
| **Tool visualization** | None (tools run silently) | Expandable `cl.Step` per tool |
| **Auth** | Custom OAuth2 in `app.py` | Chainlit OAuth + existing Entra flow |
| **Frontend** | 1400-line `index.html` | Chainlit built-in UI (zero custom HTML) |
| **Follow-up questions** | Not supported | Natural ("show me just the P0 items") |
| **Error UX** | Inline error text | `step.is_error` with expandable details |
| **Markdown rendering** | Client-side in `index.html` | Chainlit native (LaTeX, Mermaid, code blocks) |

---

## Migration Strategy

1. **Phase 1–3**: Build and test Chainlit at `/chat-ui` alongside existing UI at `/`.
2. **Phase 4–5**: Add auth and multi-turn; invite internal testers to `/chat-ui`.
3. **Phase 6**: Production hardening; promote Chainlit to `/` and move `index.html` to `/legacy`.
4. **Cleanup**: Remove `_classify_intent()`, `_TOOL_INTENTS`, and `_FORMATTERS` from `chat.py` once Chainlit is the only UI. Keep `_run_tool()` and `POST /chat` for programmatic API access.

---

## Dependencies

| Dependency | Status |
|---|---|
| `chainlit>=2.10.0` | 🔧 Add to `pyproject.toml` (available on PyPI) |
| Azure OpenAI endpoint | ✅ Already in `.env` and `settings` |
| `openai` Python package | ✅ Already in `pyproject.toml` |
| System prompt | ✅ `src/agent/system_prompt.py` — reusable |
| Tool definitions | 🔧 Extract from CLI `TOOLS` list into `src/tools/definitions.py` |
| Token budget utility | 🔧 Need a helper to trim conversation history to fit context window |
| Entra ID OAuth config | 🔧 Configure Chainlit's OAuth provider settings for Entra ID |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Chainlit version churn | M | Pin version in `pyproject.toml`; test upgrades in CI |
| Chainlit-FastAPI mount conflicts | M | Start at `/chat-ui` sub-path; move to root once stable |
| LLM latency for simple queries | L | Cache frequent queries; LLM is fast for single-tool calls |
| Token cost growth | M | Context window truncation; per-user rate limits |
| Chainlit UI customization limits | L | Chainlit supports custom CSS/JS and component overrides |
| Azure OpenAI outage | M | Fallback to keyword mode with banner message |
| **Chainlit scalability ceiling** | **H** | **See Scalability section below; plan for frontend graduation at >10K concurrent** |

---

## Scalability Assessment

> **Related**: [Scaling Strategy](scaling-strategy.md) for full infrastructure scaling analysis.

### Chainlit's Limits

Chainlit is a single-process ASGI server with in-memory WebSocket/session management. It is excellent for rapid development but has a **hard ceiling for hyperscale**:

| Factor | Limit | Why |
|---|---|---|
| **WebSocket connections per instance** | ~1K–5K concurrent | Each connection holds memory for the socket, session state, and message buffers. Python's event loop throughput degrades beyond this. |
| **Session state** | In-memory (`cl.user_session`) | Not shared across replicas. WebSocket connections require session affinity (sticky routing). |
| **Clustering** | None built-in | No distributed message bus, no sharding, no worker pools. Horizontal scaling requires an external WebSocket-aware load balancer. |
| **CPU parallelism** | Single-threaded (GIL) | Async I/O handles OpenAI/Graph wait time well, but CPU-bound work (JSON parsing, markdown formatting) is single-threaded per process. |

### The Real Bottleneck

At scale, **Chainlit is not the binding constraint — Azure OpenAI TPM is**. A full assessment consumes ~4K–8K tokens. At 30K TPM, the system maxes out at ~4–7 concurrent full assessments/minute regardless of how many Chainlit replicas are running. Even with APIM GenAI Gateway pooling 3 regional OpenAI deployments (450K TPM), throughput tops out at ~60–100 concurrent LLM conversations. The UI framework becomes irrelevant if the LLM can't keep up.

### Graduation Path

The architecture is designed so the backend logic (`_run_tool()`, tool definitions, system prompt, Azure OpenAI function-calling loop) is **decoupled from the UI layer**. This means swapping out Chainlit's frontend is a UI-only change — no backend rewrite needed.

| Scale Tier | Concurrent Users | UI Approach | Infrastructure |
|---|---|---|---|
| **Tier 1: Prototype** | 1–100 | Chainlit as-is | Single Container App, in-memory sessions |
| **Tier 2: Production** | 100–1K | Chainlit + sticky sessions | 10–20 replicas, Redis sessions, APIM |
| **Tier 3: Growth** | 1K–10K | Chainlit behind Application Gateway | Multi-region, Redis replication, APIM GenAI pooling |
| **Tier 4: Enterprise** | 10K–100K | **Graduate to custom React SPA + WebSocket** | Same backend logic, async queue (Service Bus), Cosmos DB sessions |
| **Tier 5: Hyperscale** | 100K–1M+ | Custom React SPA + CDN + WebSocket gateway | Multi-region distributed workers, queue-driven, event-sourced |

### Design Principles for Graduation-Readiness

To ensure a smooth transition when Chainlit is outgrown:

1. **Keep tool logic in `_run_tool()` and `src/tools/`** — never embed business logic in Chainlit event handlers.
2. **Keep the OpenAI function-calling loop generic** — the `while True: call → tool_calls → execute → feed back` loop should live in a reusable module, not in `@cl.on_message`.
3. **Externalize session state early** — even at Tier 1, use Redis for sessions so the Chainlit-to-custom-frontend migration doesn't require a session store migration.
4. **Keep `POST /chat` alive** — the stateless HTTP endpoint (keyword mode) serves as the API layer for programmatic callers, CI, and as a fallback. This endpoint survives any UI migration.

---

## Estimated Timeline

| Phase | Scope | Effort |
|---|---|---|
| Phase 1 | Scaffolding + hello world | 0.5 days |
| Phase 2 | Azure OpenAI function calling + streaming | 1.5 days |
| Phase 3 | Tool-call visualization | 0.5 days |
| Phase 4 | Auth + Graph token | 1 day |
| Phase 5 | Multi-turn context | 0.5 days |
| Phase 6 | Production hardening | 1 day |
| **Total** | | **~5 days** |
