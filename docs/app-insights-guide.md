# App Insights — Viewing Telemetry & Troubleshooting

This guide covers how to view PostureIQ telemetry in Azure Application Insights,
how to simulate traffic to generate data, and how to troubleshoot common issues.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Where Telemetry Lives](#where-telemetry-lives)
- [Viewing Telemetry in the Portal](#viewing-telemetry-in-the-portal)
- [Kusto Queries (KQL)](#kusto-queries-kql)
- [GenAI / Agent (preview) Blade](#genai--agent-preview-blade)
- [Querying from the CLI](#querying-from-the-cli)
- [Simulating Traffic](#simulating-traffic)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌──────────────────┐     ┌──────────────────────────────────────┐
│  Client / Load   │────▶│  Azure Container App (FastAPI)       │
│  Simulator       │     │                                      │
└──────────────────┘     │  setup_tracing()                     │
                         │    ├─ configure_azure_monitor()       │
                         │    │    └─ OpenTelemetry SDK          │
                         │    │         ├─ auto-instruments HTTP │
                         │    │         └─ exports spans/metrics │
                         │    └─ OpenAIInstrumentor().instrument()│
                         │         └─ patches openai SDK         │
                         │              └─ gen_ai.* spans        │
                         │                                      │
                         │  FastAPIInstrumentor.instrument_app() │
                         │    └─ server request spans (requests)│
                         │                                      │
                         │  @trace_tool_call decorators          │
                         │    └─ tool.* spans with attributes   │
                         │                                      │
                         │  Custom metrics:                      │
                         │    postureiq.secure_score.current     │
                         │    postureiq.assessment.duration_s    │
                         │    postureiq.remediation.steps        │
                         │    postureiq.content_safety.blocked   │
                         └───────────────┬──────────────────────┘
                                         │ OTLP/HTTP
                                         ▼
                         ┌──────────────────────────────────────┐
                         │  Azure Application Insights          │
                         │  (backed by Log Analytics workspace) │
                         │                                      │
                         │  Tables:                              │
                         │    requests      ← server HTTP spans │
                         │    dependencies  ← tool spans, HTTP  │
                         │                    + gen_ai.* LLM    │
                         │    traces        ← structlog messages│
                         │    customMetrics ← gauges, counters  │
                         │    exceptions    ← errors            │
                         │                                      │
                         │  Portal blades:                       │
                         │    Metrics       ← charts over time  │
                         │    Live metrics  ← real-time stream  │
                         │    Agent (prev.) ← GenAI LLM usage   │
                         │    Availability  ← web test pings    │
                         └──────────────────────────────────────┘
```

### How Tracing is Initialized

1. `src/api/app.py` calls `setup_tracing()` at import time (before FastAPI app creation)
2. `setup_tracing()` in `src/middleware/tracing.py` calls `configure_azure_monitor()`
3. This registers the Azure Monitor exporter + auto-instruments FastAPI, httpx, etc.
4. `setup_tracing()` then calls `OpenAIInstrumentor().instrument()` — patches the `openai`
   SDK so every `chat.completions.create()` call emits `gen_ai.*` spans (model, tokens,
   finish reasons). These feed the **Agent (preview)** blade in App Insights.
5. After the `FastAPI(...)` app object is created, `FastAPIInstrumentor.instrument_app(app)`
   is called explicitly to ensure server-side HTTP spans populate the `requests` table.
6. Each tool function is decorated with `@trace_tool_call("tool_name")` which creates child spans
7. The exporter batches and ships telemetry to App Insights via the connection string

**Critical:** If `setup_tracing()` never runs, OpenTelemetry returns a no-op tracer. Spans are
"created" silently but never exported. There are no errors — just silent data loss.

---

## Where Telemetry Lives

PostureIQ telemetry lands in **four** App Insights tables:

| Table | What's in it | Example data |
|---|---|---|
| `requests` | Server-side HTTP spans (FastAPI endpoints) | `GET /health`, `POST /chat`, `GET /ready` |
| `dependencies` | Tool-call spans, HTTP calls, audit spans, GenAI LLM calls | `tool.query_secure_score`, `POST //contentsafety/text:analyze`, `chat gpt-4o` |
| `traces` | Structured log messages (via structlog) | `tool.secure_score.complete`, `chat.tool.invoking` |
| `customMetrics` | Custom gauges, histograms, counters | `postureiq.secure_score.current`, `postureiq.assessment.duration_seconds` |
| `exceptions` | Unhandled errors and recorded exceptions | Stack traces from failed tool calls |

> **GenAI spans:** The `opentelemetry-instrumentation-openai-v2` package auto-instruments every
> `openai.AzureOpenAI.chat.completions.create()` call. These spans carry `gen_ai.*` semantic
> convention attributes and appear in the `dependencies` table as well as the **Agent (preview)**
> blade. Currently only `generate_remediation_plan` calls Azure OpenAI directly — the other
> tools use Graph API / deterministic logic and don't produce GenAI spans.

---

## Viewing Telemetry in the Portal

### Quick Navigation

1. **Azure Portal** → search for your App Insights resource (e.g., `postureiq-dev-ai`)
2. In the left sidebar under **Monitoring**:

| Blade | What it shows |
|---|---|
| **Logs** | Run KQL queries against all tables |
| **Metrics** | Chart custom metrics over time |
| **Live metrics** | Real-time request stream (re-run simulator to see live) |

3. In the left sidebar under **Investigate**:

| Blade | What it shows |
|---|---|
| **Transaction search** / **Search** | Browse individual traces by time |
| **Performance** | Request duration distribution, drill into waterfall |
| **Failures** | Failed requests and exceptions |
| **Application map** | Visual dependency graph |
| **Agent (preview)** | GenAI / LLM usage — model calls, token consumption, latency (requires `gen_ai.*` spans) |

4. In the left sidebar under **Monitoring**:

| Blade | What it shows |
|---|---|
| **Availability** | Web test ping results (requires a Web Test resource — see [Troubleshooting §8](#8-availability-metric-shows-zeros)) |

> If a blade name doesn't match, look under **Investigate** or **Monitoring** sections —
> the Portal UI changes across versions.

### Fastest Path: Logs Blade

The most reliable way to see telemetry regardless of Portal version:

1. Left sidebar → **Monitoring → Logs**
2. Close the query templates popup
3. Paste a query and click **Run**

---

## Kusto Queries (KQL)

### All tool-call spans from the last hour

```kusto
dependencies
| where timestamp > ago(1h)
| where name startswith "tool."
| project timestamp, name, duration, success,
          toolName = tostring(customDimensions["postureiq.tool.name"]),
          status = tostring(customDimensions["postureiq.tool.status"]),
          durationMs = todouble(customDimensions["postureiq.tool.duration_ms"])
| order by timestamp desc
```

### Tool invocation count and average latency

```kusto
dependencies
| where timestamp > ago(2h)
| where name startswith "tool."
| summarize
    count(),
    avg(duration),
    percentile(duration, 50),
    percentile(duration, 95)
  by name
| order by count_ desc
```

### All dependency types (tools + HTTP + audit)

```kusto
dependencies
| where timestamp > ago(1h)
| summarize count(), avg(duration) by name
| order by count_ desc
```

### Content Safety calls

```kusto
dependencies
| where timestamp > ago(2h)
| where name has "contentsafety" or name has "ContentSafety"
| project timestamp, name, duration, success, target, data
| order by timestamp desc
```

### Managed Identity token requests

```kusto
dependencies
| where timestamp > ago(2h)
| where name == "GET /msi/token"
| summarize count(), avg(duration), max(duration)
```

### Structured log messages (traces)

```kusto
traces
| where timestamp > ago(1h)
| where message has "postureiq" or message has "tool."
| project timestamp, message, severityLevel, customDimensions
| order by timestamp desc
| take 50
```

### Custom metrics — Secure Score gauge

```kusto
customMetrics
| where timestamp > ago(2h)
| where name == "postureiq.secure_score.current"
| project timestamp, value
| order by timestamp desc
```

### Custom metrics — Assessment duration histogram

```kusto
customMetrics
| where timestamp > ago(2h)
| where name == "postureiq.assessment.duration_seconds"
| summarize avg(value), max(value), count() by bin(timestamp, 5m)
| render timechart
```

### GenAI (LLM) spans — Agent blade data

These queries surface the same data shown in the **Agent (preview)** blade.

```kusto
// All GenAI LLM calls (emitted by opentelemetry-instrumentation-openai-v2)
dependencies
| where timestamp > ago(2h)
| where customDimensions has "gen_ai.system"
| project
    timestamp,
    name,
    duration,
    model = tostring(customDimensions["gen_ai.response.model"]),
    inputTokens = toint(customDimensions["gen_ai.usage.input_tokens"]),
    outputTokens = toint(customDimensions["gen_ai.usage.output_tokens"]),
    finishReason = tostring(customDimensions["gen_ai.response.finish_reasons"]),
    system = tostring(customDimensions["gen_ai.system"])
| order by timestamp desc
```

```kusto
// Token consumption summary by model (last 24h)
dependencies
| where timestamp > ago(24h)
| where customDimensions has "gen_ai.usage.input_tokens"
| summarize
    calls = count(),
    totalInputTokens = sum(toint(customDimensions["gen_ai.usage.input_tokens"])),
    totalOutputTokens = sum(toint(customDimensions["gen_ai.usage.output_tokens"])),
    avgDurationMs = avg(duration),
    p95DurationMs = percentile(duration, 95)
  by model = tostring(customDimensions["gen_ai.response.model"])
```

```kusto
// GenAI call latency over time (for timechart)
dependencies
| where timestamp > ago(6h)
| where customDimensions has "gen_ai.system"
| summarize
    avgDuration = avg(duration),
    p95Duration = percentile(duration, 95),
    calls = count()
  by bin(timestamp, 5m)
| render timechart
```

> **Note:** Only tools that call `openai.AzureOpenAI.chat.completions.create()` produce GenAI
> spans. Currently this is limited to `generate_remediation_plan`. Other tools use Graph API
> or deterministic logic and do not make LLM calls.

### Error investigation

```kusto
exceptions
| where timestamp > ago(2h)
| project timestamp, type, message, outerMessage, details
| order by timestamp desc
| take 20
```

### End-to-end transaction trace (drill into one operation)

```kusto
// First find an operation ID:
dependencies
| where timestamp > ago(1h)
| where name == "tool.generate_remediation_plan"
| project timestamp, operation_Id, duration
| take 1

// Then trace the full operation:
// (replace <op_id> with the operation_Id from above)
union dependencies, traces, requests
| where operation_Id == "<op_id>"
| project timestamp, itemType, name, duration, message
| order by timestamp asc
```

---

## GenAI / Agent (preview) Blade

The **Agent (preview)** blade (under **Investigate** in the App Insights sidebar) provides a
purpose-built view for monitoring AI/GenAI agent applications. It shows LLM call volume, token
consumption, model latency, and error rates — but **only** for spans that carry
[OpenTelemetry GenAI semantic convention](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
attributes.

### How it Works

The `opentelemetry-instrumentation-openai-v2` package (added to `pyproject.toml`) auto-patches
the `openai` Python SDK. When the app calls `openai.AzureOpenAI.chat.completions.create()`, the
instrumentor creates a span with these attributes:

| Attribute | Example Value | Purpose |
|-----------|---------------|---------|
| `gen_ai.system` | `"openai"` | Identifies the LLM provider |
| `gen_ai.operation.name` | `"chat"` | Operation type |
| `gen_ai.request.model` | `"gpt-4o"` | Requested model name |
| `gen_ai.response.model` | `"gpt-4o-2024-08-06"` | Actual model used |
| `gen_ai.usage.input_tokens` | `1842` | Prompt token count |
| `gen_ai.usage.output_tokens` | `356` | Completion token count |
| `gen_ai.response.finish_reasons` | `["stop"]` | Why generation stopped |

These spans land in the `dependencies` table and the Agent blade reads them automatically.

### What Produces GenAI Spans

| Tool | Makes LLM Call? | GenAI Spans? |
|------|----------------|--------------|
| `generate_remediation_plan` | Yes — `AzureOpenAI.chat.completions.create()` | Yes |
| `query_secure_score` | No — Graph API | No |
| `assess_defender_coverage` | No — Graph API | No |
| `check_purview_policies` | No — Graph API | No |
| `get_entra_config` | No — Graph API | No |
| `create_adoption_scorecard` | No — deterministic | No |
| `get_project479_playbook` | No — deterministic | No |

To see data in the Agent blade, send prompts that trigger `generate_remediation_plan`:

```bash
python scripts/simulate_traffic.py \
  --tools remediation \
  --burst-size 10 \
  --duration 5
```

### Initialization

The instrumentor is wired in `src/middleware/tracing.py` inside `setup_tracing()`:

```python
from opentelemetry.instrumentation.openai_v2 import OpenAIInstrumentor
OpenAIInstrumentor().instrument()
```

This runs after `configure_azure_monitor()` and patches the `openai` module globally.
No changes to individual tool files are needed — the existing `oai_client.chat.completions.create()`
call in `src/tools/remediation_plan.py` is automatically instrumented.

### Capturing Prompt/Completion Content (Optional)

By default, message content is **not** captured (privacy). To enable it for debugging:

```python
# In setup_tracing():
OpenAIInstrumentor().instrument(capture_content=True)
```

Or via environment variable on the Container App:

```bash
az containerapp update \
  -n postureiq-dev-app \
  -g rg-postureiq-dev \
  --set-env-vars "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true"
```

### Scope & Limitations

- **Direct `openai` SDK calls only.** The instrumentor patches the Python `openai` package
  within the app process. LLM calls made by external systems (e.g., the Copilot SDK runtime
  process) are not captured.
- **No GenAI spans for Graph API tools.** Most PostureIQ tools call Microsoft Graph, not an
  LLM. These appear as regular HTTP dependency spans, not GenAI spans.
- **Agent blade is in preview.** The UI and required attributes may evolve. The
  `opentelemetry-instrumentation-openai-v2` package tracks the latest GenAI semantic conventions.

---

## Querying from the CLI

You can query App Insights without opening the Portal:

```bash
# Set your App ID (from the connection string's ApplicationId)
APP_ID="7787d1cc-8e48-4f14-a39a-99530d8f7354"

# Tool span summary
az monitor app-insights query \
  --app $APP_ID \
  --analytics-query "dependencies | where timestamp > ago(1h) | summarize count() by name | order by count_ desc" \
  --offset 2h

# Check if ANY data exists
az monitor app-insights query \
  --app $APP_ID \
  --analytics-query "dependencies | take 5" \
  --offset 24h

# Custom metrics
az monitor app-insights query \
  --app $APP_ID \
  --analytics-query "customMetrics | where timestamp > ago(1h) | summarize count() by name" \
  --offset 2h
```

> The `--offset` flag sets the time window for the query lookup (not the `ago()` filter).
> Use `--offset 24h` if your `ago()` references 24 hours.

---

## Simulating Traffic

### Quick Smoke Test

```bash
# Single burst of 10 requests exercising all tools
python scripts/simulate_traffic.py
```

### Sustained Load (ideal for App Insights dashboards)

```bash
# 30-minute run, burst of 20 requests every 5 minutes
python scripts/simulate_traffic.py \
  --duration 30 \
  --interval 5 \
  --burst-size 20

# 1-hour run, burst of 50 every 2 minutes, high concurrency, with probes
python scripts/simulate_traffic.py \
  --duration 60 \
  --interval 2 \
  --burst-size 50 \
  --concurrency 10 \
  --probes
```

### Targeted Tool Testing

```bash
# Only exercise Secure Score and Defender tools
python scripts/simulate_traffic.py --tools secure_score,defender

# Only remediation and playbook (LLM-heavy, slower)
python scripts/simulate_traffic.py --tools remediation,playbook --burst-size 5
```

### Available `--tools` Tags

| Tag | Tool function | Notes |
|---|---|---|
| `secure_score` | `query_secure_score` | Graph API / mock |
| `defender` | `assess_defender_coverage` | Graph API / mock |
| `purview` | `check_purview_policies` | Graph API / mock |
| `entra` | `get_entra_config` | Graph API / mock |
| `remediation` | `generate_remediation_plan` | Calls Azure OpenAI |
| `scorecard` | `create_adoption_scorecard` | Aggregation tool |
| `playbook` | `get_project479_playbook` | Foundry IQ integration |
| `full` | All 4 assessment tools | Full tenant assessment |

### Full Parameter Reference

```
python scripts/simulate_traffic.py --help

  --url URL              Target deployment URL
  --duration MINS        Total run time in minutes (0 = single burst)
  --interval MINS        Minutes between bursts (default: 5)
  --burst-size N         Chat requests per burst (default: 10)
  --concurrency N        Max simultaneous requests (default: 5)
  --tools TAGS           Comma-separated tool tags (default: all)
  --probes               Include /health, /ready, /version probes
  -v, --verbose          Print each request as it completes
```

### Targeting a Different Endpoint

```bash
# Local development
python scripts/simulate_traffic.py --url http://localhost:8000

# Production
python scripts/simulate_traffic.py --url https://postureiq-prod-app.example.azurecontainerapps.io
```

---

## Troubleshooting

### 1. No data in App Insights at all

**Check the connection string env var on the container app:**

```bash
az containerapp show \
  -n postureiq-dev-app \
  -g rg-postureiq-dev \
  --query "properties.template.containers[0].env[?name=='APPLICATIONINSIGHTS_CONNECTION_STRING']"
```

If missing, set it:

```bash
az containerapp update \
  -n postureiq-dev-app \
  -g rg-postureiq-dev \
  --set-env-vars "APPLICATIONINSIGHTS_CONNECTION_STRING=<your-connection-string>"
```

### 2. Connection string is set but still no data

**Check if `setup_tracing()` is called at startup.**

In `src/api/app.py`, `setup_tracing()` must run before the FastAPI `app` object is created.
If it's not there, `configure_azure_monitor()` never registers the exporter, and OpenTelemetry
uses a **no-op tracer** — spans are created but silently discarded. No errors, no warnings.

Look for `tracing.setup.complete` in the container logs:

```bash
az containerapp logs show \
  -n postureiq-dev-app \
  -g rg-postureiq-dev \
  --type console --tail 100 2>&1 \
  | grep -i "tracing.setup"
```

Expected: `tracing.setup.complete target=azure_app_insights`

If you see `tracing.setup.skipped reason='no connection string configured'`, the env var
isn't reaching the app settings. Check the `Settings` class in `src/agent/config.py`.

If you see `tracing.setup.skipped reason='azure-monitor-opentelemetry not installed'`,
the package is missing from the container image. Rebuild with `pip install .`.

### 3. `dependencies` has data but `requests` is empty

This was a known issue where `configure_azure_monitor()` patches `FastAPI.__init__`
via the generic `instrument()` call, but our `app = FastAPI(...)` is created in the
same module-load so the monkey-patch doesn't take effect. The fix (commit `b38c074`)
adds an explicit `FastAPIInstrumentor.instrument_app(app)` call after app creation.

If you still see an empty `requests` table, verify the explicit instrumentation is
present in `src/api/app.py`:

```python
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
FastAPIInstrumentor.instrument_app(app)
```

**PostureIQ tool-call data always lives in the `dependencies` table** regardless:

```kusto
dependencies
| where timestamp > ago(1h)
| where name startswith "tool."
| summarize count() by name
```

### 4. `az monitor app-insights query` returns empty rows

**Time range mismatch.** The `--offset` flag AND the `ago()` in your query both affect
the window. Make sure they're compatible:

```bash
# ✅ Correct — offset covers the ago() range
az monitor app-insights query --app $APP_ID \
  --analytics-query "dependencies | where timestamp > ago(2h) | take 5" \
  --offset 3h

# ❌ Wrong — offset too small for the ago() range
az monitor app-insights query --app $APP_ID \
  --analytics-query "dependencies | where timestamp > ago(24h) | take 5" \
  --offset 1h
```

**Ingestion delay.** App Insights typically ingests data within 2–5 minutes. After running
the simulator, wait at least 3 minutes before querying.

### 5. `az` CLI says resource provider not registered

```
Subscription xxx is not registered for the Microsoft.App resource provider
```

Your CLI subscription context doesn't match the deployment subscription:

```bash
# Check current subscription
az account show --query "{name:name, id:id}"

# Switch to the correct subscription
az account set --subscription <subscription-id>
```

### 6. Permission denied pushing to GitHub

If `git push` fails with 403, switch to the correct GitHub account:

```bash
gh auth status                          # see which account is active
gh auth switch --user 9owlsboston       # switch to repo owner
gh auth setup-git                       # configure git credential helper
git push origin main
```

### 7. Container shows old code after deployment

Verify the image tag matches your latest commit SHA:

```bash
# Your latest commit
git rev-parse --short HEAD

# Image running in the container app
az containerapp show \
  -n postureiq-dev-app \
  -g rg-postureiq-dev \
  --query "properties.template.containers[0].image" -o tsv
```

If they don't match, the CI/CD pipeline may not have completed. Check GitHub Actions.

### 8. Availability metric shows zeros

The **Availability** metric in App Insights is populated **exclusively by Web Test
resources** (also called "Availability Tests"). Regular HTTP traffic — including
Container Apps health probes, load-balancer pings, and user requests — does **not**
count toward availability.

Without a Web Test resource linked to the App Insights component, the Availability
chart will always show 0%.

**How PostureIQ addresses this:**

The Bicep IaC includes an `availability-test` module
(`infra/modules/availability-test.bicep`) that creates a Standard URL Ping test.
It is wired into `infra/main.bicep` and deployed automatically with every
`az deployment group create` run.

| Setting | Value |
|---------|-------|
| Endpoint | `GET /health` |
| Frequency | Every 5 minutes |
| Locations | 5 US regions (Chicago, San Jose, Virginia, Miami, San Antonio) |
| Validation | HTTP 200, SSL valid, retry on failure |

**Verify the test exists:**

```bash
az monitor app-insights web-test list \
  --resource-group rg-postureiq-dev \
  -o table
```

**Create it manually if missing** (e.g., the IaC hasn't been re-deployed yet):

```bash
az monitor app-insights web-test create \
  --resource-group rg-postureiq-dev \
  --name "postureiq-dev-health-ping" \
  --defined-web-test-name "PostureIQ Health Ping" \
  --location centralus \
  --kind ping \
  --frequency 300 \
  --timeout 30 \
  --retry-enabled true \
  --enabled true \
  --locations Id="us-il-ch1-azr" \
  --locations Id="us-ca-sjc-azr" \
  --locations Id="us-va-ash-azr" \
  --locations Id="us-fl-mia-edge" \
  --locations Id="us-tx-sn1-azr" \
  --web-test-kind standard \
  --request-url "https://<your-container-app-fqdn>/health" \
  --http-verb GET \
  --expected-status-code 200 \
  --ssl-check true \
  --ssl-lifetime-check 7 \
  --tags "hidden-link:<app-insights-resource-id>=Resource"
```

Replace `<your-container-app-fqdn>` and `<app-insights-resource-id>` with your
actual values. Results appear in the Availability blade within 5–10 minutes.

### 9. `configure_azure_monitor()` fails silently

The `setup_tracing()` function catches all exceptions with broad `except Exception`:

```python
try:
    configure_azure_monitor(connection_string=conn_string, ...)
except ImportError:
    logger.warning("tracing.setup.skipped", reason="package not installed")
except Exception as e:
    logger.warning("tracing.setup.failed", error=str(e))
```

Check container logs for `tracing.setup.failed`:

```bash
az containerapp logs show \
  -n postureiq-dev-app \
  -g rg-postureiq-dev \
  --type console --tail 200 2>&1 \
  | grep "tracing.setup"
```

---

## Quick Reference

| What | Command / Query |
|---|---|
| Verify env var | `az containerapp show -n postureiq-dev-app -g rg-postureiq-dev --query "properties.template.containers[0].env[?name=='APPLICATIONINSIGHTS_CONNECTION_STRING']"` |
| Quick data check | `az monitor app-insights query --app $APP_ID --analytics-query "dependencies \| take 5" --offset 24h` |
| Tool span summary | `dependencies \| where timestamp > ago(1h) \| summarize count() by name` |
| Container logs | `az containerapp logs show -n postureiq-dev-app -g rg-postureiq-dev --type console --tail 50` |
| Simulate traffic | `python scripts/simulate_traffic.py --duration 30 --interval 5 --burst-size 20` |
| Live metrics | Portal → App Insights → Investigate → Live metrics |
