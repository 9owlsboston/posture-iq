# Scaling Strategy for PostureIQ

> **Status:** Proposal — pending review
> **Date:** 2026-02-26
> **Author:** PostureIQ Engineering
> **Related:** [Multi-Tenant Strategy](multi-tenant-strategy.md)

---

## Table of Contents

1. [Current Architecture (As-Is)](#1-current-architecture-as-is)
2. [Scaling Bottlenecks](#2-scaling-bottlenecks)
3. [Scaling Options](#3-scaling-options)
4. [Option Comparison Matrix](#4-option-comparison-matrix)
5. [Multi-Tenant Interaction](#5-multi-tenant-interaction)
6. [Recommended Scaling Plan](#6-recommended-scaling-plan)

---

## 1. Current Architecture (As-Is)

### Compute — Azure Container Apps

| Setting | Current Value | Source |
|---------|--------------|--------|
| Runtime | Python 3.11, FastAPI + Uvicorn | `Dockerfile` |
| Workers | 1 Uvicorn worker per container | `CMD ["uvicorn", ... "--workers", "1"]` |
| CPU / Memory | 0.5 vCPU, 1 GiB per replica | `container-app.bicep` |
| Min replicas | 0 (scale to zero) | `container-app.bicep` |
| Max replicas | 5 | `container-app.bicep` |
| Scale trigger | HTTP — 10 concurrent requests per replica | `container-app.bicep` |
| Health probes | Liveness (`/health`), Readiness (`/ready`) | `container-app.bicep`, `app.py` |

### State

| Component | Current | Scaling Impact |
|-----------|---------|---------------|
| Chat sessions | In-memory dict (`_sessions`) | **Lost on scale-down or restart. Not shared across replicas.** |
| JWKS key cache | In-memory singleton (`_jwks_cache`) | Each replica maintains its own cache (acceptable — keys fetched from Entra ID) |
| Audit log | App Insights (external) | Scales independently |

### Backend Services

| Service | SKU | Capacity | Scaling Model |
|---------|-----|----------|---------------|
| Azure OpenAI (gpt-4o) | GlobalStandard | 30K TPM (tokens per minute) | Per-deployment quota; no auto-scale |
| Azure AI Content Safety | S0 | 1K TPS (transactions per second) | Per-resource throttle |
| Microsoft Graph API | N/A (shared) | Per-tenant + per-app throttling | Governed by Microsoft; 10K req/10min per app per tenant |
| Azure Key Vault | Standard | 1K transactions/second | Per-vault throttle |
| App Insights / Log Analytics | PerGB2018 | Ingestion-based | Auto-scales on ingestion; cost scales with volume |
| Azure Container Registry | Basic (dev) / Standard (prod) | Throughput-limited | Pull throughput increases with SKU |

### Current Theoretical Capacity

```
Max replicas:          5
Concurrent per replica: 10 (scale trigger)
Max concurrent users:  ~50
```

But the real bottleneck is **Azure OpenAI at 30K TPM**. A single full
assessment (Secure Score + Defender + Purview + Entra + Remediation +
Playbook) consumes ~4K–8K tokens. At 30K TPM:

```
Max full assessments/min: ~4–7 concurrent
```

Beyond that, requests queue or get 429 (rate limited).

---

## 2. Scaling Bottlenecks

Ordered by which hits first as load increases:

| # | Bottleneck | Limit | Symptom | Severity |
|---|-----------|-------|---------|----------|
| 1 | **Azure OpenAI TPM** | 30K TPM (GlobalStandard) | 429 errors from OpenAI | **Critical** — hard ceiling |
| 2 | **In-memory sessions** | 1 replica's memory | Sessions lost on scale events; sticky sessions not guaranteed | **High** — breaks multi-turn conversations |
| 3 | **Graph API throttling** | 10K req/10min/app/tenant | 429 from Graph | **Medium** — per-tenant limit |
| 4 | **Container CPU/Memory** | 0.5 vCPU / 1 GiB | Slow responses under load | **Medium** — easily adjusted |
| 5 | **Max replicas** | 5 | Can't absorb burst traffic beyond 50 concurrent | **Medium** — easily adjusted |
| 6 | **Content Safety TPS** | 1K TPS | 429 from Content Safety | **Low** — unlikely to hit first |
| 7 | **Single Uvicorn worker** | 1 worker per container | Can't utilize multi-core within a replica | **Low** — async handles this for I/O-bound work |

---

## 3. Scaling Options

### Option S1: Tune Current Container Apps (Vertical + Horizontal)

No new Azure services. Adjust the existing deployment parameters.

#### Changes

| Parameter | Current | Proposed | Impact |
|-----------|---------|----------|--------|
| Max replicas | 5 | 20–50 | Handle burst traffic |
| CPU / Memory | 0.5 vCPU / 1 GiB | 1 vCPU / 2 GiB | Faster tool execution, larger in-memory cache |
| Scale trigger | 10 concurrent | 5 concurrent | Scale out sooner, avoid queueing |
| OpenAI TPM | 30K | 150K–300K | Raise quota via Azure portal or PTU reservation |
| Uvicorn workers | 1 | 2–4 (if CPU-bound work increases) | Better per-replica throughput |

#### Effort: ~0.5 day (Bicep parameter changes + OpenAI quota request)

#### Limits

- **Sessions still in-memory** — doesn't solve cross-replica session sharing.
- **OpenAI quota** — requires approval for >30K TPM; may take days.
- **No queue** — if all replicas are busy, requests fail rather than queue.

---

### Option S2: Add External Session Store (Redis / Cosmos DB)

Replace the in-memory `_sessions` dict with an external store so sessions
survive replica scaling, restarts, and deployments.

#### Azure Service Options

| Service | Latency | Cost (dev) | Fit |
|---------|---------|-----------|-----|
| **Azure Cache for Redis** | <1 ms | ~$13/mo (Basic C0) | Best for ephemeral session data. TTL-based expiry. |
| **Azure Cosmos DB (Serverless)** | ~5 ms | Pay-per-request | Better if sessions need durability or querying. |
| **Azure Blob (as fallback)** | ~20 ms | ~$0.02/GB | Cheapest but too slow for chat UX. |

#### Recommended: Azure Cache for Redis

```python
# chat.py — session store backed by Redis
import redis.asyncio as redis

_redis = redis.from_url(settings.redis_connection_string)

async def get_session(session_key: str) -> dict:
    data = await _redis.get(session_key)
    return json.loads(data) if data else {}

async def save_session(session_key: str, session: dict, ttl: int = 3600):
    await _redis.set(session_key, json.dumps(session), ex=ttl)
```

#### Effort: ~1 day (Bicep module + code change + tests)

---

### Option S3: Add Request Queue (Azure Service Bus / Storage Queue)

Decouple request ingestion from processing. The API accepts chat requests
immediately and returns a `202 Accepted` with a job ID. A background worker
processes the queue.

#### Architecture

```
Client → POST /chat → API (fast: enqueue + return 202)
                          ↓
                    Azure Service Bus
                          ↓
             Worker replicas (process + call OpenAI + Graph)
                          ↓
                    Redis / Cosmos (store result)
                          ↓
Client → GET /chat/{job-id}/result (poll or WebSocket)
```

#### Benefits

- **Backpressure handling** — requests queue instead of 429.
- **Worker isolation** — API replicas and worker replicas scale independently.
- **Retry logic** — failed tool calls retry from the queue.

#### Tradeoffs

- **Latency** — no longer synchronous; client must poll or use WebSocket.
- **Complexity** — two deployment targets (API + worker), queue management.
- **UX change** — current chat UI assumes synchronous responses.

#### Effort: ~3–5 days (queue infra + worker + async chat flow + UI update)

---

### Option S4: Azure API Management (APIM) Front Door

Place APIM in front of the Container App for enterprise-grade traffic
management.

#### Capabilities

| Feature | Description |
|---------|-------------|
| **Rate limiting** | Per-tenant, per-user, per-API throttling policies |
| **Caching** | Cache identical tool call results (e.g., Secure Score doesn't change every minute) |
| **Load balancing** | Route to multiple backend pools (useful for multi-region) |
| **OAuth2 validation** | Offload JWT validation to APIM (reduce app-layer work) |
| **Analytics** | Built-in request analytics, latency tracking |
| **OpenAI gateway** | APIM's GenAI gateway can load-balance across multiple OpenAI deployments |

#### Key value for PostureIQ: **OpenAI load balancing**

APIM's GenAI Gateway can distribute requests across multiple Azure OpenAI
deployments (different regions, different quotas), effectively multiplying
the TPM ceiling:

```
APIM GenAI Gateway
  ├── OpenAI East US 2  (150K TPM)
  ├── OpenAI West US    (150K TPM)
  └── OpenAI Sweden     (150K TPM)
      ──────────────────────────
      Effective: ~450K TPM
```

#### Effort: ~2–3 days (APIM Bicep + policies + backend pool config)

#### Cost: APIM Consumption tier ~$3.50 per million calls; Standard v2 ~$300/mo

---

### Option S5: Multi-Region Deployment (Azure Front Door + Container Apps)

Deploy the agent to multiple Azure regions behind Azure Front Door for
global availability and geo-proximity.

#### Architecture

```
                    Azure Front Door
                    (global load balancer)
                   /         |         \
          East US 2    West Europe    Southeast Asia
          ┌──────┐     ┌──────┐      ┌──────┐
          │ CA   │     │ CA   │      │ CA   │
          │ Redis│     │ Redis│      │ Redis│
          │ OAI  │     │ OAI  │      │ OAI  │
          └──────┘     └──────┘      └──────┘
```

#### Benefits

- **Geo-latency** — users hit the nearest region.
- **Availability** — region failover if one goes down.
- **TPM multiplication** — each region has its own OpenAI deployment quota.
- **Data residency** — can route EU tenants to EU-hosted instances.

#### Tradeoffs

- **Cost** — N × everything (OpenAI, Container Apps, Redis, Content Safety).
- **Session affinity** — need Redis replication or Cosmos DB global distribution.
- **Complexity** — multi-region Bicep, Front Door routing rules, health probes.

#### Effort: ~5–7 days (Front Door + per-region Bicep + session replication)

---

### Option S6: Azure Kubernetes Service (AKS)

Replace Container Apps with AKS for finer-grained control over scheduling,
node pools, and resource management.

#### When AKS Makes Sense

- Need GPU nodes for local model inference.
- Need custom networking (CNI, service mesh, mTLS between pods).
- Need to run sidecar containers (e.g., Envoy, telemetry agents).
- Exceeding Container Apps limits (>300 replicas, >100 Container Apps).
- Team has Kubernetes expertise and wants full control.

#### When Container Apps Still Wins

- Current scale target is <100 concurrent users.
- Prefer serverless (scale-to-zero, no cluster management).
- Team doesn't want to manage node pools, KEDA, Ingress controllers.

#### Effort: ~5–10 days (AKS Bicep + Helm charts + Ingress + KEDA + migration)

#### Recommendation: **Not yet.** Container Apps covers the current and
near-term scale needs. Revisit when hitting Container Apps hard limits or
needing GPU nodes.

---

## 4. Option Comparison Matrix

| Option | Concurrent Users | OpenAI TPM | Session Durability | Effort | Monthly Cost Delta | When |
|--------|-----------------|------------|-------------------|--------|-------------------|------|
| **S1: Tune Container Apps** | ~100–200 | 150K–300K (quota raise) | ❌ In-memory | 0.5 day | ~$0 (quota is free) | **Now** |
| **S2: Redis Sessions** | Same as S1 | Same as S1 | ✅ Cross-replica | 1 day | +$13–50/mo | **Now** |
| **S3: Request Queue** | ~500+ (queued) | Same as S1 | ✅ Queued | 3–5 days | +$10–25/mo | When sync latency is unacceptable |
| **S4: APIM Front Door** | ~500+ | **450K+ (multi-region OAI)** | Same as S2 | 2–3 days | +$50–300/mo | When per-tenant rate limiting or OAI pooling needed |
| **S5: Multi-Region** | ~1000+ | **Nx per region** | ✅ Global | 5–7 days | +$500–1500/mo | When geo-latency or data residency matters |
| **S6: AKS** | ~1000+ | Same as above | ✅ | 5–10 days | +$200–800/mo | When hitting CA limits or needing GPU |

---

## 5. Multi-Tenant Interaction

### How Scaling Choices Affect the Multi-Tenant Decision

| Scaling Factor | Multi-Tenant Option A (Shared Instance) | Multi-Tenant Option B (Stamp-per-Tenant) |
|---------------|----------------------------------------|------------------------------------------|
| **Container Apps replicas** | 1 set of replicas serves all tenants. Scale based on aggregate load. Cost-efficient. | N sets of replicas (one per tenant). Each scales independently. N × cost. |
| **OpenAI TPM** | All tenants share the same 30K–300K TPM pool. One noisy tenant can starve others. **Needs per-tenant rate limiting (S4).** | Each stamp has its own OpenAI deployment with dedicated TPM. Natural isolation. More costly. |
| **Redis sessions** | One Redis instance, sessions keyed by `(tenant_id, user_id, session_id)`. | N Redis instances (or N key prefixes). More infra to manage. |
| **Queue (Service Bus)** | One queue with tenant-aware routing. Can prioritize tenants. | N queues or N topics. Complexity grows linearly. |
| **APIM** | One APIM instance with per-tenant rate-limit policies. **Natural fit.** | N APIM backends (or one APIM routing to N stamps). Doable but complex. |
| **Multi-region** | Deploy agent to N regions, each serving all tenants in that geo. **Cleanest model.** | Deploy agent to N regions × M tenants. Combinatorial explosion. |

### Key Insight

> **Option A (multi-tenant) scales better with every scaling option except
> dedicated OpenAI TPM per tenant.** APIM's GenAI Gateway (S4) solves the
> shared-TPM problem by pooling across multiple OpenAI deployments with
> per-tenant rate limit policies.
>
> **Option B (stamp-per-tenant) gets increasingly expensive and complex as
> you layer on scaling services.** Each new service (Redis, APIM, queue)
> must be replicated per stamp.

---

## 6. Recommended Scaling Plan

### Phase 1: Immediate (Week 1)

**Goal:** Handle 50–100 concurrent users reliably.

| Action | Option | Effort |
|--------|--------|--------|
| Increase max replicas to 20 | S1 | 10 min |
| Increase CPU to 1 vCPU / 2 GiB | S1 | 10 min |
| Request Azure OpenAI quota increase to 150K TPM | S1 | 1 hour (portal) |
| Add Redis for session storage | S2 | 1 day |

#### Bicep Changes (S1)

```bicep
// container-app.bicep — adjusted parameters
resources: {
  cpu: json('1.0')    // was 0.5
  memory: '2Gi'       // was 1Gi
}
scale: {
  minReplicas: 1      // was 0 — avoid cold start for first user
  maxReplicas: 20     // was 5
}
```

### Phase 2: Growth (Weeks 2–4)

**Goal:** Handle 200–500 concurrent users with per-tenant fairness.

| Action | Option | Effort |
|--------|--------|--------|
| Add APIM with per-tenant rate limiting | S4 | 2–3 days |
| Configure APIM GenAI Gateway with 2–3 OpenAI deployments | S4 | 1 day |
| Implement multi-tenant auth (Option A from multi-tenant strategy) | — | 5 days |

### Phase 3: Enterprise Scale (Month 2+)

**Goal:** Handle 500+ concurrent users across geos.

| Action | Option | Effort |
|--------|--------|--------|
| Add second Azure region | S5 | 5–7 days |
| Azure Front Door for geo-routing | S5 | 2 days |
| Cosmos DB global session store (replaces Redis) | S5 | 2 days |
| Queue-based async processing (if sync latency is a problem) | S3 | 3–5 days |

---

## Cost Projections

Assuming 50 active tenants, 200 concurrent users at peak:

| Scenario | Monthly Estimate |
|----------|-----------------|
| **Current (as-is)** | ~$150–200 (Container Apps + OpenAI S0 + App Insights + Key Vault) |
| **Phase 1 + Multi-Tenant A** | ~$250–350 (+ Redis + higher replica hours) |
| **Phase 2 + APIM** | ~$500–800 (+ APIM + multi-region OpenAI) |
| **Phase 3 + Multi-Region** | ~$1,500–2,500 (2 regions × full stack) |
| **Option B (stamp-per-tenant, 50 stamps)** | ~$5,000–10,000 (50 × ~$150 base per stamp) |

> **Option A + S1–S4 at 50 tenants: ~$500–800/mo.**
> **Option B at 50 tenants: ~$5,000–10,000/mo.**
> This cost difference grows linearly with tenant count.

---

## Open Questions

1. **OpenAI quota timeline:** How quickly can we get 150K+ TPM approved? Do
   we need PTU (provisioned throughput) for guaranteed capacity?
2. **Session TTL:** How long should chat sessions persist? 1 hour? 24 hours?
   Affects Redis memory sizing.
3. **Async tolerance:** Would users accept a "thinking..." UX with polling,
   or is synchronous response required?
4. **Data residency requirements:** Do any target tenants require data to
   stay in a specific Azure region?
5. **Burst patterns:** Is traffic steady throughout the day or concentrated
   during specific hours (e.g., business hours in specific time zones)?
