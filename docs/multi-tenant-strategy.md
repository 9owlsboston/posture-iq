# Multi-Tenant Strategy for PostureIQ

> **Status:** Proposal — pending review  
> **Date:** 2026-02-26  
> **Author:** PostureIQ Engineering

---

## Problem Statement

The current PostureIQ deployment is bound to a **single ME5 tenant**. All
configuration — Graph API credentials, OAuth2 endpoints, JWT validation — is
pinned to one `AZURE_TENANT_ID`. To assess a different customer tenant, a
separate deployment with different environment variables is required.

For the Project 479 "Get to Green" campaign to scale across multiple ME5
customers, the agent must be reusable across tenants without redeployment.

---

## Current Single-Tenant Bindings

| Layer | What's Hardcoded | File(s) |
|-------|-----------------|---------|
| **Graph API credentials** | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` loaded once at startup | `src/agent/config.py`, `src/tools/graph_client.py` |
| **Auth (JWT validation)** | Issuer and audience pinned to one tenant; OAuth2 authorize/token endpoints use `settings.azure_tenant_id` | `src/middleware/auth.py` (lines 134–135, 196–210) |
| **App Registration** | Single-tenant Entra ID app reg with delegated Graph permissions | `scripts/provision-dev.sh` |

---

## Option A: Multi-Tenant App Registration (Recommended)

One deployed instance serves **any** ME5 tenant. Users from different tenants
log in via their own Entra ID, and the agent reads their tenant's Graph data
using their delegated token.

### Architecture Changes

#### 1. Entra ID App Registration → Multi-Tenant

- Change `signInAudience` from `AzureADMyOrg` to `AzureADMultipleOrgs`.
- Each customer tenant admin grants consent once (admin consent URL or
  `/adminconsent` endpoint).
- Graph API permissions remain **delegated** (not application-level), so the
  agent always acts on behalf of the authenticated user.

#### 2. Auth Layer — Accept Tokens from Any Tenant

**Current:** OAuth2 endpoints and issuer validation are pinned to one tenant:

```python
# auth.py — current (single-tenant)
authorizationUrl = f"{ENTRA_AUTHORITY}/{settings.azure_tenant_id}/oauth2/v2.0/authorize"
tokenUrl = f"{ENTRA_AUTHORITY}/{settings.azure_tenant_id}/oauth2/v2.0/token"

valid_issuers = [
    f"https://login.microsoftonline.com/{tenant_id}/v2.0",
    f"https://sts.windows.net/{tenant_id}/",
]
```

**Proposed:** Use the `organizations` endpoint and validate issuer dynamically:

```python
# auth.py — multi-tenant
authorizationUrl = f"{ENTRA_AUTHORITY}/organizations/oauth2/v2.0/authorize"
tokenUrl = f"{ENTRA_AUTHORITY}/organizations/oauth2/v2.0/token"

# Validate issuer matches the token's own tid claim (any Entra tenant)
token_tid = claims.get("tid", "")
valid_issuers = [
    f"https://login.microsoftonline.com/{token_tid}/v2.0",
    f"https://sts.windows.net/{token_tid}/",
]
```

The JWKS cache already accepts `tenant_id` as a parameter, so key fetching
works per-tenant without changes.

#### 3. Graph Client — Use Delegated User Token (OBO)

**Current:** `graph_client.py` creates a `ClientSecretCredential` using
app-level secrets, which only works for the home tenant.

**Proposed:** Use the user's **delegated access token** obtained from the
OAuth2 flow (On-Behalf-Of pattern) to call Graph. The agent reads each
tenant's data under that user's permissions.

```python
# graph_client.py — multi-tenant (conceptual)
from azure.identity import OnBehalfOfCredential

def create_graph_client_for_user(user_access_token: str, tenant_id: str):
    credential = OnBehalfOfCredential(
        tenant_id=tenant_id,
        client_id=settings.azure_client_id,
        client_secret=settings.azure_client_secret,
        user_assertion=user_access_token,
    )
    return GraphServiceClient(credential, scopes=["https://graph.microsoft.com/.default"])
```

Alternatively, if the user's token already has the required Graph scopes,
pass it directly without OBO.

#### 4. Config Changes

| Setting | Current | Multi-Tenant |
|---------|---------|-------------|
| `AZURE_TENANT_ID` | Required (home tenant) | Optional — only needed for app identity, not for Graph calls |
| `AZURE_CLIENT_ID` | App reg client ID | Same — but app reg is now multi-tenant |
| `AZURE_CLIENT_SECRET` | Used for Graph client credential | Not needed in production (Managed Identity) |
| `MULTI_TENANT_ENABLED` | N/A (new) | `true` — feature flag for rollout |

#### 5. Per-Request Tenant Isolation — How It Works

The critical insight: **there are no per-tenant secrets**. The user's own
token IS the credential. The agent never stores or selects a secret per
tenant — it uses the token that arrived with each HTTP request.

##### Request Flow: Client X and Client Y Hitting the Same Instance

```
┌─────────────┐    ┌─────────────┐
│  Client X   │    │  Client Y   │
│  Tenant: A  │    │  Tenant: B  │
└──────┬──────┘    └──────┬──────┘
       │                  │
       │ POST /chat       │ POST /chat
       │ Bearer: token_X  │ Bearer: token_Y
       │                  │
       ▼                  ▼
┌──────────────────────────────────┐
│      PostureIQ Agent (1 instance)│
│                                  │
│  ┌────────────────────────────┐  │
│  │ Step 1: Validate JWT       │  │
│  │ token_X → tid=A, oid=...  │  │
│  │ token_Y → tid=B, oid=...  │  │
│  └────────────────────────────┘  │
│                                  │
│  ┌────────────────────────────┐  │
│  │ Step 2: Build UserContext  │  │
│  │ Request X → {tenant_id: A,│  │
│  │   user_token: token_X}    │  │
│  │ Request Y → {tenant_id: B,│  │
│  │   user_token: token_Y}    │  │
│  └────────────────────────────┘  │
│                                  │
│  ┌────────────────────────────┐  │
│  │ Step 3: Call Graph API     │  │
│  │ Tool(X) → Graph(token_X)  │──┼──→ graph.microsoft.com (Tenant A data)
│  │ Tool(Y) → Graph(token_Y)  │──┼──→ graph.microsoft.com (Tenant B data)
│  └────────────────────────────┘  │
│                                  │
│  ┌────────────────────────────┐  │
│  │ Step 4: Scoped response    │  │
│  │ Client X ← Tenant A scores│  │
│  │ Client Y ← Tenant B scores│  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

##### Why There Are No Per-Tenant Secrets to Keep Safe

| Question | Answer |
|----------|--------|
| **How does the agent know which tenant?** | From the JWT `tid` claim in the user's bearer token. Every request carries the user's identity, which includes their tenant. `UserContext.tenant_id` already extracts this. |
| **How does the agent call Graph for the right tenant?** | It uses the **user's own access token** (or exchanges it via OBO) to call Graph. Graph automatically scopes the response to the tenant that issued the token. The agent never picks a credential — it uses the one the user brought. |
| **What if Client X's token is used for Tenant B's data?** | Impossible. Graph rejects the call. A token issued by Tenant A can only read Tenant A's data. This is enforced by Entra ID, not by the agent. |
| **Where are per-tenant secrets stored?** | Nowhere. There are none. The Managed Identity authenticates the agent to Azure services (OpenAI, Content Safety, Key Vault). The user's token authenticates to Graph. No per-tenant secret is needed. |
| **What about the Copilot SDK / OpenAI calls?** | These use the agent's own Managed Identity (same for all tenants). The LLM processes the user's query regardless of tenant — it only sees the data returned by Graph for that user's token. |

##### What the Code Looks Like (Conceptual)

```python
# chat.py — each request is self-contained
@app.post("/chat")
async def chat_endpoint(request: ChatRequest, user: UserContext = Depends(get_current_user)):
    # user.tenant_id comes from the JWT — no lookup needed
    # user's access token was obtained during OAuth2 login

    # Pass the user's token to Graph tools — NOT a shared secret
    result = await query_secure_score(
        tenant_id=user.tenant_id,
        user_access_token=user.access_token,  # scoped to this user's tenant
    )
    ...
```

```python
# graph_client.py — creates a client scoped to the requesting user
def create_graph_client_for_user(user_access_token: str):
    """Graph client authenticated as the requesting user, not the app."""
    credential = TokenCredential(user_access_token)  # user's own token
    return GraphServiceClient(credential, scopes=["https://graph.microsoft.com/.default"])
```

##### Session Isolation

The current in-memory `_sessions` dict is keyed by `session_id` only. For
multi-tenant, sessions must be keyed by `(tenant_id, user_id, session_id)` to
prevent one user's session from being accessed by another:

```python
# Session key includes tenant and user identity
session_key = f"{user.tenant_id}:{user.user_id}:{session_id}"
_sessions[session_key] = { ... }
```

This ensures that even if two users happen to generate the same `session_id`,
their sessions are isolated.

### Customer Onboarding Flow

```
1. Customer admin navigates to:
   https://login.microsoftonline.com/{customer-tenant}/adminconsent
     ?client_id=<PostureIQ-app-id>
     &redirect_uri=<PostureIQ-URL>/auth/callback

2. Admin reviews and grants the requested Graph permissions.

3. Customer users can now log in to PostureIQ and assess their own tenant.
```

### Security Considerations

- **Tenant isolation:** Each Graph call uses the authenticated user's
  delegated token — one tenant cannot access another tenant's data.
- **Least privilege:** Delegated permissions mean the agent can only see what
  the user themselves can see. No standing application-level access.
- **Admin consent:** Required once per customer tenant. No self-service user
  consent for security-sensitive Graph scopes.
- **Audit trail:** The existing `AuditLogger` already records `tenant_id` on
  every action, providing per-tenant audit visibility.

### Security Risk Exposure — Option A

| Risk | Severity | Description | Mitigation |
|------|----------|-------------|------------|
| **Cross-tenant token confusion** | **High** | A bug in issuer validation could let a token from Tenant A be accepted as Tenant B. In single-tenant mode the issuer is hardcoded, so this is impossible. Multi-tenant dynamic issuer validation widens this attack surface. | Validate that the token's `tid` claim matches the issuer URL in every request. Add integration tests that reject cross-tenant tokens. |
| **Shared infrastructure = shared blast radius** | **High** | A vulnerability in the agent (e.g., prompt injection, dependency CVE) exposes **all** customer tenants simultaneously, not just one. | WAF/DDoS protection on the Container App ingress. Content Safety filtering (already in place). Dependency scanning in CI. Incident response plan that covers multi-tenant impact. |
| **OBO token scope escalation** | **Medium** | The On-Behalf-Of flow exchanges the user's token for a Graph token. If the app registration requests overly broad scopes, a compromised agent could read more data than intended. | Request only the minimum delegated scopes needed (`SecurityEvents.Read.All`, `Policy.Read.All`, etc.). Never request `Directory.ReadWrite.All` or similar write scopes. Audit scope grants per tenant. |
| **Admin consent phishing** | **Medium** | An attacker could craft a malicious admin consent URL pointing to PostureIQ's app ID but with additional scopes, tricking an admin into granting excessive permissions. | Pin the permitted scopes in the app registration manifest (`requiredResourceAccess`). Use the `/adminconsent` endpoint with a fixed scope set. Educate customer admins on consent review. |
| **OBO credential for Graph** | **Low** | The OBO flow typically requires a `client_secret` or certificate. However, the current deployment already uses **OIDC Workload Identity Federation** for CI/CD and **User-Assigned Managed Identity** for runtime access to Azure services (OpenAI, Content Safety, Key Vault, ACR). If the managed identity can also be used for OBO, no secret is needed. If OBO requires a certificate/secret, it adds one credential to manage. | Use managed identity federated credential for OBO if supported. Otherwise, use certificate credentials stored in Key Vault with auto-rotation. |
| **Denial of service across tenants** | **Medium** | One tenant's heavy usage or a targeted attack could degrade service for all tenants on the shared instance. | Per-tenant rate limiting (to be implemented). Container Apps auto-scaling (already configured 0–5 replicas). Azure Monitor alerts on anomalous request patterns. |
| **In-memory session leakage** | **Low** | The current chat layer uses an in-memory `_sessions` dict. A bug could return one tenant's session to another tenant's user. | Key sessions by `(tenant_id, user_id, session_id)` tuple. Add a middleware guard that validates session ownership on every request. Move to Redis or Cosmos DB for durable, isolated session storage. |
| **Audit log co-mingling** | **Low** | All tenants write to the same App Insights instance. A misconfigured query could expose one tenant's audit events to another tenant's operator. | Tag every telemetry record with `tenant_id` (already done). Restrict audit read access via RBAC and tenant-scoped queries. Consider per-tenant Log Analytics workspaces for regulated customers. |

---

## Option B: Stamp-per-Tenant (Simpler, Less Scalable)

Deploy a **separate Container App instance** per customer tenant, each with
its own environment variables and single-tenant app registration.

### Architecture Changes

- Parameterize `provision-dev.sh` to accept a target tenant ID.
- Create a Bicep parameter file per tenant (or use a config map).
- Each instance has its own URL (e.g., `postureiq-contoso.azurecontainerapps.io`).

### Pros
- Minimal code changes — mostly infra/config.
- Strong tenant isolation by default (separate deployments).
- Can ship immediately.

### Cons
- **O(n) cost** — each tenant is a separate Container App with its own
  OpenAI, Content Safety, and App Insights resources.
- **O(n) maintenance** — patching, upgrades, and config changes must be
  rolled out to every instance.
- **Onboarding friction** — each new tenant requires a full provisioning run.
- Does not scale for the Project 479 campaign (potentially hundreds of tenants).

### Security Risk Exposure — Option B

| Risk | Severity | Description | Mitigation |
|------|----------|-------------|------------|
| **Secret sprawl** | **High** | Each stamp has its own `AZURE_CLIENT_SECRET`, Key Vault, and app registration. At 50+ tenants, the number of secrets to rotate and monitor grows linearly. A missed rotation or leaked secret compromises that tenant. | Automate secret rotation via Key Vault auto-rotate. Central inventory of all stamps with expiry tracking. Alert on secrets approaching expiration. |
| **Patch lag across stamps** | **High** | A critical CVE or security fix must be deployed to every stamp individually. If even one stamp is missed, that tenant remains vulnerable. This is exactly the "emergency patch" risk you flagged earlier. | Centralized CI/CD that deploys to all stamps in parallel. Automated drift detection that flags stamps running older image versions. |
| **Inconsistent security configuration** | **Medium** | Each stamp can drift in configuration — different Content Safety thresholds, different auth settings, different logging levels. One misconfigured stamp could have weaker guardrails. | Infrastructure-as-Code (Bicep) with no manual overrides. Policy-as-code validation in CI. Periodic compliance scans across all stamps. |
| **Per-stamp app registration = per-stamp attack surface** | **Medium** | Each tenant gets its own Entra ID app registration. If an attacker compromises one app reg's credentials, they get full access to that tenant's Graph data (application-level, not just delegated). | Use delegated permissions only (no application permissions). Certificate credentials instead of secrets. Conditional Access policies on app sign-ins. |
| **Blast radius per stamp is isolated (advantage)** | **Low** | A vulnerability in one stamp only affects one tenant. This is the primary security benefit of Option B. | N/A — this is an inherent advantage of stamp isolation. |
| **Operational visibility gaps** | **Medium** | With separate App Insights instances per stamp, cross-tenant threat patterns (e.g., coordinated attacks) are harder to detect. No single pane of glass for security monitoring. | Aggregate telemetry into a central Log Analytics workspace or Sentinel instance. Federated monitoring dashboard. |
| **Orphaned stamps** | **Low** | When a customer engagement ends, the stamp and its credentials may not be properly decommissioned, leaving standing access to that tenant's Graph data. | Tenant offboarding runbook. Automated expiry tagging on resource groups. Periodic audit of active stamps vs. active engagements. |

---

## Security Risk Comparison Summary

> **Note:** The current deployment already uses **OIDC Workload Identity
> Federation** (CI/CD) and **User-Assigned Managed Identity** (runtime).
> There are **zero stored secrets** in the production path — Azure
> services are accessed via `DefaultAzureCredential` / managed identity.
> The `client_secret` code path in `graph_client.py` exists only as a
> local development fallback.

| Dimension | Option A (Multi-Tenant) | Option B (Stamp-per-Tenant) |
|-----------|------------------------|----------------------------|
| **Blast radius** | All tenants at once | One tenant per stamp |
| **Secret/credential management** | 1 managed identity (zero secrets if MI supports OBO) | N managed identities (one per stamp) |
| **Credential exposure surface** | MI token cached in R replicas (short-lived, auto-rotated by Azure) | N MI tokens × R replicas each (also short-lived) |
| **Patch velocity** | Deploy once, all tenants updated | Must deploy to every stamp |
| **Tenant data isolation** | Logical (token-based) | Physical (separate infra) |
| **Configuration drift** | Not possible (single instance) | Risk grows with stamp count |
| **Regulatory compliance** | May need extra controls for data co-residency | Easier per-tenant compliance story |
| **Cross-tenant attack detection** | Centralized telemetry makes correlation easy | Requires log aggregation setup |
| **Admin consent risk** | One app reg, consent per tenant | Per-tenant app reg, per-tenant consent |

### Horizontal Scaling — Credential Exposure Clarification

> **Important:** The comparison above assumes horizontal auto-scaling, which
> is already configured (0–5 replicas in `container-app.bicep`).
>
> The current production deployment uses **Managed Identity** (not
> `client_secret`) for all Azure service access. Managed identity tokens
> are **short-lived** (~24h), **auto-rotated by Azure**, and **not stored
> on disk**. This significantly reduces the credential exposure risk
> compared to long-lived secrets.

**Option A** runs R replicas of the **same** Container App. Each replica
authenticates via the same User-Assigned Managed Identity. Azure issues
short-lived tokens to each replica on demand. A container escape or memory
dump on any replica could expose the current MI token, which grants access
to Azure resources for **all** tenants served by this instance.

**Option B** runs N stamps × R replicas each. Each stamp has its **own**
Managed Identity. A compromise of one stamp's MI token only affects that
one tenant.

| Scaling Factor | Option A | Option B |
|---------------|----------|----------|
| Replicas with credentials in memory | R (all share 1 MI, short-lived tokens) | N × R (N different MIs, short-lived tokens) |
| Tenants exposed per compromised replica | **All tenants** | **1 tenant** |
| Credential rotation | Automatic (Azure MI tokens ~24h) | Automatic (Azure MI tokens ~24h) |
| Credential to revoke after a breach | 1 MI (but impacts all tenants until re-issued) | 1 MI (impacts only that tenant) |

**Key difference from a static secret:** Unlike a `client_secret` that
remains valid until manually rotated, a compromised MI token expires
automatically. The attacker's window is limited to the token's remaining
lifetime (hours, not months).

#### Mitigations for Both Options

| Mitigation | Applies To | Status | Description |
|------------|-----------|--------|-------------|
| **Managed Identity (no secrets)** | A & B | **Already in place** | `DefaultAzureCredential` is used for OpenAI, Content Safety, Key Vault, ACR. No `client_secret` in production. |
| **OIDC Workload Identity (CI/CD)** | A & B | **Already in place** | GitHub Actions authenticates to Azure via OIDC federated credentials. Zero stored secrets in CI/CD. |
| **Key Vault for any remaining secrets** | A & B | **Already in place** | Key Vault is provisioned and wired to the Container App via managed identity. |
| **MI-based OBO for Graph** | A | **To implement** | If multi-tenant OBO is needed, use the managed identity's federated credential to perform OBO without a `client_secret`. Falls back to certificate credential if not supported. |
| **Short-lived MI/OBO tokens** | A & B | **Inherent** | MI tokens (~24h) and OBO tokens (~60–90 min) expire automatically. Compromised tokens have a limited blast window. |
| **Network isolation** | A & B | **To implement** | VNet-integrated Container Apps with private ingress reduce the container escape attack surface. |
| **Runtime threat detection** | A & B | **To implement** | Azure Defender for Containers can detect anomalous process behavior and credential access patterns at runtime. |

---

## Recommendation

**Option A (multi-tenant app)** is the right path for Project 479 at scale.

### Implementation Phases

| Phase | Scope | Effort |
|-------|-------|--------|
| **Phase 1** | Convert app reg to multi-tenant; update OAuth2 flow to use `organizations` endpoint; update issuer validation | ~1 day |
| **Phase 2** | Refactor `graph_client.py` to use OBO / user delegated tokens; thread `UserContext` through tool calls | ~2 days |
| **Phase 3** | Add admin consent endpoint (`/admin/consent`); build tenant onboarding flow | ~1 day |
| **Phase 4** | Update tests, CI/CD, and documentation | ~1 day |

### What Already Works

- `UserContext` already extracts `tenant_id` from the JWT `tid` claim.
- `JWKSKeyCache.get_signing_key()` already accepts `tenant_id` as a parameter.
- `AuditLogger` already records tenant context on every action.
- The chat endpoint already manages per-session state.

### Files to Modify

| File | Change |
|------|--------|
| `src/agent/config.py` | Add `multi_tenant_enabled` flag |
| `src/middleware/auth.py` | Use `organizations` authority; dynamic issuer validation |
| `src/tools/graph_client.py` | Accept user token; use OBO credential |
| `src/api/chat.py` | Thread `UserContext` / access token to tool calls |
| `src/api/app.py` | Add `/admin/consent` endpoint |
| `src/tools/*.py` | Accept `tenant_id` + `access_token` parameters |
| `scripts/provision-dev.sh` | Update app reg to multi-tenant |
| `tests/` | Update auth and tool tests for multi-tenant scenarios |

---

## Open Questions

1. **Tenant allowlist?** Should we restrict which tenants can use the agent
   (allowlist), or accept any Entra ID tenant that has granted admin consent?
2. **Rate limiting per tenant?** Prevent one tenant from consuming all agent
   capacity.
3. **Data residency:** Are there constraints on which Azure region the agent
   runs in relative to the customer tenant's data?
4. **Fabric telemetry:** The current `fabric_telemetry.py` tool assumes a
   single Fabric lakehouse. Multi-tenant would need per-tenant Fabric
   connections or a shared lakehouse with tenant partitioning.
