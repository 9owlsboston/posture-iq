# Multi-Tenant User Flow — Dual-Tenant Walkthrough

> **Status:** Reference — accompanies [Option A Implementation Plan](option-a-implementation-plan.md)
> **Date:** 2026-02-26
> **Author:** PostureIQ Engineering
> **Related:** [Multi-Tenant Strategy](multi-tenant-strategy.md) · [Scaling Strategy](scaling-strategy.md)

---

## Overview

This document walks through the complete user experience when **two ME5
tenants** (Tenant X and Tenant Y) use the same PostureIQ agent instance
under Option A (multi-tenant app registration).

---

## Step 0 — One-Time Operator Setup

You deploy PostureIQ once with the following configuration:

| Setting | Value |
|---------|-------|
| `MULTI_TENANT_ENABLED` | `true` |
| `ALLOWED_TENANTS` | `tenantX-guid,tenantY-guid` (or empty to accept all consented tenants) |
| App Registration `signInAudience` | `AzureADMultipleOrgs` |

There is **one** Container App, **one** OpenAI deployment, **one** App
Insights instance. No per-tenant infrastructure.

---

## Step 1 — Admin Consent (Once Per Tenant)

### Tenant X

Tenant X's Global Admin receives a link from you:

```
https://postureiq.azurecontainerapps.io/admin/consent?tenant_id=tenantX-guid
```

They click it, get redirected to Entra ID's consent screen, and see:

> **PostureIQ** is requesting permission to:
> - Read security events (`SecurityEvents.Read.All`)
> - Read security actions (`SecurityActions.Read.All`)
> - Read policies (`Policy.Read.All`)
> - Read reports (`Reports.Read.All`)
> - Read information protection config (`InformationProtection.Read.All`)
> - Read directory role assignments (`RoleManagement.Read.Directory`)
> - Read risky user data (`IdentityRiskyUser.Read.All`)
> - Read access reviews (`AccessReview.Read.All`)

> **Note:** Azure CLI (`az ad app permission add`) may fail to provision some
> of these scopes depending on the tenant's license tier or the operator's
> Entra ID role. The `setup-permissions.sh` script handles partial failures
> gracefully — it attempts every permission independently, prints a summary
> of granted vs. failed scopes, and continues. Tools that depend on a
> missing scope will fall back to mock data at runtime.

The admin clicks **Accept**. Entra ID records that Tenant X has granted
these **delegated** permissions to PostureIQ's app registration.

### Tenant Y

Tenant Y's Global Admin does the same thing independently with their own
tenant ID. Neither admin sees or knows about the other.

### What This Means

- No credentials are exchanged or stored by PostureIQ during consent.
- Consent is recorded by Entra ID on the tenant side, not by PostureIQ.
- Consent can be revoked at any time by the tenant admin from Entra ID →
  Enterprise Applications.

---

## Step 2 — User Login

### Alice (Tenant X)

Alice, a security analyst in Tenant X, opens
`https://postureiq.azurecontainerapps.io` and clicks **Sign In**.

The app redirects her to:

```
https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize
  ?client_id=<PostureIQ-app-id>
  &scope=SecurityEvents.Read.All Policy.Read.All ...
  &redirect_uri=https://postureiq.azurecontainerapps.io/auth/callback
```

Note the `/organizations/` path — this is what `auth.py` constructs when
`multi_tenant_enabled=true`. It means "let any Entra ID tenant sign in."

Alice logs in with `alice@tenantX.onmicrosoft.com`. Entra ID issues a JWT:

```json
{
  "aud": "<PostureIQ-app-id>",
  "iss": "https://login.microsoftonline.com/tenantX-guid/v2.0",
  "tid": "tenantX-guid",
  "oid": "alice-object-id",
  "preferred_username": "alice@tenantX.onmicrosoft.com",
  "scp": "SecurityEvents.Read.All Policy.Read.All ..."
}
```

### Bob (Tenant Y)

Bob does the same. His token has `tid: "tenantY-guid"` and
`oid: "bob-object-id"`.

Both are redirected back to the PostureIQ UI with their respective tokens
stored in the browser session.

---

## Step 3 — Token Validation (Per Request)

Alice sends her first chat message: *"Assess this tenant's security posture."*

The browser sends:

```
POST /chat
Authorization: Bearer <alice-jwt-token>
Body: { "message": "Assess this tenant's security posture" }
```

The `validate_token()` function in `auth.py` performs:

1. **Pre-decode** (no signature check) → extracts `tid = tenantX-guid`
2. **Allowlist check** → if `ALLOWED_TENANTS` is set, confirms
   `tenantX-guid` is in the list
3. **JWKS fetch** → downloads signing keys from
   `https://login.microsoftonline.com/tenantX-guid/discovery/v2.0/keys`
   (the `JWKSKeyCache` already handles per-tenant keys)
4. **Signature verify** → confirms the token was signed by Tenant X's
   Entra ID
5. **Issuer check** → confirms issuer matches
   `https://login.microsoftonline.com/tenantX-guid/v2.0`
6. **Audience check** → confirms `aud` matches PostureIQ's `client_id`

Result: a `UserContext` object:

```python
UserContext(
    user_id="alice-object-id",
    email="alice@tenantX.onmicrosoft.com",
    tenant_id="tenantX-guid",
    access_token="<alice-jwt-token>",   # carried for Graph calls
    scopes=["SecurityEvents.Read.All", "Policy.Read.All", ...],
)
```

**Simultaneously**, Bob's request goes through the same flow but produces a
`UserContext` with `tenant_id="tenantY-guid"` and his own token.

---

## Step 4 — Session Creation

Alice's request creates a session keyed as:

```
tenantX-guid:alice-object-id:sess-abc123
```

Bob's session is keyed as:

```
tenantY-guid:bob-object-id:sess-def456
```

Even if both happened to generate the same `session_id`, the composite key
prevents any overlap. These sessions may land on **different replicas** (or
the same one — doesn't matter, because state is per-request).

---

## Step 5 — Tool Execution

Alice's "full assessment" triggers 4 tools in sequence. Here is what happens
for `query_secure_score`:

### Alice's tool call (Tenant X)

```
Alice's request
  → handle_chat(user_context=Alice)
    → _run_tool("query_secure_score", user_context=Alice)
      → create_graph_client_for_user(
            user_access_token=Alice's token,
            tenant_id="tenantX-guid"
        )
      → OBO exchange: PostureIQ exchanges Alice's token
        for a Graph-scoped token via Entra ID
      → GET https://graph.microsoft.com/v1.0/security/secureScores
        Authorization: Bearer <alice-graph-token>
      → Graph returns Tenant X's Secure Score data
```

### Bob's tool call (Tenant Y) — at the same time

```
Bob's request
  → handle_chat(user_context=Bob)
    → _run_tool("query_secure_score", user_context=Bob)
      → create_graph_client_for_user(
            user_access_token=Bob's token,
            tenant_id="tenantY-guid"
        )
      → OBO exchange with Bob's token
      → GET https://graph.microsoft.com/v1.0/security/secureScores
        Authorization: Bearer <bob-graph-token>
      → Graph returns Tenant Y's Secure Score data
```

### Why this is safe

The PostureIQ agent **never decides** which tenant's data to fetch. Graph API
automatically returns data scoped to whichever token is presented:

- Alice's token can **only** read Tenant X's data.
- Bob's token can **only** read Tenant Y's data.
- This is enforced by **Entra ID**, not by PostureIQ.

The same pattern repeats for `assess_defender_coverage`,
`check_purview_policies`, and `get_entra_config` — each receives the
requesting user's token and calls Graph with it.

---

## Step 6 — LLM Processing

Both sets of assessment results get sent to Azure OpenAI (gpt-4o):

| Request | Input Data | Output |
|---------|-----------|--------|
| Alice's | Tenant X's Secure Score, Defender coverage, Purview policies, Entra config | Alice's assessment report |
| Bob's | Tenant Y's Secure Score, Defender coverage, Purview policies, Entra config | Bob's assessment report |

The LLM calls are independent — they share the same OpenAI deployment (and
the same TPM quota, which is why the [scaling strategy](scaling-strategy.md)
flags this as the first bottleneck). But the LLM has **no memory between
requests** — it only sees the data passed in that specific call.

---

## Step 7 — Response and Audit

### Alice receives

> *"Tenant X's Secure Score is 62/100. Key gaps: MFA not enforced for
> admins, Defender for Endpoint not fully deployed..."*

### Bob receives

> *"Tenant Y's Secure Score is 78/100. Key gaps: DLP policies not
> configured for sensitive data types..."*

### Audit trail

Both interactions are recorded in the **same** App Insights instance, but
tagged with their respective `tenant_id`:

```json
// Alice's audit entry
{
  "tenant_id": "tenantX-guid",
  "user_id": "alice-object-id",
  "tool": "query_secure_score",
  "timestamp": "2026-02-26T14:30:00Z"
}

// Bob's audit entry
{
  "tenant_id": "tenantY-guid",
  "user_id": "bob-object-id",
  "tool": "query_secure_score",
  "timestamp": "2026-02-26T14:30:02Z"
}
```

Operators can filter audit logs by `tenant_id` to get per-tenant views.

---

## Failure Scenarios and Protections

| Scenario | Protection |
|----------|-----------|
| Alice's token used to read Tenant Y's data | **Impossible.** Graph API rejects it — the token's `tid` doesn't match Tenant Y. |
| Bob sees Alice's session history | **Prevented.** Session keys include `tenant_id:user_id:session_id`. |
| A bug in PostureIQ swaps their tokens | **Contained per-request.** Tokens live on the request object (`UserContext`), not in shared state. Each async request handler has its own scope. |
| Bob's heavy usage slows Alice down | **Possible today** (shared OpenAI quota). Mitigated in Phase 2 of the [scaling plan](scaling-strategy.md) with APIM per-tenant rate limiting. |
| Tenant X revokes consent | Alice can no longer sign in. Existing tokens expire naturally (within hours). No action needed by PostureIQ. |
| Tenant X admin grants consent but a regular user tries to sign in without the required licenses | Entra ID blocks the sign-in or Graph returns 403. PostureIQ surfaces the error to the user. |

---

## Visual Timeline

```
Time ──►

TENANT X (Alice)                         TENANT Y (Bob)
─────────────────                        ─────────────────
Admin grants consent                     Admin grants consent
        │                                        │
Alice opens PostureIQ                    Bob opens PostureIQ
Alice signs in (Entra ID, Tenant X)      Bob signs in (Entra ID, Tenant Y)
        │                                        │
        ├── POST /chat ──────────────────────────────────────┐
        │   Bearer: alice-token                              │
        │                                    POST /chat ─────┤
        │                                    Bearer: bob-token│
        │                                                    │
     ┌──▼──────────── PostureIQ Agent ───────────▼──┐        │
     │  validate(alice-token) → tid=X               │        │
     │  validate(bob-token)   → tid=Y               │        │
     │                                              │        │
     │  Graph(alice-token) → Tenant X scores        │        │
     │  Graph(bob-token)   → Tenant Y scores        │        │
     │                                              │        │
     │  OpenAI(X data) → Alice's assessment         │        │
     │  OpenAI(Y data) → Bob's assessment           │        │
     └──┬───────────────────────────────────┬───────┘        │
        │                                   │                │
Alice sees Tenant X report          Bob sees Tenant Y report
```

---

## Key Principle

> **The user's JWT token IS the credential.** PostureIQ never selects,
> stores, or manages per-tenant secrets. It passes through whatever token
> the user brought. Graph API enforces tenant boundary. Entra ID enforces
> identity. PostureIQ just orchestrates.
