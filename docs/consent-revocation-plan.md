# Consent Revocation — Implementation Plan

> **Status:** Implemented
> **Date:** 2026-03-07
> **Author:** SecPostureIQ Engineering
> **Related:** [Multi-Tenant User Flow](multi-tenant-user-flow.md) · [Option A Implementation Plan](option-a-implementation-plan.md) · [Multi-Tenant Strategy](multi-tenant-strategy.md)

---

## Problem Statement

When `MULTI_TENANT_ENABLED=true`, a user from an external tenant (not the
front-end hosting tenant) is prompted for consent on first sign-in. Once
consent is granted, the user has no self-service way to revoke it from within
SecPostureIQ. They must navigate to Entra ID → My Apps → Permissions to
remove the grant, which is non-obvious and tenant-admin-dependent.

This plan adds a **user-facing consent revocation** feature so external-tenant
users can revoke their delegated permissions directly from the SecPostureIQ
UI.

---

## Background: How Consent Works Today

1. An external user opens SecPostureIQ and clicks **Sign In**.
2. Entra ID's `/organizations/oauth2/v2.0/authorize` endpoint detects that
   the user's home tenant has not yet consented to SecPostureIQ's app
   registration.
3. The user (or their tenant admin, depending on policy) is shown a consent
   prompt listing the requested delegated permissions.
4. After accepting, Entra ID records the consent grant on the tenant side.
5. The user receives a JWT and proceeds to use SecPostureIQ.

Consent revocation today requires the user to visit
`https://myapplications.microsoft.com` → select SecPostureIQ → revoke
permissions, or the tenant admin to go to Entra ID → Enterprise Applications
→ remove the service principal. Neither path is surfaced by SecPostureIQ.

---

## Proposed Solution

### Overview

Add a **`/auth/revoke-consent`** API endpoint and a corresponding **UI
element** (button in the user menu) that:

1. Calls the Microsoft Graph API to delete the user's OAuth2 permission
   grant for SecPostureIQ's service principal in their home tenant.
2. Invalidates the user's current session (clears tokens from the browser).
3. Confirms revocation to the user.

### Scope

- **User-level consent revocation only.** This feature revokes the
  individual user's own delegated permission grant. It does **not** revoke
  admin consent for the entire tenant — that remains a tenant-admin action
  in Entra ID.
- **External-tenant users only.** Users from the hosting tenant don't go
  through the consent flow, so the revocation button is hidden for them.

---

## Architecture

```
User clicks "Revoke Consent" in UI
        │
        ▼
POST /auth/revoke-consent
  Authorization: Bearer <id_token>
  X-Graph-Token: <access_token>
        │
        ▼
Backend validates token → extracts user_id, tenant_id
        │
        ▼
Graph API: GET /me/oauth2PermissionGrants
  → filter by clientId = SecPostureIQ app service principal
  → find the grant matching this user
        │
        ▼
Graph API: DELETE /oauth2PermissionGrants/{id}
  → removes the user's delegated permission grant
        │
        ▼
Return 200 { "status": "revoked" }
        │
        ▼
UI clears tokens → redirects to sign-in page
  with message: "Consent revoked successfully"
```

---

## Implementation Phases

### Phase 1 — API Endpoint (`/auth/revoke-consent`)

**Goal:** Backend endpoint to revoke the calling user's own consent grant.

**Effort:** ~1 day

#### Task 1.1 — Add `POST /auth/revoke-consent` to `app.py`

| Detail | Value |
|--------|-------|
| File | `src/api/app.py` |
| Method | `POST` |
| Auth | Requires valid Bearer token (`get_current_user` dependency) |
| Graph token | Requires `X-Graph-Token` header with `DelegatedPermissionGrant.ReadWrite.All` or `Directory.ReadWrite.All` scope |

**Request flow:**

1. Validate the user's `id_token` via `get_current_user`.
2. Extract `X-Graph-Token` from request headers.
3. Determine if the user is from an external tenant (compare `user.tenant_id`
   against `settings.azure_tenant_id`).
4. If the user is from the hosting tenant, return `400` — consent revocation
   is not applicable.
5. Call the consent revocation helper (Task 1.2).

**Endpoint signature:**

```python
@app.post("/auth/revoke-consent")
async def revoke_consent(
    request: Request,
    user: UserContext = Depends(get_current_user),
) -> dict[str, str]:
    """Revoke the current user's delegated consent for SecPostureIQ."""
```

**Response codes:**

| Code | Meaning |
|------|---------|
| `200` | Consent revoked successfully |
| `400` | User is from the hosting tenant (no external consent to revoke) |
| `404` | No consent grant found for this user |
| `403` | Graph token lacks required scope (includes `consent_url` for incremental consent) |
| `409` | Admin consent detected — returns structured actions (delete SP, disable SP, manual) |
| `502` | Graph API call failed |

#### Task 1.2 — Implement `revoke_user_consent()` helper in `auth.py`

| Detail | Value |
|--------|-------|
| File | `src/middleware/auth.py` |
| Function | `revoke_user_consent(graph_token: str, user_id: str, client_app_id: str) -> bool` |

**Logic:**

```python
async def revoke_user_consent(
    graph_token: str,
    user_id: str,
    client_app_id: str,
) -> bool:
    """Revoke the user's OAuth2 permission grant for the given app.

    Steps:
      1. GET /me/oauth2PermissionGrants?$filter=clientId eq '{sp_id}'
         — find the service principal's object ID in the user's tenant
      2. For each matching grant where principalId == user_id:
         DELETE /oauth2PermissionGrants/{grant_id}
      3. Return True if at least one grant was deleted.

    Graph permissions required (delegated):
      - DelegatedPermissionGrant.ReadWrite.All  (preferred, least privilege)
      - or Directory.ReadWrite.All              (broader fallback)
    """
```

**Key considerations:**

- The `clientId` in the `oauth2PermissionGrants` filter refers to the
  **service principal object ID** in the user's tenant, not the app
  registration's `client_id`. The helper must first resolve the service
  principal:
  ```
  GET /servicePrincipals?$filter=appId eq '{settings.oauth_client_id}'
  ```
- Only delete grants where `principalId` matches the current user's `oid`
  (to avoid revoking another user's grants or admin-level grants).
- Admin-consent grants have `consentType=AllPrincipals` — these must be
  **skipped** (only `consentType=Principal` grants should be deleted).

#### Task 1.3 — Add consent revocation scope to Graph scope configuration

| Detail | Value |
|--------|-------|
| File | `src/agent/config.py` |
| Change | Add `DelegatedPermissionGrant.ReadWrite.All` to the optional scope list |

This scope is only requested when the user initiates a consent revocation,
not on every login. It should be requested via **incremental consent** at the
point the user clicks "Revoke Consent":

```python
# In the revocaton flow, redirect the user to re-authorize with the
# additional scope, then proceed with the DELETE call.
incremental_scopes = ["DelegatedPermissionGrant.ReadWrite.All"]
```

Alternatively, if the tenant admin has already granted
`Directory.ReadWrite.All` via admin consent, no incremental consent is
needed.

#### Task 1.4 — Audit logging for consent revocation

| Detail | Value |
|--------|-------|
| File | `src/api/app.py` (endpoint) |
| Change | Log a structured audit event on successful revocation |

```python
logger.info(
    "auth.consent.revoked",
    user_id=user.user_id,
    tenant_id=user.tenant_id,
    email=user.email,
)
```

This event should also be emitted via `AuditLogger` for the immutable audit
trail in App Insights, tagged with `tenant_id` for per-tenant filtering.

---

### Phase 2 — UI Changes

**Goal:** Surface the consent revocation action in the SecPostureIQ chat UI.

**Effort:** ~0.5 day

#### Task 2.1 — Add "Revoke Consent" button to user menu in `index.html`

| Detail | Value |
|--------|-------|
| File | `src/static/index.html` |
| Where | User info section (header, alongside the Sign Out button) |
| Visibility | Only visible when the authenticated user's `tenant_id` differs from the hosting tenant ID |

**UI behavior:**

1. After sign-in, the SPA already stores the user's `tenant_id` (from the
   `/auth/me` response or decoded `id_token` claims).
2. If `user.tenant_id !== HOSTING_TENANT_ID`, show a "Revoke Consent"
   option in the user dropdown.
3. Clicking it shows a confirmation dialog:
   > **Revoke consent?**
   > This will remove SecPostureIQ's access to your tenant data. You will
   > be signed out. To use SecPostureIQ again, you'll need to re-consent.
   > [Cancel] [Revoke]
4. On confirm, call `POST /auth/revoke-consent` with both tokens.
5. On success, clear all stored tokens and redirect to the sign-in page
   with a banner: "Consent revoked. SecPostureIQ no longer has access to
   your tenant."

#### Task 2.2 — Expose hosting tenant ID to the SPA

| Detail | Value |
|--------|-------|
| File | `src/api/app.py` |
| Change | Add `hosting_tenant_id` to the `/auth/me` response (or a `/config` endpoint) |

The SPA needs to know the hosting tenant ID to determine whether the current
user is "external." Options:

- **Option A:** Add `hosting_tenant_id` to the `AuthMeResponse` model.
- **Option B:** Add a public `GET /config` endpoint that returns
  `{ hosting_tenant_id, multi_tenant_enabled }`.

Option B is preferred since it doesn't require authentication and allows the
UI to conditionally show the consent flow before sign-in.

---

### Phase 3 — Incremental Consent Flow

**Goal:** Handle the case where the user's current token doesn't include the
`DelegatedPermissionGrant.ReadWrite.All` scope needed for revocation.

**Effort:** ~0.5 day

#### Task 3.1 — Implement incremental consent redirect

| Detail | Value |
|--------|-------|
| File | `src/middleware/auth.py` |
| Change | Add a helper to construct an auth URL with additional scopes |

When the user clicks "Revoke Consent" but their current token lacks the
revocation scope:

1. The backend returns `403` with a machine-readable body:
   ```json
   {
     "error": "insufficient_scope",
     "required_scope": "DelegatedPermissionGrant.ReadWrite.All",
     "consent_url": "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?...&scope=...DelegatedPermissionGrant.ReadWrite.All..."
   }
   ```
2. The SPA redirects the user to the `consent_url`.
3. After consent, the callback returns a new token with the additional scope.
4. The SPA retries `POST /auth/revoke-consent` with the updated token.

#### Task 3.2 — SPA handling of incremental consent

| Detail | Value |
|--------|-------|
| File | `src/static/index.html` |
| Change | Handle the `insufficient_scope` response by redirecting to the consent URL |

---

### Phase 4 — Tests and Documentation

**Goal:** Validate the feature and document it for operators and users.

**Effort:** ~1 day

#### Task 4.1 — Unit tests

| Test | File |
|------|------|
| `test_revoke_consent_external_user` | `tests/unit/test_auth.py` |
| `test_revoke_consent_hosting_tenant_rejected` | `tests/unit/test_auth.py` |
| `test_revoke_consent_no_grant_found` | `tests/unit/test_auth.py` |
| `test_revoke_consent_graph_failure` | `tests/unit/test_auth.py` |
| `test_revoke_consent_audit_logged` | `tests/unit/test_auth.py` |

#### Task 4.2 — Integration test

| Test | File |
|------|------|
| `test_revoke_consent_e2e` | `tests/integration/test_consent_revocation.py` |

Uses a test tenant with a pre-consented user to verify the full flow:
sign in → revoke → verify grant is removed → verify re-consent is required.

#### Task 4.3 — Update multi-tenant user flow doc

| Detail | Value |
|--------|-------|
| File | `docs/multi-tenant-user-flow.md` |
| Change | Add a new section "Step 8 — Consent Revocation" documenting the user-facing flow |

#### Task 4.4 — Update setup guide

| Detail | Value |
|--------|-------|
| File | `docs/setup-guide.md` |
| Change | Document the `DelegatedPermissionGrant.ReadWrite.All` permission requirement for consent revocation |

---

## Graph API Reference

### List user's permission grants

```http
GET https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants
    ?$filter=clientId eq '{service_principal_id}'
Authorization: Bearer <graph_token>
```

### Resolve service principal from app ID

```http
GET https://graph.microsoft.com/v1.0/servicePrincipals
    ?$filter=appId eq '{app_client_id}'
Authorization: Bearer <graph_token>
```

### Delete a permission grant

```http
DELETE https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{grant_id}
Authorization: Bearer <graph_token>
```

### Required Graph permissions

| Permission | Type | Purpose |
|-----------|------|---------|
| `DelegatedPermissionGrant.ReadWrite.All` | Delegated | Read and delete the user's own consent grants |
| `Application.ReadWrite.All` | Delegated | Delete or disable the service principal (admin-consent tenants) |

---

## Admin Consent Handling

SecPostureIQ's permissions (e.g., `SecurityEvents.Read.All`) require admin
consent, so grants are stored as `consentType=AllPrincipals`. These are
organization-wide and cannot be deleted per-user without affecting all users.

When admin consent is detected, the endpoint returns `409 Conflict` with
three structured actions:

| Action | Graph API Call | Scope Required | Effect |
|--------|---------------|----------------|--------|
| `delete_sp` | `DELETE /servicePrincipals/{id}` | `Application.ReadWrite.All` | Fully removes the app from the tenant |
| `disable_sp` | `PATCH /servicePrincipals/{id}` `{accountEnabled: false}` | `Application.ReadWrite.All` | Blocks sign-in without deleting (reversible) |
| `enable_sp` | `PATCH /servicePrincipals/{id}` `{accountEnabled: true}` | `Application.ReadWrite.All` | Re-enables sign-in after disable (shown inline after disable) |
| `manual` | N/A (opens browser) | None | User navigates to myapplications.microsoft.com |

The SPA renders these as a modal with styled buttons. Destructive actions
(`delete_sp`) are highlighted with a red border.

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| User revokes another user's consent | The endpoint only deletes grants where `principalId` matches the authenticated user's `oid`. Admin-consent grants (`consentType=AllPrincipals`) are never touched. |
| CSRF on revocation endpoint | `POST` method + Bearer token required. The SPA must include the confirmation dialog to prevent accidental clicks. |
| Token replay after revocation | After revoking, the SPA clears all stored tokens. Existing JWTs will expire naturally (typically within 1 hour). The revocation removes future consent, not existing tokens. |
| Audit trail | Every revocation is logged with `user_id`, `tenant_id`, and timestamp to App Insights. |
| Incremental consent phishing | The consent URL is constructed server-side with the exact required scope. The SPA does not accept arbitrary redirect URLs. |

---

## Failure Scenarios

| Scenario | Behavior |
|----------|----------|
| User's Graph token lacks the revocation scope | Return `403` with `consent_url` for incremental consent |
| No consent grant found (user already revoked or admin-consent only) | Return `409` with three options (delete SP, disable SP, manual) for admin-consent; `404` for no grants at all |
| Graph API is unreachable | Return `502`; UI shows "Unable to revoke consent at this time. Try again or revoke manually from myapplications.microsoft.com." |
| User is from the hosting tenant | Return `400`; button is hidden in UI, but backend enforces this as defense-in-depth |

---

## Dependency Graph

```
Phase 1 (API)  ──► Phase 2 (UI)  ──► Phase 4 (Tests/Docs)
      │                                      ▲
      └────────► Phase 3 (Incr. Consent) ────┘
```

- Phase 1 has no prerequisites beyond the existing multi-tenant auth
  (Option A Phase 1).
- Phase 2 depends on Phase 1 (needs the endpoint).
- Phase 3 can be worked in parallel with Phase 2.
- Phase 4 depends on all prior phases.

---

## Rollback Plan

The consent revocation feature is entirely additive:

- **Endpoint:** New route — removing it has no side effects.
- **UI:** Button hidden by default for hosting-tenant users — removing the
  JS has no impact on existing functionality.
- **Config:** No new required env vars; `DelegatedPermissionGrant.ReadWrite.All`
  is only requested during incremental consent, not at startup.
- **Data:** No new database tables or persistent state.

To roll back: revert the commits and redeploy. No data migration needed.
