# Option A Implementation Plan — Multi-Tenant App Registration

> **Status:** Proposal — pending review
> **Date:** 2026-02-26
> **Author:** PostureIQ Engineering
> **Related:** [Multi-Tenant Strategy](multi-tenant-strategy.md) · [Scaling Strategy](scaling-strategy.md)
> **Effort estimate:** ~5 developer-days across 4 phases

---

## Table of Contents

1. [Phase 1 — Entra ID App Registration + Auth Layer](#phase-1--entra-id-app-registration--auth-layer)
2. [Phase 2 — Graph Client + Tool Plumbing](#phase-2--graph-client--tool-plumbing)
3. [Phase 3 — Tenant Onboarding + Admin Consent](#phase-3--tenant-onboarding--admin-consent)
4. [Phase 4 — Tests, CI/CD, and Documentation](#phase-4--tests-cicd-and-documentation)
5. [Dependency Graph](#dependency-graph)
6. [Rollback Plan](#rollback-plan)

---

## Phase 1 — Entra ID App Registration + Auth Layer

**Goal:** Accept JWT tokens from any Entra ID tenant while preserving
existing single-tenant functionality behind a feature flag.

**Effort:** ~1 day

### Task 1.1 — Add `multi_tenant_enabled` feature flag to config

| Detail | Value |
|--------|-------|
| File | `src/agent/config.py` |
| Change | Add `multi_tenant_enabled: bool = False` field to `Settings` |
| Why | Allows gradual rollout; existing deployments stay single-tenant until the flag is set |
| Acceptance | `settings.multi_tenant_enabled` returns `False` by default and `True` when env var `MULTI_TENANT_ENABLED=true` |

```python
# src/agent/config.py — add under App Settings section
multi_tenant_enabled: bool = False
```

### Task 1.2 — Add tenant allowlist to config

| Detail | Value |
|--------|-------|
| File | `src/agent/config.py` |
| Change | Add `allowed_tenants: str = ""` field (comma-separated tenant IDs, empty = accept all consented tenants) |
| Why | Security control — restrict which tenants can authenticate even when multi-tenant is enabled |
| Acceptance | `settings.allowed_tenant_list` returns `list[str]`; empty list means unrestricted |

```python
# src/agent/config.py
allowed_tenants: str = ""

@property
def allowed_tenant_list(self) -> list[str]:
    """Parse comma-separated tenant allowlist."""
    return [t.strip() for t in self.allowed_tenants.split(",") if t.strip()]
```

### Task 1.3 — Update OAuth2 endpoints to use `organizations` authority

| Detail | Value |
|--------|-------|
| File | `src/middleware/auth.py` |
| Lines | ~134–135 (OAuth2AuthorizationCodeBearer instantiation) |
| Change | When `multi_tenant_enabled`, use `/organizations/` instead of `/{tenant_id}/` in `authorizationUrl` and `tokenUrl` |
| Why | The `organizations` endpoint accepts login from any Entra ID tenant |
| Risk | Existing single-tenant OAuth2 flow must remain unchanged when flag is off |

**Current code:**
```python
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{ENTRA_AUTHORITY}/{settings.azure_tenant_id}/oauth2/v2.0/authorize",
    tokenUrl=f"{ENTRA_AUTHORITY}/{settings.azure_tenant_id}/oauth2/v2.0/token",
    auto_error=False,
)
```

**Proposed code:**
```python
_authority_segment = "organizations" if settings.multi_tenant_enabled else settings.azure_tenant_id

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{ENTRA_AUTHORITY}/{_authority_segment}/oauth2/v2.0/authorize",
    tokenUrl=f"{ENTRA_AUTHORITY}/{_authority_segment}/oauth2/v2.0/token",
    auto_error=False,
)
```

### Task 1.4 — Update `validate_token()` for dynamic issuer validation

| Detail | Value |
|--------|-------|
| File | `src/middleware/auth.py` |
| Function | `validate_token()` (~line 143) |
| Change | When `multi_tenant_enabled`: (1) decode token once without verification to extract `tid`, (2) validate issuer matches `tid`, (3) check `tid` against allowlist |
| Why | Currently validates issuer against hardcoded `settings.azure_tenant_id`; must accept any tenant's issuer |
| Risk | **Cross-tenant token confusion** — highest security risk in Option A. Requires careful implementation. |

**Proposed logic (pseudo-code):**
```python
async def validate_token(token: str) -> UserContext:
    client_id = settings.azure_client_id

    if settings.multi_tenant_enabled:
        # Step 1: Pre-decode to extract tenant ID from token claims
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
        token_tid = unverified_claims.get("tid", "")

        if not token_tid:
            raise HTTPException(401, "Token missing tid claim")

        # Step 2: Check tenant allowlist (if configured)
        if settings.allowed_tenant_list and token_tid not in settings.allowed_tenant_list:
            raise HTTPException(403, "Tenant not authorized")

        tenant_id = token_tid
    else:
        tenant_id = settings.azure_tenant_id

    # ... rest of validation uses tenant_id for JWKS + issuer check
    valid_issuers = [
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        f"https://sts.windows.net/{tenant_id}/",
    ]
    signing_key = await _jwks_cache.get_signing_key(kid, tenant_id)
    # ... jwt.decode(... issuer=valid_issuers ...)
```

### Task 1.5 — Update `build_auth_url()` and `exchange_code_for_tokens()`

| Detail | Value |
|--------|-------|
| File | `src/middleware/auth.py` |
| Functions | `build_auth_url()`, `exchange_code_for_tokens()` |
| Change | When `multi_tenant_enabled`, use `/organizations/` in the token endpoint URLs |
| Why | These functions construct OAuth2 flow URLs; must match the authority used by `oauth2_scheme` |

### Task 1.6 — Extend `UserContext` with `access_token` field

| Detail | Value |
|--------|-------|
| File | `src/middleware/auth.py` |
| Dataclass | `UserContext` |
| Change | Add `access_token: str = ""` field to carry the user's bearer token through the request lifecycle |
| Why | Tools need the user's token to call Graph API in OBO / delegated mode |
| Note | The token is already validated at this point; storing it in `UserContext` avoids re-parsing |

```python
@dataclass
class UserContext:
    user_id: str
    email: str = ""
    name: str = ""
    tenant_id: str = ""
    access_token: str = ""  # ← NEW: carry the bearer token for Graph OBO
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    raw_claims: dict[str, Any] = field(default_factory=dict)
```

---

## Phase 2 — Graph Client + Tool Plumbing

**Goal:** All Graph-calling tools use the authenticated user's delegated
token instead of a shared app credential.

**Effort:** ~2 days

### Task 2.1 — Create `create_graph_client_for_user()` in graph_client.py

| Detail | Value |
|--------|-------|
| File | `src/tools/graph_client.py` |
| Change | Add a new function that creates a `GraphServiceClient` using the user's access token (OBO or direct delegation) |
| Why | Multi-tenant Graph calls must use the requesting user's token, not the app's credential |
| Fallback | If the user has no token (demo mode), fall back to existing `create_graph_client()` |

```python
def create_graph_client_for_user(
    user_access_token: str,
    tenant_id: str = "",
    tool_name: str = "unknown",
) -> "GraphServiceClient | None":
    """Create a Graph client authenticated as the requesting user.

    Uses On-Behalf-Of (OBO) flow: exchanges the user's access token
    for a Graph-scoped token using the app's managed identity or
    client certificate.
    """
    if not user_access_token:
        logger.info(f"tool.{tool_name}.graph_client.no_user_token",
                     reason="No user token — falling back to app credential")
        return create_graph_client(tool_name=tool_name)

    try:
        from azure.identity import OnBehalfOfCredential
        from msgraph import GraphServiceClient

        credential = OnBehalfOfCredential(
            tenant_id=tenant_id or settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            # Prefer managed-identity-backed OBO; fall back to client secret
            client_secret=settings.azure_client_secret or None,
            user_assertion=user_access_token,
        )
        return GraphServiceClient(
            credential,
            scopes=["https://graph.microsoft.com/.default"],
        )
    except Exception as e:
        logger.error(f"tool.{tool_name}.graph_client_for_user.error", error=str(e))
        # Fall back to app-level client for resilience
        return create_graph_client(tool_name=tool_name)
```

### Task 2.2 — Add `user_context` parameter to Graph-calling tools

Each Graph-calling tool needs an optional `user_context` parameter. When
provided, it uses `create_graph_client_for_user()`. When `None`, it falls back
to the existing behaviour (demo / single-tenant mode).

| Tool Function | File | Current Signature | New Parameter |
|--------------|------|-------------------|---------------|
| `query_secure_score()` | `src/tools/secure_score.py` | `(tenant_id: str = "")` | `(tenant_id: str = "", user_context: UserContext \| None = None)` |
| `assess_defender_coverage()` | `src/tools/defender_coverage.py` | `()` | `(user_context: UserContext \| None = None)` |
| `get_entra_config()` | `src/tools/entra_config.py` | `()` | `(user_context: UserContext \| None = None)` |
| `check_purview_policies()` | `src/tools/purview_policies.py` | `()` | `(user_context: UserContext \| None = None)` |

**Pattern for each tool:**
```python
async def query_secure_score(
    tenant_id: str = "",
    user_context: UserContext | None = None,
) -> dict[str, Any]:
    if user_context and user_context.access_token:
        client = create_graph_client_for_user(
            user_access_token=user_context.access_token,
            tenant_id=user_context.tenant_id,
            tool_name="secure_score",
        )
    else:
        client = create_graph_client(tool_name="secure_score")
    # ... rest of tool logic unchanged
```

### Task 2.3 — Update non-Graph tools for tenant awareness

These tools don't call Graph but may need `tenant_id` for audit/telemetry:

| Tool Function | File | Change |
|--------------|------|--------|
| `generate_remediation_plan()` | `src/tools/remediation_plan.py` | Add `tenant_id: str = ""` parameter; include in audit context |
| `create_adoption_scorecard()` | `src/tools/adoption_scorecard.py` | Add `tenant_id: str = ""` parameter; include in output metadata |
| `get_project479_playbook()` | `src/tools/foundry_playbook.py` | No change needed (tenant-agnostic playbook content) |
| `push_snapshot()` | `src/tools/fabric_telemetry.py` | Already accepts `tenant_id` — no change needed |

### Task 2.4 — Thread `UserContext` through `_run_tool()` in chat.py

| Detail | Value |
|--------|-------|
| File | `src/api/chat.py` |
| Function | `_run_tool()` (~line 48) |
| Change | Add `user_context: UserContext | None = None` parameter; pass it to each tool call |

```python
async def _run_tool(
    name: str,
    args: dict[str, Any] | None = None,
    user_context: UserContext | None = None,
) -> dict[str, Any]:
    args = args or {}

    if name == "query_secure_score":
        from src.tools.secure_score import query_secure_score
        return await query_secure_score(
            tenant_id=args.get("tenant_id", ""),
            user_context=user_context,
        )

    if name == "assess_defender_coverage":
        from src.tools.defender_coverage import assess_defender_coverage
        return await assess_defender_coverage(user_context=user_context)

    # ... same pattern for all other tools
```

### Task 2.5 — Thread `UserContext` through `handle_chat()` in chat.py

| Detail | Value |
|--------|-------|
| File | `src/api/chat.py` |
| Function | `handle_chat()` |
| Change | Accept `user_context` parameter; pass to `_run_tool()` calls |

### Task 2.6 — Update session key to include tenant and user

| Detail | Value |
|--------|-------|
| File | `src/api/chat.py` |
| Change | Key `_sessions` dict by `(tenant_id, user_id, session_id)` instead of `session_id` alone |
| Why | Prevents session cross-contamination between tenants / users |

**Current:**
```python
session = _sessions.get(session_id, {"messages": []})
```

**Proposed:**
```python
if user_context:
    session_key = f"{user_context.tenant_id}:{user_context.user_id}:{session_id}"
else:
    session_key = session_id  # demo mode fallback
session = _sessions.get(session_key, {"messages": []})
```

### Task 2.7 — Update Copilot SDK tool adapters in main.py

| Detail | Value |
|--------|-------|
| File | `src/agent/main.py` |
| Functions | `_handle_secure_score()`, `_handle_defender_coverage()`, `_handle_purview_policies()`, `_handle_entra_config()`, `_handle_remediation_plan()`, `_handle_adoption_scorecard()` |
| Change | Extract `user_context` from invocation arguments (Copilot SDK passes it as serialized JSON); pass to tool functions |
| Note | This depends on how the Copilot SDK exposes the calling user's context. May need a custom middleware or session-level injection. |

### Task 2.8 — Update `/chat` endpoint in app.py to pass UserContext

| Detail | Value |
|--------|-------|
| File | `src/api/app.py` |
| Change | The `/chat` route handler should inject the authenticated `UserContext` (from `get_current_user` dependency) and pass it to `handle_chat()` |

---

## Phase 3 — Tenant Onboarding + Admin Consent

**Goal:** Provide a self-service admin consent flow so customer tenant admins
can authorize PostureIQ with one click.

**Effort:** ~1 day

### Task 3.1 — Switch app registration to multi-tenant

| Detail | Value |
|--------|-------|
| File | `scripts/provision-dev.sh` (line 181) |
| Change | Change `--sign-in-audience "AzureADMyOrg"` to `--sign-in-audience "AzureADMultipleOrgs"` |
| Also | `scripts/setup-permissions.sh` (line 31) — same change |
| Why | Required for Entra ID to issue tokens for users from any tenant |

```bash
# Before
--sign-in-audience "AzureADMyOrg" \
# After
--sign-in-audience "AzureADMultipleOrgs" \
```

### Task 3.2 — Add `/admin/consent` redirect endpoint

| Detail | Value |
|--------|-------|
| File | `src/api/app.py` |
| Change | Add `GET /admin/consent` that redirects to the Entra ID admin consent URL |
| Why | Customer admins navigate here to grant PostureIQ permissions to their tenant |

```python
@app.get("/admin/consent")
async def admin_consent_redirect(tenant_id: str = "organizations"):
    """Redirect a customer admin to the Entra ID admin consent flow."""
    params = urlencode({
        "client_id": settings.azure_client_id,
        "redirect_uri": f"{settings.app_base_url}/admin/consent/callback",
        "scope": settings.graph_scopes.replace(",", " "),
        "response_type": "code",
    })
    consent_url = (
        f"{ENTRA_AUTHORITY}/{tenant_id}/v2.0/adminconsent?{params}"
    )
    return RedirectResponse(consent_url)
```

### Task 3.3 — Add `/admin/consent/callback` handler

| Detail | Value |
|--------|-------|
| File | `src/api/app.py` |
| Change | Add `GET /admin/consent/callback` to handle the redirect after admin consent |
| Behaviour | Log the consenting tenant ID; show a success page; record in audit log |

### Task 3.4 — Add `app_base_url` setting to config

| Detail | Value |
|--------|-------|
| File | `src/agent/config.py` |
| Change | Add `app_base_url: str = "http://localhost:8000"` |
| Why | Used to construct the `redirect_uri` for the admin consent callback |

### Task 3.5 — Document tenant onboarding runbook

| Detail | Value |
|--------|-------|
| File | `docs/tenant-onboarding-runbook.md` (new file) |
| Contents | Step-by-step instructions for customer admins: consent URL, required permissions, verification checklist |

---

## Phase 4 — Tests, CI/CD, and Documentation

**Goal:** Full test coverage for multi-tenant paths; CI/CD pipeline validates
multi-tenant configuration.

**Effort:** ~1 day

### Task 4.1 — Unit tests: multi-tenant token validation

| Detail | Value |
|--------|-------|
| File | `tests/unit/test_auth.py` |
| New tests | |
| | `test_multi_tenant_accepts_token_from_allowed_tenant` |
| | `test_multi_tenant_rejects_token_from_disallowed_tenant` |
| | `test_multi_tenant_rejects_token_without_tid_claim` |
| | `test_multi_tenant_validates_issuer_matches_tid` |
| | `test_multi_tenant_cross_tenant_token_rejected` — critical: craft a token with `tid=A` but issuer from `tid=B` |
| | `test_single_tenant_mode_unchanged_when_flag_off` |
| | `test_organizations_authority_used_when_multi_tenant` |

### Task 4.2 — Unit tests: Graph client OBO flow

| Detail | Value |
|--------|-------|
| File | `tests/unit/test_secure_score.py` (and other tool test files) |
| New tests | |
| | `test_tool_uses_user_token_when_user_context_provided` |
| | `test_tool_falls_back_to_app_credential_when_no_user_context` |
| | `test_tool_falls_back_to_mock_when_obo_fails` |

### Task 4.3 — Unit tests: session isolation

| Detail | Value |
|--------|-------|
| File | `tests/unit/test_chat.py` |
| New tests | |
| | `test_session_key_includes_tenant_and_user` |
| | `test_sessions_isolated_across_tenants` — create sessions from two different tenant contexts, verify no cross-access |
| | `test_demo_mode_session_key_unchanged` |

### Task 4.4 — Unit tests: admin consent endpoint

| Detail | Value |
|--------|-------|
| File | `tests/unit/test_auth.py` or new `tests/unit/test_admin_consent.py` |
| New tests | |
| | `test_admin_consent_redirects_to_entra` |
| | `test_admin_consent_callback_logs_tenant` |
| | `test_admin_consent_callback_rejects_error_response` |

### Task 4.5 — Integration test: multi-tenant smoke test

| Detail | Value |
|--------|-------|
| File | `tests/integration/test_e2e_smoke.py` |
| New test | `test_multi_tenant_e2e_two_tenants` — mock tokens from two tenants, verify each gets its own Graph data |

### Task 4.6 — Update CI/CD: add `MULTI_TENANT_ENABLED` env var

| Detail | Value |
|--------|-------|
| File | `infra/modules/container-app.bicep` |
| Change | Add `multiTenantEnabled` parameter (default `false`); wire to env var in container config |
| Also | `infra/parameters/dev.json` — set to `true` for dev environment |
| Also | `infra/parameters/prod.json` — set to `false` initially; flip after validation |

### Task 4.7 — Update CI/CD: add `ALLOWED_TENANTS` env var

| Detail | Value |
|--------|-------|
| File | `infra/modules/container-app.bicep` |
| Change | Add `allowedTenants` parameter; wire to env var |
| Also | Populate in dev params with test tenant IDs |

### Task 4.8 — Update docs/multi-tenant-strategy.md status

| Detail | Value |
|--------|-------|
| File | `docs/multi-tenant-strategy.md` |
| Change | Update status from "Proposal — pending review" to "In progress" → "Implemented" as phases complete |

### Task 4.9 — Update README.md

| Detail | Value |
|--------|-------|
| File | `README.md` |
| Change | Add "Multi-Tenant Configuration" section documenting the `MULTI_TENANT_ENABLED`, `ALLOWED_TENANTS`, and `APP_BASE_URL` env vars |

---

## Dependency Graph

```
Phase 1 (Auth layer)
├── 1.1 Feature flag in config
├── 1.2 Tenant allowlist in config
├── 1.3 OAuth2 organizations endpoint ────────────────┐
├── 1.4 Dynamic issuer validation ────────────────────┤
├── 1.5 build_auth_url / exchange_code update ────────┤
└── 1.6 UserContext.access_token ──┐                  │
                                   │                  │
Phase 2 (Tool plumbing)            │                  │
├── 2.1 create_graph_client_for_user() ◄──────────────┘
├── 2.2 Add user_context to Graph tools ◄── 2.1
├── 2.3 Tenant awareness for non-Graph tools
├── 2.4 Thread UserContext through _run_tool() ◄── 1.6, 2.2
├── 2.5 Thread UserContext through handle_chat() ◄── 2.4
├── 2.6 Session key includes tenant+user ◄── 1.6
├── 2.7 Update Copilot SDK adapters ◄── 2.2
└── 2.8 /chat endpoint passes UserContext ◄── 2.5
                                   │
Phase 3 (Onboarding)               │
├── 3.1 App reg → AzureADMultipleOrgs ◄── Phase 1
├── 3.2 /admin/consent endpoint ◄── 3.4
├── 3.3 /admin/consent/callback ◄── 3.2
├── 3.4 app_base_url config ◄── 1.1
└── 3.5 Onboarding runbook doc
                                   │
Phase 4 (Tests + CI/CD)            │
├── 4.1 Auth multi-tenant tests ◄── 1.3, 1.4
├── 4.2 Graph OBO tests ◄── 2.1, 2.2
├── 4.3 Session isolation tests ◄── 2.6
├── 4.4 Admin consent tests ◄── 3.2, 3.3
├── 4.5 Integration smoke test ◄── Phase 2
├── 4.6 Bicep: MULTI_TENANT_ENABLED ◄── 1.1
├── 4.7 Bicep: ALLOWED_TENANTS ◄── 1.2
├── 4.8 Update strategy doc status
└── 4.9 Update README
```

---

## Rollback Plan

All changes are gated behind `MULTI_TENANT_ENABLED=false` (default). If any
issue is discovered post-deployment:

| Step | Action | Impact |
|------|--------|--------|
| 1 | Set `MULTI_TENANT_ENABLED=false` in Container App env vars | Immediately reverts to single-tenant mode. No code deployment needed. |
| 2 | Clear `ALLOWED_TENANTS` | Removes tenant allowlist filter |
| 3 | App reg: change `signInAudience` back to `AzureADMyOrg` | Prevents any cross-tenant login attempts at the Entra ID level |

**Zero-downtime rollback:** Step 1 alone is sufficient. The feature flag
disables all multi-tenant code paths. The `organizations` endpoint still
works for single-tenant when the issuer validation falls back to
`settings.azure_tenant_id`.

---

## Files Modified (Complete List)

| File | Phase | Type of Change |
|------|-------|---------------|
| `src/agent/config.py` | 1, 3 | Add `multi_tenant_enabled`, `allowed_tenants`, `app_base_url` fields |
| `src/middleware/auth.py` | 1 | Dynamic authority, dynamic issuer validation, `UserContext.access_token` |
| `src/tools/graph_client.py` | 2 | Add `create_graph_client_for_user()` |
| `src/tools/secure_score.py` | 2 | Add `user_context` parameter |
| `src/tools/defender_coverage.py` | 2 | Add `user_context` parameter |
| `src/tools/entra_config.py` | 2 | Add `user_context` parameter |
| `src/tools/purview_policies.py` | 2 | Add `user_context` parameter |
| `src/tools/remediation_plan.py` | 2 | Add `tenant_id` parameter |
| `src/tools/adoption_scorecard.py` | 2 | Add `tenant_id` parameter |
| `src/api/chat.py` | 2 | Thread `user_context` through `_run_tool()` and `handle_chat()`; update session key |
| `src/agent/main.py` | 2 | Update Copilot SDK adapters to pass `user_context` |
| `src/api/app.py` | 2, 3 | Pass `UserContext` to chat; add admin consent endpoints |
| `scripts/provision-dev.sh` | 3 | `AzureADMyOrg` → `AzureADMultipleOrgs` |
| `scripts/setup-permissions.sh` | 3 | `AzureADMyOrg` → `AzureADMultipleOrgs` |
| `infra/modules/container-app.bicep` | 4 | Add `multiTenantEnabled`, `allowedTenants` params + env vars |
| `infra/parameters/dev.json` | 4 | Set multi-tenant params for dev |
| `infra/parameters/prod.json` | 4 | Set multi-tenant params for prod (default off) |
| `tests/unit/test_auth.py` | 4 | Multi-tenant token validation tests |
| `tests/unit/test_chat.py` | 4 | Session isolation tests |
| `tests/unit/test_secure_score.py` | 4 | OBO Graph client tests |
| `tests/integration/test_e2e_smoke.py` | 4 | Multi-tenant smoke test |
| `docs/multi-tenant-strategy.md` | 4 | Status update |
| `docs/tenant-onboarding-runbook.md` | 3 | New — onboarding instructions |
| `README.md` | 4 | Multi-tenant config section |
