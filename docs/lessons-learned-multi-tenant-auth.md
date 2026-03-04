# Lessons Learned: Multi-Tenant Authentication & Deployment

> **Date:** 2026-03-04  
> **Version:** v1.3  
> **Context:** SecPostureIQ — FastAPI agent on Azure Container Apps with Entra ID OAuth2  
> **Scope:** All issues encountered from initial deployment through multi-tenant enablement  
> **PRs:** #2 through #14  
> **Workflows:** `ci-cd.yml`, `pr-deploy.yml`, `rollback.yml`

---

## Part I — Authentication & Identity

### 1. App Registration Client ID ≠ Managed Identity Client ID (PR #6)

**Error:** Clicking "Sign In" returned a 404 from `login.microsoftonline.com` — the OAuth2 authorize URL had an empty tenant and used the managed identity's client ID.

**Root cause:** The SPA's OAuth2 flow used `AZURE_CLIENT_ID` for the `client_id` parameter. But `AZURE_CLIENT_ID` was set to the **managed identity** client ID (for ACR pull), not the app registration. The MI has no app registration in Entra ID, so the OAuth2 URL was invalid.

**Fix:** Introduce `ENTRA_APP_CLIENT_ID` as a separate environment variable pointing to the app registration. Update the auth middleware and SPA to use it for OAuth2 flows.

**Lesson:** A Container App that uses both a managed identity (for Azure services) and an app registration (for user auth) has **two different client IDs**. They must never share an environment variable. Name convention:
- `AZURE_CLIENT_ID` → Managed Identity (infrastructure: ACR, Key Vault, OpenAI)
- `ENTRA_APP_CLIENT_ID` → App Registration (user-facing OAuth2)

---

### 2. Entra ID Account Picker for Multi-Account Users (PR #2)

**Problem:** Users with multiple Entra ID accounts (e.g., `alice@contoso.com` + `alice@fabrikam.com`) couldn't choose which identity to sign in with. Entra ID silently picked the most recent session.

**Fix:** Add `prompt=select_account` to the OAuth2 authorize URL, which forces Entra ID to show the account picker regardless of existing sessions.

**Lesson:** For any enterprise app where users may have multiple identities, always include `prompt=select_account` in the authorization request. Without it, Entra ID's SSO behavior will silently pick an account — which may not be the one the user intends to assess.

---

### 3. Reverse Proxy Headers Break OAuth2 Redirect URIs (PR #7)

**Error:** `AADSTS50011 — The redirect URI does not match the redirect URIs configured for the application`

**Root cause:** Azure Container Apps terminates TLS at an ingress proxy and forwards requests to the container over HTTP. Uvicorn, unaware it was behind a proxy, generated OAuth2 redirect URIs with `http://` instead of `https://`. Entra ID rejected the mismatch.

**Fix:** Add `--proxy-headers` and `--forwarded-allow-ips *` to the Uvicorn CMD in the Dockerfile.

**Lesson:** Any ASGI/WSGI server behind a cloud load balancer or ingress must be explicitly told to trust forwarded headers (`X-Forwarded-Proto`, `X-Forwarded-For`). Without this, every URL the framework generates — OAuth2 callbacks, OpenAPI docs, CORS origins — will use the wrong scheme.

---

### 4. Client Secret Collision Between MI and App Reg (PR #9)

**Error:** `AADSTS7000232 — The provided client_secret is not valid for this application`

**Root cause:** A single `AZURE_CLIENT_SECRET` env var was shared. When `graph_client.py` tried `ClientSecretCredential` it paired the **managed identity's** client ID with the **app registration's** secret. Entra ID rejected it — the secret belongs to a different identity.

**Fix:** Introduce `ENTRA_APP_CLIENT_SECRET` for the app registration secret, separate from any infra credentials.

**Lesson:** This is a variant of lesson #1 — identity collision extends to secrets too. If two identities coexist in one deployment, their credentials must be fully separated:

| Purpose | Client ID Var | Secret Var |
|---------|--------------|------------|
| Infrastructure (ACR, KV) | `AZURE_CLIENT_ID` | _(none — uses MI)_ |
| User auth (OAuth2) | `ENTRA_APP_CLIENT_ID` | `ENTRA_APP_CLIENT_SECRET` |

---

### 5. `signInAudience` Must Match OAuth2 Endpoint Tenant Scope (PR #11)

**Error:** External tenant users got `AADSTS50020 — User account from identity provider does not exist in tenant`.

**Root cause:** The app registration's `signInAudience` was `AzureADMyOrg` (single-tenant), so only users from the home tenant could authenticate. The OAuth2 endpoints used the home tenant ID, further restricting access.

**Fix:**
1. Change `signInAudience` to `AzureADMultipleOrgs` on the app registration.
2. Use `/organizations/oauth2/v2.0/authorize` and `/organizations/oauth2/v2.0/token` endpoints.
3. Validate the JWT issuer dynamically using the token's `tid` claim.
4. Add `MULTI_TENANT_ENABLED` feature flag to Bicep and CI/CD.

**Lesson:** Multi-tenant auth requires alignment at three layers:
1. **App registration** — `signInAudience: AzureADMultipleOrgs`
2. **OAuth2 endpoints** — Use `/organizations` or `/common` instead of a specific tenant ID
3. **Token validation** — Accept issuers from any tenant (validate `tid` claim matches the issuer URL)

Missing any one of these three causes a different error, making it hard to diagnose.

---

### 6. Delegated vs Application Graph Permissions — Name Traps (PR #12, #13)

**Error:** `AADSTS650053 — The application asked for scope '...' that doesn't exist on the resource`

**Round 1 (PR #12):** The scope `InformationProtection.Read.All` doesn't exist at all in the Microsoft Graph permission catalog. It was a hallucinated name.

**Round 2 (PR #13):** The replacement `InformationProtectionPolicy.Read.All` (ID `19da66cb...`) **does** exist — but only as an **application permission** (`appRoles`), not as a delegated scope (`oauth2PermissionScopes`). Entra ID rejects it when requested in a delegated token flow.

**Fix:** Query the Graph service principal to find the correct **delegated** scope:
```bash
az ad sp show --id 00000003-0000-0000-c000-000000000000 \
  --query "oauth2PermissionScopes[?contains(value,'InformationProtection')]"
```
This revealed `InformationProtectionPolicy.Read` (ID `4ad84827-5578-4e18-ad7a-86530b12f884`) — without the `.All` suffix.

**Lesson:**
- **Permission names are NOT intuitive.** `Foo.Read.All` may be application-only while `Foo.Read` is delegated. The `.All` suffix doesn't always mean "all resources" — sometimes it means "application permission only."
- **Always verify permissions against the service principal**, not documentation alone. Documentation can be stale or ambiguous.
- **Use the permission ID, not just the name**, when calling `az ad app permission add`. The ID is the source of truth.
- After changing scopes, existing tenant consents may need to be re-granted. There's no automatic "scope upgrade."
- The quickest way to find the correct delegated scope:
  ```bash
  az ad sp show --id 00000003-0000-0000-c000-000000000000 \
    --query "oauth2PermissionScopes[?contains(value,'YourKeyword')].{id:id,value:value,type:type}"
  ```

---

### 7. Admin Consent for Multi-Tenant Apps

**Observation:** When an external tenant user first authenticates, they see a consent prompt for the requested Graph scopes. Security-sensitive scopes require tenant admin consent.

**Lesson:**
- Document the exact admin consent URL for customer onboarding:
  ```
  https://login.microsoftonline.com/{customer-tenant-id}/adminconsent?client_id={app-client-id}
  ```
- Keep the set of requested scopes minimal — every additional scope is a question the admin must evaluate.
- After changing scopes (as we did twice), existing tenant consents may need to be re-granted.

---

## Part II — Data Flow & Graph Client

### 8. Authenticated Users Still Saw Mock Data (PR #4)

**Error:** Users who had signed in with Entra ID saw "MOCK DATA" badges in the UI despite being authenticated.

**Root cause:** The chat endpoint validated the user's JWT but never forwarded the user's **Graph access token** to the tool functions. The tools created a Graph client without a user token, defaulting to mock data.

**Fix:** Extract the `X-Graph-Token` header in the chat endpoint and thread it through to each tool's `create_graph_client()` call. The SPA sends both the `Authorization: Bearer <id_token>` (for API auth) and `X-Graph-Token: <access_token>` (for Graph API calls).

**Lesson:** In an OAuth2 SPA-to-API flow, the **ID token** (who the user is) and the **access token** (what the user can do) are different. The API might validate the ID token for auth but still need to forward the access token to downstream services. Design the token flow end-to-end before implementing.

---

### 9. Managed Identity Fallback Leaks Hosting Tenant Data (PR #14)

**Error:** Unauthenticated users saw real security posture data from the hosting tenant, with the UI badge incorrectly showing "Live Data."

**Root cause:** `create_graph_client()` had a fallback chain: user token → `ClientSecretCredential` → `DefaultAzureCredential`. When no user token was present, the function fell through to `DefaultAzureCredential`, which picked up the Container App's managed identity. This MI successfully authenticated to Graph for the **hosting** tenant, returning real data labeled as live.

**Fix:** Remove the entire app-level credentials fallback. `create_graph_client()` now only accepts user-delegated tokens. No token → return `None` → mock data.

**Lesson:**
- **Managed identities for infrastructure ≠ managed identities for user data.** The MI exists for ACR pull, Key Vault, and OpenAI — never for Graph API user-data queries.
- **Fallback chains are dangerous** when the fallback credential has different access than intended. A "convenient" `DefaultAzureCredential()` fallback meant for local dev can silently activate in production with the wrong identity.
- **Test the unauthenticated path explicitly.** If your API supports optional auth (`auto_error=False`), test what happens when no token is provided — the answer might be "it works, but with the wrong tenant's data."

---

### 10. Data Source Aggregation Can Mask Partial Failures

**Observation (design smell, not a bug):** The chat handler aggregates `data_source` across all tool results. If even one tool returns `data_source: "graph_api"` while others return `"mock"`, the overall response is labeled `"live"`. When the MI fallback worked for Defender Coverage but failed (403) for Secure Score, the response still showed "Live Data."

**Lesson:** When aggregating status across multiple tool calls:
- Show per-tool data source indicators (not just one overall badge)
- Flag mixed states explicitly (e.g., "partial — 2/4 tools used live data")
- Log which tools returned live vs mock for debugging

---

## Part III — CI/CD & Infrastructure

### 11. PR Preview Deploys Need Shared ACR Access (PR #3)

**Error:** PR preview Container Apps couldn't pull images. Each PR created a new resource group, but the Container App needed `AcrPull` on the **shared dev ACR** in a different resource group.

**Root cause:** The original Bicep template created a separate ACR per PR (wasteful and slow). The fix switched to using the shared dev ACR, but the PR's managed identity didn't have `AcrPull` on it.

**Fix:** Before Bicep deploy: (1) pre-create the PR's managed identity, (2) grant `AcrPull` on the shared dev ACR, (3) wait 30 seconds for RBAC propagation.

**Lesson:** PR preview environments that share resources with the main deployment need explicit cross-resource-group role assignments. The "create identity → assign role → wait → deploy" pattern should be a standard CI/CD step, not an afterthought.

---

### 12. RBAC Propagation Delays in Pipelines (PR #7)

**Error:** Even after granting `AcrPull`, the Bicep deployment intermittently failed because the role assignment hadn't propagated to the ARM control plane.

**Root cause:** Azure RBAC assignments can take 30–60 seconds to propagate. The CI/CD pipeline ran the Bicep deploy immediately after `az role assignment create`.

**Fix:** Add `sleep 30` between role assignment and Bicep deploy. The `pr-deploy.yml` workflow has this as an explicit step: "Wait for role assignment propagation."

**Lesson:** When a pipeline depends on an RBAC assignment, always add a propagation delay. 30 seconds is usually sufficient, but for mission-critical pipelines, use a retry loop that checks for the expected permission before proceeding.

---

### 13. Bicep Deployments Overwrite Manual Configuration (PR #10)

**Error:** `AADSTS7000218 — client_secret not found` reappeared after a successful manual fix.

**Root cause:** Every push to `main` triggers a Bicep deployment that defines the complete Container App configuration. Any environment variable set manually (via `az containerapp update` or the portal) gets wiped because it's not in the template.

**Fix:** Add the secret as a Key Vault reference in the Bicep template (`secretRef` pointing to the KV secret), so it survives redeployment.

**Lesson:** Infrastructure-as-Code is **declarative and complete**. If a Container App's env vars are managed by Bicep, every variable must be in the template. Manual `az` CLI additions are temporary — they'll vanish on the next deploy. For secrets, always use Key Vault references in the template rather than hardcoded values.

---

### 14. `github` vs `context` in GitHub Actions Scripts (PR #8)

**Error:** Teardown job's "Comment on PR" step failed with `TypeError: Cannot read properties of undefined (reading 'pull_request')`.

**Root cause:** Inside an `actions/github-script` block, the Octokit client is named `github`. The workflow event context is on `context`. The script used `github.event.pull_request` instead of `context.payload.pull_request`.

**Fix:** Replace `github.event.pull_request` with `context.payload.pull_request`.

**Lesson:** In `actions/github-script`:
| Object | What It Is | Equivalent In YAML |
|--------|------------|-------------------|
| `github` | Octokit REST client | _(no equivalent — it's for API calls)_ |
| `context` | Workflow event context | `${{ github }}` |
| `context.payload` | Event payload | `${{ github.event }}` |
| `context.repo` | `{ owner, repo }` | `${{ github.repository_owner }}`, `${{ github.event.repository.name }}` |

These are different objects. Use `context.payload` for event data, `github.rest.*` for API calls.

---

### 15. Concurrency Groups Prevent Deployment Conflicts

**Problem:** Simultaneous pushes to `main` or multiple PR updates could cause overlapping deployments that interfered with each other.

**Fix:** Both `ci-cd.yml` and `pr-deploy.yml` use concurrency groups:
```yaml
# ci-cd.yml — one deploy at a time for main
concurrency:
  group: deploy-${{ github.ref }}
  cancel-in-progress: true

# pr-deploy.yml — one deploy per PR
concurrency:
  group: pr-preview-${{ github.event.pull_request.number }}
  cancel-in-progress: true
```

**Lesson:** Always use concurrency groups for deployment workflows. Without them:
- Two pushes to `main` can deploy different commits simultaneously, leaving the environment in an undefined state
- Rapid PR updates waste runner minutes deploying versions that are immediately obsolete
- `cancel-in-progress: true` ensures only the latest version deploys

---

### 16. PR Preview Lifecycle — Deploy and Teardown

**Problem:** PR preview environments accumulated over time, wasting Azure resources and costs.

**Pattern adopted:** The `pr-deploy.yml` workflow handles the full lifecycle:
```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened, closed]
```
- `opened/synchronize/reopened` → Deploy preview
- `closed` → Delete the PR resource group (`az group delete --yes --no-wait`)

**Gotchas encountered:**
1. **Teardown must check if the RG exists** — `az group delete` fails if the RG was already deleted or never created (e.g., deploy step failed before creating it).
2. **Teardown runs on `closed`, not `merged`** — closing without merging also triggers teardown (correct behavior).
3. **`--no-wait` is essential** — RG deletion can take 5+ minutes; the workflow shouldn't block on it.

**Lesson:** Treat preview environments as ephemeral. Automate both creation and teardown. Gate teardown on `closed` (not `merged`) and always check for resource existence before deleting.

---

### 17. OIDC Workload Identity Federation — Zero Stored Secrets in CI/CD

**Pattern:** All three workflows (`ci-cd.yml`, `pr-deploy.yml`, `rollback.yml`) use OIDC Workload Identity Federation for Azure authentication:
```yaml
permissions:
  id-token: write  # Required for OIDC token request

- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

**Lesson:**
- OIDC federation means **no Azure secrets stored in GitHub**. The three values (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`) are non-sensitive IDs, not credentials.
- The `id-token: write` permission is **required** — without it, the OIDC token request fails silently with a generic auth error.
- The federated credential must be configured on the app registration with the correct subject claim (`repo:org/repo:ref:refs/heads/main` for pushes, `repo:org/repo:pull_request` for PRs).
- Rollback workflows also need OIDC — don't forget to add the `workflow_dispatch` subject to the federated credential.

---

### 18. Rollback Workflow — Image Verification Before Deploy

**Pattern:** The `rollback.yml` workflow verifies the target image tag exists in ACR before deploying:
```yaml
- name: Verify image exists in ACR
  run: |
    az acr repository show-tags ... --query "[?@=='${IMAGE_TAG}']" | grep -q .
```

**Lesson:** A rollback to a non-existent image tag leaves the Container App in a broken state. Always verify the image exists before deploying. The workflow also runs a health check after rollback to confirm the app is responsive.

---

### 19. Trivy Image Scanning in the Build Pipeline

**Pattern:** The `ci-cd.yml` build job scans the Docker image for vulnerabilities before pushing to ACR:
```yaml
- uses: aquasecurity/trivy-action@master
  with:
    severity: CRITICAL,HIGH
    exit-code: 1
    ignore-unfixed: true
```

**Lesson:** Scanning between build and push catches vulnerabilities before they reach the registry. `ignore-unfixed: true` prevents blocking on CVEs that have no available patch — otherwise every base image update could stall the pipeline.

---

## Part IV — UI & Frontend

### 20. Data Source Badge Sync Between Header and Messages

**Problem:** The header badge showed "Mock Data" while individual message badges showed "Live Data" (or vice versa). Two separate UI elements tracked data source state independently.

**Fix:** Unified the badge update logic so both the header badge (`#dataSourceBadge`) and per-message badges read from the same `data.data_source` field in the API response.

**Lesson:** When the same status is displayed in multiple UI locations, derive all of them from a single source of truth. Separate state variables for the same concept will always drift.

---

## Summary: What We'd Do Differently

| # | Issue | Prevention |
|---|-------|-----------|
| 1 | App reg vs MI client ID collision | Name env vars by purpose (`ENTRA_APP_*` vs `AZURE_*`) from the start |
| 2 | No account picker for multi-account users | Always include `prompt=select_account` in OAuth2 flows |
| 3 | Proxy header mismatch | Include `--proxy-headers` in the Dockerfile from day one for any cloud deployment |
| 4 | Client secret collision | Fully separate credential sets per identity from the beginning |
| 5 | Single-tenant → multi-tenant | Design for multi-tenant from the beginning if there's any chance of it |
| 6 | Wrong Graph permission names (× 2) | Always query the service principal for the exact permission ID before adding |
| 7 | Admin consent scope changes | Automate a consent validation check in the onboarding flow |
| 8 | Graph token not forwarded | Design the token flow end-to-end (ID token vs access token) before implementing |
| 9 | MI fallback leaking data | Never use `DefaultAzureCredential` as a silent fallback for user-scoped data access |
| 10 | Aggregated data source badge | Show per-tool data source status, not just an aggregate |
| 11 | PR preview can't pull from shared ACR | Grant cross-RG AcrPull as a standard CI/CD step |
| 12 | RBAC propagation race | Always add a propagation delay after role assignments |
| 13 | Bicep wiping manual config | Never manually set env vars — always go through IaC |
| 14 | `github` vs `context` confusion | Use TypeScript for GitHub Actions scripts (type checking catches this) |
| 15 | Concurrent deploys | Always use concurrency groups for deployment workflows |
| 16 | Orphaned PR preview resources | Automate teardown on PR close, check existence before deleting |
| 17 | Stored secrets in CI/CD | Use OIDC federation from day one; ensure `id-token: write` permission is set |
| 18 | Rollback to missing image | Verify image exists in ACR before deploying |
| 19 | Vulnerable base images | Scan images between build and push with `ignore-unfixed: true` |
| 20 | Badge state drift | Derive all UI status indicators from a single source of truth |

---

## Appendix: PR Index

| PR | Title | Category |
|----|-------|----------|
| #2 | feat(auth): Entra ID account picker for multi-account users | Auth |
| #3 | fix(ci): PR preview deploy uses dev ACR with proper AcrPull | CI/CD |
| #4 | fix: use delegated Graph token for live tenant data | Data Flow |
| #6 | fix(auth): separate app registration client ID from managed identity | Auth |
| #7 | fix: enable uvicorn proxy headers for correct HTTPS redirect URIs | Auth / Infra |
| #8 | fix(ci): use context.payload in teardown github-script step | CI/CD |
| #9 | fix(auth): separate OAuth client secret from managed identity credentials | Auth |
| #10 | infra: wire ENTRA_APP_CLIENT_SECRET via Key Vault ref in Bicep | Infra |
| #11 | feat: enable multi-tenant authentication | Auth |
| #12 | fix: correct Graph scope InformationProtection → InformationProtectionPolicy | Auth / Scopes |
| #13 | fix: use delegated scope InformationProtectionPolicy.Read (drop .All suffix) | Auth / Scopes |
| #14 | fix: remove app-level Graph fallback to prevent hosting tenant data leak | Data Flow / Security |
