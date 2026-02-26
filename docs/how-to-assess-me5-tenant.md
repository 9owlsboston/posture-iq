# PostureIQ — How to Assess an ME5 Tenant

> This document explains the end-to-end flow for using PostureIQ to assess
> a Microsoft 365 E5 (ME5) tenant's security posture.
>
> All environment-specific values (tenant IDs, endpoints, secrets) are defined in
> the `.env` file at the project root. See `.env.example` for the template.

---

## What We Built

```
┌──────────────┐     POST /chat      ┌──────────────────┐     Graph API      ┌─────────────────┐
│  Chat UI     │ ──────────────────► │  FastAPI App     │ ──────────────────► │  ME5 Tenant     │
│  (browser)   │ ◄────────────────── │  (Container App) │ ◄────────────────── │  (Graph API)    │
│  index.html  │     JSON response   │  chat.py → tools │     JSON data       │  Secure Score,  │
└──────────────┘                     └──────────────────┘                     │  Defender, etc. │
                                            │                                └─────────────────┘
                                            │ uses
                                            ▼
                                     ┌──────────────────┐
                                     │  graph_client.py │
                                     │  Credential:     │
                                     │  - ClientSecret  │
                                     │  - or MI (prod)  │
                                     └──────────────────┘
```

PostureIQ is a containerized FastAPI application deployed to **Azure Container Apps**.
It exposes a chat UI at `/` and a `POST /chat` endpoint. When a user asks a security
question, the app classifies intent, dispatches to the appropriate tool, and that tool
calls the **Microsoft Graph Security API** to retrieve real tenant data.

---

## What Is an ME5 Tenant?

An **ME5 tenant** is not a special type of Azure tenant. It's a standard **Entra ID
(Azure AD) tenant** whose users have **Microsoft 365 E5 licenses**.

| Concept | What It Is |
|---|---|
| **Azure tenant** | An Entra ID directory — every organization gets one. It's the identity boundary. |
| **M365 E5 license** | The top-tier Microsoft 365 subscription bundle purchased *within* that tenant. |
| **ME5 tenant** | Shorthand for a tenant whose users have M365 E5 licenses — unlocking the full security stack. |

### What M365 E5 Includes (What PostureIQ Assesses)

- **Defender XDR** — Defender for Endpoint, Identity, Cloud Apps, Office 365
- **Purview** — DLP policies, sensitivity labels, insider risk management, retention policies
- **Entra ID P2** — Conditional Access, PIM, Identity Protection, Access Reviews
- **Compliance** — eDiscovery, communication compliance, audit (premium)

### The Problem PostureIQ Solves

Many customers *buy* ME5 licenses but don't *deploy* all the security features — they're
paying for Defender, Purview, and Entra ID P2 but haven't turned them on.
**Project 479 ("Get to Green")** is Microsoft's internal campaign to help these
customers actually adopt what they've paid for.

PostureIQ assesses this adoption by calling the **Microsoft Graph Security API**:
- `/security/secureScores` → Are they using Defender?
- `/policies/conditionalAccessPolicies` → Is Entra ID P2 configured?
- `/informationProtection/policy/labels` → Are Purview policies active?

---

## How to Verify Your Tenant Has E5 Licensing

Before running an assessment, confirm that the target tenant has M365 E5 licenses:

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/subscribedSkus" \
  --query "value[].{SKU:skuPartNumber, Enabled:prepaidUnits.enabled, Assigned:consumedUnits}" \
  -o table
```

### SKU Reference

| SKU Part Number | License |
|---|---|
| `SPE_E5` | **Microsoft 365 E5** (the full bundle — this is ME5) |
| `Microsoft_365_E5_(no_Teams)` | **Microsoft 365 E5 without Teams** (Teams now separate) |
| `SPE_E3` | Microsoft 365 E3 |
| `ENTERPRISEPREMIUM` | Office 365 E5 (older naming) |
| `ENTERPRISEPACK` | Office 365 E3 |
| `EMSPREMIUM` | EMS E5 (Enterprise Mobility + Security E5) |
| `AAD_PREMIUM_P2` | Entra ID P2 (standalone add-on) |
| `IDENTITY_THREAT_PROTECTION` | Microsoft 365 E5 Security add-on |
| `INFORMATION_PROTECTION_COMPLIANCE` | Microsoft 365 E5 Compliance add-on |

Look for `SPE_E5` or `Microsoft_365_E5_(no_Teams)`. Some organizations achieve
"equivalent to ME5" by combining E3 + add-ons (E5 Security + E5 Compliance).

### Our Tenant's Licensing

```
SKU                          Enabled    Assigned
---------------------------  ---------  ----------
FLOW_FREE                    10000      3
CCIBOTS_PRIVPREV_VIRAL       10000      3
AAD_PREMIUM_P2               1          1
Microsoft_365_E5_(no_Teams)  25         3
POWERAPPS_DEV                10000      3
```

**Confirmed: ME5 tenant.** 25 E5 licenses available, 3 assigned.
Plus a standalone Entra ID P2 license.

---

## Configuration: `.env` File

All PostureIQ settings are managed through a single `.env` file at the project root,
loaded by `pydantic-settings` in `src/agent/config.py`.

```bash
# First-time setup
cp .env.example .env
# Then fill in your values (see .env.example for documentation on each variable)
```

Key variables for Graph API assessment:

| `.env` Variable | Purpose | Example |
|---|---|---|
| `AZURE_TENANT_ID` | Your Entra ID tenant | `635ae6b5-...` |
| `AZURE_CLIENT_ID` | App Registration client ID | `8ec5b682-...` |
| `AZURE_CLIENT_SECRET` | Client secret for Graph API OAuth2 | *(generated via az cli)* |
| `AZURE_KEYVAULT_URL` | Key Vault for production secrets | `https://<vault>.vault.azure.net/` |
| `CONTAINER_APP_URL` | Deployed app URL | `https://<app>.<region>.azurecontainerapps.io` |
| `ACR_LOGIN_SERVER` | Container Registry | `<acr>.azurecr.io` |
| `RESOURCE_GROUP` | Azure resource group | `rg-postureiq-dev` |

> **Security:** `.env` is in `.gitignore` and is never committed. Only `.env.example`
> (with placeholders) is tracked in source control.

---

## Current State: Demo Mode (Mock Data)

The Container App (URL in `$CONTAINER_APP_URL`) works but returns **mock data** when
`AZURE_TENANT_ID` or `AZURE_CLIENT_ID` are not set in `.env`.

The tools in `src/tools/graph_client.py` check:

```python
if not settings.azure_tenant_id or not settings.azure_client_id:
    return None  # → triggers mock data fallback in each tool
```

This is by design — mock mode is useful for demos, UI testing, and development
without needing Graph API access.

---

## Connecting to Real Tenant Data — 3 Steps

### Step 1: Grant Graph API Permissions (Admin Consent)

The App Registration (identified by `AZURE_CLIENT_ID` in `.env`) needs
**admin consent** for 5 **Application** (not Delegated) permissions.

> **⚠️ Critical: Application vs Delegated Permissions**
>
> PostureIQ uses `ClientSecretCredential` (client credentials grant flow), which
> requires **Application** permissions (`type: Role`). Delegated permissions
> (`type: Scope`) will result in 403 errors even after admin consent.
> See [Lessons Learned](#lessons-learned) for details.

> **Important:** The `az ad app permission admin-consent` command operates on
> **whichever tenant you're currently signed into** with `az login`. It does not
> reference an external tenant by name. Since PostureIQ is a single-tenant app
> (`--sign-in-audience "AzureADMyOrg"`), you must be logged into the same tenant
> where the App Registration lives (`AZURE_TENANT_ID` in `.env`).

| Permission (Application) | Graph App Role ID | Purpose |
|---|---|---|
| `SecurityEvents.Read.All` | `bf394140-e372-4bf9-a898-299cfc7564e5` | Secure Score, security alerts |
| `SecurityActions.Read.All` | `5e0edab9-c148-49d0-b423-ac253e121825` | Defender security actions |
| `InformationProtectionPolicy.Read.All` | `19da66cb-0fb0-4390-b071-ebc76a349482` | Purview/DLP policies |
| `Policy.Read.All` | `246dd0d5-5bd0-4def-940b-0421030a5b68` | Conditional Access, Entra config |
| `Reports.Read.All` | `230c1aed-a721-4c5d-9cb4-a90514e508ef` | Adoption scorecard, usage reports |

> **Note:** The Application-level permission for information protection is
> `InformationProtectionPolicy.Read.All` (not `InformationProtection.Read.All`,
> which is the Delegated version).

```bash
# Source .env to load variables
set -a && source .env && set +a

# Ensure you're logged into YOUR tenant
az login --tenant $AZURE_TENANT_ID

# Grant admin consent (requires Global Admin or Privileged Role Admin)
az ad app permission admin-consent --id $AZURE_CLIENT_ID
```

#### ⚠️ Troubleshooting: Partial Consent

`az ad app permission admin-consent` may **silently grant only a subset** of the
registered permissions. This is a known Azure CLI behavior — the command exits
successfully even when some scopes are not consented.

**Verify** all 5 Application permissions were actually granted:

```bash
# Get the Service Principal Object ID for the app
SP_ID=$(az ad sp show --id $AZURE_CLIENT_ID --query id -o tsv)

# List granted Application permission role assignments
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignments" \
  --query "value[].{appRoleId:appRoleId,resourceDisplayName:resourceDisplayName}" -o table
```

Expected: 5 rows, all targeting `Microsoft Graph`. If any are missing, **grant them
directly** via `appRoleAssignments`:

```bash
# Get the Microsoft Graph service principal's object ID
GRAPH_SP_ID=$(az ad sp show --id "00000003-0000-0000-c000-000000000000" --query id -o tsv)

# Grant each missing Application permission
# Replace ROLE_ID with the appRoleId from the table above
for ROLE_ID in \
  "bf394140-e372-4bf9-a898-299cfc7564e5" \
  "5e0edab9-c148-49d0-b423-ac253e121825" \
  "19da66cb-0fb0-4390-b071-ebc76a349482" \
  "246dd0d5-5bd0-4def-940b-0421030a5b68" \
  "230c1aed-a721-4c5d-9cb4-a90514e508ef"; do
  az rest --method POST \
    --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{
      \"principalId\": \"$SP_ID\",
      \"resourceId\": \"$GRAPH_SP_ID\",
      \"appRoleId\": \"$ROLE_ID\"
    }" 2>&1
done

# Verify — should show 5 rows
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignments" \
  --query "value[].{appRoleId:appRoleId,resourceDisplayName:resourceDisplayName}" -o table
```

> **Why does this happen?** The `admin-consent` CLI command creates consent grants
> iteratively. If some permission IDs haven't fully propagated in Entra ID, or if
> there are transient API issues, the command may skip those roles without
> reporting an error. The direct `appRoleAssignment` approach is deterministic.

### Step 2: Create a Client Secret and Store in Key Vault

```bash
# Source .env to load variables
set -a && source .env && set +a

# Generate a client secret (1-year expiry)
az ad app credential reset --id $AZURE_CLIENT_ID --years 1
# Save the output — you'll need the "password" value

# Update AZURE_CLIENT_SECRET in .env with the new password
# Then store it in Key Vault for production use
KV_NAME=$(echo $AZURE_KEYVAULT_URL | sed 's|https://||;s|.vault.azure.net/||')
az keyvault secret set \
  --vault-name $KV_NAME \
  --name "graph-client-secret" \
  --value "<the-password-from-above>"
```

> **Key Vault RBAC:** If you get a `Forbidden (ForbiddenByRbac)` error, your
> signed-in user needs the **Key Vault Secrets Officer** role on the vault:
> ```bash
> MY_OID=$(az ad signed-in-user show --query id -o tsv)
> KV_ID=$(az keyvault show --name $KV_NAME --query id -o tsv)
> az role assignment create --assignee "$MY_OID" \
>   --role "Key Vault Secrets Officer" --scope "$KV_ID"
> # Wait ~15 seconds for RBAC propagation, then retry
> ```

### Step 3: Configure Container App Environment Variables

Set the 3 Graph API env vars on the Container App so the tools connect to real data:

```bash
# Source .env to load variables
set -a && source .env && set +a

az containerapp update \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --set-env-vars \
    AZURE_TENANT_ID="$AZURE_TENANT_ID" \
    AZURE_CLIENT_ID="$AZURE_CLIENT_ID" \
    AZURE_CLIENT_SECRET=secretref:graph-client-secret
```

> In production, the `secretref:` prefix pulls the value from the Container App's
> secret store backed by Key Vault — the secret is never stored as plain text in
> environment variables.
>
> For **local development**, the app reads `AZURE_CLIENT_SECRET` directly from `.env`.

---

## User Flow (After Configuration)

1. Open the app URL (value of `CONTAINER_APP_URL` in `.env`, or `http://localhost:8000` for local dev)
2. The Chat UI loads with the 7 security assessment tools in the sidebar
3. Type a question like *"Show me the secure score"* or click a quick action button
4. The `/chat` endpoint classifies intent → dispatches to the right tool → tool calls Graph API → returns real data
5. Results appear as formatted markdown with scores, categories, trends, and recommendations

---

## The 7 Assessment Tools

| Tool | Graph API Endpoint | What It Assesses |
|---|---|---|
| Secure Score | `/security/secureScores` | Overall security posture score + category breakdown |
| Defender Coverage | `/security/alerts` | Defender for Endpoint/Identity/Cloud coverage |
| Entra Config | `/policies/conditionalAccessPolicies` | Conditional Access, MFA, Identity Protection |
| Purview Policies | `/informationProtection/policy/labels` | DLP, sensitivity labels, compliance |
| Adoption Scorecard | `/reports/getM365AppUserDetail` | M365 app adoption rates |
| Remediation Plan | *(aggregates all tools + GPT-4o)* | Prioritized fix recommendations with scripts |
| Graph Client | *(shared factory)* | Authentication layer for all tools |

---

## Single-Tenant vs. Multi-Tenant

### Current Design: Assess Your Own Tenant

PostureIQ is currently configured as a **single-tenant** application:

| Setting | Value | Implication |
|---|---|---|
| `sign-in-audience` | `AzureADMyOrg` | Only users in `$AZURE_TENANT_ID` can authenticate |
| `ClientSecretCredential` | Uses `$AZURE_TENANT_ID` | Graph API calls target our tenant's data |
| Application permissions | App-context (Role) | Agent sees all tenant data the app roles allow |

This means PostureIQ assesses **your own tenant's ME5 posture** — verifying whether
Defender, Purview, and Entra ID P2 features are actually deployed and configured.

### To Assess a Different Customer's Tenant (Future)

To assess external customer tenants, the app would need to become **multi-tenant**:

1. **Change sign-in audience:**
   ```bash
   set -a && source .env && set +a
   az ad app update --id $AZURE_CLIENT_ID --sign-in-audience AzureADMultipleOrgs
   ```

2. **Customer's Global Admin grants consent** via the admin consent URL:
   ```
   https://login.microsoftonline.com/{CUSTOMER_TENANT_ID}/adminconsent
     ?client_id=$AZURE_CLIENT_ID
     &redirect_uri=$CONTAINER_APP_URL/auth/callback
   ```
   The customer's admin clicks this link, signs in, sees the 5 permissions, and clicks "Accept."

3. **PostureIQ then calls Graph API against the customer's tenant** — the OAuth2 flow
   gets a token scoped to their tenant based on the signed-in user's identity.

---

## Quick Testing with a CDX Demo Tenant

If you don't want to use a production tenant, use a **CDX demo tenant**
(pre-populated with M365 E5 licenses and sample security data):

1. Go to [cdx.transform.microsoft.com](https://cdx.transform.microsoft.com)
2. Create a "Microsoft 365 Enterprise" demo tenant
3. Use that tenant's credentials in the 3 configuration steps above

This gives you real Graph API data without touching production.

---

## Authentication Layers — Summary

PostureIQ has **4 separate authentication mechanisms** (don't confuse them):

| Auth Layer | Purpose | Mechanism | Secrets |
|---|---|---|---|
| **User auth** | User signs in to chat UI | Entra ID OAuth2 (delegated) | None (browser redirect) |
| **Graph API auth** | App calls Graph Security API | ClientSecretCredential | Client secret in Key Vault |
| **Service auth** | Container App → Azure services | Managed Identity | None (RBAC + DefaultAzureCredential) |
| **CI/CD auth** | GitHub Actions → Azure | OIDC Workload Identity Federation | None (3 non-sensitive IDs) |

---

## Deployed Resources

All resource identifiers are stored in `.env`. Here's the mapping:

| Resource | `.env` Variable |
|---|---|
| Container App URL | `CONTAINER_APP_URL` |
| Container App Name | `CONTAINER_APP_NAME` |
| ACR Login Server | `ACR_LOGIN_SERVER` |
| Key Vault URL | `AZURE_KEYVAULT_URL` |
| App Insights | `APPLICATIONINSIGHTS_CONNECTION_STRING` |
| Managed Identity | `MANAGED_IDENTITY_CLIENT_ID` |
| Resource Group | `RESOURCE_GROUP` |
| App Registration | `AZURE_CLIENT_ID` |
| Tenant ID | `AZURE_TENANT_ID` |
| Subscription | `AZURE_SUBSCRIPTION_ID` |

To see your current values:

```bash
grep -v '^#' .env | grep -v '^$' | sort
```

---

## Lessons Learned

Gotchas encountered during the initial tenant connection — documented so you
don't repeat them.

### 1. Application vs Delegated Permissions (403 on Every Graph Call)

**Symptom:** All Graph API calls return `403 — Auth token does not contain valid
permissions or user does not have valid roles`, even after admin consent.

**Root Cause:** PostureIQ uses `ClientSecretCredential` (OAuth2 client credentials
grant), which authenticates as the **application**, not a user. This flow only
recognizes **Application** permissions (`type: Role`). Delegated permissions
(`type: Scope`) are ignored — they only work with user-context flows
(authorization code, on-behalf-of).

**Fix:** Register permissions as **Application** (Role), not Delegated (Scope).
Use the Graph API to update the app's `requiredResourceAccess`:

```bash
APP_OBJ_ID=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications" \
  --query "value[?appId=='$AZURE_CLIENT_ID'].id" -o tsv)

az rest --method PATCH \
  --url "https://graph.microsoft.com/v1.0/applications/$APP_OBJ_ID" \
  --headers "Content-Type=application/json" \
  --body '{
    "requiredResourceAccess": [{
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        {"id": "bf394140-e372-4bf9-a898-299cfc7564e5", "type": "Role"},
        {"id": "5e0edab9-c148-49d0-b423-ac253e121825", "type": "Role"},
        {"id": "19da66cb-0fb0-4390-b071-ebc76a349482", "type": "Role"},
        {"id": "246dd0d5-5bd0-4def-940b-0421030a5b68", "type": "Role"},
        {"id": "230c1aed-a721-4c5d-9cb4-a90514e508ef", "type": "Role"}
      ]
    }]
  }'
```

Then grant admin consent via `appRoleAssignments` (see Step 1 troubleshooting).

### 2. `az ad app permission admin-consent` Grants Partial Scopes Silently

**Symptom:** Command exits with no errors but only 2 of 5 permissions are
actually consented.

**Root Cause:** The CLI iterates through permissions and creates grants one at a
time. If any fail (due to propagation delays, transient errors), the command
swallows the error and continues — reporting success overall.

**Fix:** Always verify after consent. For Application permissions, check
`appRoleAssignments`; for Delegated, check `oauth2PermissionGrants`. Grant
missing ones individually (see Step 1 troubleshooting).

### 3. Key Vault RBAC — "Forbidden" When Storing Secrets

**Symptom:** `az keyvault secret set` returns `ForbiddenByRbac` even though
you created the Key Vault.

**Root Cause:** Key Vault uses **RBAC** (not access policies) by default in
newer deployments. Creating the vault doesn't automatically give you data-plane
access — only ARM (management plane) access.

**Fix:** Assign yourself `Key Vault Secrets Officer` scoped to the vault
(see Step 2 RBAC note). Wait ~15 seconds for propagation.

### 4. Application Permission Name Differs from Delegated

**Symptom:** Can't find `InformationProtection.Read.All` in the Graph service
principal's `appRoles`.

**Root Cause:** The Delegated and Application versions of some permissions have
different names:

| Delegated (Scope) | Application (Role) |
|---|---|
| `InformationProtection.Read.All` | `InformationProtectionPolicy.Read.All` |

**Fix:** Always look up the correct permission IDs from the Microsoft Graph
service principal's `appRoles` list, not the `oauth2PermissionScopes` list.

### 5. Container App Provisioning Conflict

**Symptom:** `az containerapp secret set` returns
`ContainerAppOperationInProgress — Cannot modify a container app`.

**Root Cause:** A previous `az containerapp update` or deployment is still
provisioning. Container Apps only allow one mutation at a time.

**Fix:** Wait for the active operation to complete:
```bash
# Poll until Succeeded
az containerapp show --name $CONTAINER_APP_NAME --resource-group $RESOURCE_GROUP \
  --query "properties.provisioningState" -o tsv
```

### 6. Additional Permissions for Deeper Entra Analysis

The base 5 permissions cover the core assessment tools. For deeper Entra ID
analysis (PIM roles, identity providers, app registrations), the Entra config
tool attempts additional Graph API calls that require:

| Additional Permission | Purpose | Status |
|---|---|---|
| `RoleManagement.Read.Directory` | PIM role assignments | Optional (graceful fallback) |
| `IdentityProvider.Read.All` | Federated identity providers | Optional (graceful fallback) |
| `Application.Read.All` | App registration audit | Optional (graceful fallback) |

The tool handles 403 errors gracefully and still returns useful results without
these permissions. Add them only if you need the full Entra configuration picture.

### 7. First-Time Test Results (Baseline)

Our first real assessment of the ME5 tenant returned:

| Tool | Result | Notes |
|---|---|---|
| Secure Score | **127.2 / 271.0** (46.9%) | Gap to green: 23 points |
| Defender Coverage | **0%** all workloads | Defender not onboarded yet |
| Entra Config | **55%** coverage, 6 gaps | Legacy auth not blocked (critical gap) |

This baseline confirms the "bought but not deployed" problem that
Project 479 targets — the tenant has E5 licenses but hasn't activated
the security features they paid for.
