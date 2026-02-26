# PostureIQ — Azure Resource Provisioning & Graph API Setup Guide

This guide covers the full provisioning of PostureIQ's Azure environment and
the Microsoft Graph API permissions required for security assessment.

---

## Quick Start (Automated)

The fastest way to provision the complete dev environment:

```bash
# Login to Azure
az login

# Provision everything: resource group, Azure resources, App Registration
./scripts/provision-dev.sh

# To skip specific stages:
./scripts/provision-dev.sh --skip-app-reg    # Skip Entra ID App Registration
./scripts/provision-dev.sh --skip-infra      # Skip Azure resource deployment
```

This script handles:
| Step | Resource | Description |
|------|----------|-------------|
| 1 | Resource Group (`rg-postureiq-dev`) | Container for all Azure resources |
| 2 | Azure Container Registry | Container image store (OIDC push, managed identity pull) |
| 3 | Azure OpenAI (GPT-4o) | LLM reasoning & summarization |
| 4 | Azure AI Content Safety | RAI content filtering |
| 5 | Azure Application Insights | Distributed tracing & observability |
| 6 | Azure Key Vault | Secrets management (Graph API credentials) |
| 7 | Azure Container Apps | Deployment target (scale 0–5 replicas) |
| 8 | Entra ID App Registration | Graph API access with least-privilege scopes |
| 9 | OIDC Federated Credentials | Workload Identity Federation for GitHub Actions |

---

## Manual Provisioning

### Azure Resources (Bicep)

To deploy infrastructure manually using the Bicep templates:

```bash
# Create resource group
az group create --name rg-postureiq-dev --location eastus2 --tags project=postureiq environment=dev

# Validate templates
az deployment group validate \
  --resource-group rg-postureiq-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters/dev.bicepparam

# Deploy
az deployment group create \
  --resource-group rg-postureiq-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters/dev.bicepparam
```

### Infrastructure Modules

| Module | File | Resources |
|--------|------|-----------|
| Container Registry | `infra/modules/container-registry.bicep` | ACR (admin disabled, OIDC push, MI pull) |
| OpenAI | `infra/modules/openai.bicep` | Azure OpenAI account + GPT-4o deployment |
| Content Safety | `infra/modules/content-safety.bicep` | Azure AI Content Safety (S0) |
| App Insights | `infra/modules/app-insights.bicep` | Application Insights + Log Analytics workspace |
| Key Vault | `infra/modules/keyvault.bicep` | Key Vault with RBAC authorization |
| Container App | `infra/modules/container-app.bicep` | Container Apps Environment + App with managed identity |

---

## CI/CD Authentication: OIDC Workload Identity Federation

PostureIQ uses **OIDC Workload Identity Federation** for CI/CD — zero stored secrets.

### Why OIDC?

| Approach | Secrets Stored | Credential Lifetime | Rotation |
|----------|---------------|-------------------|----------|
| Service Principal + ACR Admin | 4 (SP JSON, ACR user/pass, login server) | Months/years | Manual |
| **OIDC Federation** | **0 real secrets** (3 non-sensitive IDs) | **Minutes** (per workflow run) | **Automatic** |

### Setup

```bash
# One-time setup — configures federated credentials + GitHub secrets
chmod +x scripts/setup-oidc.sh
./scripts/setup-oidc.sh
```

This creates 3 federated credentials on the App Registration:

| Subject | Purpose |
|---------|---------|
| `repo:9owlsboston/posture-iq:ref:refs/heads/main` | Push to main → build & deploy |
| `repo:9owlsboston/posture-iq:pull_request` | PR preview environments |
| `repo:9owlsboston/posture-iq:environment:production` | Production deploy stage |

### GitHub Secrets Required

Only 3 non-sensitive identifiers (NOT credentials):

| Secret | Value | Sensitive? |
|--------|-------|-----------|
| `AZURE_CLIENT_ID` | App Registration client ID | No — public identifier |
| `AZURE_TENANT_ID` | Entra ID tenant ID | No — public identifier |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID | No — public identifier |

---

## Required Permissions (Delegated)

PostureIQ uses **delegated permissions** — it acts on behalf of the signed-in user
and only accesses data the user is authorized to see.

| Permission | Type | Purpose | Admin Consent |
|------------|------|---------|---------------|
| `SecurityEvents.Read.All` | Delegated | Read Secure Score, security alerts | Yes |
| `SecurityActions.Read.All` | Delegated | Read Defender security actions | Yes |
| `InformationProtection.Read.All` | Delegated | Read Purview/DLP policies | Yes |
| `Policy.Read.All` | Delegated | Read Conditional Access, Identity Protection | Yes |
| `Reports.Read.All` | Delegated | Read usage and adoption reports | Yes |

> **Note:** All permissions require **admin consent** because they access tenant-wide security data.

---

## Setup Steps

### 1. Create App Registration

```bash
# Using Azure CLI
az ad app create \
  --display-name "PostureIQ - ME5 Security Assessment" \
  --sign-in-audience "AzureADMyOrg" \
  --web-redirect-uris "http://localhost:8000/auth/callback"
```

### 2. Add API Permissions

```bash
# Get the App ID
APP_ID=$(az ad app list --display-name "PostureIQ" --query "[0].appId" -o tsv)

# Add Graph API permissions
# SecurityEvents.Read.All
az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions bf394140-e372-4bf9-a898-299cfc7564e5=Scope

# Policy.Read.All
az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 572fea84-0151-49b2-9301-11cb16974376=Scope

# Reports.Read.All
az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 02e97553-ed7b-43d0-ab3c-f8bace0d040c=Scope
```

### 3. Grant Admin Consent

```bash
# Requires Global Admin or Privileged Role Admin
az ad app permission admin-consent --id $APP_ID
```

### 4. Create Client Secret (for Graph API OAuth2 Flow)

> **Note:** This client secret is used for the **Graph API OAuth2 authorization code flow**
> (exchanging user auth codes for tokens). It is **not** used for CI/CD — the pipeline
> uses [OIDC Workload Identity Federation](#cicd-authentication-oidc-workload-identity-federation)
> with zero stored secrets. In production, this secret is stored in Key Vault and
> accessed via Managed Identity.

```bash
az ad app credential reset --id $APP_ID --years 1
# Save the output — you'll need the password (client secret)
```

### 5. Configure PostureIQ (Local Development)

Add the following to your `.env` file:

```env
AZURE_TENANT_ID=<your-tenant-id>
AZURE_CLIENT_ID=<app-client-id-from-step-1>
AZURE_CLIENT_SECRET=<secret-from-step-4>
```

> **Production:** The Container App uses Managed Identity — no client secret
> in environment variables. The secret is retrieved from Key Vault at runtime.

---

## Using CDX Demo Tenants

For development, you can use a **Microsoft CDX demo tenant** which comes pre-populated
with M365 E5 licenses and sample data:

1. Go to [CDX Portal](https://cdx.transform.microsoft.com)
2. Create a new "Microsoft 365 Enterprise" demo tenant
3. Use the tenant credentials for the App Registration above

---

## Least-Privilege Principle

PostureIQ follows least-privilege:
- **Read-only** permissions only — no write/modify scopes
- **Delegated** (not application) — acts as the user, not as a service
- Specific scopes targeted to security assessment, not broad `Directory.Read.All`

---

## Troubleshooting

### Graph API Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Authorization_RequestDenied` | Missing admin consent | Run `az ad app permission admin-consent` |
| `InvalidAuthenticationToken` | Expired or invalid client secret | Regenerate with `az ad app credential reset` |
| `InsufficientPrivileges` | User doesn't have required role | User needs Security Reader role minimum |

### CI/CD Errors (OIDC)

| Error | Cause | Fix |
|-------|-------|-----|
| `AADSTS70021: No matching federated identity credential found` | Missing or misconfigured federated credential | Run `./scripts/setup-oidc.sh` to create federated credentials |
| `az acr login` fails | OIDC token doesn't have AcrPush role | Verify `cicdPrincipalId` parameter in Bicep deployment |
| `AZURE_CLIENT_ID` secret not set | GitHub secrets not configured | Run `./scripts/setup-oidc.sh` (uses `gh secret set`) |

---

## Cleanup / Teardown

Use the cleanup script to delete all development resources when they're no longer needed:

```bash
# Interactive — prompts before each deletion
./scripts/cleanup-dev.sh

# Non-interactive — skip all prompts (for CI/automation)
./scripts/cleanup-dev.sh --yes

# Delete only the Entra ID App Registration (keep Azure resources)
./scripts/cleanup-dev.sh --app-only

# Delete only the resource group (keep App Registration)
./scripts/cleanup-dev.sh --rg-only
```

The script handles:

| Resource | Action |
|----------|--------|
| Resource group (`rg-postureiq-dev`) | Deletes the group and all resources inside (async) |
| Entra ID App Registration | Deletes the `PostureIQ - ME5 Security Assessment` app |
| Soft-deleted Key Vaults | Purges any soft-deleted vaults (required to reuse names) |
| Local `.env` file | Optionally removes it |

> **Tip:** Resource group deletion runs asynchronously. Check status with:
> ```bash
> az group exists --name rg-postureiq-dev
> ```

---

## Pre-flight Check

Run the pre-flight script before every commit/push to validate the full project:

```bash
./scripts/preflight.sh
```

### What it checks

| # | Check | Details |
|---|-------|---------|
| 1 | **Python tests** | Runs `pytest` and reports pass/fail count |
| 2 | **Linting** | Runs `ruff` — distinguishes blocking errors (E4/E7/E9/F) from style warnings |
| 3 | **Bicep compile** | Builds `infra/main.bicep` to verify ARM template generation |
| 4 | **Bicep lint** | Runs linter rules on the Bicep templates |
| 5 | **Bicep params** | Validates `dev.bicepparam` and `prod.bicepparam` |
| 6 | **YAML workflows** | Parses all `.github/workflows/*.yml` files |
| 7 | **Docker build** | Full `docker build` + container health-probe smoke test |
| 8 | **Git status** | Shows modified/untracked/staged file counts |

### Options

| Flag | Effect |
|------|--------|
| `--quick` | Skip the Docker build (faster iteration) |
| `--docker-only` | Run only the Docker build check |
| `--help` | Show usage information |

Checks that require missing tools (e.g., `az`, `docker`, `ruff`) are automatically skipped rather than failing.
