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
| 2 | Azure OpenAI (GPT-4o) | LLM reasoning & summarization |
| 3 | Azure AI Content Safety | RAI content filtering |
| 4 | Azure Application Insights | Distributed tracing & observability |
| 5 | Azure Key Vault | Secrets management (Graph API credentials) |
| 6 | Azure Container Apps | Deployment target (scale 0–5 replicas) |
| 7 | Entra ID App Registration | Graph API access with least-privilege scopes |

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
| OpenAI | `infra/modules/openai.bicep` | Azure OpenAI account + GPT-4o deployment |
| Content Safety | `infra/modules/content-safety.bicep` | Azure AI Content Safety (S0) |
| App Insights | `infra/modules/app-insights.bicep` | Application Insights + Log Analytics workspace |
| Key Vault | `infra/modules/keyvault.bicep` | Key Vault with RBAC authorization |
| Container App | `infra/modules/container-app.bicep` | Container Apps Environment + App with managed identity |

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

### 4. Create Client Secret

```bash
az ad app credential reset --id $APP_ID --years 1
# Save the output — you'll need the password (client secret)
```

### 5. Configure PostureIQ

Add the following to your `.env` file:

```env
AZURE_TENANT_ID=<your-tenant-id>
AZURE_CLIENT_ID=<app-client-id-from-step-1>
AZURE_CLIENT_SECRET=<secret-from-step-4>
```

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

| Error | Cause | Fix |
|-------|-------|-----|
| `Authorization_RequestDenied` | Missing admin consent | Run `az ad app permission admin-consent` |
| `InvalidAuthenticationToken` | Expired or invalid secret | Regenerate with `az ad app credential reset` |
| `InsufficientPrivileges` | User doesn't have required role | User needs Security Reader role minimum |

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
