# PostureIQ — Graph API Permission Setup Guide

This guide documents the Microsoft Graph API permissions required by PostureIQ
and how to configure them via Entra ID App Registration.

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
