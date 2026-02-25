#!/usr/bin/env bash
#
# PostureIQ — Graph API Permission Setup Script
#
# Creates an Entra ID App Registration with the minimum required
# Graph API permissions for PostureIQ security assessment.
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Permissions to create App Registrations in the tenant
#   - Global Admin or Privileged Role Admin for admin consent
#
# Usage:
#   chmod +x scripts/setup-permissions.sh
#   ./scripts/setup-permissions.sh

set -euo pipefail

APP_NAME="PostureIQ - ME5 Security Assessment"
REDIRECT_URI="http://localhost:8000/auth/callback"

echo "🛡️  PostureIQ — Setting up Graph API permissions"
echo "================================================"

# ── Step 1: Create App Registration ──────────────────────────
echo ""
echo "📝 Step 1: Creating App Registration..."

APP_ID=$(az ad app create \
  --display-name "$APP_NAME" \
  --sign-in-audience "AzureADMyOrg" \
  --web-redirect-uris "$REDIRECT_URI" \
  --query "appId" -o tsv)

echo "   ✅ App created: $APP_ID"

# ── Step 2: Add Graph API Permissions ────────────────────────
echo ""
echo "🔑 Step 2: Adding Graph API permissions..."

GRAPH_API_ID="00000003-0000-0000-c000-000000000000"

# SecurityEvents.Read.All (Delegated)
az ad app permission add --id "$APP_ID" \
  --api "$GRAPH_API_ID" \
  --api-permissions "bf394140-e372-4bf9-a898-299cfc7564e5=Scope" \
  2>/dev/null
echo "   ✅ SecurityEvents.Read.All"

# SecurityActions.Read.All (Delegated)
az ad app permission add --id "$APP_ID" \
  --api "$GRAPH_API_ID" \
  --api-permissions "1638cddf-07a5-4f16-928e-0b80f95e632c=Scope" \
  2>/dev/null
echo "   ✅ SecurityActions.Read.All"

# Policy.Read.All (Delegated)
az ad app permission add --id "$APP_ID" \
  --api "$GRAPH_API_ID" \
  --api-permissions "572fea84-0151-49b2-9301-11cb16974376=Scope" \
  2>/dev/null
echo "   ✅ Policy.Read.All"

# Reports.Read.All (Delegated)
az ad app permission add --id "$APP_ID" \
  --api "$GRAPH_API_ID" \
  --api-permissions "02e97553-ed7b-43d0-ab3c-f8bace0d040c=Scope" \
  2>/dev/null
echo "   ✅ Reports.Read.All"

# InformationProtection.Read.All (Delegated) — for Purview policies
az ad app permission add --id "$APP_ID" \
  --api "$GRAPH_API_ID" \
  --api-permissions "d9731f5b-aca7-42d8-8aeb-0ac1bf55e2e9=Scope" \
  2>/dev/null
echo "   ✅ InformationProtection.Read.All"

# ── Step 3: Grant Admin Consent ──────────────────────────────
echo ""
echo "🔓 Step 3: Granting admin consent..."
echo "   ⚠️  This requires Global Admin or Privileged Role Admin"

az ad app permission admin-consent --id "$APP_ID" 2>/dev/null || {
  echo "   ⚠️  Admin consent failed — you may need a Global Admin to run:"
  echo "      az ad app permission admin-consent --id $APP_ID"
}
echo "   ✅ Admin consent granted (or pending)"

# ── Step 4: Create Client Secret ─────────────────────────────
echo ""
echo "🔐 Step 4: Creating client secret..."

SECRET_OUTPUT=$(az ad app credential reset --id "$APP_ID" --years 1 --query "{clientId: appId, tenantId: tenant, clientSecret: password}" -o json)

echo "   ✅ Client secret created"

# ── Step 5: Output Configuration ─────────────────────────────
echo ""
echo "================================================"
echo "🎉 PostureIQ App Registration Complete!"
echo "================================================"
echo ""
echo "Add these to your .env file:"
echo ""
echo "AZURE_TENANT_ID=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["tenantId"])')"
echo "AZURE_CLIENT_ID=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientId"])')"
echo "AZURE_CLIENT_SECRET=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientSecret"])')"
echo ""
echo "⚠️  Store the client secret securely — it won't be shown again."
echo "   In production, use Azure Key Vault instead of .env files."
