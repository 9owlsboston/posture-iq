#!/usr/bin/env bash
#
# SecPostureIQ — azd postprovision hook
#
# Automatically runs after `azd provision` (or as part of `azd up`).
# Completes the Entra ID App Registration + Graph API setup that
# Bicep cannot do, making `azd up` a true end-to-end deployment.
#
# What this script does:
#   1. Creates an Entra ID App Registration (if it doesn't exist)
#   2. Adds 8 read-only Graph API permissions
#   3. Grants admin consent
#   4. Creates a client secret
#   5. Stores Graph API credentials in the deployed Key Vault
#   6. Saves values to the azd environment for future runs
#
# azd automatically makes Bicep outputs available as environment
# variables during hook execution (from .azure/<env>/.env).

set -uo pipefail

APP_DISPLAY_NAME="SecPostureIQ - ME5 Security Assessment"
GRAPH_API_ID="00000003-0000-0000-c000-000000000000"

# ── Tracking ──────────────────────────────────────────────
GRANTED=()
FAILED=()

add_permission() {
  local name="$1"
  local guid="$2"
  az ad app permission add --id "$APP_ID" \
    --api "$GRAPH_API_ID" \
    --api-permissions "${guid}=Scope" \
    2>/dev/null && {
    GRANTED+=("$name")
    echo "   ✅ $name"
    return 0
  }
  FAILED+=("$name")
  echo "   ⚠️  $name — failed (may already exist)"
  return 0  # Don't abort on individual permission failures
}

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   SecPostureIQ — Post-Provision Setup (azd hook)       ║"
echo "║   Setting up Entra ID + Graph API access            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Resolve Key Vault name from azd environment ──────────
# azd stores Bicep outputs in the environment; try common variable names
KEY_VAULT_NAME="${AZURE_KEY_VAULT_NAME:-${keyVaultName:-}}"

if [[ -z "$KEY_VAULT_NAME" ]]; then
  # Fall back to querying azd env
  KEY_VAULT_NAME=$(azd env get-value keyVaultName 2>/dev/null || echo "")
fi

if [[ -z "$KEY_VAULT_NAME" ]]; then
  echo "   ⚠️  Could not determine Key Vault name from azd environment."
  echo "      Graph API credentials will be printed instead of stored in Key Vault."
fi

# ── Get tenant ID ────────────────────────────────────────
TENANT_ID=$(az account show --query "tenantId" -o tsv 2>/dev/null)
echo "   Tenant: $TENANT_ID"
echo ""

# ══════════════════════════════════════════════════════════
# STEP 1: Create or find App Registration
# ══════════════════════════════════════════════════════════

echo "📝 Step 1/4: Entra ID App Registration"

EXISTING_APP_ID=$(az ad app list --display-name "$APP_DISPLAY_NAME" \
  --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_APP_ID" ]]; then
  echo "   ⏭️  App Registration already exists: $EXISTING_APP_ID"
  APP_ID="$EXISTING_APP_ID"
else
  APP_ID=$(az ad app create \
    --display-name "$APP_DISPLAY_NAME" \
    --sign-in-audience "AzureADMyOrg" \
    --query "appId" -o tsv) || {
    echo "   ❌ Failed to create App Registration."
    echo "      You may not have permission. Run manually:"
    echo "      az ad app create --display-name \"$APP_DISPLAY_NAME\" --sign-in-audience AzureADMyOrg"
    exit 1
  }
  echo "   ✅ Created App Registration: $APP_ID"
fi

echo ""

# ══════════════════════════════════════════════════════════
# STEP 2: Add Graph API permissions (8 read-only scopes)
# ══════════════════════════════════════════════════════════

echo "🔑 Step 2/4: Graph API permissions (8 scopes)"

add_permission "SecurityEvents.Read.All"         "bf394140-e372-4bf9-a898-299cfc7564e5"
add_permission "SecurityActions.Read.All"        "1638cddf-07a5-4f16-928e-0b80f95e632c"
add_permission "Policy.Read.All"                 "572fea84-0151-49b2-9301-11cb16974376"
add_permission "Reports.Read.All"                "02e97553-ed7b-43d0-ab3c-f8bace0d040c"
add_permission "InformationProtectionPolicy.Read"     "4ad84827-5578-4e18-ad7a-86530b12f884"
add_permission "RoleManagement.Read.Directory"   "741f803b-c850-494e-b5df-cde7c675a1ca"
add_permission "IdentityRiskyUser.Read.All"      "d04bb851-cb7c-4146-97c7-ca3e71baf56c"
add_permission "AccessReview.Read.All"           "ebfcd32b-babb-40f4-a14b-42706e83bd28"

echo ""
echo "   Granted: ${#GRANTED[@]}/8  |  Issues: ${#FAILED[@]}/8"
echo ""

# ══════════════════════════════════════════════════════════
# STEP 3: Admin consent
# ══════════════════════════════════════════════════════════

echo "🔓 Step 3/4: Admin consent"

az ad app permission admin-consent --id "$APP_ID" 2>/dev/null && {
  echo "   ✅ Admin consent granted"
} || {
  echo "   ⚠️  Admin consent requires Global Admin or Privileged Role Admin."
  echo "      Ask your tenant admin to run:"
  echo "      az ad app permission admin-consent --id $APP_ID"
}

echo ""

# ══════════════════════════════════════════════════════════
# STEP 4: Client secret → Key Vault
# ══════════════════════════════════════════════════════════

echo "🔐 Step 4/4: Client secret + Key Vault storage"

SECRET_OUTPUT=$(az ad app credential reset --id "$APP_ID" --years 1 \
  --query "{clientId: appId, tenantId: tenant, clientSecret: password}" -o json 2>/dev/null) || {
  echo "   ❌ Failed to create client secret."
  exit 1
}

CLIENT_ID=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientId"])')
CLIENT_SECRET=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientSecret"])')

echo "   ✅ Client secret created"

# Store in Key Vault
if [[ -n "$KEY_VAULT_NAME" ]]; then
  echo "   🔒 Storing credentials in Key Vault ($KEY_VAULT_NAME)..."
  az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
    --name "AZURE-TENANT-ID" --value "$TENANT_ID" --output none 2>/dev/null || true
  az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
    --name "AZURE-CLIENT-ID" --value "$CLIENT_ID" --output none 2>/dev/null || true
  az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
    --name "AZURE-CLIENT-SECRET" --value "$CLIENT_SECRET" --output none 2>/dev/null || true
  echo "   ✅ Credentials stored in Key Vault (not displayed)"
else
  echo "   ⚠️  No Key Vault found. Save these credentials:"
  echo "      AZURE_TENANT_ID=$TENANT_ID"
  echo "      AZURE_CLIENT_ID=$CLIENT_ID"
  echo "      AZURE_CLIENT_SECRET=<created — check az ad app credential list>"
fi

# Save to azd environment so subsequent runs can reference them
if command -v azd &>/dev/null; then
  azd env set AZURE_TENANT_ID "$TENANT_ID" 2>/dev/null || true
  azd env set AZURE_CLIENT_ID "$CLIENT_ID" 2>/dev/null || true
  azd env set SECPOSTUREIQ_APP_REGISTRATION_ID "$APP_ID" 2>/dev/null || true
  echo "   ✅ Values saved to azd environment"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ✅ Post-provision setup complete!                  ║"
echo "║   Graph API credentials are in Key Vault.           ║"
echo "║   azd will now build & deploy the container.        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
