#!/usr/bin/env bash
#
# PostureIQ — Graph API Permission Setup Script
#
# Creates an Entra ID App Registration with the minimum required
# Graph API permissions for PostureIQ security assessment.
#
# All 8 required delegated scopes and their consuming tools:
#   1. SecurityEvents.Read.All      — secure_score, defender_coverage, purview_policies
#   2. SecurityActions.Read.All     — defender_coverage (action recommendations)
#   3. Policy.Read.All              — entra_config (conditional access)
#   4. Reports.Read.All             — adoption_scorecard (usage reports)
#   5. InformationProtection.Read.All — purview_policies (sensitivity labels)
#   6. RoleManagement.Read.Directory  — entra_config (PIM role assignments)
#   7. IdentityRiskyUser.Read.All     — entra_config (identity protection)
#   8. AccessReview.Read.All          — entra_config (access reviews)
#
# Error handling:
#   - Each permission add is attempted independently (no early abort).
#   - Failures are recorded and summarised at the end.
#   - The script exits 0 if all critical permissions succeed, 1 otherwise.
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Permissions to create App Registrations in the tenant
#   - Global Admin or Privileged Role Admin for admin consent
#
# Usage:
#   chmod +x scripts/setup-permissions.sh
#   ./scripts/setup-permissions.sh

# Do NOT use set -e — we handle errors per-command for graceful reporting.
set -uo pipefail

APP_NAME="PostureIQ - ME5 Security Assessment"
REDIRECT_URI="http://localhost:8000/auth/callback"

# ── Tracking arrays ──────────────────────────────────────────
GRANTED=()
FAILED=()

add_permission() {
  local name="$1"
  local guid="$2"
  local error_output

  error_output=$(az ad app permission add --id "$APP_ID" \
    --api "$GRAPH_API_ID" \
    --api-permissions "${guid}=Scope" 2>&1) && {
    GRANTED+=("$name")
    echo "   ✅ $name"
    return 0
  }

  FAILED+=("$name")
  echo "   ❌ $name — FAILED"
  echo "      $error_output" | head -3
  return 1
}

echo "🛡️  PostureIQ — Setting up Graph API permissions"
echo "================================================"

# ── Step 1: Create App Registration ──────────────────────────
echo ""
echo "📝 Step 1: Creating App Registration..."

APP_ID=$(az ad app create \
  --display-name "$APP_NAME" \
  --sign-in-audience "AzureADMyOrg" \
  --web-redirect-uris "$REDIRECT_URI" \
  --query "appId" -o tsv) || {
  echo "   ❌ Failed to create app registration. Cannot continue."
  exit 1
}

echo "   ✅ App created: $APP_ID"

# ── Step 2: Add Graph API Permissions (all 8) ────────────────
echo ""
echo "🔑 Step 2: Adding Graph API permissions (8 total)..."

GRAPH_API_ID="00000003-0000-0000-c000-000000000000"

# ── Core security scopes ─────────────────────────────────────
add_permission "SecurityEvents.Read.All"         "bf394140-e372-4bf9-a898-299cfc7564e5" || true
add_permission "SecurityActions.Read.All"        "1638cddf-07a5-4f16-928e-0b80f95e632c" || true
add_permission "Policy.Read.All"                 "572fea84-0151-49b2-9301-11cb16974376" || true
add_permission "Reports.Read.All"                "02e97553-ed7b-43d0-ab3c-f8bace0d040c" || true
add_permission "InformationProtection.Read.All"  "d9731f5b-aca7-42d8-8aeb-0ac1bf55e2e9" || true

# ── Entra ID configuration scopes (entra_config.py) ─────────
add_permission "RoleManagement.Read.Directory"   "741f803b-c850-494e-b5df-cde7c675a1ca" || true
add_permission "IdentityRiskyUser.Read.All"      "d04bb851-cb7c-4146-97c7-ca3e71baf56c" || true
add_permission "AccessReview.Read.All"           "ebfcd32b-babb-40f4-a14b-42706e83bd28" || true

# ── Permission summary ───────────────────────────────────────
echo ""
echo "   ── Summary ──"
echo "   Granted : ${#GRANTED[@]} / 8"
echo "   Failed  : ${#FAILED[@]} / 8"
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "   Failed permissions:"
  for perm in "${FAILED[@]}"; do
    echo "      • $perm"
  done
fi

# ── Step 3: Grant Admin Consent ──────────────────────────────
echo ""
echo "🔓 Step 3: Granting admin consent..."
echo "   ⚠️  This requires Global Admin or Privileged Role Admin"

if [[ ${#GRANTED[@]} -eq 0 ]]; then
  echo "   ⏭️  Skipping admin consent — no permissions were added."
else
  az ad app permission admin-consent --id "$APP_ID" 2>&1 || {
    echo "   ⚠️  Admin consent failed — you may need a Global Admin to run:"
    echo "      az ad app permission admin-consent --id $APP_ID"
  }
  echo "   ✅ Admin consent granted (or pending) for ${#GRANTED[@]} permissions"
fi

# ── Step 4: Verify granted permissions ───────────────────────
echo ""
echo "🔍 Step 4: Verifying consented permissions..."

CONSENTED=$(az ad app permission list-grants --id "$APP_ID" \
  --query "[].scope" -o tsv 2>/dev/null || echo "")

if [[ -n "$CONSENTED" ]]; then
  echo "   Confirmed scopes: $CONSENTED"
else
  echo "   ⚠️  Could not verify — consent may be pending admin approval."
  echo "      Check in Entra ID → App Registrations → $APP_NAME → API permissions"
fi

# ── Step 5: Create Client Secret ─────────────────────────────
echo ""
echo "🔐 Step 5: Creating client secret..."

SECRET_OUTPUT=$(az ad app credential reset --id "$APP_ID" --years 1 \
  --query "{clientId: appId, tenantId: tenant, clientSecret: password}" -o json) || {
  echo "   ❌ Failed to create client secret."
  exit 1
}

echo "   ✅ Client secret created"

# ── Step 6: Output Configuration ─────────────────────────────
echo ""
echo "================================================"
if [[ ${#FAILED[@]} -eq 0 ]]; then
  echo "🎉 PostureIQ App Registration Complete! (8/8 permissions)"
else
  echo "⚠️  PostureIQ App Registration Complete with issues"
  echo "   ${#GRANTED[@]}/8 permissions granted, ${#FAILED[@]} failed."
  echo "   The agent will fall back to mock data for tools that"
  echo "   depend on the missing scopes, but functionality will"
  echo "   be degraded. Re-run this script or grant the missing"
  echo "   permissions manually in the Azure portal:"
  echo "   Entra ID → App Registrations → $APP_NAME → API permissions"
fi
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

# ── Exit code reflects permission completeness ───────────────
if [[ ${#FAILED[@]} -gt 0 ]]; then
  exit 1
fi
