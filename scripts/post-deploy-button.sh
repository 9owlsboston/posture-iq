#!/usr/bin/env bash
#
# SecPostureIQ — Post "Deploy to Azure" Button Setup
#
# Run this AFTER deploying infrastructure via the "Deploy to Azure" button.
# It completes the three remaining steps that the ARM template cannot do:
#
#   1. Builds and pushes the SecPostureIQ Docker image to the customer's ACR
#   2. Creates an Entra ID App Registration with Graph API permissions
#   3. Stores Graph API credentials in Key Vault
#   4. Updates the Container App with the real image
#   5. Runs a health check
#
# Usage:
#   ./scripts/post-deploy-button.sh --resource-group <rg-name>
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Docker installed and running
#   - The "Deploy to Azure" button deployment completed successfully
#   - Permissions: Contributor + User Access Admin (or Owner) on the RG
#   - Global Admin or Privileged Role Admin for Graph API admin consent

set -euo pipefail

RESOURCE_GROUP=""
SKIP_BUILD=false
SKIP_APP_REG=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Parse CLI arguments ──────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --resource-group|-g) RESOURCE_GROUP="$2"; shift 2 ;;
    --skip-build)        SKIP_BUILD=true; shift ;;
    --skip-app-reg)      SKIP_APP_REG=true; shift ;;
    --help|-h)
      echo "SecPostureIQ — Post Deploy-to-Azure Button Setup"
      echo ""
      echo "Usage: $0 --resource-group <rg-name> [options]"
      echo ""
      echo "Options:"
      echo "  --resource-group, -g   Resource group created by the Deploy to Azure button (required)"
      echo "  --skip-build           Skip Docker build & push (if image already in ACR)"
      echo "  --skip-app-reg         Skip Entra ID App Registration (if already done)"
      echo "  --help                 Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1. Use --help for usage."
      exit 1
      ;;
  esac
done

# ── Banner ────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   SecPostureIQ — Post-Deployment Setup                 ║"
echo "║   Complete your Deploy-to-Azure deployment          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Pre-flight checks ────────────────────────────────────
echo "🔍 Pre-flight checks..."

if ! command -v az &>/dev/null; then
  echo "   ❌ Azure CLI not found. Install: https://aka.ms/installazurecli"
  exit 1
fi
echo "   ✅ Azure CLI"

ACCOUNT_INFO=$(az account show --query "{name:name, id:id, tenantId:tenantId}" -o json 2>/dev/null) || {
  echo "   ❌ Not logged in. Run: az login"
  exit 1
}
SUBSCRIPTION_NAME=$(echo "$ACCOUNT_INFO" | python3 -c 'import sys,json; print(json.load(sys.stdin)["name"])')
SUBSCRIPTION_ID=$(echo "$ACCOUNT_INFO" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
TENANT_ID=$(echo "$ACCOUNT_INFO" | python3 -c 'import sys,json; print(json.load(sys.stdin)["tenantId"])')
echo "   ✅ Logged in — $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"

if [[ "$SKIP_BUILD" != true ]]; then
  if ! command -v docker &>/dev/null; then
    echo "   ❌ Docker not found. Install Docker Desktop or use --skip-build."
    exit 1
  fi
  if ! docker info &>/dev/null 2>&1; then
    echo "   ❌ Docker daemon not running. Start Docker or use --skip-build."
    exit 1
  fi
  echo "   ✅ Docker"
fi

# ── Get resource group (prompt if not provided) ──────────
if [[ -z "$RESOURCE_GROUP" ]]; then
  echo ""
  echo "📋 Which resource group did you deploy to?"
  echo "   (This is the resource group you selected in the Azure Portal)"
  echo ""

  # List resource groups with secpostureiq tags or names
  echo "   Recent resource groups:"
  az group list --query "[?contains(name,'secpostureiq') || tags.project=='secpostureiq'].{Name:name, Location:location}" -o table 2>/dev/null || true
  echo ""

  read -rp "   Resource group name: " RESOURCE_GROUP
  if [[ -z "$RESOURCE_GROUP" ]]; then
    echo "   ❌ Resource group is required."
    exit 1
  fi
fi

# Verify resource group exists
az group show --name "$RESOURCE_GROUP" --output none 2>/dev/null || {
  echo "   ❌ Resource group '$RESOURCE_GROUP' not found."
  echo "      Make sure the Deploy to Azure button deployment completed successfully."
  exit 1
}
echo "   ✅ Resource group: $RESOURCE_GROUP"
echo ""

# ── Discover deployed resources ──────────────────────────
echo "🔎 Discovering deployed resources..."

ACR_NAME=$(az acr list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null || echo "")
if [[ -z "$ACR_NAME" ]]; then
  echo "   ❌ No Container Registry found in $RESOURCE_GROUP."
  echo "      The Deploy to Azure button may not have completed. Check the Azure Portal."
  exit 1
fi
ACR_LOGIN_SERVER=$(az acr show -n "$ACR_NAME" --query "loginServer" -o tsv)
echo "   ├── ACR: $ACR_NAME ($ACR_LOGIN_SERVER)"

KEY_VAULT_NAME=$(az keyvault list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null || echo "")
echo "   ├── Key Vault: ${KEY_VAULT_NAME:-⚠️  not found}"

CONTAINER_APP_NAME=$(az containerapp list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null || echo "")
CONTAINER_APP_FQDN=$(az containerapp show -n "$CONTAINER_APP_NAME" -g "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || echo "")
echo "   ├── Container App: ${CONTAINER_APP_NAME:-⚠️  not found}"

MANAGED_IDENTITY_NAME=$(az identity list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null || echo "")
MANAGED_IDENTITY_CLIENT_ID=$(az identity show -n "$MANAGED_IDENTITY_NAME" -g "$RESOURCE_GROUP" \
  --query "clientId" -o tsv 2>/dev/null || echo "")
echo "   └── Managed Identity: ${MANAGED_IDENTITY_NAME:-⚠️  not found}"

echo ""

# ══════════════════════════════════════════════════════════
# STEP 1: Build & Push Container Image
# ══════════════════════════════════════════════════════════

if [[ "$SKIP_BUILD" != true ]]; then
  echo "🐳 Step 1/3: Build & Push Container Image"

  GIT_SHA=$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "manual")
  FULL_IMAGE="${ACR_LOGIN_SERVER}/secpostureiq"

  echo "   🔑 Logging in to ACR ($ACR_NAME)..."
  az acr login --name "$ACR_NAME" 2>/dev/null

  echo "   🔨 Building image..."
  docker build \
    --build-arg GIT_SHA="$GIT_SHA" \
    --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -t "${FULL_IMAGE}:${GIT_SHA}" \
    -t "${FULL_IMAGE}:latest" \
    "$REPO_ROOT"

  echo "   📤 Pushing to ACR..."
  docker push "${FULL_IMAGE}:${GIT_SHA}"
  docker push "${FULL_IMAGE}:latest"

  echo "   ✅ Image pushed: ${FULL_IMAGE}:${GIT_SHA}"

  # Update Container App with the real image
  echo ""
  echo "   🔄 Updating Container App with SecPostureIQ image..."
  if [[ -n "$CONTAINER_APP_NAME" ]]; then
    az containerapp update \
      -n "$CONTAINER_APP_NAME" \
      -g "$RESOURCE_GROUP" \
      --image "${FULL_IMAGE}:${GIT_SHA}" \
      --output none 2>/dev/null
    echo "   ✅ Container App updated"
  else
    echo "   ⚠️  No Container App found — skipping update."
    echo "      You may need to redeploy via the portal or az containerapp create."
  fi
else
  echo "⏭️  Step 1/3: Skipping Docker build (--skip-build)"
fi

echo ""

# ══════════════════════════════════════════════════════════
# STEP 2: Entra ID App Registration + Graph API
# ══════════════════════════════════════════════════════════

if [[ "$SKIP_APP_REG" != true ]]; then
  echo "📝 Step 2/3: Entra ID App Registration"

  GRAPH_API_ID="00000003-0000-0000-c000-000000000000"
  APP_DISPLAY_NAME="SecPostureIQ - ME5 Security Assessment"

  # Check if app already exists
  EXISTING_APP_ID=$(az ad app list --display-name "$APP_DISPLAY_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

  if [[ -n "$EXISTING_APP_ID" ]]; then
    echo "   ⏭️  App Registration already exists: $EXISTING_APP_ID"
    APP_ID="$EXISTING_APP_ID"
  else
    APP_ID=$(az ad app create \
      --display-name "$APP_DISPLAY_NAME" \
      --sign-in-audience "AzureADMyOrg" \
      --query "appId" -o tsv)
    echo "   ✅ Created App Registration: $APP_ID"
  fi

  # Add all 8 Graph API permissions (read-only, least-privilege)
  echo "   🔑 Adding Graph API permissions..."

  declare -A PERMISSIONS=(
    ["SecurityEvents.Read.All"]="bf394140-e372-4bf9-a898-299cfc7564e5"
    ["SecurityActions.Read.All"]="1638cddf-07a5-4f16-928e-0b80f95e632c"
    ["Policy.Read.All"]="572fea84-0151-49b2-9301-11cb16974376"
    ["Reports.Read.All"]="02e97553-ed7b-43d0-ab3c-f8bace0d040c"
    ["InformationProtection.Read.All"]="d9731f5b-aca7-42d8-8aeb-0ac1bf55e2e9"
    ["RoleManagement.Read.Directory"]="741c54c3-0c1e-44a1-818b-3f97ab4e8c83"
    ["IdentityRiskyUser.Read.All"]="dc5007c0-2d7d-4c42-879c-2dab87571379"
    ["AccessReview.Read.All"]="ebfcd32b-babb-40f4-a14b-42706e83bd28"
  )

  PERM_ERRORS=0
  for perm_name in "${!PERMISSIONS[@]}"; do
    perm_id="${PERMISSIONS[$perm_name]}"
    az ad app permission add --id "$APP_ID" \
      --api "$GRAPH_API_ID" \
      --api-permissions "${perm_id}=Scope" \
      2>/dev/null || { echo "   ⚠️  Failed: $perm_name"; ((PERM_ERRORS++)); }
  done
  echo "   ✅ Permissions added ($((${#PERMISSIONS[@]} - PERM_ERRORS))/${#PERMISSIONS[@]} succeeded)"

  # Admin consent
  echo "   🔓 Granting admin consent..."
  az ad app permission admin-consent --id "$APP_ID" 2>/dev/null || {
    echo "   ⚠️  Admin consent requires Global Admin or Privileged Role Admin."
    echo "      Ask your tenant admin to run:"
    echo "      az ad app permission admin-consent --id $APP_ID"
  }

  # Create client secret
  echo "   🔐 Creating client secret (1 year)..."
  SECRET_OUTPUT=$(az ad app credential reset --id "$APP_ID" --years 1 \
    --query "{clientId: appId, tenantId: tenant, clientSecret: password}" -o json 2>/dev/null)

  CLIENT_ID=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientId"])')
  CLIENT_SECRET=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientSecret"])')

  # Store credentials in Key Vault
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
    echo "   ⚠️  No Key Vault found — printing credentials (save these!):"
    echo "      AZURE_TENANT_ID=$TENANT_ID"
    echo "      AZURE_CLIENT_ID=$CLIENT_ID"
    echo "      AZURE_CLIENT_SECRET=<stored securely — check az ad app credential list>"
  fi

  echo "   ✅ App Registration complete"
else
  echo "⏭️  Step 2/3: Skipping App Registration (--skip-app-reg)"
fi

echo ""

# ══════════════════════════════════════════════════════════
# STEP 3: Health Check
# ══════════════════════════════════════════════════════════

echo "🏥 Step 3/3: Health Check"

if [[ -n "$CONTAINER_APP_FQDN" ]]; then
  echo "   Waiting for Container App to be ready..."
  HEALTHY=false
  for i in {1..12}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${CONTAINER_APP_FQDN}/health" 2>/dev/null || echo "000")
    if [[ "$STATUS" == "200" ]]; then
      HEALTHY=true
      break
    fi
    echo "   ⏳ Attempt $i/12 — HTTP $STATUS (retrying in 15s)"
    sleep 15
  done

  if [[ "$HEALTHY" == true ]]; then
    echo "   ✅ Health check passed!"
  else
    echo "   ⚠️  Health check didn't pass within 3 minutes."
    echo "      The container may still be starting. Check logs:"
    echo "      az containerapp logs show -n $CONTAINER_APP_NAME -g $RESOURCE_GROUP"
  fi
else
  echo "   ⚠️  No Container App FQDN found — skipping health check."
fi

# ══════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   🎉 SecPostureIQ — Setup Complete!                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "   🌐 Application URL:    https://${CONTAINER_APP_FQDN:-<pending>}"
echo "   📦 Container Registry: $ACR_LOGIN_SERVER"
echo "   🔐 Key Vault:          ${KEY_VAULT_NAME:-N/A}"
echo "   📊 Resource Group:     $RESOURCE_GROUP"
echo ""
echo "   Next steps:"
echo "   1. Open https://${CONTAINER_APP_FQDN:-<app-url>} in your browser"
echo "   2. Try: 'What is our Secure Score?'"
echo "   3. Try: 'Generate a remediation plan'"
echo ""
echo "   To tear down all resources:"
echo "     az group delete --name $RESOURCE_GROUP --yes --no-wait"
echo ""
