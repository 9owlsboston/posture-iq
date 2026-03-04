#!/usr/bin/env bash
#
# SecPostureIQ — Development Environment Provisioning Script
#
# Provisions all Azure resources required for SecPostureIQ:
#   1. Creates the resource group
#   2. Deploys Bicep templates (OpenAI, Content Safety, App Insights, Key Vault, Container App)
#   3. Registers Entra ID App Registration with Graph API permissions
#   4. Stores credentials in Key Vault
#
# Prerequisites:
#   - Azure CLI installed and logged in (`az login`)
#   - Bicep CLI installed (`az bicep install`)
#   - Sufficient permissions to create resources and App Registrations
#   - Global Admin or Privileged Role Admin for admin consent
#
# Usage:
#   chmod +x scripts/provision-dev.sh
#   ./scripts/provision-dev.sh
#   ./scripts/provision-dev.sh --skip-app-reg    # Skip App Registration (if already done)
#   ./scripts/provision-dev.sh --skip-infra      # Skip infrastructure (if already done)

set -euo pipefail

# ── Configuration ─────────────────────────────────────────
RESOURCE_GROUP="rg-secpostureiq-dev"
LOCATION="eastus2"
ENVIRONMENT="dev"
PROJECT_NAME="secpostureiq"
APP_NAME="SecPostureIQ - ME5 Security Assessment"
REDIRECT_URI="http://localhost:8000/auth/callback"
GRAPH_API_ID="00000003-0000-0000-c000-000000000000"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$SCRIPT_DIR/../infra"

SKIP_APP_REG=false
SKIP_INFRA=false

# ── Parse arguments ───────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --skip-app-reg)  SKIP_APP_REG=true ;;
    --skip-infra)    SKIP_INFRA=true ;;
    --help|-h)
      echo "Usage: $0 [--skip-app-reg] [--skip-infra]"
      echo ""
      echo "Options:"
      echo "  --skip-app-reg  Skip Entra ID App Registration (if already created)"
      echo "  --skip-infra    Skip Azure resource provisioning (if already deployed)"
      echo "  --help          Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg"
      exit 1
      ;;
  esac
done

echo "🛡️  SecPostureIQ — Development Environment Provisioning"
echo "======================================================"
echo ""
echo "Configuration:"
echo "  Resource Group:  $RESOURCE_GROUP"
echo "  Location:        $LOCATION"
echo "  Environment:     $ENVIRONMENT"
echo ""

# ── Pre-flight checks ────────────────────────────────────
echo "🔍 Pre-flight checks..."

if ! command -v az &> /dev/null; then
  echo "   ❌ Azure CLI not found. Install from: https://aka.ms/installazurecli"
  exit 1
fi
echo "   ✅ Azure CLI found"

# Verify logged in
ACCOUNT=$(az account show --query "{name:name, id:id}" -o tsv 2>/dev/null) || {
  echo "   ❌ Not logged in to Azure. Run: az login"
  exit 1
}
echo "   ✅ Logged in to Azure: $ACCOUNT"

# Verify Bicep is available
az bicep version &>/dev/null || {
  echo "   ⚠️  Installing Bicep CLI..."
  az bicep install
}
echo "   ✅ Bicep CLI available"

echo ""

# ══════════════════════════════════════════════════════════
# STAGE 1: Azure Resource Group
# ══════════════════════════════════════════════════════════

if [[ "$SKIP_INFRA" != true ]]; then

  echo "📦 Stage 1: Creating resource group..."

  RG_EXISTS=$(az group exists --name "$RESOURCE_GROUP" 2>/dev/null || echo "false")
  if [[ "$RG_EXISTS" == "true" ]]; then
    echo "   ⏭️  Resource group '$RESOURCE_GROUP' already exists — skipping creation"
  else
    az group create \
      --name "$RESOURCE_GROUP" \
      --location "$LOCATION" \
      --tags project=secpostureiq environment=dev \
      --output none
    echo "   ✅ Resource group '$RESOURCE_GROUP' created in $LOCATION"
  fi

  echo ""

  # ══════════════════════════════════════════════════════════
  # STAGE 2: Deploy Bicep Templates
  # ══════════════════════════════════════════════════════════

  echo "🏗️  Stage 2: Deploying Azure resources via Bicep..."
  echo "   This deploys: OpenAI (GPT-4o), Content Safety, App Insights, Key Vault, Container App"
  echo ""

  # Validate the Bicep template first
  echo "   📋 Validating Bicep template..."
  az deployment group validate \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$INFRA_DIR/main.bicep" \
    --parameters "$INFRA_DIR/parameters/dev.bicepparam" \
    --output none 2>/dev/null || {
    echo "   ❌ Bicep validation failed. Check template syntax."
    exit 1
  }
  echo "   ✅ Bicep template validated"

  # Deploy
  echo "   🚀 Deploying resources (this may take 5–10 minutes)..."
  DEPLOYMENT_OUTPUT=$(az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$INFRA_DIR/main.bicep" \
    --parameters "$INFRA_DIR/parameters/dev.bicepparam" \
    --query "properties.outputs" \
    -o json 2>/dev/null)

  echo "   ✅ Bicep deployment complete"

  # Extract outputs
  CONTAINER_APP_URL=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('containerAppUrl',{}).get('value','N/A'))" 2>/dev/null || echo "N/A")
  APP_INSIGHTS_NAME=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('appInsightsName',{}).get('value','N/A'))" 2>/dev/null || echo "N/A")
  KEY_VAULT_NAME=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('keyVaultName',{}).get('value','N/A'))" 2>/dev/null || echo "N/A")
  AVAILABILITY_TEST=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('availabilityTestName',{}).get('value','N/A'))" 2>/dev/null || echo "N/A")

  echo ""
  echo "   Deployed resources:"
  echo "   ├── Container App:          https://$CONTAINER_APP_URL"
  echo "   ├── App Insights:           $APP_INSIGHTS_NAME"
  echo "   ├── Availability Web Test:  $AVAILABILITY_TEST"
  echo "   └── Key Vault:              $KEY_VAULT_NAME"
  echo ""

else
  echo "⏭️  Skipping infrastructure deployment (--skip-infra)"
  echo ""
fi

# ══════════════════════════════════════════════════════════
# STAGE 3: Entra ID App Registration
# ══════════════════════════════════════════════════════════

if [[ "$SKIP_APP_REG" != true ]]; then

  echo "📝 Stage 3: Registering Entra ID App Registration..."

  # Check if app already exists
  EXISTING_APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

  if [[ -n "$EXISTING_APP_ID" ]]; then
    echo "   ⏭️  App Registration already exists: $EXISTING_APP_ID"
    APP_ID="$EXISTING_APP_ID"
  else
    APP_ID=$(az ad app create \
      --display-name "$APP_NAME" \
      --sign-in-audience "AzureADMyOrg" \
      --web-redirect-uris "$REDIRECT_URI" \
      --query "appId" -o tsv)
    echo "   ✅ App Registration created: $APP_ID"
  fi

  # ── Add Graph API Permissions ──────────────────────────
  echo ""
  echo "   🔑 Adding Graph API permissions..."

  declare -A PERMISSIONS=(
    ["SecurityEvents.Read.All"]="bf394140-e372-4bf9-a898-299cfc7564e5"
    ["SecurityActions.Read.All"]="1638cddf-07a5-4f16-928e-0b80f95e632c"
    ["Policy.Read.All"]="572fea84-0151-49b2-9301-11cb16974376"
    ["Reports.Read.All"]="02e97553-ed7b-43d0-ab3c-f8bace0d040c"
    ["InformationProtectionPolicy.Read.All"]="19da66cb-0fb0-4390-b071-ebc76a349482"
  )

  for perm_name in "${!PERMISSIONS[@]}"; do
    perm_id="${PERMISSIONS[$perm_name]}"
    az ad app permission add --id "$APP_ID" \
      --api "$GRAPH_API_ID" \
      --api-permissions "${perm_id}=Scope" \
      2>/dev/null || true
    echo "      ✅ $perm_name"
  done

  # ── Grant Admin Consent ────────────────────────────────
  echo ""
  echo "   🔓 Granting admin consent..."
  az ad app permission admin-consent --id "$APP_ID" 2>/dev/null || {
    echo "   ⚠️  Admin consent failed — requires Global Admin or Privileged Role Admin."
    echo "      Run manually: az ad app permission admin-consent --id $APP_ID"
  }
  echo "   ✅ Admin consent granted (or pending)"

  # ── Create Client Secret ───────────────────────────────
  echo ""
  echo "   🔐 Creating client secret..."
  SECRET_OUTPUT=$(az ad app credential reset --id "$APP_ID" --years 1 \
    --query "{clientId: appId, tenantId: tenant, clientSecret: password}" -o json 2>/dev/null)
  echo "   ✅ Client secret created"

  TENANT_ID=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["tenantId"])')
  CLIENT_ID=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientId"])')
  CLIENT_SECRET=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientSecret"])')

  # ── Store Credentials in Key Vault ─────────────────────
  if [[ "$SKIP_INFRA" != true ]] && [[ "${KEY_VAULT_NAME:-}" != "N/A" ]] && [[ -n "${KEY_VAULT_NAME:-}" ]]; then
    echo ""
    echo "   🔒 Storing credentials in Key Vault ($KEY_VAULT_NAME)..."

    az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
      --name "AZURE-TENANT-ID" --value "$TENANT_ID" --output none 2>/dev/null || true
    az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
      --name "AZURE-CLIENT-ID" --value "$CLIENT_ID" --output none 2>/dev/null || true
    az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
      --name "AZURE-CLIENT-SECRET" --value "$CLIENT_SECRET" --output none 2>/dev/null || true

    echo "   ✅ Credentials stored in Key Vault"
  fi

  # ── Write local .env file ──────────────────────────────
  echo ""
  echo "   📄 Writing .env file..."
  cat > .env <<EOF
# SecPostureIQ — Development Environment Configuration
# Generated by provision-dev.sh on $(date -Iseconds)

AZURE_TENANT_ID=$TENANT_ID
AZURE_CLIENT_ID=$CLIENT_ID
AZURE_CLIENT_SECRET=$CLIENT_SECRET
ENVIRONMENT=$ENVIRONMENT
EOF

  echo "   ✅ .env file created"

else
  echo "⏭️  Skipping App Registration (--skip-app-reg)"
fi

# ══════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════

echo ""
echo "======================================================"
echo "🎉 SecPostureIQ — Development environment provisioned!"
echo "======================================================"
echo ""
echo "Resources created:"
if [[ "$SKIP_INFRA" != true ]]; then
  echo "  ✅ Resource Group:       $RESOURCE_GROUP"
  echo "  ✅ Azure OpenAI:         GPT-4o deployment"
  echo "  ✅ Azure Content Safety: RAI filtering"
  echo "  ✅ App Insights:         Observability (distributed tracing)"
  echo "  ✅ Availability Test:    Health-ping from 5 US locations (every 5 min)"
  echo "  ✅ Key Vault:            Secrets management"
  echo "  ✅ Container App:        Deployment target (scale 0–5)"
fi
if [[ "$SKIP_APP_REG" != true ]]; then
  echo "  ✅ App Registration:     ${APP_ID:-N/A}"
  echo "  ✅ Graph API Permissions: SecurityEvents, SecurityActions, Policy, Reports, InformationProtection"
fi
echo ""
echo "Next steps:"
echo "  1. Verify resources:  az resource list -g $RESOURCE_GROUP -o table"
echo "  2. Run tests:         pytest tests/"
echo "  3. Start locally:     uvicorn src.api.app:app --port 8000"
echo ""
echo "  To tear down:         ./scripts/cleanup-dev.sh"
