#!/usr/bin/env bash
#
# PostureIQ — Customer Deployment Script
#
# One-command deployment for customer Azure tenants.
# No forking, no CI/CD pipeline, no OIDC setup required.
#
# What this script does:
#   1. Prompts for customer-specific values (or accepts CLI args)
#   2. Creates a resource group
#   3. Deploys all Azure resources via Bicep (OpenAI, Content Safety, ACR, etc.)
#   4. Builds and pushes the container image to the customer's ACR
#   5. Registers Entra ID App Registration with Graph API permissions
#   6. Deploys the container to Azure Container Apps
#   7. Runs a health check and prints the live URL
#
# Usage:
#   git clone https://github.com/<your-org>/posture-iq.git
#   cd posture-iq
#   chmod +x scripts/deploy-customer.sh
#   ./scripts/deploy-customer.sh
#
# Non-interactive mode (for automation):
#   ./scripts/deploy-customer.sh \
#     --customer-name contoso \
#     --location eastus2 \
#     --environment prod \
#     --skip-app-reg
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Docker installed and running (for container build)
#   - Sufficient Azure permissions (Contributor + User Access Admin on subscription)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────
CUSTOMER_NAME=""
LOCATION=""
ENVIRONMENT="prod"
PROJECT_NAME="postureiq"
SKIP_APP_REG=false
SKIP_BUILD=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INFRA_DIR="$REPO_ROOT/infra"

# ── Parse CLI arguments ──────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --customer-name)  CUSTOMER_NAME="$2"; shift 2 ;;
    --location)       LOCATION="$2"; shift 2 ;;
    --environment)    ENVIRONMENT="$2"; shift 2 ;;
    --skip-app-reg)   SKIP_APP_REG=true; shift ;;
    --skip-build)     SKIP_BUILD=true; shift ;;
    --help|-h)
      echo "PostureIQ — Customer Deployment"
      echo ""
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --customer-name NAME   Customer short name (e.g., contoso). Used in resource naming."
      echo "  --location REGION      Azure region (e.g., eastus2, westus3, centralus)"
      echo "  --environment ENV      Environment: dev, staging, prod (default: prod)"
      echo "  --skip-app-reg         Skip Entra ID App Registration (if already done)"
      echo "  --skip-build           Skip Docker build (use existing image in ACR)"
      echo "  --help                 Show this help message"
      echo ""
      echo "If options are omitted, the script will prompt interactively."
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
echo "║   PostureIQ — Customer Azure Deployment             ║"
echo "║   ME5 Security Posture Assessment Agent             ║"
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
echo "   ✅ Logged in — Subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"
echo "   ✅ Tenant: $TENANT_ID"

az bicep version &>/dev/null || {
  echo "   ⚠️  Installing Bicep CLI..."
  az bicep install
}
echo "   ✅ Bicep CLI"

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

echo ""

# ── Interactive prompts (if values not provided via CLI) ──
if [[ -z "$CUSTOMER_NAME" ]]; then
  echo "📋 Configuration"
  echo ""
  read -rp "   Customer short name (e.g., contoso, fabrikam): " CUSTOMER_NAME
  if [[ -z "$CUSTOMER_NAME" ]]; then
    echo "   ❌ Customer name is required."
    exit 1
  fi
fi

# Sanitize: lowercase, alphanumeric + hyphens only
CUSTOMER_NAME=$(echo "$CUSTOMER_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')

if [[ -z "$LOCATION" ]]; then
  echo ""
  echo "   Available regions (common choices):"
  echo "     1) eastus2        4) westeurope"
  echo "     2) centralus      5) northeurope"
  echo "     3) westus3        6) southeastasia"
  echo ""
  read -rp "   Azure region [eastus2]: " LOCATION
  LOCATION=${LOCATION:-eastus2}
fi

echo ""

# ── Derived names ────────────────────────────────────────
RESOURCE_GROUP="rg-${PROJECT_NAME}-${CUSTOMER_NAME}"
CONTAINER_IMAGE_NAME="postureiq"
APP_NAME="PostureIQ - ${CUSTOMER_NAME}"
GIT_SHA=$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "manual")
IMAGE_TAG="$GIT_SHA"

echo "   Configuration:"
echo "   ├── Customer:        $CUSTOMER_NAME"
echo "   ├── Resource Group:  $RESOURCE_GROUP"
echo "   ├── Location:        $LOCATION"
echo "   ├── Environment:     $ENVIRONMENT"
echo "   ├── Image Tag:       $IMAGE_TAG"
echo "   └── Subscription:    $SUBSCRIPTION_NAME"
echo ""

read -rp "   Proceed with deployment? [Y/n]: " CONFIRM
CONFIRM=${CONFIRM:-Y}
if [[ "$CONFIRM" != [Yy]* ]]; then
  echo "   Cancelled."
  exit 0
fi

echo ""

# ══════════════════════════════════════════════════════════
# STAGE 1: Resource Group
# ══════════════════════════════════════════════════════════

echo "📦 Stage 1/5: Resource Group"

RG_EXISTS=$(az group exists --name "$RESOURCE_GROUP" 2>/dev/null || echo "false")
if [[ "$RG_EXISTS" == "true" ]]; then
  echo "   ⏭️  '$RESOURCE_GROUP' already exists — reusing"
else
  az group create \
    --name "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --tags project=postureiq customer="$CUSTOMER_NAME" environment="$ENVIRONMENT" \
    --output none
  echo "   ✅ Created '$RESOURCE_GROUP' in $LOCATION"
fi

echo ""

# ══════════════════════════════════════════════════════════
# STAGE 2: Deploy Infrastructure (Bicep)
# ══════════════════════════════════════════════════════════

echo "🏗️  Stage 2/5: Deploy Azure Infrastructure"
echo "   Resources: OpenAI (GPT-4o), Content Safety, App Insights, Key Vault, ACR, Container App"
echo ""

# Generate a customer-specific parameter override file
PARAM_FILE=$(mktemp /tmp/postureiq-params-XXXXX.json)
cat > "$PARAM_FILE" <<EOF
{
  "\$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "environment": { "value": "$ENVIRONMENT" },
    "location": { "value": "$LOCATION" },
    "projectName": { "value": "$PROJECT_NAME" }
  }
}
EOF

echo "   📋 Validating Bicep template..."
az deployment group validate \
  --resource-group "$RESOURCE_GROUP" \
  --template-file "$INFRA_DIR/main.bicep" \
  --parameters @"$PARAM_FILE" \
  --output none || {
  echo "   ❌ Bicep validation failed."
  rm -f "$PARAM_FILE"
  exit 1
}
echo "   ✅ Template validated"

echo "   🚀 Deploying resources (this takes 5–10 minutes)..."
DEPLOYMENT_OUTPUT=$(az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --template-file "$INFRA_DIR/main.bicep" \
  --parameters @"$PARAM_FILE" \
  --query "properties.outputs" \
  -o json 2>/dev/null)

rm -f "$PARAM_FILE"

# Extract outputs
CONTAINER_APP_URL=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('containerAppUrl',{}).get('value',''))" 2>/dev/null || echo "")
APP_INSIGHTS_NAME=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('appInsightsName',{}).get('value',''))" 2>/dev/null || echo "")
KEY_VAULT_NAME=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('keyVaultName',{}).get('value',''))" 2>/dev/null || echo "")
ACR_LOGIN_SERVER=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('acrLoginServer',{}).get('value',''))" 2>/dev/null || echo "")
ACR_NAME=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('acrName',{}).get('value',''))" 2>/dev/null || echo "")
MANAGED_IDENTITY_CLIENT_ID=$(echo "$DEPLOYMENT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('managedIdentityClientId',{}).get('value',''))" 2>/dev/null || echo "")

echo "   ✅ Infrastructure deployed"
echo ""
echo "   ├── Container App:  https://$CONTAINER_APP_URL"
echo "   ├── ACR:            $ACR_LOGIN_SERVER"
echo "   ├── App Insights:   $APP_INSIGHTS_NAME"
echo "   └── Key Vault:      $KEY_VAULT_NAME"

echo ""

# ══════════════════════════════════════════════════════════
# STAGE 3: Build & Push Container Image
# ══════════════════════════════════════════════════════════

if [[ "$SKIP_BUILD" != true ]]; then
  echo "🐳 Stage 3/5: Build & Push Container Image"

  echo "   🔑 Logging in to ACR ($ACR_NAME)..."
  az acr login --name "$ACR_NAME" 2>/dev/null

  FULL_IMAGE="${ACR_LOGIN_SERVER}/${CONTAINER_IMAGE_NAME}"

  echo "   🔨 Building image..."
  docker build \
    --build-arg GIT_SHA="$GIT_SHA" \
    --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -t "${FULL_IMAGE}:${IMAGE_TAG}" \
    -t "${FULL_IMAGE}:latest" \
    "$REPO_ROOT"

  echo "   📤 Pushing to ACR..."
  docker push "${FULL_IMAGE}:${IMAGE_TAG}"
  docker push "${FULL_IMAGE}:latest"

  echo "   ✅ Image pushed: ${FULL_IMAGE}:${IMAGE_TAG}"

  # Update Container App with the new image
  echo ""
  echo "   🔄 Updating Container App with new image..."
  az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$INFRA_DIR/main.bicep" \
    --parameters \
      environment="$ENVIRONMENT" \
      location="$LOCATION" \
      projectName="$PROJECT_NAME" \
      containerImage="${FULL_IMAGE}:${IMAGE_TAG}" \
    --output none 2>/dev/null

  echo "   ✅ Container App updated"
else
  echo "⏭️  Stage 3/5: Skipping Docker build (--skip-build)"
fi

echo ""

# ══════════════════════════════════════════════════════════
# STAGE 4: Entra ID App Registration (Graph API access)
# ══════════════════════════════════════════════════════════

if [[ "$SKIP_APP_REG" != true ]]; then
  echo "📝 Stage 4/5: Entra ID App Registration"

  GRAPH_API_ID="00000003-0000-0000-c000-000000000000"

  # Check if app already exists
  EXISTING_APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

  if [[ -n "$EXISTING_APP_ID" ]]; then
    echo "   ⏭️  App Registration exists: $EXISTING_APP_ID"
    APP_ID="$EXISTING_APP_ID"
  else
    APP_ID=$(az ad app create \
      --display-name "$APP_NAME" \
      --sign-in-audience "AzureADMyOrg" \
      --query "appId" -o tsv)
    echo "   ✅ Created App Registration: $APP_ID"
  fi

  # Add Graph API permissions (read-only)
  echo "   🔑 Adding Graph API permissions (read-only)..."
  declare -A PERMISSIONS=(
    ["SecurityEvents.Read.All"]="bf394140-e372-4bf9-a898-299cfc7564e5"
    ["SecurityActions.Read.All"]="1638cddf-07a5-4f16-928e-0b80f95e632c"
    ["Policy.Read.All"]="572fea84-0151-49b2-9301-11cb16974376"
    ["Reports.Read.All"]="02e97553-ed7b-43d0-ab3c-f8bace0d040c"
    ["InformationProtection.Read.All"]="d9731f5b-aca7-42d8-8aeb-0ac1bf55e2e9"
  )

  for perm_name in "${!PERMISSIONS[@]}"; do
    perm_id="${PERMISSIONS[$perm_name]}"
    az ad app permission add --id "$APP_ID" \
      --api "$GRAPH_API_ID" \
      --api-permissions "${perm_id}=Scope" \
      2>/dev/null || true
  done
  echo "   ✅ Permissions added: ${!PERMISSIONS[*]}"

  # Admin consent
  echo "   🔓 Granting admin consent..."
  az ad app permission admin-consent --id "$APP_ID" 2>/dev/null || {
    echo "   ⚠️  Admin consent requires Global Admin. Run manually:"
    echo "      az ad app permission admin-consent --id $APP_ID"
  }

  # Create client secret
  echo "   🔐 Creating client secret..."
  SECRET_OUTPUT=$(az ad app credential reset --id "$APP_ID" --years 1 \
    --query "{clientId: appId, tenantId: tenant, clientSecret: password}" -o json 2>/dev/null)

  CLIENT_ID=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientId"])')
  CLIENT_SECRET=$(echo "$SECRET_OUTPUT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["clientSecret"])')

  # Store in Key Vault
  if [[ -n "$KEY_VAULT_NAME" ]]; then
    echo "   🔒 Storing credentials in Key Vault..."
    az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
      --name "AZURE-TENANT-ID" --value "$TENANT_ID" --output none 2>/dev/null || true
    az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
      --name "AZURE-CLIENT-ID" --value "$CLIENT_ID" --output none 2>/dev/null || true
    az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
      --name "AZURE-CLIENT-SECRET" --value "$CLIENT_SECRET" --output none 2>/dev/null || true
    echo "   ✅ Credentials stored in Key Vault ($KEY_VAULT_NAME)"
  fi

  echo "   ✅ App Registration complete"
else
  echo "⏭️  Stage 4/5: Skipping App Registration (--skip-app-reg)"
fi

echo ""

# ══════════════════════════════════════════════════════════
# STAGE 5: Health Check
# ══════════════════════════════════════════════════════════

echo "🏥 Stage 5/5: Health Check"

if [[ -n "$CONTAINER_APP_URL" ]]; then
  echo "   Waiting for Container App to be ready..."
  HEALTHY=false
  for i in {1..12}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${CONTAINER_APP_URL}/health" 2>/dev/null || echo "000")
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
    echo "      The container may still be pulling/starting. Check:"
    echo "      az containerapp logs show -n ${PROJECT_NAME}-${ENVIRONMENT}-app -g $RESOURCE_GROUP"
  fi
fi

# ══════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   🎉 PostureIQ — Deployment Complete!               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "   🌐 Application URL:   https://$CONTAINER_APP_URL"
echo "   📊 App Insights:      $APP_INSIGHTS_NAME"
echo "   🔐 Key Vault:         $KEY_VAULT_NAME"
echo "   📦 Container Registry: $ACR_LOGIN_SERVER"
echo "   🏷️  Image Tag:         $IMAGE_TAG"
echo ""
echo "   Resource Group:  $RESOURCE_GROUP"
echo "   Subscription:    $SUBSCRIPTION_ID"
echo "   Tenant:          $TENANT_ID"
echo ""
if [[ "$SKIP_APP_REG" != true ]] && [[ -n "${CLIENT_ID:-}" ]]; then
  echo "   ⚠️  App Registration credentials (save these!):"
  echo "   ├── Client ID:     $CLIENT_ID"
  echo "   └── Client Secret: (stored in Key Vault: $KEY_VAULT_NAME)"
fi
echo ""
echo "   Next steps:"
echo "   1. Open https://$CONTAINER_APP_URL in your browser"
echo "   2. Try: 'What is our Secure Score?'"
echo "   3. Try: 'Generate a remediation plan'"
echo ""
echo "   To update later:"
echo "     git pull && ./scripts/deploy-customer.sh --customer-name $CUSTOMER_NAME --location $LOCATION --skip-app-reg"
echo ""
echo "   To tear down:"
echo "     az group delete --name $RESOURCE_GROUP --yes --no-wait"
echo ""
