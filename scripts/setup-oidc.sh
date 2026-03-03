#!/usr/bin/env bash
#
# SecPostureIQ — OIDC Workload Identity Federation Setup
#
# Configures the existing Entra ID App Registration with:
#   1. A service principal (if not already created)
#   2. Federated credential for GitHub Actions OIDC
#   3. Contributor role on the resource group
#   4. AcrPush role on the container registry (once provisioned)
#
# After running this script, configure these GitHub repo secrets:
#   AZURE_CLIENT_ID        — App Registration client ID
#   AZURE_TENANT_ID        — Entra ID tenant ID
#   AZURE_SUBSCRIPTION_ID  — Azure subscription ID
#
# NO passwords or tokens need to be stored — that's the point of OIDC.
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - GitHub CLI installed and logged in (gh auth login)
#   - Permissions to manage App Registrations and role assignments
#
# Usage:
#   chmod +x scripts/setup-oidc.sh
#   ./scripts/setup-oidc.sh
#   ./scripts/setup-oidc.sh --skip-github   # Skip GitHub secret setup

set -euo pipefail

RESOURCE_GROUP="rg-secpostureiq-dev"
APP_NAME="SecPostureIQ - ME5 Security Assessment"
GITHUB_REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo '')}"
if [[ -z "$GITHUB_REPO" ]]; then
  echo "❌ Could not detect GitHub repo. Pass it as first argument: $0 <org/repo>"
  exit 1
fi
SKIP_GITHUB=false

for arg in "$@"; do
  case $arg in
    --skip-github) SKIP_GITHUB=true ;;
    --help|-h)
      echo "Usage: $0 [--skip-github]"
      echo ""
      echo "  --skip-github  Skip GitHub Actions secret configuration"
      exit 0
      ;;
  esac
done

echo "🔐 SecPostureIQ — OIDC Workload Identity Federation Setup"
echo "======================================================="
echo ""

# ── Step 1: Get existing App Registration ─────────────────
echo "📝 Step 1: Looking up App Registration..."

APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null)
if [[ -z "$APP_ID" ]]; then
  echo "   ❌ App Registration '$APP_NAME' not found"
  echo "   Run ./scripts/setup-permissions.sh first to create it"
  exit 1
fi
echo "   ✅ Found: $APP_ID"

OBJECT_ID=$(az ad app show --id "$APP_ID" --query "id" -o tsv)
TENANT_ID=$(az account show --query "tenantId" -o tsv)
SUBSCRIPTION_ID=$(az account show --query "id" -o tsv)

# ── Step 2: Ensure service principal exists ───────────────
echo ""
echo "📝 Step 2: Ensuring service principal exists..."

SP_ID=$(az ad sp show --id "$APP_ID" --query "id" -o tsv 2>/dev/null || echo "")
if [[ -z "$SP_ID" ]]; then
  SP_ID=$(az ad sp create --id "$APP_ID" --query "id" -o tsv)
  echo "   ✅ Service principal created: $SP_ID"
else
  echo "   ✅ Service principal exists: $SP_ID"
fi

# ── Step 3: Add federated credential for GitHub Actions ───
echo ""
echo "📝 Step 3: Configuring federated credential for GitHub Actions OIDC..."

# Check if a federated credential already exists for this repo
EXISTING_CRED=$(az ad app federated-credential list --id "$OBJECT_ID" \
  --query "[?subject=='repo:${GITHUB_REPO}:ref:refs/heads/main'].name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_CRED" ]]; then
  echo "   ⏭️  Federated credential already exists: $EXISTING_CRED"
else
  az ad app federated-credential create --id "$OBJECT_ID" --parameters '{
    "name": "github-actions-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:'"$GITHUB_REPO"':ref:refs/heads/main",
    "description": "GitHub Actions OIDC for SecPostureIQ main branch deployments",
    "audiences": ["api://AzureADTokenExchange"]
  }' > /dev/null
  echo "   ✅ Federated credential created for: repo:${GITHUB_REPO}:ref:refs/heads/main"
fi

# Also add a credential for PR environments (pull_request events)
EXISTING_PR_CRED=$(az ad app federated-credential list --id "$OBJECT_ID" \
  --query "[?contains(subject, 'pull_request')].name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_PR_CRED" ]]; then
  echo "   ⏭️  PR federated credential already exists: $EXISTING_PR_CRED"
else
  az ad app federated-credential create --id "$OBJECT_ID" --parameters '{
    "name": "github-actions-pr",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:'"$GITHUB_REPO"':pull_request",
    "description": "GitHub Actions OIDC for SecPostureIQ PR preview deployments",
    "audiences": ["api://AzureADTokenExchange"]
  }' > /dev/null
  echo "   ✅ Federated credential created for: repo:${GITHUB_REPO}:pull_request"
fi

# Add credential for the production environment (environment-scoped)
EXISTING_ENV_CRED=$(az ad app federated-credential list --id "$OBJECT_ID" \
  --query "[?contains(subject, 'environment:production')].name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_ENV_CRED" ]]; then
  echo "   ⏭️  Production env federated credential already exists: $EXISTING_ENV_CRED"
else
  az ad app federated-credential create --id "$OBJECT_ID" --parameters '{
    "name": "github-actions-production",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:'"$GITHUB_REPO"':environment:production",
    "description": "GitHub Actions OIDC for SecPostureIQ production deployments",
    "audiences": ["api://AzureADTokenExchange"]
  }' > /dev/null
  echo "   ✅ Federated credential created for: repo:${GITHUB_REPO}:environment:production"
fi

# ── Step 4: Assign Contributor role on resource group ─────
echo ""
echo "📝 Step 4: Assigning Contributor role on resource group..."

# Ensure resource group exists
RG_EXISTS=$(az group exists --name "$RESOURCE_GROUP" 2>/dev/null || echo "false")
if [[ "$RG_EXISTS" != "true" ]]; then
  echo "   ⚠️  Resource group '$RESOURCE_GROUP' does not exist yet"
  echo "   Role assignment will be done after provisioning (via Bicep or manual)"
else
  EXISTING_ROLE=$(az role assignment list \
    --assignee "$SP_ID" \
    --resource-group "$RESOURCE_GROUP" \
    --role "Contributor" \
    --query "[0].id" -o tsv 2>/dev/null || echo "")

  if [[ -n "$EXISTING_ROLE" ]]; then
    echo "   ⏭️  Contributor role already assigned"
  else
    az role assignment create \
      --assignee-object-id "$SP_ID" \
      --assignee-principal-type "ServicePrincipal" \
      --role "Contributor" \
      --resource-group "$RESOURCE_GROUP" > /dev/null
    echo "   ✅ Contributor role assigned on $RESOURCE_GROUP"
  fi
fi

# ── Step 5: Configure GitHub repo secrets ─────────────────
if [[ "$SKIP_GITHUB" == true ]]; then
  echo ""
  echo "⏭️  Skipping GitHub secret setup (--skip-github)"
else
  echo ""
  echo "📝 Step 5: Configuring GitHub repo secrets..."

  # Check if gh is available
  if ! command -v gh &>/dev/null; then
    echo "   ⚠️  GitHub CLI (gh) not found — set secrets manually:"
    echo ""
    echo "   gh secret set AZURE_CLIENT_ID --body \"$APP_ID\""
    echo "   gh secret set AZURE_TENANT_ID --body \"$TENANT_ID\""
    echo "   gh secret set AZURE_SUBSCRIPTION_ID --body \"$SUBSCRIPTION_ID\""
  else
    gh secret set AZURE_CLIENT_ID --repo "$GITHUB_REPO" --body "$APP_ID" 2>/dev/null
    echo "   ✅ AZURE_CLIENT_ID"

    gh secret set AZURE_TENANT_ID --repo "$GITHUB_REPO" --body "$TENANT_ID" 2>/dev/null
    echo "   ✅ AZURE_TENANT_ID"

    gh secret set AZURE_SUBSCRIPTION_ID --repo "$GITHUB_REPO" --body "$SUBSCRIPTION_ID" 2>/dev/null
    echo "   ✅ AZURE_SUBSCRIPTION_ID"
  fi
fi

# ── Summary ───────────────────────────────────────────────
echo ""
echo "======================================================="
echo "✅ OIDC Workload Identity Federation setup complete!"
echo ""
echo "Summary:"
echo "  App Registration:  $APP_NAME"
echo "  Client ID:         $APP_ID"
echo "  Tenant ID:         $TENANT_ID"
echo "  Subscription ID:   $SUBSCRIPTION_ID"
echo "  Service Principal: $SP_ID"
echo ""
echo "Federated credentials configured for:"
echo "  • repo:${GITHUB_REPO}:ref:refs/heads/main          (push to main)"
echo "  • repo:${GITHUB_REPO}:pull_request                 (PR previews)"
echo "  • repo:${GITHUB_REPO}:environment:production        (deploy stage)"
echo ""
echo "GitHub Actions secrets needed (3 non-sensitive IDs):"
echo "  AZURE_CLIENT_ID        = $APP_ID"
echo "  AZURE_TENANT_ID        = $TENANT_ID"
echo "  AZURE_SUBSCRIPTION_ID  = $SUBSCRIPTION_ID"
echo ""
echo "Zero passwords or tokens stored. 🔒"
echo ""
echo "Next steps:"
echo "  1. Provision resources:  az deployment group create -g $RESOURCE_GROUP -f infra/main.bicep -p infra/parameters/dev.bicepparam"
echo "  2. Push to main — CI/CD will build, push to ACR, and deploy automatically"
