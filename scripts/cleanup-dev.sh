#!/usr/bin/env bash
#
# SecPostureIQ — Cleanup Script
#
# Deletes all Azure development resources provisioned by the Bicep templates.
# Supports deleting the entire resource group or individual resources.
#
# Usage:
#   ./scripts/cleanup-dev.sh              # Interactive — prompts before deleting
#   ./scripts/cleanup-dev.sh --yes        # Skip confirmation (CI/automation)
#   ./scripts/cleanup-dev.sh --app-only   # Delete only the Entra ID App Registration
#   ./scripts/cleanup-dev.sh --rg-only    # Delete only the resource group (keep App Registration)

set -euo pipefail

RESOURCE_GROUP="rg-secpostureiq-dev"
APP_NAME="SecPostureIQ - ME5 Security Assessment"
AUTO_CONFIRM=false
APP_ONLY=false
RG_ONLY=false

# ── Parse arguments ───────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --yes)       AUTO_CONFIRM=true ;;
    --app-only)  APP_ONLY=true ;;
    --rg-only)   RG_ONLY=true ;;
    --help|-h)
      echo "Usage: $0 [--yes] [--app-only] [--rg-only]"
      echo ""
      echo "Options:"
      echo "  --yes       Skip confirmation prompts"
      echo "  --app-only  Delete only the Entra ID App Registration"
      echo "  --rg-only   Delete only the resource group (keep App Registration)"
      echo "  --help      Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg"
      exit 1
      ;;
  esac
done

confirm() {
  if [[ "$AUTO_CONFIRM" == true ]]; then
    return 0
  fi
  read -rp "$1 [y/N]: " response
  [[ "$response" =~ ^[Yy]$ ]]
}

echo "🧹 SecPostureIQ — Development Resource Cleanup"
echo "============================================="

# ── Show what exists ──────────────────────────────────────
echo ""
echo "📋 Current resources:"

RG_EXISTS=$(az group exists --name "$RESOURCE_GROUP" 2>/dev/null || echo "false")
if [[ "$RG_EXISTS" == "true" ]]; then
  echo "   Resource group: $RESOURCE_GROUP ✅"
  az resource list --resource-group "$RESOURCE_GROUP" \
    --query "[].{Name:name, Type:type}" -o table 2>/dev/null | sed 's/^/   /'
else
  echo "   Resource group: $RESOURCE_GROUP ❌ (not found)"
fi

APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")
if [[ -n "$APP_ID" ]]; then
  echo ""
  echo "   App Registration: $APP_NAME ($APP_ID) ✅"
else
  echo ""
  echo "   App Registration: $APP_NAME ❌ (not found)"
fi

# ── Delete Resource Group ─────────────────────────────────
if [[ "$APP_ONLY" != true ]]; then
  echo ""
  if [[ "$RG_EXISTS" == "true" ]]; then
    if confirm "🗑️  Delete resource group '$RESOURCE_GROUP' and ALL resources inside it?"; then
      echo "   Deleting resource group (this may take a few minutes)..."
      az group delete --name "$RESOURCE_GROUP" --yes --no-wait 2>/dev/null
      echo "   ✅ Resource group deletion initiated (async)"
    else
      echo "   ⏭️  Skipped resource group deletion"
    fi
  else
    echo "   ⏭️  Resource group '$RESOURCE_GROUP' does not exist — nothing to delete"
  fi
fi

# ── Delete App Registration ───────────────────────────────
if [[ "$RG_ONLY" != true ]]; then
  echo ""
  if [[ -n "$APP_ID" ]]; then
    if confirm "🗑️  Delete Entra ID App Registration '$APP_NAME' ($APP_ID)?"; then
      az ad app delete --id "$APP_ID" 2>/dev/null
      echo "   ✅ App Registration deleted"
    else
      echo "   ⏭️  Skipped App Registration deletion"
    fi
  else
    echo "   ⏭️  App Registration not found — nothing to delete"
  fi
fi

# ── Purge soft-deleted Key Vaults (optional) ──────────────
if [[ "$APP_ONLY" != true ]]; then
  echo ""
  DELETED_VAULTS=$(az keyvault list-deleted --query "[?contains(name, 'secpostureiq')].name" -o tsv 2>/dev/null || echo "")
  if [[ -n "$DELETED_VAULTS" ]]; then
    echo "📦 Soft-deleted Key Vaults found:"
    echo "   $DELETED_VAULTS"
    if confirm "🗑️  Purge soft-deleted Key Vaults? (required to reuse the same names)"; then
      for vault in $DELETED_VAULTS; do
        az keyvault purge --name "$vault" --no-wait 2>/dev/null || true
        echo "   ✅ Purge initiated: $vault"
      done
    else
      echo "   ⏭️  Skipped Key Vault purge"
    fi
  fi
fi

# ── Clean up local .env ──────────────────────────────────
echo ""
if [[ -f ".env" ]]; then
  if confirm "🗑️  Delete local .env file?"; then
    rm -f .env
    echo "   ✅ .env deleted"
  else
    echo "   ⏭️  Kept .env file"
  fi
fi

echo ""
echo "============================================="
echo "🧹 Cleanup complete!"
echo ""
echo "Note: Resource group deletion runs async."
echo "Check status: az group exists --name $RESOURCE_GROUP"
