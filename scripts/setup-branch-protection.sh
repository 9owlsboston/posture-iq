#!/usr/bin/env bash
#
# PostureIQ — Configure Branch Protection Rules
#
# Sets up branch protection on 'main' to require:
#   - Passing CI checks (lint, test, bicep-validate) before merge
#   - At least 1 approving review on PRs
#   - Up-to-date branches before merging
#
# Prerequisites:
#   - GitHub CLI installed (`gh`)
#   - Authenticated: `gh auth login`
#   - Admin access to the repository
#
# Usage:
#   chmod +x scripts/setup-branch-protection.sh
#   ./scripts/setup-branch-protection.sh

set -euo pipefail

BRANCH="main"
REPO=$(gh repo view --json nameWithOwner -q '.nameWithOwner' 2>/dev/null) || {
  echo "❌ Could not determine repository. Make sure you're in the repo directory and gh is authenticated."
  exit 1
}

echo "🛡️  PostureIQ — Branch Protection Setup"
echo "========================================"
echo "  Repository: $REPO"
echo "  Branch:     $BRANCH"
echo ""

# ── Apply branch protection rules ────────────────────────
echo "📋 Applying branch protection rules..."

gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/$REPO/branches/$BRANCH/protection" \
  -f 'required_status_checks[strict]=true' \
  -f 'required_status_checks[contexts][]=Lint & Type Check' \
  -f 'required_status_checks[contexts][]=Test' \
  -f 'required_status_checks[contexts][]=Validate Bicep Templates' \
  -f 'required_pull_request_reviews[required_approving_review_count]=1' \
  -f 'required_pull_request_reviews[dismiss_stale_reviews]=true' \
  -F 'enforce_admins=false' \
  -f 'restrictions=null' \
  --silent 2>/dev/null && {
  echo "  ✅ Branch protection applied"
} || {
  echo "  ⚠️  Could not apply branch protection via REST API."
  echo "     This may require admin access or a paid GitHub plan."
  echo ""
  echo "  To configure manually:"
  echo "    1. Go to https://github.com/$REPO/settings/branches"
  echo "    2. Add a branch protection rule for '$BRANCH'"
  echo "    3. Enable:"
  echo "       - Require a pull request before merging (1 approval)"
  echo "       - Require status checks to pass: Lint & Type Check, Test, Validate Bicep Templates"
  echo "       - Require branches to be up to date before merging"
  echo "       - Dismiss stale pull request approvals"
}

echo ""
echo "========================================"
echo "🎉 Done!"
echo ""
echo "Protected checks:"
echo "  ✅ Lint & Type Check"
echo "  ✅ Test (80% coverage threshold)"
echo "  ✅ Validate Bicep Templates"
echo "  ✅ 1 approving review required"
echo "  ✅ Branches must be up-to-date"
