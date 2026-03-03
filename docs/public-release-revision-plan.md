# SecPostureIQ — Public Release Revision Plan

> **Purpose:** This document outlines every change required before SecPostureIQ can be
> safely and cleanly published for customers to clone and deploy to their own Azure
> tenants. It is organized by severity and includes the exact files and lines that
> need attention.
>
> **Date:** March 2, 2026
> **Status:** Draft — awaiting review

---

## Executive Summary

The codebase was originally built for single-tenant development under the
`9owlsboston` GitHub org, deploying to a known `rg-secpostureiq-dev` resource group.
Making it public requires three categories of work:

| Category | Items | Effort |
|----------|-------|--------|
| **P0 — Must Fix** (blocks release) | 7 items | ~2 hours |
| **P1 — Should Fix** (improves customer experience) | 8 items | ~3 hours |
| **P2 — Polish** (nice to have) | 5 items | ~2 hours |

---

## P0 — Must Fix (Blocks Public Release)

### 1. Remove real dev environment URLs

Two scripts contain the **live dev Container App URL**, which leaks the internal
Azure environment name and FQDN.

| File | Line | Current Value |
|------|------|---------------|
| `scripts/load_test.py` | 16 | `BASE_URL = "https://secpostureiq-dev-app.redrock-8f5cd3d2.centralus.azurecontainerapps.io"` |
| `scripts/simulate_traffic.py` | 84 | `DEFAULT_URL = "https://secpostureiq-dev-app.redrock-8f5cd3d2.centralus.azurecontainerapps.io"` |

**Fix:** Replace with environment variable or a placeholder:
```python
BASE_URL = os.environ.get("SECPOSTUREIQ_URL", "http://localhost:8000")
```

---

### 2. Remove real App Insights application ID

| File | Line | Current Value |
|------|------|---------------|
| `docs/app-insights-guide.md` | ~409 | `APP_ID="7787d1cc-8e48-4f14-a39a-99530d8f7354"` |

**Fix:** Replace with `APP_ID="<your-app-insights-application-id>"`.

---

### 3. Remove hardcoded `9owlsboston` org references

14 occurrences across the repo assume the GitHub org is `9owlsboston`. Customers
who clone will see URLs pointing to your private org.

| File | Occurrences | Type |
|------|-------------|------|
| `scripts/setup-oidc.sh` | 1 | **Script logic** — `GITHUB_REPO="9owlsboston/posture-iq"` (line 32) |
| `README.md` | 3 | Clone URLs, Deploy-to-Azure button URL |
| `docs/ghcp_challenge_submission/secpostureiq-customer-deployment-guide.md` | 5 | Clone URLs, Deploy-to-Azure button, source repo link |
| `scripts/deploy-customer.sh` | 1 | Comment with clone URL |
| `docs/app-insights-guide.md` | 1 | `gh auth switch --user 9owlsboston` |
| `docs/setup-guide.md` | 2 | OIDC federation subjects with `repo:9owlsboston/posture-iq:...` |

**Fix:**
- **Scripts:** Auto-detect via `gh repo view --json nameWithOwner -q .nameWithOwner` or
  prompt the user. Never hardcode.
- **Docs:** Replace `9owlsboston` with `<your-org>` placeholders, or use relative paths
  (e.g., "clone this repo" instead of a full URL).
- **Deploy-to-Azure button:** The ARM template URL must point to the customer's own
  fork/repo. Document this — the button only works from the canonical repo.

---

### 4. Add missing standard public-repo files

| File | Status | Action |
|------|--------|--------|
| `LICENSE` | **Missing** — `pyproject.toml` declares MIT but no file exists | Create `LICENSE` with MIT text |
| `CONTRIBUTING.md` | Missing | Create with contribution guidelines, PR process, code style |
| `SECURITY.md` | Missing | Create with vulnerability reporting instructions |
| `CODE_OF_CONDUCT.md` | Missing | Create (Microsoft Open Source CoC or equivalent) |

---

### 5. Parameterize hardcoded resource group in CI/CD

The CI/CD pipeline hardcodes the deployment target, meaning any fork will fail or
deploy to the wrong place unless the customer edits YAML source files.

| File | Line | Current Value |
|------|------|---------------|
| `.github/workflows/ci-cd.yml` | 30 | `RESOURCE_GROUP: "rg-secpostureiq-dev"` |
| `.github/workflows/pr-deploy.yml` | 82 | `az acr list --resource-group rg-secpostureiq-dev` (hardcoded string, not even using the env var) |

**Fix:** Move to GitHub repository variables (`vars.*`):
```yaml
env:
  RESOURCE_GROUP: ${{ vars.RESOURCE_GROUP || 'rg-secpostureiq-dev' }}
  ACR_NAME: ${{ vars.ACR_NAME }}
```
Add a `SETUP.md` or section in README explaining which repo variables to configure.

---

### 6. CI/CD deploys `dev` params but labels environment `production`

The deploy job uses `environment: production` but deploys with `dev.bicepparam`.
This is confusing and incorrect for any customer deploying to production.

| File | Lines | Issue |
|------|-------|-------|
| `.github/workflows/ci-cd.yml` | 174, 192 | `environment: production` but `parameters: ./infra/parameters/dev.bicepparam` |

**Fix:** Implement environment promotion:
```
push to main → build → deploy-dev (auto, dev.bicepparam) → smoke-test → deploy-prod (approval gate, prod.bicepparam)
```
Or at minimum: match the environment label to the parameter file being used.

---

### 7. No post-deploy health check

Bicep success ≠ app is actually running. A broken container image or misconfigured
env var won't be caught.

**Fix:** Add a smoke test step after `Deploy Bicep` in `ci-cd.yml`:
```yaml
- name: Smoke test
  run: |
    APP_URL=$(az containerapp show --name $APP_NAME -g $RG \
      --query "properties.configuration.ingress.fqdn" -o tsv)
    for i in {1..10}; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${APP_URL}/health")
      [[ "$STATUS" == "200" ]] && echo "✅ Passed" && exit 0
      sleep 15
    done
    exit 1
```

---

## P1 — Should Fix (Customer Experience)

### 8. PR preview depends on dev resource group

`pr-deploy.yml` line 82 runs `az acr list --resource-group rg-secpostureiq-dev` to
discover the ACR. If a customer hasn't deployed dev first, PR previews break.

**Fix:** Use `vars.ACR_NAME` directly:
```yaml
- name: Login to ACR
  run: az acr login --name ${{ vars.ACR_NAME }}
```

---

### 9. `setup-oidc.sh` hardcodes repo name

Line 32: `GITHUB_REPO="9owlsboston/posture-iq"` — won't work for any fork.

**Fix:** Auto-detect or accept as argument:
```bash
GITHUB_REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
```

---

### 10. `setup-permissions.sh` echoes client secret to stdout

Line ~168: The script prints `AZURE_CLIENT_SECRET` directly to the terminal. This
is a security risk — anyone with terminal history or CI logs can see it.

**Fix:** Suppress echo or write directly to `.env` / Key Vault without printing:
```bash
echo "   ✅ Client secret created (stored in .env — not displayed)"
```

---

### 11. Add rollback workflow

No rollback mechanism exists. If a bad image deploys, the only option is to push
a fix commit and wait for CI/CD.

**Fix:** Create `.github/workflows/rollback.yml`:
```yaml
on:
  workflow_dispatch:
    inputs:
      image_tag:
        description: 'Git SHA of image to roll back to'
      environment:
        type: choice
        options: [dev, prod]
```

---

### 12. CDX demo tenant references

Two docs reference `cdx.transform.microsoft.com`, which is an internal Microsoft
portal that external customers cannot access.

| File | Line |
|------|------|
| `docs/how-to-assess-me5-tenant.md` | ~378 |
| `docs/setup-guide.md` | ~206 |

**Fix:** Add a note: _"CDX is available to Microsoft employees and partners only.
External customers should use their own M365 E5 tenant or trial."_

---

### 13. Decide on "Project 479" branding

"Project 479" and "Get to Green" appear in:
- `pyproject.toml` description
- `README.md`
- `src/api/app.py` FastAPI description
- System prompt
- Multiple docs and test files
- The tool name `get_project479_playbook`

**Decision needed:** Is this a public-facing initiative name or internal Microsoft
branding? If internal:
- Replace with generic terminology like "security posture improvement" or
  "ME5 license optimization"
- Rename the tool to something like `get_remediation_playbook`

---

### 14. Add `SETUP.md` for fork/clone configuration

Customers need a single document that says: _"After cloning, configure these N things."_
This supplements the deploy-customer.sh script for customers who want CI/CD.

Contents:
- GitHub repo variables to set (`RESOURCE_GROUP`, `ACR_NAME`, `LOCATION`)
- GitHub secrets to set (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`)
- Bicep parameter files to review
- OIDC federated credential setup

---

### 15. Add concurrency control to CI/CD

No concurrency limits — two simultaneous pushes to main can cause conflicting
deployments.

**Fix:**
```yaml
concurrency:
  group: deploy-${{ github.ref }}
  cancel-in-progress: true
```

---

## P2 — Polish

### 16. Drop `:latest` Docker tag

`ci-cd.yml` pushes both `:latest` and `:<sha>`. The `:latest` tag hides what's
actually running and causes confusion in multi-environment setups.

**Fix:** Only push `:<sha>` tags. Reference the SHA tag in all deployments.

---

### 17. Add container image vulnerability scanning

No image scan before pushing to ACR.

**Fix:** Add Trivy scan step before ACR push:
```yaml
- name: Scan image for vulnerabilities
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ${{ env.IMAGE }}
    severity: CRITICAL,HIGH
    exit-code: 1
```

---

### 18. Add deploy notifications

No notification on deploy success/failure. Customer ops teams need visibility.

**Fix:** Add a Slack/Teams webhook step at the end of deploy job, or use
GitHub Actions built-in email notifications.

---

### 19. Remove `continue-on-error: true` from MyPy

`ci-cd.yml` line 55: MyPy errors are silently swallowed. This accumulates type
debt.

**Fix:** Once type annotations stabilize, remove `continue-on-error: true` so
type errors fail the build.

---

### 20. Resolve TODO in app.py

| File | Line | Content |
|------|------|---------|
| `src/api/app.py` | 377 | `# TODO: Wire up to the agent session` |

**Fix:** Implement the wiring or remove the dead code path with a comment
explaining the current design.

---

## Implementation Order

```
Week 1 (P0 — blocks release):
  ├── #1  Remove real dev URLs from load_test.py, simulate_traffic.py
  ├── #2  Remove real App Insights ID from docs
  ├── #3  Replace all 9owlsboston references
  ├── #4  Create LICENSE, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md
  ├── #5  Parameterize CI/CD with vars.*
  ├── #6  Fix environment label vs. parameter file mismatch
  └── #7  Add post-deploy health check

Week 2 (P1 — customer experience):
  ├── #8   Fix PR preview ACR dependency
  ├── #9   Fix setup-oidc.sh hardcoded repo
  ├── #10  Stop echoing secrets in setup-permissions.sh
  ├── #11  Add rollback workflow
  ├── #12  Add note on CDX references
  ├── #13  Decide Project 479 branding
  ├── #14  Create SETUP.md
  └── #15  Add concurrency control

Week 3 (P2 — polish):
  ├── #16  Drop :latest tag
  ├── #17  Add Trivy image scan
  ├── #18  Add deploy notifications
  ├── #19  Remove MyPy continue-on-error
  └── #20  Resolve TODO in app.py
```

---

## Files Changed Summary

| Category | Files Affected |
|----------|---------------|
| **CI/CD workflows** | `.github/workflows/ci-cd.yml`, `.github/workflows/pr-deploy.yml` |
| **Scripts** | `scripts/setup-oidc.sh`, `scripts/setup-permissions.sh`, `scripts/load_test.py`, `scripts/simulate_traffic.py`, `scripts/deploy-customer.sh` |
| **Source code** | `src/api/app.py` |
| **Infrastructure** | None (Bicep is already parameterized) |
| **Docs** | `README.md`, `docs/app-insights-guide.md`, `docs/setup-guide.md`, `docs/how-to-assess-me5-tenant.md`, `docs/ghcp_challenge_submission/secpostureiq-customer-deployment-guide.md` |
| **New files** | `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `SETUP.md`, `.github/workflows/rollback.yml` |
