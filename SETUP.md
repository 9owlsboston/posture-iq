# SecPostureIQ — Setup Guide for Forks & Clones

After cloning or forking SecPostureIQ, configure these items so that CI/CD
and the deployment scripts work in **your** Azure tenant.

---

## 1. GitHub Repository Variables

Set these in **Settings → Secrets and variables → Actions → Variables**:

| Variable | Example | Purpose |
|----------|---------|---------|
| `RESOURCE_GROUP` | `rg-secpostureiq-dev` | Azure resource group for deployments |
| `DEPLOY_ENV` | `dev` or `prod` | Selects the Bicep parameter file (`infra/parameters/<env>.bicepparam`) and the GitHub environment label |

> If these variables are not set, the pipeline defaults to `rg-secpostureiq-dev` / `dev`.

---

## 2. GitHub Secrets

Set these in **Settings → Secrets and variables → Actions → Secrets**:

| Secret | Source | Purpose |
|--------|--------|---------|
| `AZURE_CLIENT_ID` | Entra ID → App Registrations → your app → Overview | OIDC Workload Identity |
| `AZURE_TENANT_ID` | Entra ID → Properties → Tenant ID | OIDC Workload Identity |
| `AZURE_SUBSCRIPTION_ID` | Subscriptions → your sub → Overview | Target Azure subscription |

These are **non-sensitive IDs** — the actual authentication uses OIDC federated
credentials with no stored secrets.

---

## 3. OIDC Federated Credential

Run the setup script to create the Entra ID app registration and federated
credential for GitHub Actions:

```bash
./scripts/setup-oidc.sh
```

The script auto-detects your GitHub org/repo via `gh repo view`. It creates
federated credential subjects for:

- `repo:<org>/<repo>:ref:refs/heads/main` — push to main
- `repo:<org>/<repo>:pull_request` — PR preview environments
- `repo:<org>/<repo>:environment:production` — production deploy gate

---

## 4. Bicep Parameter Files

Review and customise the parameter files for your environment:

| File | Purpose |
|------|---------|
| `infra/parameters/dev.bicepparam` | Development / default deployment |
| `infra/parameters/prod.bicepparam` | Production deployment |

Key parameters to review:
- `projectName` — used as prefix for all Azure resources
- `location` — Azure region
- `openAiModelName` / `openAiModelVersion` — GPT model selection

---

## 5. GitHub Environment (optional)

If you want an **approval gate** before production deploys:

1. Go to **Settings → Environments**
2. Create an environment matching your `DEPLOY_ENV` value (e.g., `prod`)
3. Add **required reviewers**
4. The deploy job will pause for approval before proceeding

---

## 6. App Registration for Graph API

SecPostureIQ needs delegated Microsoft Graph permissions to read security data.
Run:

```bash
./scripts/setup-permissions.sh
```

This creates an app registration with the required read-only Graph scopes and
writes credentials to `.env`. See [docs/setup-guide.md](docs/setup-guide.md)
for the full permission list.

---

## Quick Checklist

```
[ ] Set GitHub variable: RESOURCE_GROUP
[ ] Set GitHub variable: DEPLOY_ENV
[ ] Set GitHub secret: AZURE_CLIENT_ID
[ ] Set GitHub secret: AZURE_TENANT_ID
[ ] Set GitHub secret: AZURE_SUBSCRIPTION_ID
[ ] Run ./scripts/setup-oidc.sh
[ ] Review infra/parameters/dev.bicepparam
[ ] Run ./scripts/setup-permissions.sh
[ ] Push to main — CI/CD should build, scan, deploy, and health-check
```
