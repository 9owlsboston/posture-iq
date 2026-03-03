# PostureIQ Multi-Tenant Production Cutover Runbook

This runbook is for migrating an existing PostureIQ deployment from single-tenant to multi-tenant mode during a controlled production change window.

---

## 0. Environment Profile (Fill Before Change Window)

Repo defaults (from `infra/parameters/prod.bicepparam`):
- `DEPLOY_ENV=prod`
- `LOCATION=eastus2`
- `PROJECT_NAME=postureiq`

Set these runtime values before execution:

```bash
export RESOURCE_GROUP="<prod-resource-group>"
export CONTAINER_APP_NAME="<prod-container-app-name>"
export CONTAINER_APP_URL="https://<prod-app>.<region>.azurecontainerapps.io"
export AZURE_CLIENT_ID="<app-registration-client-id>"
export PRIMARY_OWNER="<name/email>"
export ONCALL_CONTACT="<name/email>"
```

Optional: discover URL from Azure if `RESOURCE_GROUP` and `CONTAINER_APP_NAME` are known:

```bash
az containerapp show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CONTAINER_APP_NAME" \
  --query "properties.configuration.ingress.fqdn" -o tsv
```

---

## 1. Preconditions

- Deployment is healthy in single-tenant mode (`/health`, `/ready` return 200).
- You have owner/admin access to:
  - Entra App Registration (`AZURE_CLIENT_ID`)
  - Azure Container App configuration
  - Deployment pipeline or release process
- A rollback path is prepared (documented below).

Recommended change window length: 30-60 minutes.

---

## 2. Pre-Checks (T-30 to T-5 minutes)

1. Confirm current mode:
   - `MULTI_TENANT_ENABLED=false`
2. Capture current app revision and config:
   - Container App active revision name
   - Current environment variables
3. Confirm callback URL is registered:
   - `$CONTAINER_APP_URL/auth/callback`
4. Confirm monitoring is live:
   - App Insights request/error dashboards
   - `/health` and `/ready` probe status
5. Confirm at least one external tenant test user is available.

Go/No-Go criteria:
- No active Sev2+ incidents.
- Baseline error rate stable.
- `PRIMARY_OWNER` and `ONCALL_CONTACT` are both available during the window.

---

## 3. Cutover Steps (Change Window)

1. Update app registration audience:
```bash
az ad app update --id <AZURE_CLIENT_ID> --sign-in-audience AzureADMultipleOrgs
```
2. Update runtime configuration:
```env
MULTI_TENANT_ENABLED=true
ALLOWED_TENANTS=<tenant-guid-1>,<tenant-guid-2>
```
3. Deploy/restart the app so new environment variables are applied.
4. Confirm deployment health:
   - `GET /health` = 200
   - `GET /ready` = 200

---

## 4. Post-Cutover Validation (T+0 to T+15 minutes)

Run these checks in order:

1. Home tenant auth check:
   - Sign in with existing tenant user.
   - `GET /auth/me` returns expected `tenant_id`.
2. External tenant auth check:
   - Sign in with allowed external tenant user.
   - `GET /auth/me` returns external `tenant_id`.
3. API protection check:
   - Anonymous `POST /chat` returns 401.
4. Tenant isolation check:
   - Run `POST /chat` as tenant A and tenant B users.
   - Responses must reflect each tenant's own data.
5. Audit isolation check:
   - `GET /audit/logs` as each user only returns same-tenant entries.

Success criteria:
- All checks pass.
- Error rate and latency remain within normal range.

---

## 5. Rollback Triggers

Rollback immediately if any of these occur:

- External tenant sign-in fails for >10 minutes after cutover.
- Cross-tenant data exposure is observed or suspected.
- `5xx` error rate > 5% for 5 consecutive minutes.
- p95 latency > 2x baseline for 10 consecutive minutes.
- `/ready` probe fails persistently after deployment stabilization.

---

## 6. Rollback Procedure

1. Disable multi-tenant mode:
```env
MULTI_TENANT_ENABLED=false
```
2. Redeploy/restart app to apply config.
3. Validate:
   - Home tenant login works.
   - `POST /chat` works for home tenant users.
   - `/health` and `/ready` are healthy.
4. If needed, revert app registration audience to single-tenant:
```bash
az ad app update --id <AZURE_CLIENT_ID> --sign-in-audience AzureADMyOrg
```
5. Announce rollback completion and begin incident follow-up.

---

## 7. Communications Template

- Start: "Multi-tenant cutover started at <time>, expected completion <time>."
- Success: "Cutover completed successfully at <time>; validation checks passed."
- Rollback: "Cutover rolled back at <time> due to <trigger>; service restored in single-tenant mode."
