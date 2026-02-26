// PostureIQ — Azure Container Registry module
//
// Provisions an ACR instance for storing PostureIQ container images.
// Features: OIDC-based CI/CD push (no admin credentials), managed identity
// pull via AcrPull role for Container Apps.

@description('Container Registry resource name')
param name string

@description('Azure region')
param location string

@description('SKU for ACR (Basic for dev, Standard/Premium for prod)')
@allowed(['Basic', 'Standard', 'Premium'])
param sku string = 'Basic'

@description('Principal ID of the managed identity to grant AcrPull role (Container Apps)')
param pullIdentityPrincipalId string = ''

@description('Principal ID of the CI/CD service principal to grant AcrPush role (GitHub Actions OIDC)')
param pushIdentityPrincipalId string = ''

// ── Container Registry ────────────────────────────────────
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: name
  location: location
  sku: {
    name: sku
  }
  properties: {
    adminUserEnabled: false  // OIDC eliminates need for admin credentials
    publicNetworkAccess: 'Enabled'
  }
}

// ── AcrPull role assignment for managed identity (image pull) ──
// This allows the Container App's managed identity to pull images
// without needing admin credentials.
var acrPullRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d' // AcrPull built-in role
)

resource acrPullRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(pullIdentityPrincipalId)) {
  name: guid(acr.id, pullIdentityPrincipalId, acrPullRoleDefinitionId)
  scope: acr
  properties: {
    roleDefinitionId: acrPullRoleDefinitionId
    principalId: pullIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// ── AcrPush role assignment for CI/CD identity (OIDC image push) ──
// This allows the GitHub Actions OIDC service principal to push images
// without needing ACR admin credentials.
var acrPushRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '8311e382-0749-4cb8-b61a-304f252e45ec' // AcrPush built-in role
)

resource acrPushRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(pushIdentityPrincipalId)) {
  name: guid(acr.id, pushIdentityPrincipalId, acrPushRoleDefinitionId)
  scope: acr
  properties: {
    roleDefinitionId: acrPushRoleDefinitionId
    principalId: pushIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// ── Outputs ───────────────────────────────────────────────
output loginServer string = acr.properties.loginServer
output name string = acr.name
output id string = acr.id
