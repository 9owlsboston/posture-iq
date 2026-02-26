// PostureIQ — Main Bicep Template
//
// Orchestrates all Azure resources required for PostureIQ:
//   - User-Assigned Managed Identity (service auth — deployed first for RBAC)
//   - Azure Container Registry (image store — OIDC push, managed identity pull)
//   - Azure OpenAI (LLM reasoning) + RBAC for managed identity
//   - Azure AI Content Safety (RAI filtering) + RBAC for managed identity
//   - Azure Application Insights + Log Analytics (observability)
//   - Azure Key Vault (secrets management) + RBAC for managed identity
//   - Azure Container Apps (deployment target)

targetScope = 'resourceGroup'

// ── Parameters ────────────────────────────────────────────
@description('Environment name (dev, staging, prod)')
@allowed(['dev', 'staging', 'prod'])
param environment string = 'dev'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Project name prefix for resource naming')
param projectName string = 'postureiq'

@description('Container image to deploy (e.g., myacr.azurecr.io/postureiq:latest)')
param containerImage string = ''

@description('Principal ID of the CI/CD service principal (for AcrPush RBAC via OIDC)')
param cicdPrincipalId string = ''

// ── Variables ─────────────────────────────────────────────
var uniqueSuffix = substring(uniqueString(resourceGroup().id), 0, 6)
var resourcePrefix = '${projectName}-${environment}'

// ── Managed Identity (deployed early for RBAC wiring) ─────
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${resourcePrefix}-app-identity'
  location: location
}

// ── Modules ───────────────────────────────────────────────

module containerRegistry 'modules/container-registry.bicep' = {
  name: 'containerRegistryDeployment'
  params: {
    name: '${projectName}${environment}acr${uniqueSuffix}'  // ACR names must be alphanumeric
    location: location
    sku: environment == 'prod' ? 'Standard' : 'Basic'
    pullIdentityPrincipalId: managedIdentity.properties.principalId
    pushIdentityPrincipalId: cicdPrincipalId
  }
}

module appInsights 'modules/app-insights.bicep' = {
  name: 'appInsightsDeployment'
  params: {
    name: '${resourcePrefix}-ai'
    location: location
  }
}

module contentSafety 'modules/content-safety.bicep' = {
  name: 'contentSafetyDeployment'
  params: {
    name: '${resourcePrefix}-cs-${uniqueSuffix}'
    location: location
    managedIdentityPrincipalId: managedIdentity.properties.principalId
  }
}

module keyVault 'modules/keyvault.bicep' = {
  name: 'keyVaultDeployment'
  params: {
    name: '${resourcePrefix}-kv-${uniqueSuffix}'
    location: location
    managedIdentityPrincipalId: managedIdentity.properties.principalId
  }
}

module openai 'modules/openai.bicep' = {
  name: 'openaiDeployment'
  params: {
    name: '${resourcePrefix}-oai-${uniqueSuffix}'
    location: location
    managedIdentityPrincipalId: managedIdentity.properties.principalId
  }
}

module containerApp 'modules/container-app.bicep' = {
  name: 'containerAppDeployment'
  params: {
    name: '${resourcePrefix}-app'
    location: location
    containerImage: containerImage
    appInsightsConnectionString: appInsights.outputs.connectionString
    openaiEndpoint: openai.outputs.endpoint
    contentSafetyEndpoint: contentSafety.outputs.endpoint
    keyVaultUrl: keyVault.outputs.vaultUri
    environment: environment
    managedIdentityId: managedIdentity.id
    managedIdentityClientId: managedIdentity.properties.clientId
    acrLoginServer: containerRegistry.outputs.loginServer
  }
}

// ── Outputs ───────────────────────────────────────────────
output containerAppUrl string = containerApp.outputs.fqdn
output appInsightsName string = appInsights.outputs.name
output keyVaultName string = keyVault.outputs.name
output managedIdentityName string = managedIdentity.name
output managedIdentityClientId string = managedIdentity.properties.clientId
output acrLoginServer string = containerRegistry.outputs.loginServer
output acrName string = containerRegistry.outputs.name
