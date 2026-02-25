// PostureIQ — Main Bicep Template
//
// Orchestrates all Azure resources required for PostureIQ:
//   - Azure Container Apps (deployment target)
//   - Azure OpenAI (LLM reasoning)
//   - Azure Application Insights + Log Analytics (observability)
//   - Azure AI Content Safety (RAI filtering)
//   - Azure Key Vault (secrets management)
//   - User-Assigned Managed Identity (service auth)

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

// ── Variables ─────────────────────────────────────────────
var uniqueSuffix = uniqueString(resourceGroup().id)
var resourcePrefix = '${projectName}-${environment}'

// ── Modules ───────────────────────────────────────────────

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
  }
}

module keyVault 'modules/keyvault.bicep' = {
  name: 'keyVaultDeployment'
  params: {
    name: '${resourcePrefix}-kv-${uniqueSuffix}'
    location: location
  }
}

module openai 'modules/openai.bicep' = {
  name: 'openaiDeployment'
  params: {
    name: '${resourcePrefix}-oai-${uniqueSuffix}'
    location: location
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
  }
}

// ── Outputs ───────────────────────────────────────────────
output containerAppUrl string = containerApp.outputs.fqdn
output appInsightsName string = appInsights.outputs.name
output keyVaultName string = keyVault.outputs.name
