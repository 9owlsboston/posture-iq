// PostureIQ — Azure Container Apps module
//
// Deploys the PostureIQ agent as a serverless container on Azure Container Apps.
// Features: scale-to-zero, health probes, managed identity, env vars from Key Vault.

@description('Container App resource name')
param name string

@description('Azure region')
param location string

@description('Container image reference')
param containerImage string

@description('App Insights connection string')
param appInsightsConnectionString string

@description('Azure OpenAI endpoint')
param openaiEndpoint string

@description('Azure AI Content Safety endpoint')
param contentSafetyEndpoint string

@description('Azure Key Vault URL')
param keyVaultUrl string

@description('Environment name')
param environment string

@description('User-Assigned Managed Identity resource ID')
param managedIdentityId string

@description('User-Assigned Managed Identity client ID (for AZURE_CLIENT_ID env var)')
param managedIdentityClientId string

@description('ACR login server (e.g., postureiqdevacrabcdef.azurecr.io)')
param acrLoginServer string = ''

// ── Container Apps Environment ────────────────────────────
resource containerAppEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${name}-env'
  location: location
  properties: {
    zoneRedundant: false
  }
}

// ── Container App ─────────────────────────────────────────
resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'http'
      }
      registries: !empty(acrLoginServer) ? [
        {
          server: acrLoginServer
          identity: managedIdentityId
        }
      ] : []
    }
    template: {
      containers: [
        {
          name: 'postureiq'
          image: !empty(containerImage) ? containerImage : 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'ENVIRONMENT', value: environment }
            { name: 'AZURE_OPENAI_ENDPOINT', value: openaiEndpoint }
            { name: 'AZURE_CONTENT_SAFETY_ENDPOINT', value: contentSafetyEndpoint }
            { name: 'AZURE_KEYVAULT_URL', value: keyVaultUrl }
            { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsightsConnectionString }
            { name: 'AZURE_CLIENT_ID', value: managedIdentityClientId }
            { name: 'PORT', value: '8000' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/ready'
                port: 8000
              }
              initialDelaySeconds: 15
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 5
        rules: [
          {
            name: 'http-rule'
            http: {
              metadata: {
                concurrentRequests: '10'
              }
            }
          }
        ]
      }
    }
  }
}

output fqdn string = containerApp.properties.configuration.ingress.fqdn
