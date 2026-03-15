// SecPostureIQ — Azure OpenAI module

@description('Azure OpenAI resource name')
param name string

@description('Azure region')
param location string

@description('Principal ID to grant Cognitive Services OpenAI User role (optional)')
param managedIdentityPrincipalId string = ''

@description('Model deployments to create under this Azure OpenAI resource')
param modelDeployments array = [
  {
    name: 'gpt-4o'
    model: 'gpt-4o'
    version: '2024-05-13'
    capacity: 30
  }
]

resource openai 'Microsoft.CognitiveServices/accounts@2024-04-01-preview' = {
  name: name
  location: location
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: name
    publicNetworkAccess: 'Enabled'
  }
}

@batchSize(1)
resource modelDeployment 'Microsoft.CognitiveServices/accounts/deployments@2024-04-01-preview' = [
  for deployment in modelDeployments: {
    parent: openai
    name: deployment.name
    sku: {
      name: 'GlobalStandard'
      capacity: deployment.capacity
    }
    properties: {
      model: {
        format: 'OpenAI'
        name: deployment.model
        version: deployment.version
      }
    }
  }
]

// Cognitive Services OpenAI User role — allows the managed identity to use OpenAI
// Role definition ID: 5e0bd9bd-7b93-4f28-af87-19fc36ad61bd
resource openaiUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(managedIdentityPrincipalId)) {
  name: guid(openai.id, managedIdentityPrincipalId, '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd')
  scope: openai
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd')
    principalId: managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

output endpoint string = openai.properties.endpoint
output name string = openai.name
output deployedModels array = [for (deployment, i) in modelDeployments: deployment.name]
