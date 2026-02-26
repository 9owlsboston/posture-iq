// PostureIQ — Azure AI Content Safety module

@description('Content Safety resource name')
param name string

@description('Azure region')
param location string

@description('Principal ID to grant Cognitive Services User role (optional)')
param managedIdentityPrincipalId string = ''

resource contentSafety 'Microsoft.CognitiveServices/accounts@2024-04-01-preview' = {
  name: name
  location: location
  kind: 'ContentSafety'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: name
    publicNetworkAccess: 'Enabled'
  }
}

// Cognitive Services User role — allows the managed identity to use Content Safety
// Role definition ID: a97b65f3-24c7-4388-baec-2e87135dc908
resource csUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(managedIdentityPrincipalId)) {
  name: guid(contentSafety.id, managedIdentityPrincipalId, 'a97b65f3-24c7-4388-baec-2e87135dc908')
  scope: contentSafety
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'a97b65f3-24c7-4388-baec-2e87135dc908')
    principalId: managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

output endpoint string = contentSafety.properties.endpoint
output name string = contentSafety.name
