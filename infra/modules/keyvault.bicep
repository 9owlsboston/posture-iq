// PostureIQ — Azure Key Vault module

@description('Key Vault resource name')
param name string

@description('Azure region')
param location string

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: name
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 30
    enablePurgeProtection: false  // Allow purge in dev; set true for prod
  }
}

output vaultUri string = keyVault.properties.vaultUri
output name string = keyVault.name
