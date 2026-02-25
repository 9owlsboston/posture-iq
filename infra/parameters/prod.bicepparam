// PostureIQ — Production environment parameters
using '../main.bicep'

param environment = 'prod'
param location = 'eastus2'
param projectName = 'postureiq'
param containerImage = '' // Set to ACR image URI for production
