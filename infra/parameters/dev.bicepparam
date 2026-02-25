// PostureIQ — Dev environment parameters
using '../main.bicep'

param environment = 'dev'
param location = 'eastus2'
param projectName = 'postureiq'
param containerImage = '' // Will be set by CI/CD pipeline
