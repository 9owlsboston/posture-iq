// SecPostureIQ — Dev environment parameters
using '../main.bicep'

param environment = 'dev'
param location = 'centralus'
param projectName = 'secpostureiq'
param containerImage = '' // Will be set by CI/CD pipeline
