using './main.bicep'

// param tenantId = '<your tenant id>'
// param spnProviderId = '<your Microsoft.AzureStackHCI resource provider object id>'
// param windowsAdminUsername = 'arcdemo'
// param windowsAdminPassword = '<your password>'
param tenantId = '173eb3fc-9ba1-437f-99a1-89d5e53b91d1'
param spnProviderId = '978c59bc-0b1d-4d2a-9ebb-dfff80e33740'
param windowsAdminUsername = 'arcdemo'
param windowsAdminPassword = 'arc@DEMO12345!'
param logAnalyticsWorkspaceName = 'LocalBox-Workspace'
param natDNS = '8.8.8.8'
param githubAccount = 'microsoft'
param githubBranch = 'main'
param deployBastion = false
param location = 'southcentralus'
//param azureLocalInstanceLocation = 'australiaeast'
param azureLocalInstanceLocation = 'southcentralus'
param rdpPort = '3389'
param autoDeployClusterResource = true
param autoUpgradeClusterResource = false
param vmAutologon = true
param vmSize = 'Standard_E32s_v6'
param enableAzureSpotPricing = false
param governResourceTags = true
param tags = {
  Project: 'jumpstart_LocalBox'
}
