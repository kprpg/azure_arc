$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Env:LocalBoxDir = 'C:\LocalBox'

$LocalBoxConfig = Import-PowerShellDataFile -Path $Env:LocalBoxConfigFile
Start-Transcript -Path "$($LocalBoxConfig.Paths.LogsDir)\Generate-ARM-Template.log"

$arcNodes = Get-AzConnectedMachine -ResourceGroup $env:resourceGroup
$arcNodeResourceIds = @($arcNodes.Id)

$domainName = $LocalBoxConfig.SDNDomainFQDN.Split('.')
$ouPath = "OU=$($LocalBoxConfig.LCMADOUName)"
foreach ($name in $domainName) {
    $ouPath += ",DC=$name"
}

$guid = ([System.Guid]::NewGuid()).ToString().Substring(0, 5).ToLower()
$keyVaultName = "localbox-kv-$guid"
$diagnosticsStorageName = "localboxdiagsa$guid"

$physicalNodesSettings = @(
    foreach ($node in $LocalBoxConfig.NodeHostConfig) {
        @{
            name        = $node.Hostname
            ipv4Address = $node.IP.Split('/')[0]
        }
    }
)

$AzLocalParams = "$env:LocalBoxDir\azlocal.parameters.json"
$paramsObject = Get-Content -Path $AzLocalParams -Raw | ConvertFrom-Json -Depth 100

$paramsObject.parameters.clusterName.value = $LocalBoxConfig.ClusterName
$paramsObject.parameters.arcNodeResourceIds.value = $arcNodeResourceIds
$paramsObject.parameters.localAdminUserName.value = 'Administrator'
$paramsObject.parameters.localAdminPassword.value = $LocalBoxConfig.SDNAdminPassword
$paramsObject.parameters.AzureStackLCMAdminUsername.value = $LocalBoxConfig.LCMDeployUsername
$paramsObject.parameters.AzureStackLCMAdminPasssword.value = $LocalBoxConfig.SDNAdminPassword
$paramsObject.parameters.hciResourceProviderObjectID.value = $env:spnProviderId
$paramsObject.parameters.domainFqdn.value = $LocalBoxConfig.SDNDomainFQDN
$paramsObject.parameters.namingPrefix.value = $LocalBoxConfig.LCMDeploymentPrefix
$paramsObject.parameters.adouPath.value = $ouPath
$paramsObject.parameters.subnetMask.value = $LocalBoxConfig.rbSubnetMask
$paramsObject.parameters.defaultGateway.value = $LocalBoxConfig.SDNLABRoute
$paramsObject.parameters.startingIPAddress.value = $LocalBoxConfig.clusterIpRangeStart
$paramsObject.parameters.endingIPAddress.value = $LocalBoxConfig.clusterIpRangeEnd
$paramsObject.parameters.dnsServers.value = @($LocalBoxConfig.vmDNS)
$paramsObject.parameters.keyVaultName.value = $keyVaultName
$paramsObject.parameters.physicalNodesSettings.value = $physicalNodesSettings
$paramsObject.parameters.storageNetworkList.value[0].vlanId = $LocalBoxConfig.StorageAVLAN
$paramsObject.parameters.storageNetworkList.value[1].vlanId = $LocalBoxConfig.StorageBVLAN
$paramsObject.parameters.clusterWitnessStorageAccountName.value = $env:stagingStorageAccountName
$paramsObject.parameters.diagnosticStorageAccountName.value = $diagnosticsStorageName
$paramsObject.parameters.customLocation.value = $LocalBoxConfig.rbCustomLocationName
$paramsObject.parameters.location.value = $env:azureLocation
$paramsObject.parameters.tenantId.value = $env:tenantId

$paramsObject | ConvertTo-Json -Depth 100 | Set-Content -Path $AzLocalParams -Encoding utf8

Stop-Transcript
