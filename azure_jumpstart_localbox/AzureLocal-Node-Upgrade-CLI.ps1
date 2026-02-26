$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -ne 'Core') { throw 'Run this script with pwsh (PowerShell 7).' }
Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
Import-Module Az.ConnectedMachine -ErrorAction Stop

# Arc agent upgrade for multiple Arc-enabled servers.
# This uses Az PowerShell Run Command because this environment's Azure CLI
# extension does not expose "az connectedmachine run-command".

$subscriptionId = "5f3972d8-b1e2-4a27-bf67-0db461308c53"
$resourceGroupName = "RGAZLOCAL"
$machines = @("AZLHOST1", "AZLHOST2")

Set-AzContext -Subscription $subscriptionId | Out-Null

foreach ($machine in $machines) {
    Write-Host "Configuring $machine..." -ForegroundColor Cyan

    # Keep automatic upgrades enabled for future upgrades.
    Invoke-AzRestMethod `
        -ResourceGroupName $resourceGroupName `
        -ResourceProviderName "Microsoft.HybridCompute" `
        -ResourceType "machines" `
        -ApiVersion "2024-07-01" `
        -Name $machine `
        -Method PATCH `
        -Payload '{"properties":{"agentUpgrade":{"enableAutomaticUpgrade":true}}}' | Out-Null

    # Trigger immediate agent upgrade on the host through Arc Run Command.
    $location = (Get-AzConnectedMachine -ResourceGroupName $resourceGroupName -Name $machine).Location
    $runName = "UpgradeArcAgent-{0}-{1}" -f $machine, (Get-Date -Format "yyyyMMddHHmmss")

    New-AzConnectedMachineRunCommand `
        -ResourceGroupName $resourceGroupName `
        -MachineName $machine `
        -RunCommandName $runName `
        -Location $location `
        -SourceScript "azcmagent upgrade; azcmagent show" `
        -TimeoutInSecond 1800 | Out-Null

    Write-Host "Submitted run command '$runName' for $machine" -ForegroundColor Green
}
