[CmdletBinding()]
param(
    [Parameter()]
    [string] $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,

    [Parameter()]
    [string] $ResourceGroupName = $env:AZURE_RESOURCE_GROUP,

    [Parameter()]
    [string[]] $MachineName,

    [Parameter()]
    [switch] $WaitForCompletion,

    [Parameter()]
    [ValidateRange(10, 7200)]
    [int] $TimeoutInSeconds = 1800,

    [Parameter()]
    [ValidateRange(5, 300)]
    [int] $PollIntervalSeconds = 15
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Core') {
    throw 'Run this script with pwsh (PowerShell 7).'
}

Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
Import-Module Az.ConnectedMachine -ErrorAction Stop

function Get-DefaultMachineNames {
    $configPath = Join-Path $PSScriptRoot 'artifacts\PowerShell\LocalBox-Config.psd1'
    if (Test-Path -LiteralPath $configPath) {
        $config = Import-PowerShellDataFile -Path $configPath
        $names = @($config.NodeHostConfig | ForEach-Object { $_.Hostname } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($names.Count -gt 0) {
            return $names
        }
    }

    return @('AzLHOST1', 'AzLHOST2')
}

function Resolve-SubscriptionId {
    param(
        [string] $ConfiguredSubscriptionId
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredSubscriptionId)) {
        return $ConfiguredSubscriptionId
    }

    $context = Get-AzContext
    if ($null -ne $context -and $null -ne $context.Subscription -and -not [string]::IsNullOrWhiteSpace($context.Subscription.Id)) {
        return $context.Subscription.Id
    }

    throw 'SubscriptionId was not provided, AZURE_SUBSCRIPTION_ID is empty, and there is no current Az context.'
}

function Get-TargetMachines {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ResolvedSubscriptionId,

        [Parameter(Mandatory = $true)]
        [string[]] $RequestedMachineNames,

        [string] $ConfiguredResourceGroupName
    )

    $allMachines = if ([string]::IsNullOrWhiteSpace($ConfiguredResourceGroupName)) {
        @(Get-AzConnectedMachine -SubscriptionId $ResolvedSubscriptionId)
    }
    else {
        @(Get-AzConnectedMachine -SubscriptionId $ResolvedSubscriptionId -ResourceGroupName $ConfiguredResourceGroupName)
    }

    if ($allMachines.Count -eq 0) {
        $scopeText = if ($ConfiguredResourceGroupName) {
            "subscription '$ResolvedSubscriptionId', resource group '$ConfiguredResourceGroupName'"
        }
        else {
            "subscription '$ResolvedSubscriptionId'"
        }

        throw "No Arc-enabled machines were found in $scopeText."
    }

    $targets = @($allMachines | Where-Object { $_.Name -in $RequestedMachineNames })
    $missing = @($RequestedMachineNames | Where-Object { $_ -notin $targets.Name })
    if ($missing.Count -gt 0) {
        throw "The following Arc-enabled machines were not found: $($missing -join ', ')."
    }

    $resourceGroups = @($targets | Select-Object -ExpandProperty ResourceGroupName -Unique)
    if ([string]::IsNullOrWhiteSpace($ConfiguredResourceGroupName) -and $resourceGroups.Count -ne 1) {
        throw "The requested machines span multiple resource groups ($($resourceGroups -join ', ')). Pass -ResourceGroupName explicitly."
    }

    return $targets
}

function Get-RunCommandState {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ResolvedSubscriptionId,

        [Parameter(Mandatory = $true)]
        [string] $TargetResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string] $TargetMachineName,

        [Parameter(Mandatory = $true)]
        [string] $RunCommandName
    )

    return Get-AzConnectedMachineRunCommand `
        -SubscriptionId $ResolvedSubscriptionId `
        -ResourceGroupName $TargetResourceGroupName `
        -MachineName $TargetMachineName `
        -RunCommandName $RunCommandName
}

function Wait-RunCommandCompletion {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ResolvedSubscriptionId,

        [Parameter(Mandatory = $true)]
        [string] $TargetResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string] $TargetMachineName,

        [Parameter(Mandatory = $true)]
        [string] $RunCommandName,

        [Parameter(Mandatory = $true)]
        [int] $TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [int] $IntervalSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $state = Get-RunCommandState -ResolvedSubscriptionId $ResolvedSubscriptionId -TargetResourceGroupName $TargetResourceGroupName -TargetMachineName $TargetMachineName -RunCommandName $RunCommandName
        $provisioningState = [string] $state.ProvisioningState
        $executionState = [string] $state.InstanceViewExecutionState

        if ($executionState -in @('Succeeded', 'Failed', 'TimedOut', 'Canceled')) {
            return $state
        }

        if ($provisioningState -eq 'Failed') {
            return $state
        }

        Start-Sleep -Seconds $IntervalSeconds
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for Arc run command '$RunCommandName' on '$TargetMachineName'."
}

if (-not $MachineName -or $MachineName.Count -eq 0) {
    $MachineName = Get-DefaultMachineNames
}

$resolvedSubscriptionId = Resolve-SubscriptionId -ConfiguredSubscriptionId $SubscriptionId
Set-AzContext -Subscription $resolvedSubscriptionId | Out-Null

$targetMachines = Get-TargetMachines -ResolvedSubscriptionId $resolvedSubscriptionId -RequestedMachineNames $MachineName -ConfiguredResourceGroupName $ResourceGroupName
if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
    $ResourceGroupName = ($targetMachines | Select-Object -First 1).ResourceGroupName
}

Write-Host "Target subscription: $resolvedSubscriptionId" -ForegroundColor Cyan
Write-Host "Target resource group: $ResourceGroupName" -ForegroundColor Cyan
Write-Host "Target machines: $($targetMachines.Name -join ', ')" -ForegroundColor Cyan
Write-Host 'These machines can be Azure Local nested hosts as long as they are Azure Arc-enabled and Connected.' -ForegroundColor DarkCyan

foreach ($machine in $targetMachines) {
    Write-Host "Configuring $($machine.Name)..." -ForegroundColor Cyan
    if ($machine.Status -and $machine.Status -ne 'Connected') {
        throw "Machine '$($machine.Name)' is not in Connected state. Current state: $($machine.Status)"
    }

    if ($machine.OsName -and $machine.OsName -ne 'Azure Stack HCI') {
        Write-Warning "Machine '$($machine.Name)' reports OS '$($machine.OsName)'. Continuing because it matches the requested target list."
    }

    $currentVersion = if ($machine.AgentVersion) { $machine.AgentVersion } else { '<unknown>' }
    Write-Host "Current Arc agent version: $currentVersion"

    $upgradeScript = @'
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$logDir = "C:\Support\Logs"
$msiPath = Join-Path $env:TEMP "AzureConnectedMachineAgent.msi"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Invoke-WebRequest -Uri "https://aka.ms/AzureConnectedMachineAgent" -OutFile $msiPath
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn /l*v `"C:\Support\Logs\azcmagentupgradesetup.log`"" -Wait -NoNewWindow
azcmagent show
'@

    Invoke-AzRestMethod `
        -ResourceGroupName $ResourceGroupName `
        -ResourceProviderName 'Microsoft.HybridCompute' `
        -ResourceType 'machines' `
        -ApiVersion '2024-07-01' `
        -Name $machine.Name `
        -Method PATCH `
        -Payload '{"properties":{"agentUpgrade":{"enableAutomaticUpgrade":true}}}' | Out-Null

    $runName = 'InstallLatestArcAgent-{0}-{1}' -f $machine.Name, (Get-Date -Format 'yyyyMMddHHmmss')
    New-AzConnectedMachineRunCommand `
        -SubscriptionId $resolvedSubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -MachineName $machine.Name `
        -RunCommandName $runName `
        -Location $machine.Location `
        -SourceScript $upgradeScript `
        -TimeoutInSecond $TimeoutInSeconds | Out-Null

    Write-Host "Submitted run command '$runName' for $($machine.Name)." -ForegroundColor Green

    if ($WaitForCompletion) {
        Write-Host "Waiting for Arc run command '$runName' to complete on $($machine.Name)..."
        $state = Wait-RunCommandCompletion `
            -ResolvedSubscriptionId $resolvedSubscriptionId `
            -TargetResourceGroupName $ResourceGroupName `
            -TargetMachineName $machine.Name `
            -RunCommandName $runName `
            -TimeoutSeconds $TimeoutInSeconds `
            -IntervalSeconds $PollIntervalSeconds

        $executionState = [string] $state.InstanceViewExecutionState
        $output = [string] $state.InstanceViewOutput
        $errorText = [string] $state.InstanceViewError

        if ($executionState -ne 'Succeeded') {
            throw "Arc agent upgrade failed for '$($machine.Name)'. Execution state: $executionState. Error: $errorText"
        }

        $refreshedMachine = Get-AzConnectedMachine -SubscriptionId $resolvedSubscriptionId -ResourceGroupName $ResourceGroupName -Name $machine.Name
        $newVersion = if ($refreshedMachine.AgentVersion) { $refreshedMachine.AgentVersion } else { '<unknown>' }
        Write-Host "Upgrade completed for $($machine.Name). New Arc agent version: $newVersion" -ForegroundColor Green

        if (-not [string]::IsNullOrWhiteSpace($output)) {
            Write-Host $output
        }
    }
}
