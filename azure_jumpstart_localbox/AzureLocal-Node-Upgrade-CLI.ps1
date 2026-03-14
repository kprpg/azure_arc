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

$scriptPath = Join-Path $PSScriptRoot 'AzureLocal-Node-Upgrade.ps1'
if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Upgrade script not found: $scriptPath"
}

& $scriptPath `
    -SubscriptionId $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -MachineName $MachineName `
    -WaitForCompletion:$WaitForCompletion `
    -TimeoutInSeconds $TimeoutInSeconds `
    -PollIntervalSeconds $PollIntervalSeconds
