[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroupName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $ParametersFile,

    [Parameter()]
    [switch] $AllowInsecureSampleParameters,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $TemplateFile = (Join-Path $PSScriptRoot 'bicep\main.bicep'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $Location = 'westeurope'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SubscriptionId = 'cbaf34df-7bb5-4fcf-bd7d-686a5f43ad31'

function Get-DefaultParametersFile {
    $jsonParam = Join-Path $PSScriptRoot 'bicep\main.parameters.json'
    if (Test-Path -LiteralPath $jsonParam) {
        return $jsonParam
    }

    $bicepParam = Join-Path $PSScriptRoot 'bicep\\main.bicepparam'
    if (Test-Path -LiteralPath $bicepParam) {
        return $bicepParam
    }

    throw "No parameters file found. Expected either '$bicepParam' or '$jsonParam'."
}

if (-not $ParametersFile) {
    $ParametersFile = Get-DefaultParametersFile
}

$TemplateFile = (Resolve-Path -LiteralPath $TemplateFile).Path
$ParametersFile = (Resolve-Path -LiteralPath $ParametersFile).Path

if (-not $AllowInsecureSampleParameters) {
    $paramText = Get-Content -LiteralPath $ParametersFile -Raw

    if ($ParametersFile -like '*main.parameters.json' -and $paramText -match '<your\s+') {
        throw "ParametersFile appears to contain placeholders (e.g., '<your ...>'). Update '$ParametersFile' with real values or pass -AllowInsecureSampleParameters to proceed anyway."
    }

    if ($ParametersFile -like '*main.bicepparam' -and ($paramText -match "param\s+windowsAdminPassword\s*=\s*'arc@DEMO12345!'") ) {
        throw "ParametersFile appears to use the sample password 'arc@DEMO12345!'. For safety, set your own password in '$ParametersFile' or pass -AllowInsecureSampleParameters to proceed anyway."
    }
}

Write-Verbose "TemplateFile: $TemplateFile"
Write-Verbose "ParametersFile: $ParametersFile"
Write-Verbose "ResourceGroupName: $ResourceGroupName"
Write-Verbose "Location: $Location"
Write-Verbose "SubscriptionId: $SubscriptionId"

$az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
if (-not $az) {
    throw "Azure CLI ('az') is not installed or not on PATH. Install it from https://learn.microsoft.com/cli/azure/install-azure-cli"
}

$azDiagArgs = @()
if ($PSBoundParameters.ContainsKey('Verbose') -or $VerbosePreference -ne 'SilentlyContinue') {
    $azDiagArgs += '--verbose'
}
if ($PSBoundParameters.ContainsKey('Debug') -or $DebugPreference -ne 'SilentlyContinue') {
    $azDiagArgs += '--debug'
}

function Invoke-AzCli {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Args,

        [Parameter()]
        [switch] $NoOutput
    )

    $finalArgs = @($Args)
    if ($NoOutput) {
        $finalArgs += @('--output', 'none')
    }

    # Workaround: with this Azure CLI build, `az deployment group ...` breaks when
    # `--verbose/--debug` are placed before the command group. Put them at the end.
    if ($azDiagArgs.Count -gt 0) {
        $finalArgs += $azDiagArgs
    }

    & az @finalArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed (exit $LASTEXITCODE): az $($finalArgs -join ' ')"
    }
}

Write-Verbose "Validating Azure CLI login..."
try {
    Invoke-AzCli -Args @('account', 'show') -NoOutput
}
catch {
    throw "Not logged into Azure CLI. Run 'az login' first, then re-run this script. Original error: $($_.Exception.Message)"
}

Write-Verbose "Setting Azure subscription..."
Invoke-AzCli -Args @('account', 'set', '--subscription', $SubscriptionId) -NoOutput

Write-Verbose "Creating/ensuring resource group exists..."
if ($PSCmdlet.ShouldProcess("Resource group '$ResourceGroupName' in '$Location'", 'Create or update')) {
    Invoke-AzCli -Args @('group', 'create', '--name', $ResourceGroupName, '--location', $Location) -NoOutput
}

$deploymentName = 'azurelocal-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
Write-Verbose "Starting group deployment '$deploymentName'..."

if ($PSCmdlet.ShouldProcess("Deployment '$deploymentName'", 'Deploy Azure Local (LocalBox) Bicep template')) {
    $deployArgs = @(
        'deployment', 'group', 'create',
        '--resource-group', $ResourceGroupName,
        '--name', $deploymentName,
        '--template-file', $TemplateFile,
        '--parameters', $ParametersFile,
        '--parameters', "location=$Location",
        '--parameters', "azureLocalInstanceLocation=$Location"
    )

    Invoke-AzCli -Args $deployArgs
}
