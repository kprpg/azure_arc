[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SubscriptionId,

    [Parameter()]
    [string] $ResourceGroupName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$readerRoleDefinitionId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

function Invoke-AzJson {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Args
    )

    $output = & az @Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed (exit $LASTEXITCODE): az $($Args -join ' ')`n$output"
    }

    if (-not $output) {
        return $null
    }

    return ($output | ConvertFrom-Json -Depth 100)
}

function Invoke-AzText {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Args
    )

    $output = & az @Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed (exit $LASTEXITCODE): az $($Args -join ' ')`n$output"
    }

    return ($output | Out-String).Trim()
}

function Test-AzSuccess {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Args,

        [Parameter(Mandatory = $true)]
        [ref] $Output
    )

    $result = & az @Args 2>&1
    $Output.Value = ($result | Out-String).Trim()
    return $LASTEXITCODE -eq 0
}

function Get-CurrentPrincipalContext {
    $account = Invoke-AzJson -Args @(
        'account', 'show',
        '--output', 'json',
        '--only-show-errors'
    )

    $principalName = [string]$account.user.name
    $principalType = [string]$account.user.type

    if ([string]::IsNullOrWhiteSpace($principalName) -or [string]::IsNullOrWhiteSpace($principalType)) {
        throw 'Unable to determine the current Azure principal from az account show.'
    }

    switch ($principalType.ToLowerInvariant()) {
        'user' {
            $objectId = Invoke-AzText -Args @(
                'ad', 'signed-in-user', 'show',
                '--query', 'id',
                '--output', 'tsv',
                '--only-show-errors'
            )

            return [pscustomobject]@{
                Name          = $principalName
                ObjectId      = [string]$objectId
                PrincipalType = 'User'
            }
        }
        'serviceprincipal' {
            $objectId = Invoke-AzText -Args @(
                'ad', 'sp', 'show',
                '--id', $principalName,
                '--query', 'id',
                '--output', 'tsv',
                '--only-show-errors'
            )

            return [pscustomobject]@{
                Name          = $principalName
                ObjectId      = [string]$objectId
                PrincipalType = 'ServicePrincipal'
            }
        }
        default {
            throw "Unsupported Azure principal type '$principalType' for automatic DCR access remediation."
        }
    }
}

function Test-RoleAssignmentExists {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PrincipalObjectId,

        [Parameter(Mandatory = $true)]
        [string] $Scope,

        [Parameter(Mandatory = $true)]
        [string] $RoleDefinitionId
    )

    $assignments = Invoke-AzJson -Args @(
        'role', 'assignment', 'list',
        '--assignee-object-id', $PrincipalObjectId,
        '--scope', $Scope,
        '--role', $RoleDefinitionId,
        '--output', 'json',
        '--only-show-errors'
    )

    return ($assignments | Measure-Object).Count -gt 0
}

function Ensure-DcrReadAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string] $DcrId,

        [Parameter(Mandatory = $true)]
        $Principal
    )

    $readResult = Test-DcrReadAccess -DcrId $DcrId
    if ($readResult.Succeeded) {
        return [pscustomobject]@{
            Succeeded = $true
            Changed   = $false
            Message   = "Verified read access to linked Data Collection Rule: $DcrId"
        }
    }

    if (-not (Test-RoleAssignmentExists -PrincipalObjectId $Principal.ObjectId -Scope $DcrId -RoleDefinitionId $readerRoleDefinitionId)) {
        Write-Host "Missing read access to linked Data Collection Rule. Attempting to grant Reader on: $DcrId"

        $assignmentOutput = $null
        $assignmentSucceeded = Test-AzSuccess -Args @(
            'role', 'assignment', 'create',
            '--assignee-object-id', $Principal.ObjectId,
            '--assignee-principal-type', $Principal.PrincipalType,
            '--role', $readerRoleDefinitionId,
            '--scope', $DcrId,
            '--output', 'json',
            '--only-show-errors'
        ) -Output ([ref]$assignmentOutput)

        if (-not $assignmentSucceeded) {
            return [pscustomobject]@{
                Succeeded        = $false
                Changed          = $false
                Message          = $readResult.Output
                RemediationError = if ($assignmentOutput) { $assignmentOutput } else { 'Automatic Reader role assignment failed.' }
            }
        }
    }

    Start-Sleep -Seconds 5
    $verifyResult = Test-DcrReadAccess -DcrId $DcrId
    if ($verifyResult.Succeeded) {
        return [pscustomobject]@{
            Succeeded = $true
            Changed   = $true
            Message   = "Granted Reader and verified read access to linked Data Collection Rule: $DcrId"
        }
    }

    return [pscustomobject]@{
        Succeeded        = $false
        Changed          = $true
        Message          = if ($verifyResult.Output) { $verifyResult.Output } else { $readResult.Output }
        RemediationError = 'Reader role assignment was attempted, but read access is still not effective.'
    }
}

function Get-ExistingScopes {
    $scopes = [System.Collections.Generic.List[string]]::new()
    $scopes.Add("/subscriptions/$SubscriptionId")

    if ($ResourceGroupName) {
        $existsOutput = $null
        $groupExists = Test-AzSuccess -Args @('group', 'exists', '--name', $ResourceGroupName, '--output', 'tsv', '--only-show-errors') -Output ([ref]$existsOutput)
        if ($groupExists -and $existsOutput -eq 'true') {
            $scopes.Add("/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName")
        }
    }

    return $scopes | Select-Object -Unique
}

function Add-DcrMatches {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]] $Matches
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return
    }

    $pattern = '(?i)/subscriptions/[^/\s]+/resourceGroups/[^/\s]+/providers/Microsoft\.Insights/dataCollectionRules/[^\s"'']+'
    foreach ($match in [regex]::Matches($Text, $pattern)) {
        [void]$Matches.Add($match.Value)
    }
}

function Get-DcrIdsFromValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]] $Matches
    )

    if ($null -eq $Value) {
        return
    }

    if ($Value -is [string]) {
        Add-DcrMatches -Text $Value -Matches $Matches
        return
    }

    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($entry in $Value.GetEnumerator()) {
            Get-DcrIdsFromValue -Value $entry.Value -Matches $Matches
        }
        return
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        foreach ($item in $Value) {
            Get-DcrIdsFromValue -Value $item -Matches $Matches
        }
        return
    }

    foreach ($property in $Value.PSObject.Properties) {
        Get-DcrIdsFromValue -Value $property.Value -Matches $Matches
    }
}

function Get-ReferencedDcrIds {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Scopes
    )

    $matches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($scope in $Scopes) {
        $assignments = Invoke-AzJson -Args @(
            'policy', 'assignment', 'list',
            '--scope', $scope,
            '--disable-scope-strict-match', 'true',
            '--output', 'json',
            '--only-show-errors'
        )

        Get-DcrIdsFromValue -Value $assignments -Matches $matches
    }

    return @($matches.ToArray() | Sort-Object)
}

function Test-DcrReadAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string] $DcrId
    )

    $commandOutput = $null
    $succeeded = Test-AzSuccess -Args @(
        'resource', 'show',
        '--ids', $DcrId,
        '--api-version', '2023-03-11',
        '--output', 'json',
        '--only-show-errors'
    ) -Output ([ref]$commandOutput)

    return [pscustomobject]@{
        Succeeded = $succeeded
        Output    = $commandOutput
    }
}

$scopes = Get-ExistingScopes
Write-Host 'Checking effective Azure Policy assignments for linked Data Collection Rules...'

$currentPrincipal = Get-CurrentPrincipalContext
Write-Host "Using Azure principal '$($currentPrincipal.Name)' ($($currentPrincipal.PrincipalType)) for linked DCR access checks."

$dcrIds = Get-ReferencedDcrIds -Scopes $scopes
if ($dcrIds.Count -eq 0) {
    Write-Host 'No linked Data Collection Rule references were discovered in policy assignment payloads.'
    return
}

Write-Host "Found $($dcrIds.Count) linked Data Collection Rule reference(s) in effective policy assignments."

$failures = [System.Collections.Generic.List[object]]::new()
foreach ($dcrId in $dcrIds) {
    $result = Ensure-DcrReadAccess -DcrId $dcrId -Principal $currentPrincipal
    if ($result.Succeeded) {
        Write-Host $result.Message
        continue
    }

    $failures.Add([pscustomobject]@{
            DcrId            = $dcrId
            Error            = $result.Message
            RemediationError = $result.RemediationError
        }) | Out-Null
}

if ($failures.Count -gt 0) {
    $details = $failures | ForEach-Object {
        if ($_.RemediationError) {
            "- $($_.DcrId)`n  Read check error: $($_.Error)`n  Auto-remediation error: $($_.RemediationError)"
        }
        else {
            "- $($_.DcrId)`n  Read check error: $($_.Error)"
        }
    }

    $remediation = @(
        'The current deployer can create resources in the target resource group but still cannot read one or more policy-linked Data Collection Rules.',
        'This script already attempted to grant Reader on each linked DCR to the signed-in principal.',
        'If that failed, grant the deployer a role on the DCR scope that includes Microsoft.Insights/dataCollectionRules/read and Microsoft.Authorization/roleAssignments/write, or have an administrator grant Reader directly.',
        'If the DCR belongs to a central monitoring subscription, you can also exclude this LocalBox resource group from the inherited Azure Monitor policy assignment.',
        'The deployment is stopped here because ARM would otherwise fail later with LinkedAuthorizationFailed.'
    ) -join "`n"

    throw "$remediation`n`nAffected linked scopes:`n$($details -join "`n")"
}

Write-Host 'Verified read access to all linked Data Collection Rules referenced by effective policy assignments.'