# Requires: PowerShell 5.1+; optional azcmagent (Azure Connected Machine agent)
# Purpose : Validate Azure Arc (Servers) reachability from inside the network for East US.
# Output  : CSV and JSON reports under %TEMP%, non-zero exit if any test fails.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Settings
$Location  = 'eastus'
$TimeoutSec = 10
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutCsv  = Join-Path $env:TEMP "arc-endpoints-$Location-$Timestamp.csv"
$OutJson = Join-Path $env:TEMP "arc-endpoints-$Location-$Timestamp.json"

Write-Host "Azure Arc reachability check for region: $Location" -ForegroundColor Cyan

function Invoke-HttpHead {
  param([Parameter(Mandatory)][string]$TargetHost, [int]$TimeoutSec = 10, [string]$Proxy)
  $uri = "https://$TargetHost/"
  try {
    $params = @{ Uri = $uri; Method = 'Head'; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
    if ($Proxy) {
      $params.Proxy = $Proxy
      $params.ProxyUseDefaultCredentials = $true
    }
    $r = Invoke-WebRequest @params
    return @{ Ok=$true; Code=$r.StatusCode; Error=$null }
  } catch {
    $code = $null
    try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
    if ($code -in 401,403) { return @{ Ok=$true; Code=$code; Error=$null } }
    return @{ Ok=$false; Code=$code; Error=$_.Exception.Message }
  }
}

function Get-ArcEndpointsFromAzcmagent {
  param([string]$Location)
  $hosts = @()
  $azcm = Get-Command azcmagent -ErrorAction SilentlyContinue
  if (-not $azcm) { return @() }

  Write-Host "Running 'azcmagent check --location $Location' to discover endpoints..." -ForegroundColor Yellow
  $check = & azcmagent check --location $Location 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "azcmagent check returned exit code $LASTEXITCODE; attempting to parse output anyway."
  }

  $regex = [regex]'(?:(?<=https://|http://))?([a-z0-9-]+\.)+[a-z]{2,}'
  foreach ($line in $check) {
    foreach ($m in $regex.Matches([string]$line)) {
      $h = $m.Value.Trim().Trim('/')
      if ($h -match '^(https?://)') { $h = $h -replace '^(https?://)','' }
      if ($h -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and $h -ne 'localhost') {
        $hosts += $h.ToLower()
      }
    }
  }
  $hosts | Sort-Object -Unique
}

function Get-FallbackEndpointsEastUS {
  # Minimal, commonly required endpoints for Arc onboarding/ops and Azure Monitor.
  # NOTE: This list is not exhaustive. Prefer azcmagent discovery when available.
  @(
    'login.microsoftonline.com'
    '*.login.microsoft.com'
    'download.microsoft.com'
    'packages.microsoft.com'
    'pas.windows.net'
    '*.guestconfiguration.azure.com'
    'guesnotificationservice.azure.com'
    'servicebus.windows.net'
    'waconazure.com'
    'blob.core.windows.net'
    'eastus.arcdataservices.com'
    'dls.microsoft.com'
    'management.azure.com'
    'guestconfiguration.azure.com'
    'his.arc.azure.com'
    'gbl.his.arc.azure.com'
    'eastus.his.arc.azure.com'
    'gbl.his.arc.azure.net'              # some environments may see this
    #'global.handler.control.monitor.azure.com'
    #'eastus.handler.control.monitor.azure.com'
    #'agentserviceapi.azure-automation.net'
    #'ods.opinsights.azure.com'
    #'oms.opinsights.azure.com'
    #'monitoring.azure.com'
    #'dc.services.visualstudio.com'
    #'global.prod.microsoftmetrics.com'
  ) | Sort-Object -Unique
}

# Discover endpoints
$endpoints = Get-ArcEndpointsFromAzcmagent -Location $Location
if (-not $endpoints -or $endpoints.Count -eq 0) {
  Write-Warning "azcmagent not available or returned no endpoints; using fallback East US list."
  $endpoints = Get-FallbackEndpointsEastUS
}

Write-Host ("Testing {0} endpoints ..." -f $endpoints.Count) -ForegroundColor Cyan

# Optional: honor system proxy if set (WinHTTP/ENV). Leave blank to test direct.
$Proxy = $null

$results = foreach ($h in $endpoints) {
  $dnsOk = $false; $dnsErr = $null; $ips = @()
  try {
    $dns = Resolve-DnsName -Name $h -ErrorAction Stop
    $ips = ($dns | Where-Object {$_.Type -in 'A','AAAA'} | Select-Object -ExpandProperty IPAddress) -join ','
    $dnsOk = $true
  } catch { $dnsErr = $_.Exception.Message }

  $tlsOk = $false; $tlsErr = $null
  try {
    $tnc = Test-NetConnection -ComputerName $h -Port 443 -WarningAction SilentlyContinue
    $tlsOk = [bool]$tnc.TcpTestSucceeded
    if (-not $tlsOk) { $tlsErr = "TCP 443 failed" }
  } catch { $tlsErr = $_.Exception.Message }

  $http = Invoke-HttpHead -TargetHost $h -TimeoutSec $TimeoutSec -Proxy $Proxy

  [pscustomobject]@{
    Host   = $h
    IPs    = $ips
    DNS    = if ($dnsOk) {'PASS'} else {'FAIL'}
    TLS443 = if ($tlsOk) {'PASS'} else {'FAIL'}
    HTTPS  = if ($http.Ok) {"PASS ($($http.Code))"} else {"FAIL ($($http.Code))"}
    Error  = ($dnsErr, $tlsErr, $http.Error | Where-Object {$_}) -join ' | '
  }
}

# Save reports
$results | Tee-Object -FilePath $OutCsv | Out-Null
$results | ConvertTo-Json -Depth 4 | Set-Content -Path $OutJson -Encoding UTF8

# Summary
$bad = $results | Where-Object { $_.DNS -eq 'FAIL' -or $_.TLS443 -eq 'FAIL' -or $_.HTTPS -like 'FAIL*' }
Write-Host ""
Write-Host "Report saved:" -ForegroundColor Green
Write-Host " - CSV : $OutCsv"
Write-Host " - JSON: $OutJson"
Write-Host ""
if ($bad) {
  Write-Host "Failures detected:" -ForegroundColor Red
  $bad | Format-Table -AutoSize
  exit 1
} else {
  Write-Host "All tests passed." -ForegroundColor Green
  exit 0
}