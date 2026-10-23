#Requires -Version 5.1
<#
.SYNOPSIS
  Fails when a corpus report from a clean corpus holds any suspicious or malicious verdict, and
  lists what was flagged and why.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReportPath,
    [int]$MinimumFiles = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$result = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
if ([int]$result.files -lt $MinimumFiles) {
    throw "The clean corpus is too small to mean anything: $($result.files) files."
}
$flagged = @($result.results | Where-Object { $_.verdict -in 'suspicious', 'malicious' })
$flagged | Select-Object path, verdict, risk_score, threat_name, sha256, reasons | Format-List
if ($flagged.Count -gt 0) {
    throw "$($flagged.Count) of $($result.files) clean files were flagged: false positives."
}
Write-Host "No false positives in $($result.files) clean files."
