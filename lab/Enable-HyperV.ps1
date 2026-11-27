#Requires -RunAsAdministrator
# Step 0: turn on Hyper-V (platform + management tools). Needs a restart afterwards.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -eq 'Enabled') {
    Write-Host '[+] Hyper-V is already enabled.' -ForegroundColor Green
    return
}

Write-Host '[*] Enabling Hyper-V...' -ForegroundColor Cyan
$result = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
if ($result.RestartNeeded) {
    Write-Host '[!] Restart Windows, then run .\New-BlackshardLab.ps1.' -ForegroundColor Yellow
}
