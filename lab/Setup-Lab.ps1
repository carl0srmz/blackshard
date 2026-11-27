#Requires -RunAsAdministrator
<#
.SYNOPSIS
  One command to rebuild the whole filming lab on a new PC. Safe to run again: each step is skipped
  once it is done.

  1. Enables Hyper-V (first run only; restart and run the same command again).
  2. Optionally builds blackshard (deploy.ps1) from a local checkout.
  3. Creates the networks and the VM, and starts the unattended Windows 10 install.

.EXAMPLE
  .\Setup-Lab.ps1 -WindowsIso D:\iso\Win10_22H2_English_x64.iso -Build
.EXAMPLE
  .\Setup-Lab.ps1 -WindowsIso D:\iso\Win10_22H2_English_x64.iso -DistPath C:\src\blackshard\dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WindowsIso,
    # A blackshard checkout (default: the one this lab\ folder is in). Its dist\ is used; with
    # -Build, deploy.ps1 runs first.
    [string]$RepoPath,
    [switch]$Build,
    # Or point straight at a dist\ folder.
    [string]$DistPath,
    [string]$Edition = 'Windows 10 Pro'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 1. Hyper-V
$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -ne 'Enabled' -or -not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    & (Join-Path $PSScriptRoot 'Enable-HyperV.ps1')
    Write-Host ''
    Write-Host '[!] Restart Windows, then run exactly the same command again to continue.' -ForegroundColor Yellow
    return
}

Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
$c = Get-LabConfig

# 2. blackshard build. lab\ lives inside the repository, so that checkout is the default.
if (-not $RepoPath -and -not $DistPath -and (Test-Path -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'deploy.ps1'))) {
    $RepoPath = Split-Path $PSScriptRoot -Parent
}
if ($RepoPath) {
    $RepoPath = (Resolve-Path -LiteralPath $RepoPath).Path
    if ($Build) {
        Write-Host "[*] Building blackshard in $RepoPath (deploy.ps1)..." -ForegroundColor Cyan
        Push-Location $RepoPath
        try {
            & rustup toolchain install
            & (Join-Path $RepoPath 'deploy.ps1')
            if ($LASTEXITCODE) { throw "deploy.ps1 failed with exit code $LASTEXITCODE." }
        }
        finally { Pop-Location }
    }
    $repoDist = Join-Path $RepoPath 'dist'
    if (-not $DistPath) {
        if (Test-Path -LiteralPath $repoDist) { $DistPath = $repoDist }
        else { Write-Host "    No dist\ in $RepoPath yet: the VM is set up without blackshard. Add it later with Update-LabPayload.ps1." }
    }
}
if ($DistPath -and -not (Test-Path -LiteralPath $DistPath)) {
    throw "$DistPath does not exist. Build first (-Build) or leave dist out and add it later with Update-LabPayload.ps1."
}

# 3. VM
if (Get-VM -Name $c.VmName -ErrorAction SilentlyContinue) {
    Write-Host "[+] $($c.VmName) already exists." -ForegroundColor Green
    if ($DistPath) { & (Join-Path $PSScriptRoot 'Update-LabPayload.ps1') -DistPath $DistPath }
    & (Join-Path $PSScriptRoot 'Set-LabNetwork.ps1')
    return
}
$params = @{ WindowsIso = $WindowsIso; Edition = $Edition }
if ($DistPath) { $params.DistPath = $DistPath }
& (Join-Path $PSScriptRoot 'New-BlackshardLab.ps1') @params
