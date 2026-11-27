#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Repacks a new blackshard build (dist\) into the read-only payload ISO and swaps it into the VM.
  Inside the VM it shows up on the BSLAB drive under dist\. Then run install.ps1 again and restart
  (the driver can't be unloaded), before retaking the 'ready' checkpoint.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DistPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
Assert-LabAdmin
Assert-LabHyperV
$c = Get-LabConfig

$drive = Get-VMDvdDrive -VMName $c.VmName | Where-Object { $_.ControllerNumber -eq 1 -and $_.ControllerLocation -eq 1 }
if (-not $drive) { throw 'The payload DVD drive (IDE 1:1) is missing from the VM.' }
# Eject first so the old ISO file is no longer in use, then rebuild and reinsert.
Set-VMDvdDrive -VMDvdDrive $drive -Path $null
$iso = New-LabPayload -DistPath $DistPath
Set-VMDvdDrive -VMDvdDrive $drive -Path $iso
Write-Host "[+] New payload inserted: $iso" -ForegroundColor Green
