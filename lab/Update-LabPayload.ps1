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

$slot = @{ VMName = $c.VmName; ControllerNumber = 1; ControllerLocation = 1 }
if (-not (Get-VMDvdDrive @slot -ErrorAction SilentlyContinue)) { throw 'The payload DVD drive (IDE 1:1) is missing from the VM.' }
# Eject first so the old ISO file is no longer in use, then rebuild and reinsert. The drive is
# named by its slot each time: on a running VM, the object from before the eject is stale after it.
Set-VMDvdDrive @slot -Path $null
$iso = New-LabPayload -DistPath $DistPath
Set-VMDvdDrive @slot -Path $iso
Write-Host "[+] New payload inserted: $iso" -ForegroundColor Green
