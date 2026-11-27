#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Copies text reports (service.log, report.json, ...) out of the VM's OUTBOX disk.

  The VM must be off. The disk is mounted read-only with no drive letter, only plain-text file
  types under 50 MB are copied, and nothing on it is ever executed. Do this BEFORE reverting a
  checkpoint: reverting also rolls the outbox back.
#>
[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $PSScriptRoot "exports\$(Get-Date -Format 'yyyyMMdd-HHmmss')")
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
Assert-LabAdmin
Assert-LabHyperV
$c = Get-LabConfig

$vm = Get-VM -Name $c.VmName
if ($vm.State -ne 'Off') { throw "Shut the VM down first (it is $($vm.State))." }

# With checkpoints, the outbox's current contents live in its newest differencing disk (.avhdx).
$outbox = Get-VMHardDiskDrive -VM $vm -ControllerType SCSI | Where-Object { $_.Path -match 'outbox' } | Select-Object -First 1
if (-not $outbox) { throw 'The VM has no outbox disk.' }

$allowed = '.log', '.txt', '.json', '.csv', '.md', '.xml'
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$disk = Mount-VHD -Path $outbox.Path -ReadOnly -NoDriveLetter -Passthru | Get-Disk
try {
    $partition = Get-Partition -DiskNumber $disk.Number | Where-Object Size -gt 100MB | Select-Object -First 1
    $tempMount = Join-Path (Get-LabStateDir) 'outbox-mount'
    New-Item -ItemType Directory -Force -Path $tempMount | Out-Null
    Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $tempMount
    try {
        Get-ChildItem -LiteralPath $tempMount -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $allowed -contains $_.Extension.ToLowerInvariant() -and $_.Length -lt 50MB } |
            ForEach-Object {
                $relative = $_.FullName.Substring($tempMount.Length).TrimStart('\')
                $target = Join-Path $Destination $relative
                New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
                Copy-Item -LiteralPath $_.FullName -Destination $target
                Write-Host "    $relative"
            }
    }
    finally {
        Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $tempMount
    }
}
finally { Dismount-VHD -Path $outbox.Path }
Write-Host "[+] Exported to $Destination" -ForegroundColor Green
