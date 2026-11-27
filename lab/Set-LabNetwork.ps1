#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Moves the filming VM between networks. Run with no -Mode to see the current one.

  Isolated  private switch: no host, no LAN, no internet. The ONLY mode for samples.
  Online    NAT to the internet only (host and LAN denied by switch-port ACLs). For Windows setup,
            blackshard definitions and downloading still-zipped samples. Never with samples unpacked.
  Off       adapter disconnected.
#>
[CmdletBinding()]
param(
    [ValidateSet('Isolated', 'Online', 'Off')][string]$Mode,
    # Go online even though a 'ready' checkpoint exists and the VM isn't running from 'base'.
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
Assert-LabAdmin
Assert-LabHyperV
$c = Get-LabConfig
$vm = Get-VM -Name $c.VmName
$nic = Get-VMNetworkAdapter -VM $vm

function Show-State {
    $n = Get-VMNetworkAdapter -VM $vm
    $now = if (-not $n.SwitchName) { 'Off' } elseif ($n.SwitchName -eq $c.IsolatedSwitch) { 'Isolated' }
           elseif ($n.SwitchName -eq $c.OnlineSwitch) { 'Online' } else { "UNEXPECTED switch '$($n.SwitchName)'" }
    $acls = @(Get-VMNetworkAdapterAcl -VMNetworkAdapter $n | Where-Object Action -eq 'Deny').Count
    Write-Host "$($c.VmName): network = $now; deny ACLs on port = $acls; running from checkpoint = $($vm.ParentCheckpointName)"
}

if (-not $Mode) { Show-State; return }

if ($Mode -eq 'Online' -and -not $Force) {
    $ready = Get-VMCheckpoint -VM $vm -Name 'ready' -ErrorAction SilentlyContinue
    if ($ready -and $vm.ParentCheckpointName -ne 'base') {
        throw @"
Refusing to go online: a 'ready' checkpoint exists, so samples may be unpacked on this disk.
Revert to the 'base' checkpoint first (Restore-VMCheckpoint -VMName $($c.VmName) -Name base), or pass -Force
if you are certain nothing from a sample is on the disk.
"@
    }
}

switch ($Mode) {
    'Isolated' { Connect-VMNetworkAdapter -VMNetworkAdapter $nic -SwitchName $c.IsolatedSwitch }
    'Online'   { Connect-VMNetworkAdapter -VMNetworkAdapter $nic -SwitchName $c.OnlineSwitch }
    'Off'      { Disconnect-VMNetworkAdapter -VMNetworkAdapter $nic }
}
Show-State
