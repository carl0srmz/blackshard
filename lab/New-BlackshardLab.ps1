#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Creates the isolated blackshard filming VM (Gen 1 / BIOS, Windows 10) and its two networks.

.EXAMPLE
  .\New-BlackshardLab.ps1 -WindowsIso D:\iso\Win10_22H2_English_x64.iso -DistPath C:\src\blackshard\dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WindowsIso,
    # blackshard's dist\ from deploy.ps1. Optional now; add it later with Update-LabPayload.ps1.
    [string]$DistPath,
    [string]$Edition = 'Windows 10 Pro',
    [switch]$NoStart
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
Assert-LabAdmin
Assert-LabHyperV
$c = Get-LabConfig
$state = Get-LabStateDir

if (Get-VM -Name $c.VmName -ErrorAction SilentlyContinue) {
    throw "A VM named $($c.VmName) already exists. Remove it first (Remove-VM, then delete $($c.VmRoot))."
}

# --- 1. Inspect the Windows ISO ---------------------------------------------------------------
$WindowsIso = (Resolve-Path -LiteralPath $WindowsIso).Path
Write-Host "[*] Reading $WindowsIso..." -ForegroundColor Cyan
$mounted = Mount-DiskImage -ImagePath $WindowsIso -PassThru -Access ReadOnly -StorageType ISO
try {
    $letter = ($mounted | Get-Volume).DriveLetter
    $wim = @("${letter}:\sources\install.wim", "${letter}:\sources\install.esd") |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $wim) { throw 'This ISO has no sources\install.wim or install.esd. Is it a Windows install ISO?' }
    $images = @(Get-WindowsImage -ImagePath $wim)
    $image = $images | Where-Object ImageName -eq $Edition | Select-Object -First 1
    if (-not $image) {
        throw "Edition '$Edition' is not on this ISO. Pass -Edition with one of: $(($images.ImageName) -join ', ')"
    }
    $detail = Get-WindowsImage -ImagePath $wim -Index $image.ImageIndex
    $build = [version]$detail.Version
    if ($build.Build -ge 22000) {
        throw "This is Windows 11 (build $($build.Build)). FILMING.md needs Windows 10 on a Gen 1/BIOS VM; Windows 11 won't install without TPM/UEFI."
    }
    $language = @($detail.Languages)[0]
}
finally {
    Dismount-DiskImage -ImagePath $WindowsIso | Out-Null
}
Write-Host "    $Edition, build $build, $language (index $($image.ImageIndex))"

# Microsoft's published generic (KMS client) setup keys: they let Setup run unattended and
# leave Windows unactivated. Activate with your own key if the watermark bothers you on camera.
$keys = @{
    'Windows 10 Pro'          = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
    'Windows 10 Pro N'        = 'MH37W-N47XK-V7XM9-C7227-GCQG9'
    'Windows 10 Education'    = 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'
    'Windows 10 Enterprise'   = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
}
$productKeyBlock = ''
if ($keys.ContainsKey($Edition)) {
    $productKeyBlock = "<ProductKey><Key>$($keys[$Edition])</Key><WillShowUI>OnError</WillShowUI></ProductKey>"
}

# --- 2. Guest account + unattend ----------------------------------------------------------------
$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'.ToCharArray()
$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })

$unattend = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'guest\autounattend.template.xml') -Raw).
    Replace('{{LANG}}', $language).
    Replace('{{IMAGE_INDEX}}', [string]$image.ImageIndex).
    Replace('{{PRODUCT_KEY_BLOCK}}', $productKeyBlock).
    Replace('{{USER}}', $c.GuestUser).
    Replace('{{PASSWORD}}', $password).
    Replace('{{COMPUTER}}', $c.ComputerName)

$credFile = Join-Path $state 'vm-credentials.txt'
@"
blackshard filming VM ($($c.VmName)) - local account inside the VM only
user:     $($c.GuestUser)
password: $password
(The VM signs in automatically. This password exists nowhere else; it is not used on the host.)
"@ | Set-Content -LiteralPath $credFile -Encoding UTF8

# --- 3. Networks ------------------------------------------------------------------------------
$clash = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -like (($c.NatPrefix -split '\.')[0..2] -join '.') + '.*' -and $_.InterfaceAlias -notlike "*$($c.OnlineSwitch)*" }
if ($clash) { throw "$($c.NatPrefix) is already used on this host ($($clash.InterfaceAlias)). Change NatPrefix/HostNatIp/GuestIp in LabCommon.psm1." }

if (-not (Get-VMSwitch -Name $c.IsolatedSwitch -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Creating private switch $($c.IsolatedSwitch) (VM-only, no host or LAN path)..." -ForegroundColor Cyan
    New-VMSwitch -Name $c.IsolatedSwitch -SwitchType Private | Out-Null
}

if (-not (Get-VMSwitch -Name $c.OnlineSwitch -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Creating internal switch $($c.OnlineSwitch) + NAT $($c.NatPrefix)..." -ForegroundColor Cyan
    New-VMSwitch -Name $c.OnlineSwitch -SwitchType Internal | Out-Null
}
$hostIf = Get-NetAdapter -Name "vEthernet ($($c.OnlineSwitch))"
if (-not (Get-NetIPAddress -InterfaceIndex $hostIf.ifIndex -IPAddress $c.HostNatIp -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceIndex $hostIf.ifIndex -IPAddress $c.HostNatIp -PrefixLength $c.PrefixLength | Out-Null
}
# Nothing on the host needs IPv6 on this adapter.
Disable-NetAdapterBinding -Name $hostIf.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
if (-not (Get-NetNat -Name $c.NatName -ErrorAction SilentlyContinue)) {
    try {
        New-NetNat -Name $c.NatName -InternalIPInterfaceAddressPrefix $c.NatPrefix | Out-Null
    }
    catch {
        throw "Could not create the NAT ($($_.Exception.Message)). Another NAT (Docker, old WSL) may hold WinNAT: see Get-NetNat."
    }
}

# Host firewall: the VM may never open connections to the host itself (any protocol, v4 or v6).
$ruleName = 'blackshard-lab-block-vm-to-host'
if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $ruleName -DisplayName 'blackshard lab: block filming VM -> host' `
        -Direction Inbound -Action Block -Profile Any -InterfaceAlias $hostIf.Name | Out-Null
}
$ruleName2 = 'blackshard-lab-block-vm-subnet'
if (-not (Get-NetFirewallRule -Name $ruleName2 -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $ruleName2 -DisplayName 'blackshard lab: block filming VM subnet -> host' `
        -Direction Inbound -Action Block -Profile Any -RemoteAddress $c.NatPrefix | Out-Null
}

# No enhanced session: that path carries clipboard, drives and devices between host and VM.
# This is a host-wide Hyper-V setting.
Set-VMHost -EnableEnhancedSessionMode $false

# --- 4. The VM --------------------------------------------------------------------------------
Write-Host "[*] Creating VM $($c.VmName) in $($c.VmRoot)..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $c.VmRoot | Out-Null
$osDisk = Join-Path $c.VmRoot "$($c.VmName).vhdx"
New-VHD -Path $osDisk -SizeBytes $c.OsDiskBytes -Dynamic | Out-Null

$vm = New-VM -Name $c.VmName -Generation 1 -MemoryStartupBytes $c.MemoryBytes `
    -Path (Split-Path $c.VmRoot -Parent) -VHDPath $osDisk -SwitchName $c.OnlineSwitch
Set-VM -VM $vm -ProcessorCount $c.ProcessorCount -StaticMemory `
    -CheckpointType Standard -AutomaticCheckpointsEnabled $false `
    -AutomaticStartAction Nothing -AutomaticStopAction TurnOff `
    -Notes 'blackshard filming VM. Runs live malware. Never connect to an external switch.'
Set-VMProcessor -VM $vm -ExposeVirtualizationExtensions $false

# Integration services that move data between host and guest: off.
$disable = @(
    '6C09BB55-D683-4DA0-8931-C9BF705F6480',  # Guest Service Interface (Copy-VMFile)
    '2A34B1C2-FD73-4043-8A5B-DD2159BC743F',  # Key-Value Pair Exchange
    '5CED1297-4598-4915-A5FC-AD21BB4D02A4'   # VSS / Backup
)
Get-VMIntegrationService -VM $vm | Where-Object {
    $id = ($_.Id -split '\\')[-1]; $disable -contains $id.ToUpperInvariant()
} | Disable-VMIntegrationService

# Network adapter: guards on, and host-enforced ACLs that deny every private/link-local/multicast
# destination. These live on the Hyper-V switch port, so nothing inside the guest can lift them.
$nic = Get-VMNetworkAdapter -VM $vm
Set-VMNetworkAdapter -VMNetworkAdapter $nic -DhcpGuard On -RouterGuard On -MacAddressSpoofing Off
Set-LabPortAcl -VMNetworkAdapter $nic

# DVDs: Windows ISO on IDE 1:0, lab payload on IDE 1:1.
$payloadIso = New-LabPayload -DistPath $DistPath -UnattendXml $unattend
$dvd = Get-VMDvdDrive -VM $vm | Where-Object { $_.ControllerNumber -eq 1 -and $_.ControllerLocation -eq 0 }
if ($dvd) { Set-VMDvdDrive -VMDvdDrive $dvd -Path $WindowsIso }
else { Add-VMDvdDrive -VM $vm -ControllerNumber 1 -ControllerLocation 0 -Path $WindowsIso }
Add-VMDvdDrive -VM $vm -ControllerNumber 1 -ControllerLocation 1 -Path $payloadIso

# Hard disk first: a blank disk falls through to the DVD, and later boots never show
# "press any key to boot from CD" on camera.
Set-VMBios -VM $vm -StartupOrder @('IDE', 'CD', 'LegacyNetworkAdapter', 'Floppy')

# Outbox: a small data disk the guest writes logs/reports to. The host reads it read-only with
# Export-LabOutbox.ps1 while the VM is off. Attached on SCSI so the OS disk stays Disk 0.
$outbox = Join-Path $c.VmRoot 'outbox.vhdx'
New-VHD -Path $outbox -SizeBytes $c.OutboxDiskBytes -Dynamic | Out-Null
$disk = Mount-VHD -Path $outbox -Passthru -NoDriveLetter | Get-Disk
try {
    Initialize-Disk -Number $disk.Number -PartitionStyle MBR
    New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter:$false |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel 'OUTBOX' -Confirm:$false | Out-Null
}
finally { Dismount-VHD -Path $outbox }
if (-not (Get-VMScsiController -VM $vm)) { Add-VMScsiController -VM $vm }
Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber 0 -Path $outbox

Write-Host "[+] VM ready. Guest credentials saved to $credFile" -ForegroundColor Green
if (-not $NoStart) {
    Start-VM -VM $vm
    Start-Process vmconnect.exe -ArgumentList 'localhost', $c.VmName
    Write-Host '    Windows installs unattended (~15 min), signs in, runs the guest setup and restarts once.'
}
