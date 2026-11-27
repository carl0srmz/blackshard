Set-StrictMode -Version Latest

# Everything the lab scripts share. Change values here, not in the scripts.
$script:LabConfig = [ordered]@{
    VmName          = 'blackshard-film'
    VmRoot          = 'C:\HyperV\blackshard-film'
    MemoryBytes     = 8GB
    ProcessorCount  = 4
    OsDiskBytes     = 80GB
    OutboxDiskBytes = 2GB

    # VM-only switch: no host vNIC, no physical NIC. Samples run here.
    IsolatedSwitch  = 'blackshard-isolated'
    # Internal switch + WinNAT: internet only (host and LAN are denied by port ACLs).
    OnlineSwitch    = 'blackshard-online'
    NatName         = 'blackshard-online-nat'
    NatPrefix       = '10.213.0.0/24'
    HostNatIp       = '10.213.0.1'
    GuestIp         = '10.213.0.10'
    PrefixLength    = 24
    GuestDns        = @('1.1.1.1', '9.9.9.9')

    # Addresses the VM may never reach, enforced on the Hyper-V switch port (outside the guest).
    DeniedRemoteRanges = @(
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16',
        '100.64.0.0/10', '224.0.0.0/4', '255.255.255.255/32'
    )
    DeniedRemoteRangesV6 = @('fc00::/7', 'fe80::/10', 'ff00::/8')

    GuestUser       = 'filmer'
    ComputerName    = 'BSFILM'
}

$script:LabRoot  = $PSScriptRoot
$script:StateDir = Join-Path $PSScriptRoot 'state'

function Get-LabConfig { $script:LabConfig }
function Get-LabRoot { $script:LabRoot }
function Get-LabStateDir {
    if (-not (Test-Path -LiteralPath $script:StateDir)) {
        New-Item -ItemType Directory -Path $script:StateDir | Out-Null
    }
    $script:StateDir
}

# (Re)applies the switch-port ACLs: deny every private/link-local/multicast range, except the NAT
# gateway itself. Hyper-V port ACLs also filter ARP, so without that one /32 allow the 10/8 deny
# stops the VM from resolving its gateway and nothing leaves at all. Traffic to the gateway
# address is the host itself, which the host firewall rules block (all inbound on that adapter).
# Idempotent: clears whatever ACLs the adapter had first.
function Set-LabPortAcl {
    param([Parameter(Mandatory)]$VMNetworkAdapter)
    $c = Get-LabConfig
    Get-VMNetworkAdapterAcl -VMNetworkAdapter $VMNetworkAdapter | ForEach-Object {
        Remove-VMNetworkAdapterAcl -VMNetworkAdapter $VMNetworkAdapter -RemoteIPAddress $_.RemoteAddress -Direction $_.Direction -Action $_.Action
    }
    foreach ($range in $c.DeniedRemoteRanges) {
        Add-VMNetworkAdapterAcl -VMNetworkAdapter $VMNetworkAdapter -RemoteIPAddress $range -Direction Both -Action Deny
    }
    foreach ($range in $c.DeniedRemoteRangesV6) {
        try { Add-VMNetworkAdapterAcl -VMNetworkAdapter $VMNetworkAdapter -RemoteIPAddress $range -Direction Both -Action Deny }
        catch { Write-Warning "IPv6 ACL $range not applied: $($_.Exception.Message) (guest IPv6 is disabled anyway)." }
    }
    Add-VMNetworkAdapterAcl -VMNetworkAdapter $VMNetworkAdapter -RemoteIPAddress "$($c.HostNatIp)/32" -Direction Both -Action Allow
}

function Assert-LabAdmin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell (Run as administrator).'
    }
}

function Assert-LabHyperV {
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        throw 'The Hyper-V PowerShell module is missing. Run .\Enable-HyperV.ps1 and restart first.'
    }
}

# Builds a read-only data ISO from a folder with IMAPI2 (ships with Windows, no ADK needed).
# The ISO is the only way files go INTO the VM: one-way, read-only, no shared folders.
function New-LabIsoFile {
    param(
        [Parameter(Mandatory)][string]$SourceDirectory,
        [Parameter(Mandatory)][string]$Path,
        [string]$VolumeName = 'BSLAB'
    )
    if (-not ('BlackshardLab.IsoWriter' -as [type])) {
        Add-Type -TypeDefinition @'
namespace BlackshardLab {
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Runtime.InteropServices.ComTypes;
    public static class IsoWriter {
        public static void Write(string path, object stream, int blockSize, int totalBlocks) {
            IStream source = (IStream)stream;
            byte[] buffer = new byte[blockSize];
            IntPtr read = Marshal.AllocHGlobal(sizeof(int));
            try {
                using (FileStream output = File.Create(path)) {
                    while (totalBlocks-- > 0) {
                        source.Read(buffer, blockSize, read);
                        output.Write(buffer, 0, Marshal.ReadInt32(read));
                    }
                }
            } finally {
                Marshal.FreeHGlobal(read);
            }
        }
    }
}
'@
    }
    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $image.ChooseImageDefaultsForMediaType(13)   # IMAPI_MEDIA_TYPE_DISK: no size cap
    $image.FileSystemsToCreate = 7               # ISO9660 + Joliet + UDF
    $image.VolumeName = $VolumeName
    $image.Root.AddTree((Resolve-Path -LiteralPath $SourceDirectory).Path, $false)
    $result = $image.CreateResultImage()
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    [BlackshardLab.IsoWriter]::Write($Path, $result.ImageStream, $result.BlockSize, $result.TotalBlocks)
    Get-Item -LiteralPath $Path
}

# Stages the guest payload (unattend, guest scripts, config, optional dist\) and packs it as an ISO.
function New-LabPayload {
    param(
        [string]$DistPath,
        [string]$UnattendXml   # only on first build; later builds keep it out of the payload
    )
    $config = Get-LabConfig
    $state = Get-LabStateDir
    $staging = Join-Path $state 'payload-staging'
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging | Out-Null

    Set-Content -LiteralPath (Join-Path $staging 'blackshard-lab.marker') -Value 'blackshard lab payload' -Encoding ASCII
    Copy-Item -LiteralPath (Join-Path $script:LabRoot 'guest') -Destination (Join-Path $staging 'guest') -Recurse
    Remove-Item -LiteralPath (Join-Path $staging 'guest\autounattend.template.xml') -ErrorAction SilentlyContinue

    if ($UnattendXml) {
        Set-Content -LiteralPath (Join-Path $staging 'autounattend.xml') -Value $UnattendXml -Encoding UTF8
    }

    # Host addresses the guest isolation test should NOT be able to reach.
    $probe = @(
        Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
            ForEach-Object { $_.IPv4Address.IPAddress; $_.IPv4DefaultGateway.NextHop }
    ) | Where-Object { $_ } | Select-Object -Unique
    [ordered]@{
        guestIp      = $config.GuestIp
        prefixLength = $config.PrefixLength
        gateway      = $config.HostNatIp
        dns          = $config.GuestDns
        hostLanProbe = @($probe)
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $staging 'lab-config.json') -Encoding UTF8

    if ($DistPath) {
        $dist = (Resolve-Path -LiteralPath $DistPath).Path
        foreach ($required in 'blackshard.sys', 'blackshard-service.exe', 'install.ps1', 'enable-test-signing.ps1') {
            if (-not (Test-Path -LiteralPath (Join-Path $dist $required))) {
                throw "$DistPath does not look like blackshard's dist\ (missing $required). Run deploy.ps1 first."
            }
        }
        Copy-Item -LiteralPath $dist -Destination (Join-Path $staging 'dist') -Recurse
    }

    $iso = Join-Path $state 'payload.iso'
    New-LabIsoFile -SourceDirectory $staging -Path $iso -VolumeName 'BSLAB' | Out-Null
    Remove-Item -LiteralPath $staging -Recurse -Force
    $iso
}

Export-ModuleMember -Function Get-LabConfig, Get-LabRoot, Get-LabStateDir, Assert-LabAdmin,
    Assert-LabHyperV, New-LabIsoFile, New-LabPayload, Set-LabPortAcl
