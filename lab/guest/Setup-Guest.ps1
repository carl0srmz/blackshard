<#
  Runs once INSIDE the filming VM, at first sign-in (FirstLogonCommands in autounattend.xml).
  Log: C:\lab\setup.log
#>
param([Parameter(Mandatory)][string]$PayloadRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path C:\lab | Out-Null
Start-Transcript -Path C:\lab\setup.log -Append | Out-Null

function Step($text) { Write-Host "[*] $text" -ForegroundColor Cyan }

Step 'Copying lab scripts to C:\lab'
Copy-Item -Path (Join-Path $PayloadRoot 'guest\*') -Destination C:\lab -Recurse -Force
Copy-Item -LiteralPath (Join-Path $PayloadRoot 'lab-config.json') -Destination C:\lab -Force
Get-ChildItem C:\lab -Recurse -File | ForEach-Object { $_.IsReadOnly = $false }
$cfg = Get-Content C:\lab\lab-config.json -Raw | ConvertFrom-Json

Step 'Network: static IPv4 for the NAT switch, IPv6 off, Public profile'
$nic = Get-NetAdapter -Physical | Sort-Object ifIndex | Select-Object -First 1
if ($nic) {
    Disable-NetAdapterBinding -Name $nic.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled -ErrorAction SilentlyContinue
    Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $cfg.guestIp -PrefixLength $cfg.prefixLength -DefaultGateway $cfg.gateway | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $cfg.dns
    Get-NetConnectionProfile -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue | Set-NetConnectionProfile -NetworkCategory Public -ErrorAction SilentlyContinue
}

Step 'Guest firewall: no inbound, no outbound to private/link-local/multicast (backs up the host ACLs)'
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block
Get-NetFirewallRule -Name 'blackshard-lab-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name 'blackshard-lab-no-lan' -DisplayName 'blackshard lab: no LAN' -Direction Outbound -Action Block `
    -RemoteAddress '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', '224.0.0.0/4' | Out-Null
# LLMNR and NetBIOS name broadcasts: off.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object { $null = $_ | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } }

Step 'Defender: no cloud sample upload (fully off needs Tamper Protection off: see C:\lab\Disable-Defender.ps1)'
Set-MpPreference -SubmitSamplesConsent 2 -MAPSReporting 0 -ErrorAction SilentlyContinue

Step 'Filming comfort: no sleep, no screen-off, no auto-updates, file extensions shown'
powercfg /change monitor-timeout-ac 0; powercfg /change standby-timeout-ac 0; powercfg /hibernate off
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -Value 0 -Type DWord
New-Item -ItemType Directory -Force -Path C:\samples | Out-Null

Step 'Outbox disk -> O:'
$outbox = Get-Volume -FileSystemLabel OUTBOX -ErrorAction SilentlyContinue
if ($outbox) {
    $part = Get-Partition -Volume $outbox
    Set-Disk -Number $part.DiskNumber -IsOffline $false -ErrorAction SilentlyContinue
    Set-Disk -Number $part.DiskNumber -IsReadOnly $false -ErrorAction SilentlyContinue
    if ($outbox.DriveLetter -ne 'O') { $part | Set-Partition -NewDriveLetter O -ErrorAction SilentlyContinue }
}

$dist = Join-Path $PayloadRoot 'dist'
if (Test-Path -LiteralPath $dist) {
    Step 'blackshard dist -> C:\blackshard-dist, then test-signing'
    Copy-Item -LiteralPath $dist -Destination C:\blackshard-dist -Recurse -Force
    Get-ChildItem C:\blackshard-dist -Recurse -File | ForEach-Object { $_.IsReadOnly = $false }
    & C:\blackshard-dist\enable-test-signing.ps1
}
else {
    # No local build: take the testing build from the release (the VM is online and sample-free now).
    Step 'No dist\ on the payload: downloading the testing build, then test-signing'
    try { & C:\lab\Get-BlackshardRelease.ps1 }
    catch { Write-Host "    Download failed ($($_.Exception.Message)). Run C:\lab\Get-BlackshardRelease.ps1 later." -ForegroundColor Yellow }
}

@'
blackshard filming VM: next steps (full runbook: lab\README.md on the host)

1. Optional: turn off Tamper Protection in Windows Security, then run as admin:
     C:\lab\Disable-Defender.ps1
2. As admin:  cd C:\blackshard-dist; .\install.ps1 -AllowUnsigned   then restart.
   (If C:\blackshard-dist is missing: run C:\lab\Get-BlackshardRelease.ps1 as admin and restart
    first. It downloads the testing build and test-signs the driver.)
3. Open blackshard, wait for green + definitions.
4. Run C:\lab\Test-Isolation.ps1  -> expect: internet OK, host/LAN BLOCKED.
5. Host: Checkpoint-VM -Name blackshard-film -SnapshotName base
6. Download sample ZIPs into C:\samples. DO NOT unzip yet.
7. Host: .\Set-LabNetwork.ps1 -Mode Isolated
8. Run C:\lab\Test-Isolation.ps1  -> expect: everything BLOCKED.
9. Unzip samples, run --evaluate-corpus, then host: Checkpoint-VM ... -SnapshotName ready
Logs/reports for the host: save them to O:\ (the OUTBOX disk).
'@ | Set-Content -LiteralPath ([Environment]::GetFolderPath('Desktop') + '\NEXT-STEPS.txt') -Encoding UTF8

Step 'Restarting in 15 s'
Stop-Transcript | Out-Null
shutdown.exe /r /t 15 /c "blackshard lab setup finished"
