#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Diagnoses the filming VM's Online network and writes lab\state\network-report.txt.

  Checks the host side (switch, NAT, firewall rules, port ACLs), then runs checks INSIDE the VM
  over PowerShell Direct (host-initiated, needs the VM password from state\vm-credentials.txt).
  If the VM is Online but can't reach the internet, it lifts each blocking layer for a single
  test and puts it straight back, to name the layer at fault. That only runs while no 'ready'
  checkpoint exists (nothing from a sample on the disk).
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
Assert-LabAdmin
Assert-LabHyperV
$c = Get-LabConfig
$report = Join-Path (Get-LabStateDir) 'network-report.txt'
$lines = New-Object Collections.Generic.List[string]
function Out-Report([string]$Title, $Value) {
    $lines.Add("===== $Title")
    $lines.Add(($Value | Out-String -Width 200).TrimEnd())
    Write-Host "===== $Title"
}

try {
    $vm = Get-VM -Name $c.VmName
    $nic = Get-VMNetworkAdapter -VM $vm
    Out-Report 'VM' ($vm | Select-Object Name, State, Status, Uptime, ParentCheckpointName | Format-List)
    Out-Report 'VM adapter' ($nic | Select-Object SwitchName, Connected, MacAddress, IPAddresses, Status, DhcpGuard, RouterGuard | Format-List)
    Out-Report 'Port ACLs' (Get-VMNetworkAdapterAcl -VMNetworkAdapter $nic | Select-Object Direction, Action, RemoteAddress | Format-Table -AutoSize)
    Out-Report 'Switches' (Get-VMSwitch | Select-Object Name, SwitchType | Format-Table -AutoSize)
    Out-Report 'NAT' (Get-NetNat | Select-Object Name, InternalIPInterfaceAddressPrefix, Active | Format-Table -AutoSize)
    Out-Report 'Host lab adapter' (Get-NetIPAddress -InterfaceAlias "vEthernet ($($c.OnlineSwitch))" -ErrorAction SilentlyContinue | Select-Object IPAddress, PrefixLength | Format-Table -AutoSize)
    Out-Report 'Host firewall rules' (Get-NetFirewallRule -Name 'blackshard-lab-*' | Select-Object Name, Enabled, Action | Format-Table -AutoSize)
    Out-Report 'Integration services' (Get-VMIntegrationService -VM $vm | Select-Object Name, Enabled, PrimaryStatusDescription | Format-Table -AutoSize)

    $hasReady = [bool](Get-VMCheckpoint -VM $vm -Name 'ready' -ErrorAction SilentlyContinue)
    if (-not $nic.SwitchName -or $nic.SwitchName -ne $c.OnlineSwitch) {
        if ($hasReady -and $vm.ParentCheckpointName -ne 'base') {
            Out-Report 'Network' "VM is not on the Online switch, and a 'ready' checkpoint exists: leaving it as it is."
            return
        }
        Connect-VMNetworkAdapter -VMNetworkAdapter $nic -SwitchName $c.OnlineSwitch
        Out-Report 'Network' "VM was on '$($nic.SwitchName)'; moved it to $($c.OnlineSwitch)."
    }

    if ($vm.State -ne 'Running') {
        Start-VM -VM $vm
        Out-Report 'VM start' 'VM was not running; started it.'
    }

    $cred = $null
    $credFile = Join-Path (Get-LabStateDir) 'vm-credentials.txt'
    $password = (Get-Content -LiteralPath $credFile | Where-Object { $_ -like 'password:*' }) -replace '^password:\s*', ''
    $cred = New-Object Management.Automation.PSCredential ("$($c.ComputerName)\$($c.GuestUser)", (ConvertTo-SecureString $password -AsPlainText -Force))

    Write-Host '[*] Waiting for the VM to accept PowerShell Direct (up to 5 min)...'
    $deadline = (Get-Date).AddMinutes(5)
    $session = $null
    while (-not $session -and (Get-Date) -lt $deadline) {
        try { $session = New-PSSession -VMName $c.VmName -Credential $cred -ErrorAction Stop }
        catch { Start-Sleep -Seconds 10 }
    }
    if (-not $session) { Out-Report 'PowerShell Direct' 'Could not connect into the VM within 5 minutes.'; return }

    $guestInfo = Invoke-Command -Session $session -ScriptBlock {
        "--- ipconfig /all"; ipconfig /all
        "--- route print -4"; route print -4
        "--- adapters"; Get-NetAdapter | Format-Table Name, Status, MacAddress, LinkSpeed -AutoSize | Out-String
        "--- IPv4 interface"; Get-NetIPInterface -AddressFamily IPv4 | Format-Table InterfaceAlias, Dhcp, ConnectionState -AutoSize | Out-String
        "--- lab firewall rules"; Get-NetFirewallRule -Name 'blackshard-lab-*' -ErrorAction SilentlyContinue | Format-Table Name, Enabled, Direction, Action -AutoSize | Out-String
        "--- firewall profiles"; Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize | Out-String
        "--- ARP"; arp -a
        "--- setup.log (tail)"; if (Test-Path C:\lab\setup.log) { Get-Content C:\lab\setup.log -Tail 80 } else { 'C:\lab\setup.log missing' }
    }
    Out-Report 'Inside the VM' $guestInfo

    $probe = {
        $result = [ordered]@{}
        $client = New-Object Net.Sockets.TcpClient
        try { $result['tcp 1.1.1.1:443'] = $client.ConnectAsync('1.1.1.1', 443).Wait(3000) -and $client.Connected } catch { $result['tcp 1.1.1.1:443'] = $false } finally { $client.Dispose() }
        try { $result['dns via 1.1.1.1'] = [bool](Resolve-DnsName example.com -Server 1.1.1.1 -DnsOnly -QuickTimeout -ErrorAction Stop) } catch { $result['dns via 1.1.1.1'] = $false }
        $result['ping gateway'] = Test-Connection 10.213.0.1 -Count 1 -Quiet
        [pscustomobject]$result
    }
    $baseline = Invoke-Command -Session $session -ScriptBlock $probe
    Out-Report 'Reachability, all layers on' ($baseline | Select-Object 'tcp 1.1.1.1:443', 'dns via 1.1.1.1', 'ping gateway' | Format-List)

    if (-not $baseline.'tcp 1.1.1.1:443') {
        if ($hasReady) {
            Out-Report 'Layer test' "Skipped: a 'ready' checkpoint exists, so layers are not lifted even briefly."
        }
        else {
            # 1. Host firewall rules, off for one probe.
            $rules = Get-NetFirewallRule -Name 'blackshard-lab-*'
            try {
                $rules | Disable-NetFirewallRule
                $r = Invoke-Command -Session $session -ScriptBlock $probe
                Out-Report 'With host firewall rules lifted' ($r | Select-Object 'tcp 1.1.1.1:443', 'dns via 1.1.1.1' | Format-List)
            }
            finally { $rules | Enable-NetFirewallRule }

            # 2. Port ACLs, removed for one probe and re-added exactly.
            $acls = @(Get-VMNetworkAdapterAcl -VMNetworkAdapter $nic)
            try {
                $acls | ForEach-Object { Remove-VMNetworkAdapterAcl -VMNetworkAdapter $nic -RemoteIPAddress $_.RemoteAddress -Direction $_.Direction -Action $_.Action }
                $r = Invoke-Command -Session $session -ScriptBlock $probe
                Out-Report 'With port ACLs lifted' ($r | Select-Object 'tcp 1.1.1.1:443', 'dns via 1.1.1.1' | Format-List)
            }
            finally {
                $acls | ForEach-Object { Add-VMNetworkAdapterAcl -VMNetworkAdapter $nic -RemoteIPAddress $_.RemoteAddress -Direction $_.Direction -Action $_.Action }
            }
            Out-Report 'Port ACLs after restore' (Get-VMNetworkAdapterAcl -VMNetworkAdapter $nic | Select-Object Direction, Action, RemoteAddress | Format-Table -AutoSize)
        }
    }
    Remove-PSSession $session
}
catch {
    Out-Report 'ERROR' ($_ | Out-String)
}
finally {
    $lines | Set-Content -LiteralPath $report -Encoding UTF8
    Write-Host "[+] Report: $report" -ForegroundColor Green
    if (-not (Get-Process vmconnect -ErrorAction SilentlyContinue)) {
        Start-Process vmconnect.exe -ArgumentList 'localhost', $c.VmName
    }
}
