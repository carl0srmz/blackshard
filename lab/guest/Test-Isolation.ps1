<#
  Inside the VM. Proves what the VM can and can't reach right now. Run it after every network change.
    Online:   internet OK; host and LAN BLOCKED
    Isolated: everything BLOCKED
#>
Set-StrictMode -Version Latest
$cfg = Get-Content C:\lab\lab-config.json -Raw | ConvertFrom-Json

function Test-Tcp([string]$Address, [int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try { $client.ConnectAsync($Address, $Port).Wait(1500) -and $client.Connected } catch { $false } finally { $client.Dispose() }
}

$rows = @()
foreach ($port in 445, 135, 3389, 80) {
    $rows += [pscustomobject]@{ Target = "host NAT side $($cfg.gateway):$port"; Kind = 'host/LAN'; Reached = Test-Tcp $cfg.gateway $port }
}
foreach ($ip in @($cfg.hostLanProbe)) {
    foreach ($port in 445, 80, 443) {
        $rows += [pscustomobject]@{ Target = "host LAN $($ip):$port"; Kind = 'host/LAN'; Reached = Test-Tcp $ip $port }
    }
}
$dns = $false; try { $dns = [bool](Resolve-DnsName example.com -DnsOnly -QuickTimeout -ErrorAction Stop) } catch {}
$rows += [pscustomobject]@{ Target = 'DNS example.com'; Kind = 'internet'; Reached = $dns }
$rows += [pscustomobject]@{ Target = '1.1.1.1:443'; Kind = 'internet'; Reached = Test-Tcp '1.1.1.1' 443 }

$rows | Format-Table -AutoSize
$leaks = @($rows | Where-Object { $_.Kind -eq 'host/LAN' -and $_.Reached })
$internet = @($rows | Where-Object { $_.Kind -eq 'internet' -and $_.Reached }).Count -gt 0
if ($leaks.Count) {
    Write-Host "LEAK: the VM reached the host or LAN. Do not run samples. Shut the VM down." -ForegroundColor Red
}
elseif ($internet) {
    Write-Host 'ONLINE mode: internet only, host and LAN blocked. Do not unpack or run samples now.' -ForegroundColor Yellow
}
else {
    Write-Host 'ISOLATED: nothing reachable. Safe to run samples.' -ForegroundColor Green
}
