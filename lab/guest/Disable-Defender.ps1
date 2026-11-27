#Requires -RunAsAdministrator
<#
  Inside the VM only. Turns Microsoft Defender's protection off so blackshard is the one acting on
  camera, and makes sure no sample is uploaded to Microsoft.
  First turn OFF "Tamper Protection" in Windows Security > Virus & threat protection settings,
  or Windows silently ignores all of this.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ((Get-MpComputerStatus).IsTamperProtected) {
    throw 'Tamper Protection is still on. Turn it off in Windows Security, then run this again.'
}

Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true `
    -DisableScriptScanning $true -DisableBlockAtFirstSeen $true -MAPSReporting 0 -SubmitSamplesConsent 2

# Policies make it survive restarts and checkpoint reverts.
$root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$values = @{
    "$root\Real-Time Protection" = @{ DisableRealtimeMonitoring = 1; DisableBehaviorMonitoring = 1; DisableIOAVProtection = 1; DisableScriptScanning = 1; DisableOnAccessProtection = 1 }
    "$root\Spynet"               = @{ SpynetReporting = 0; SubmitSamplesConsent = 2; DisableBlockAtFirstSeen = 1 }
}
foreach ($key in $values.Keys) {
    New-Item -Path $key -Force | Out-Null
    foreach ($name in $values[$key].Keys) { Set-ItemProperty -Path $key -Name $name -Value $values[$key][$name] -Type DWord }
}
Write-Host '[+] Defender real-time protection and cloud upload are off.' -ForegroundColor Green
