#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Hands-off version of Setup-Lab.ps1: start it once in an admin PowerShell and walk away.

  1. Waits until the Windows ISO has finished downloading (no .part/.crdownload left, size stable).
  2. Runs Setup-Lab.ps1.
  3. If Hyper-V had to be enabled: registers a one-time task that runs this script again, elevated,
     when you next sign in, and (with -RestartAutomatically) restarts Windows after a 5-minute
     warning. `shutdown /a` cancels that restart.
  Log: lab\state\setup-*.log

.EXAMPLE
  .\Start-LabSetup.ps1 -WindowsIso $HOME\Downloads\Win10_22H2_English_x64.iso -RestartAutomatically
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WindowsIso,
    [switch]$Build,
    [string]$DistPath,
    [switch]$RestartAutomatically,
    [string]$Edition = 'Windows 10 Pro'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskName = 'blackshard-lab-resume'
$stateDir = Join-Path $PSScriptRoot 'state'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
Start-Transcript -Path (Join-Path $stateDir "setup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log") | Out-Null

try {
    # This run may be the resume after a restart: the one-time task has done its job.
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    # --- 1. Wait for the download ---
    $WindowsIso = [IO.Path]::GetFullPath($WindowsIso)
    $folder = Split-Path $WindowsIso -Parent
    $stem = [IO.Path]::GetFileNameWithoutExtension($WindowsIso)
    $lastSize = -1; $stableSince = $null
    while ($true) {
        $partial = @(Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "$stem*" -and $_.Name -match '\.(part|crdownload|partial|download|tmp)$' })
        $size = if (Test-Path -LiteralPath $WindowsIso) { (Get-Item -LiteralPath $WindowsIso).Length } else { 0 }
        if ($partial.Count -eq 0 -and $size -gt 3GB) {
            if ($size -ne $lastSize) { $lastSize = $size; $stableSince = Get-Date }
            elseif (((Get-Date) - $stableSince).TotalSeconds -ge 30) {
                try { [IO.File]::Open($WindowsIso, 'Open', 'Read', 'None').Dispose(); break } catch { }
            }
        }
        else {
            $done = ($partial | Measure-Object Length -Sum).Sum
            Write-Host ("[{0:HH:mm:ss}] waiting for the ISO download... {1:N1} GB so far" -f (Get-Date), ($done / 1GB))
        }
        Start-Sleep -Seconds 20
    }
    Write-Host "[+] ISO ready: $WindowsIso ($([math]::Round($lastSize / 1GB, 2)) GB)" -ForegroundColor Green

    # --- 2. Set up ---
    $params = @{ WindowsIso = $WindowsIso; Edition = $Edition }
    if ($Build) { $params.Build = $true }
    if ($DistPath) { $params.DistPath = $DistPath }
    & (Join-Path $PSScriptRoot 'Setup-Lab.ps1') @params

    # --- 3. Hyper-V just got enabled: resume after the restart ---
    $state = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State
    if ($state -ne 'Enabled' -or -not (Get-Module -ListAvailable -Name Hyper-V)) {
        $arguments = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-WindowsIso', "`"$WindowsIso`"", '-Edition', "`"$Edition`"")
        if ($Build) { $arguments += '-Build' }
        if ($DistPath) { $arguments += @('-DistPath', "`"$DistPath`"") }
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Register-ScheduledTask -TaskName $taskName -Force `
            -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($arguments -join ' ') -WorkingDirectory $PSScriptRoot) `
            -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $user) `
            -Principal (New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest) `
            -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 6)) | Out-Null
        Write-Host "[+] Setup continues by itself the next time $user signs in (task '$taskName')." -ForegroundColor Green
        if ($RestartAutomatically) {
            shutdown.exe /r /t 300 /c "Restarting in 5 minutes to finish enabling Hyper-V for the blackshard lab. Run 'shutdown /a' to cancel."
            Write-Host '[!] Windows restarts in 5 minutes. Save your work, or run: shutdown /a' -ForegroundColor Yellow
        }
        else {
            Write-Host '[!] Restart Windows when convenient.' -ForegroundColor Yellow
        }
    }
}
finally {
    Stop-Transcript | Out-Null
}
