#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ResumeAfterReboot,
    [switch]$Uninstall,
    [switch]$UiMode,
    [switch]$CompleteForUser,
    # Also install the kernel minifilter. It is test-signed, so this path is for disposable VMs
    # only: it turns on Windows test-signing and restarts. Without it, setup installs the
    # driverless tier, which works on any 64-bit Windows 10 or 11 machine with no restart.
    [switch]$WithDriver
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$taskName = "blackshard-development-setup-resume"
$legacyTaskName = "blacksharddevelopmentsetupresume"
$stageRoot = Join-Path $env:ProgramData "blackshard-development-installer"
$logPath = Join-Path $stageRoot "setup.log"
$successPath = Join-Path $stageRoot "installed.txt"
$failurePath = Join-Path $stageRoot "failed.txt"
$installedDirectory = Join-Path $env:ProgramFiles "blackshard"
$installedUi = Join-Path $installedDirectory "blackshard-ui.exe"
$installedOobe = Join-Path $installedDirectory "oobe.png"
$installedLogo = Join-Path $installedDirectory "logo.png"
$installedIcon = Join-Path $installedDirectory "blackshard.ico"
$uninstallRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\blackshard-development"
$runOnceRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$runOnceValueName = "blackshard-development-complete"
$legacyRunOnceValueName = "blacksharddevelopmentlaunch"
$startMenuShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\blackshard.lnk"
$commonDesktopDirectory = [Environment]::GetFolderPath("CommonDesktopDirectory")
if ([string]::IsNullOrWhiteSpace($commonDesktopDirectory)) {
    $commonDesktopDirectory = Join-Path $env:PUBLIC "Desktop"
}
$desktopShortcut = Join-Path $commonDesktopDirectory "blackshard.lnk"
$driverModePath = Join-Path $stageRoot "driver-mode"
$bootstrapLogPath = Join-Path $env:TEMP "blackshard-setup.log"
$immediateInstallTimeoutSeconds = 300
$serviceReadinessTimeoutSeconds = 180

function Test-SystemAccount {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18"
}

function Show-SetupMessage([string]$Message, [string]$Title, [bool]$ErrorMessage = $false) {
    if ($UiMode -or (Test-SystemAccount) -or -not [Environment]::UserInteractive) {
        return
    }
    try {
        Add-Type -AssemblyName PresentationFramework
        $icon = if ($ErrorMessage) {
            [Windows.MessageBoxImage]::Error
        }
        else {
            [Windows.MessageBoxImage]::Information
        }
        [void][Windows.MessageBox]::Show(
            $Message,
            $Title,
            [Windows.MessageBoxButton]::OK,
            $icon
        )
    }
    catch {

    }
}

trap {
    $detail = ($_ | Out-String).Trim()
    $record = "[{0:o}] {1}" -f (Get-Date), $detail
    try { Add-Content -LiteralPath $bootstrapLogPath -Value $record -Encoding UTF8 } catch {}
    try {
        if (Test-Path -LiteralPath $stageRoot -PathType Container) {
            Add-Content -LiteralPath $logPath -Value $record -Encoding UTF8
        }
    }
    catch {}
    if ($ResumeAfterReboot -or (Test-SystemAccount)) {
        try { Set-Content -LiteralPath $failurePath -Value $record -Encoding UTF8 -Force } catch {}
    }
    Show-SetupMessage -Message ("blackshard setup failed.`n`n{0}`n`nDiagnostic log:`n{1}" -f $detail, $bootstrapLogPath) `
        -Title "blackshard setup" -ErrorMessage $true
    Write-Output "blackshard_ui:ERROR:$detail"
    exit 1
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevated {
    $arguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $PSCommandPath)
    )
    if ($ResumeAfterReboot) { $arguments += "-ResumeAfterReboot" }
    if ($Uninstall) { $arguments += "-Uninstall" }
    if ($UiMode) { $arguments += "-UiMode" }
    if ($CompleteForUser) { $arguments += "-CompleteForUser" }
    if ($WithDriver) { $arguments += "-WithDriver" }
    $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList ($arguments -join " ") -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    exit $process.ExitCode
}

function Assert-DisposableVirtualMachine {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $identity = "{0} {1}" -f $computer.Manufacturer, $computer.Model
    $knownVirtualMachine = $identity -match "(?i)(virtual machine|vmware|virtualbox|kvm|qemu|xen|parallels|hyper-v|nutanix|bochs)"
    if (-not $knownVirtualMachine) {
        throw @"
blackshard VM development setup refused to run because this system was not identified as a virtual machine:
$identity

This installer enables Windows test-signing and installs a development kernel driver. Use it only in a disposable, snapshotted VM. It intentionally has no physical-machine override.
"@
    }
}

function Assert-SecureBootDisabled {
    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) {
            throw "Secure Boot is enabled. Turn it off in this disposable VM's firmware settings, then run setup again."
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -match "(?i)(PlatformRequiresUEFI|CmdletizationQuery_NotSupported|NotSupported)") {

            return
        }
        throw
    }
}

function Test-TestSigningActive {
    $output = & bcdedit.exe /enum "{current}" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Windows boot configuration could not be inspected."
    }
    $configured = ($output | Out-String) -match "(?im)^\s*testsigning\s+Yes\s*$"
    $control = Get-ItemProperty `
        -LiteralPath "HKLM:\System\CurrentControlSet\Control" `
        -Name SystemStartOptions `
        -ErrorAction SilentlyContinue
    $startOptions = if ($null -eq $control) { "" } else { [string]$control.SystemStartOptions }
    return $configured -and ($startOptions -match "(?i)(^|\s)TESTSIGNING($|\s)")
}

function Set-StageAcl {
    New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
    # The folder may already exist, created by a standard user who still owns it (and could grant
    # themselves access again) or holding files with their own explicit entries. Take ownership and
    # reset everything below it, as install.ps1 does, before applying the protected ACL.
    & icacls.exe $stageRoot "/setowner" "*S-1-5-32-544" "/T" "/C" "/Q" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Could not take ownership of $stageRoot."
    }
    & icacls.exe $stageRoot "/reset" "/T" "/C" "/Q" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Could not reset the access entries under $stageRoot."
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $users = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-545")
    $readRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $users,
        [Security.AccessControl.FileSystemRights]"ReadAndExecute, Synchronize",
        $inheritance,
        $propagation,
        $allow
    )
    [void]$acl.AddAccessRule($readRule)
    Set-Acl -LiteralPath $stageRoot -AclObject $acl
}

function Copy-InstallerPayload {
    Set-StageAcl
    $required = @(
        "blackshard-service.exe",
        "blackshard-ui.exe",
        "blackshard.sys",
        "blackshard-amsi-x64.dll",
        "blackshard-amsi-x86.dll",
        "install.ps1",
        "uninstall.ps1",
        "verify.ps1",
        "enable-test-signing.ps1",
        "disable-test-signing.ps1",
        "vm-setup.ps1",
        "version.txt",
        "blackshard-setup-ui.exe",
        "oobe.png",
        "logo.png",
        "blackshard.ico"
    )
    foreach ($name in $required) {
        $source = Join-Path $PSScriptRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "The installer payload is incomplete: $name is missing."
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $stageRoot $name) -Force
    }
    Remove-Item -LiteralPath $successPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $failurePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
    if ($WithDriver) {
        Set-Content -LiteralPath $driverModePath -Value "test-signed minifilter" -Encoding UTF8 -Force
    }
    else {
        Remove-Item -LiteralPath $driverModePath -Force -ErrorAction SilentlyContinue
    }
}

function Register-ResumeTask([switch]$RegisterInteractiveCompletion) {
    Unregister-ScheduledTask -TaskName $legacyTaskName -Confirm:$false -ErrorAction SilentlyContinue
    $powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $resumeScript = Join-Path $stageRoot "vm-setup.ps1"
    $action = New-ScheduledTaskAction -Execute $powerShell `
        -Argument ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -ResumeAfterReboot' -f $resumeScript)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    if ($RegisterInteractiveCompletion) {
        Register-CompletionRunOnce
    }
}

function Remove-ResumeTask {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $legacyTaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Register-CompletionRunOnce {
    New-Item -Path $runOnceRegistryPath -Force | Out-Null
    $monitor = Join-Path $stageRoot "blackshard-setup-ui.exe"
    $completionCommand = '"{0}" --resume-monitor' -f $monitor
    New-ItemProperty -Path $runOnceRegistryPath -Name $runOnceValueName `
        -Value $completionCommand -PropertyType String -Force | Out-Null
}

function Remove-CompletionRunOnce {
    Remove-ItemProperty -Path $runOnceRegistryPath -Name $runOnceValueName -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runOnceRegistryPath -Name $legacyRunOnceValueName -ErrorAction SilentlyContinue
}

function New-blackshardShortcut([string]$Path) {
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $installedUi
    $shortcut.WorkingDirectory = $installedDirectory
    $shortcut.Description = "blackshard antivirus"
    $shortcut.IconLocation = "$installedIcon,0"
    $shortcut.Save()
}

function Install-ShortcutsAndRegistration {
    foreach ($assetName in @("oobe.png", "logo.png", "blackshard.ico")) {
        $source = Join-Path $stageRoot $assetName
        $destination = Join-Path $installedDirectory $assetName
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
    New-blackshardShortcut -Path $startMenuShortcut
    New-blackshardShortcut -Path $desktopShortcut

    New-Item -Path $uninstallRegistryPath -Force | Out-Null
    $uninstallCommand = '"{0}" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "{1}" -Uninstall' -f `
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe", (Join-Path $stageRoot "vm-setup.ps1")
    $driverMode = Test-Path -LiteralPath $driverModePath -PathType Leaf
    $displayName = if ($driverMode) { "blackshard development (VM only)" } else { "blackshard (preview)" }
    $version = (Get-Content -LiteralPath (Join-Path $stageRoot "version.txt") -Raw).Trim()
    New-ItemProperty -Path $uninstallRegistryPath -Name DisplayName -Value $displayName -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name DisplayVersion -Value $version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name Publisher -Value "blackshard open source project" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name DisplayIcon -Value $installedIcon -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name UninstallString -Value $uninstallCommand -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
}

function Install-AllComponents {
    # Clears the file-based development policy older builds used; install.ps1 now records it in
    # the service's registry key instead.
    Remove-Item -LiteralPath (Join-Path $stageRoot "development-ipc-policy") -Force -ErrorAction SilentlyContinue
    Write-Output "blackshard_ui:PROGRESS:15:Preparing the protected installation."
    $installer = Join-Path $stageRoot "install.ps1"
    $verifier = Join-Path $stageRoot "verify.ps1"
    if (Test-Path -LiteralPath $driverModePath -PathType Leaf) {
        Write-Output "blackshard_ui:STATUS:Trusting the VM development certificate and signing the minifilter."
        Write-Output "blackshard_ui:PROGRESS:25:Trusting the VM certificate and signing the minifilter."
        & (Join-Path $stageRoot "enable-test-signing.ps1") -SkipBootConfiguration
        Write-Output "blackshard_ui:STATUS:Installing the kernel minifilter and LocalSystem protection service."
        Write-Output "blackshard_ui:PROGRESS:45:Installing the protection service, UI, and minifilter."
        & $installer
        Write-Output "blackshard_ui:PROGRESS:70:Validating real-time protection and malware intelligence."
        & $verifier -DevelopmentVm -NoExit -WaitSeconds $serviceReadinessTimeoutSeconds
    }
    else {
        Write-Output "blackshard_ui:STATUS:Installing the protection service, script scanning, and UI."
        Write-Output "blackshard_ui:PROGRESS:40:Installing the protection service, script scanning, and UI."
        & $installer -SkipDriver
        Write-Output "blackshard_ui:PROGRESS:70:Checking that the protection service is running."
        & $verifier -DevelopmentVm -Userland -NoExit -WaitSeconds 60
    }
    Write-Output "blackshard_ui:PROGRESS:90:Creating shortcuts and registering blackshard."
    Install-ShortcutsAndRegistration
    foreach ($completionArtifact in @(
        $installedUi,
        $installedOobe,
        $installedIcon,
        $startMenuShortcut,
        $desktopShortcut
    )) {
        if (-not (Test-Path -LiteralPath $completionArtifact -PathType Leaf)) {
            throw "Installation completion artifact is missing: $completionArtifact"
        }
    }

    Set-Content -LiteralPath $successPath `
        -Value ("Installed and verified at {0:o}" -f (Get-Date)) -Encoding UTF8
    Remove-Item -LiteralPath $failurePath -Force -ErrorAction SilentlyContinue
    Remove-ResumeTask
    Write-Output "blackshard_ui:PROGRESS:100:Installation completed successfully."
    Write-Output "blackshard_ui:INSTALL_COMPLETE"

    Write-Host "[+] blackshard is installed and verified." -ForegroundColor Green
    if (Test-Path -LiteralPath $driverModePath -PathType Leaf) {
        Write-Host "[+] blackshard completion will appear when an interactive user signs in." -ForegroundColor Green
    }
}

function Start-ImmediateSystemInstall {
    Write-Output "blackshard_ui:STATUS:Repairing the partial installation with LocalSystem authority."
    Register-ResumeTask
    Start-ScheduledTask -TaskName $taskName
    $marker = $successPath
    for ($attempt = 0; $attempt -lt $immediateInstallTimeoutSeconds; $attempt++) {
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            Write-Output "blackshard_ui:INSTALL_COMPLETE"
            return
        }
        if (Test-Path -LiteralPath $failurePath -PathType Leaf) {
            $failure = (Get-Content -LiteralPath $failurePath -Raw -ErrorAction SilentlyContinue).Trim()
            if ([string]::IsNullOrWhiteSpace($failure)) {
                $failure = "The LocalSystem installation worker failed without diagnostic text."
            }
            throw "The LocalSystem installation failed:`n$failure`n`nFull worker log: $logPath"
        }
        Start-Sleep -Seconds 1
    }
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
    $taskState = if ($null -eq $task) { "missing" } else { [string]$task.State }
    $lastResult = if ($null -eq $taskInfo) { "unknown" } else { "0x{0:X8}" -f [uint32]$taskInfo.LastTaskResult }
    $tail = if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        (Get-Content -LiteralPath $logPath -Tail 40 -ErrorAction SilentlyContinue) -join "`n"
    } else {
        "The LocalSystem worker did not create its log."
    }
    throw "The SYSTEM installation did not finish within $immediateInstallTimeoutSeconds seconds (task state: $taskState; last result: $lastResult).`n`n$tail`n`nFull worker log: $logPath"
}

function Show-UserCompletion {
    Remove-CompletionRunOnce
    if (-not [Environment]::UserInteractive) {
        return
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($immediateInstallTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $successPath -PathType Leaf) {
            break
        }
        if (Test-Path -LiteralPath $failurePath -PathType Leaf) {
            $failure = (Get-Content -LiteralPath $failurePath -Raw -ErrorAction SilentlyContinue).Trim()
            if ([string]::IsNullOrWhiteSpace($failure)) {
                $failure = "The installation worker failed without diagnostic text."
            }
            Show-SetupMessage -Message ("blackshard installation failed.`n`n{0}`n`nFull log:`n{1}" -f $failure, $logPath) `
                -Title "blackshard setup" -ErrorMessage $true
            return
        }
        Start-Sleep -Seconds 1
    }

    if (-not (Test-Path -LiteralPath $successPath -PathType Leaf)) {
        Show-SetupMessage -Message ("blackshard setup did not finish within {0} seconds.`n`nFull log:`n{1}" -f `
            $immediateInstallTimeoutSeconds, $logPath) -Title "blackshard setup" -ErrorMessage $true
        return
    }
    if (-not (Test-Path -LiteralPath $installedOobe -PathType Leaf)) {
        Show-SetupMessage -Message "blackshard was installed, but the OOBE image is missing." `
            -Title "blackshard setup" -ErrorMessage $true
        return
    }

    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName PresentationFramework
    $bitmap = [Windows.Media.Imaging.BitmapImage]::new()
    $bitmap.BeginInit()
    $bitmap.CacheOption = [Windows.Media.Imaging.BitmapCacheOption]::OnLoad
    $bitmap.UriSource = [Uri]::new($installedOobe)
    $bitmap.EndInit()
    $bitmap.Freeze()

    $image = [Windows.Controls.Image]::new()
    $image.Source = $bitmap
    $image.Stretch = [Windows.Media.Stretch]::Uniform

    $workArea = [Windows.SystemParameters]::WorkArea
    $window = [Windows.Window]::new()
    $window.Title = "blackshard installation complete"
    $window.Content = $image
    $window.Background = [Windows.Media.Brushes]::Black
    $window.Width = [Math]::Min(1280, [Math]::Floor($workArea.Width * 0.86))
    $window.Height = [Math]::Min(720, [Math]::Floor($workArea.Height * 0.86))
    $window.MinWidth = 640
    $window.MinHeight = 360
    $window.WindowStartupLocation = [Windows.WindowStartupLocation]::CenterScreen
    $window.Topmost = $true
    [void]$window.ShowDialog()

    if (Test-Path -LiteralPath $installedUi -PathType Leaf) {
        Start-Process -FilePath "explorer.exe" -ArgumentList ('"{0}"' -f $installedUi)
    }
}

function Remove-AllComponents {
    Remove-ResumeTask
    $uninstaller = Join-Path $stageRoot "uninstall.ps1"
    if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
        & $uninstaller
    }
    Remove-Item -LiteralPath $startMenuShortcut -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $desktopShortcut -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $uninstallRegistryPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-CompletionRunOnce
    $disableTestSigning = Join-Path $stageRoot "disable-test-signing.ps1"
    if ((Test-Path -LiteralPath $driverModePath -PathType Leaf) -and
        (Test-Path -LiteralPath $disableTestSigning -PathType Leaf)) {
        & $disableTestSigning
        Write-Host "[+] blackshard was removed. Restart the VM to leave test-signing mode." -ForegroundColor Green
        return
    }
    Write-Host "[+] blackshard was removed." -ForegroundColor Green
}

if ($CompleteForUser) {
    Show-UserCompletion
    exit 0
}

if (-not (Test-Administrator)) {
    Invoke-SelfElevated
}

if ($Uninstall) {
    Remove-AllComponents
    exit 0
}

if ($ResumeAfterReboot) {
    New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
    Remove-Item -LiteralPath $failurePath -Force -ErrorAction SilentlyContinue
    try { Start-Transcript -LiteralPath $logPath -Append | Out-Null } catch {}
    try {
        Install-AllComponents
    }
    finally {
        try { Stop-Transcript | Out-Null } catch {}
    }
    exit 0
}

if (-not $WithDriver) {
    Write-Output "blackshard_ui:STATUS:Staging the protected installer payload."
    Write-Output "blackshard_ui:PROGRESS:10:Staging the protected installer payload."
    Copy-InstallerPayload
    try { Start-Transcript -LiteralPath $logPath -Append | Out-Null } catch {}
    try {
        Install-AllComponents
    }
    finally {
        try { Stop-Transcript | Out-Null } catch {}
    }
    exit 0
}

Write-Output "blackshard_ui:PROGRESS:2:Validating the virtual-machine safety boundary."
Write-Output "blackshard_ui:STATUS:Validating the virtual-machine safety boundary."
Assert-DisposableVirtualMachine
Assert-SecureBootDisabled
$testSigningActive = Test-TestSigningActive
Write-Output "blackshard_ui:STATUS:Staging the protected installer payload."
Write-Output "blackshard_ui:PROGRESS:10:Staging the protected installer payload."
Copy-InstallerPayload
try { Start-Transcript -LiteralPath $bootstrapLogPath -Append | Out-Null } catch {}
try {
    if ($testSigningActive) {
        Write-Host "[*] Test-signing is already active; starting the SYSTEM installation without another reboot..." -ForegroundColor Cyan
        Start-ImmediateSystemInstall
        exit 0
    }
    Write-Host "[*] Enabling Windows test-signing mode for the disposable VM..." -ForegroundColor Yellow
    Write-Output "blackshard_ui:STATUS:Enabling Windows test-signing for the disposable VM."
    Write-Output "blackshard_ui:PROGRESS:20:Enabling Windows test-signing for the disposable VM."
    & bcdedit.exe /set testsigning on | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Windows could not enable test-signing. Disable Secure Boot in this disposable VM and retry."
    }
    Register-ResumeTask -RegisterInteractiveCompletion
    Write-Output "blackshard_ui:PROGRESS:25:Restarting Windows to activate the development driver."
    Write-Output "blackshard_ui:REBOOT_PENDING"
    Write-Host "[+] Setup will automatically resume during the next VM boot." -ForegroundColor Green
    if ($UiMode) {
        Write-Host "[*] Waiting for the interactive installer to request the restart." -ForegroundColor Yellow
        exit 0
    }
    Show-SetupMessage -Message @"
The test certificate and boot configuration are ready.

The disposable VM will restart in 15 seconds. blackshard setup will resume automatically during boot and install the UI, protection service, and minifilter.

Run shutdown /a now if you need to postpone the restart.
"@ -Title "blackshard setup"
    Write-Host "[*] Restarting the disposable VM in 15 seconds. Run 'shutdown /a' now to postpone." -ForegroundColor Yellow
    & shutdown.exe /r /t 15 /d p:2:4 /c "blackshard development setup must restart to activate test-signing."
    if ($LASTEXITCODE -ne 0) {
        throw "Windows refused the setup restart request. Restart the VM manually; setup will resume automatically."
    }
}
finally {
    try { Stop-Transcript | Out-Null } catch {}
}
