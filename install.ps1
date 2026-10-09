#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$AllowUnsigned,
    # Install without the kernel minifilter. Real-time coverage then comes from AMSI, which needs
    # no kernel code and therefore no EV certificate or test-signing.
    [switch]$SkipDriver,
    # Where the service downloads ClamAV definitions from, for a private mirror. Also settable
    # through the BLACKSHARD_CLAMAV_MIRROR environment variable of the installing process.
    [string]$DefinitionMirror = $env:BLACKSHARD_CLAMAV_MIRROR
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverName = "blackshard"
$protectionServiceName = "blackshard-protection-service"
$legacyProtectionServiceName = "blackshardprotectionservice"
$sourceDriver = Join-Path $PSScriptRoot "blackshard.sys"
$sourceService = Join-Path $PSScriptRoot "blackshard-service.exe"
$sourceUi = Join-Path $PSScriptRoot "blackshard-ui.exe"
$sourceAmsiX64 = Join-Path $PSScriptRoot "blackshard-amsi-x64.dll"
$sourceAmsiX86 = Join-Path $PSScriptRoot "blackshard-amsi-x86.dll"
$destinationDriver = Join-Path $env:SystemRoot "System32\drivers\blackshard.sys"
$agentDirectory = Join-Path $env:ProgramFiles "blackshard"
$destinationService = Join-Path $agentDirectory "blackshard-service.exe"
$destinationUi = Join-Path $agentDirectory "blackshard-ui.exe"
$destinationAmsiX64 = Join-Path $agentDirectory "blackshard-amsi-x64.dll"
$destinationAmsiX86 = Join-Path $agentDirectory "blackshard-amsi-x86.dll"
$dataDirectory = Join-Path $env:ProgramData "blackshard"
$amsiClsid = "{73A5A75D-BF05-4A2C-8C51-64C1EC8B5C92}"
$serviceRegistryPath = "HKLM:\System\CurrentControlSet\Services\$driverName"

function Test-blackshardFilterLoaded {
    $filterOutput = & fltmc.exe filters 2>$null
    return ($filterOutput -match "(?im)^blackshard\s")
}

function Stop-blackshardServiceForReplacement([string]$Name) {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }

    & sc.exe stop $Name 2>$null | Out-Host
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    while ([DateTime]::UtcNow -lt $deadline) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
        if ($null -eq $service -or [string]$service.State -eq "Stopped" -or [uint32]$service.ProcessId -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if ($null -ne $service -and [uint32]$service.ProcessId -ne 0) {
        $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$([uint32]$service.ProcessId)" -ErrorAction SilentlyContinue
        $expectedPath = [IO.Path]::GetFullPath($destinationService)
        $actualPath = if ($null -eq $process -or [string]::IsNullOrWhiteSpace([string]$process.ExecutablePath)) {
            ""
        }
        else {
            [IO.Path]::GetFullPath([string]$process.ExecutablePath)
        }
        if (-not $actualPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "The $Name service did not stop and its process identity could not be validated."
        }
        Stop-Process -Id ([uint32]$service.ProcessId) -Force -ErrorAction Stop
        Wait-Process -Id ([uint32]$service.ProcessId) -Timeout 15 -ErrorAction SilentlyContinue
    }

    & sc.exe delete $Name 2>$null | Out-Host
    $deleteDeadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deleteDeadline) {
        if ($null -eq (Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue)) {
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw "The $Name service registration could not be removed before replacement."
}

# Every PowerShell, Office and script host loads the AMSI provider at startup, including the
# PowerShell running this script, and Windows will not delete or overwrite a loaded DLL. It
# will rename one, so a file in use is moved aside and deleted at the next restart.
if (-not ("blackshard.NativeFile" -as [type])) {
Add-Type -Namespace blackshard -Name NativeFile -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool MoveFileEx(string existing, string replacement, int flags);
"@
}

function Remove-FileNowOrAtRestart([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }
    try {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        return
    }
    catch [UnauthorizedAccessException], [IO.IOException] {
    }
    $aside = "$Path.$([Guid]::NewGuid().ToString('N')).old"
    [IO.File]::Move($Path, $aside)
    $delayUntilReboot = 4
    if (-not [blackshard.NativeFile]::MoveFileEx($aside, $null, $delayUntilReboot)) {
        Write-Warning "$aside is in use and could not be scheduled for deletion; remove it after a restart."
        return
    }
    Write-Host "[*] $([IO.Path]::GetFileName($Path)) is in use; it will be deleted at the next restart." -ForegroundColor Yellow
}

function Get-DriverLoadDiagnostics {
    $lines = New-Object Collections.Generic.List[string]
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $destinationDriver
        $lines.Add("Installed driver signature: $($signature.Status) - $($signature.StatusMessage)")
    }
    catch {
        $lines.Add("Installed driver signature could not be inspected: $($_.Exception.Message)")
    }

    try {
        $since = (Get-Date).AddMinutes(-5)
        $events = Get-WinEvent -FilterHashtable @{ LogName = "System"; StartTime = $since } -ErrorAction Stop |
            Where-Object {
                $_.ProviderName -match "(?i)(FilterManager|Service Control Manager|CodeIntegrity)" -and
                $_.Message -match "(?i)(blackshard|driver|filter)"
            } |
            Select-Object -First 8
        foreach ($event in $events) {
            $message = ([string]$event.Message -replace "\s+", " ").Trim()
            $lines.Add("System event $($event.Id) [$($event.ProviderName)]: $message")
        }
    }
    catch {
        $lines.Add("Recent driver events could not be read: $($_.Exception.Message)")
    }

    if ($lines.Count -eq 0) {
        return "No relevant Windows driver events were found in the last five minutes."
    }
    return $lines -join "`n"
}

function Remove-blackshardInstallation {
    Write-Host "[*] Stopping blackshard protection service..." -ForegroundColor Cyan
    foreach ($serviceName in @($protectionServiceName, $legacyProtectionServiceName)) {
        Stop-blackshardServiceForReplacement -Name $serviceName
    }

    foreach ($registryView in @("32", "64")) {
        & reg.exe delete "HKLM\Software\Microsoft\AMSI\Providers\$amsiClsid" /f "/reg:$registryView" 2>$null | Out-Null
        & reg.exe delete "HKLM\Software\Classes\CLSID\$amsiClsid" /f "/reg:$registryView" 2>$null | Out-Null
    }

    if (Test-blackshardFilterLoaded) {
        Write-Host "[*] Unloading blackshard minifilter..." -ForegroundColor Cyan
        & fltmc.exe unload $driverName | Out-Host
    }

    & sc.exe stop $driverName 2>$null | Out-Host
    & sc.exe delete $driverName 2>$null | Out-Host
    Start-Sleep -Seconds 1

    Remove-FileNowOrAtRestart $destinationDriver
    # Only blackshard writes here (the directory is administrator-only), so everything in it goes.
    if (Test-Path -LiteralPath $agentDirectory -PathType Container) {
        foreach ($installedFile in @(Get-ChildItem -LiteralPath $agentDirectory -File -Force)) {
            Remove-FileNowOrAtRestart $installedFile.FullName
        }
        if (@(Get-ChildItem -LiteralPath $agentDirectory -Force).Count -eq 0) {
            Remove-Item -LiteralPath $agentDirectory -Force
        }
        else {
            # Only files moved aside remain. Windows deletes them at restart, then the directory.
            [void][blackshard.NativeFile]::MoveFileEx($agentDirectory, $null, 4)
        }
    }

    Write-Host "[+] blackshard was removed." -ForegroundColor Green
}

if ($Uninstall) {
    Remove-blackshardInstallation
    exit 0
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "This build supports only 64-bit Windows."
}

$installDriver = -not $SkipDriver
if ($installDriver -and -not (Test-Path -LiteralPath $sourceDriver -PathType Leaf)) {
    Write-Warning "blackshard.sys was not found beside install.ps1; installing without the kernel minifilter."
    $installDriver = $false
}
foreach ($sourceArtifact in @(
    @{ Path = $sourceService; Name = "blackshard-service.exe" },
    @{ Path = $sourceUi; Name = "blackshard-ui.exe" },
    @{ Path = $sourceAmsiX64; Name = "blackshard-amsi-x64.dll" },
    @{ Path = $sourceAmsiX86; Name = "blackshard-amsi-x86.dll" }
)) {
    if (-not (Test-Path -LiteralPath $sourceArtifact.Path -PathType Leaf)) {
        throw "$($sourceArtifact.Name) was not found beside install.ps1. Run deploy.ps1 before copying dist to the VM."
    }
}

if ($installDriver) {
    $signature = Get-AuthenticodeSignature -LiteralPath $sourceDriver
    if ($signature.Status -ne "Valid" -and -not $AllowUnsigned) {
        # Windows would refuse to load it anyway, so fall back rather than abort. The agent is
        # still useful without the driver; it just cannot mediate file system operations.
        Write-Warning @"
blackshard.sys does not have a trusted signature (status: $($signature.Status)), so the kernel
minifilter will not be installed. blackshard will run with AMSI coverage for scripts and macros,
plus on-demand scanning and quarantine.
To use the minifilter, either install a properly signed driver, or on an isolated test VM run
enable-test-signing.ps1, reboot, and re-run install.ps1 with -AllowUnsigned.
"@
        $installDriver = $false
    }
    elseif ($signature.Status -ne "Valid") {
        Write-Warning "Installing an untrusted driver in test mode. Never do this on a production system."
    }
}

# The service only answers its own UI when both are Authenticode-signed, unless the installer
# records otherwise in the service's registry key (writable by administrators alone).
$unsignedComponents = $false
foreach ($sourceExecutable in @($sourceService, $sourceUi)) {
    $executableSignature = Get-AuthenticodeSignature -LiteralPath $sourceExecutable
    if ($executableSignature.Status -ne "Valid") {
        $unsignedComponents = $true
        Write-Warning "$([IO.Path]::GetFileName($sourceExecutable)) is not Authenticode-signed; this is a preview build."
    }
}

foreach ($serviceName in @($protectionServiceName, $legacyProtectionServiceName)) {
    Stop-blackshardServiceForReplacement -Name $serviceName
}
New-Item -ItemType Directory -Path $agentDirectory -Force | Out-Null
foreach ($component in @(
    @{ Source = $sourceService; Destination = $destinationService },
    @{ Source = $sourceUi; Destination = $destinationUi },
    @{ Source = $sourceAmsiX64; Destination = $destinationAmsiX64 },
    @{ Source = $sourceAmsiX86; Destination = $destinationAmsiX86 }
)) {
    # An upgrade finds the old AMSI provider loaded in running processes, and the UI may be open.
    Remove-FileNowOrAtRestart $component.Destination
    Copy-Item -LiteralPath $component.Source -Destination $component.Destination -Force
}

& icacls.exe $agentDirectory "/inheritance:e" `
    "/grant:r" "*S-1-5-18:(OI)(CI)(F)" `
    "/grant:r" "*S-1-5-32-544:(OI)(CI)(F)" `
    "/grant:r" "*S-1-5-32-545:(OI)(CI)(RX)" `
    "/grant:r" "*S-1-15-2-1:(OI)(CI)(RX)" `
    "/grant:r" "*S-1-15-2-2:(OI)(CI)(RX)" | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Could not apply the protected Program Files ACL."
}

# ProgramData is writable by standard users, so the directory may already exist with an owner and
# access entries someone else chose. Take ownership, strip every explicit entry below it, then set
# the protected ACL that everything inside inherits.
New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
& icacls.exe $dataDirectory "/setowner" "*S-1-5-32-544" "/T" "/C" "/Q" | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Could not take ownership of $dataDirectory."
}
& icacls.exe $dataDirectory "/reset" "/T" "/C" "/Q" | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Could not reset the access entries under $dataDirectory."
}
& icacls.exe $dataDirectory "/inheritance:r" `
    "/grant:r" "*S-1-5-18:(OI)(CI)(F)" `
    "/grant:r" "*S-1-5-32-544:(OI)(CI)(F)" `
    "/grant:r" "*S-1-5-32-545:(OI)(CI)(RX)" | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Could not apply the protected ProgramData ACL."
}
foreach ($privateDirectoryName in @("ClamAV", "Keys", "Quarantine", "State", "Updates")) {
    $privateDirectory = Join-Path $dataDirectory $privateDirectoryName
    New-Item -ItemType Directory -Path $privateDirectory -Force | Out-Null
    & icacls.exe $privateDirectory "/inheritance:r" `
        "/grant:r" "*S-1-5-18:(OI)(CI)(F)" `
        "/grant:r" "*S-1-5-32-544:(OI)(CI)(F)" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Could not protect $privateDirectory."
    }
}

foreach ($provider in @(
    @{ View = "64"; Path = $destinationAmsiX64 },
    @{ View = "32"; Path = $destinationAmsiX86 }
)) {
    & reg.exe add "HKLM\Software\Classes\CLSID\$amsiClsid\InprocServer32" /ve /t REG_SZ /d $provider.Path /f "/reg:$($provider.View)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not register the $($provider.View)-bit AMSI COM server." }
    & reg.exe add "HKLM\Software\Classes\CLSID\$amsiClsid\InprocServer32" /v ThreadingModel /t REG_SZ /d Both /f "/reg:$($provider.View)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not configure the $($provider.View)-bit AMSI COM server." }
    & reg.exe add "HKLM\Software\Microsoft\AMSI\Providers\$amsiClsid" /ve /t REG_SZ /d "blackshard AMSI provider" /f "/reg:$($provider.View)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not register the $($provider.View)-bit AMSI provider." }
}

if ($installDriver) {
    if (Test-blackshardFilterLoaded) {
        & fltmc.exe unload $driverName | Out-Host
    }
    & sc.exe stop $driverName 2>$null | Out-Host
    & sc.exe delete $driverName 2>$null | Out-Host

    $waitLimit = 20
    for ($i = 0; $i -lt $waitLimit; $i++) {
        $query = & sc.exe query $driverName 2>&1
        if ($LASTEXITCODE -ne 0) {
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (Test-Path -LiteralPath $serviceRegistryPath) {
        Remove-Item -LiteralPath $serviceRegistryPath -Recurse -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }

    Copy-Item -LiteralPath $sourceDriver -Destination $destinationDriver -Force

    $createCmd = 'sc.exe create "{0}" type= filesys start= system error= normal binPath= "{1}" group= "FSFilter Anti-Virus" depend= FltMgr' -f $driverName, $destinationDriver
    $createOutput = & cmd.exe /c $createCmd 2>&1
    $createExitCode = $LASTEXITCODE
    $createOutput | Out-Host
    if ($createExitCode -ne 0) {
        throw "Could not create the blackshard driver service (sc.exe exit code $createExitCode)."
    }

    if (-not (Test-Path -LiteralPath $serviceRegistryPath)) {
        New-Item -Path $serviceRegistryPath -Force | Out-Null
    }

    $instanceLayouts = @(
        (Join-Path $serviceRegistryPath "Instances"),
        (Join-Path $serviceRegistryPath "Parameters\Instances")
    )
    foreach ($instancesPath in $instanceLayouts) {
        $instancePath = Join-Path $instancesPath "blackshard Instance"
        New-Item -Path $instancesPath -Force | Out-Null
        New-ItemProperty -Path $instancesPath -Name "DefaultInstance" -Value "blackshard Instance" -PropertyType String -Force | Out-Null
        New-Item -Path $instancePath -Force | Out-Null

        New-ItemProperty -Path $instancePath -Name "Altitude" -Value "320000.4242" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $instancePath -Name "Flags" -Value 0 -PropertyType DWord -Force | Out-Null
    }

    $parametersPath = Join-Path $serviceRegistryPath "Parameters"
    New-Item -Path $parametersPath -Force | Out-Null
    New-ItemProperty -Path $parametersPath -Name "DebugFlags" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $parametersPath -Name "SupportedFeatures" -Value 3 -PropertyType DWord -Force | Out-Null

    Write-Host "[*] Loading blackshard minifilter..." -ForegroundColor Cyan

    $registryDump = & reg.exe query "HKLM\System\CurrentControlSet\Services\$driverName" /s 2>&1
    $registryDump | Out-Host

    $loadOutput = & fltmc.exe load $driverName 2>&1
    $loadExitCode = $LASTEXITCODE
    $loadOutput | Out-Host
    if ($loadExitCode -ne 0) {
        $loadMessage = ($loadOutput | Out-String).Trim()
        $diagnostics = Get-DriverLoadDiagnostics
        $regDump = ($registryDump | Out-String).Trim()
        throw @"
The service was installed, but Windows refused to load the minifilter (fltmc exit code $loadExitCode).
fltmc output: $loadMessage
$diagnostics
Service registry state:
$regDump
"@
    }

    if (-not (Test-blackshardFilterLoaded)) {
        throw "fltmc reported success, but blackshard is absent from the loaded filter list."
    }
}
else {
    Write-Host "[*] Skipping the kernel minifilter; blackshard will run with AMSI coverage." -ForegroundColor Yellow
}
Write-Host "[*] Installing blackshard protection service..." -ForegroundColor Cyan
$null = New-Service `
    -Name $protectionServiceName `
    -BinaryPathName $destinationService `
    -StartupType Automatic `
    -Description "blackshard real-time protection and quarantine service"

$serviceCommand = "`"$destinationService`" --service"
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$protectionServiceName"
Set-ItemProperty -Path $serviceKey -Name ImagePath -Value $serviceCommand -Type ExpandString
$serviceParameters = Join-Path $serviceKey "Parameters"
New-Item -Path $serviceParameters -Force | Out-Null
if ($unsignedComponents) {
    New-ItemProperty -Path $serviceParameters -Name AllowUnsignedComponents -Value 1 -PropertyType DWord -Force | Out-Null
}
else {
    Remove-ItemProperty -Path $serviceParameters -Name AllowUnsignedComponents -ErrorAction SilentlyContinue
}

if ([string]::IsNullOrWhiteSpace($DefinitionMirror)) {
    Remove-ItemProperty -Path $serviceKey -Name Environment -ErrorAction SilentlyContinue
}
else {
    New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString `
        -Value @("BLACKSHARD_CLAMAV_MIRROR=$DefinitionMirror") -Force | Out-Null
}

& sc.exe failure $protectionServiceName "reset= 86400" "actions= restart/30000/restart/30000/none/0" | Out-Host
Start-Service -Name $protectionServiceName

$serviceRunning = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    $query = & sc.exe query $protectionServiceName 2>&1
    if ($LASTEXITCODE -eq 0 -and (($query | Out-String) -match '(?im)STATE\s*:\s*4\s+RUNNING')) {
        $serviceRunning = $true
        break
    }
    Start-Sleep -Milliseconds 250
}
if (-not $serviceRunning) {
    throw "The blackshard protection service did not reach RUNNING state."
}

if ($installDriver) {
    Write-Host "[+] blackshard minifilter and protection service are running." -ForegroundColor Green
    & fltmc.exe instances -f $driverName | Out-Host
}
else {
    Write-Host "[+] blackshard protection service is running with AMSI coverage." -ForegroundColor Green
    Write-Host "    Real-time protection covers scripts and macros. Install the signed driver for file system coverage." -ForegroundColor Gray
}
