#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$DevelopmentVm,
    # Verify a driverless install: the service runs in the userland tier and no minifilter is
    # expected. Definitions may still be downloading, so readiness is reported but not required.
    [switch]$Userland,
    [switch]$NoExit,
    [ValidateRange(0, 600)]
    [int]$WaitSeconds = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverName = "blackshard"
$protectionServiceName = "blackshard-protection-service"
$driverPath = Join-Path $env:SystemRoot "System32\drivers\blackshard.sys"
$agentDirectory = Join-Path $env:ProgramFiles "blackshard"
$applicationNames = @("blackshard-service.exe", "blackshard-ui.exe")
$healthPath = Join-Path $env:ProgramData "blackshard\service-health.json"
$healthSchemaVersion = 4

function Invoke-ServiceQuery {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Label
    )

    Write-Host "`n=== $Label ($Name) ===" -ForegroundColor Cyan
    $output = & sc.exe query $Name 2>&1
    $exitCode = $LASTEXITCODE
    $output | Out-Host
    return [pscustomobject]@{
        Exists  = ($exitCode -eq 0)
        Running = ($exitCode -eq 0 -and (($output | Out-String) -match "(?im)STATE\s*:\s*4\s+RUNNING"))
    }
}

$driverService = Invoke-ServiceQuery -Name $driverName -Label "Kernel minifilter service"

$protectionService = Invoke-ServiceQuery `
    -Name $protectionServiceName `
    -Label "User-mode protection service"

Write-Host "`n=== Loaded minifilter ===" -ForegroundColor Cyan
$filterOutput = & fltmc.exe filters 2>&1
$filterExitCode = $LASTEXITCODE
$filterOutput | Out-Host
$loaded = ($filterExitCode -eq 0 -and (($filterOutput | Out-String) -match "(?im)^\s*blackshard\s+"))

$instancesHealthy = $false
if ($loaded) {
    Write-Host "`n=== Filter instances ===" -ForegroundColor Cyan
    $instanceOutput = & fltmc.exe instances -f $driverName 2>&1
    $instanceExitCode = $LASTEXITCODE
    $instanceOutput | Out-Host
    # `fltmc instances -f` can omit the filter column, so the instance name counts too.
    $instancesHealthy = ($instanceExitCode -eq 0 -and (($instanceOutput | Out-String) -match "(?im)^\s*blackshard\s+|blackshard Instance"))
}

Write-Host "`n=== Installed driver file ===" -ForegroundColor Cyan
if (Test-Path -LiteralPath $driverPath -PathType Leaf) {
    $driverFile = Get-Item -LiteralPath $driverPath
    $driverFile | Select-Object FullName, Length, LastWriteTimeUtc | Format-List | Out-Host
    Write-Host "Embedded Authenticode status (the production driver may instead be trusted through its signed catalog):"
    Get-AuthenticodeSignature -LiteralPath $driverPath |
        Select-Object Status, StatusMessage, SignerCertificate |
        Format-List |
        Out-Host
} else {
    Write-Host "Driver file not found: $driverPath" -ForegroundColor Red
}

$applicationsPresent = $true
$applicationsSigned = $true
$applicationAclHealthy = $true
if (Test-Path -LiteralPath $agentDirectory -PathType Container) {
    $agentAcl = Get-Acl -LiteralPath $agentDirectory
    $applicationAclHealthy = -not $agentAcl.AreAccessRulesProtected
    Write-Host "`n=== blackshard application-directory ACL ===" -ForegroundColor Cyan
    if ($applicationAclHealthy) {
        Write-Host "Program Files inheritance is enabled, including Windows application-package read/execute access."
    }
    else {
        Write-Host "Program Files inheritance is disabled. WinRT dependencies can fail with status 0xC0000022." -ForegroundColor Red
    }
}
Write-Host "`n=== blackshard application signatures ===" -ForegroundColor Cyan
foreach ($applicationName in $applicationNames) {
    $installedPath = Join-Path $env:ProgramFiles "blackshard\$applicationName"
    $localPath = Join-Path $PSScriptRoot $applicationName
    $applicationPath = if (Test-Path -LiteralPath $installedPath -PathType Leaf) {
        $installedPath
    } elseif (Test-Path -LiteralPath $localPath -PathType Leaf) {
        $localPath
    } else {
        $null
    }
    if ($null -eq $applicationPath) {
        Write-Host "$applicationName was not found in Program Files or beside verify.ps1." -ForegroundColor Red
        $applicationsPresent = $false
        $applicationsSigned = $false
        continue
    }
    $applicationSignature = Get-AuthenticodeSignature -LiteralPath $applicationPath
    $applicationSignature |
        Select-Object Path, Status, StatusMessage, SignerCertificate |
        Format-List |
        Out-Host
    if ($applicationSignature.Status -ne "Valid") {
        $applicationsSigned = $false
    }
}

$healthHealthy = $false
Write-Host "`n=== Protection-service health ===" -ForegroundColor Cyan
$health = $null
$healthError = $null
$healthDeadline = [DateTimeOffset]::UtcNow.AddSeconds($WaitSeconds)
do {
    $healthError = $null
    if (-not (Test-Path -LiteralPath $healthPath -PathType Leaf)) {
        $healthError = "Health file not found: $healthPath"
    }
    else {
        try {
            $candidate = Get-Content -LiteralPath $healthPath -Raw | ConvertFrom-Json
            $updatedAt = [DateTimeOffset]::Parse([string]$candidate.updated_at)
            $ageSeconds = ([DateTimeOffset]::UtcNow - $updatedAt.ToUniversalTime()).TotalSeconds
            $current = (
                [int]$candidate.schema_version -eq $healthSchemaVersion -and
                [string]$candidate.lifecycle -eq "running" -and
                $ageSeconds -ge -5 -and
                $ageSeconds -le 15
            )
            $healthHealthy = if ($Userland) {
                $current -and [string]$candidate.tier -eq "Userland"
            }
            else {
                [int]$candidate.schema_version -eq $healthSchemaVersion -and
                [string]$candidate.lifecycle -eq "running" -and
                [string]$candidate.connection -eq "connected" -and
                [string]$candidate.readiness -eq "Ready" -and
                [bool]$candidate.real_time_enabled -and
                -not [bool]$candidate.external_rules_suppressed -and
                $ageSeconds -ge -5 -and
                $ageSeconds -le 15
            }
            $health = $candidate
        }
        catch {
            $healthError = "Could not validate $healthPath`: $($_.Exception.Message)"
            $healthHealthy = $false
        }
    }
    if ($healthHealthy -or [DateTimeOffset]::UtcNow -ge $healthDeadline) {
        break
    }
    Start-Sleep -Seconds 1
} while ($true)

if ($null -ne $health) {
    try {
        $health | Format-List | Out-Host
        if (-not $healthHealthy) {
            Write-Host "Health did not report current, connected real-time protection within $WaitSeconds seconds." -ForegroundColor Red
        }
        $driverBypasses = [uint64]$health.counters.service_unavailable_bypasses +
            [uint64]$health.counters.object_resolution_bypasses +
            [uint64]$health.counters.oversize_path_bypasses +
            [uint64]$health.counters.irql_bypasses +
            [uint64]$health.counters.enforcement_bypasses +
            [uint64]$health.counters.bypassed_due_to_load
        if ($driverBypasses -gt 0 -or [uint64]$health.counters.driver_timeouts -gt 0) {
            Write-Host "Warning: the driver reports $driverBypasses bypassed requests and $($health.counters.driver_timeouts) timeouts since load. Review before release qualification." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Could not validate $healthPath`: $($_.Exception.Message)" -ForegroundColor Red
        $healthHealthy = $false
    }
}
elseif ($null -ne $healthError) {
    Write-Host $healthError -ForegroundColor Red
}

# Named so a failure says which check it was.
$checks = if ($Userland) {
    [ordered]@{
        "no kernel minifilter service is registered"      = -not $driverService.Exists
        "no blackshard minifilter is loaded"              = -not $loaded
        "the protection service is running"               = $protectionService.Running
        "service health is current"                       = $healthHealthy
        "the applications are installed"                  = $applicationsPresent
        "the application directory inherits its ACL"      = $applicationAclHealthy
        "the applications are signed"                     = ($DevelopmentVm -or $applicationsSigned)
    }
}
else {
    [ordered]@{
        "the kernel minifilter service is running"        = $driverService.Running
        "the minifilter is loaded"                        = $loaded
        "the minifilter is attached to volumes"           = $instancesHealthy
        "the protection service is running"               = $protectionService.Running
        "service health is current, connected and ready"  = $healthHealthy
        "the applications are installed"                  = $applicationsPresent
        "the application directory inherits its ACL"      = $applicationAclHealthy
        "the applications are signed"                     = ($DevelopmentVm -or $applicationsSigned)
    }
}
$failedChecks = @($checks.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key })
$passed = $failedChecks.Count -eq 0
if ($passed) {
    if ($Userland) {
        Write-Host "`n[PASS] The protection service is running without the kernel minifilter." -ForegroundColor Green
        # Readiness is a plain string when ready and an object named after the state otherwise.
        $readiness = if ($null -eq $health) { "unknown" }
            elseif ($health.readiness -is [string]) { $health.readiness }
            else { @($health.readiness.PSObject.Properties.Name) -join ", " }
        if ($readiness -ne "Ready") {
            Write-Host "Readiness is '$readiness'; definitions may still be downloading." -ForegroundColor Yellow
        }
    } elseif ($DevelopmentVm) {
        Write-Host "`n[PASS] The development-VM minifilter and protection service are healthy." -ForegroundColor Green
        Write-Host "Launch .\blackshard-ui.exe and run the harmless protection test. This result is not production qualification."
    } else {
        Write-Host "`n[PASS] Both blackshard services, filter attachment, service health, and application signature passed local checks." -ForegroundColor Green
        Write-Host "Run the UI's harmless protection test. This diagnostic does not prove detection efficacy or release readiness."
    }
    if ($NoExit) {
        return
    }
    exit 0
}

$failureSummary = "blackshard did not pass all checks for this mode. Failed: $($failedChecks -join '; ')."
Write-Host "`n[FAIL] $failureSummary" -ForegroundColor Red
if (-not $DevelopmentVm) {
    Write-Host "Use -DevelopmentVm only for the legacy unsigned/test-signed disposable-VM workflow."
}
if ($NoExit) {
    throw $failureSummary
}
exit 1
