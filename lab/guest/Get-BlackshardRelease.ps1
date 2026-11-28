#Requires -RunAsAdministrator
<#
  Inside the VM, while it is on the Online network and BEFORE any sample is on it.
  Downloads the testing build (blackshard-portable-x64.zip, rebuilt from every commit to main),
  checks it against the release's SHA256SUMS.txt, unpacks it to C:\blackshard-dist and test-signs
  the driver. Then restart and run install.ps1 -AllowUnsigned.

  Use this when the host can't build blackshard. A build from deploy.ps1 goes in with the host's
  Update-LabPayload.ps1 instead.
#>
[CmdletBinding()]
param(
    [string]$Release = 'https://github.com/carl0srmz/blackshard/releases/download/veryveryunstable',
    [string]$Destination = 'C:\blackshard-dist',
    [switch]$SkipTestSigning
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is many times slower with the progress bar

$work = Join-Path $env:TEMP "blackshard-release-$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $work | Out-Null
$zip = Join-Path $work 'blackshard-portable-x64.zip'
$sums = Join-Path $work 'SHA256SUMS.txt'

Write-Host '[*] Downloading the testing build...' -ForegroundColor Cyan
Invoke-WebRequest "$Release/SHA256SUMS.txt" -OutFile $sums -UseBasicParsing
Invoke-WebRequest "$Release/blackshard-portable-x64.zip" -OutFile $zip -UseBasicParsing

$expected = Get-Content -LiteralPath $sums | Where-Object { $_ -match '^([0-9a-f]{64})\s+blackshard-portable-x64\.zip$' } |
    ForEach-Object { $Matches[1] } | Select-Object -First 1
$actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $expected -or $expected -ne $actual) {
    throw "Checksum mismatch for blackshard-portable-x64.zip (expected '$expected', got '$actual'). Not unpacking it."
}
Write-Host "    SHA256 OK: $actual"

# Unpack and check next to the download first, so the build already in $Destination is only
# replaced by a complete one.
$unpacked = Join-Path $work 'dist'
Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
foreach ($required in 'blackshard.sys', 'blackshard-service.exe', 'install.ps1') {
    if (-not (Test-Path -LiteralPath (Join-Path $unpacked $required))) {
        throw "The release has no $required. Build on the host instead and use Update-LabPayload.ps1."
    }
}

# A shell sitting in $Destination (say, after running install.ps1 from it) holds the folder open,
# and Windows won't delete it. Step out to its parent; the shell stays there afterwards.
$Destination = [IO.Path]::GetFullPath($Destination)
$here = [IO.Path]::GetFullPath((Get-Location -PSProvider FileSystem).ProviderPath)
if ($here.TrimEnd('\') -eq $Destination.TrimEnd('\') -or $here.StartsWith($Destination.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    Set-Location -LiteralPath (Split-Path -Parent $Destination)
    [Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
}
if (Test-Path -LiteralPath $Destination) {
    try { Remove-Item -LiteralPath $Destination -Recurse -Force }
    catch { throw "Couldn't replace $Destination ($_). Close any window or program using a file in it, then run this again." }
}
Move-Item -LiteralPath $unpacked -Destination $Destination
Remove-Item -LiteralPath $work -Recurse -Force
$version = Join-Path $Destination 'VERSION.txt'
if (Test-Path -LiteralPath $version) { Write-Host "    version: $((Get-Content -LiteralPath $version -Raw).Trim())" }

if ($SkipTestSigning) { return }
$signer = Join-Path $Destination 'enable-test-signing.ps1'
if (-not (Test-Path -LiteralPath $signer)) {
    # Older packages left it out; it's the same script as in the repository.
    Invoke-WebRequest 'https://raw.githubusercontent.com/carl0srmz/blackshard/main/enable-test-signing.ps1' -OutFile $signer -UseBasicParsing
}
& $signer
Write-Host '[+] Next: restart, then in an admin PowerShell: cd C:\blackshard-dist; .\install.ps1 -AllowUnsigned' -ForegroundColor Green
