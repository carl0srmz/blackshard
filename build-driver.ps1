[CmdletBinding()]
param(
    [switch]$NoNuGetFallback,
    # Compile with MSVC code analysis (/analyze) as well, writing findings to the console. It
    # builds nothing; run it to see what the analyzer reports about the driver.
    [switch]$Analyze
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "Visual Studio Build Tools were not found. Install Visual Studio 2022 Build Tools with C++ support."
}

$visualStudioRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $visualStudioRoot) {
    throw "The Visual Studio C++ x64 build tools were not found."
}

$msvcRoot = Join-Path $visualStudioRoot "VC\Tools\MSVC"
$msvcVersionDirectory = Get-ChildItem -LiteralPath $msvcRoot -Directory |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1
if (-not $msvcVersionDirectory) {
    throw "No MSVC toolchain was found under $msvcRoot."
}

$compiler = Join-Path $msvcVersionDirectory.FullName "bin\Hostx64\x64\cl.exe"
$linker = Join-Path $msvcVersionDirectory.FullName "bin\Hostx64\x64\link.exe"

$kitsRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
$kitsProperties = Get-ItemProperty -LiteralPath $kitsRegistryPath -ErrorAction SilentlyContinue
$kitsRoot = if ($kitsProperties) { $kitsProperties.KitsRoot10 } else { $null }
if (-not $kitsRoot) {
    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\"
}

$windowsSdkRoot = $kitsRoot
$windowsSdkVersionDirectory = Get-ChildItem -LiteralPath (Join-Path $windowsSdkRoot "Include") -Directory -ErrorAction SilentlyContinue |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "shared\specstrings.h") } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1
if (-not $windowsSdkVersionDirectory) {
    throw "Windows SDK shared headers were not found. Install the Windows 10/11 SDK with the Visual Studio C++ tools."
}

$includeRoot = Join-Path $kitsRoot "Include"
$wdkVersionDirectory = Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "km\fltKernel.h") } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1

if (-not $wdkVersionDirectory -and -not $NoNuGetFallback) {
    $packageId = "microsoft.windows.wdk.x64"
    $packageVersion = "10.0.26100.6584"
    $expectedSha512 = "jhddaBnhMDqt3GVr32RVTtaR0KHmZDjY0JCTMn10OQpk4+AShXCK9QA09vBazp8ni1Mju84qM5SGXfIfnyOJ+g=="
    $cacheRoot = Join-Path $PSScriptRoot "target\wdk-nuget"
    $packagePath = Join-Path $cacheRoot "$packageId.$packageVersion.nupkg"
    $extractPath = Join-Path $cacheRoot "$packageId.$packageVersion"
    $packageUri = "https://api.nuget.org/v3-flatcontainer/$packageId/$packageVersion/$packageId.$packageVersion.nupkg"

    New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
    if (-not (Test-Path -LiteralPath $packagePath)) {
        Write-Host "[*] Downloading verified Microsoft WDK package $packageVersion..." -ForegroundColor Cyan
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $webClient = New-Object System.Net.WebClient
        try {
            $webClient.DownloadFile($packageUri, $packagePath)
        }
        finally {
            $webClient.Dispose()
        }
    }

    $sha512 = [System.Security.Cryptography.SHA512]::Create()
    $packageStream = [System.IO.File]::OpenRead($packagePath)
    try {
        $actualSha512 = [Convert]::ToBase64String($sha512.ComputeHash($packageStream))
    }
    finally {
        $packageStream.Dispose()
        $sha512.Dispose()
    }
    if ($actualSha512 -ne $expectedSha512) {
        throw "The cached Microsoft WDK package failed SHA-512 verification. Delete $packagePath and retry."
    }

    if (-not (Test-Path -LiteralPath $extractPath)) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $extractPath)
    }

    $kitsRoot = Join-Path $extractPath "c"
    $includeRoot = Join-Path $kitsRoot "Include"
    $wdkVersionDirectory = Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "km\fltKernel.h") } |
        Sort-Object { [version]$_.Name } -Descending |
        Select-Object -First 1
}

if (-not $wdkVersionDirectory) {
    throw @"
Windows Driver Kit kernel headers were not found. Install the WDK that matches your
Windows SDK, then rerun this script. The ordinary Windows SDK is not sufficient.
Expected a file like: $includeRoot\<version>\km\fltKernel.h
"@
}

$wdkVersion = $wdkVersionDirectory.Name
$source = Join-Path $PSScriptRoot "src\driver\blackshard_driver.c"
$outputDirectory = Join-Path $PSScriptRoot "src\driver\x64\Release"
$object = Join-Path $outputDirectory "blackshard_driver.obj"
$driver = Join-Path $outputDirectory "blackshard.sys"
$pdb = Join-Path $outputDirectory "blackshard.pdb"

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$compileArguments = @(
    "/nologo", "/c", "/O2", "/W4", "/WX", "/external:W0", "/GS",
    "/D", "AMD64", "/D", "_AMD64_", "/D", "_KERNEL_MODE",
    "/external:I", (Join-Path $wdkVersionDirectory.FullName "km"),
    "/external:I", (Join-Path $wdkVersionDirectory.FullName "km\crt"),
    "/external:I", (Join-Path $wdkVersionDirectory.FullName "shared"),
    "/external:I", (Join-Path $windowsSdkVersionDirectory.FullName "shared"),
    "/external:I", (Join-Path $windowsSdkVersionDirectory.FullName "ucrt"),
    $source,
    "/Fo:$object"
)

if ($Analyze) {
    Write-Host "[*] Analyzing blackshard minifilter with WDK $wdkVersion..." -ForegroundColor Cyan
    $analysisArguments = $compileArguments | Where-Object { $_ -ne "/WX" -and $_ -ne "/Fo:$object" }
    & $compiler @analysisArguments "/analyze" "/analyze:WX-" "/Fo:$object.analysis"
    exit 0
}

Write-Host "[*] Compiling blackshard minifilter with WDK $wdkVersion..." -ForegroundColor Cyan
& $compiler @compileArguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$libraryDirectory = Join-Path $kitsRoot "Lib\$wdkVersion\km\x64"
$linkArguments = @(
    "/nologo", "/MACHINE:X64", "/DRIVER", "/SUBSYSTEM:NATIVE", "/ENTRY:DriverEntry",
    "/NODEFAULTLIB",
    "/LIBPATH:$libraryDirectory",
    "FltMgr.lib", "ntoskrnl.lib", "hal.lib", "BufferOverflowFastFailK.lib",
    $object,
    "/OUT:$driver",
    "/PDB:$pdb"
)

Write-Host "[*] Linking blackshard.sys..." -ForegroundColor Cyan
& $linker @linkArguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "[+] Driver built: $driver" -ForegroundColor Green
