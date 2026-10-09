[CmdletBinding()]
param(
    # Rebuild the service with profile-guided optimisation, trained on a scan corpus. CI uses it
    # for the published build; it adds two service builds, so local builds leave it off.
    [switch]$ProfileGuided
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot
try {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "Cargo is not installed or is not available in PATH."
    }

    & (Join-Path $PSScriptRoot "build-driver.ps1")
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    cargo build --workspace --release
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $x86Target = "i686-pc-windows-msvc"
    $installedTargets = @(& rustup target list --installed)
    if ($LASTEXITCODE -ne 0 -or $x86Target -notin $installedTargets) {
        throw "The $x86Target Rust target is required to build the 32-bit AMSI provider. Run: rustup target add $x86Target"
    }
    cargo build --release -p blackshard-amsi --target $x86Target
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $driverSource = Join-Path $PSScriptRoot "src\driver\blackshard_driver.c"
    $driverBinary = Join-Path $PSScriptRoot "src\driver\x64\Release\blackshard.sys"
    $serviceBinary = Join-Path $PSScriptRoot "target\release\blackshard-service.exe"

    if ($ProfileGuided) {
        # The optimised service only ships once it reaches the plain build's verdict on every file
        # of the corpus. Any failure ships the plain build instead: an optimisation must never be
        # what stops a release.
        try {
            $pgoRoot = Join-Path $PSScriptRoot "target\pgo"
            $corpus = Join-Path $pgoRoot "corpus"
            $optimised = Join-Path $pgoRoot "blackshard-service.exe"
            & (Join-Path $PSScriptRoot "tools\New-PerfCorpus.ps1") -OutputDirectory $corpus
            & (Join-Path $PSScriptRoot "tools\Build-PgoService.ps1") -CorpusDirectory $corpus `
                -OutputPath $optimised -WorkDirectory (Join-Path $pgoRoot "work")
            & (Join-Path $PSScriptRoot "tools\Measure-Performance.ps1") -CorpusDirectory $corpus `
                -Build "plain=$serviceBinary", "profile-guided=$optimised" -Baseline plain `
                -MustAgree plain, profile-guided -Rounds 2 -SummaryPath $env:GITHUB_STEP_SUMMARY
            $serviceBinary = $optimised
            Write-Host "[+] Shipping the profile-guided service." -ForegroundColor Green
        }
        catch {
            Write-Warning "Profile-guided optimisation failed; shipping the plain service: $_"
            if ($env:GITHUB_ACTIONS) { Write-Host "::warning::Profile-guided optimisation failed; the plain service was shipped. $_" }
        }
    }
    $uiBinary = Join-Path $PSScriptRoot "target\release\blackshard-ui.exe"
    $amsiX64Binary = Join-Path $PSScriptRoot "target\release\blackshard_amsi.dll"
    $amsiX86Binary = Join-Path $PSScriptRoot "target\$x86Target\release\blackshard_amsi.dll"

    if (-not (Test-Path -LiteralPath $driverBinary)) {
        throw "The driver build completed without producing blackshard.sys."
    }
    if ((Get-Item -LiteralPath $driverBinary).LastWriteTimeUtc -lt (Get-Item -LiteralPath $driverSource).LastWriteTimeUtc) {
        throw "blackshard.sys is older than its source. Refusing to package a stale kernel driver."
    }
    foreach ($artifact in @(
        @{ Path = $serviceBinary; Name = "blackshard-service.exe" },
        @{ Path = $uiBinary; Name = "blackshard-ui.exe" },
        @{ Path = $amsiX64Binary; Name = "blackshard-amsi-x64.dll" },
        @{ Path = $amsiX86Binary; Name = "blackshard-amsi-x86.dll" }
    )) {
        if (-not (Test-Path -LiteralPath $artifact.Path -PathType Leaf)) {
            throw "The Cargo build completed without producing $($artifact.Name)."
        }
    }

    $distributionDirectory = Join-Path $PSScriptRoot "dist"
    if (Test-Path -LiteralPath $distributionDirectory) {
        $resolvedDistribution = (Resolve-Path -LiteralPath $distributionDirectory).Path
        if ($resolvedDistribution -ne (Join-Path $PSScriptRoot "dist")) {
            throw "Refusing to clean unexpected distribution path: $resolvedDistribution"
        }
        Remove-Item -LiteralPath $resolvedDistribution -Recurse -Force
    }
    New-Item -ItemType Directory -Path $distributionDirectory | Out-Null

    foreach ($scriptName in @(
        "install.ps1",
        "uninstall.ps1",
        "verify.ps1",
        "enable-test-signing.ps1",
        "disable-test-signing.ps1"
    )) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $scriptName) -Destination $distributionDirectory
    }

    Copy-Item -LiteralPath $driverBinary -Destination (Join-Path $distributionDirectory "blackshard.sys")
    Copy-Item -LiteralPath $serviceBinary -Destination (Join-Path $distributionDirectory "blackshard-service.exe")
    Copy-Item -LiteralPath $uiBinary -Destination (Join-Path $distributionDirectory "blackshard-ui.exe")
    Copy-Item -LiteralPath $amsiX64Binary -Destination (Join-Path $distributionDirectory "blackshard-amsi-x64.dll")
    Copy-Item -LiteralPath $amsiX86Binary -Destination (Join-Path $distributionDirectory "blackshard-amsi-x86.dll")
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "README.md") -Destination $distributionDirectory
    $requiredArtifacts = @(
        "blackshard-service.exe",
        "blackshard-ui.exe",
        "blackshard.sys",
        "blackshard-amsi-x64.dll",
        "blackshard-amsi-x86.dll"
    )
    foreach ($requiredArtifact in $requiredArtifacts) {
        if (-not (Test-Path -LiteralPath (Join-Path $distributionDirectory $requiredArtifact) -PathType Leaf)) {
            throw "Missing release artifact: $requiredArtifact"
        }
    }

    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $distributionDirectory "blackshard.sys")
    if ($signature.Status -ne "Valid") {
        Write-Warning "The packaged driver is not production-signed. Use the included test-signing script only in an isolated VM."
    }

    Write-Host "[+] Distribution created successfully:" -ForegroundColor Green
    Get-ChildItem -LiteralPath $distributionDirectory -File |
        Select-Object Name, Length, LastWriteTime |
        Format-Table -AutoSize |
        Out-Host
}
finally {
    Pop-Location
}
