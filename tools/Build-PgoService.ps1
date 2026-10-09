#Requires -Version 5.1

<#
.SYNOPSIS
Builds blackshard-service.exe with profile-guided optimisation, trained on a scan corpus.

.DESCRIPTION
The compiler optimises best when it knows which code is hot. This builds an instrumented service,
lets it scan the corpus (tools/New-PerfCorpus.ps1) so it records which branches and functions the
scan path actually takes, merges that profile, and rebuilds the service optimised for it. The
result scans exactly what the plain build scans, only faster; Measure-Performance.ps1 checks both.

Needs the llvm-tools rustup component for llvm-profdata.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CorpusDirectory,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$WorkDirectory = (Join-Path ([IO.Path]::GetTempPath()) 'blackshard-pgo'),
    [int]$TrainingRuns = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = Split-Path -Parent $PSScriptRoot
$corpus = (Resolve-Path -LiteralPath $CorpusDirectory).Path
$profiles = Join-Path $WorkDirectory 'profiles'
if (Test-Path -LiteralPath $profiles) { Remove-Item -LiteralPath $profiles -Recurse -Force }
New-Item -ItemType Directory -Force -Path $profiles | Out-Null

$sysroot = (& rustc --print sysroot).Trim()
$profdata = Get-ChildItem -LiteralPath (Join-Path $sysroot 'lib\rustlib') -Recurse -Filter 'llvm-profdata.exe' |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $profdata) { throw 'llvm-profdata was not found; run: rustup component add llvm-tools' }

function Invoke-ServiceBuild([string]$Flags, [string]$TargetDirectory) {
    # RUSTFLAGS replaces the target rustflags in .cargo/config.toml, so the static CRT is restated.
    $saved = $env:RUSTFLAGS
    $env:RUSTFLAGS = "$Flags -Ctarget-feature=+crt-static"
    # One fat-LTO unit. With the default sixteen codegen units the instrumented service wrote
    # profiles with no counters in them on windows-msvc, and the optimised build ignored them.
    $env:CARGO_PROFILE_RELEASE_LTO = 'fat'
    $env:CARGO_PROFILE_RELEASE_CODEGEN_UNITS = '1'
    try {
        # To the host, not the pipeline: anything left in the pipeline becomes the return value.
        & cmd /c "cargo build --release --bin blackshard-service --manifest-path `"$repository\Cargo.toml`" --target-dir `"$TargetDirectory`" 2>&1" |
            Out-Host
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with $Flags" }
    }
    finally {
        $env:RUSTFLAGS = $saved
        Remove-Item Env:CARGO_PROFILE_RELEASE_LTO, Env:CARGO_PROFILE_RELEASE_CODEGEN_UNITS
    }
    Join-Path $TargetDirectory 'release\blackshard-service.exe'
}

$instrumented = Invoke-ServiceBuild "-Cprofile-generate=$profiles" (Join-Path $WorkDirectory 'target-instrumented')
# Named explicitly: the default path compiled into the binary was silently not written on some
# machines, leaving nothing to merge.
$env:LLVM_PROFILE_FILE = Join-Path $profiles 'training-%p.profraw'
try {
    for ($run = 0; $run -lt $TrainingRuns; $run++) {
        & $instrumented --evaluate-corpus $corpus (Join-Path $WorkDirectory "training-$run.json")
        if ($LASTEXITCODE -ne 0) { throw "The instrumented training scan failed with $LASTEXITCODE." }
    }
}
finally { Remove-Item Env:LLVM_PROFILE_FILE }
if (-not (Get-ChildItem -LiteralPath $profiles -Filter '*.profraw')) {
    throw 'The training scans wrote no profile data.'
}

$merged = Join-Path $WorkDirectory 'blackshard-service.profdata'
& $profdata merge -o $merged $profiles
if ($LASTEXITCODE -ne 0) { throw 'llvm-profdata could not merge the training profiles.' }
$functions = (& $profdata show $merged | Select-String 'Total functions: (\d+)').Matches[0].Groups[1].Value
if ([int]$functions -eq 0) { throw 'The merged profile is empty; the optimised build would ignore it.' }
Write-Host "[*] Profile covers $functions functions."

$optimised = Invoke-ServiceBuild "-Cprofile-use=$merged" (Join-Path $WorkDirectory 'target-optimised')
Copy-Item -LiteralPath $optimised -Destination $OutputPath -Force
Copy-Item -LiteralPath $merged -Destination ([IO.Path]::ChangeExtension($OutputPath, '.profdata')) -Force
Write-Host "[+] Profile-guided service: $OutputPath"
