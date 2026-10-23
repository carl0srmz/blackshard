#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CorpusDirectory,
    [Parameter(Mandatory = $true)]
    [string]$ReportPath,
    [string]$blackshardPath = (Join-Path $PSScriptRoot '..\target\release\blackshard-service.exe'),
    # The unpacked ClamAV databases to evaluate with, on top of the built-in rules.
    [string]$SignaturesPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($path in @($CorpusDirectory, $blackshardPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path was not found: $path" }
}
$corpus = (Resolve-Path -LiteralPath $CorpusDirectory).Path
$binary = (Resolve-Path -LiteralPath $blackshardPath).Path
$report = [IO.Path]::GetFullPath($ReportPath)
$arguments = "--evaluate-corpus `"$corpus`" `"$report`""
if ($SignaturesPath) {
    $arguments += " `"$((Resolve-Path -LiteralPath $SignaturesPath).Path)`""
}
$process = Start-Process -FilePath $binary -ArgumentList $arguments -PassThru -WindowStyle Hidden
if (-not $process.WaitForExit(24 * 60 * 60 * 1000)) {
    $process.Kill()
    $process.WaitForExit()
    throw 'Corpus evaluation exceeded 24 hours.'
}
if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $report -PathType Leaf)) {
    throw "blackshard corpus evaluation failed with exit code $($process.ExitCode)."
}
$result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
Write-Host "Files: $($result.files); clean: $($result.clean); suspicious: $($result.suspicious); malicious: $($result.malicious); errors: $($result.errors)"
Write-Host "Throughput: $([Math]::Round([double]$result.throughput_mib_per_second, 2)) MiB/s; p95: $($result.latency_p95_micros) us; p99: $($result.latency_p99_micros) us"
Write-Host "Evidence report: $report"
