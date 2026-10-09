#Requires -Version 5.1

<#
.SYNOPSIS
Times one or more blackshard builds against the same corpus and compares them.

.DESCRIPTION
Each build runs `blackshard-service.exe --evaluate-corpus` several times. Runs alternate between
builds, so drift on a shared CI machine (thermal throttling, a noisy neighbour, Defender waking up)
lands on every build rather than one. The first round is a warm-up that fills the file cache and is
discarded; the median of the rest is reported.

With -Baseline, the first build is the reference and every other build is compared with it. With
-MaxRegressionPercent, the script fails when a candidate is slower than the baseline by more than
that much, which is how CI stops a change that makes scanning slower.

Builds of the same source (say a plain and a profile-guided build) must make the same detections;
list them in -MustAgree and the script fails if an optimisation changed what blackshard detects.

A Markdown summary goes to -SummaryPath (CI passes $GITHUB_STEP_SUMMARY) and the raw numbers to
-ReportPath as JSON.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CorpusDirectory,
    # name=path pairs, e.g. "main=C:\base\blackshard-service.exe","change=.\target\release\blackshard-service.exe"
    [Parameter(Mandatory = $true)]
    [string[]]$Build,
    [int]$Rounds = 5,
    [string]$Baseline,
    [double]$MaxRegressionPercent = 0,
    [string[]]$MustAgree = @(),
    [string]$ReportPath,
    [string]$SummaryPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# `powershell -File` hands an array over as one comma-separated string.
$Build = @($Build | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$MustAgree = @($MustAgree | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$corpus = (Resolve-Path -LiteralPath $CorpusDirectory).Path
$builds = [ordered]@{}
foreach ($pair in $Build) {
    $name, $path = $pair -split '=', 2
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Build '$pair' must be name=path to an existing blackshard-service.exe."
    }
    $builds[$name] = @{ Path = (Resolve-Path -LiteralPath $path).Path; Runs = New-Object System.Collections.ArrayList }
}
if ($Baseline -and -not $builds.Contains($Baseline)) { throw "Baseline '$Baseline' is not one of the builds." }

$scratch = Join-Path ([IO.Path]::GetTempPath()) ("blackshard-perf-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    for ($round = 0; $round -le $Rounds; $round++) {
        foreach ($name in $builds.Keys) {
            $report = Join-Path $scratch "$name-$round.json"
            $process = Start-Process -FilePath $builds[$name].Path `
                -ArgumentList @('--evaluate-corpus', "`"$corpus`"", "`"$report`"") `
                -PassThru -Wait -WindowStyle Hidden
            if ($process.ExitCode -ne 0) { throw "$name exited with $($process.ExitCode) in round $round." }
            $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
            if ($round -eq 0) { continue }
            [void]$builds[$name].Runs.Add([pscustomobject]@{
                    Throughput = [double]$result.throughput_mib_per_second
                    WallMillis = [double]$result.wall_millis
                    P50 = [double]$result.latency_p50_micros / 1000
                    P95 = [double]$result.latency_p95_micros / 1000
                    P99 = [double]$result.latency_p99_micros / 1000
                    Files = [int]$result.files
                    Verdicts = "$($result.clean)/$($result.suspicious)/$($result.malicious)/$($result.errors)"
                })
        }
    }
}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

function Get-Median([double[]]$Values) {
    $sorted = $Values | Sort-Object
    $middle = [int][Math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2) { $sorted[$middle] } else { ($sorted[$middle - 1] + $sorted[$middle]) / 2 }
}

$results = foreach ($name in $builds.Keys) {
    $runs = $builds[$name].Runs
    [pscustomobject]@{
        Build = $name
        ThroughputMiBps = [Math]::Round((Get-Median ($runs | ForEach-Object Throughput)), 2)
        WallMillis = [Math]::Round((Get-Median ($runs | ForEach-Object WallMillis)))
        P50Millis = [Math]::Round((Get-Median ($runs | ForEach-Object P50)), 2)
        P95Millis = [Math]::Round((Get-Median ($runs | ForEach-Object P95)), 2)
        P99Millis = [Math]::Round((Get-Median ($runs | ForEach-Object P99)), 2)
        Files = $runs[0].Files
        # clean/suspicious/malicious/error. Must not differ between builds of the same source.
        Verdicts = $runs[0].Verdicts
    }
}

$reference = if ($Baseline) { $results | Where-Object Build -eq $Baseline } else { $null }
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('| build | throughput | wall time | p50 per file | p95 | p99 | vs. baseline |')
$lines.Add('|---|---:|---:|---:|---:|---:|---:|')
$regressions = New-Object System.Collections.Generic.List[string]
foreach ($result in $results) {
    $change = ''
    if ($reference -and $result.Build -ne $Baseline) {
        $percent = ($result.ThroughputMiBps / $reference.ThroughputMiBps - 1) * 100
        $change = '{0:+0.0;-0.0}%' -f $percent
        if ($MaxRegressionPercent -gt 0 -and -$percent -gt $MaxRegressionPercent) {
            $regressions.Add("$($result.Build) scans $([Math]::Abs([Math]::Round($percent, 1)))% slower than $Baseline")
        }
    }
    $lines.Add(('| {0} | {1} MiB/s | {2:N0} ms | {3:N2} ms | {4:N2} ms | {5:N2} ms | {6} |' -f
            $result.Build, $result.ThroughputMiBps, $result.WallMillis, $result.P50Millis,
            $result.P95Millis, $result.P99Millis, $change))
}
$lines.Add('')
$lines.Add(("{0} files in the corpus, median of {1} rounds after a warm-up." -f $results[0].Files, $Rounds))
$lines.Add('')
$lines.Add('Verdicts (clean/suspicious/malicious/error): ' +
    (($results | ForEach-Object { "$($_.Build) $($_.Verdicts)" }) -join ', '))
# Detections only: a file another process held open for a moment is an error in one run and clean
# in the next, which says nothing about the build.
$agreeing = @($results | Where-Object { $MustAgree -contains $_.Build })
$disagree = @($agreeing | ForEach-Object { ($_.Verdicts -split '/')[1..2] -join '/' } | Select-Object -Unique).Count -gt 1

$markdown = $lines -join "`n"
Write-Host $markdown
if ($SummaryPath) { Add-Content -LiteralPath $SummaryPath -Value "`n$markdown`n" -Encoding utf8 }
if ($ReportPath) { $results | ConvertTo-Json | Set-Content -LiteralPath $ReportPath -Encoding utf8 }
if ($disagree) {
    throw "An optimisation changed what blackshard detects: $($MustAgree -join ' and ') disagree on verdicts."
}
if ($regressions.Count -gt 0) {
    throw ("Performance regression beyond {0}%: {1}" -f $MaxRegressionPercent, ($regressions -join '; '))
}
