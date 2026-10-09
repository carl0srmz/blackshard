#Requires -Version 5.1

<#
.SYNOPSIS
Builds a deterministic, harmless corpus for measuring how fast blackshard scans.

.DESCRIPTION
The mix follows what real-time protection actually sees: signed Windows executables and libraries,
scripts (some carrying the patterns the heuristics look for), plain documents, zip archives and
high-entropy blobs. Everything is either copied from System32 or generated from a fixed seed, so
two runs on the same Windows image produce the same files, and two builds measured against it are
compared fairly. A different -Seed picks other files and generates others, which is how a
profile-guided build is checked on a corpus it was not trained on. Nothing in it is malware; the
only detection is blackshard's own harmless self-test file.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [int]$WindowsBinaries = 400,
    [int]$Scripts = 300,
    [int]$Documents = 150,
    [int]$Archives = 60,
    [int]$Blobs = 40,
    [int]$Seed = 4242
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
$root = (New-Item -ItemType Directory -Path $OutputDirectory).FullName
$random = New-Object System.Random $Seed

function New-Folder([string]$Name) {
    (New-Item -ItemType Directory -Path (Join-Path $root $Name)).FullName
}

function Get-RandomBytes([int]$Count) {
    $bytes = New-Object byte[] $Count
    $random.NextBytes($bytes)
    $bytes
}

# Real PE images exercise header parsing, import analysis, section entropy and YARA's pe module.
$windowsFolder = New-Folder 'windows'
Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'System32') -File |
    Where-Object { $_.Extension -in '.exe', '.dll' -and $_.Length -gt 0 -and $_.Length -le 8MB } |
    Sort-Object Name |
    Sort-Object { $random.Next() } |
    Select-Object -First $WindowsBinaries |
    ForEach-Object {
        try { Copy-Item -LiteralPath $_.FullName -Destination $windowsFolder } catch { }
    }

# Scripts in each language the classifier knows. One template carries an encoded payload and a
# download, so the heuristics have work to do, but never anything that executes what it fetched:
# Microsoft Defender on the runner would remove that, and the corpus would stop being stable.
$scriptFolder = New-Folder 'scripts'
$templates = @(
    @{ Extension = 'ps1'; Body = "param(`$Path)`r`nGet-ChildItem -Path `$Path -Recurse | Where-Object {{ `$_.Length -gt {0} }} | Select-Object FullName, Length`r`nWrite-Output 'done {1}'`r`n" },
    @{ Extension = 'ps1'; Body = "`$data = [Convert]::FromBase64String('{2}')`r`n`$client = New-Object System.Net.WebClient`r`n`$client.DownloadFile('https://example.invalid/{0}', 'report-{1}.csv')`r`n" },
    @{ Extension = 'bat'; Body = "@echo off`r`nsetlocal`r`nset COUNT={0}`r`nfor %%f in (*.log) do echo %%f >> report-{1}.txt`r`nendlocal`r`n" },
    @{ Extension = 'js'; Body = "function total(items) {{ let sum = {0}; for (const item of items) {{ sum += item; }} return sum; }}`r`nconst label = 'run {1}';`r`n" },
    @{ Extension = 'vbs'; Body = "Sub Main()`r`n  Set shell = WScript.CreateObject(""WScript.Shell"")`r`n  shell.Run ""notepad.exe {0}""`r`nEnd Sub`r`n' {1}`r`n" }
)
for ($index = 0; $index -lt $Scripts; $index++) {
    $template = $templates[$index % $templates.Count]
    $payload = [Convert]::ToBase64String((Get-RandomBytes 240))
    $body = $template.Body -f $random.Next(1, 100000), $index, $payload
    $repeat = 1 + $random.Next(0, 40)
    $text = ($body * $repeat)
    [IO.File]::WriteAllText((Join-Path $scriptFolder ("script-{0:D4}.{1}" -f $index, $template.Extension)), $text)
}

# Plain documents: the common case, which should cost almost nothing.
$documentFolder = New-Folder 'documents'
$words = 'shard', 'kernel', 'signature', 'quarantine', 'network', 'gossip', 'engine', 'file', 'scan', 'adaptive', 'legacy', 'windows'
for ($index = 0; $index -lt $Documents; $index++) {
    $builder = New-Object System.Text.StringBuilder
    $length = 200 + $random.Next(0, 20000)
    while ($builder.Length -lt $length) {
        [void]$builder.Append($words[$random.Next(0, $words.Count)]).Append(' ')
    }
    $extension = @('txt', 'csv', 'md')[$index % 3]
    [IO.File]::WriteAllText((Join-Path $documentFolder ("document-{0:D4}.{1}" -f $index, $extension)), $builder.ToString())
}

# Archives, so container inspection and nested scanning are timed.
$archiveFolder = New-Folder 'archives'
$staging = New-Folder 'staging'
$members = @(Get-ChildItem -LiteralPath $scriptFolder, $documentFolder -File | Sort-Object Name)
for ($index = 0; $index -lt $Archives; $index++) {
    $set = Join-Path $staging "set-$index"
    New-Item -ItemType Directory -Path $set | Out-Null
    for ($member = 0; $member -lt (2 + $random.Next(0, 6)); $member++) {
        Copy-Item -LiteralPath $members[$random.Next(0, $members.Count)].FullName -Destination $set
    }
    Compress-Archive -Path (Join-Path $set '*') -DestinationPath (Join-Path $archiveFolder ("archive-{0:D4}.zip" -f $index))
}
Remove-Item -LiteralPath $staging -Recurse -Force

# High-entropy blobs, the shape of compressed media and encrypted data.
$blobFolder = New-Folder 'blobs'
for ($index = 0; $index -lt $Blobs; $index++) {
    $size = 64KB + $random.Next(0, 4MB)
    [IO.File]::WriteAllBytes((Join-Path $blobFolder ("blob-{0:D4}.bin" -f $index)), (Get-RandomBytes $size))
}

# blackshard's harmless self-test payload, so the malicious verdict path is timed as well.
$testFolder = New-Folder 'self-test'
for ($index = 0; $index -lt 5; $index++) {
    [IO.File]::WriteAllText((Join-Path $testFolder "self-test-$index.txt"),
        "BLACKSHARD-HARMLESS-SELF-TEST-V2`nThis file contains no executable code.`n")
}

$files = @(Get-ChildItem -LiteralPath $root -File -Recurse)
$bytes = ($files | Measure-Object -Property Length -Sum).Sum
Write-Host ("Corpus: {0} files, {1:N1} MiB in {2}" -f $files.Count, ($bytes / 1MB), $root)
