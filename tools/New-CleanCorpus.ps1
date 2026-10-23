#Requires -Version 5.1
<#
.SYNOPSIS
  Copies a few thousand of the machine's own Windows and developer-tool files into one folder, as
  a corpus of software that is known to be clean. Writes the folder's path to the pipeline.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$sources = @(
    @{ Path = "$env:windir\System32"; Count = 1200 },
    @{ Path = "$env:windir\SysWOW64"; Count = 400 },
    @{ Path = "$env:windir\System32\drivers"; Count = 200 },
    @{ Path = "${env:ProgramFiles}\Git"; Count = 300; Recurse = $true },
    @{ Path = "${env:ProgramFiles}\PowerShell"; Count = 100; Recurse = $true },
    @{ Path = "${env:ProgramFiles(x86)}\Microsoft Visual Studio"; Count = 400; Recurse = $true }
)
$extensions = '.exe', '.dll', '.sys', '.ps1', '.psm1', '.vbs', '.js', '.bat', '.cmd'
foreach ($source in $sources) {
    if (-not (Test-Path -LiteralPath $source.Path)) { continue }
    $files = Get-ChildItem -LiteralPath $source.Path -File -Recurse:([bool]$source.Recurse) -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in $extensions -and $_.Length -lt 64MB } |
        Sort-Object FullName | Select-Object -First $source.Count
    $index = 0
    foreach ($file in $files) {
        $name = '{0}-{1:D5}-{2}' -f ($source.Path -replace '[^A-Za-z0-9]', '_'), $index++, $file.Name
        Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $OutputDirectory $name) -ErrorAction SilentlyContinue
    }
}
$OutputDirectory
