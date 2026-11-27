[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ServicePath,
    [Parameter(Mandatory)]
    [string]$UiPath,
    [Parameter(Mandatory)]
    [string]$DriverPath,
    [Parameter(Mandatory)]
    [string]$AmsiX64Path,
    [Parameter(Mandatory)]
    [string]$AmsiX86Path,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\target\development-installer"),
    # Shown in Apps & features and stamped into the executable. Defaults to the Cargo version.
    [string]$Version,
    # CI run number, used as the fourth part of the file version.
    [ValidateRange(0, 65535)]
    [int]$BuildNumber = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RequiredFile([string]$Path, [string]$Description) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description was not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$Description must not be a reparse point: $Path"
    }
    return $item.FullName
}

$ServicePath = Resolve-RequiredFile $ServicePath "blackshard protection service"
$UiPath = Resolve-RequiredFile $UiPath "blackshard desktop UI"
$DriverPath = Resolve-RequiredFile $DriverPath "blackshard development driver"
$AmsiX64Path = Resolve-RequiredFile $AmsiX64Path "blackshard x64 AMSI provider"
$AmsiX86Path = Resolve-RequiredFile $AmsiX86Path "blackshard x86 AMSI provider"
$oobeSource = Resolve-RequiredFile (Join-Path $PSScriptRoot "..\oobe.png") "blackshard OOBE image"
$logoSource = Resolve-RequiredFile (Join-Path $PSScriptRoot "..\logo.png") "blackshard logo"
$cargoVersion = (Select-String -LiteralPath (Join-Path $PSScriptRoot "..\Cargo.toml") `
    -Pattern '^version\s*=\s*"(\d+)\.(\d+)\.(\d+)' | Select-Object -First 1).Matches[0]
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "{0}.{1}.{2}" -f $cargoVersion.Groups[1].Value, $cargoVersion.Groups[2].Value, $cargoVersion.Groups[3].Value
}
$fileVersion = "{0}.{1}.{2}.{3}" -f $cargoVersion.Groups[1].Value, $cargoVersion.Groups[2].Value, `
    $cargoVersion.Groups[3].Value, $BuildNumber
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$buildRoot = Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\target"))) "development-installer-build"
if (Test-Path -LiteralPath $buildRoot) {
    $resolvedBuildRoot = (Resolve-Path -LiteralPath $buildRoot).Path
    $allowedParent = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\target"))
    if (-not $resolvedBuildRoot.StartsWith($allowedParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean unexpected installer workspace: $resolvedBuildRoot"
    }
    Remove-Item -LiteralPath $resolvedBuildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $buildRoot | Out-Null

$cscCandidates = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
)
$csc = $cscCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1
if (-not $csc) {
    throw "The .NET Framework C# compiler is required to build the VM setup interface."
}

$uiSource = Resolve-RequiredFile (Join-Path $PSScriptRoot "development\setup-ui.cs") "VM setup UI source"
$fontRoot = Join-Path $PSScriptRoot "..\assets\fonts"
$interRegular = Resolve-RequiredFile (Join-Path $fontRoot "Inter-Regular.ttf") "Inter Regular font"
$interBold = Resolve-RequiredFile (Join-Path $fontRoot "Inter-Bold.ttf") "Inter Bold font"
$jetBrainsMonoRegular = Resolve-RequiredFile (Join-Path $fontRoot "JetBrainsMono-Regular.ttf") "JetBrains Mono Regular font"
$jetBrainsMonoBold = Resolve-RequiredFile (Join-Path $fontRoot "JetBrainsMono-Bold.ttf") "JetBrains Mono Bold font"
$interLicense = Resolve-RequiredFile (Join-Path $fontRoot "LICENSE-Inter.txt") "Inter license"
$jetBrainsMonoLicense = Resolve-RequiredFile (Join-Path $fontRoot "LICENSE-JetBrainsMono.txt") "JetBrains Mono license"
$uiExecutable = Join-Path $buildRoot "blackshard-setup-ui.exe"
$uiManifest = Join-Path $buildRoot "blackshard-setup-ui.manifest"
$outerManifest = Join-Path $buildRoot "blackshard-vm-setup.manifest"
$assemblyInfo = Join-Path $buildRoot "blackshard-setup-assembly-info.cs"
$manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="1.0.0.0" name="blackshard.development.setup-ui" />
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
      <supportedOS Id="{4f476546-9374-4f8b-9b18-69815ec5e903}" />
    </application>
  </compatibility>
</assembly>
"@
[IO.File]::WriteAllText($uiManifest, $manifest, [Text.Encoding]::UTF8)
$outerManifestContent = $manifest.Replace(
    'level="asInvoker"',
    'level="requireAdministrator"'
)
[IO.File]::WriteAllText($outerManifest, $outerManifestContent, [Text.Encoding]::UTF8)
$assemblyMetadata = @"
using System.Reflection;
[assembly: AssemblyTitle("blackshard setup")]
[assembly: AssemblyDescription("blackshard preview installer")]
[assembly: AssemblyCompany("blackshard")]
[assembly: AssemblyProduct("blackshard")]
[assembly: AssemblyVersion("$fileVersion")]
[assembly: AssemblyFileVersion("$fileVersion")]
[assembly: AssemblyInformationalVersion("$Version")]
"@
[IO.File]::WriteAllText($assemblyInfo, $assemblyMetadata, [Text.Encoding]::UTF8)
$compiler = Start-Process -FilePath $csc -ArgumentList @(
    "/nologo",
    "/target:winexe",
    "/optimize+",
    "/platform:x64",
    ('/win32manifest:"{0}"' -f $uiManifest),
    "/reference:System.dll",
    "/reference:System.Drawing.dll",
    "/reference:System.Windows.Forms.dll",
    ('/resource:"{0}",blackshard.fonts.Inter.Regular.ttf' -f $interRegular),
    ('/resource:"{0}",blackshard.fonts.Inter.Bold.ttf' -f $interBold),
    ('/resource:"{0}",blackshard.fonts.JetBrainsMono.Regular.ttf' -f $jetBrainsMonoRegular),
    ('/resource:"{0}",blackshard.fonts.JetBrainsMono.Bold.ttf' -f $jetBrainsMonoBold),
    ('/resource:"{0}",blackshard.fonts.Inter.LICENSE.txt' -f $interLicense),
    ('/resource:"{0}",blackshard.fonts.JetBrainsMono.LICENSE.txt' -f $jetBrainsMonoLicense),
    ('/out:"{0}"' -f $uiExecutable),
    ('"{0}"' -f $assemblyInfo),
    ('"{0}"' -f $uiSource)
) -WorkingDirectory $buildRoot -WindowStyle Hidden -Wait -PassThru
if ($compiler.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $uiExecutable -PathType Leaf)) {
    throw "The blackshard VM setup interface could not be compiled (csc exit code $($compiler.ExitCode))."
}

$iconPath = Join-Path $buildRoot "blackshard.ico"
& (Join-Path $PSScriptRoot "..\tools\New-BlackshardIcon.ps1") -LogoPath $logoSource -OutputPath $iconPath

$versionFile = Join-Path $buildRoot "version.txt"
[IO.File]::WriteAllText($versionFile, $Version, [Text.UTF8Encoding]::new($false))

$payload = [ordered]@{
    "blackshard-setup-ui.exe" = $uiExecutable
    "blackshard-service.exe" = $ServicePath
    "blackshard-ui.exe" = $UiPath
    "blackshard.sys" = $DriverPath
    "blackshard-amsi-x64.dll" = $AmsiX64Path
    "blackshard-amsi-x86.dll" = $AmsiX86Path
    "install.ps1" = (Join-Path $PSScriptRoot "..\install.ps1")
    "uninstall.ps1" = (Join-Path $PSScriptRoot "..\uninstall.ps1")
    "verify.ps1" = (Join-Path $PSScriptRoot "..\verify.ps1")
    "enable-test-signing.ps1" = (Join-Path $PSScriptRoot "..\enable-test-signing.ps1")
    "disable-test-signing.ps1" = (Join-Path $PSScriptRoot "..\disable-test-signing.ps1")
    "vm-setup.ps1" = (Join-Path $PSScriptRoot "development\vm-setup.ps1")
    "version.txt" = $versionFile
    "oobe.png" = $oobeSource
    "logo.png" = $logoSource
    "blackshard.ico" = $iconPath
}

# The setup UI refuses to start unless every file it lists is embedded, so the two lists must
# match exactly. A stale entry there once shipped an installer that failed on launch.
$uiSourceText = Get-Content -LiteralPath $uiSource -Raw
$listMatch = [regex]::Match($uiSourceText, '(?s)string\[\]\s+FileNames\s*=\s*\{(.*?)\};')
if (-not $listMatch.Success) {
    throw "Could not find the EmbeddedPayload.FileNames list in $uiSource."
}
$uiPayloadNames = @([regex]::Matches($listMatch.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
$missingFromPayload = @($uiPayloadNames | Where-Object { $_ -notin $payload.Keys })
$missingFromUi = @($payload.Keys | Where-Object { $_ -notin $uiPayloadNames })
if ($missingFromPayload.Count -or $missingFromUi.Count) {
    throw "setup-ui.cs and this script disagree on the payload. Listed by the UI but not embedded: $($missingFromPayload -join ', '). Embedded but not listed by the UI: $($missingFromUi -join ', ')."
}

foreach ($entry in $payload.GetEnumerator()) {
    $source = Resolve-RequiredFile $entry.Value "Installer payload $($entry.Key)"
    $destination = Join-Path $buildRoot $entry.Key
    if (-not $source.Equals([IO.Path]::GetFullPath($destination), [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $source -Destination $destination
    }
}

$packageOutputDirectory = Join-Path $buildRoot "package-output"
New-Item -ItemType Directory -Path $packageOutputDirectory | Out-Null
$packageOutputPath = Join-Path $packageOutputDirectory "blackshard-setup.exe"
$outputPath = Join-Path $OutputDirectory "blackshard-setup.exe"
if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
    Remove-Item -LiteralPath $outputPath -Force
}
$outerArguments = New-Object Collections.Generic.List[string]
$outerArguments.Add("/nologo")
$outerArguments.Add("/target:winexe")
$outerArguments.Add("/optimize+")
$outerArguments.Add("/platform:x64")
$outerArguments.Add(('/win32manifest:"{0}"' -f $outerManifest))
$outerArguments.Add(('/win32icon:"{0}"' -f $iconPath))
$outerArguments.Add("/reference:System.dll")
$outerArguments.Add("/reference:System.Drawing.dll")
$outerArguments.Add("/reference:System.Windows.Forms.dll")
$outerArguments.Add(('/resource:"{0}",blackshard.fonts.Inter.Regular.ttf' -f $interRegular))
$outerArguments.Add(('/resource:"{0}",blackshard.fonts.Inter.Bold.ttf' -f $interBold))
$outerArguments.Add(('/resource:"{0}",blackshard.fonts.JetBrainsMono.Regular.ttf' -f $jetBrainsMonoRegular))
$outerArguments.Add(('/resource:"{0}",blackshard.fonts.JetBrainsMono.Bold.ttf' -f $jetBrainsMonoBold))
$outerArguments.Add(('/resource:"{0}",blackshard.fonts.Inter.LICENSE.txt' -f $interLicense))
$outerArguments.Add(('/resource:"{0}",blackshard.fonts.JetBrainsMono.LICENSE.txt' -f $jetBrainsMonoLicense))
foreach ($name in $payload.Keys) {
    $outerArguments.Add((
        '/resource:"{0}",blackshard.payload.{1}' -f (Join-Path $buildRoot $name), $name
    ))
}
$outerArguments.Add(('/out:"{0}"' -f $packageOutputPath))
$outerArguments.Add(('"{0}"' -f $assemblyInfo))
$outerArguments.Add(('"{0}"' -f $uiSource))

$outerCompiler = Start-Process -FilePath $csc -ArgumentList $outerArguments `
    -WorkingDirectory $buildRoot -WindowStyle Hidden -Wait -PassThru
if ($outerCompiler.ExitCode -ne 0) {
    throw "The blackshard VM setup executable could not be compiled (csc exit code $($outerCompiler.ExitCode))."
}
if (-not (Test-Path -LiteralPath $packageOutputPath -PathType Leaf)) {
    throw "The compiler completed without producing $packageOutputPath."
}
Copy-Item -LiteralPath $packageOutputPath -Destination $outputPath -Force

$builtAssembly = [Reflection.Assembly]::LoadFile($outputPath)
$embeddedPayloads = @(
    $builtAssembly.GetManifestResourceNames() |
        Where-Object { $_.StartsWith("blackshard.payload.", [StringComparison]::Ordinal) }
)
$expectedPayloads = @($payload.Keys | ForEach-Object { "blackshard.payload.$_" })
if ($embeddedPayloads.Count -ne $expectedPayloads.Count) {
    throw "Expected $($expectedPayloads.Count) embedded payloads, found $($embeddedPayloads.Count)."
}
foreach ($resourceName in $expectedPayloads) {
    if ($embeddedPayloads -notcontains $resourceName) {
        throw "The compiled installer is missing embedded payload $resourceName."
    }
}

$hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
Write-Host "[+] Installer $Version created: $outputPath" -ForegroundColor Green
Write-Host "[+] SHA-256: $hash" -ForegroundColor Green
