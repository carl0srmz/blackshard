[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$LogoPath,
    [Parameter(Mandatory)]
    [string]$OutputPath
)

# Builds blackshard.ico from the logo: one 256x256 PNG-compressed image, the logo scaled to fit
# 224 px and centred on a transparent square. Used for the shortcuts that both the setup
# installer and install.ps1 create, so they show the same icon.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$LogoPath = (Resolve-Path -LiteralPath $LogoPath).Path
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

Add-Type -AssemblyName System.Drawing
$sourceImage = $null
$iconBitmap = $null
$graphics = $null
$pngStream = $null
$iconStream = $null
$iconWriter = $null
try {
    $sourceImage = [Drawing.Image]::FromFile($LogoPath)
    $iconBitmap = [Drawing.Bitmap]::new(
        256,
        256,
        [Drawing.Imaging.PixelFormat]::Format32bppArgb
    )
    $graphics = [Drawing.Graphics]::FromImage($iconBitmap)
    $graphics.Clear([Drawing.Color]::Transparent)
    $graphics.CompositingQuality = [Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $maximumDimension = 224.0
    $scale = [Math]::Min(
        $maximumDimension / [double]$sourceImage.Width,
        $maximumDimension / [double]$sourceImage.Height
    )
    $drawWidth = [Math]::Max(1, [int][Math]::Round($sourceImage.Width * $scale))
    $drawHeight = [Math]::Max(1, [int][Math]::Round($sourceImage.Height * $scale))
    $drawX = [int][Math]::Floor((256 - $drawWidth) / 2.0)
    $drawY = [int][Math]::Floor((256 - $drawHeight) / 2.0)
    $graphics.DrawImage($sourceImage, $drawX, $drawY, $drawWidth, $drawHeight)

    $pngStream = [IO.MemoryStream]::new()
    $iconBitmap.Save($pngStream, [Drawing.Imaging.ImageFormat]::Png)
    $pngBytes = $pngStream.ToArray()

    # ICONDIR (reserved, type 1 = icon, one image), then one ICONDIRENTRY (0 = 256 px wide and
    # high, no palette, 1 plane, 32 bpp, data size, data offset 22), then the PNG itself.
    $iconStream = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write)
    $iconWriter = [IO.BinaryWriter]::new($iconStream)
    $iconWriter.Write([uint16]0)
    $iconWriter.Write([uint16]1)
    $iconWriter.Write([uint16]1)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([uint16]1)
    $iconWriter.Write([uint16]32)
    $iconWriter.Write([uint32]$pngBytes.Length)
    $iconWriter.Write([uint32]22)
    $iconWriter.Write($pngBytes)
}
finally {
    if ($null -ne $iconWriter) { $iconWriter.Dispose() }
    elseif ($null -ne $iconStream) { $iconStream.Dispose() }
    if ($null -ne $pngStream) { $pngStream.Dispose() }
    if ($null -ne $graphics) { $graphics.Dispose() }
    if ($null -ne $iconBitmap) { $iconBitmap.Dispose() }
    if ($null -ne $sourceImage) { $sourceImage.Dispose() }
}
if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
    throw "The blackshard shortcut icon could not be created from $LogoPath."
}
