#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$SkipBootConfiguration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverPath = Join-Path $PSScriptRoot "blackshard.sys"
if (-not (Test-Path -LiteralPath $driverPath)) {
    throw "blackshard.sys was not found beside this script."
}

$subject = "CN=blackshard development test"
# Anything left in LocalMachine\My under this subject is a signing key from an earlier run of an
# older copy of this script, which kept its key. Any administrator, or malware running as one,
# could use it to sign code this machine trusts as a root, so it goes.
Get-ChildItem -LiteralPath "Cert:\LocalMachine\My" |
    Where-Object Subject -eq $subject |
    ForEach-Object { Remove-Item -LiteralPath $_.PSPath -DeleteKey }

# A fresh certificate every run, whose private key exists only until blackshard.sys is signed.
# Only its public half stays, in Root and TrustedPublisher, where it can verify but never sign.
$certificate = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $subject `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

try {
    $publicCertificatePath = Join-Path $PSScriptRoot "blackshard-test.cer"
    Export-Certificate -Cert $certificate -FilePath $publicCertificatePath -Force | Out-Null

    $certutil = Join-Path $env:SystemRoot "System32\certutil.exe"
    foreach ($store in @("Root", "TrustedPublisher")) {
        $output = & $certutil -f -addstore $store $publicCertificatePath 2>&1
        $exitCode = $LASTEXITCODE
        $output | Out-Host
        if ($exitCode -ne 0) {
            throw "Windows could not trust the blackshard development certificate in LocalMachine\$store (certutil exit code $exitCode)."
        }
        $trusted = Get-ChildItem -LiteralPath "Cert:\LocalMachine\$store" |
            Where-Object Thumbprint -eq $certificate.Thumbprint |
            Select-Object -First 1
        if (-not $trusted) {
            throw "The blackshard development certificate is absent from LocalMachine\$store after certutil reported success."
        }
        if ($trusted.HasPrivateKey) {
            throw "The blackshard development certificate in LocalMachine\$store carries its private key."
        }
    }

    Write-Host "[*] Test-signing blackshard.sys..." -ForegroundColor Cyan
    $signature = Set-AuthenticodeSignature `
        -LiteralPath $driverPath `
        -Certificate $certificate `
        -HashAlgorithm SHA256 `
        -IncludeChain All
    if ($signature.Status -ne "Valid") {
        throw "The driver signature could not be validated after signing: $($signature.Status)"
    }
}
finally {
    Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($certificate.Thumbprint)" -DeleteKey
}

Write-Host "[+] Driver signed for development testing." -ForegroundColor Green
if (-not $SkipBootConfiguration) {
    Write-Host "[*] Enabling Windows test-signing mode..." -ForegroundColor Yellow
    & bcdedit.exe /set testsigning on | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Windows could not enable test-signing. Disable Secure Boot in this disposable VM and retry."
    }
    Write-Host "Restart the VM, then run install.ps1 as Administrator." -ForegroundColor Yellow
}
