param(
    [string]$ExePath = "..\x64\Release\zipHashGUI.exe",
    [string]$CertSubject = "CN=ZipHash Test",
    [switch]$InstallTrusted
)

if (-not (Test-Path $ExePath)) {
    Write-Error "Executable not found at $ExePath"
    exit 1
}

Write-Host "Creating a self-signed Code Signing certificate (current user) with subject: $CertSubject"
$cert = New-SelfSignedCertificate -Subject $CertSubject -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)
if (-not $cert) { Write-Error "Certificate creation failed"; exit 1 }

$pfx = Join-Path $env:TEMP "ziphash_sign.pfx"
$pwd = ConvertTo-SecureString -String "password" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd | Out-Null

Write-Host "Signing $ExePath with the new certificate..."
Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert -HashAlgorithm sha256 | Format-List | Out-Host

if ($InstallTrusted) {
    Write-Host "Installing certificate to CurrentUser TrustedPublisher and TrustedPeople stores (requires elevation)..."
    $cer = Join-Path $env:TEMP "ziphash_sign.cer"
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null

    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\CurrentUser\TrustedPublisher | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null

    Write-Host "Certificate installed to TrustedPublisher and TrustedPeople (current user)."
    Write-Host "Smart App Control may still block programs unless the certificate is trusted by the system policies."
}

Write-Host "Signing complete."
Write-Host "Note: This creates a self-signed test certificate. For production, sign with a certificate from a trusted CA (EV/Code Signing)."
