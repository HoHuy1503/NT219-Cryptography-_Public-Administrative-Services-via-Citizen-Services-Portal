param(
  [string]$OutDir,
  [string]$PfxPassword = $(if ($env:PFX_PASSWORD) { $env:PFX_PASSWORD } else { "changeit" }),
  [string]$OpenSsl = $(if ($env:OPENSSL_BIN) { $env:OPENSSL_BIN } else { "openssl" })
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..\..")
if (-not $OutDir) {
  $OutDir = Join-Path $repoRoot "domain_key\browser_clients"
}

$caDir = Join-Path $OutDir "ca"
$certDir = Join-Path $OutDir "certs"
$pfxDir = Join-Path $OutDir "pfx"
New-Item -ItemType Directory -Force -Path $caDir, $certDir, $pfxDir | Out-Null

function Invoke-OpenSsl {
  & $OpenSsl @args
  if ($LASTEXITCODE -ne 0) {
    throw "openssl failed: $OpenSsl $($args -join ' ')"
  }
}

function New-EcKey([string]$Path) {
  Invoke-OpenSsl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:prime256v1" -out $Path
}

$caKey = Join-Path $caDir "portal-client-ca.key"
$caCrt = Join-Path $caDir "portal-client-ca.crt"
if (-not (Test-Path -LiteralPath $caCrt)) {
  New-EcKey $caKey
  Invoke-OpenSsl req -x509 -new -key $caKey -sha256 -days 3650 `
    -out $caCrt `
    -subj "/CN=GovPortal Browser Client CA/O=GovPortal/OU=public-portals"
}

function New-ClientCert([string]$Name, [string]$CommonName) {
  $key = Join-Path $certDir "$Name.key.pem"
  $csr = Join-Path $certDir "$Name.csr"
  $crt = Join-Path $certDir "$Name.crt.pem"
  $p12 = Join-Path $pfxDir "$Name.p12"
  $ext = New-TemporaryFile
  Set-Content -LiteralPath $ext -Value @"
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:govportal:role:$Name
"@ -NoNewline

  New-EcKey $key
  Invoke-OpenSsl req -new -key $key -out $csr -subj "/CN=$CommonName/O=GovPortal/OU=browser-client"
  Invoke-OpenSsl x509 -req -in $csr `
    -CA $caCrt -CAkey $caKey -CAcreateserial `
    -out $crt -days 825 -sha256 -extfile $ext
  Invoke-OpenSsl pkcs12 -export `
    -inkey $key -in $crt -certfile $caCrt `
    -out $p12 -passout "pass:$PfxPassword" -name $CommonName
  Remove-Item -LiteralPath $csr, $ext -Force
}

New-ClientCert "pki_admin" "pki-admin@pki.gt.tc"
New-ClientCert "thirdparty" "thirdparty-user@thirdparties.gt.tc"
New-ClientCert "officer" "officer@officers.gt.tc"
New-ClientCert "storage_admin" "storage-admin@dbadmin.gt.tc"

Write-Host "[portal-client-certs] Done."
Write-Host "  Trust CA in nginx: $caCrt"
Write-Host "  Import to browser/USB token: $pfxDir\*.p12"
Write-Host "  P12 password: $PfxPassword"
