param(
  [string]$MtlsDir,
  [string]$OpenSsl = $(if ($env:OPENSSL_BIN) { $env:OPENSSL_BIN } else { "openssl" })
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$d2Root = Resolve-Path (Join-Path $scriptDir "..")
if (-not $MtlsDir) {
  $MtlsDir = Join-Path $d2Root "state\mtls"
}

$caDir = Join-Path $MtlsDir "ca"
$gatewayDir = Join-Path $MtlsDir "gateway"
$servicesDir = Join-Path $MtlsDir "services"
$clientsDir = Join-Path $MtlsDir "clients"
New-Item -ItemType Directory -Force -Path $caDir, $gatewayDir, $servicesDir, $clientsDir | Out-Null

function Invoke-OpenSsl {
  & $OpenSsl @args
  if ($LASTEXITCODE -ne 0) {
    throw "openssl failed: $OpenSsl $($args -join ' ')"
  }
}

function New-MlDsaKey([string]$Path) {
  Invoke-OpenSsl genpkey -algorithm "ML-DSA-44" -out $Path
}

$caKey = Join-Path $caDir "ca.key"
$caCrt = Join-Path $caDir "ca.crt"
New-MlDsaKey $caKey
Invoke-OpenSsl req -x509 -new -key $caKey -days 3650 `
  -out $caCrt `
  -subj "/CN=GovPortal-MLDSA-mTLS-CA/O=GovPortal/OU=internal-mtls" `
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" `
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

function New-ServiceCert([string]$Name, [string]$CommonName, [string]$San, [string]$OutDir) {
  $key = Join-Path $OutDir "$Name.key"
  $csr = Join-Path $OutDir "$Name.csr"
  $crt = Join-Path $OutDir "$Name.crt"
  $ext = New-TemporaryFile
  Set-Content -LiteralPath $ext -Value @"
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:$CommonName,DNS:$San
"@ -NoNewline
  New-MlDsaKey $key
  Invoke-OpenSsl req -new -key $key -out $csr -subj "/CN=$CommonName/O=GovPortal/OU=internal-mtls"
  Invoke-OpenSsl x509 -req -in $csr `
    -CA $caCrt -CAkey $caKey -CAcreateserial `
    -out $crt -days 825 -extfile $ext
  Remove-Item -LiteralPath $csr, $ext -Force
}

New-ServiceCert "server" "gateway.govportal.local" "gateway" $gatewayDir
New-ServiceCert "client" "gateway-client" "gateway-client" $gatewayDir
New-ServiceCert "storage" "storage_service.govportal.local" "storage_service" $servicesDir
New-ServiceCert "doc" "doc_service.govportal.local" "doc_service" $servicesDir
New-ServiceCert "qr" "qr_service.govportal.local" "qr_service" $servicesDir
New-ServiceCert "api-client" "api-client" "api-client" $clientsDir

Write-Host "[mldsa-mtls] Done."
Write-Host "  CA: $caCrt"
Write-Host "  Gateway server: $(Join-Path $gatewayDir 'server.crt')"
Write-Host "  Services: $servicesDir\*.crt"
