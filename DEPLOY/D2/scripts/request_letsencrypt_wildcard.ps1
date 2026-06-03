param(
  [string]$Email = "admin@gt.tc",
  [string]$Domain = "gt.tc"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..\..")
$leRoot = Join-Path $repoRoot "domain_key\letsencrypt"
$etcDir = Join-Path $leRoot "etc"
$libDir = Join-Path $leRoot "lib"
$logDir = Join-Path $leRoot "log"

New-Item -ItemType Directory -Force -Path $etcDir, $libDir, $logDir | Out-Null

Write-Host "Requesting Let's Encrypt wildcard certificate for *.$Domain and $Domain"
Write-Host "Certbot will print a DNS TXT value for: _acme-challenge.$Domain"
Write-Host "Create that TXT record in your DNS, wait until it resolves, then press Enter in Certbot."
Write-Host ""
Write-Host "Output after success:"
Write-Host "  $etcDir\live\$Domain\fullchain.pem"
Write-Host "  $etcDir\live\$Domain\privkey.pem"
Write-Host ""

docker run --rm -it `
  -v "${etcDir}:/etc/letsencrypt" `
  -v "${libDir}:/var/lib/letsencrypt" `
  -v "${logDir}:/var/log/letsencrypt" `
  certbot/certbot certonly `
    --manual `
    --preferred-challenges dns `
    --manual-public-ip-logging-ok `
    --agree-tos `
    --email $Email `
    --key-type ecdsa `
    -d "*.$Domain" `
    -d "$Domain"
