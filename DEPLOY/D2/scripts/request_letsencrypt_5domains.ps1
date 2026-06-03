param(
  [string]$Email = "admin@gt.tc",
  [switch]$Staging
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..\..")
$leRoot = Join-Path $repoRoot "domain_key\letsencrypt-5domains"
$etcDir = Join-Path $leRoot "etc"
$libDir = Join-Path $leRoot "lib"
$logDir = Join-Path $leRoot "log"

New-Item -ItemType Directory -Force -Path $etcDir, $libDir, $logDir | Out-Null

$domains = @(
  "citizens.gt.tc",
  "dbadmin.gt.tc",
  "thirdparties.gt.tc",
  "pki.gt.tc",
  "officers.gt.tc"
)

$certbotArgs = @(
  "certonly",
  "--standalone",
  "--non-interactive",
  "--agree-tos",
  "--email", $Email,
  "--key-type", "ecdsa",
  "--cert-name", "govportal-gt-tc-5domains"
)

if ($Staging) {
  $certbotArgs += "--staging"
}

foreach ($domain in $domains) {
  $certbotArgs += @("-d", $domain)
}

Write-Host "Requesting Let's Encrypt certificate for:"
$domains | ForEach-Object { Write-Host "  - $_" }
Write-Host ""
Write-Host "Requirements:"
Write-Host "  - All five domains must resolve to this machine."
Write-Host "  - Public TCP port 80 must be reachable."
Write-Host "  - Stop any service currently using local port 80 before running this script."
Write-Host ""
Write-Host "Output after success:"
Write-Host "  $etcDir\live\govportal-gt-tc-5domains\fullchain.pem"
Write-Host "  $etcDir\live\govportal-gt-tc-5domains\privkey.pem"
Write-Host ""

docker run --rm -it `
  -p 80:80 `
  -v "${etcDir}:/etc/letsencrypt" `
  -v "${libDir}:/var/lib/letsencrypt" `
  -v "${logDir}:/var/log/letsencrypt" `
  certbot/certbot @certbotArgs
