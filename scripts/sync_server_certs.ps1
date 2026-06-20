param(
  [string]$Server = "20.205.109.23",
  [string]$User = "azureuser",
  [string]$KeyPath = "C:\Users\Admin\Documents\azurekey\govportal_key.pem",
  [string]$RemoteProjectRoot = "/opt/govportal",
  [string]$CertificateName = "citizens.hnh2511.xyz",
  [string]$DestinationRoot = "",
  [switch]$OpenAfterSync,
  [switch]$Snapshot
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Require-Command($Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Required command not found: $Name"
  }
}

Require-Command ssh
Require-Command scp
Require-Command tar

if (-not (Test-Path -LiteralPath $KeyPath)) {
  throw "SSH private key not found: $KeyPath"
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if (-not $DestinationRoot) {
  $DestinationRoot = Join-Path $RepoRoot "domain_key"
}

if ($Snapshot) {
  $Destination = Join-Path (Join-Path $DestinationRoot "server_sync") $Timestamp
} else {
  $Destination = $DestinationRoot
}

$Archive = Join-Path $env:TEMP "govportal-server-sync-$Timestamp.tgz"
$ExtractRoot = Join-Path $env:TEMP "govportal-server-sync-extract-$Timestamp"

New-Item -ItemType Directory -Force -Path $Destination | Out-Null
New-Item -ItemType Directory -Force -Path $ExtractRoot | Out-Null

$Remote = "$User@$Server"
$RemoteArchive = "/tmp/govportal-server-sync-$Timestamp.tgz"

Write-Host "Syncing from $Remote"
Write-Host "Destination: $Destination"

$RemoteCommand = @"
set -eu
sudo tar -C / --dereference -czf '$RemoteArchive' \
  'etc/letsencrypt/live/$CertificateName' \
  'etc/letsencrypt/renewal/$CertificateName.conf' \
  'etc/nginx/sites-enabled/govportal' \
  'opt/govportal/domain_key/browser_clients'
sudo chown "`$(id -u):`$(id -g)" '$RemoteArchive'
"@

ssh -i $KeyPath $Remote $RemoteCommand
scp -i $KeyPath "${Remote}:$RemoteArchive" $Archive
ssh -i $KeyPath $Remote "rm -f '$RemoteArchive'"

tar -xzf $Archive -C $ExtractRoot

if ($Snapshot) {
  Get-ChildItem -LiteralPath $ExtractRoot -Force | Move-Item -Destination $Destination
} else {
  $LetsEncryptSource = Join-Path $ExtractRoot "etc\letsencrypt"
  $NginxSource = Join-Path $ExtractRoot "etc\nginx"
  $BrowserClientsSource = Join-Path $ExtractRoot "opt\govportal\domain_key\browser_clients"

  $LetsEncryptDestination = Join-Path $Destination "letsencrypt"
  $NginxDestination = Join-Path $Destination "nginx"
  $BrowserClientsDestination = Join-Path $Destination "browser_clients"

  foreach ($Path in @($LetsEncryptDestination, $NginxDestination, $BrowserClientsDestination)) {
    if (Test-Path -LiteralPath $Path) {
      Remove-Item -LiteralPath $Path -Force -Recurse
    }
  }

  Copy-Item -LiteralPath $LetsEncryptSource -Destination $LetsEncryptDestination -Recurse
  Copy-Item -LiteralPath $NginxSource -Destination $NginxDestination -Recurse
  Copy-Item -LiteralPath $BrowserClientsSource -Destination $BrowserClientsDestination -Recurse
}

Remove-Item -LiteralPath $Archive -Force
Remove-Item -LiteralPath $ExtractRoot -Force -Recurse

$ManifestPath = Join-Path $Destination "MANIFEST.txt"
@(
  "Synced at: $(Get-Date -Format s)"
  "Server: $Remote"
  "Certificate: $CertificateName"
  ""
  "Public HTTPS cert/key:"
  "  letsencrypt/live/$CertificateName/fullchain.pem"
  "  letsencrypt/live/$CertificateName/privkey.pem"
  ""
  "mTLS browser client material:"
  "  browser_clients/"
  ""
  "Nginx config:"
  "  nginx/sites-enabled/govportal"
) | Set-Content -LiteralPath $ManifestPath -Encoding UTF8

Write-Host ""
Write-Host "Done."
Write-Host "Snapshot: $Destination"
Write-Host "Manifest: $ManifestPath"
Write-Host ""
Write-Host "Private key copied locally:"
Write-Host "  $(Join-Path $Destination "letsencrypt\live\$CertificateName\privkey.pem")"

if ($OpenAfterSync) {
  Invoke-Item $Destination
}
