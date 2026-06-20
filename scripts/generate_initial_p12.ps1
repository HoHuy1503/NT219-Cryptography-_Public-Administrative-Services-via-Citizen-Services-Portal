param(
  [ValidateSet("officer", "thirdparty")]
  [string]$Role,
  [string]$UserId,
  [string]$DisplayName,
  [string]$Email,
  [string]$Organization = "GovPortal",
  [string]$OrganizationalUnit = "browser-client",
  [string]$Country = "VN",
  [string]$State = "HCM",
  [string]$Locality = "HCM",
  [int]$Days = 825,
  [string]$PfxPassword = "changeit"
)

$ErrorActionPreference = "Stop"

function Read-Default([string]$Prompt, [string]$Default = "") {
  if ($Default) {
    $value = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value.Trim()
  }
  return (Read-Host $Prompt).Trim()
}

function Require-SafeId([string]$Value, [string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Value)) {
    throw "$Name is required"
  }
  if ($Value -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "$Name may only contain letters, numbers, dot, underscore, or dash"
  }
}

if (-not $Role) {
  $Role = Read-Default "Role: officer or thirdparty"
}
if ($Role -notin @("officer", "thirdparty")) {
  throw "Role must be officer or thirdparty"
}

if (-not $UserId) {
  $UserId = Read-Default "User ID"
}
Require-SafeId $UserId "User ID"

if (-not $DisplayName) {
  $DisplayName = Read-Default "Display name / full name" $UserId
}
if (-not $Email) {
  $Email = Read-Default "Email" "$UserId@govportal.local"
}
$Organization = Read-Default "Organization" $Organization
$OrganizationalUnit = Read-Default "Organizational unit" $OrganizationalUnit
$Country = Read-Default "Country code" $Country
$State = Read-Default "State / province" $State
$Locality = Read-Default "Locality" $Locality
$daysInput = Read-Default "Validity days" ([string]$Days)
$Days = [int]$daysInput
$PfxPassword = Read-Default "P12 password" $PfxPassword

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$domainKeyRoot = Join-Path $repoRoot "domain_key"
$caDir = Join-Path $domainKeyRoot "browser_clients\ca"
$caCert = Join-Path $caDir "portal-client-ca.crt"
$caKey = Join-Path $caDir "portal-client-ca.key"

if (-not (Test-Path $caCert)) { throw "Client CA cert not found: $caCert" }
if (-not (Test-Path $caKey)) { throw "Client CA key not found: $caKey" }

$domain = if ($Role -eq "officer") { "officers.hnh2511.xyz" } else { "thirdparties.hnh2511.xyz" }
$outFolderName = if ($Role -eq "officer") { "init_key_officer" } else { "init_key_thirdparty" }
$outRoot = Join-Path $domainKeyRoot $outFolderName
$outDir = Join-Path $outRoot $UserId
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$keyPath = Join-Path $outDir "$UserId.key.pem"
$csrPath = Join-Path $outDir "$UserId.csr.pem"
$certPath = Join-Path $outDir "$UserId.crt.pem"
$pubPath = Join-Path $outDir "$UserId.pub.pem"
$p12Path = Join-Path $outDir "$UserId.p12"
$extPath = Join-Path $outDir "$UserId.ext"
$metaPath = Join-Path $outDir "$UserId.metadata.txt"

$cn = "$UserId@$domain"
$subject = "/C=$Country/ST=$State/L=$Locality/O=$Organization/OU=$OrganizationalUnit/CN=$cn"

$sanParts = @("email:$Email", "URI:govportal:${Role}:${UserId}")
$san = $sanParts -join ","
@"
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=$san
"@ | Set-Content -Path $extPath -Encoding ascii

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out $keyPath
openssl req -new -key $keyPath -out $csrPath -subj $subject
openssl x509 -req -in $csrPath -CA $caCert -CAkey $caKey -CAcreateserial -days $Days -sha256 -extfile $extPath -out $certPath
openssl pkey -in $keyPath -pubout -out $pubPath
openssl pkcs12 -export -inkey $keyPath -in $certPath -certfile $caCert -out $p12Path -passout "pass:$PfxPassword" -name $UserId

$fingerprint = (& openssl x509 -in $certPath -noout -fingerprint -sha256) -join "`n"
@"
role=$Role
user_id=$UserId
display_name=$DisplayName
email=$Email
domain=$domain
subject=$subject
cn=$cn
organization=$Organization
organizational_unit=$OrganizationalUnit
country=$Country
state=$State
locality=$Locality
days=$Days
p12_password=$PfxPassword
$fingerprint
"@ | Set-Content -Path $metaPath -Encoding utf8

Write-Host ""
Write-Host "Generated initial browser mTLS P12:"
Write-Host "  $p12Path"
Write-Host ""
Write-Host "Artifacts:"
Write-Host "  Private key: $keyPath"
Write-Host "  Public key : $pubPath"
Write-Host "  Cert       : $certPath"
Write-Host "  Metadata   : $metaPath"
Write-Host ""
Write-Host "Import command:"
Write-Host "  certutil -user -p $PfxPassword -importpfx `"$p12Path`" NoExport"
