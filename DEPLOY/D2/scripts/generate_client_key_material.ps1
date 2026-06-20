param(
  [ValidateSet("officer", "thirdparty")]
  [string]$Role,
  [string]$UserId,
  [switch]$BusinessSigningKey,
  [int]$KdfIterations = 600000,
  [string]$OpenSsl = "openssl"
)

$ErrorActionPreference = "Stop"

if (-not $Role) {
  $Role = Read-Host "Role (officer/thirdparty)"
}
if (-not $UserId) {
  $UserId = Read-Host "User id"
}
if (-not $UserId) {
  throw "UserId is required"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$safeUserId = $UserId -replace '[^A-Za-z0-9_.-]', '_'
$outDir = Join-Path $repoRoot "domain_key\client_private\$Role\$safeUserId"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$mtlsPrivate = Join-Path $outDir "mtls_private.pem"
$mtlsPublic = Join-Path $outDir "mtls_public.pem"

& $OpenSsl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out $mtlsPrivate
& $OpenSsl pkey -in $mtlsPrivate -pubout -out $mtlsPublic

$businessNotes = @"
Business signing:
  Not generated for this role/run.
"@

if ($Role -eq "officer" -and $BusinessSigningKey) {
  $signingPrivate = Join-Path $outDir "business_signing_private.cleartext.tmp.pem"
  $signingPublic = Join-Path $outDir "business_signing_public.pem"
  $signingCsr = Join-Path $outDir "business_signing.csr.pem"
  $encryptedPrivate = Join-Path $outDir "business_signing_private.pem.enc"
  $encryptedPrivateB64 = Join-Path $outDir "business_signing_private.pem.enc.b64"
  $kdfJson = Join-Path $outDir "business_signing_kdf.json"

  $securePassword = Read-Host "Password to encrypt ML-DSA signing key" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
  try {
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if (-not $password) { throw "Password is required" }

    & $OpenSsl genpkey -algorithm ML-DSA-44 -out $signingPrivate
    & $OpenSsl pkey -in $signingPrivate -pubout -out $signingPublic
    & $OpenSsl req -new -key $signingPrivate -out $signingCsr -subj "/C=VN/O=OFFICER/OU=GovPortal/CN=$UserId"
    & $OpenSsl enc -aes-256-cbc -pbkdf2 -iter $KdfIterations -md sha256 -salt -in $signingPrivate -out $encryptedPrivate -pass "pass:$password"
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($encryptedPrivate)) | Set-Content -Path $encryptedPrivateB64 -Encoding ascii

    @{
      kdf = "PBKDF2"
      digest = "sha256"
      iterations = $KdfIterations
      cipher = "aes-256-cbc"
      salt = "embedded-openssl-salted-format"
      format = "openssl-enc"
    } | ConvertTo-Json | Set-Content -Path $kdfJson -Encoding ascii
  }
  finally {
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if (Test-Path $signingPrivate) { Remove-Item -Force $signingPrivate }
  }

  $businessNotes = @"
Business signing:
  business_signing_public.pem:
    Public key ML-DSA de PKI quan ly va cap cert signing.

  business_signing.csr.pem:
    CSR gui len server de PKI ky cert signing.

  business_signing_private.pem.enc:
    Private key ML-DSA da ma hoa bang password + PBKDF2. Server chi duoc luu file ma hoa nay.

  business_signing_private.pem.enc.b64:
    Noi dung base64 cua file ma hoa, dung de gui qua API PKI.

  business_signing_kdf.json:
    Tham so KDF/cipher can gui kem khi nap key vao PKI.
"@
}

$readme = Join-Path $outDir "README.txt"
@"
Role=$Role
UserId=$UserId

mtls_private.pem:
  Private key EC dung de dong goi .p12 sau khi PKI cap cert mTLS.
  Day KHONG PHAI key ky tai lieu.

mtls_public.pem:
  Dan noi dung file nay vao form dang ky truong public key truy cap.

$businessNotes
"@ | Set-Content -Path $readme -Encoding utf8

Write-Host "Created client key material:"
Write-Host "  $outDir"
Write-Host ""
Write-Host "Paste this mTLS public key into the portal:"
Write-Host "  $mtlsPublic"
if ($Role -eq "officer" -and $BusinessSigningKey) {
  Write-Host ""
  Write-Host "Send these encrypted signing-key files to PKI:"
  Write-Host "  $(Join-Path $outDir 'business_signing_public.pem')"
  Write-Host "  $(Join-Path $outDir 'business_signing.csr.pem')"
  Write-Host "  $(Join-Path $outDir 'business_signing_private.pem.enc')"
  Write-Host "  $(Join-Path $outDir 'business_signing_private.pem.enc.b64')"
  Write-Host "  $(Join-Path $outDir 'business_signing_kdf.json')"
}
