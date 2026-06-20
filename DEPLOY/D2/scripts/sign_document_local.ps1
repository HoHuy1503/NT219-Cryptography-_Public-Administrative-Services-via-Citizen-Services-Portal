param(
  [string]$DocumentPath,
  [string]$EncryptedPrivateKeyPath,
  [int]$KdfIterations = 600000,
  [string]$OpenSsl = "openssl"
)

$ErrorActionPreference = "Stop"

if (-not $DocumentPath) {
  $DocumentPath = Read-Host "Document path to sign"
}
if (-not $EncryptedPrivateKeyPath) {
  $EncryptedPrivateKeyPath = Read-Host "Encrypted ML-DSA private key path"
}
if (-not (Test-Path $DocumentPath)) {
  throw "Document not found: $DocumentPath"
}
if (-not (Test-Path $EncryptedPrivateKeyPath)) {
  throw "Encrypted private key not found: $EncryptedPrivateKeyPath"
}

$securePassword = Read-Host "Password to decrypt ML-DSA signing key" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$tempKey = Join-Path ([IO.Path]::GetTempPath()) ("govportal-signing-key-{0}.pem" -f [guid]::NewGuid().ToString("N"))
$tempEncryptedKey = $null
$signaturePath = Join-Path (Split-Path -Parent $DocumentPath) ((Split-Path -Leaf $DocumentPath) + ".sig.b64")

try {
  $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  if (-not $password) { throw "Password is required" }

  $encryptedInput = $EncryptedPrivateKeyPath
  if ($EncryptedPrivateKeyPath.ToLowerInvariant().EndsWith(".b64")) {
    $tempEncryptedKey = Join-Path ([IO.Path]::GetTempPath()) ("govportal-encrypted-key-{0}.enc" -f [guid]::NewGuid().ToString("N"))
    [IO.File]::WriteAllBytes($tempEncryptedKey, [Convert]::FromBase64String((Get-Content -Raw $EncryptedPrivateKeyPath).Trim()))
    $encryptedInput = $tempEncryptedKey
  }

  & $OpenSsl enc -d -aes-256-cbc -pbkdf2 -iter $KdfIterations -md sha256 -in $encryptedInput -out $tempKey -pass "pass:$password"

  $signatureRaw = Join-Path ([IO.Path]::GetTempPath()) ("govportal-signature-{0}.bin" -f [guid]::NewGuid().ToString("N"))
  try {
    & $OpenSsl pkeyutl -sign -rawin -inkey $tempKey -in $DocumentPath -out $signatureRaw
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($signatureRaw)) | Set-Content -Path $signaturePath -Encoding ascii
  }
  finally {
    if (Test-Path $signatureRaw) { Remove-Item -Force $signatureRaw }
  }
}
finally {
  if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  if ($tempEncryptedKey -and (Test-Path $tempEncryptedKey)) { Remove-Item -Force $tempEncryptedKey }
  if (Test-Path $tempKey) { Remove-Item -Force $tempKey }
}

Write-Host "Detached signature base64 written to:"
Write-Host "  $signaturePath"
Write-Host ""
Write-Host "Paste the file content into the officer portal when completing the signing request."
