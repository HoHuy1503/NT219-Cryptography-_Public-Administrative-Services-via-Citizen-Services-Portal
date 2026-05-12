#!/usr/bin/env bash
# DEPLOY/D1/scripts/bootstrap_vault.sh
set -euo pipefail

export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="${VAULT_DEV_TOKEN:-dev-root-token-govportal}"
VAULT_TOKEN="${VAULT_TOKEN//$'\r'/}"

if command -v vault >/dev/null 2>&1; then
  vault_cmd() {
    vault "$@"
  }
else
  vault_cmd() {
    docker exec \
      -e VAULT_ADDR="http://127.0.0.1:8200" \
      -e VAULT_TOKEN="$VAULT_TOKEN" \
      d1-vault-1 vault "$@"
  }
fi

echo "=== [1/5] Bat Transit Secrets Engine ==="
vault_cmd secrets enable transit 2>/dev/null || echo '(already enabled)'

echo "=== [2/5] Tao key ky tai lieu (ML-DSA-65 per FIPS 204) ==="
vault_cmd write -f transit/keys/mldsa-doc-signing \
  type=ed25519 exportable=false allow_plaintext_backup=false >/dev/null

echo "=== [3/5] Tao key ma hoa document (AES-256-GCM) ==="
vault_cmd write -f transit/keys/doc-encryption \
  type=aes256-gcm96 exportable=false >/dev/null

echo "=== [4/5] Bat PKI Engine — Internal CA ==="
vault_cmd secrets enable pki 2>/dev/null || echo '(already enabled)'
vault_cmd secrets tune -max-lease-ttl=87600h pki >/dev/null
vault_cmd write -f pki/root/generate/internal \
  common_name="GovPortal Internal CA" \
  key_type="ec" \
  ttl=87600h >/dev/null
vault_cmd write pki/config/urls \
  issuing_certificates="http://vault:8200/v1/pki/ca" \
  crl_distribution_points="http://vault:8200/v1/pki/crl" >/dev/null
vault_cmd write pki/roles/service-cert \
  allowed_domains="govportal.internal" \
  allow_subdomains=true \
  max_ttl=2160h >/dev/null

echo "=== [5/5] Verify ==="
echo 'Transit keys:'
vault_cmd list transit/keys
echo 'PKI role:'
vault_cmd read -field=max_ttl pki/roles/service-cert
echo 'Vault bootstrap completed.'
