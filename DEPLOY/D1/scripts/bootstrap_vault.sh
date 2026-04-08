#!/bin/bash
# DEPLOY/D1/scripts/bootstrap_vault.sh
set -e
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="${VAULT_DEV_TOKEN:-dev-root-token-govportal}"
 
echo "=== [1/5] Bật Transit Secrets Engine ==="
vault secrets enable transit 2>/dev/null || echo '(already enabled)'
 
echo "=== [2/5] Tạo key ký tài liệu (FALCON-512 → ed25519 demo) ==="
vault write -f transit/keys/falcon-doc-signing \
  type=ed25519 exportable=false allow_plaintext_backup=false
 
echo "=== [3/5] Tạo key mã hóa document (AES-256-GCM) ==="
vault write -f transit/keys/doc-encryption \
  type=aes256-gcm96 exportable=false
 
echo "=== [4/5] Bật PKI Engine — Internal CA ==="
vault secrets enable pki 2>/dev/null || echo '(already enabled)'
vault secrets tune -max-lease-ttl=87600h pki
vault write -f pki/root/generate/internal \
  common_name="GovPortal Internal CA" \
  ttl=87600h
vault write pki/config/urls \
  issuing_certificates="http://vault:8200/v1/pki/ca" \
  crl_distribution_points="http://vault:8200/v1/pki/crl"
vault write pki/roles/service-cert \
  allowed_domains="govportal.internal" \
  allow_subdomains=true \
  max_ttl=2160h
 
echo "=== [5/5] Verify ==="
echo 'Transit keys:' && vault list transit/keys
echo 'PKI role:' && vault read -field=max_ttl pki/roles/service-cert
echo '✓ Vault bootstrap hoàn tất!'
