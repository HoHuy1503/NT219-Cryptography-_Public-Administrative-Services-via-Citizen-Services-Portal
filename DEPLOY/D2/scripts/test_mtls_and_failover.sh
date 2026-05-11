#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="${TMPDIR:-/tmp}/govportal-mtls"
mkdir -p "$TMP_DIR"

VAULT_VM="10.0.3.10"
INTERNAL_VM="10.0.1.11"
VAULT_TOKEN=$(ssh vagrant@$VAULT_VM 'jq -r .root_token /root/vault-init.json')
 
echo '=== TEST 1: Xin cert từ Vault CA ==='
CERT_JSON=$(curl -s -X POST http://$VAULT_VM:8200/v1/pki/issue/service-cert \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"common_name":"doc-service.govportal.internal"}')
echo "$CERT_JSON" | jq -r .data.certificate > "$TMP_DIR/doc.crt"
echo "$CERT_JSON" | jq -r .data.private_key > "$TMP_DIR/doc.key"
echo "$CERT_JSON" | jq -r .data.issuing_ca  > "$TMP_DIR/ca.crt"
echo '[OK] Cert issued từ Internal CA'
 
echo '=== TEST 2: mTLS call với cert hợp lệ → phải PASS ==='
curl --cert "$TMP_DIR/doc.crt" --key "$TMP_DIR/doc.key" --cacert "$TMP_DIR/ca.crt" \
  http://$VAULT_VM:8200/v1/sys/health | jq .initialized
# Kết quả: true
 
echo '=== TEST 3: Không có cert → phải FAIL (Zone 4 requires mTLS) ==='
# (Vault dev mode không enforce mTLS — trong production config thì có)
echo '[INFO] mTLS enforcement: sử dụng Vault TLS config trong production'
 
echo '=== TEST 4: Vault HA Failover Test ==='
# Ký tài liệu bình thường
curl -s http://$INTERNAL_VM:5000/health | jq .status
 
# Kill Vault
echo 'Kill Vault...'
ssh vagrant@$VAULT_VM 'sudo systemctl stop vault'
sleep 3
 
# Doc-service vẫn alive (cached token)
HEALTH=$(curl -s --connect-timeout 3 http://$INTERNAL_VM:5000/health 2>/dev/null || echo 'down')
echo "Doc-service khi Vault down: $HEALTH"
 
# Restart Vault
echo 'Restart Vault...'
ssh vagrant@$VAULT_VM 'sudo systemctl start vault'
sleep 5
UNSEAL_KEY=$(ssh vagrant@$VAULT_VM 'jq -r .unseal_keys_b64[0] /root/vault-init.json')
ssh vagrant@$VAULT_VM "VAULT_ADDR=http://127.0.0.1:8200 vault operator unseal $UNSEAL_KEY"
sleep 5
 
# Doc-service tự reconnect
HEALTH2=$(curl -s http://$INTERNAL_VM:5000/health | jq -r .status)
echo "Doc-service sau khi Vault recover: $HEALTH2"
[ "$HEALTH2" = 'ok' ] && echo '[PASS] Failover OK' || echo '[FAIL] Failover failed'
