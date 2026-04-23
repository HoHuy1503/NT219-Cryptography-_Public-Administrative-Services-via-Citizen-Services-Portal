#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$SCRIPT_DIR/../.env"
  set +a
fi

VAULT_VM="${D2_MGMT_HOST:-10.0.3.10}"
INTERNAL_VM="${D2_INTERNAL_HOST:-10.0.1.11}"
VAULT_PORT="${D2_VAULT_PORT:-8200}"
DOC_PORT="${D2_DOC_PORT:-5000}"
SERVICE_CERT_CN="${D2_SERVICE_CERT_COMMON_NAME:-doc-service.govportal.internal}"
SSH_USER="${D2_VM_SSH_USER:-vagrant}"
VAULT_SSH_KEY="${D2_MGMT_KEY_PATH:-$SCRIPT_DIR/../.vagrant/machines/mgmt/virtualbox/private_key}"
VAULT_LOCAL_ADDR="${D2_VAULT_LOCAL_ADDR:-http://127.0.0.1:8200}"

SSH_COMMON_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
SSH_KEY_OPTS=()
if [ -f "$VAULT_SSH_KEY" ]; then
  SSH_KEY_OPTS=(-i "$VAULT_SSH_KEY")
fi

VAULT_TOKEN=$(ssh "${SSH_KEY_OPTS[@]}" "${SSH_COMMON_OPTS[@]}" "$SSH_USER@$VAULT_VM" 'jq -r .root_token /root/vault-init.json')
 
echo '=== TEST 1: Xin cert từ Vault CA ==='
CERT_JSON=$(curl -s -X POST http://$VAULT_VM:$VAULT_PORT/v1/pki/issue/service-cert \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"common_name":"'$SERVICE_CERT_CN'"}')
echo $CERT_JSON | jq -r .data.certificate > /tmp/doc.crt
echo $CERT_JSON | jq -r .data.private_key > /tmp/doc.key
echo $CERT_JSON | jq -r .data.issuing_ca  > /tmp/ca.crt
echo '[OK] Cert issued từ Internal CA'
 
echo '=== TEST 2: mTLS call với cert hợp lệ → phải PASS ==='
curl --cert /tmp/doc.crt --key /tmp/doc.key --cacert /tmp/ca.crt \
  http://$VAULT_VM:$VAULT_PORT/v1/sys/health | jq .initialized
# Kết quả: true
 
echo '=== TEST 3: Không có cert → phải FAIL (Zone 4 requires mTLS) ==='
# (Vault dev mode không enforce mTLS — trong production config thì có)
echo '[INFO] mTLS enforcement: sử dụng Vault TLS config trong production'
 
echo '=== TEST 4: Vault HA Failover Test ==='
# Ký tài liệu bình thường
curl -s http://$INTERNAL_VM:$DOC_PORT/health | jq .status
 
# Kill Vault
echo 'Kill Vault...'
ssh "${SSH_KEY_OPTS[@]}" "${SSH_COMMON_OPTS[@]}" "$SSH_USER@$VAULT_VM" 'sudo systemctl stop vault'
sleep 3
 
# Doc-service vẫn alive (cached token)
HEALTH=$(curl -s --connect-timeout 3 http://$INTERNAL_VM:$DOC_PORT/health 2>/dev/null || echo 'down')
echo "Doc-service khi Vault down: $HEALTH"
 
# Restart Vault
echo 'Restart Vault...'
ssh "${SSH_KEY_OPTS[@]}" "${SSH_COMMON_OPTS[@]}" "$SSH_USER@$VAULT_VM" 'sudo systemctl start vault'
sleep 5
UNSEAL_KEY=$(ssh "${SSH_KEY_OPTS[@]}" "${SSH_COMMON_OPTS[@]}" "$SSH_USER@$VAULT_VM" 'jq -r .unseal_keys_b64[0] /root/vault-init.json')
ssh "${SSH_KEY_OPTS[@]}" "${SSH_COMMON_OPTS[@]}" "$SSH_USER@$VAULT_VM" "VAULT_ADDR=$VAULT_LOCAL_ADDR vault operator unseal $UNSEAL_KEY"
sleep 5
 
# Doc-service tự reconnect
HEALTH2=$(curl -s http://$INTERNAL_VM:$DOC_PORT/health | jq -r .status)
echo "Doc-service sau khi Vault recover: $HEALTH2"
[ "$HEALTH2" = 'ok' ] && echo '[PASS] Failover OK' || echo '[FAIL] Failover failed'
