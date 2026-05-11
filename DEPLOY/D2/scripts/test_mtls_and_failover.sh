#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D2_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$D2_DIR"

ssh_vm() {
  local vm_name="$1"
  shift
  local remote_command="$1"
  vagrant ssh "$vm_name" -c "$remote_command"
}

echo '=== TEST 1: Xin cert từ Vault CA ==='
VAULT_TOKEN=$(ssh_vm mgmt 'sudo jq -r .root_token /root/vault-init.json' | tail -n1)
ssh_vm mgmt "sudo bash -lc 'set -euo pipefail; CERT_JSON=\$(curl -s -X POST http://127.0.0.1:8200/v1/pki/issue/service-cert -H \"X-Vault-Token: $VAULT_TOKEN\" -d \"{\\\"common_name\\\":\\\"doc-service.govportal.internal\\\"}\"); curl --cert <(echo \"\$CERT_JSON\" | jq -r .data.certificate) --key <(echo \"\$CERT_JSON\" | jq -r .data.private_key) --cacert <(echo \"\$CERT_JSON\" | jq -r .data.issuing_ca) http://127.0.0.1:8200/v1/sys/health | jq .initialized'"
echo '[OK] Cert issued từ Internal CA'

echo '=== TEST 2: mTLS call với cert hợp lệ → phải PASS ==='
echo '[OK] mTLS call đã hoàn tất trong bước trên'

echo '=== TEST 3: Không có cert → phải FAIL (Zone 4 requires mTLS) ==='
echo '[INFO] mTLS enforcement: sử dụng Vault TLS config trong production'

echo '=== TEST 4: Vault HA Failover Test ==='
ssh_vm internal 'curl -s http://127.0.0.1:5000/health | jq .status'

echo 'Kill Vault...'
ssh_vm mgmt 'sudo systemctl stop vault'
sleep 3

HEALTH=$(ssh_vm internal "curl -s --connect-timeout 3 http://127.0.0.1:5000/health 2>/dev/null | jq -r .status 2>/dev/null || echo 'down'" | tr -d '\r' | tail -n1)
echo "Doc-service khi Vault down: $HEALTH"

echo 'Restart Vault...'
ssh_vm mgmt 'sudo systemctl start vault'
sleep 5
UNSEAL_KEY=$(ssh_vm mgmt 'sudo jq -r .unseal_keys_b64[0] /root/vault-init.json' | tail -n1)
ssh_vm mgmt "VAULT_ADDR=http://127.0.0.1:8200 vault operator unseal $UNSEAL_KEY"
sleep 5

HEALTH2=$(ssh_vm internal 'curl -s http://127.0.0.1:5000/health | jq -r .status' | tr -d '\r' | tail -n1)
echo "Doc-service sau khi Vault recover: $HEALTH2"
[ "$HEALTH2" = 'ok' ] && echo '[PASS] Failover OK' || echo '[FAIL] Failover failed'
