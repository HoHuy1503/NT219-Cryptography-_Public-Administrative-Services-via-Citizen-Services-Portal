#!/bin/bash
# EVAL/E-X/run_e_x1.sh
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN="${VAULT_DEV_TOKEN:-dev-root-token-govportal}"
echo '=== E-X1: Key Rotation SLA Test (I6) ==='

vault_cmd() {
	if command -v vault >/dev/null 2>&1; then
		vault "$@"
	else
		docker exec -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="$VAULT_TOKEN" d1-vault-1 vault "$@"
	fi
}
 
OLD=$(vault_cmd read -field=latest_version transit/keys/falcon-doc-signing)
echo "Phiên bản hiện tại: $OLD"
START=$(date +%s)
 
vault_cmd write -f transit/keys/falcon-doc-signing/rotate
 
NEW=$(vault_cmd read -field=latest_version transit/keys/falcon-doc-signing)
END=$(date +%s)
ELAPSED=$((END-START))
 
echo "Phiên bản mới: $NEW | Thời gian: ${ELAPSED}s (threshold ≤600s)"
STATUS='PASS'; [ $ELAPSED -gt 600 ] && STATUS='FAIL'
echo "E-X1: $STATUS (I6)"
 
# Kiểm tra key cũ vẫn dùng decrypt được (không break backward compat)
echo 'Key cũ vẫn available cho decrypt: '
vault_cmd read -field=min_decryption_version transit/keys/falcon-doc-signing
 
cat > EVAL/E-X/E-X1-result.json << EOF
{"eval_id":"E-X1","invariant":"I6",
 "rotation_seconds":$ELAPSED,"old_version":$OLD,"new_version":$NEW,
 "status":"$STATUS","threshold":"600s"}
EOF
