#!/bin/bash
# DEPLOY/D1/scripts/smoke_test.sh
set -e
PASS=0; FAIL=0
 
check() {
  local name=$1 cmd=$2 expect=$3
  result=$(eval $cmd 2>/dev/null || echo 'ERROR')
  if echo $result | grep -q "$expect"; then
    echo "[PASS] $name"; ((PASS++))
  else
    echo "[FAIL] $name — got: $result"; ((FAIL++))
  fi
}
 
check "Vault healthy" \
  "curl -s http://localhost:8200/v1/sys/health | jq -r .sealed" \
  "false"
 
check "Keycloak realm exists" \
  "curl -s http://localhost:8080/realms/govportal | jq -r .realm" \
  "govportal"
 
check "OPA responds" \
  "curl -s http://localhost:8181/health" \
  "{}"
 
check "Doc-service healthy" \
  "curl -s http://localhost:5000/health | jq -r .status" \
  "ok"
 
check "QR-service healthy" \
  "curl -s http://localhost:5002/health | jq -r .status" \
  "ok"
 
check "Sign document works" \
  "curl -s -X POST http://localhost:5000/api/documents/sign \
    -H 'Content-Type: application/json' \
    -d '{\"document_base64\":\"'$(echo 'test doc' | base64)'\"}' | jq -r .signature | head -c 4" \
  "vault"
 
check "OPA deny cross-user" \
  "curl -s -X POST http://localhost:8181/v1/data/govportal/authz \
    -H 'Content-Type: application/json' \
    -d '{\"input\":{\"user\":{\"role\":\"CITIZEN\",\"id\":\"u1\"},\"action\":\"read\",\"resource\":{\"type\":\"application\",\"owner\":\"u2\"}}}' \
    | jq -r .result.allow" \
  "false"
 
echo ""
echo "=== SMOKE TEST: $PASS pass, $FAIL fail ==="
[ $FAIL -eq 0 ] && echo '✓ ALL PASS — D1 ready!' || exit 1
