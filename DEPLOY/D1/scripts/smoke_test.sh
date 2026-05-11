#!/bin/bash
# DEPLOY/D1/scripts/smoke_test.sh
set -euo pipefail

PASS=0
FAIL=0

pass() {
  echo "[PASS] $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "[FAIL] $1"
  FAIL=$((FAIL + 1))
}

vault_sealed=$(curl -s http://localhost:8200/v1/sys/health | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("sealed", "")).lower())' 2>/dev/null || echo "")
[ "$vault_sealed" = "false" ] && pass "Vault healthy" || fail "Vault healthy — got: $vault_sealed"

realm_name=$(curl -s http://localhost:8080/realms/govportal | python3 -c 'import json,sys; print(json.load(sys.stdin).get("realm", ""))' 2>/dev/null || echo "")
[ "$realm_name" = "govportal" ] && pass "Keycloak realm exists" || fail "Keycloak realm exists — got: $realm_name"

opa_health=$(curl -s http://localhost:8181/health 2>/dev/null || echo "")
[ "$opa_health" = "{}" ] && pass "OPA responds" || fail "OPA responds — got: $opa_health"

doc_health=$(curl -s http://localhost:5000/health | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", ""))' 2>/dev/null || echo "")
[ "$doc_health" = "ok" ] && pass "Doc-service healthy" || fail "Doc-service healthy — got: $doc_health"

qr_health=$(curl -s http://localhost:5002/health | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", ""))' 2>/dev/null || echo "")
[ "$qr_health" = "ok" ] && pass "QR-service healthy" || fail "QR-service healthy — got: $qr_health"

sign_sig=$(curl -s -X POST http://localhost:5000/api/documents/sign \
  -H "Content-Type: application/json" \
  -H "X-Internal-Bypass: true" \
  -d "{\"document_base64\":\"$(echo 'test doc' | base64 | tr -d '\n')\"}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("signature", ""))' 2>/dev/null || echo "")
[ -n "$sign_sig" ] && pass "Sign document works" || fail "Sign document works — got: $sign_sig"

opa_allow=$(curl -s -X POST http://localhost:8181/v1/data/govportal/authz \
  -H "Content-Type: application/json" \
  -d '{"input":{"user":{"role":"CITIZEN","id":"u1"},"action":"read","resource":{"type":"application","owner":"u2"}}}' \
  | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("result",{}).get("allow", "")).lower())' 2>/dev/null || echo "")
[ "$opa_allow" = "false" ] && pass "OPA deny cross-user" || fail "OPA deny cross-user — got: $opa_allow"

echo ""
echo "=== SMOKE TEST: $PASS pass, $FAIL fail ==="
if [ "$FAIL" -eq 0 ]; then
  echo "All checks passed. D1 ready."
else
  exit 1
fi
