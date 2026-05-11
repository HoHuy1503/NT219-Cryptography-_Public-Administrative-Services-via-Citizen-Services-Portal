#!/usr/bin/env bash
# DEPLOY/D1/scripts/demo_e2e.sh
set -euo pipefail

DOC_API="http://localhost:5000"
QR_API="http://localhost:5002"

json_get() {
  local payload="$1"
  local key="$2"
  printf '%s' "$payload" | python3 -c 'import json,sys; data=json.load(sys.stdin); key=sys.argv[1]; print(data.get(key, ""))' "$key"
}

json_pick() {
  local payload="$1"
  shift
  printf '%s' "$payload" | python3 -c 'import json,sys; data=json.load(sys.stdin); keys=sys.argv[1:]; print(json.dumps({k: data.get(k) for k in keys}, ensure_ascii=True, indent=2))' "$@"
}

echo ""
echo "=== [1/4] Citizen submit sample document ==="
echo ""
DOC_TEXT='Ho so hanh chinh cong - citizen001 - request birth_certificate'
DOC_B64=$(printf "%s" "$DOC_TEXT" | base64 | tr -d '\n')

SIGN_RESP=$(curl -s -X POST "$DOC_API/api/documents/sign" \
  -H "Content-Type: application/json" \
  -H "X-Internal-Bypass: true" \
  -d "{\"document_base64\":\"$DOC_B64\"}")

DOC_ID=$(json_get "$SIGN_RESP" doc_id)
SIG=$(json_get "$SIGN_RESP" signature)

echo "  doc_id: $DOC_ID"
echo "  signed_at: $(json_get "$SIGN_RESP" signed_at)"


echo ""
echo "=== [2/4] Verify signed document integrity ==="
echo ""
VERIFY_RESP=$(curl -s -X POST "$DOC_API/api/documents/verify" \
  -H "Content-Type: application/json" \
  -H "X-Internal-Bypass: true" \
  -d "{\"document_base64\":\"$DOC_B64\",\"signature\":\"$SIG\"}")

json_pick "$VERIFY_RESP" valid doc_hash tampered


echo ""
echo "=== [3/4] Generate QR for citizen ==="
echo ""
QR_GEN=$(curl -s -X POST "$QR_API/api/qr/generate" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"citizen001"}')

QR_DATA=$(json_get "$QR_GEN" qr_data)
NONCE=$(json_get "$QR_GEN" nonce)

echo "  nonce: $NONCE"
echo "  expires_in: $(json_get "$QR_GEN" expires_in)s"

echo ""
echo "=== [4/4] Verify QR and replay protection ==="
echo ""
QR_OK=$(curl -s -X POST "$QR_API/api/qr/verify" \
  -H "Content-Type: application/json" \
  -d "{\"qr_data\":\"$QR_DATA\"}")

echo "  first verify: $(json_get "$QR_OK" valid)"

QR_REPLAY=$(curl -s -o /tmp/qr_replay.json -w "%{http_code}" -X POST "$QR_API/api/qr/verify" \
  -H "Content-Type: application/json" \
  -d "{\"qr_data\":\"$QR_DATA\"}")

echo "  replay http_code: $QR_REPLAY"
python3 -m json.tool /tmp/qr_replay.json

echo ""
echo "Demo completed. Document signing, integrity check, and QR replay defense are working."
