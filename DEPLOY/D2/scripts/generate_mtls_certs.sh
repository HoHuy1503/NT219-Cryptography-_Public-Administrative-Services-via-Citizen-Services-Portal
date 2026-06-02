#!/usr/bin/env bash
# Generate dedicated mTLS CA + gateway/service/client certificates (ECDSA P-256).
# Separate from JWT keys, PKI CA, and document-signing keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MTLS_DIR="${1:-$ROOT/state/mtls}"
DAYS="${MTLS_DAYS:-825}"
EC_CURVE="${MTLS_ECDSA_CURVE:-prime256v1}"

mkdir -p "$MTLS_DIR"/{ca,gateway,services,clients}

gen_ec_key() {
  local key_path="$1"
  openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${EC_CURVE}" -out "$key_path"
}

sign_cert() {
  local name="$1"
  local cn="$2"
  local out_dir="$3"
  gen_ec_key "$out_dir/$name.key"
  openssl req -new -key "$out_dir/$name.key" -out "$out_dir/$name.csr" \
    -subj "/CN=$cn/O=GovPortal/OU=mTLS"
  openssl x509 -req -in "$out_dir/$name.csr" \
    -CA "$MTLS_DIR/ca/ca.crt" -CAkey "$MTLS_DIR/ca/ca.key" -CAcreateserial \
    -out "$out_dir/$name.crt" -days "$DAYS" -sha256
  rm -f "$out_dir/$name.csr"
}

if [[ ! -f "$MTLS_DIR/ca/ca.crt" ]]; then
  echo "[mtls] Creating ECDSA (${EC_CURVE}) mTLS CA in $MTLS_DIR"
  gen_ec_key "$MTLS_DIR/ca/ca.key"
  openssl req -x509 -new -nodes -key "$MTLS_DIR/ca/ca.key" -sha256 -days 3650 \
    -out "$MTLS_DIR/ca/ca.crt" -subj "/CN=GovPortal-mTLS-CA/O=GovPortal/OU=mTLS"
  chmod 600 "$MTLS_DIR/ca/ca.key"
fi

sign_cert server gateway.govportal.local "$MTLS_DIR/gateway"
sign_cert client gateway-client "$MTLS_DIR/gateway"
sign_cert storage storage_service.govportal.local "$MTLS_DIR/services"
sign_cert doc doc_service.govportal.local "$MTLS_DIR/services"
sign_cert qr qr_service.govportal.local "$MTLS_DIR/services"
sign_cert api-client api-client "$MTLS_DIR/clients"

chmod 600 "$MTLS_DIR"/gateway/*.key "$MTLS_DIR"/services/*.key "$MTLS_DIR"/clients/*.key

echo "[mtls] Done (ECDSA curve: ${EC_CURVE})."
echo "  CA:              $MTLS_DIR/ca/ca.crt"
echo "  Gateway server:  $MTLS_DIR/gateway/server.crt"
echo "  Gateway client:  $MTLS_DIR/gateway/client.crt"
echo "  API client cert: $MTLS_DIR/clients/api-client.crt (for curl mTLS on :8443)"
echo ""
echo "  Regenerate from scratch: rm -rf $MTLS_DIR && $0"
