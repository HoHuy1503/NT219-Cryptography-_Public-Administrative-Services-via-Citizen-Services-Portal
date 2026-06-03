#!/usr/bin/env bash
# Generate an internal mTLS CA and service certificates with ML-DSA-44.
#
# Warning: these certificates require TLS software linked against OpenSSL 3.6+
# with ML-DSA support. The stock nginx:alpine image in this repo is not enough
# unless it is rebuilt against that OpenSSL.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MTLS_DIR="${1:-$ROOT/state/mtls}"
DAYS="${MTLS_DAYS:-825}"
CA_DAYS="${MTLS_CA_DAYS:-3650}"
ML_ALG="${MTLS_ML_ALG:-ML-DSA-44}"

mkdir -p "$MTLS_DIR"/{ca,gateway,services,clients}

gen_key() {
  local key_path="$1"
  openssl genpkey -algorithm "$ML_ALG" -out "$key_path"
}

make_extfile() {
  local cn="$1"
  local san="$2"
  local extfile="$3"
  cat > "$extfile" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:${cn},DNS:${san}
EOF
}

sign_cert() {
  local name="$1"
  local cn="$2"
  local san="$3"
  local out_dir="$4"
  local extfile
  extfile="$(mktemp)"
  gen_key "$out_dir/$name.key"
  openssl req -new -key "$out_dir/$name.key" -out "$out_dir/$name.csr" \
    -subj "/CN=$cn/O=GovPortal/OU=internal-mtls"
  make_extfile "$cn" "$san" "$extfile"
  openssl x509 -req -in "$out_dir/$name.csr" \
    -CA "$MTLS_DIR/ca/ca.crt" -CAkey "$MTLS_DIR/ca/ca.key" -CAcreateserial \
    -out "$out_dir/$name.crt" -days "$DAYS" -extfile "$extfile"
  rm -f "$out_dir/$name.csr" "$extfile"
}

echo "[mldsa-mtls] Creating ML-DSA-44 CA in $MTLS_DIR"
gen_key "$MTLS_DIR/ca/ca.key"
openssl req -x509 -new -key "$MTLS_DIR/ca/ca.key" -days "$CA_DAYS" \
  -out "$MTLS_DIR/ca/ca.crt" \
  -subj "/CN=GovPortal-MLDSA-mTLS-CA/O=GovPortal/OU=internal-mtls" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

sign_cert server gateway.govportal.local gateway "$MTLS_DIR/gateway"
sign_cert client gateway-client gateway-client "$MTLS_DIR/gateway"
sign_cert storage storage_service.govportal.local storage_service "$MTLS_DIR/services"
sign_cert doc doc_service.govportal.local doc_service "$MTLS_DIR/services"
sign_cert qr qr_service.govportal.local qr_service "$MTLS_DIR/services"
sign_cert api-client api-client api-client "$MTLS_DIR/clients"

chmod 600 "$MTLS_DIR"/ca/*.key "$MTLS_DIR"/gateway/*.key "$MTLS_DIR"/services/*.key "$MTLS_DIR"/clients/*.key

echo "[mldsa-mtls] Done."
echo "  CA:              $MTLS_DIR/ca/ca.crt"
echo "  Gateway server:  $MTLS_DIR/gateway/server.crt"
echo "  Gateway client:  $MTLS_DIR/gateway/client.crt"
echo "  Services:        $MTLS_DIR/services/*.crt"
