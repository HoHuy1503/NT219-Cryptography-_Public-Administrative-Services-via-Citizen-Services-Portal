#!/usr/bin/env bash
# Generate browser/client certificates for non-citizen portals.
# These are ECDSA P-256 because current browsers and USB/smart-card stacks
# support them broadly for TLS client authentication.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT_DIR="${1:-$ROOT/domain_key/browser_clients}"
DAYS="${PORTAL_CLIENT_DAYS:-825}"
PFX_PASSWORD="${PFX_PASSWORD:-changeit}"
EC_CURVE="${PORTAL_CLIENT_CURVE:-prime256v1}"

mkdir -p "$OUT_DIR"/{ca,certs,pfx}

gen_ec_key() {
  openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${EC_CURVE}" -out "$1"
}

if [[ ! -f "$OUT_DIR/ca/portal-client-ca.crt" ]]; then
  gen_ec_key "$OUT_DIR/ca/portal-client-ca.key"
  openssl req -x509 -new -key "$OUT_DIR/ca/portal-client-ca.key" -sha256 -days 3650 \
    -out "$OUT_DIR/ca/portal-client-ca.crt" \
    -subj "/CN=GovPortal Browser Client CA/O=GovPortal/OU=public-portals"
  chmod 600 "$OUT_DIR/ca/portal-client-ca.key"
fi

make_client() {
  local name="$1"
  local cn="$2"
  local key="$OUT_DIR/certs/${name}.key.pem"
  local csr="$OUT_DIR/certs/${name}.csr"
  local crt="$OUT_DIR/certs/${name}.crt.pem"
  local pfx="$OUT_DIR/pfx/${name}.p12"
  local extfile
  extfile="$(mktemp)"
  cat > "$extfile" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:govportal:role:${name}
EOF
  gen_ec_key "$key"
  openssl req -new -key "$key" -out "$csr" -subj "/CN=$cn/O=GovPortal/OU=browser-client"
  openssl x509 -req -in "$csr" \
    -CA "$OUT_DIR/ca/portal-client-ca.crt" -CAkey "$OUT_DIR/ca/portal-client-ca.key" -CAcreateserial \
    -out "$crt" -days "$DAYS" -sha256 -extfile "$extfile"
  openssl pkcs12 -export -inkey "$key" -in "$crt" -certfile "$OUT_DIR/ca/portal-client-ca.crt" \
    -out "$pfx" -passout "pass:${PFX_PASSWORD}" -name "$cn"
  rm -f "$csr" "$extfile"
  chmod 600 "$key" "$pfx"
}

make_client "pki_admin" "pki-admin@pki.gt.tc"
make_client "thirdparty" "thirdparty-user@thirdparties.gt.tc"
make_client "officer" "officer@officers.gt.tc"
make_client "storage_admin" "storage-admin@dbadmin.gt.tc"

echo "[portal-client-certs] Done."
echo "  Trust CA in nginx: $OUT_DIR/ca/portal-client-ca.crt"
echo "  Import to browser/USB token: $OUT_DIR/pfx/*.p12"
echo "  P12 password: ${PFX_PASSWORD}"
