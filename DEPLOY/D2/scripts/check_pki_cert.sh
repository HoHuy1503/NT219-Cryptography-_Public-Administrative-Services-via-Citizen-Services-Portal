#!/usr/bin/env bash
set -euo pipefail

GATEWAY_URL="${GOVPORTAL_GATEWAY_URL:-http://10.0.1.10:8080}"
OPENSSL_BIN="${OPENSSL_BIN:-/home/hnh/Documents/openssl/openssl-3.6.1/apps/openssl}"
OPENSSL_LIB_DIR="${OPENSSL_LIB_DIR:-/home/hnh/Documents/openssl/openssl-3.6.1}"
COMMON_NAME="${1:-officer-test-001}"
ORG_NAME="${2:-GovPortal Officer Unit}"
COUNTRY="${3:-VN}"

TMP_JSON="$(mktemp)"
TMP_CERT="$(mktemp)"
trap 'rm -f "$TMP_JSON" "$TMP_CERT"' EXIT

curl -sS -X POST "${GATEWAY_URL}/api/pki/issue-certificate" \
  -H "Content-Type: application/json" \
  -d "{\"common_name\":\"${COMMON_NAME}\",\"organization\":\"${ORG_NAME}\",\"country\":\"${COUNTRY}\"}" \
  > "$TMP_JSON"

if ! jq -e '.certificate' "$TMP_JSON" >/dev/null 2>&1; then
  echo "[error] PKI issue-certificate response does not include certificate"
  cat "$TMP_JSON"
  exit 1
fi

jq -r '.certificate' "$TMP_JSON" > "$TMP_CERT"

echo "[info] Issued cert metadata:"
jq -r '{cert_id, issuer, subject, not_before, not_after}' "$TMP_JSON"

echo "[info] OpenSSL issuer/subject check:"
LD_LIBRARY_PATH="$OPENSSL_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$OPENSSL_BIN" x509 -in "$TMP_CERT" -noout -issuer -subject -dates -serial

echo "[ok] Certificate was issued and parsed successfully"
