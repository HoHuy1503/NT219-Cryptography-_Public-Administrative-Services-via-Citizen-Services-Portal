#!/bin/bash
# Script to retrieve GovPortal CA public key from Vault PKMS or local certificate
# Usage: ./retrieve_public_key.sh [--from-vault|--local] [output-dir]

set -e

OUTPUT_DIR="${2:-.}"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

case "${1:-}" in
  --from-vault)
    echo "[*] Retrieving CA public key from Vault API..."
    if [ -z "$VAULT_TOKEN" ]; then
      echo "[-] Error: VAULT_TOKEN not set"
      exit 1
    fi
    
    # Retrieve certificate from Vault
    curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
      "$VAULT_ADDR/v1/pki/cert/ca" | jq '.data.certificate' -r > "$OUTPUT_DIR/govportal_ca.pem"
    
    echo "[+] CA certificate saved to: $OUTPUT_DIR/govportal_ca.pem"
    ;;
  
  --local)
    echo "[*] Using local CA certificate..."
    if [ ! -f "$OUTPUT_DIR/govportal_ca.pem" ]; then
      echo "[-] Error: $OUTPUT_DIR/govportal_ca.pem not found"
      exit 1
    fi
    ;;
  
  *)
    echo "Usage: $0 {--from-vault|--local} [output-dir]"
    echo ""
    echo "Examples:"
    echo "  # Retrieve from Vault KMS"
    echo "  VAULT_TOKEN=\$ROOT_TOKEN $0 --from-vault /tmp"
    echo ""
    echo "  # Use existing local certificate"
    echo "  $0 --local /tmp"
    exit 1
    ;;
esac

# Extract public key from certificate
echo "[*] Extracting public key from certificate..."
openssl x509 -in "$OUTPUT_DIR/govportal_ca.pem" -pubkey -noout \
  > "$OUTPUT_DIR/govportal_public_key.pem"

echo "[+] Public key saved to: $OUTPUT_DIR/govportal_public_key.pem"

# Display certificate details
echo ""
echo "=== CERTIFICATE DETAILS ==="
openssl x509 -in "$OUTPUT_DIR/govportal_ca.pem" -text -noout | head -20

# Display public key
echo ""
echo "=== PUBLIC KEY (PEM FORMAT) ==="
cat "$OUTPUT_DIR/govportal_public_key.pem"

# Show key fingerprint
echo ""
echo "=== KEY FINGERPRINT ==="
openssl x509 -in "$OUTPUT_DIR/govportal_ca.pem" -noout -fingerprint -sha256
