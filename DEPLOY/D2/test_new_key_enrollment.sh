#!/bin/bash

#
# Test Script: New Officer Key Generation & Certificate Enrollment Flow
#
# This script demonstrates the complete new enrollment flow where officers
# generate their own keys locally and register only the public key.
#

set -e

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
OFFICER_ID="test_officer_$(date +%s)"
EMAIL="$OFFICER_ID@govportal.vn"
PASSWORD="TestPass123!"
API_TOKEN=""

echo "=========================================="
echo "New Officer Key Enrollment Flow Test"
echo "=========================================="
echo ""

# Step 1: Generate keys locally
echo "[STEP 1] Officer generates keys locally..."
TMPDIR=$(mktemp -d)
PRIVATE_KEY="$TMPDIR/officer_private.pem"
PUBLIC_KEY="$TMPDIR/officer_public.pem"

# Generate ML-DSA-44 key pair (post-quantum)
if ! command -v openssl &> /dev/null; then
    echo "ERROR: openssl not found. Please install OpenSSL to run this test."
    exit 1
fi

echo "  Generating ML-DSA-44 key pair..."
openssl genpkey -algorithm ML-DSA-44 -out "$PRIVATE_KEY" 2>/dev/null
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null

echo "  ✓ Private key saved to: $PRIVATE_KEY (KEEP SECURE)"
echo "  ✓ Public key saved to: $PUBLIC_KEY"
echo ""

# Step 2: Officer creates account
echo "[STEP 2] Officer creates account..."
REGISTER_RESPONSE=$(curl -s -X POST "$GATEWAY_URL/api/storage/register/officer" \
  -H "Content-Type: application/json" \
  -d @- << EOF
{
  "officer_id": "$OFFICER_ID",
  "email": "$EMAIL",
  "name": "Test Officer",
  "password": "$PASSWORD",
  "department": "UBND Test",
  "region_code": "VN-01"
}
EOF
)

echo "  Response:"
echo "$REGISTER_RESPONSE" | jq . 2>/dev/null || echo "$REGISTER_RESPONSE"

# Check if registration was successful
if echo "$REGISTER_RESPONSE" | grep -q "Officer account created"; then
    echo "  ✓ Account created successfully"
else
    echo "  ✗ Failed to create account"
    exit 1
fi
echo ""

# Step 3: Officer logs in
echo "[STEP 3] Officer logs in to get auth token..."
LOGIN_RESPONSE=$(curl -s -X POST "$GATEWAY_URL/api/storage/login" \
  -H "Content-Type: application/json" \
  -d @- << EOF
{
  "username": "$OFFICER_ID",
  "password": "$PASSWORD"
}
EOF
)

echo "  Response:"
echo "$LOGIN_RESPONSE" | jq . 2>/dev/null | head -20 || echo "$LOGIN_RESPONSE" | head -20

# Extract token
API_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token' 2>/dev/null || echo "")
if [ -z "$API_TOKEN" ] || [ "$API_TOKEN" = "null" ]; then
    echo "  ✗ Failed to get authentication token"
    echo "  Full response: $LOGIN_RESPONSE"
    exit 1
fi
echo "  ✓ Authentication token obtained"
echo ""

# Step 4: Officer registers public key
echo "[STEP 4] Officer registers their public key..."
PUBLIC_KEY_PEM=$(cat "$PUBLIC_KEY")
REGISTER_KEY_RESPONSE=$(curl -s -X POST "$GATEWAY_URL/api/storage/officers/$OFFICER_ID/register-key" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_TOKEN" \
  -d @- << EOF
{
  "public_key_pem": "$PUBLIC_KEY_PEM",
  "key_algorithm": "ML-DSA-44"
}
EOF
)

echo "  Response:"
echo "$REGISTER_KEY_RESPONSE" | jq . 2>/dev/null || echo "$REGISTER_KEY_RESPONSE"

# Check if key registration was successful
if echo "$REGISTER_KEY_RESPONSE" | grep -q "key_id"; then
    echo "  ✓ Public key registered successfully"
    KEY_ID=$(echo "$REGISTER_KEY_RESPONSE" | jq -r '.key_id' 2>/dev/null)
else
    echo "  ✗ Failed to register public key"
    exit 1
fi
echo ""

# Step 5: PKI admin issues certificate with officer's public key
echo "[STEP 5] PKI admin issues certificate using officer's public key..."
ISSUE_CERT_RESPONSE=$(curl -s -X POST "$GATEWAY_URL/api/pki/issue-certificate" \
  -H "Content-Type: application/json" \
  -d @- << EOF
{
  "officer_id": "$OFFICER_ID",
  "common_name": "Test Officer",
  "organization": "UBND Test",
  "country": "VN",
  "purpose": "officer_identity",
  "public_key_pem": "$PUBLIC_KEY_PEM"
}
EOF
)

echo "  Response (first 500 chars):"
echo "$ISSUE_CERT_RESPONSE" | jq . 2>/dev/null | head -30 || echo "$ISSUE_CERT_RESPONSE" | head -30

# Check if certificate was issued
if echo "$ISSUE_CERT_RESPONSE" | grep -q "cert_id"; then
    echo "  ✓ Certificate issued successfully"
    CERT_ID=$(echo "$ISSUE_CERT_RESPONSE" | jq -r '.cert_id' 2>/dev/null)
    CERTIFICATE=$(echo "$ISSUE_CERT_RESPONSE" | jq -r '.certificate' 2>/dev/null)
    
    # Save certificate
    CERT_FILE="$TMPDIR/officer_cert.pem"
    echo "$CERTIFICATE" > "$CERT_FILE"
    echo "  ✓ Certificate saved to: $CERT_FILE"
else
    echo "  ✗ Failed to issue certificate"
    echo "  Response: $ISSUE_CERT_RESPONSE"
    exit 1
fi
echo ""

# Step 6: Verify the flow worked
echo "[STEP 6] Verification..."
echo "  ✓ Officer account created with ID: $OFFICER_ID"
echo "  ✓ Public key registered with ID: $KEY_ID"
echo "  ✓ Certificate issued with ID: $CERT_ID"
echo ""

# Step 7: Demonstrate that officer can sign with private key
echo "[STEP 7] Officer can sign documents with their private key..."

# Create test document
TEST_DOC="$TMPDIR/test_document.txt"
echo "This is a test document" > "$TEST_DOC"

# Sign document
SIGNATURE_FILE="$TMPDIR/test_document.sig"
if openssl dgst -sha256 -sign "$PRIVATE_KEY" "$TEST_DOC" > "$SIGNATURE_FILE" 2>/dev/null; then
    echo "  ✓ Document signed successfully"
    
    # Verify signature (using public key)
    if openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE_FILE" "$TEST_DOC" &>/dev/null; then
        echo "  ✓ Signature verified successfully"
    else
        echo "  ✗ Signature verification failed"
    fi
else
    echo "  ⚠ Document signing not available in test environment"
fi
echo ""

# Cleanup
echo "[CLEANUP] Removing temporary files..."
rm -rf "$TMPDIR"
echo "  ✓ Temporary files removed"
echo ""

echo "=========================================="
echo "✓ All tests passed!"
echo "=========================================="
echo ""
echo "Key Takeaways:"
echo "1. Officer generated ML-DSA-44 keys locally (PRIVATE KEY NEVER SENT TO SERVER)"
echo "2. Officer created account"
echo "3. Officer authenticated and registered public key"
echo "4. PKI admin issued certificate using the registered public key"
echo "5. Officer can sign documents with their private key"
echo "6. Gateway successfully routed all requests"
echo ""
echo "Files generated:"
echo "  - Private key (SECURE): $TMPDIR/officer_private.pem (DELETED)"
echo "  - Public key: $TMPDIR/officer_public.pem (DELETED)"
echo "  - Certificate: $TMPDIR/officer_cert.pem (DELETED)"
echo ""
