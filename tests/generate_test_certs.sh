#!/bin/bash
# Generate test certificates for DCAP quote verification
#
# This script generates a simple certificate chain for testing:
# - Root CA
# - TCB Signing Certificate  
# - PCK Certificate
# - CRLs

set -e

CERTS_DIR="test_data/certs"

echo "=== Generating Test Certificates ==="
echo ""

# Create directory
mkdir -p "$CERTS_DIR"

echo "Generating Root CA..."
# Generate root CA private key (ECDSA - same as Intel)
openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS_DIR/root_ca.key"

# Generate root CA certificate
openssl req -new -x509 -key "$CERTS_DIR/root_ca.key" \
    -out "$CERTS_DIR/root_ca.pem" -days 3650 \
    -subj "/CN=Test Root CA/O=Test/C=US"

# Convert to DER
openssl x509 -in "$CERTS_DIR/root_ca.pem" -outform DER -out "$CERTS_DIR/root_ca.der"

echo "Generating TCB Signing Certificate..."
# Generate TCB signing key (PKCS8 format for ring compatibility)
openssl ecparam -name prime256v1 -genkey -noout | \
    openssl pkcs8 -topk8 -nocrypt -out "$CERTS_DIR/tcb_signing.pkcs8.key"

# Generate TCB signing CSR
openssl req -new -key "$CERTS_DIR/tcb_signing.pkcs8.key" \
    -out "$CERTS_DIR/tcb_signing.csr" \
    -subj "/CN=Test TCB Signing/O=Test/C=US"

# Sign TCB certificate with root CA (version 3)
openssl x509 -req -in "$CERTS_DIR/tcb_signing.csr" \
    -CA "$CERTS_DIR/root_ca.pem" -CAkey "$CERTS_DIR/root_ca.key" \
    -CAcreateserial -out "$CERTS_DIR/tcb_signing.pem" -days 3650 \
    -extfile /dev/stdin <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

echo "Generating PCK Certificate..."
# Generate PCK key (PKCS8 format for ring compatibility)
openssl ecparam -name prime256v1 -genkey -noout | \
    openssl pkcs8 -topk8 -nocrypt -out "$CERTS_DIR/pck.pkcs8.key"

# Generate PCK CSR
openssl req -new -key "$CERTS_DIR/pck.pkcs8.key" \
    -out "$CERTS_DIR/pck.csr" \
    -subj "/CN=Test PCK/O=Test/C=US"

# Sign PCK certificate with Root CA directly (version 3)
openssl x509 -req -in "$CERTS_DIR/pck.csr" \
    -CA "$CERTS_DIR/root_ca.pem" -CAkey "$CERTS_DIR/root_ca.key" \
    -CAcreateserial -out "$CERTS_DIR/pck.pem" -days 3650 \
    -extfile /dev/stdin <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
1.2.840.113741.1.13.1 = DER:308201C1301E060A2A864886F84D010D01010410D04EC06D4E6D92DC90D0AD3CF5EE2DDF30820164060A2A864886F84D010D0102308201543010060B2A864886F84D010D01020102010B3010060B2A864886F84D010D01020202010B3010060B2A864886F84D010D0102030201023010060B2A864886F84D010D0102040201023011060B2A864886F84D010D010205020200FF3010060B2A864886F84D010D0102060201013010060B2A864886F84D010D0102070201003010060B2A864886F84D010D0102080201003010060B2A864886F84D010D0102090201003010060B2A864886F84D010D01020A0201003010060B2A864886F84D010D01020B0201003010060B2A864886F84D010D01020C0201003010060B2A864886F84D010D01020D0201003010060B2A864886F84D010D01020E0201003010060B2A864886F84D010D01020F0201003010060B2A864886F84D010D0102100201003010060B2A864886F84D010D01021102010D301F060B2A864886F84D010D01021204100B0B0202FF01000000000000000000003010060A2A864886F84D010D0103040200003014060A2A864886F84D010D0104040600906EA10000300F060A2A864886F84D010D01050A0100
EOF

echo "Creating certificate chain..."
# Create TCB chain (TCB signing + Root CA)
cat "$CERTS_DIR/tcb_signing.pem" "$CERTS_DIR/root_ca.pem" > "$CERTS_DIR/tcb_chain.pem"

# Create PCK chain (PCK + TCB signing + Root CA)
cat "$CERTS_DIR/pck.pem" "$CERTS_DIR/tcb_signing.pem" "$CERTS_DIR/root_ca.pem" > "$CERTS_DIR/pck_chain.pem"

echo "Generating CRLs..."
# Create empty database files first
touch "$CERTS_DIR/index.txt"
echo "01" > "$CERTS_DIR/serial"
echo "01" > "$CERTS_DIR/crlnumber"

# Create empty CRL for root CA
openssl ca -gencrl -keyfile "$CERTS_DIR/root_ca.key" \
    -cert "$CERTS_DIR/root_ca.pem" \
    -out "$CERTS_DIR/root_ca.crl.pem" \
    -crlexts crl_ext \
    -config /dev/stdin <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
database = $CERTS_DIR/index.txt
serial = $CERTS_DIR/serial
crlnumber = $CERTS_DIR/crlnumber
default_crl_days = 3650
default_md = sha256

[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer
EOF

# Convert CRL to DER
openssl crl -in "$CERTS_DIR/root_ca.crl.pem" -outform DER -out "$CERTS_DIR/root_ca.crl.der"

# Create PCK CRL (same as root for simplicity)
cp "$CERTS_DIR/root_ca.crl.der" "$CERTS_DIR/pck.crl.der"

echo ""
echo "=== Certificate Generation Complete ==="
echo "Certificates saved to: $CERTS_DIR"
echo ""
echo "Generated files:"
ls -lh "$CERTS_DIR" | grep -E "\.(pem|der|key)$" | awk '{print "  " $9 " (" $5 ")"}'
