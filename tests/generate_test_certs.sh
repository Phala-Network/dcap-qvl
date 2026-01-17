#!/bin/bash
# Generate test certificates for DCAP quote verification
#
# This script generates a 3-level certificate chain for testing:
# - Root CA (CA:TRUE)
# - TCB Signing CA (CA:TRUE) - intermediate CA for signing CRLs
# - TCB Signer (CA:FALSE) - end-entity cert for signing TCB Info and QE Identity
# - PCK Certificate (CA:FALSE)
# - CRLs
#
# Also generates a CA-only chain for testing CaUsedAsEndEntity error

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

echo "Generating TCB Signing CA (intermediate CA)..."
# Generate TCB signing CA key (PKCS8 format for ring compatibility)
openssl ecparam -name prime256v1 -genkey -noout | \
    openssl pkcs8 -topk8 -nocrypt -out "$CERTS_DIR/tcb_signing_ca.pkcs8.key"

# Generate TCB signing CA CSR
openssl req -new -key "$CERTS_DIR/tcb_signing_ca.pkcs8.key" \
    -out "$CERTS_DIR/tcb_signing_ca.csr" \
    -subj "/CN=Test TCB Signing CA/O=Test/C=US"

# Sign TCB CA certificate with root CA (version 3)
# TCB Signing CA cert needs CA:TRUE and cRLSign to sign PCK CRL
openssl x509 -req -in "$CERTS_DIR/tcb_signing_ca.csr" \
    -CA "$CERTS_DIR/root_ca.pem" -CAkey "$CERTS_DIR/root_ca.key" \
    -CAcreateserial -out "$CERTS_DIR/tcb_signing_ca.pem" -days 3650 \
    -extfile /dev/stdin <<EOF
basicConstraints = CA:TRUE, pathlen:0
keyUsage = digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

echo "Generating TCB Signer (end-entity for signing TCB Info and QE Identity)..."
# Generate TCB signer key (PKCS8 format for ring compatibility)
openssl ecparam -name prime256v1 -genkey -noout | \
    openssl pkcs8 -topk8 -nocrypt -out "$CERTS_DIR/tcb_signing.pkcs8.key"

# Generate TCB signer CSR
openssl req -new -key "$CERTS_DIR/tcb_signing.pkcs8.key" \
    -out "$CERTS_DIR/tcb_signing.csr" \
    -subj "/CN=Test TCB Signer/O=Test/C=US"

# Sign TCB signer certificate with TCB Signing CA (version 3)
# This is an end-entity cert (CA:FALSE) for signing data
openssl x509 -req -in "$CERTS_DIR/tcb_signing.csr" \
    -CA "$CERTS_DIR/tcb_signing_ca.pem" -CAkey "$CERTS_DIR/tcb_signing_ca.pkcs8.key" \
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

echo "Creating certificate chains..."
# Create TCB chain (TCB signer + TCB Signing CA + Root CA) - 3-level chain
cat "$CERTS_DIR/tcb_signing.pem" "$CERTS_DIR/tcb_signing_ca.pem" "$CERTS_DIR/root_ca.pem" > "$CERTS_DIR/tcb_chain.pem"

# Create CA-only TCB chain for testing CaUsedAsEndEntity error
# This chain uses the CA cert as the signing cert (wrong!)
cat "$CERTS_DIR/tcb_signing_ca.pem" "$CERTS_DIR/root_ca.pem" > "$CERTS_DIR/tcb_chain_ca_only.pem"

# Create PCK chain (PCK + TCB Signing CA + Root CA)
cat "$CERTS_DIR/pck.pem" "$CERTS_DIR/tcb_signing_ca.pem" "$CERTS_DIR/root_ca.pem" > "$CERTS_DIR/pck_chain.pem"

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

# Create PCK CRL signed by TCB Signing CA (which is the PCK CRL issuer)
# Reset database for TCB Signing CA
rm -f "$CERTS_DIR/index.txt" "$CERTS_DIR/crlnumber"
touch "$CERTS_DIR/index.txt"
echo "01" > "$CERTS_DIR/crlnumber"

openssl ca -gencrl -keyfile "$CERTS_DIR/tcb_signing_ca.pkcs8.key" \
    -cert "$CERTS_DIR/tcb_signing_ca.pem" \
    -out "$CERTS_DIR/pck.crl.pem" \
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

# Convert PCK CRL to DER
openssl crl -in "$CERTS_DIR/pck.crl.pem" -outform DER -out "$CERTS_DIR/pck.crl.der"

echo ""
echo "=== Certificate Generation Complete ==="
echo "Certificates saved to: $CERTS_DIR"
echo ""
echo "Generated files:"
ls -lh "$CERTS_DIR" | grep -E "\.(pem|der|key)$" | awk '{print "  " $9 " (" $5 ")"}'
