#!/bin/bash

#!/bin/bash

# Ensure LIND_WASM_ROOT is set, fallback to current directory if not
LINDFS_DIR="${LIND_WASM_ROOT:-.}/lindfs"
CERT_DIR="$LINDFS_DIR/certs"
mkdir -p "$CERT_DIR"

echo "Generating mTLS Certificates for Lind-Wasm..."

# 1. Generate the CA private key
openssl genrsa -out "$CERT_DIR/ca.key" 4096

# 2. Generate the CA root certificate (ca.crt)
# Added basicConstraints to explicitly define this as a valid Certificate Authority
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 -out "$CERT_DIR/ca.crt" \
  -subj "/CN=MyLocalCA" \
  -addext "basicConstraints=critical,CA:TRUE"

# 3. Generate the application's private key (key.pem)
openssl genrsa -out "$CERT_DIR/key.pem" 2048

# 4. Generate a Certificate Signing Request (CSR)
openssl req -new -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.csr" \
  -subj "/CN=localhost"

# 5. Create the v3 extension file required by rustls
# rustls ignores the Common Name (CN) and requires a Subject Alternative Name (SAN)
cat <<EOF > "$CERT_DIR/v3.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# 6. Sign the CSR with your CA to create the final certificate (cert.pem)
openssl x509 -req -in "$CERT_DIR/cert.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial -out "$CERT_DIR/cert.pem" -days 365 -sha256 -extfile "$CERT_DIR/v3.ext"

# 7. Clean up and Verify
rm "$CERT_DIR/cert.csr" "$CERT_DIR/ca.srl" "$CERT_DIR/v3.ext"

echo "------------------------------------------------"
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/cert.pem"
echo "------------------------------------------------"
echo "Certificates successfully generated in $CERT_DIR"

# 8. Execution Commands
# Running the server
# lind_run mTLS-grate-rs.cwasm --cert ./certs/cert.pem --key ./certs/key.pem --ca ./certs/ca.crt -- mtls_test.cwasm

# Client connection test
# Note: Ensure the paths match where the client is running from
# openssl s_client --ignore_unexpected_eof connect 127.0.0.1:443 -cert "$CERT_DIR/cert.pem" -key "$CERT_DIR/key.pem" -CAfile "$CERT_DIR/ca.crt"
